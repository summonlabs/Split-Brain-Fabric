#include <algorithm>
#include <cstdint>
#include <vector>

#include "sbf/arbiter.hpp"
#include "sbf/canonical.hpp"

// Implementation of the authority plan selection described in arbiter.hpp.
//
// The solver is deliberately split into three independently written pieces:
//   * the production branch-and-bound below,
//   * an exhaustive reference enumerator (select_authority_set_reference),
//   * a greedy heuristic (select_authority_set_greedy).
// The differential tests compare all three, and every emitted plan is re-checked
// by validate_plan before it leaves the library.
namespace sbf {
namespace {

struct RankedCandidate {
  std::size_t index = 0;
  std::size_t rank = 0;
};

bool preference_less(const AuthorityRequest& a, const AuthorityRequest& b) noexcept {
  if (a.epoch != b.epoch) return a.epoch > b.epoch;
  if (a.presented_fence_token != b.presented_fence_token) {
    return a.presented_fence_token > b.presented_fence_token;
  }
  if (!(a.domain == b.domain)) return a.domain < b.domain;
  return a.claim < b.claim;
}

bool exclusive_overlap(const AuthorityRequest& a, const AuthorityRequest& b) noexcept {
  if (a.mode != AuthorityMode::ExclusiveMutation || b.mode != AuthorityMode::ExclusiveMutation) {
    return false;
  }
  return a.scope.overlaps(b.scope);
}

struct SearchState {
  std::vector<char> legal;
  std::vector<std::vector<char>> conflict;
  std::vector<std::size_t> order;   // candidate indices in preference order
  std::vector<std::size_t> rank_of; // index -> rank
  std::uint64_t budget = 0;
  std::uint64_t nodes = 0;
  bool budget_exhausted = false;
  bool complete = false;
  std::vector<std::size_t> best;    // indices, ascending by rank
};

// Selections are carried as *candidate indices* in ascending preference-rank
// order. Ranks are only ever used for the canonical tie-break comparison, which
// is what keeps the solver independent of the order candidates arrive in.
bool better_selection(const std::vector<std::size_t>& candidate,
                      const std::vector<std::size_t>& incumbent,
                      const std::vector<std::size_t>& rank_of) {
  if (candidate.size() != incumbent.size()) return candidate.size() > incumbent.size();
  for (std::size_t i = 0; i < candidate.size(); ++i) {
    const std::size_t left = rank_of[candidate[i]];
    const std::size_t right = rank_of[incumbent[i]];
    if (left != right) return left < right;
  }
  return false;
}

void search(SearchState& state, std::size_t position, std::vector<std::size_t>& chosen) {
  if (state.budget_exhausted) return;
  if (++state.nodes > state.budget) {
    state.budget_exhausted = true;
    return;
  }
  if (position == state.order.size()) {
    if (better_selection(chosen, state.best, state.rank_of)) state.best = chosen;
    return;
  }
  const std::size_t candidate = state.order[position];

  // Upper bound: even taking everything left cannot beat a strictly larger
  // incumbent; the bound only prunes, it never changes the answer.
  if (chosen.size() + (state.order.size() - position) >= state.best.size()) {
    bool compatible = true;
    if (state.legal[candidate] == 0) {
      compatible = false;
    } else {
      for (const std::size_t taken : chosen) {
        if (state.conflict[candidate][taken] != 0) {
          compatible = false;
          break;
        }
      }
    }
    if (compatible) {
      chosen.push_back(candidate);
      search(state, position + 1, chosen);
      chosen.pop_back();
    }
  }
  search(state, position + 1, chosen);
}

AuthorityPlan build_plan(const std::vector<AuthorityRequest>& candidates,
                         const std::vector<AuthorityDecision>& decisions,
                         const std::vector<std::size_t>& order,
                         const std::vector<std::size_t>& ranks,
                         SelectionOutcome outcome, std::uint64_t nodes, bool proven) {
  AuthorityPlan plan;
  plan.outcome = outcome;
  plan.nodes_explored = nodes;
  plan.optimality_proven = proven;
  std::vector<char> selected_flags(candidates.size(), 0);
  for (const std::size_t index : ranks) {
    selected_flags[index] = 1;
    plan.authorized.push_back(decisions[index]);
  }
  (void)order;
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    if (selected_flags[i] == 0) plan.refused.push_back(candidates[i].claim);
  }
  for (const auto& decision : plan.authorized) {
    for (const auto& claim : decision.must_fence) {
      if (std::find(plan.must_fence.begin(), plan.must_fence.end(), claim) == plan.must_fence.end()) {
        plan.must_fence.push_back(claim);
      }
    }
  }
  std::sort(plan.refused.begin(), plan.refused.end());
  std::sort(plan.must_fence.begin(), plan.must_fence.end());
  switch (outcome) {
    case SelectionOutcome::ProvenOptimal:
      plan.status = Status::ok();
      break;
    case SelectionOutcome::ProvenInfeasible:
      plan.status = Status::make(Outcome::Ok, Reason::ProvenInfeasible, 0);
      break;
    case SelectionOutcome::SearchLimitReached:
      plan.status = Status::make(Outcome::SearchLimitReached, Reason::SearchLimitReached, nodes);
      break;
    case SelectionOutcome::Indeterminate:
      plan.status = Status::make(Outcome::Indeterminate, Reason::NoCertificate, nodes);
      break;
    case SelectionOutcome::Invalid:
      plan.status = Status::make(Outcome::Invalid, Reason::PlanInvalid, nodes);
      break;
  }
  return plan;
}

SearchState prepare(const std::vector<AuthorityRequest>& candidates, const ArbiterView& view,
                    std::vector<AuthorityDecision>& decisions, std::uint64_t node_budget) {
  SearchState state;
  state.budget = node_budget;
  const std::size_t n = candidates.size();
  state.legal.assign(n, 0);
  state.conflict.assign(n, std::vector<char>(n, 0));
  state.order.resize(n);
  state.rank_of.resize(n);
  for (std::size_t i = 0; i < n; ++i) state.order[i] = i;
  std::stable_sort(state.order.begin(), state.order.end(), [&](std::size_t a, std::size_t b) {
    return preference_less(candidates[a], candidates[b]);
  });
  for (std::size_t rank = 0; rank < n; ++rank) state.rank_of[state.order[rank]] = rank;

  ArbiterView isolated = view;
  isolated.competing.clear();
  decisions.clear();
  decisions.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    decisions.push_back(decide_authority(candidates[i], isolated));
    state.legal[i] = decisions[i].is_authoritative() ? 1 : 0;
  }
  for (std::size_t i = 0; i < n; ++i) {
    for (std::size_t j = i + 1; j < n; ++j) {
      const char conflict = exclusive_overlap(candidates[i], candidates[j]) ? 1 : 0;
      state.conflict[i][j] = conflict;
      state.conflict[j][i] = conflict;
    }
  }
  return state;
}

}  // namespace

std::string_view to_string(SelectionOutcome outcome) noexcept {
  switch (outcome) {
    case SelectionOutcome::ProvenOptimal: return "PROVEN_OPTIMAL";
    case SelectionOutcome::ProvenInfeasible: return "PROVEN_INFEASIBLE";
    case SelectionOutcome::SearchLimitReached: return "SEARCH_LIMIT_REACHED";
    case SelectionOutcome::Indeterminate: return "INDETERMINATE";
    case SelectionOutcome::Invalid: return "INVALID";
  }
  return "INDETERMINATE";
}

AuthorityPlan select_authority_set(const std::vector<AuthorityRequest>& candidates,
                                   const ArbiterView& view, std::uint64_t node_budget) {
  AuthorityPlan plan;
  if (candidates.empty()) {
    plan.outcome = SelectionOutcome::ProvenInfeasible;
    plan.optimality_proven = true;
    plan.status = Status::make(Outcome::Ok, Reason::ProvenInfeasible, 0);
    plan.validated = true;
    return plan;
  }
  if (candidates.size() > limits::kMaxCompetingClaims) {
    plan.outcome = SelectionOutcome::Invalid;
    plan.status = Status::make(Outcome::Exhausted, Reason::BoundedTableFull, candidates.size());
    return plan;
  }
  if (node_budget == 0) node_budget = limits::kMaxSearchNodes;

  std::vector<AuthorityDecision> decisions;
  SearchState state = prepare(candidates, view, decisions, node_budget);

  std::vector<std::size_t> chosen;
  search(state, 0, chosen);

  const bool complete = !state.budget_exhausted;
  SelectionOutcome outcome = SelectionOutcome::Indeterminate;
  if (complete) {
    outcome = state.best.empty() ? SelectionOutcome::ProvenInfeasible
                                 : SelectionOutcome::ProvenOptimal;
  } else {
    outcome = state.best.empty() ? SelectionOutcome::Indeterminate
                                 : SelectionOutcome::SearchLimitReached;
  }
  plan = build_plan(candidates, decisions, state.order, state.best, outcome, state.nodes, complete);
  plan.status.aux = state.nodes;
  plan.validated = validate_plan(plan, candidates, view).is_ok();
  if (!plan.validated) {
    // A plan that fails its own independent validation is never returned as a
    // plan: it becomes an explicit internal invariant violation.
    plan.authorized.clear();
    plan.outcome = SelectionOutcome::Invalid;
    plan.optimality_proven = false;
    plan.status = Status::make(Outcome::Corrupt, Reason::InternalInvariantViolation, state.nodes);
  }
  return plan;
}

AuthorityPlan select_authority_set_reference(const std::vector<AuthorityRequest>& candidates,
                                             const ArbiterView& view, std::uint64_t node_budget) {
  // Exhaustive enumeration written without the production pruning logic: it
  // walks the entire powerset and compares complete selections.
  AuthorityPlan plan;
  if (node_budget == 0) node_budget = limits::kMaxSearchNodes;
  const std::size_t n = candidates.size();
  if (n > 24) {
    plan.outcome = SelectionOutcome::Invalid;
    plan.status = Status::make(Outcome::Exhausted, Reason::BoundedTableFull, n);
    return plan;
  }
  std::vector<AuthorityDecision> decisions;
  SearchState state = prepare(candidates, view, decisions, node_budget);

  std::vector<std::size_t> best;
  std::uint64_t nodes = 0;
  bool exhausted = false;
  const std::uint64_t total = std::uint64_t{1} << n;
  for (std::uint64_t mask = 0; mask < total; ++mask) {
    if (++nodes > node_budget) {
      exhausted = true;
      break;
    }
    std::vector<std::size_t> selection;
    bool feasible = true;
    for (std::size_t i = 0; i < n && feasible; ++i) {
      if ((mask >> i) & 1u) {
        if (state.legal[i] == 0) {
          feasible = false;
          break;
        }
        for (const std::size_t chosen : selection) {
          if (state.conflict[i][chosen] != 0) {
            feasible = false;
            break;
          }
        }
        if (feasible) selection.push_back(i);
      }
    }
    if (!feasible) continue;
    // Reorder by preference rank: the canonical tie-break is defined over ranks,
    // while the conflict matrix is indexed by candidate.
    std::sort(selection.begin(), selection.end(), [&](std::size_t a, std::size_t b) {
      return state.rank_of[a] < state.rank_of[b];
    });
    if (better_selection(selection, best, state.rank_of)) best = selection;
  }

  const SelectionOutcome outcome =
      exhausted ? (best.empty() ? SelectionOutcome::Indeterminate : SelectionOutcome::SearchLimitReached)
                : (best.empty() ? SelectionOutcome::ProvenInfeasible : SelectionOutcome::ProvenOptimal);
  plan = build_plan(candidates, decisions, state.order, best, outcome, nodes, !exhausted);
  plan.status.aux = nodes;
  plan.validated = validate_plan(plan, candidates, view).is_ok();
  return plan;
}

std::vector<ClaimId> select_authority_set_greedy(const std::vector<AuthorityRequest>& candidates,
                                                 const ArbiterView& view,
                                                 std::vector<AuthorityDecision>& out) {
  std::vector<AuthorityDecision> decisions;
  SearchState state = prepare(candidates, view, decisions, limits::kMaxSearchNodes);
  out.clear();
  std::vector<std::size_t> chosen;
  std::vector<ClaimId> claims;
  for (const std::size_t candidate : state.order) {
    if (state.legal[candidate] == 0) continue;
    bool compatible = true;
    for (const std::size_t taken : chosen) {
      if (state.conflict[candidate][taken] != 0) {
        compatible = false;
        break;
      }
    }
    if (!compatible) continue;
    chosen.push_back(candidate);
    out.push_back(decisions[candidate]);
    claims.push_back(candidates[candidate].claim);
  }
  return claims;
}

Status validate_plan(const AuthorityPlan& plan, const std::vector<AuthorityRequest>& candidates,
                     const ArbiterView& view) {
  ArbiterView isolated = view;
  isolated.competing.clear();
  std::vector<const AuthorityRequest*> selected;
  for (const auto& decision : plan.authorized) {
    const AuthorityRequest* match = nullptr;
    for (const auto& candidate : candidates) {
      if (candidate.claim == decision.claim) {
        match = &candidate;
        break;
      }
    }
    if (match == nullptr) {
      return Status::make(Outcome::Invalid, Reason::PlanInvalid);
    }
    const AuthorityDecision recheck = decide_authority(*match, isolated);
    if (!recheck.is_authoritative()) {
      return Status::make(Outcome::Invalid, Reason::PlanInvalid, recheck.status.aux);
    }
    if (!(recheck.digest() == decision.digest())) {
      return Status::make(Outcome::Corrupt, Reason::InternalInvariantViolation);
    }
    selected.push_back(match);
  }
  for (std::size_t i = 0; i < selected.size(); ++i) {
    for (std::size_t j = i + 1; j < selected.size(); ++j) {
      if (exclusive_overlap(*selected[i], *selected[j])) {
        return Status::make(Outcome::Conflict, Reason::OverlappingExclusiveClaim, j);
      }
    }
  }
  return Status::ok();
}

}  // namespace sbf
