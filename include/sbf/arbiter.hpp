#pragma once

#include <cstdint>
#include <vector>

#include "sbf/authority.hpp"
#include "sbf/evidence.hpp"
#include "sbf/fence.hpp"
#include "sbf/lineage.hpp"

namespace sbf {

struct ArbiterPolicy {
  PolicyId policy;
  Generation generation = Generation{1};
  QuorumProfile quorum;
  bool require_quorum_for_exclusive = true;
  bool require_lease_for_exclusive = false;
  // When false, two claims over overlapping extents must both stand down even
  // if their epochs differ. Default true matches the fencing model.
  bool allow_non_overlapping_authority = true;
  bool fence_lower_epoch_claimants = true;
  bool equal_epoch_conflict_is_fatal = true;
  std::uint64_t lease_default_horizon_steps = 1000;

  Status validate() const noexcept;
};

// Everything the decision function may look at. The arbiter performs no I/O and
// reads no clock: the whole world is this view, which makes decisions
// reproducible from persisted state alone.
struct ArbiterView {
  const ArbiterPolicy* policy = nullptr;
  const FenceTable* fences = nullptr;
  const LineageTable* lineage = nullptr;
  Step now;
  Generation registry_generation;
  Generation domain_generation;
  std::vector<CompetingClaim> competing;
  std::vector<WitnessFloor> witness_floors;
};

// The deterministic authority decision. Pure function: same request plus same
// view always yields byte-identical decisions, and wall-clock fields in the
// request are carried into the explanation but never ordered on.
AuthorityDecision decide_authority(const AuthorityRequest& request, const ArbiterView& view);

// Re-evaluates a prior decision against a newer view. Any change to an
// authority-bearing dependency revokes the decision.
RevocationCheck check_revocation(const AuthorityDecision& decision, const ArbiterView& view);

// ---- authority plan selection -------------------------------------------------
//
// Problem class (stated exactly):
//   Input: a bounded list of candidate authority requests, each fully specified
//   (domain, scope, epoch, incarnation, fence token, evidence bundle, mode).
//   A candidate is *individually legal* when decide_authority() on it with an
//   empty competing set returns Authoritative.
//   A set S of candidates is *feasible* when every member is individually legal
//   and no two members with mode ExclusiveMutation have overlapping scopes.
//   Objective: maximise |S|; tie-break deterministically by the canonical
//   preference order (higher epoch, then higher fence token, then domain id,
//   then claim id) taking the lexicographically smallest sorted sequence.
//
// Completeness: the exact search enumerates the whole lattice when the node
// budget allows, in which case optimality is *proven*. If the budget is reached
// the planner returns SearchLimitReached together with a sound (independently
// validated) but not provably optimal set, and never claims optimality.
// ProvenInfeasible is emitted only when the exhaustive search completed and
// proved that no non-empty feasible set exists.
enum class SelectionOutcome : std::uint8_t {
  ProvenOptimal = 0,
  ProvenInfeasible = 1,
  SearchLimitReached = 2,
  Indeterminate = 3,
  Invalid = 4,
};

std::string_view to_string(SelectionOutcome outcome) noexcept;

struct AuthorityPlan {
  SelectionOutcome outcome = SelectionOutcome::Indeterminate;
  Status status;
  std::vector<AuthorityDecision> authorized;   // canonical order
  std::vector<ClaimId> refused;
  std::vector<ClaimId> must_fence;
  std::uint64_t nodes_explored = 0;
  bool optimality_proven = false;
  bool validated = false;                      // independent re-validation passed
  Digest256 digest() const;
};

// Deterministic planner. Production entry point.
AuthorityPlan select_authority_set(const std::vector<AuthorityRequest>& candidates,
                                   const ArbiterView& view,
                                   std::uint64_t node_budget);

// Independent plan validator: re-checks every emitted decision's legality and
// every pairwise exclusion. Returns Ok only when the plan is sound.
Status validate_plan(const AuthorityPlan& plan, const std::vector<AuthorityRequest>& candidates,
                     const ArbiterView& view);

// Slow reference solver used by the differential tests: exhaustive subset
// enumeration written independently of the production search.
AuthorityPlan select_authority_set_reference(const std::vector<AuthorityRequest>& candidates,
                                             const ArbiterView& view,
                                             std::uint64_t node_budget);

// Deterministic greedy heuristic. Sound (every emitted set is validated) but not
// optimal; used to demonstrate that the exact solver beats local heuristics on
// adversarially constructed instances.
std::vector<ClaimId> select_authority_set_greedy(const std::vector<AuthorityRequest>& candidates,
                                                 const ArbiterView& view,
                                                 std::vector<AuthorityDecision>& out);

}  // namespace sbf
