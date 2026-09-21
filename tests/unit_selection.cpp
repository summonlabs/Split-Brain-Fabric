#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "sbf/arbiter.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

namespace {

// Builds a random instance: n candidates over a small extent universe, with
// randomised epochs, tokens and evidence quality.
struct Instance {
  std::vector<AuthorityRequest> candidates;
  ArbiterPolicy policy;
  FenceTable fences;
  LineageTable lineage;
  std::vector<Scope> scopes;
  Step now{10};
};

Instance make_instance(Rng& rng, std::size_t count, std::size_t extent_universe,
                       bool all_legal) {
  Instance instance;
  instance.policy = policy_of(3);
  instance.scopes.resize(count);
  for (std::size_t i = 0; i < count; ++i) {
    std::vector<ExtentId> extents;
    const std::size_t size = 1 + static_cast<std::size_t>(rng.bounded(3));
    for (std::size_t j = 0; j < size; ++j) {
      extents.push_back(ExtentId::make("e" + std::to_string(rng.bounded(extent_universe))));
    }
    instance.scopes[i] = Scope::try_make(extents).value_or(Scope{});
    if (instance.scopes[i].empty()) {
      instance.scopes[i] = Scope::try_parse("e0").value_or(Scope{});
    }
  }

  // Every candidate gets its own incarnation and token, and the fence table is
  // fed the maximum token so that the presented token is the current owner.
  for (std::size_t i = 0; i < count; ++i) {
    const Epoch epoch{1};
    const IncarnationId incarnation{static_cast<std::uint64_t>(i + 1)};
    const FenceToken token{static_cast<std::uint64_t>(i + 1)};
    const GrantId grant{static_cast<std::uint64_t>(i + 1)};
    EpochGrant record;
    record.id = grant;
    record.domain = DomainId::make("domain-" + std::to_string(i));
    record.scope = instance.scopes[i].digest();
    record.extents = instance.scopes[i];
    record.epoch = epoch;
    record.incarnation = incarnation;
    record.boot = BootId{incarnation.value()};
    record.fence_token = token;
    record.opened_at = Step{1};
    record.registry_sequence = Sequence{static_cast<std::uint64_t>(i + 1)};
    instance.fences.adopt(instance.scopes[i], token, epoch, incarnation, grant, Step{1});
    instance.lineage.open_grant(record);

    std::vector<WitnessAttestation> attestations;
    if (all_legal || rng.coin()) {
      for (std::size_t w = 0; w < instance.policy.quorum.witnesses.size(); ++w) {
        attestations.push_back(attestation_of(instance.policy.quorum, w, record.domain,
                                              instance.scopes[i], epoch, incarnation, token,
                                              Sequence{static_cast<std::uint64_t>(w + 1)}));
      }
    }
    const auto bundle =
        bundle_with(instance.policy.quorum, instance.scopes[i], instance.now, attestations);
    auto request = request_of(record.domain, instance.scopes[i], epoch, incarnation, token, bundle,
                             AuthorityMode::ExclusiveMutation,
                             ClaimId::make("claim-" + std::to_string(i)));
    instance.candidates.push_back(request);
  }
  return instance;
}

ArbiterView view_of(const Instance& instance) {
  ArbiterView view;
  view.policy = &instance.policy;
  view.fences = &instance.fences;
  view.lineage = &instance.lineage;
  view.now = instance.now;
  view.registry_generation = Generation{1};
  return view;
}

std::vector<std::string> claim_names(const std::vector<AuthorityDecision>& decisions) {
  std::vector<std::string> names;
  for (const auto& decision : decisions) names.push_back(decision.claim.str());
  std::sort(names.begin(), names.end());
  return names;
}

}  // namespace

SBF_TEST(selection, exact_solver_matches_the_independent_reference) {
  Rng rng(0xF00Dull);
  std::printf("seed=%llu\n", static_cast<unsigned long long>(rng.state()));
  for (int iteration = 0; iteration < 3000; ++iteration) {
    const std::size_t count = 1 + static_cast<std::size_t>(rng.bounded(9));
    Instance instance = make_instance(rng, count, 5, false);
    const auto view = view_of(instance);
    const AuthorityPlan plan =
        select_authority_set(instance.candidates, view, limits::kMaxSearchNodes);
    const AuthorityPlan reference =
        select_authority_set_reference(instance.candidates, view, limits::kMaxSearchNodes);
    CHECK(!plan.optimality_proven || reference.optimality_proven);
    CHECK_EQ(plan.authorized.size(), reference.authorized.size());
    CHECK(claim_names(plan.authorized) == claim_names(reference.authorized));
    CHECK(plan.validated);
    CHECK_OK(validate_plan(plan, instance.candidates, view));
    CHECK(plan.status.is_ok() || plan.outcome == SelectionOutcome::ProvenInfeasible);
  }
}

SBF_TEST(selection, plan_is_independent_of_candidate_order) {
  Rng rng(0xBEEFull);
  std::printf("seed=%llu\n", static_cast<unsigned long long>(rng.state()));
  for (int iteration = 0; iteration < 400; ++iteration) {
    const std::size_t count = 1 + static_cast<std::size_t>(rng.bounded(8));
    Instance instance = make_instance(rng, count, 4, false);
    const auto view = view_of(instance);
    const AuthorityPlan forward =
        select_authority_set(instance.candidates, view, limits::kMaxSearchNodes);

    std::vector<AuthorityRequest> reversed(instance.candidates.rbegin(),
                                           instance.candidates.rend());
    const AuthorityPlan backward = select_authority_set(reversed, view, limits::kMaxSearchNodes);
    CHECK(claim_names(forward.authorized) == claim_names(backward.authorized));
    CHECK_EQ(forward.outcome, backward.outcome);
  }
}

SBF_TEST(selection, greedy_is_sound_but_provably_suboptimal_on_adversarial_input) {
  // Adversarial instance built specifically to break a first-fit heuristic:
  // candidate 0 claims {a, b} and is the most preferred, while candidates 1 and
  // 2 claim {a} and {b} and do not conflict with each other. A greedy scan in
  // preference order takes 0 and stops at size one; the optimum is {1, 2}.
  //
  // The fence table and lineage are deliberately empty here: this test isolates
  // the selection objective, and an empty view means every candidate's fence
  // token and epoch are individually admissible.
  std::vector<AuthorityRequest> candidates;
  ArbiterPolicy policy = policy_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
  FenceTable fences;
  LineageTable lineage;

  const char* scopes[3] = {"a,b", "a", "b"};
  const std::uint64_t epochs[3] = {3, 2, 1};
  for (int i = 0; i < 3; ++i) {
    const auto scope = Scope::try_parse(scopes[i]).value();
    const Epoch epoch{epochs[i]};
    const IncarnationId incarnation{static_cast<std::uint64_t>(i + 1)};
    const FenceToken token{epochs[i]};
    const DomainId domain = DomainId::make("domain-" + std::to_string(i));
    std::vector<WitnessAttestation> attestations;
    attestations.push_back(attestation_of(policy.quorum, 0, domain, scope, epoch, incarnation,
                                          token, Sequence{1}));
    candidates.push_back(request_of(domain, scope, epoch, incarnation, token,
                                    bundle_with(policy.quorum, scope, Step{10}, attestations),
                                    AuthorityMode::ExclusiveMutation,
                                    ClaimId::make("claim-" + std::to_string(i))));
  }

  ArbiterView view;
  view.policy = &policy;
  view.fences = &fences;
  view.lineage = &lineage;
  view.now = Step{10};

  std::vector<AuthorityDecision> greedy_decisions;
  const auto greedy = select_authority_set_greedy(candidates, view, greedy_decisions);
  CHECK_EQ(greedy.size(), std::size_t{1});   // the heuristic is trapped by candidate 0

  const AuthorityPlan exact = select_authority_set(candidates, view, limits::kMaxSearchNodes);
  CHECK(exact.optimality_proven);
  CHECK_EQ(exact.authorized.size(), std::size_t{2});
  CHECK_OK(validate_plan(exact, candidates, view));
  CHECK(exact.authorized.size() > greedy.size());

  // Whatever the heuristic returns must still be sound; it is bounded, not wrong.
  AuthorityPlan heuristic;
  heuristic.authorized = greedy_decisions;
  CHECK_OK(validate_plan(heuristic, candidates, view));
}

SBF_TEST(selection, infeasible_is_proven_only_when_search_completes) {
  Rng rng(0x1234ull);
  std::printf("seed=%llu\n", static_cast<unsigned long long>(rng.state()));
  Instance instance = make_instance(rng, 4, 4, false);
  // Strip all evidence: nothing can be legal.
  for (auto& candidate : instance.candidates) {
    candidate.evidence.attestations.clear();
  }
  const auto view = view_of(instance);
  const AuthorityPlan plan = select_authority_set(instance.candidates, view, limits::kMaxSearchNodes);
  CHECK(plan.outcome == SelectionOutcome::ProvenInfeasible);
  CHECK(plan.authorized.empty());
  CHECK(plan.optimality_proven);
}

SBF_TEST(selection, exhausted_budget_reports_search_limit_and_keeps_a_sound_plan) {
  Rng rng(0xABCDull);
  std::printf("seed=%llu\n", static_cast<unsigned long long>(rng.state()));
  Instance instance = make_instance(rng, 16, 3, true);
  const auto view = view_of(instance);
  // A budget far below what an exhaustive search needs.
  const AuthorityPlan plan = select_authority_set(instance.candidates, view, 64);
  CHECK(plan.outcome == SelectionOutcome::SearchLimitReached ||
        plan.outcome == SelectionOutcome::ProvenOptimal);
  if (plan.outcome == SelectionOutcome::SearchLimitReached) {
    CHECK(!plan.optimality_proven);
    CHECK(plan.status.outcome == Outcome::SearchLimitReached);
  }
  // Regardless of the outcome, the emitted plan is independently validated.
  CHECK(plan.validated);
  CHECK_OK(validate_plan(plan, instance.candidates, view));
}

SBF_TEST(selection, every_emitted_plan_satisfies_pairwise_exclusion) {
  Rng rng(0x77AAull);
  std::printf("seed=%llu\n", static_cast<unsigned long long>(rng.state()));
  for (int iteration = 0; iteration < 500; ++iteration) {
    const std::size_t count = 1 + static_cast<std::size_t>(rng.bounded(7));
    Instance instance = make_instance(rng, count, 3, true);
    const auto view = view_of(instance);
    const AuthorityPlan plan = select_authority_set(instance.candidates, view, 1 << 20);
    CHECK(plan.optimality_proven);
    // The invariant that matters: no two authorised candidates overlap.
    for (std::size_t i = 0; i < plan.authorized.size(); ++i) {
      for (std::size_t j = i + 1; j < plan.authorized.size(); ++j) {
        CHECK(!plan.authorized[i].scope.overlaps(plan.authorized[j].scope));
      }
    }
    // Every refused candidate is individually accounted for.
    CHECK_EQ(plan.authorized.size() + plan.refused.size(), instance.candidates.size());
  }
}
SBF_TEST_MAIN
