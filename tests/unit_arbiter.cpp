#include <algorithm>
#include <string>
#include <vector>

#include "sbf/arbiter.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

SBF_TEST(arbiter, grants_authority_only_with_current_quorum_evidence) {
  Fixture fixture;
  const auto view = fixture.view();
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, fixture.full_evidence());
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.is_authoritative());
  CHECK(verdict_permits_mutation(decision.verdict));
  CHECK_EQ(decision.vector.fence_token.value(), fixture.token.value());
  CHECK_EQ(decision.vector.epoch.value(), fixture.epoch.value());
  CHECK_EQ(decision.scope.csv(), fixture.scope.csv());
  CHECK(!decision.claim.empty());
  // Decisions are pure: the same inputs give a byte-identical digest.
  CHECK(decide_authority(request, view).digest() == decision.digest());
}

SBF_TEST(arbiter, insufficient_witnesses_is_unknown_and_never_authority) {
  Fixture fixture;  // majority of three requires two
  const auto view = fixture.view();
  std::vector<WitnessAttestation> one;
  one.push_back(attestation_of(fixture.policy.quorum, 0, fixture.domain, fixture.scope,
                               fixture.epoch, fixture.incarnation, fixture.token, Sequence{1}));
  const auto bundle = bundle_with(fixture.policy.quorum, fixture.scope, view.now, one);
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, bundle);
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.verdict == AuthorityVerdict::Unknown);
  CHECK(decision.status.outcome == Outcome::Unknown);
  CHECK(!verdict_permits_mutation(decision.verdict));
  CHECK(decision.explanation.contains(Reason::InsufficientDistinctWitnesses));
}

SBF_TEST(arbiter, no_evidence_at_all_is_unknown_not_absence) {
  Fixture fixture;
  const auto view = fixture.view();
  const auto bundle = bundle_with(fixture.policy.quorum, fixture.scope, view.now, {});
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, bundle);
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.verdict == AuthorityVerdict::Unknown);
  CHECK(!verdict_permits_mutation(decision.verdict));
}

SBF_TEST(arbiter, conflicting_attestations_are_a_conflict_not_a_majority) {
  Fixture fixture;
  const auto view = fixture.view();
  std::vector<WitnessAttestation> attestations;
  attestations.push_back(attestation_of(fixture.policy.quorum, 0, fixture.domain, fixture.scope,
                                        fixture.epoch, fixture.incarnation, fixture.token,
                                        Sequence{1}));
  WitnessAttestation dissent = attestation_of(fixture.policy.quorum, 1, fixture.domain,
                                              fixture.scope, fixture.epoch, fixture.incarnation,
                                              fixture.token, Sequence{2});
  dissent.support = false;
  attestations.push_back(dissent);
  attestations.push_back(attestation_of(fixture.policy.quorum, 2, fixture.domain, fixture.scope,
                                        fixture.epoch, fixture.incarnation, fixture.token,
                                        Sequence{3}));
  const auto bundle = bundle_with(fixture.policy.quorum, fixture.scope, view.now, attestations);
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, bundle);
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.verdict == AuthorityVerdict::Conflict);
  CHECK(!verdict_permits_mutation(decision.verdict));
}

SBF_TEST(arbiter, duplicate_witness_messages_never_inflate_the_quorum) {
  Fixture fixture;
  const auto view = fixture.view();
  std::vector<WitnessAttestation> attestations;
  // The same witness three times, at three different sequences.
  for (std::uint64_t sequence = 1; sequence <= 3; ++sequence) {
    attestations.push_back(attestation_of(fixture.policy.quorum, 0, fixture.domain, fixture.scope,
                                          fixture.epoch, fixture.incarnation, fixture.token,
                                          Sequence{sequence}));
  }
  const auto bundle = bundle_with(fixture.policy.quorum, fixture.scope, view.now, attestations);
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, bundle);
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(!decision.is_authoritative());
  CHECK(decision.verdict == AuthorityVerdict::Unknown);

  // An exact replay of the same (witness, sequence) is counted and dropped.
  std::vector<WitnessAttestation> replayed = attestations;
  replayed.push_back(attestations[2]);
  const EvidenceRequest evidence_request{fixture.domain, fixture.scope.digest(), fixture.epoch,
                                         fixture.incarnation, fixture.token, view.now};
  const EvidenceAssessment assessment =
      assess_evidence(evidence_request, fixture.policy.quorum,
                      bundle_with(fixture.policy.quorum, fixture.scope, view.now, replayed), {});
  CHECK(assessment.replayed_attestations >= 1);
  CHECK_EQ(assessment.distinct_supporting_witnesses, std::uint32_t{1});
}

SBF_TEST(arbiter, assessment_is_independent_of_attestation_order) {
  Fixture fixture;
  const auto view = fixture.view();
  const auto bundle = fixture.full_evidence();
  std::vector<WitnessAttestation> reversed(bundle.attestations.rbegin(), bundle.attestations.rend());
  const EvidenceRequest evidence_request{fixture.domain, fixture.scope.digest(), fixture.epoch,
                                         fixture.incarnation, fixture.token, view.now};
  const auto forward = assess_evidence(evidence_request, fixture.policy.quorum, bundle, {});
  const auto backward = assess_evidence(
      evidence_request, fixture.policy.quorum,
      bundle_with(fixture.policy.quorum, fixture.scope, view.now, reversed), {});
  CHECK(forward.state == backward.state);
  CHECK_EQ(forward.distinct_supporting_witnesses, backward.distinct_supporting_witnesses);
  CHECK_EQ(forward.floor_generation.value(), backward.floor_generation.value());
}

SBF_TEST(arbiter, stale_epoch_and_fenced_incarnation_are_refused) {
  Fixture fixture;
  auto view = fixture.view();
  // A grant that has been superseded.
  const EpochGrant* open = fixture.lineage.open_grant_for(fixture.domain, fixture.scope.digest());
  CHECK(open != nullptr);
  CHECK_OK(fixture.lineage.close_grant(fixture.grant, GrantState::Fenced,
                                       Reason::CompensatingFenceRequired, Step{5}));
  EpochGrant newer = *open;
  newer.state = GrantState::Open;
  newer.id = GrantId{2};
  newer.epoch = Epoch{2};
  newer.incarnation = IncarnationId{3};
  newer.fence_token = FenceToken{2};
  newer.registry_sequence = Sequence{2};
  CHECK_OK(fixture.lineage.open_grant(newer));
  view = fixture.view();

  const auto stale = request_of(fixture.domain, fixture.scope, fixture.epoch, fixture.incarnation,
                                fixture.token, fixture.full_evidence());
  const AuthorityDecision stale_decision = decide_authority(stale, view);
  CHECK(stale_decision.verdict == AuthorityVerdict::Stale);
  CHECK(stale_decision.explanation.contains(Reason::StaleEpoch));

  // Raise the durable high-water mark for the scope without fencing the new
  // incarnation: the new epoch presented under the *old* token must then be
  // refused by the token floor.
  FenceRecord raised;
  raised.token = FenceToken{2};
  raised.domain = fixture.domain;
  raised.scope = fixture.scope.digest();
  raised.fenced_epoch = Epoch{1};
  raised.fenced_incarnation = IncarnationId{2};   // the superseded incarnation
  raised.issued_at = Step{5};
  CHECK_OK(fixture.fences.apply(raised, fixture.scope));
  view = fixture.view();
  const auto stale_token = request_of(fixture.domain, fixture.scope, Epoch{2}, IncarnationId{3},
                                      fixture.token, fixture.full_evidence());
  const AuthorityDecision token_decision = decide_authority(stale_token, view);
  CHECK(token_decision.verdict == AuthorityVerdict::Fenced);
  CHECK(token_decision.explanation.contains(Reason::TokenFloorRejected));

  // A fenced incarnation can never come back.
  FenceRecord record;
  record.token = FenceToken{4};
  record.domain = fixture.domain;
  record.scope = fixture.scope.digest();
  record.fenced_epoch = Epoch{2};
  record.fenced_incarnation = IncarnationId{3};
  record.issued_at = Step{6};
  CHECK_OK(fixture.fences.apply(record, fixture.scope));
  view = fixture.view();
  const auto fenced = request_of(fixture.domain, fixture.scope, Epoch{2}, IncarnationId{3},
                                 FenceToken{3}, fixture.full_evidence());
  const AuthorityDecision fenced_decision = decide_authority(fenced, view);
  CHECK(fenced_decision.verdict == AuthorityVerdict::Fenced);
  CHECK(fenced_decision.explanation.contains(Reason::IncarnationFenced));
}

SBF_TEST(arbiter, observation_eligibility_and_recommendation_never_authorize) {
  Fixture fixture;
  const auto view = fixture.view();
  for (const auto mode : {AuthorityMode::Observation, AuthorityMode::EligibilityProbe,
                          AuthorityMode::RecommendationRequest, AuthorityMode::SharedRead}) {
    const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                    fixture.incarnation, fixture.token, fixture.full_evidence(),
                                    mode);
    const AuthorityDecision decision = decide_authority(request, view);
    CHECK(!verdict_carries_authority(decision.verdict));
    CHECK(!verdict_permits_mutation(decision.verdict));
  }
}

SBF_TEST(arbiter, applied_is_not_authority) {
  CHECK(!verdict_carries_authority(AuthorityVerdict::Applied));
  CHECK(!verdict_permits_mutation(AuthorityVerdict::Applied));
  CHECK(!verdict_permits_mutation(AuthorityVerdict::Acknowledged));
  CHECK(verdict_permits_mutation(AuthorityVerdict::Authoritative));
}

SBF_TEST(arbiter, equal_epoch_two_incarnations_conflict_for_both_sides) {
  Fixture fixture;
  Scope overlapping = Scope::try_parse("p3,p4").value_or(Scope{});
  CompetingClaim competing;
  competing.claim = ClaimId::make("claim-b");
  competing.domain = DomainId::make("domain-b");
  competing.scope = overlapping;
  competing.epoch = fixture.epoch;   // the same epoch, a different incarnation
  competing.incarnation = IncarnationId{9};
  competing.fence_token = FenceToken{9};
  competing.grant = GrantId{9};
  competing.mode = AuthorityMode::ExclusiveMutation;
  competing.evidence_state = EvidenceState::Current;
  competing.active = true;
  auto view = fixture.view();
  view.competing.push_back(competing);

  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, fixture.full_evidence());
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(!decision.is_authoritative());
  CHECK(decision.verdict == AuthorityVerdict::Conflict);
  CHECK(decision.explanation.contains(Reason::EqualEpochConflict));
  // Both sides are named as requiring a fence: neither is allowed to act.
  CHECK(std::find(decision.must_fence.begin(), decision.must_fence.end(),
                  ClaimId::make("claim-b")) != decision.must_fence.end());
}

SBF_TEST(arbiter, higher_epoch_claimant_blocks_and_unknown_claimant_is_not_a_win) {
  Fixture fixture;
  Scope overlapping = Scope::try_parse("p1").value_or(Scope{});
  CompetingClaim competing;
  competing.claim = ClaimId::make("claim-b");
  competing.domain = DomainId::make("domain-b");
  competing.scope = overlapping;
  competing.epoch = Epoch{9};
  competing.incarnation = IncarnationId{9};
  competing.fence_token = FenceToken{9};
  competing.grant = GrantId{9};
  competing.mode = AuthorityMode::ExclusiveMutation;
  competing.active = true;

  auto view = fixture.view();
  competing.evidence_state = EvidenceState::Current;
  view.competing.push_back(competing);
  auto request = request_of(fixture.domain, fixture.scope, fixture.epoch, fixture.incarnation,
                            fixture.token, fixture.full_evidence());
  AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.verdict == AuthorityVerdict::Conflict);
  CHECK(decision.explanation.contains(Reason::HigherEpochClaimant));

  // The same competitor without current evidence cannot be assumed to have lost
  // either: the outcome is explicitly UNKNOWN.
  competing.evidence_state = EvidenceState::Unknown;
  view.competing.clear();
  view.competing.push_back(competing);
  decision = decide_authority(request, view);
  CHECK(decision.verdict == AuthorityVerdict::Unknown);
  CHECK(!decision.is_authoritative());
}

SBF_TEST(arbiter, non_overlapping_domains_may_remain_authoritative) {
  Fixture fixture;
  CompetingClaim competing;
  competing.claim = ClaimId::make("claim-b");
  competing.domain = DomainId::make("domain-b");
  competing.scope = Scope::try_parse("p9,p10").value_or(Scope{});
  competing.epoch = Epoch{9};
  competing.incarnation = IncarnationId{9};
  competing.fence_token = FenceToken{9};
  competing.grant = GrantId{9};
  competing.mode = AuthorityMode::ExclusiveMutation;
  competing.evidence_state = EvidenceState::Current;
  competing.active = true;
  auto view = fixture.view();
  view.competing.push_back(competing);
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, fixture.full_evidence());
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.is_authoritative());
}

SBF_TEST(arbiter, wall_clock_fields_never_change_a_decision) {
  Fixture fixture;
  const auto view = fixture.view();
  Rng rng(0x51DEull);
  std::printf("seed=%llu\n", static_cast<unsigned long long>(rng.state()));
  auto request = request_of(fixture.domain, fixture.scope, fixture.epoch, fixture.incarnation,
                            fixture.token, fixture.full_evidence());
  request.requested_at.unix_nanos = 0;
  const Digest256 baseline = decide_authority(request, view).digest();
  for (int i = 0; i < 2000; ++i) {
    auto perturbed = request;
    perturbed.requested_at.unix_nanos = static_cast<std::int64_t>(rng.next());
    perturbed.requested_at.observed_regression = rng.coin();
    for (auto& attestation : perturbed.evidence.attestations) {
      attestation.observed_at.unix_nanos = static_cast<std::int64_t>(rng.next());
      attestation.observed_at.observed_regression = rng.coin();
    }
    const AuthorityDecision decision = decide_authority(perturbed, view);
    // Wall-clock perturbation may change the diagnostic fields but must never
    // change the verdict, the bound generations or the decision digest.
    CHECK(decision.digest() == baseline);
    CHECK(decision.verdict == AuthorityVerdict::Authoritative);
  }
}

SBF_TEST(arbiter, policy_generation_change_is_stale_not_silently_accepted) {
  Fixture fixture;
  auto view = fixture.view();
  auto request = request_of(fixture.domain, fixture.scope, fixture.epoch, fixture.incarnation,
                            fixture.token, fixture.full_evidence());
  request.evidence.policy_generation = Generation{99};
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.verdict == AuthorityVerdict::Stale);
  CHECK(decision.explanation.contains(Reason::PolicyGenerationMismatch));
}

SBF_TEST(arbiter, missing_view_is_unknown_not_authority) {
  Fixture fixture;
  ArbiterView empty;
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, fixture.full_evidence());
  const AuthorityDecision decision = decide_authority(request, empty);
  CHECK(decision.verdict == AuthorityVerdict::Unknown);
  CHECK(!decision.is_authoritative());
}

SBF_TEST(arbiter, revocation_fires_whenever_an_authority_bearing_dependency_changes) {
  Fixture fixture;
  const auto view = fixture.view();
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, fixture.full_evidence());
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.is_authoritative());
  CHECK(!check_revocation(decision, view).revoked);

  // A policy change revokes.
  auto changed = view;
  ArbiterPolicy new_policy = fixture.policy;
  new_policy.generation = Generation{2};
  changed.policy = &new_policy;
  auto check = check_revocation(decision, changed);
  CHECK(check.revoked);
  CHECK(check.reason == Reason::PolicyGenerationMismatch);

  // A fence-table change revokes.
  auto fenced = fixture;
  FenceRecord record;
  record.token = FenceToken{50};
  record.domain = fixture.domain;
  record.scope = fixture.scope.digest();
  record.fenced_epoch = fixture.epoch;
  record.fenced_incarnation = fixture.incarnation;
  record.issued_at = Step{7};
  CHECK_OK(fenced.fences.apply(record, fixture.scope));
  check = check_revocation(decision, fenced.view());
  CHECK(check.revoked);

  // A newer epoch revokes.
  auto advanced = fixture;
  EpochGrant newer = *fixture.lineage.open_grant_for(fixture.domain, fixture.scope.digest());
  CHECK_OK(advanced.lineage.close_grant(fixture.grant, GrantState::Fenced,
                                        Reason::CompensatingFenceRequired, Step{9}));
  newer.id = GrantId{2};
  newer.epoch = Epoch{5};
  newer.incarnation = IncarnationId{8};
  newer.fence_token = FenceToken{60};
  newer.registry_sequence = Sequence{3};
  CHECK_OK(advanced.lineage.open_grant(newer));
  check = check_revocation(decision, advanced.view());
  CHECK(check.revoked);
  CHECK(check.reason == Reason::StaleEpoch);
}

SBF_TEST(arbiter, expired_window_revokes) {
  Fixture fixture;
  auto view = fixture.view();
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, fixture.full_evidence());
  AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.is_authoritative());
  CHECK(decision.valid_until.is_set());
  view.now = Step{decision.valid_until.value() + 1};
  const auto check = check_revocation(decision, view);
  CHECK(check.revoked);
  CHECK(check.reason == Reason::LeaseExpired);
}
SBF_TEST_MAIN
