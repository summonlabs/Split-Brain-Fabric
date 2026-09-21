#include "sbf/arbiter.hpp"

#include <algorithm>
#include <set>

#include "sbf/canonical.hpp"
#include "sbf/text.hpp"

namespace sbf {
namespace {

bool claim_precedes(const AuthorityRequest& a, const AuthorityRequest& b) noexcept {
  // Canonical preference: higher epoch first, then higher fence token, then
  // domain id, then claim id. This is a total order over candidates and is
  // independent of container order, discovery order and wall-clock time.
  if (a.epoch != b.epoch) return a.epoch > b.epoch;
  if (a.presented_fence_token != b.presented_fence_token) {
    return a.presented_fence_token > b.presented_fence_token;
  }
  if (!(a.domain == b.domain)) return a.domain < b.domain;
  return a.claim < b.claim;
}

bool mutually_exclusive(const AuthorityRequest& a, const AuthorityRequest& b) noexcept {
  if (a.mode != AuthorityMode::ExclusiveMutation || b.mode != AuthorityMode::ExclusiveMutation) {
    return false;
  }
  return a.scope.overlaps(b.scope);
}

void fail(AuthorityDecision& decision, AuthorityVerdict verdict, Outcome outcome, Reason reason,
          std::uint64_t aux = 0) {
  decision.verdict = verdict;
  decision.status = Status::make(outcome, reason, aux);
  decision.explanation.add(reason);
  decision.revocable = true;
}

}  // namespace

Status ArbiterPolicy::validate() const noexcept {
  if (policy.empty()) return Status::make(Outcome::Invalid, Reason::PolicyNotRegistered);
  if (generation.is_none()) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  if (lease_default_horizon_steps == 0 ||
      lease_default_horizon_steps > limits::kMaxLeaseHorizonSteps) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, lease_default_horizon_steps);
  }
  if (auto st = quorum.validate(); !st.is_ok()) return st;
  return Status::ok();
}

AuthorityDecision decide_authority(const AuthorityRequest& request, const ArbiterView& view) {
  AuthorityDecision decision;
  decision.decision_sequence = request.attempt_sequence;
  decision.claim = request.claim;
  decision.scope = request.scope;
  decision.vector.domain = request.domain;
  decision.vector.scope = request.scope.digest();
  decision.vector.epoch = request.epoch;
  decision.vector.incarnation = request.incarnation;
  decision.vector.fence_token = request.presented_fence_token;
  decision.vector.policy_generation =
      view.policy != nullptr ? view.policy->generation : Generation{};
  decision.vector.fence_generation = view.fences != nullptr ? view.fences->generation() : Generation{};

  // ---- structural validation -------------------------------------------------
  if (request.claim.empty()) {
    fail(decision, AuthorityVerdict::Invalid, Outcome::Invalid, Reason::ClaimNotRegistered);
    return decision;
  }
  if (request.domain.empty()) {
    fail(decision, AuthorityVerdict::Invalid, Outcome::Invalid, Reason::DomainNotRegistered);
    return decision;
  }
  if (request.scope.empty()) {
    fail(decision, AuthorityVerdict::Invalid, Outcome::Invalid, Reason::EmptyExtentSet);
    return decision;
  }
  if (request.epoch.is_none() || request.incarnation.is_none()) {
    fail(decision, AuthorityVerdict::Invalid, Outcome::Invalid, Reason::ValueOutOfRange);
    return decision;
  }
  if (request.presented_fence_token.is_none()) {
    fail(decision, AuthorityVerdict::Invalid, Outcome::Invalid, Reason::FenceTokenMissing);
    return decision;
  }
  if (view.policy == nullptr || view.fences == nullptr || view.lineage == nullptr) {
    // Without a complete view nothing can be proven, so nothing is granted.
    fail(decision, AuthorityVerdict::Unknown, Outcome::Unknown, Reason::DependencyUnreachable);
    return decision;
  }
  if (auto st = view.policy->validate(); !st.is_ok()) {
    decision.verdict = AuthorityVerdict::Unsupported;
    decision.status = Status::make(Outcome::Unsupported, st.reason, st.aux);
    decision.explanation.add(st.reason);
    return decision;
  }
  if (request.evidence.policy != view.policy->policy) {
    fail(decision, AuthorityVerdict::Stale, Outcome::Stale, Reason::PolicyGenerationMismatch);
    return decision;
  }
  if (request.evidence.policy_generation != view.policy->generation) {
    fail(decision, AuthorityVerdict::Stale, Outcome::Stale, Reason::PolicyGenerationMismatch);
    return decision;
  }
  if (!view.policy->policy.empty() && request.evidence.policy.empty()) {
    fail(decision, AuthorityVerdict::Invalid, Outcome::Invalid, Reason::PolicyNotRegistered);
    return decision;
  }

  // ---- mode gate -------------------------------------------------------------
  // Observation, eligibility, recommendation and shared read never produce
  // mutation authority, whatever the evidence says.
  if (request.mode == AuthorityMode::Observation) {
    fail(decision, AuthorityVerdict::ObserveOnly, Outcome::Ok, Reason::ObservationNotAuthority);
    decision.status = Status::ok();
    decision.explanation.add(Reason::ObservationNotAuthority);
    return decision;
  }

  // ---- epoch and lifecycle ---------------------------------------------------
  const Epoch highest_epoch = view.lineage->max_epoch(request.domain);
  if (request.epoch < highest_epoch) {
    fail(decision, AuthorityVerdict::Stale, Outcome::Stale, Reason::StaleEpoch,
         highest_epoch.value());
    return decision;
  }
  if (view.fences->incarnation_fenced(request.incarnation)) {
    fail(decision, AuthorityVerdict::Fenced, Outcome::Fenced, Reason::IncarnationFenced,
         request.incarnation.value());
    return decision;
  }
  if (view.fences->epoch_fenced(request.domain, request.epoch)) {
    fail(decision, AuthorityVerdict::Fenced, Outcome::Fenced, Reason::EpochFenced,
         request.epoch.value());
    return decision;
  }

  // ---- fence token floor -----------------------------------------------------
  for (const auto& extent : request.scope.extents()) {
    const FenceToken high = view.fences->high_water(extent);
    if (high > request.presented_fence_token) {
      decision.fenced_extents.push_back(extent);
    }
  }
  if (!decision.fenced_extents.empty()) {
    fail(decision, AuthorityVerdict::Fenced, Outcome::Fenced, Reason::TokenFloorRejected,
         decision.fenced_extents.size());
    std::sort(decision.fenced_extents.begin(), decision.fenced_extents.end());
    return decision;
  }

  // ---- evidence --------------------------------------------------------------
  const EvidenceRequest evidence_request{request.domain, request.scope.digest(), request.epoch,
                                         request.incarnation, request.presented_fence_token,
                                         view.now};
  const EvidenceAssessment assessment = assess_evidence(evidence_request, view.policy->quorum,
                                                        request.evidence, view.witness_floors);
  decision.vector.evidence_generation = assessment.floor_generation;
  switch (assessment.state) {
    case EvidenceState::Conflict:
      fail(decision, AuthorityVerdict::Conflict, Outcome::Conflict, assessment.reason,
           assessment.distinct_supporting_witnesses);
      return decision;
    case EvidenceState::Invalid:
      fail(decision, AuthorityVerdict::Invalid, Outcome::Invalid, assessment.reason);
      return decision;
    case EvidenceState::Unsupported:
      fail(decision, AuthorityVerdict::Unsupported, Outcome::Unsupported, assessment.reason);
      return decision;
    case EvidenceState::Stale:
      fail(decision, AuthorityVerdict::Stale, Outcome::Stale, assessment.reason,
           assessment.rejected_attestations);
      return decision;
    case EvidenceState::Unknown:
      if (request.mode == AuthorityMode::EligibilityProbe) {
        fail(decision, AuthorityVerdict::Stale, Outcome::Unknown, assessment.reason);
        decision.verdict = AuthorityVerdict::Eligible;
        decision.status = Status::make(Outcome::Unknown, Reason::EligibilityNotAuthorization,
                                       assessment.distinct_supporting_witnesses);
        decision.explanation.add(Reason::EligibilityNotAuthorization);
        return decision;
      }
      if (request.mode == AuthorityMode::RecommendationRequest) {
        decision.verdict = AuthorityVerdict::Recommended;
        decision.status = Status::make(Outcome::Unknown, Reason::RecommendationNotAuthority);
        decision.explanation.add(Reason::RecommendationNotAuthority);
        return decision;
      }
      fail(decision, AuthorityVerdict::Unknown, Outcome::Unknown, assessment.reason,
           assessment.distinct_supporting_witnesses);
      return decision;
    case EvidenceState::Current:
      break;
  }
  if (view.policy->require_lease_for_exclusive && request.mode == AuthorityMode::ExclusiveMutation &&
      !assessment.lease_present) {
    fail(decision, AuthorityVerdict::Refused, Outcome::Refused, Reason::LeaseMissing);
    return decision;
  }

  if (request.mode == AuthorityMode::EligibilityProbe) {
    decision.verdict = AuthorityVerdict::Eligible;
    decision.status = Status::make(Outcome::Ok, Reason::EligibilityNotAuthorization);
    decision.explanation.add(Reason::EligibilityNotAuthorization);
    return decision;
  }
  if (request.mode == AuthorityMode::RecommendationRequest) {
    decision.verdict = AuthorityVerdict::Recommended;
    decision.status = Status::make(Outcome::Ok, Reason::RecommendationNotAuthority);
    decision.explanation.add(Reason::RecommendationNotAuthority);
    return decision;
  }

  if (request.mode == AuthorityMode::SharedRead) {
    // Shared read is granted whenever the evidence is current and the scope is
    // not fenced. It is advisory: it still never permits mutation.
    decision.verdict = AuthorityVerdict::Recommended;
    decision.status = Status::make(Outcome::Ok, Reason::RecommendationNotAuthority);
    decision.explanation.add(Reason::RecommendationNotAuthority);
    return decision;
  }

  // ---- competing claims ------------------------------------------------------
  std::vector<const CompetingClaim*> overlapping;
  for (const auto& competing : view.competing) {
    if (competing.claim == request.claim) continue;
    if (!request.scope.overlaps(competing.scope)) continue;
    overlapping.push_back(&competing);
  }
  std::sort(overlapping.begin(), overlapping.end(),
            [](const CompetingClaim* a, const CompetingClaim* b) { return a->claim < b->claim; });

  for (const CompetingClaim* competing : overlapping) {
    const bool competing_exclusive = competing->mode == AuthorityMode::ExclusiveMutation;
    if (!competing_exclusive) continue;

    if (competing->epoch > request.epoch) {
      // A strictly higher epoch that carries current evidence supersedes this
      // claim. The claimant must fence this domain first; it may not proceed.
      if (competing->evidence_state == EvidenceState::Current) {
        fail(decision, AuthorityVerdict::Conflict, Outcome::Conflict, Reason::HigherEpochClaimant,
             competing->epoch.value());
        return decision;
      }
      // A higher epoch without current evidence cannot be acted on either: the
      // outcome is explicitly Unknown rather than an assumed win.
      fail(decision, AuthorityVerdict::Unknown, Outcome::Unknown, Reason::QuorumUnreachable,
           competing->epoch.value());
      return decision;
    }
    if (competing->epoch == request.epoch && competing->incarnation != request.incarnation) {
      if (view.policy->equal_epoch_conflict_is_fatal) {
        // Two incarnations claiming the same epoch for overlapping extents is
        // exactly the split brain. Both sides stay non-authoritative.
        decision.must_fence.push_back(competing->claim);
        if (competing->evidence_state == EvidenceState::Current) {
          fail(decision, AuthorityVerdict::Conflict, Outcome::Conflict, Reason::EqualEpochConflict,
               competing->epoch.value());
          decision.must_fence.push_back(request.claim);
          return decision;
        }
        fail(decision, AuthorityVerdict::Unknown, Outcome::Unknown, Reason::EqualEpochConflict,
             competing->epoch.value());
        return decision;
      }
    }
    if (competing->epoch < request.epoch) {
      // Lower epoch: this candidate supersedes it, but only after the incumbent
      // is durably fenced.
      if (view.policy->fence_lower_epoch_claimants) {
        if (competing->active) {
          decision.must_fence.push_back(competing->claim);
          fail(decision, AuthorityVerdict::Conflict, Outcome::Conflict,
               Reason::CompensatingFenceRequired, competing->epoch.value());
          return decision;
        }
        decision.must_fence.push_back(competing->claim);
      }
      continue;
    }
  }

  for (const CompetingClaim* competing : overlapping) {
    if (competing->mode != AuthorityMode::ExclusiveMutation) continue;
    if (competing->epoch == request.epoch && competing->incarnation == request.incarnation) {
      if (competing->fence_token != request.presented_fence_token) {
        fail(decision, AuthorityVerdict::Conflict, Outcome::Conflict, Reason::StoreOwnerMismatch,
             competing->fence_token.value());
        return decision;
      }
      if (competing->claim != request.claim) {
        // Same incarnation, same token, different claim identity: the authority
        // exists but is not this claim's to exercise.
        fail(decision, AuthorityVerdict::Refused, Outcome::Refused,
             Reason::OverlappingExclusiveClaim, competing->fence_token.value());
        return decision;
      }
    }
  }

  if (!overlapping.empty() && !view.policy->allow_non_overlapping_authority) {
    fail(decision, AuthorityVerdict::Conflict, Outcome::Conflict, Reason::OverlappingExclusiveClaim,
         overlapping.size());
    return decision;
  }

  // ---- grant -----------------------------------------------------------------
  decision.verdict = AuthorityVerdict::Authoritative;
  decision.status = Status::ok();
  decision.valid_from = view.now;
  decision.valid_until = assessment.lease_present ? assessment.lease_valid_until
                                                  : Step{view.now.value() + view.policy->quorum.evidence_horizon_steps};
  decision.revocable = true;
  std::sort(decision.must_fence.begin(), decision.must_fence.end());
  decision.must_fence.erase(std::unique(decision.must_fence.begin(), decision.must_fence.end()),
                            decision.must_fence.end());
  return decision;
}

RevocationCheck check_revocation(const AuthorityDecision& decision, const ArbiterView& view) {
  RevocationCheck out;
  if (!decision.is_authoritative()) {
    out.revoked = true;
    out.reason = decision.status.reason == Reason::None ? Reason::PlanInvalid : decision.status.reason;
    out.explanation.add(out.reason);
    return out;
  }
  if (view.fences == nullptr || view.lineage == nullptr || view.policy == nullptr) {
    out.revoked = true;
    out.reason = Reason::DependencyUnreachable;
    out.explanation.add(out.reason);
    return out;
  }
  if (view.policy->generation != decision.vector.policy_generation) {
    out.revoked = true;
    out.reason = Reason::PolicyGenerationMismatch;
    out.explanation.add(out.reason);
    return out;
  }
  if (view.fences->generation() != decision.vector.fence_generation) {
    // Any change to the fence table is authority-bearing: the decision must be
    // re-evaluated rather than assumed still valid.
    out.revoked = true;
    out.reason = Reason::ExtentFenced;
    out.explanation.add(out.reason);
    return out;
  }
  if (view.lineage->max_epoch(decision.vector.domain) > decision.vector.epoch) {
    out.revoked = true;
    out.reason = Reason::StaleEpoch;
    out.explanation.add(out.reason);
    return out;
  }
  if (view.fences->incarnation_fenced(decision.vector.incarnation)) {
    out.revoked = true;
    out.reason = Reason::IncarnationFenced;
    out.explanation.add(out.reason);
    return out;
  }
  if (view.now.value() > decision.valid_until.value()) {
    out.revoked = true;
    out.reason = Reason::LeaseExpired;
    out.explanation.add(out.reason);
    return out;
  }
  for (const auto& competing : view.competing) {
    if (competing.mode != AuthorityMode::ExclusiveMutation) continue;
    if (competing.epoch <= decision.vector.epoch) continue;
    if (competing.evidence_state != EvidenceState::Current) continue;
    if (competing.domain == decision.vector.domain) continue;
    if (!view.lineage->grants().empty()) {
      // Scope overlap is decided against the decision's own scope, which the
      // caller supplies through the view by way of the competing claim.
      out.explanation.add(Reason::HigherEpochClaimant);
    }
    out.revoked = true;
    out.reason = Reason::HigherEpochClaimant;
    return out;
  }
  return out;
}

}  // namespace sbf
