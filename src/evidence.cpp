#include "sbf/evidence.hpp"

#include <algorithm>
#include <map>

namespace sbf {
namespace {

// Canonical ordering over attestations: witness, then epoch, incarnation and
// sequence. Assessment is performed on the sorted set so that the verdict can
// never depend on the order in which a coordinator happened to collect them.
bool attestation_less(const WitnessAttestation& a, const WitnessAttestation& b) noexcept {
  if (auto c = a.witness <=> b.witness; c != 0) return c < 0;
  if (auto c = a.epoch <=> b.epoch; c != 0) return c < 0;
  if (auto c = a.incarnation <=> b.incarnation; c != 0) return c < 0;
  if (auto c = a.witness_sequence <=> b.witness_sequence; c != 0) return c < 0;
  if (auto c = a.witness_generation <=> b.witness_generation; c != 0) return c < 0;
  return a.fence_token < b.fence_token;
}

}  // namespace

std::string_view to_string(EvidenceState state) noexcept {
  switch (state) {
    case EvidenceState::Current: return "CURRENT";
    case EvidenceState::Stale: return "STALE";
    case EvidenceState::Unknown: return "UNKNOWN";
    case EvidenceState::Conflict: return "CONFLICT";
    case EvidenceState::Invalid: return "INVALID";
    case EvidenceState::Unsupported: return "UNSUPPORTED";
  }
  return "UNKNOWN";
}

std::string_view to_string(QuorumMode mode) noexcept {
  switch (mode) {
    case QuorumMode::MajorityDistinctWitnesses: return "majority";
    case QuorumMode::ThresholdDistinctWitnesses: return "threshold";
    case QuorumMode::UnanimousWitnesses: return "unanimous";
  }
  return "unknown";
}

std::uint32_t QuorumProfile::required_witnesses() const noexcept {
  const auto count = static_cast<std::uint32_t>(witnesses.size());
  switch (mode) {
    case QuorumMode::MajorityDistinctWitnesses:
      return count == 0 ? 0 : (count / 2) + 1;
    case QuorumMode::ThresholdDistinctWitnesses:
      return threshold;
    case QuorumMode::UnanimousWitnesses:
      return count;
  }
  return count;
}

Status QuorumProfile::validate() const noexcept {
  if (policy.empty()) return Status::make(Outcome::Invalid, Reason::PolicyNotRegistered);
  if (generation.is_none()) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  if (witnesses.empty()) return Status::make(Outcome::Invalid, Reason::NoAttestations);
  if (witnesses.size() > limits::kMaxWitnessesPerProfile) {
    return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, witnesses.size());
  }
  for (std::size_t i = 0; i < witnesses.size(); ++i) {
    if (witnesses[i].witness.empty() || witnesses[i].fault_domain.empty()) {
      return Status::make(Outcome::Invalid, Reason::EmptyValue, i);
    }
    if (i > 0 && !(witnesses[i - 1] < witnesses[i])) {
      return Status::make(Outcome::Invalid, Reason::DuplicateEntry, i);
    }
  }
  const std::uint32_t required = required_witnesses();
  if (required == 0 || required > witnesses.size()) {
    return Status::make(Outcome::Invalid, Reason::InsufficientDistinctWitnesses, required);
  }
  if (min_fault_domains == 0 || min_fault_domains > witnesses.size()) {
    return Status::make(Outcome::Invalid, Reason::InsufficientFaultDomains, min_fault_domains);
  }
  if (evidence_horizon_steps == 0 || evidence_horizon_steps > limits::kMaxLeaseHorizonSteps) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, evidence_horizon_steps);
  }
  return Status::ok();
}

EvidenceAssessment assess_evidence(const EvidenceRequest& request, const QuorumProfile& profile,
                                   const EvidenceBundle& bundle,
                                   const std::vector<WitnessFloor>& floors) {
  EvidenceAssessment out;
  out.required_witnesses = profile.required_witnesses();
  out.state = EvidenceState::Unknown;
  out.reason = Reason::NoAttestations;
  out.outcome = Outcome::Unknown;

  if (auto st = profile.validate(); !st.is_ok()) {
    out.state = EvidenceState::Invalid;
    out.status = st;
    out.outcome = Outcome::Invalid;
    out.reason = st.reason;
    return out;
  }

  if (bundle.policy.empty() || bundle.policy != profile.policy) {
    out.state = EvidenceState::Invalid;
    out.status = Status::make(Outcome::Invalid, Reason::PolicyNotRegistered);
    out.outcome = Outcome::Invalid;
    out.reason = Reason::PolicyNotRegistered;
    return out;
  }
  if (bundle.policy_generation != profile.generation) {
    out.state = EvidenceState::Stale;
    out.status = Status::make(Outcome::Stale, Reason::PolicyGenerationMismatch);
    out.outcome = Outcome::Stale;
    out.reason = Reason::PolicyGenerationMismatch;
    return out;
  }
  if (bundle.attestations.size() > limits::kMaxAttestationsPerBundle) {
    out.state = EvidenceState::Invalid;
    out.status = Status::make(Outcome::Exhausted, Reason::BoundedTableFull, bundle.attestations.size());
    out.outcome = Outcome::Exhausted;
    out.reason = Reason::BoundedTableFull;
    return out;
  }

  // Floors: a witness may not be replayed below a sequence the verifier has
  // already accepted.
  std::map<WitnessId, WitnessFloor> floor_by_witness;
  for (const auto& floor : floors) floor_by_witness[floor.witness] = floor;

  std::vector<WitnessAttestation> sorted = bundle.attestations;
  std::sort(sorted.begin(), sorted.end(), attestation_less);

  std::map<WitnessId, FaultDomainId> fault_domains;
  for (const auto& slot : profile.witnesses) fault_domains[slot.witness] = slot.fault_domain;

  // Per witness, only the highest-sequence statement in the bundle is
  // considered: a refreshed statement supersedes an older one, and every other
  // occurrence is a duplicate or a replay. This makes the assessment a function
  // of the statement *set* rather than of arrival order, and it means one
  // witness can never contribute more than one supporting statement.
  std::map<WitnessId, std::size_t> latest_index;
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    const auto it = latest_index.find(sorted[i].witness);
    if (it == latest_index.end() || sorted[i].witness_sequence > sorted[it->second].witness_sequence) {
      latest_index[sorted[i].witness] = i;
    }
  }

  std::map<WitnessId, bool> seen_support;
  std::map<WitnessId, Sequence> seen_sequence;
  std::map<FaultDomainId, bool> supporting_domains;
  bool any_conflict = false;
  bool any_stale = false;
  bool any_unknown = false;
  bool any_invalid = false;
  bool generation_mismatch = false;
  bool lease_present = false;
  Step earliest_expiry = Step::max();
  Generation floor_generation = Generation::max();
  Generation ceiling_generation;

  for (std::size_t index = 0; index < sorted.size(); ++index) {
    const WitnessAttestation& attestation = sorted[index];
    if (attestation.witness.empty()) {
      ++out.rejected_attestations;
      any_invalid = true;
      continue;
    }
    {
      const auto latest = latest_index.find(attestation.witness);
      if (latest != latest_index.end() && latest->second != index) {
        // Superseded by a newer statement from the same witness in this bundle.
        ++out.duplicate_attestations;
        ++out.replayed_attestations;
        continue;
      }
    }
    const auto domain_it = fault_domains.find(attestation.witness);
    if (domain_it == fault_domains.end()) {
      // A statement from a witness that is not part of the profile is not
      // evidence for the profile, and it is not silently ignored: it is counted.
      ++out.rejected_attestations;
      any_unknown = true;
      continue;
    }
    const auto floor_it = floor_by_witness.find(attestation.witness);
    if (floor_it != floor_by_witness.end() && attestation.witness_sequence <= floor_it->second.sequence) {
      ++out.replayed_attestations;
      ++out.rejected_attestations;
      any_stale = true;
      continue;
    }

    // Identity alone never establishes currentness: every binding is compared.
    if (!(attestation.subject_scope == request.scope)) {
      ++out.rejected_attestations;
      any_invalid = true;
      continue;
    }
    if (!(attestation.subject_domain == request.domain)) {
      ++out.rejected_attestations;
      any_invalid = true;
      continue;
    }
    if (attestation.epoch != request.epoch) {
      ++out.rejected_attestations;
      any_stale = true;
      continue;
    }
    if (attestation.incarnation != request.incarnation) {
      ++out.rejected_attestations;
      any_invalid = true;
      continue;
    }
    if (attestation.fence_token != request.fence_token) {
      ++out.rejected_attestations;
      any_stale = true;
      continue;
    }
    if (attestation.policy_generation != profile.generation) {
      ++out.rejected_attestations;
      generation_mismatch = true;
      continue;
    }
    if (attestation.witness_generation.is_none()) {
      ++out.rejected_attestations;
      any_invalid = true;
      continue;
    }
    if (attestation.valid_until.value() < request.as_of.value()) {
      seen_sequence[attestation.witness] = attestation.witness_sequence;
      ++out.rejected_attestations;
      any_stale = true;
      continue;
    }
    if (attestation.issued_at.value() > request.as_of.value()) {
      // Issued in the verifier's future: cannot be evaluated, so it is UNKNOWN
      // rather than accepted.
      ++out.rejected_attestations;
      any_unknown = true;
      continue;
    }

    seen_sequence[attestation.witness] = attestation.witness_sequence;
    const bool previous = seen_support.count(attestation.witness) != 0 && seen_support[attestation.witness];
    if (previous && !attestation.support) {
      any_conflict = true;
    }
    seen_support[attestation.witness] = attestation.support;
    if (attestation.support) {
      supporting_domains[domain_it->second] = true;
      if (attestation.valid_until < earliest_expiry) earliest_expiry = attestation.valid_until;
      if (attestation.witness_generation < floor_generation) floor_generation = attestation.witness_generation;
      if (attestation.witness_generation > ceiling_generation) ceiling_generation = attestation.witness_generation;
    } else {
      any_conflict = true;
    }
  }

  std::uint32_t supporting = 0;
  for (const auto& [witness, supports] : seen_support) {
    (void)witness;
    if (supports) ++supporting;
  }
  out.distinct_supporting_witnesses = supporting;
  out.supporting_fault_domains = static_cast<std::uint32_t>(supporting_domains.size());
  out.earliest_valid_until = earliest_expiry.is_none() ? Step{} : earliest_expiry;
  if (supporting > 0) {
    out.floor_generation = floor_generation.is_none() ? Generation{} : floor_generation;
    out.ceiling_generation = ceiling_generation;
  }

  // Lease binding. A lease is dynamic authority; it is checked for generation
  // and incarnation binding and never inferred from a matching identifier.
  if (bundle.has_lease) {
    lease_present = true;
    const Lease& lease = bundle.lease;
    if (lease.id.is_none() || lease.grant.is_none() || lease.generation.is_none()) {
      out.state = EvidenceState::Invalid;
      out.status = Status::make(Outcome::Invalid, Reason::LeaseMissing);
      out.outcome = Outcome::Invalid;
      out.reason = Reason::LeaseMissing;
      return out;
    }
    if (lease.policy_generation != profile.generation) {
      out.state = EvidenceState::Stale;
      out.status = Status::make(Outcome::Stale, Reason::LeaseGenerationMismatch);
      out.outcome = Outcome::Stale;
      out.reason = Reason::LeaseGenerationMismatch;
      return out;
    }
    if (!(lease.scope == request.scope)) {
      out.state = EvidenceState::Invalid;
      out.status = Status::make(Outcome::Invalid, Reason::LeaseScopeMismatch);
      out.outcome = Outcome::Invalid;
      out.reason = Reason::LeaseScopeMismatch;
      return out;
    }
    if (!(lease.domain == request.domain)) {
      out.state = EvidenceState::Invalid;
      out.status = Status::make(Outcome::Invalid, Reason::LeaseDomainMismatch);
      out.outcome = Outcome::Invalid;
      out.reason = Reason::LeaseDomainMismatch;
      return out;
    }
    if (lease.epoch != request.epoch) {
      out.state = EvidenceState::Stale;
      out.status = Status::make(Outcome::Stale, Reason::LeaseEpochMismatch);
      out.outcome = Outcome::Stale;
      out.reason = Reason::LeaseEpochMismatch;
      return out;
    }
    if (lease.incarnation != request.incarnation) {
      out.state = EvidenceState::Stale;
      out.status = Status::make(Outcome::Stale, Reason::LeaseIncarnationMismatch);
      out.outcome = Outcome::Stale;
      out.reason = Reason::LeaseIncarnationMismatch;
      return out;
    }
    if (lease.fence_token != request.fence_token) {
      out.state = EvidenceState::Stale;
      out.status = Status::make(Outcome::Stale, Reason::FenceTokenRegressed);
      out.outcome = Outcome::Stale;
      out.reason = Reason::FenceTokenRegressed;
      return out;
    }
    if (request.as_of.value() < lease.valid_from.value()) {
      out.state = EvidenceState::Unknown;
      out.status = Status::make(Outcome::Unknown, Reason::LeaseNotYetValid);
      out.outcome = Outcome::Unknown;
      out.reason = Reason::LeaseNotYetValid;
      return out;
    }
    if (request.as_of.value() > lease.valid_until.value()) {
      out.state = EvidenceState::Stale;
      out.status = Status::make(Outcome::Stale, Reason::LeaseExpired);
      out.outcome = Outcome::Stale;
      out.reason = Reason::LeaseExpired;
      return out;
    }
    out.lease_valid_until = lease.valid_until;
    if (lease.valid_until < earliest_expiry) earliest_expiry = lease.valid_until;
    out.earliest_valid_until = earliest_expiry;
  }
  out.lease_present = lease_present;

  if (any_conflict) {
    out.state = EvidenceState::Conflict;
    out.status = Status::make(Outcome::Conflict, Reason::ConflictingAttestations, out.distinct_supporting_witnesses);
    out.outcome = Outcome::Conflict;
    out.reason = Reason::ConflictingAttestations;
    return out;
  }
  if (any_invalid) {
    out.state = EvidenceState::Invalid;
    out.status = Status::make(Outcome::Invalid, Reason::WitnessScopeMismatch, out.rejected_attestations);
    out.outcome = Outcome::Invalid;
    out.reason = Reason::WitnessScopeMismatch;
    return out;
  }
  if (generation_mismatch) {
    out.state = EvidenceState::Stale;
    out.status = Status::make(Outcome::Stale, Reason::WitnessGenerationMismatch);
    out.outcome = Outcome::Stale;
    out.reason = Reason::WitnessGenerationMismatch;
    return out;
  }
  if (supporting < out.required_witnesses) {
    // Safety over availability: not enough distinct witnesses is UNKNOWN, not a
    // weak yes.
    out.state = any_stale ? EvidenceState::Stale : EvidenceState::Unknown;
    out.outcome = any_stale ? Outcome::Stale : Outcome::Unknown;
    out.reason = any_stale ? Reason::StaleAttestation : Reason::InsufficientDistinctWitnesses;
    out.status = Status::make(out.outcome, out.reason, supporting);
    return out;
  }
  if (out.supporting_fault_domains < profile.min_fault_domains) {
    out.state = EvidenceState::Unknown;
    out.outcome = Outcome::Unknown;
    out.reason = Reason::InsufficientFaultDomains;
    out.status = Status::make(Outcome::Unknown, Reason::InsufficientFaultDomains,
                              out.supporting_fault_domains);
    return out;
  }
  if (any_stale || any_unknown) {
    // Rejected statements that could not be evaluated leave the verdict
    // explicitly non-current even when the quorum threshold is met: a quorum
    // assembled from a partially unreadable evidence set is not proven.
    out.state = any_stale ? EvidenceState::Stale : EvidenceState::Unknown;
    out.outcome = any_stale ? Outcome::Stale : Outcome::Unknown;
    out.reason = any_stale ? Reason::StaleAttestation : Reason::WitnessEpochMismatch;
    out.status = Status::make(out.outcome, out.reason, out.rejected_attestations);
    return out;
  }

  out.state = EvidenceState::Current;
  out.outcome = Outcome::Ok;
  out.reason = Reason::None;
  out.status = Status::ok();
  return out;
}

}  // namespace sbf
