#pragma once

// Deterministic synthetic fixtures shared by the arbiter, service and adversarial
// suites. Everything produced here is labelled SYNTHETIC in the release report:
// it is configuration and evidence data, not observed fabric hardware.

#include <string>

#include "sbf/arbiter.hpp"
#include "sbf/protocol.hpp"

namespace sbf::test {

inline QuorumProfile quorum_of(std::size_t witness_count,
                               QuorumMode mode = QuorumMode::MajorityDistinctWitnesses,
                               std::uint32_t threshold = 0,
                               std::uint32_t min_fault_domains = 1) {
  QuorumProfile profile;
  profile.policy = PolicyId::make("fabric-policy");
  profile.generation = Generation{1};
  for (std::size_t i = 0; i < witness_count; ++i) {
    profile.witnesses.push_back(
        WitnessSlot{WitnessId::make("witness-" + std::to_string(i)),
                    FaultDomainId::make("fd-" + std::to_string(i))});
  }
  profile.mode = mode;
  profile.threshold = threshold;
  profile.min_fault_domains = min_fault_domains;
  profile.evidence_horizon_steps = 10000;
  return profile;
}

inline ArbiterPolicy policy_of(std::size_t witness_count = 3,
                               QuorumMode mode = QuorumMode::MajorityDistinctWitnesses,
                               std::uint32_t threshold = 0) {
  ArbiterPolicy policy;
  policy.policy = PolicyId::make("fabric-policy");
  policy.generation = Generation{1};
  policy.quorum = quorum_of(witness_count, mode, threshold);
  return policy;
}

inline WitnessAttestation attestation_of(const QuorumProfile& profile, std::size_t witness_index,
                                         const DomainId& domain, const Scope& scope, Epoch epoch,
                                         IncarnationId incarnation, FenceToken token,
                                         Sequence sequence, Step issued_at = Step{1},
                                         Step valid_until = Step{100000}) {
  WitnessAttestation attestation;
  attestation.witness = profile.witnesses[witness_index].witness;
  attestation.subject_domain = domain;
  attestation.subject_scope = scope.digest();
  attestation.epoch = epoch;
  attestation.incarnation = incarnation;
  attestation.fence_token = token;
  attestation.witness_generation = Generation{1};
  attestation.policy_generation = profile.generation;
  attestation.issued_at = issued_at;
  attestation.valid_until = valid_until;
  attestation.witness_sequence = sequence;
  attestation.support = true;
  return attestation;
}

inline EvidenceBundle bundle_with(const QuorumProfile& profile, const Scope& scope, Step as_of,
                                  const std::vector<WitnessAttestation>& attestations) {
  EvidenceBundle bundle;
  bundle.policy = profile.policy;
  bundle.policy_generation = profile.generation;
  bundle.as_of = as_of;
  bundle.attestations = attestations;
  (void)scope;
  return bundle;
}

inline AuthorityRequest request_of(const DomainId& domain, const Scope& scope, Epoch epoch,
                                   IncarnationId incarnation, FenceToken token,
                                   const EvidenceBundle& bundle,
                                   AuthorityMode mode = AuthorityMode::ExclusiveMutation,
                                   ClaimId claim = ClaimId{}) {
  AuthorityRequest request;
  request.claim = claim.empty() ? ClaimId::make("claim-" + domain.str()) : claim;
  request.domain = domain;
  request.scope = scope;
  request.epoch = epoch;
  request.incarnation = incarnation;
  request.boot = BootId{incarnation.value()};
  request.presented_fence_token = token;
  request.mode = mode;
  request.attempt_sequence = Sequence{1};
  request.evidence = bundle;
  return request;
}

// Builds a fence/lineage pair consistent with one open exclusive grant.
struct Fixture {
  ArbiterPolicy policy;
  FenceTable fences;
  LineageTable lineage;
  Scope scope;
  DomainId domain;
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken token;
  GrantId grant;
  Step now;

  explicit Fixture(std::size_t witnesses = 3,
                   QuorumMode mode = QuorumMode::MajorityDistinctWitnesses,
                   std::uint32_t threshold = 0, std::string_view csv = "p1,p2,p3") {
    policy = policy_of(witnesses, mode, threshold);
    scope = Scope::try_parse(csv).value_or(Scope{});
    domain = DomainId::make("domain-a");
    epoch = Epoch{1};
    incarnation = IncarnationId{2};
    token = FenceToken{1};
    grant = GrantId{1};
    now = Step{10};
    fences.adopt(scope, token, epoch, incarnation, grant, Step{1});
    EpochGrant record;
    record.id = grant;
    record.domain = domain;
    record.scope = scope.digest();
    record.extents = scope;
    record.epoch = epoch;
    record.incarnation = incarnation;
    record.boot = BootId{incarnation.value()};
    record.fence_token = token;
    record.opened_at = Step{1};
    record.registry_sequence = Sequence{1};
    lineage.open_grant(record);
  }

  ArbiterView view() const {
    ArbiterView out;
    out.policy = &policy;
    out.fences = &fences;
    out.lineage = &lineage;
    out.now = now;
    out.registry_generation = Generation{1};
    return out;
  }

  EvidenceBundle full_evidence() const {
    std::vector<WitnessAttestation> attestations;
    for (std::size_t i = 0; i < policy.quorum.witnesses.size(); ++i) {
      attestations.push_back(attestation_of(policy.quorum, i, domain, scope, epoch, incarnation,
                                            token, Sequence{static_cast<std::uint64_t>(i + 1)}));
    }
    return bundle_with(policy.quorum, scope, now, attestations);
  }
};

}  // namespace sbf::test
