#pragma once

#include <cstdint>
#include <vector>

#include "sbf/digest.hpp"
#include "sbf/ids.hpp"
#include "sbf/limits.hpp"
#include "sbf/status.hpp"

namespace sbf {

// Classification of an authority-bearing dependency. UNKNOWN is never treated as
// affirmative, and matching identifiers alone never establish Current: the
// generation must match as well.
enum class EvidenceState : std::uint8_t {
  Current = 0,
  Stale = 1,
  Unknown = 2,
  Conflict = 3,
  Invalid = 4,
  Unsupported = 5,
};

std::string_view to_string(EvidenceState state) noexcept;

// A statement by one witness about one (domain, scope, epoch, incarnation)
// subject. Every field that the decision binds is carried explicitly so that
// the arbiter never has to infer currentness from a matching identifier.
struct WitnessAttestation {
  WitnessId witness;
  DomainId subject_domain;
  Digest256 subject_scope;         // exact extent-set identity
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken fence_token;
  Generation witness_generation;   // the witness's own generation for the subject
  Generation policy_generation;
  Step issued_at;
  Step valid_until;
  Sequence witness_sequence;       // strictly monotone per witness
  bool support = true;
  WallClockReading observed_at;    // diagnostics only; never ordered on
};

// A witness and the failure domain it belongs to. Quorum diversity is computed
// over fault domains, not over transport endpoints.
struct WitnessSlot {
  WitnessId witness;
  FaultDomainId fault_domain;
  friend bool operator==(const WitnessSlot&, const WitnessSlot&) = default;
  friend std::strong_ordering operator<=>(const WitnessSlot& a, const WitnessSlot& b) noexcept {
    if (auto c = a.witness <=> b.witness; c != 0) return c;
    return a.fault_domain <=> b.fault_domain;
  }
};

enum class QuorumMode : std::uint8_t {
  MajorityDistinctWitnesses = 0,
  ThresholdDistinctWitnesses = 1,
  UnanimousWitnesses = 2,
};

std::string_view to_string(QuorumMode mode) noexcept;

struct QuorumProfile {
  PolicyId policy;
  Generation generation = Generation{1};
  std::vector<WitnessSlot> witnesses;  // canonical: sorted by witness id
  QuorumMode mode = QuorumMode::MajorityDistinctWitnesses;
  std::uint32_t threshold = 0;              // used by Threshold mode
  std::uint32_t min_fault_domains = 1;
  std::uint64_t evidence_horizon_steps = 1000;

  // Number of distinct supporting witnesses required by the mode.
  std::uint32_t required_witnesses() const noexcept;
  Status validate() const noexcept;
};

// A lease is the durable, epoch-bound right to act for one scope. It is bound to
// a fence token, so a lease from a superseded epoch can never be replayed into
// authority.
struct Lease {
  LeaseId id;
  GrantId grant;
  DomainId domain;
  Digest256 scope;
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken fence_token;
  Generation generation;
  Generation policy_generation;
  Step valid_from;
  Step valid_until;
};

// Highest witness sequence the verifier has already accepted. Replays at or
// below the floor are refused rather than silently dropped.
struct WitnessFloor {
  WitnessId witness;
  Sequence sequence;
  Generation generation;
  friend bool operator==(const WitnessFloor&, const WitnessFloor&) = default;
};

struct EvidenceBundle {
  PolicyId policy;
  Generation policy_generation = Generation{1};
  Step as_of;                                   // requester's logical step
  Generation fence_generation;                  // generation of the fence view used
  std::vector<WitnessAttestation> attestations; // canonicalised before assessment
  bool has_lease = false;
  Lease lease;
};

struct EvidenceRequest {
  DomainId domain;
  Digest256 scope;
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken fence_token;
  Step as_of;
};

struct EvidenceAssessment {
  EvidenceState state = EvidenceState::Unknown;
  Status status;
  Outcome outcome = Outcome::Unknown;
  Reason reason = Reason::None;
  std::uint32_t required_witnesses = 0;
  std::uint32_t distinct_supporting_witnesses = 0;
  std::uint32_t supporting_fault_domains = 0;
  Generation floor_generation;     // lowest generation among accepted evidence
  Generation ceiling_generation;   // highest generation among accepted evidence
  std::uint64_t duplicate_attestations = 0;
  std::uint64_t replayed_attestations = 0;
  std::uint64_t rejected_attestations = 0;
  Step earliest_valid_until;       // earliest expiry among accepted evidence
  bool lease_present = false;
  Step lease_valid_until;

  bool is_current() const noexcept { return state == EvidenceState::Current; }
};

// Deterministic evidence assessment. The result depends only on the *set* of
// attestations, never on their order in the bundle.
EvidenceAssessment assess_evidence(const EvidenceRequest& request,
                                   const QuorumProfile& profile,
                                   const EvidenceBundle& bundle,
                                   const std::vector<WitnessFloor>& floors);

}  // namespace sbf
