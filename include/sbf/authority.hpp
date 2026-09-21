#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sbf/digest.hpp"
#include "sbf/evidence.hpp"
#include "sbf/ids.hpp"
#include "sbf/limits.hpp"
#include "sbf/scope.hpp"
#include "sbf/status.hpp"

namespace sbf {

// What the caller is asking about. Only ExclusiveMutation can ever move fabric
// state; the remaining modes exist so that observation, eligibility, advice and
// backlog acknowledgements are never confused with authority.
enum class AuthorityMode : std::uint8_t {
  Observation = 0,
  EligibilityProbe = 1,
  RecommendationRequest = 2,
  SharedRead = 3,
  ExclusiveMutation = 4,
};

std::string_view to_string(AuthorityMode mode) noexcept;

// The verdict vocabulary. Exactly one verdict - Authoritative - carries mutation
// authority. Everything else is an observation, a precondition, advice, an
// acknowledgement, or an explicit failure.
enum class AuthorityVerdict : std::uint8_t {
  Authoritative = 0,
  Fenced = 1,
  ObserveOnly = 2,
  Eligible = 3,
  Recommended = 4,
  Acknowledged = 5,
  Applied = 6,
  Unknown = 7,
  Stale = 8,
  Conflict = 9,
  Invalid = 10,
  Unsupported = 11,
  Refused = 12,
  Interrupted = 13,
};

std::string_view to_string(AuthorityVerdict verdict) noexcept;
// True only for Authoritative.
bool verdict_carries_authority(AuthorityVerdict verdict) noexcept;
// True only for Authoritative: the single predicate that may gate a mutation.
bool verdict_permits_mutation(AuthorityVerdict verdict) noexcept;

// The complete binding that makes a decision legal. Every field is part of the
// decision digest, so a decision cannot be transplanted onto another domain,
// scope, epoch, incarnation, fence token or evidence/policy generation.
struct AuthorityVector {
  DomainId domain;
  Digest256 scope;
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken fence_token;
  GrantId grant;
  Sequence authority_sequence = Sequence{1};
  Generation policy_generation;
  Generation evidence_generation;
  Generation fence_generation;

  Digest256 digest() const;
};

struct AuthorityRequest {
  ClaimId claim;
  DomainId domain;
  Scope scope;
  Epoch epoch;
  IncarnationId incarnation;
  BootId boot;
  FenceToken presented_fence_token;
  AuthorityMode mode = AuthorityMode::ExclusiveMutation;
  Sequence attempt_sequence = Sequence{1};
  EvidenceBundle evidence;
  WallClockReading requested_at;  // diagnostics only
};

// A competing claimant as observed by the arbiter. "active" records the
// caller-observed liveness of the competing claim; liveness never grants
// authority, it only decides whether a fence must be issued.
struct CompetingClaim {
  ClaimId claim;
  DomainId domain;
  Scope scope;
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken fence_token;
  GrantId grant;
  AuthorityMode mode = AuthorityMode::ExclusiveMutation;
  EvidenceState evidence_state = EvidenceState::Unknown;
  bool active = false;
};

struct AuthorityDecision {
  AuthorityVerdict verdict = AuthorityVerdict::Unknown;
  Status status;
  Explanation explanation;
  AuthorityVector vector;
  // The exact subject the decision applies to. A decision is never valid for a
  // claim other than the one it names.
  ClaimId claim;
  Scope scope;
  Step valid_from;
  Step valid_until;
  std::vector<ClaimId> must_fence;      // claims that must be fenced first
  std::vector<ExtentId> fenced_extents;
  Sequence decision_sequence = Sequence{1};
  bool revocable = true;

  bool is_authoritative() const noexcept { return verdict_carries_authority(verdict); }
  Digest256 digest() const;
};

// Answers whether a *previously issued* decision is still legal against a newer
// view of the world. Any change to an authority-bearing dependency revokes.
struct RevocationCheck {
  bool revoked = false;
  Reason reason = Reason::None;
  Explanation explanation;
};

std::string describe(const AuthorityDecision& decision);
std::string describe(const AuthorityVector& vector);

}  // namespace sbf
