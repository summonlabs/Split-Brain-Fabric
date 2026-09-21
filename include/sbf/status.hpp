#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "sbf/limits.hpp"

namespace sbf {

// Every externally visible result carries one of these outcomes. UNKNOWN, STALE,
// CONFLICT, INVALID and UNSUPPORTED are first-class and are never collapsed into
// success or into ordinary absence.
enum class Outcome : std::uint8_t {
  Ok = 0,
  Unknown = 1,
  Stale = 2,
  Conflict = 3,
  Invalid = 4,
  Unsupported = 5,
  Fenced = 6,
  Refused = 7,
  Exhausted = 8,
  Interrupted = 9,
  Indeterminate = 10,
  SearchLimitReached = 11,
  NotFound = 12,
  AlreadyExists = 13,
  Corrupt = 14,
  Unreachable = 15,
  Closed = 16,
};

std::string_view to_string(Outcome outcome) noexcept;
bool outcome_from_string(std::string_view name, Outcome& out) noexcept;
// True when the outcome constitutes a positive result.
bool is_positive(Outcome outcome) noexcept;

// Stable, machine-readable reason codes. The numeric values are part of the
// durable format: they are persisted and transported, so they must never be
// renumbered. New codes are appended.
#define SBF_REASON_LIST(X)                        \
  X(None, 0)                                      \
  X(EmptyValue, 1)                                \
  X(IdTooLong, 2)                                 \
  X(IdCharset, 3)                                 \
  X(ValueOutOfRange, 4)                           \
  X(CounterOverflow, 5)                           \
  X(BoundedTableFull, 6)                          \
  X(DuplicateEntry, 7)                            \
  X(EmptyExtentSet, 8)                            \
  X(ScopeTooLarge, 9)                             \
  X(DuplicateExtent, 10)                          \
  X(NoAttestations, 20)                           \
  X(InsufficientDistinctWitnesses, 21)            \
  X(InsufficientFaultDomains, 22)                 \
  X(WitnessGenerationMismatch, 23)                \
  X(WitnessScopeMismatch, 24)                     \
  X(WitnessEpochMismatch, 25)                     \
  X(WitnessIncarnationMismatch, 26)               \
  X(ConflictingAttestations, 27)                  \
  X(DuplicateWitness, 28)                         \
  X(UnknownWitness, 29)                           \
  X(StaleAttestation, 30)                         \
  X(PolicyGenerationMismatch, 31)                 \
  X(LeaseMissing, 40)                             \
  X(LeaseGenerationMismatch, 41)                  \
  X(LeaseScopeMismatch, 42)                       \
  X(LeaseDomainMismatch, 43)                      \
  X(LeaseEpochMismatch, 44)                       \
  X(LeaseIncarnationMismatch, 45)                 \
  X(LeaseExpired, 46)                             \
  X(LeaseNotYetValid, 47)                         \
  X(FenceTokenMissing, 60)                        \
  X(FenceTokenRegressed, 61)                      \
  X(ExtentFenced, 62)                             \
  X(IncarnationFenced, 63)                        \
  X(EpochFenced, 64)                              \
  X(StaleEpoch, 70)                               \
  X(EpochRegression, 71)                          \
  X(EpochUnknown, 72)                             \
  X(OverlappingExclusiveClaim, 80)                \
  X(EqualEpochConflict, 81)                       \
  X(HigherEpochClaimant, 82)                      \
  X(NonOverlappingAllowed, 83)                    \
  X(CompensatingFenceRequired, 84)                \
  X(ObservationNotAuthority, 90)                  \
  X(EligibilityNotAuthorization, 91)              \
  X(RecommendationNotAuthority, 92)               \
  X(AcknowledgementNotEffect, 93)                 \
  X(PermitNotApplied, 94)                         \
  X(CorruptHeader, 100)                           \
  X(UnsupportedVersion, 101)                      \
  X(IntegrityMismatch, 102)                       \
  X(SequenceRegression, 103)                      \
  X(TrailingGarbage, 104)                         \
  X(ImpossibleLength, 105)                        \
  X(InvalidEnum, 106)                             \
  X(TornTail, 107)                                \
  X(StoreNotFound, 108)                           \
  X(StoreBusy, 109)                               \
  X(BadMagic, 120)                                \
  X(TruncatedFrame, 121)                          \
  X(OversizedPayload, 122)                        \
  X(StickyFailure, 123)                           \
  X(SessionMismatch, 124)                         \
  X(RequestIdRegression, 125)                     \
  X(RequestIdReplay, 126)                         \
  X(ConnectionClosed, 127)                        \
  X(InterruptedByRestart, 140)                    \
  X(PreRestartAuthorityInvalid, 141)              \
  X(IncarnationNotCurrent, 142)                   \
  X(DependencyUnreachable, 143)                   \
  X(NoCertificate, 160)                           \
  X(PlanInvalid, 161)                             \
  X(ProvenInfeasible, 162)                        \
  X(SearchLimitReached, 163)                      \
  X(StoreOwnerMismatch, 180)                      \
  X(EffectNotVerified, 181)                       \
  X(TokenFloorRejected, 182)                      \
  X(ScopeNotRegistered, 190)                      \
  X(DomainNotRegistered, 191)                     \
  X(PolicyNotRegistered, 192)                     \
  X(ClaimNotRegistered, 193)                      \
  X(QuorumUnreachable, 194)                       \
  X(GrantNotRegistered, 195)                      \
  X(BootNotRegistered, 196)                       \
  X(ReconciliationRequired, 200)                  \
  X(LineageDivergence, 201)                       \
  X(HistoryPreserved, 202)                        \
  X(InternalInvariantViolation, 220)              \
  X(ResourceExhausted, 221)                       \
  X(ShutdownInProgress, 222)

enum class Reason : std::uint16_t {
#define SBF_REASON_ENUM(name, value) name = value,
  SBF_REASON_LIST(SBF_REASON_ENUM)
#undef SBF_REASON_ENUM
};

std::string_view to_string(Reason reason) noexcept;
bool reason_from_code(std::uint16_t code, Reason& out) noexcept;

struct Status {
  Outcome outcome = Outcome::Ok;
  Reason reason = Reason::None;
  std::uint64_t aux = 0;

  constexpr Status() = default;
  constexpr Status(Outcome o, Reason r, std::uint64_t a = 0) noexcept
      : outcome(o), reason(r), aux(a) {}

  static constexpr Status ok() noexcept { return Status{}; }
  static constexpr Status make(Outcome o, Reason r, std::uint64_t a = 0) noexcept {
    return Status(o, r, a);
  }

  constexpr bool is_ok() const noexcept { return outcome == Outcome::Ok; }
  constexpr explicit operator bool() const noexcept { return is_ok(); }

  friend constexpr bool operator==(const Status&, const Status&) noexcept = default;
};

// Renders "<Outcome>:<Reason>[#aux]" into a fixed buffer; bounded by
// limits::kMaxTextLength.
std::string to_string(const Status& status);

// A bounded, deduplicated set of reason codes explaining a decision.
class Explanation {
 public:
  bool add(Reason reason) noexcept;
  bool contains(Reason reason) const noexcept;
  std::size_t size() const noexcept { return count_; }
  Reason at(std::size_t i) const noexcept { return codes_[i]; }
  bool full() const noexcept;

  std::string render(std::string_view subject, const Status& primary) const;

  friend bool operator==(const Explanation&, const Explanation&) = default;

 private:
  Reason codes_[limits::kMaxExplanationCodes] = {};
  std::uint8_t count_ = 0;
};

}  // namespace sbf
