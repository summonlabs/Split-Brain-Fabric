#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "sbf/status.hpp"

namespace sbf {

// A validated, bounded identifier. Identifiers are opaque byte strings drawn
// from a restricted alphabet so that they are always safe to place in paths,
// logs and canonical documents.
//
// Strong typing is obtained by instantiating over a distinct tag type, so a
// WitnessId can never be passed where a DomainId is expected.
template <class Tag>
class Id {
 public:
  Id() = default;

  // Returns Invalid/IdCharset or Invalid/IdTooLong on rejection.
  static Status validate(std::string_view value) noexcept;

  static std::optional<Id> try_make(std::string_view value) noexcept {
    Id id;
    if (auto st = validate(value); !st.is_ok()) return std::nullopt;
    id.value_.assign(value);
    return id;
  }

  // Precondition: validate(value).is_ok().
  static Id make(std::string_view value);

  bool empty() const noexcept { return value_.empty(); }
  std::string_view view() const noexcept { return value_; }
  const std::string& str() const noexcept { return value_; }

  friend bool operator==(const Id& a, const Id& b) noexcept { return a.value_ == b.value_; }
  friend std::strong_ordering operator<=>(const Id& a, const Id& b) noexcept {
    // Byte-wise comparison; independent of locale and of signedness of char.
    const int c = a.value_.compare(b.value_);
    if (c < 0) return std::strong_ordering::less;
    if (c > 0) return std::strong_ordering::greater;
    return std::strong_ordering::equal;
  }

 private:
  std::string value_;
};

// Monotone counters. Zero is reserved for "absent/none" on every counter type.
template <class Tag>
class Counter {
 public:
  using value_type = std::uint64_t;

  constexpr Counter() = default;
  constexpr explicit Counter(std::uint64_t v) noexcept : value_(v) {}

  static constexpr Counter none() noexcept { return Counter{}; }
  static constexpr Counter max() noexcept { return Counter{~std::uint64_t{0}}; }

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_none() const noexcept { return value_ == 0; }
  constexpr bool is_set() const noexcept { return value_ != 0; }
  constexpr explicit operator bool() const noexcept { return value_ != 0; }

  // Checked increment. Returns false (leaving the value untouched) on wrap.
  constexpr bool try_increment(std::uint64_t by = 1) noexcept {
    if (value_ > max_value() - by) return false;
    value_ += by;
    return true;
  }

  static constexpr std::uint64_t max_value() noexcept { return ~std::uint64_t{0}; }

  friend constexpr bool operator==(Counter a, Counter b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(Counter a, Counter b) noexcept {
    return a.value_ <=> b.value_;
  }

 private:
  std::uint64_t value_ = 0;
};

struct DomainIdTag {};
struct ExtentIdTag {};
struct WitnessIdTag {};
struct StoreIdTag {};
struct PolicyIdTag {};
struct ClaimIdTag {};
struct NodeIdTag {};
struct FaultDomainIdTag {};

using DomainId = Id<DomainIdTag>;
using ExtentId = Id<ExtentIdTag>;
using WitnessId = Id<WitnessIdTag>;
using StoreId = Id<StoreIdTag>;
using PolicyId = Id<PolicyIdTag>;
using ClaimId = Id<ClaimIdTag>;
using NodeId = Id<NodeIdTag>;
using FaultDomainId = Id<FaultDomainIdTag>;

struct EpochTag {};
struct IncarnationTag {};
struct FenceTokenTag {};
struct StepTag {};
struct SequenceTag {};
struct GenerationTag {};
struct BootTag {};
struct SessionTag {};
struct RequestIdTag {};
struct LeaseTag {};
struct GrantTag {};
struct AttemptTag {};

using Epoch = Counter<EpochTag>;
using IncarnationId = Counter<IncarnationTag>;
using FenceToken = Counter<FenceTokenTag>;
using Step = Counter<StepTag>;
using Sequence = Counter<SequenceTag>;
using Generation = Counter<GenerationTag>;
using BootId = Counter<BootTag>;
using SessionId = Counter<SessionTag>;
using RequestId = Counter<RequestIdTag>;
using LeaseId = Counter<LeaseTag>;
using GrantId = Counter<GrantTag>;
using AttemptId = Counter<AttemptTag>;

// Wall-clock readings are recorded for operator visibility only. They are never
// compared for ordering by any authority decision: see docs and the
// wall-clock-invariance property test.
struct WallClockReading {
  std::int64_t unix_nanos = 0;
  std::uint64_t source = 0;
  bool observed_regression = false;

  friend bool operator==(const WallClockReading&, const WallClockReading&) = default;
};

}  // namespace sbf
