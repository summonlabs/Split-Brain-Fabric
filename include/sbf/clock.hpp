#pragma once

#include <cstdint>

#include "sbf/ids.hpp"

namespace sbf {

// Monotone logical time.
//
// Every authority validity window in this runtime is expressed in logical steps
// of this counter, never in wall-clock time. The step counter only ever moves
// forward and is persisted; on restart it resumes strictly above the highest
// step ever issued. This is the only clock that may gate authority.
class StepClock {
 public:
  StepClock() = default;

  Step now() const noexcept { return Step{value_}; }

  // Monotone advance. Returns false (leaving the value untouched) on overflow.
  bool advance(std::uint64_t by = 1) noexcept;

  // Raises the floor to at least the given value (used on restart to resume
  // above the highest persisted step).
  bool observe_persisted(Step value) noexcept;

  static constexpr std::uint64_t capacity() noexcept { return Step::max_value(); }

 private:
  std::uint64_t value_ = 0;
};

// Wall-clock readings exist only for operator visibility, log correlation and
// clock-skew diagnostics. The runtime records them, reports regressions, and
// never orders authority decisions by them.
class WallClockObserver {
 public:
  WallClockReading read() noexcept;                             // system clock
  WallClockReading observe(std::int64_t unix_nanos) noexcept;   // injected reading

  std::int64_t last_reading() const noexcept { return last_; }
  std::uint64_t regression_count() const noexcept { return regressions_; }
  std::uint64_t max_regression_nanos() const noexcept { return max_regression_; }

  static std::int64_t system_unix_nanos() noexcept;

 private:
  std::int64_t last_ = 0;
  std::uint64_t regressions_ = 0;
  std::uint64_t max_regression_ = 0;
};

}  // namespace sbf
