#include "sbf/clock.hpp"

#include <chrono>

namespace sbf {

bool StepClock::advance(std::uint64_t by) noexcept {
  if (value_ > Step::max_value() - by) return false;
  value_ += by;
  return true;
}

bool StepClock::observe_persisted(Step value) noexcept {
  if (value.value() <= value_) return true;
  if (value.value() == Step::max_value()) return false;
  value_ = value.value();
  return true;
}

std::int64_t WallClockObserver::system_unix_nanos() noexcept {
  using namespace std::chrono;
  const auto now = system_clock::now().time_since_epoch();
  return duration_cast<nanoseconds>(now).count();
}

WallClockReading WallClockObserver::read() noexcept { return observe(system_unix_nanos()); }

WallClockReading WallClockObserver::observe(std::int64_t unix_nanos) noexcept {
  WallClockReading reading;
  reading.unix_nanos = unix_nanos;
  if (last_ != 0 && unix_nanos < last_) {
    reading.observed_regression = true;
    ++regressions_;
    const auto delta = static_cast<std::uint64_t>(last_ - unix_nanos);
    if (delta > max_regression_) max_regression_ = delta;
  }
  if (unix_nanos > last_) last_ = unix_nanos;
  return reading;
}

}  // namespace sbf
