#include "sbf/status.hpp"

#include <array>

#include "sbf/text.hpp"

namespace sbf {
namespace {

constexpr std::array<std::string_view, 17> kOutcomeNames = {
    "Ok", "Unknown", "Stale", "Conflict", "Invalid", "Unsupported", "Fenced",
    "Refused", "Exhausted", "Interrupted", "Indeterminate", "SearchLimitReached",
    "NotFound", "AlreadyExists", "Corrupt", "Unreachable", "Closed"};

}  // namespace

std::string_view to_string(Outcome outcome) noexcept {
  const auto index = static_cast<std::size_t>(outcome);
  if (index >= kOutcomeNames.size()) return "InvalidOutcome";
  return kOutcomeNames[index];
}

bool outcome_from_string(std::string_view name, Outcome& out) noexcept {
  for (std::size_t i = 0; i < kOutcomeNames.size(); ++i) {
    if (kOutcomeNames[i] == name) {
      out = static_cast<Outcome>(i);
      return true;
    }
  }
  return false;
}

bool is_positive(Outcome outcome) noexcept { return outcome == Outcome::Ok; }

std::string_view to_string(Reason reason) noexcept {
  switch (reason) {
#define SBF_REASON_CASE(name, value) case Reason::name: return #name;
    SBF_REASON_LIST(SBF_REASON_CASE)
#undef SBF_REASON_CASE
  }
  return "ReasonOutOfRange";
}

bool reason_from_code(std::uint16_t code, Reason& out) noexcept {
  switch (code) {
#define SBF_REASON_CASE(name, value) case value: out = Reason::name; return true;
    SBF_REASON_LIST(SBF_REASON_CASE)
#undef SBF_REASON_CASE
    default: return false;
  }
}

std::string to_string(const Status& status) {
  std::string out;
  out.reserve(48);
  out.append(to_string(status.outcome));
  out.push_back(':');
  out.append(to_string(status.reason));
  if (status.aux != 0) {
    out.append("#");
    out.append(text::hex_u64(status.aux));
  }
  return out;
}

bool Explanation::add(Reason reason) noexcept {
  if (reason == Reason::None) return true;
  for (std::uint8_t i = 0; i < count_; ++i) {
    if (codes_[i] == reason) return true;
  }
  if (count_ >= limits::kMaxExplanationCodes) return false;
  codes_[count_++] = reason;
  return true;
}

bool Explanation::contains(Reason reason) const noexcept {
  for (std::uint8_t i = 0; i < count_; ++i) {
    if (codes_[i] == reason) return true;
  }
  return false;
}

bool Explanation::full() const noexcept { return count_ >= limits::kMaxExplanationCodes; }

std::string Explanation::render(std::string_view subject, const Status& primary) const {
  std::string out;
  out.reserve(128);
  out.append(subject);
  out.append(" -> ");
  out.append(sbf::to_string(primary));
  if (count_ == 0) return out;
  out.append(" [");
  for (std::uint8_t i = 0; i < count_; ++i) {
    if (i != 0) out.push_back(',');
    out.append(sbf::to_string(codes_[i]));
  }
  out.push_back(']');
  if (out.size() > limits::kMaxExplanationBytes) {
    out.resize(limits::kMaxExplanationBytes);
  }
  return out;
}

}  // namespace sbf
