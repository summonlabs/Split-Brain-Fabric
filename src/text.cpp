#include "sbf/text.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <limits>

namespace sbf::text {

Status parse_u64(std::string_view in, std::uint64_t& out) noexcept {
  if (in.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  std::uint64_t value = 0;
  for (const char c : in) {
    if (c < '0' || c > '9') return Status::make(Outcome::Invalid, Reason::IdCharset);
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
      return Status::make(Outcome::Invalid, Reason::CounterOverflow);
    }
    value = value * 10u + digit;
  }
  out = value;
  return Status::ok();
}

Status parse_i64(std::string_view in, std::int64_t& out) noexcept {
  if (in.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  bool negative = false;
  if (in.front() == '-') {
    negative = true;
    in.remove_prefix(1);
    if (in.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  } else if (in.front() == '+') {
    in.remove_prefix(1);
    if (in.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  }
  std::uint64_t magnitude = 0;
  if (auto st = parse_u64(in, magnitude); !st.is_ok()) return st;
  const std::uint64_t limit = negative
                                  ? static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ull
                                  : static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  if (magnitude > limit) return Status::make(Outcome::Invalid, Reason::CounterOverflow);
  if (negative) {
    out = (magnitude == limit) ? std::numeric_limits<std::int64_t>::min()
                               : -static_cast<std::int64_t>(magnitude);
  } else {
    out = static_cast<std::int64_t>(magnitude);
  }
  return Status::ok();
}

Status parse_bool(std::string_view in, bool& out) noexcept {
  if (equals_ci(in, "true") || in == "1" || equals_ci(in, "yes") || equals_ci(in, "on")) {
    out = true;
    return Status::ok();
  }
  if (equals_ci(in, "false") || in == "0" || equals_ci(in, "no") || equals_ci(in, "off")) {
    out = false;
    return Status::ok();
  }
  return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
}

std::string hex_u64(std::uint64_t value) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(18);
  out.append("0x");
  bool started = false;
  for (int shift = 60; shift >= 0; shift -= 4) {
    const auto digit = static_cast<std::uint8_t>((value >> shift) & 0xFu);
    if (digit != 0 || started || shift == 0) {
      started = true;
      out.push_back(kDigits[digit]);
    }
  }
  return out;
}

std::string to_lower(std::string_view in) {
  std::string out(in);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

std::string_view trim(std::string_view in) noexcept {
  std::size_t begin = 0;
  std::size_t end = in.size();
  while (begin < end && (in[begin] == ' ' || in[begin] == '\t' || in[begin] == '\r' || in[begin] == '\n')) ++begin;
  while (end > begin && (in[end - 1] == ' ' || in[end - 1] == '\t' || in[end - 1] == '\r' || in[end - 1] == '\n')) --end;
  return in.substr(begin, end - begin);
}

std::vector<std::string> split(std::string_view in, char delimiter) {
  std::vector<std::string> out;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= in.size(); ++i) {
    if (i == in.size() || in[i] == delimiter) {
      out.emplace_back(in.substr(start, i - start));
      start = i + 1;
    }
  }
  return out;
}

bool equals_ci(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    const auto ca = static_cast<unsigned char>(a[i]);
    const auto cb = static_cast<unsigned char>(b[i]);
    if (std::tolower(ca) != std::tolower(cb)) return false;
  }
  return true;
}

bool append_bounded(std::string& out, std::string_view piece, std::size_t bound) {
  if (piece.size() > bound || out.size() > bound - piece.size()) return false;
  out.append(piece);
  return true;
}

}  // namespace sbf::text
