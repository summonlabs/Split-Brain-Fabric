#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sbf/status.hpp"

namespace sbf::text {

// Parses an unsigned decimal integer with full overflow checking: a value that
// does not fit in std::uint64_t is rejected rather than wrapping.
Status parse_u64(std::string_view in, std::uint64_t& out) noexcept;
Status parse_i64(std::string_view in, std::int64_t& out) noexcept;
Status parse_bool(std::string_view in, bool& out) noexcept;

std::string hex_u64(std::uint64_t value);
std::string to_lower(std::string_view in);
std::string_view trim(std::string_view in) noexcept;

// Splits on a single delimiter character. Empty fields are preserved; the
// caller decides whether they are legal.
std::vector<std::string> split(std::string_view in, char delimiter);

bool equals_ci(std::string_view a, std::string_view b) noexcept;

// Bounded append: returns false and leaves the buffer unchanged when the result
// would exceed the bound.
bool append_bounded(std::string& out, std::string_view piece, std::size_t bound);

}  // namespace sbf::text
