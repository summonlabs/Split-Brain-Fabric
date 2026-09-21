#pragma once

#include <string_view>

#include "sbf/version_generated.hpp"

namespace sbf {

inline constexpr std::string_view kVersion = SBF_VERSION_STRING;
inline constexpr int kVersionMajor = SBF_VERSION_MAJOR;
inline constexpr int kVersionMinor = SBF_VERSION_MINOR;
inline constexpr int kVersionPatch = SBF_VERSION_PATCH;

// Human-readable identification of the running binary.
std::string_view build_description() noexcept;

}  // namespace sbf
