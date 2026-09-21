#pragma once

// Small argument-parsing helpers shared by the command line tools. Everything is
// bounded and validated: unknown flags are refused rather than ignored.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "sbf/text.hpp"

namespace sbf::cli {

struct Options {
  std::vector<std::pair<std::string, std::string>> values;

  bool has(std::string_view key) const {
    for (const auto& entry : values) {
      if (entry.first == key) return true;
    }
    return false;
  }

  std::optional<std::string> get(std::string_view key) const {
    for (const auto& entry : values) {
      if (entry.first == key) return entry.second;
    }
    return std::nullopt;
  }

  std::vector<std::string> all(std::string_view key) const {
    std::vector<std::string> out;
    for (const auto& entry : values) {
      if (entry.first == key) out.push_back(entry.second);
    }
    return out;
  }

  std::string str(std::string_view key, std::string fallback = {}) const {
    const auto value = get(key);
    return value.has_value() ? *value : std::move(fallback);
  }

  std::uint64_t number(std::string_view key, std::uint64_t fallback) const {
    const auto value = get(key);
    if (!value.has_value()) return fallback;
    std::uint64_t out = fallback;
    if (!text::parse_u64(*value, out).is_ok()) return fallback;
    return out;
  }
};

// Parses "--key value" and "--flag" pairs. Returns false and fills the error
// string when the command line is malformed.
inline bool parse(int argc, char** argv, int start, Options& out, std::string& error) {
  for (int i = start; i < argc; ++i) {
    std::string token = argv[i];
    if (token.size() < 3 || token[0] != '-' || token[1] != '-') {
      error = "unexpected argument: " + token;
      return false;
    }
    std::string key = token.substr(2);
    std::string value;
    const auto equals = key.find('=');
    if (equals != std::string::npos) {
      value = key.substr(equals + 1);
      key = key.substr(0, equals);
    } else if (i + 1 < argc && argv[i + 1][0] != '-') {
      value = argv[++i];
    } else {
      value = "true";
    }
    if (key.empty()) {
      error = "empty option name";
      return false;
    }
    out.values.emplace_back(std::move(key), std::move(value));
  }
  return true;
}

// Publishes the effective endpoint so a supervising process can discover a port
// that was chosen by the operating system.
inline bool announce(const std::string& path, const std::string& endpoint, std::uint64_t pid) {
  if (path.empty()) return true;
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) return false;
  file << endpoint << "\n" << pid << "\n";
  file.flush();
  return static_cast<bool>(file);
}

inline int fail(const std::string& message) {
  std::cerr << "error: " << message << "\n";
  return 2;
}

}  // namespace sbf::cli
