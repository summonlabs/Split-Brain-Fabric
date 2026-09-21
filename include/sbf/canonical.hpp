#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include "sbf/digest.hpp"
#include "sbf/ids.hpp"
#include "sbf/limits.hpp"
#include "sbf/status.hpp"

namespace sbf {

// Deterministic canonical encoding.
//
// Layout rules (fixed, little-endian, no padding, no implicit lengths):
//   u8/u16/u32/u64/i64 : fixed width little-endian
//   bool               : u8, exactly 0 or 1
//   enum               : u16
//   text               : u16 byte length followed by the raw bytes
//   blob               : u32 byte length followed by the raw bytes
//   sequence<T>        : u32 element count followed by the elements
//   optional<T>        : u8 presence flag (0/1) followed by T when present
//
// Decoding is total: it either consumes exactly the encoded bytes and reports
// Ok, or reports a specific failing reason. Trailing bytes are an error.
class CanonicalWriter {
 public:
  void u8(std::uint8_t v);
  void u16(std::uint16_t v);
  void u32(std::uint32_t v);
  void u64(std::uint64_t v);
  void i64(std::int64_t v);
  void boolean(bool v) { u8(v ? 1u : 0u); }
  void text(std::string_view v);
  void blob(std::string_view v);
  void digest(const Digest256& v);
  void outcome(Outcome v) { u16(static_cast<std::uint16_t>(v)); }
  void reason(Reason v) { u16(static_cast<std::uint16_t>(v)); }

  template <class T>
  void counter(Counter<T> v) {
    u64(v.value());
  }

  template <class Fn>
  void sequence(std::size_t count, Fn&& fn) {
    u32(static_cast<std::uint32_t>(count));
    for (std::size_t i = 0; i < count; ++i) fn(i);
  }

  template <class Fn>
  void optional(bool present, Fn&& fn) {
    boolean(present);
    if (present) fn();
  }

  const std::string& bytes() const noexcept { return bytes_; }
  std::string take() && { return std::move(bytes_); }
  std::size_t size() const noexcept { return bytes_.size(); }
  void reserve(std::size_t n) { bytes_.reserve(n); }

 private:
  std::string bytes_;
};

class CanonicalReader {
 public:
  explicit CanonicalReader(std::string_view data) noexcept : data_(data) {}

  Status u8(std::uint8_t& out) noexcept;
  Status u16(std::uint16_t& out) noexcept;
  Status u32(std::uint32_t& out) noexcept;
  Status u64(std::uint64_t& out) noexcept;
  Status i64(std::int64_t& out) noexcept;
  Status boolean(bool& out) noexcept;
  Status text(std::string& out) noexcept;
  Status blob(std::string& out) noexcept;
  Status digest(Digest256& out) noexcept;
  Status outcome(Outcome& out) noexcept;
  Status reason(Reason& out) noexcept;

  template <class T>
  Status counter(Counter<T>& out) noexcept {
    std::uint64_t raw = 0;
    if (auto st = u64(raw); !st.is_ok()) return st;
    out = Counter<T>(raw);
    return Status::ok();
  }

  // Reads a sequence count and validates it against a bound before any
  // allocation is attempted.
  Status count(std::uint32_t bound, std::uint32_t& out) noexcept;

  template <class Fn>
  Status sequence(std::uint32_t bound, Fn&& fn) {
    std::uint32_t n = 0;
    if (auto st = count(bound, n); !st.is_ok()) return st;
    for (std::uint32_t i = 0; i < n; ++i) {
      if (auto st = fn(i); !st.is_ok()) return st;
    }
    return Status::ok();
  }

  template <class Fn>
  Status optional(Fn&& fn) {
    bool present = false;
    if (auto st = boolean(present); !st.is_ok()) return st;
    if (!present) return Status::ok();
    return fn();
  }

  // True only when every encoded byte was consumed.
  bool exhausted() const noexcept { return offset_ == data_.size(); }
  std::size_t remaining() const noexcept { return data_.size() - offset_; }
  // Returns Invalid/TrailingGarbage when bytes remain.
  Status finish() const noexcept;

 private:
  std::string_view data_;
  std::size_t offset_ = 0;
};

// Convenience: encode with fn, return the bytes.
template <class Fn>
std::string canonical_encode(Fn&& fn) {
  CanonicalWriter w;
  fn(w);
  return std::move(w).take();
}

}  // namespace sbf
