#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "sbf/status.hpp"

namespace sbf {

// CRC-32C (Castagnoli). Used for frame integrity, durable record integrity and
// torn-tail detection. It detects accidental corruption only; it is not a MAC
// and provides no authenticity whatsoever.
std::uint32_t crc32c(const std::uint8_t* data, std::size_t size) noexcept;
std::uint32_t crc32c(std::string_view data) noexcept;

// Streaming CRC-32C so that large payloads need not be buffered twice.
class Crc32cBuilder {
 public:
  void update(const std::uint8_t* data, std::size_t size) noexcept;
  void update(std::string_view data) noexcept {
    update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  }
  std::uint32_t value() const noexcept;
  void reset() noexcept { state_ = 0; }

 private:
  std::uint32_t state_ = 0;
};

// A 256-bit content fingerprint (FIPS 180-4 SHA-256). This is a collision
// resistant identity function, not a security mechanism: nothing here is keyed,
// so a digest proves nothing about who produced the bytes.
class Digest256 {
 public:
  Digest256() = default;

  static Digest256 of(const std::uint8_t* data, std::size_t size) noexcept;
  static Digest256 of(std::string_view data) noexcept {
    return of(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
  }
  static Status parse(std::string_view hex, Digest256& out) noexcept;
  static Digest256 from_raw(const std::array<std::uint8_t, 32>& raw) noexcept {
    Digest256 digest;
    digest.bytes_ = raw;
    return digest;
  }

  std::string hex() const;
  const std::array<std::uint8_t, 32>& bytes() const noexcept { return bytes_; }

  friend bool operator==(const Digest256&, const Digest256&) = default;
  friend std::strong_ordering operator<=>(const Digest256& a, const Digest256& b) noexcept {
    return a.bytes_ <=> b.bytes_;
  }

 private:
  std::array<std::uint8_t, 32> bytes_{};
};

class Sha256Builder {
 public:
  void update(const std::uint8_t* data, std::size_t size) noexcept;
  Digest256 finish() noexcept;

 private:
  void compress(const std::uint8_t block[64]) noexcept;

  std::uint32_t state_[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                             0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  std::uint8_t buffer_[64] = {};
  std::uint64_t bit_length_ = 0;
  std::size_t buffer_length_ = 0;
};

}  // namespace sbf
