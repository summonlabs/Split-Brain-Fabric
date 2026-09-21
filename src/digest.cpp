#include "sbf/digest.hpp"

#include <cstring>

namespace sbf {
namespace {

// Reflected CRC-32C (Castagnoli) table, built once at first use.
struct Crc32cTable {
  std::uint32_t entries[256];
  constexpr Crc32cTable() : entries() {
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t crc = i;
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc & 1u) ? ((crc >> 1) ^ 0x82F63B78u) : (crc >> 1);
      }
      entries[i] = crc;
    }
  }
};

constexpr Crc32cTable kCrcTable{};

inline std::uint32_t rotate_right(std::uint32_t value, std::uint32_t count) noexcept {
  return (value >> count) | (value << (32u - count));
}

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

}  // namespace

std::uint32_t crc32c(const std::uint8_t* data, std::size_t size) noexcept {
  Crc32cBuilder builder;
  builder.update(data, size);
  return builder.value();
}

std::uint32_t crc32c(std::string_view data) noexcept {
  return crc32c(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

void Crc32cBuilder::update(const std::uint8_t* data, std::size_t size) noexcept {
  std::uint32_t crc = state_ ^ 0xFFFFFFFFu;
  for (std::size_t i = 0; i < size; ++i) {
    crc = kCrcTable.entries[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
  }
  state_ = crc ^ 0xFFFFFFFFu;
}

std::uint32_t Crc32cBuilder::value() const noexcept { return state_; }

void Sha256Builder::compress(const std::uint8_t block[64]) noexcept {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
  std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

  for (int i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
  state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256Builder::update(const std::uint8_t* data, std::size_t size) noexcept {
  bit_length_ += static_cast<std::uint64_t>(size) * 8u;
  std::size_t offset = 0;
  while (offset < size) {
    const std::size_t take = (size - offset < 64 - buffer_length_) ? (size - offset) : (64 - buffer_length_);
    std::memcpy(buffer_ + buffer_length_, data + offset, take);
    buffer_length_ += take;
    offset += take;
    if (buffer_length_ == 64) {
      compress(buffer_);
      buffer_length_ = 0;
    }
  }
}

Digest256 Sha256Builder::finish() noexcept {
  const std::uint64_t bits = bit_length_;
  buffer_[buffer_length_++] = 0x80u;
  if (buffer_length_ > 56) {
    while (buffer_length_ < 64) buffer_[buffer_length_++] = 0;
    compress(buffer_);
    buffer_length_ = 0;
  }
  while (buffer_length_ < 56) buffer_[buffer_length_++] = 0;
  for (int i = 7; i >= 0; --i) {
    buffer_[buffer_length_++] = static_cast<std::uint8_t>((bits >> (i * 8)) & 0xFFu);
  }
  compress(buffer_);
  buffer_length_ = 0;

  std::array<std::uint8_t, 32> bytes{};
  for (int i = 0; i < 8; ++i) {
    bytes[static_cast<std::size_t>(i) * 4 + 0] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFFu);
    bytes[static_cast<std::size_t>(i) * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFFu);
    bytes[static_cast<std::size_t>(i) * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFFu);
    bytes[static_cast<std::size_t>(i) * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFu);
  }
  return Digest256::from_raw(bytes);
}

Digest256 Digest256::of(const std::uint8_t* data, std::size_t size) noexcept {
  Sha256Builder builder;
  builder.update(data, size);
  return builder.finish();
}

Status Digest256::parse(std::string_view hex, Digest256& out) noexcept {
  if (hex.size() != 64) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, hex.size());
  }
  std::array<std::uint8_t, 32> bytes{};
  for (std::size_t i = 0; i < 32; ++i) {
    std::uint8_t value = 0;
    for (int nibble = 0; nibble < 2; ++nibble) {
      const char c = hex[i * 2 + static_cast<std::size_t>(nibble)];
      std::uint8_t digit = 0;
      if (c >= '0' && c <= '9') digit = static_cast<std::uint8_t>(c - '0');
      else if (c >= 'a' && c <= 'f') digit = static_cast<std::uint8_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') digit = static_cast<std::uint8_t>(c - 'A' + 10);
      else return Status::make(Outcome::Invalid, Reason::IdCharset, static_cast<std::uint64_t>(i * 2 + static_cast<std::size_t>(nibble)));
      value = static_cast<std::uint8_t>((value << 4) | digit);
    }
    bytes[i] = value;
  }
  out = Digest256::from_raw(bytes);
  return Status::ok();
}

std::string Digest256::hex() const {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.resize(64);
  for (std::size_t i = 0; i < 32; ++i) {
    out[i * 2] = kDigits[(bytes_[i] >> 4) & 0x0Fu];
    out[i * 2 + 1] = kDigits[bytes_[i] & 0x0Fu];
  }
  return out;
}

}  // namespace sbf
