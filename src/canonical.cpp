#include "sbf/canonical.hpp"

#include <cstring>

namespace sbf {
namespace {

void put_u16(std::string& out, std::uint16_t v) {
  out.push_back(static_cast<char>(v & 0xFFu));
  out.push_back(static_cast<char>((v >> 8) & 0xFFu));
}

void put_u32(std::string& out, std::uint32_t v) {
  out.push_back(static_cast<char>(v & 0xFFu));
  out.push_back(static_cast<char>((v >> 8) & 0xFFu));
  out.push_back(static_cast<char>((v >> 16) & 0xFFu));
  out.push_back(static_cast<char>((v >> 24) & 0xFFu));
}

}  // namespace

void CanonicalWriter::u8(std::uint8_t v) { bytes_.push_back(static_cast<char>(v)); }

void CanonicalWriter::u16(std::uint16_t v) { put_u16(bytes_, v); }

void CanonicalWriter::u32(std::uint32_t v) { put_u32(bytes_, v); }

void CanonicalWriter::u64(std::uint64_t v) {
  put_u32(bytes_, static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
  put_u32(bytes_, static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFu));
}

void CanonicalWriter::i64(std::int64_t v) { u64(static_cast<std::uint64_t>(v)); }

void CanonicalWriter::text(std::string_view v) {
  u16(static_cast<std::uint16_t>(v.size()));
  bytes_.append(v);
}

void CanonicalWriter::blob(std::string_view v) {
  u32(static_cast<std::uint32_t>(v.size()));
  bytes_.append(v);
}

void CanonicalWriter::digest(const Digest256& v) {
  const auto& raw = v.bytes();
  bytes_.append(reinterpret_cast<const char*>(raw.data()), raw.size());
}

Status CanonicalReader::u8(std::uint8_t& out) noexcept {
  if (remaining() < 1) return Status::make(Outcome::Invalid, Reason::TruncatedFrame, offset_);
  out = static_cast<std::uint8_t>(data_[offset_]);
  ++offset_;
  return Status::ok();
}

Status CanonicalReader::u16(std::uint16_t& out) noexcept {
  if (remaining() < 2) return Status::make(Outcome::Invalid, Reason::TruncatedFrame, offset_);
  out = static_cast<std::uint16_t>(static_cast<std::uint8_t>(data_[offset_])) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(static_cast<std::uint8_t>(data_[offset_ + 1])) << 8);
  offset_ += 2;
  return Status::ok();
}

Status CanonicalReader::u32(std::uint32_t& out) noexcept {
  if (remaining() < 4) return Status::make(Outcome::Invalid, Reason::TruncatedFrame, offset_);
  out = 0;
  for (int i = 0; i < 4; ++i) {
    out |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(data_[offset_ + static_cast<std::size_t>(i)]))
           << (8 * i);
  }
  offset_ += 4;
  return Status::ok();
}

Status CanonicalReader::u64(std::uint64_t& out) noexcept {
  std::uint32_t low = 0;
  std::uint32_t high = 0;
  if (auto st = u32(low); !st.is_ok()) return st;
  if (auto st = u32(high); !st.is_ok()) return st;
  out = static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32);
  return Status::ok();
}

Status CanonicalReader::i64(std::int64_t& out) noexcept {
  std::uint64_t raw = 0;
  if (auto st = u64(raw); !st.is_ok()) return st;
  out = static_cast<std::int64_t>(raw);
  return Status::ok();
}

Status CanonicalReader::boolean(bool& out) noexcept {
  std::uint8_t raw = 0;
  if (auto st = u8(raw); !st.is_ok()) return st;
  if (raw > 1) return Status::make(Outcome::Invalid, Reason::InvalidEnum, raw);
  out = raw == 1;
  return Status::ok();
}

Status CanonicalReader::text(std::string& out) noexcept {
  std::uint16_t length = 0;
  if (auto st = u16(length); !st.is_ok()) return st;
  if (remaining() < length) return Status::make(Outcome::Invalid, Reason::TruncatedFrame, offset_);
  out.assign(data_.substr(offset_, length));
  offset_ += length;
  return Status::ok();
}

Status CanonicalReader::blob(std::string& out) noexcept {
  std::uint32_t length = 0;
  if (auto st = u32(length); !st.is_ok()) return st;
  if (length > limits::kMaxSnapshotBytes) {
    return Status::make(Outcome::Invalid, Reason::ImpossibleLength, length);
  }
  if (remaining() < length) return Status::make(Outcome::Invalid, Reason::TruncatedFrame, offset_);
  out.assign(data_.substr(offset_, length));
  offset_ += length;
  return Status::ok();
}

Status CanonicalReader::digest(Digest256& out) noexcept {
  if (remaining() < 32) return Status::make(Outcome::Invalid, Reason::TruncatedFrame, offset_);
  std::array<std::uint8_t, 32> raw{};
  for (std::size_t i = 0; i < 32; ++i) raw[i] = static_cast<std::uint8_t>(data_[offset_ + i]);
  offset_ += 32;
  out = Digest256::from_raw(raw);
  return Status::ok();
}

Status CanonicalReader::outcome(Outcome& out) noexcept {
  std::uint16_t raw = 0;
  if (auto st = u16(raw); !st.is_ok()) return st;
  if (raw > static_cast<std::uint16_t>(Outcome::Closed)) {
    return Status::make(Outcome::Invalid, Reason::InvalidEnum, raw);
  }
  out = static_cast<Outcome>(raw);
  return Status::ok();
}

Status CanonicalReader::reason(Reason& out) noexcept {
  std::uint16_t raw = 0;
  if (auto st = u16(raw); !st.is_ok()) return st;
  if (!reason_from_code(raw, out)) return Status::make(Outcome::Invalid, Reason::InvalidEnum, raw);
  return Status::ok();
}

Status CanonicalReader::count(std::uint32_t bound, std::uint32_t& out) noexcept {
  std::uint32_t raw = 0;
  if (auto st = u32(raw); !st.is_ok()) return st;
  if (raw > bound) return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, raw);
  // A collection can never claim more elements than there are remaining bytes
  // (each element costs at least one byte), so this rejects absurd counts before
  // any allocation happens.
  if (raw > remaining()) return Status::make(Outcome::Invalid, Reason::ImpossibleLength, raw);
  out = raw;
  return Status::ok();
}

Status CanonicalReader::finish() const noexcept {
  if (!exhausted()) {
    return Status::make(Outcome::Invalid, Reason::TrailingGarbage, remaining());
  }
  return Status::ok();
}

}  // namespace sbf
