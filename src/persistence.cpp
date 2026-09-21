#include "sbf/persistence.hpp"

#include <cstdio>
#include <cstring>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace sbf {
namespace {

Status flush_to_disk(std::FILE* file) {
  if (std::fflush(file) != 0) {
    return Status::make(Outcome::Unreachable, Reason::EffectNotVerified, 1);
  }
#ifdef _WIN32
  if (_commit(_fileno(file)) != 0) {
    return Status::make(Outcome::Unreachable, Reason::EffectNotVerified, 2);
  }
#else
  if (fsync(fileno(file)) != 0) {
    return Status::make(Outcome::Unreachable, Reason::EffectNotVerified, 3);
  }
#endif
  return Status::ok();
}

Status rename_replace(const std::filesystem::path& from, const std::filesystem::path& to) {
#ifdef _WIN32
  if (MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return Status::make(Outcome::Unreachable, Reason::EffectNotVerified,
                        static_cast<std::uint64_t>(GetLastError()));
  }
  return Status::ok();
#else
  std::error_code ec;
  std::filesystem::rename(from, to, ec);
  if (ec) return Status::make(Outcome::Unreachable, Reason::EffectNotVerified, ec.value());
  return Status::ok();
#endif
}

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

void put_u64(std::string& out, std::uint64_t v) {
  put_u32(out, static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
  put_u32(out, static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFu));
}

std::uint32_t read_u32(const char* p) {
  return static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[0])) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[1])) << 8) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[2])) << 16) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[3])) << 24);
}

std::uint64_t read_u64(const char* p) {
  return static_cast<std::uint64_t>(read_u32(p)) |
         (static_cast<std::uint64_t>(read_u32(p + 4)) << 32);
}

}  // namespace

std::string encode_store_header(const StoreHeader& header) {
  CanonicalWriter writer;
  writer.u32(header.magic);
  writer.u16(header.format_version);
  writer.u16(header.reserved);
  writer.text(header.store_id.view());
  writer.u64(header.created_at.value());
  writer.u64(header.created_by_boot.value());
  const std::uint32_t crc = crc32c(writer.bytes());
  writer.u32(crc);
  writer.digest(Digest256::of(writer.bytes()));
  return std::move(writer).take();
}

Status decode_store_header(std::string_view bytes, StoreHeader& out) {
  CanonicalReader reader(bytes);
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t reserved = 0;
  std::string store_id;
  std::uint64_t created = 0;
  std::uint64_t boot = 0;
  std::uint32_t crc = 0;
  Digest256 digest;
  if (auto st = reader.u32(magic); !st.is_ok()) return st;
  if (auto st = reader.u16(version); !st.is_ok()) return st;
  if (auto st = reader.u16(reserved); !st.is_ok()) return st;
  if (auto st = reader.text(store_id); !st.is_ok()) return st;
  if (auto st = reader.u64(created); !st.is_ok()) return st;
  if (auto st = reader.u64(boot); !st.is_ok()) return st;
  // The CRC field starts where the reader currently stands; the digest that
  // follows covers everything up to and including the CRC.
  if (reader.remaining() < 4 + 32) {
    return Status::make(Outcome::Corrupt, Reason::TruncatedFrame, bytes.size());
  }
  const std::size_t crc_position = bytes.size() - reader.remaining();
  if (auto st = reader.u32(crc); !st.is_ok()) return st;
  if (auto st = reader.digest(digest); !st.is_ok()) return st;
  if (auto st = reader.finish(); !st.is_ok()) return st;
  if (magic != kStoreMagic) return Status::make(Outcome::Corrupt, Reason::BadMagic, magic);
  if (version != kStoreFormatVersion) {
    return Status::make(Outcome::Unsupported, Reason::UnsupportedVersion, version);
  }
  if (crc32c(bytes.substr(0, crc_position)) != crc) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, crc_position);
  }
  if (!(Digest256::of(bytes.substr(0, crc_position + 4)) == digest)) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, crc_position + 4);
  }
  auto id = StoreId::try_make(store_id);
  if (!id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  out.magic = magic;
  out.format_version = version;
  out.reserved = reserved;
  out.store_id = *id;
  out.created_at = Step{created};
  out.created_by_boot = BootId{boot};
  out.header_digest = digest;
  return Status::ok();
}

Status write_store_header(const std::filesystem::path& path, const StoreHeader& header) {
  return atomic_write_file(path, encode_store_header(header));
}

Status read_store_header(const std::filesystem::path& path, StoreHeader& out) {
  std::string bytes;
  if (auto st = read_file_bounded(path, 4096, bytes); !st.is_ok()) return st;
  return decode_store_header(bytes, out);
}

namespace {

std::string encode_snapshot_header(const SnapshotHeader& header) {
  CanonicalWriter writer;
  writer.u32(header.magic);
  writer.u16(header.format_version);
  writer.u16(header.reserved);
  writer.text(header.store_id.view());
  writer.u64(header.covers_sequence.value());
  writer.u64(header.taken_at.value());
  writer.u64(header.payload_length);
  writer.digest(header.payload_digest);
  const std::uint32_t crc = crc32c(writer.bytes());
  writer.u32(crc);
  return std::move(writer).take();
}

Status decode_snapshot_header(std::string_view bytes, std::size_t& consumed, SnapshotHeader& out) {
  CanonicalReader reader(bytes);
  std::uint32_t magic = 0;
  std::uint16_t version = 0;
  std::uint16_t reserved = 0;
  std::string store_id;
  std::uint64_t covers = 0;
  std::uint64_t taken = 0;
  std::uint64_t payload_length = 0;
  Digest256 payload_digest;
  std::uint32_t crc = 0;
  if (auto st = reader.u32(magic); !st.is_ok()) return st;
  if (auto st = reader.u16(version); !st.is_ok()) return st;
  if (auto st = reader.u16(reserved); !st.is_ok()) return st;
  if (auto st = reader.text(store_id); !st.is_ok()) return st;
  if (auto st = reader.u64(covers); !st.is_ok()) return st;
  if (auto st = reader.u64(taken); !st.is_ok()) return st;
  if (auto st = reader.u64(payload_length); !st.is_ok()) return st;
  if (auto st = reader.digest(payload_digest); !st.is_ok()) return st;
  const std::size_t crc_position = bytes.size() - reader.remaining();
  if (auto st = reader.u32(crc); !st.is_ok()) return st;
  if (magic != kStoreMagic) return Status::make(Outcome::Corrupt, Reason::BadMagic, magic);
  if (version != kStoreFormatVersion) {
    return Status::make(Outcome::Unsupported, Reason::UnsupportedVersion, version);
  }
  if (payload_length > limits::kMaxSnapshotBytes) {
    return Status::make(Outcome::Invalid, Reason::ImpossibleLength, payload_length);
  }
  if (crc32c(bytes.substr(0, crc_position)) != crc) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, crc_position);
  }
  auto id = StoreId::try_make(store_id);
  if (!id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  out.magic = magic;
  out.format_version = version;
  out.reserved = reserved;
  out.store_id = *id;
  out.covers_sequence = Sequence{covers};
  out.taken_at = Step{taken};
  out.payload_length = payload_length;
  out.payload_digest = payload_digest;
  out.header_crc = crc;
  consumed = crc_position + 4;
  return Status::ok();
}

}  // namespace

bool record_kind_valid(std::uint16_t raw) noexcept {
  switch (static_cast<RecordKind>(raw)) {
    case RecordKind::StoreHeader:
    case RecordKind::BootBegin:
    case RecordKind::BootEnd:
    case RecordKind::PolicyDefine:
    case RecordKind::GrantOpen:
    case RecordKind::GrantClose:
    case RecordKind::Fence:
    case RecordKind::ExtentAdopt:
    case RecordKind::CommitRecord:
    case RecordKind::InterruptMark:
    case RecordKind::StoreIdAssign:
    case RecordKind::StepAdvance:
    case RecordKind::DomainDefine:
    case RecordKind::IncarnationAllocate:
      return true;
  }
  return false;
}

std::string_view to_string(RecordKind kind) noexcept {
  switch (kind) {
    case RecordKind::StoreHeader: return "StoreHeader";
    case RecordKind::BootBegin: return "BootBegin";
    case RecordKind::BootEnd: return "BootEnd";
    case RecordKind::PolicyDefine: return "PolicyDefine";
    case RecordKind::GrantOpen: return "GrantOpen";
    case RecordKind::GrantClose: return "GrantClose";
    case RecordKind::Fence: return "Fence";
    case RecordKind::ExtentAdopt: return "ExtentAdopt";
    case RecordKind::CommitRecord: return "CommitRecord";
    case RecordKind::InterruptMark: return "InterruptMark";
    case RecordKind::StoreIdAssign: return "StoreIdAssign";
    case RecordKind::StepAdvance: return "StepAdvance";
    case RecordKind::DomainDefine: return "DomainDefine";
    case RecordKind::IncarnationAllocate: return "IncarnationAllocate";
  }
  return "Unknown";
}

std::string Store::encode_record(const JournalRecord& record) {
  CanonicalWriter writer;
  writer.u16(static_cast<std::uint16_t>(record.kind));
  writer.u64(record.sequence.value());
  writer.u64(record.step.value());
  writer.outcome(record.status.outcome);
  writer.reason(record.status.reason);
  writer.u64(record.status.aux);
  writer.blob(record.payload);
  return std::move(writer).take();
}

Status Store::decode_record(std::string_view bytes, JournalRecord& out) {
  CanonicalReader reader(bytes);
  std::uint16_t kind = 0;
  std::uint64_t sequence = 0;
  std::uint64_t step = 0;
  Outcome outcome = Outcome::Ok;
  Reason reason = Reason::None;
  std::uint64_t aux = 0;
  std::string payload;
  if (auto st = reader.u16(kind); !st.is_ok()) return st;
  if (auto st = reader.u64(sequence); !st.is_ok()) return st;
  if (auto st = reader.u64(step); !st.is_ok()) return st;
  if (auto st = reader.outcome(outcome); !st.is_ok()) return st;
  if (auto st = reader.reason(reason); !st.is_ok()) return st;
  if (auto st = reader.u64(aux); !st.is_ok()) return st;
  if (auto st = reader.blob(payload); !st.is_ok()) return st;
  if (auto st = reader.finish(); !st.is_ok()) return st;
  if (!record_kind_valid(kind)) return Status::make(Outcome::Invalid, Reason::InvalidEnum, kind);
  if (sequence == 0) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  out.kind = static_cast<RecordKind>(kind);
  out.sequence = Sequence{sequence};
  out.step = Step{step};
  out.status = Status{outcome, reason, aux};
  out.payload = std::move(payload);
  return Status::ok();
}

Status ensure_directory(const std::filesystem::path& dir) {
  std::error_code ec;
  if (std::filesystem::exists(dir, ec)) {
    if (!std::filesystem::is_directory(dir, ec)) {
      return Status::make(Outcome::Invalid, Reason::StoreNotFound);
    }
    return Status::ok();
  }
  std::filesystem::create_directories(dir, ec);
  if (ec) return Status::make(Outcome::Unreachable, Reason::StoreNotFound, ec.value());
  return Status::ok();
}

Status read_file_bounded(const std::filesystem::path& path, std::uint64_t max_bytes,
                         std::string& out) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  if (ec) return Status::make(Outcome::NotFound, Reason::StoreNotFound);
  if (size > max_bytes) return Status::make(Outcome::Invalid, Reason::ImpossibleLength, size);
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (file == nullptr) return Status::make(Outcome::NotFound, Reason::StoreNotFound);
  out.resize(static_cast<std::size_t>(size));
  const std::size_t read = out.empty() ? 0 : std::fread(out.data(), 1, out.size(), file);
  std::fclose(file);
  if (read != out.size()) return Status::make(Outcome::Corrupt, Reason::TruncatedFrame, read);
  return Status::ok();
}

Status remove_file_if_exists(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
  if (ec) return Status::make(Outcome::Unreachable, Reason::StoreNotFound, ec.value());
  return Status::ok();
}

Status atomic_write_file(const std::filesystem::path& target, std::string_view bytes) {
  std::filesystem::path staging = target;
  staging += ".staging";
  {
    std::FILE* file = std::fopen(staging.string().c_str(), "wb");
    if (file == nullptr) return Status::make(Outcome::Unreachable, Reason::StoreNotFound);
    const std::size_t written =
        bytes.empty() ? 0 : std::fwrite(bytes.data(), 1, bytes.size(), file);
    if (written != bytes.size()) {
      std::fclose(file);
      return Status::make(Outcome::Unreachable, Reason::EffectNotVerified, written);
    }
    if (auto st = flush_to_disk(file); !st.is_ok()) {
      std::fclose(file);
      return st;
    }
    std::fclose(file);
  }
  return rename_replace(staging, target);
}

Store::~Store() {
  if (file_ != nullptr) {
    std::fclose(static_cast<std::FILE*>(file_));
    file_ = nullptr;
  }
}

Store::Store(Store&& other) noexcept
    : directory_(std::move(other.directory_)),
      journal_path_(std::move(other.journal_path_)),
      snapshot_path_(std::move(other.snapshot_path_)),
      store_id_(std::move(other.store_id_)),
      file_(other.file_),
      last_sequence_(other.last_sequence_),
      records_appended_(other.records_appended_),
      torn_tail_recovered_(other.torn_tail_recovered_) {
  other.file_ = nullptr;
}

Store& Store::operator=(Store&& other) noexcept {
  if (this != &other) {
    if (file_ != nullptr) std::fclose(static_cast<std::FILE*>(file_));
    directory_ = std::move(other.directory_);
    journal_path_ = std::move(other.journal_path_);
    snapshot_path_ = std::move(other.snapshot_path_);
    store_id_ = std::move(other.store_id_);
    file_ = other.file_;
    last_sequence_ = other.last_sequence_;
    records_appended_ = other.records_appended_;
    torn_tail_recovered_ = other.torn_tail_recovered_;
    other.file_ = nullptr;
  }
  return *this;
}

Status Store::open(const std::filesystem::path& directory, const StoreId& store_id,
                   const StoreOpenOptions& options, Store& out, StoreRecoveryReport& report) {
  if (store_id.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  if (auto st = ensure_directory(directory); !st.is_ok()) return st;

  Store store;
  store.directory_ = directory;
  store.journal_path_ = directory / "sbf.journal";
  store.snapshot_path_ = directory / "sbf.snapshot";
  store.store_id_ = store_id;

  const std::filesystem::path header_path = directory / "sbf.store";
  std::error_code ec;
  const bool header_exists = std::filesystem::exists(header_path, ec);
  if (!header_exists) {
    if (!options.create_if_missing) {
      return Status::make(Outcome::NotFound, Reason::StoreNotFound);
    }
    StoreHeader header;
    header.store_id = store_id;
    header.created_at = Step{1};
    header.created_by_boot = options.opening_boot;
    if (auto st = atomic_write_file(header_path, encode_store_header(header)); !st.is_ok()) {
      return st;
    }
    report.created = true;
  } else {
    std::string bytes;
    if (auto st = read_file_bounded(header_path, 4096, bytes); !st.is_ok()) return st;
    StoreHeader header;
    if (auto st = decode_store_header(bytes, header); !st.is_ok()) return st;
    if (!(header.store_id == store_id)) {
      return Status::make(Outcome::Conflict, Reason::StoreNotFound);
    }
  }

  // ---- snapshot --------------------------------------------------------------
  Sequence snapshot_covers;
  if (std::filesystem::exists(store.snapshot_path_, ec)) {
    std::string bytes;
    if (auto st = read_file_bounded(store.snapshot_path_, limits::kMaxSnapshotBytes + 4096, bytes);
        !st.is_ok()) {
      return st;
    }
    std::size_t consumed = 0;
    SnapshotHeader header;
    if (auto st = decode_snapshot_header(bytes, consumed, header); !st.is_ok()) return st;
    if (!(header.store_id == store_id)) {
      return Status::make(Outcome::Conflict, Reason::StoreNotFound);
    }
    if (bytes.size() - consumed != header.payload_length) {
      return Status::make(Outcome::Corrupt, Reason::ImpossibleLength,
                          bytes.size() - consumed);
    }
    const std::string_view payload(bytes.data() + consumed,
                                   static_cast<std::size_t>(header.payload_length));
    if (!(Digest256::of(payload) == header.payload_digest)) {
      return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, consumed);
    }
    snapshot_covers = header.covers_sequence;
    report.snapshot_loaded = true;
    store.last_sequence_ = header.covers_sequence;
  }

  // ---- journal ---------------------------------------------------------------
  std::uint64_t expected = snapshot_covers.value() + 1;
  if (std::filesystem::exists(store.journal_path_, ec)) {
    std::string bytes;
    if (auto st = read_file_bounded(store.journal_path_, limits::kMaxFabricStoreBytes, bytes);
        !st.is_ok()) {
      return st;
    }
    std::size_t offset = 0;
    std::size_t good_end = 0;
    while (offset < bytes.size()) {
      if (bytes.size() - offset < kRecordPrefixBytes) {
        if (!options.allow_torn_tail_recovery) {
          return Status::make(Outcome::Corrupt, Reason::TornTail, offset);
        }
        report.torn_tail_recovered = true;
        report.torn_tail_bytes = bytes.size() - offset;
        break;
      }
      const std::uint32_t length = read_u32(bytes.data() + offset);
      const std::uint32_t expected_crc = read_u32(bytes.data() + offset + 4);
      if (length == 0 || length > limits::kMaxJournalRecordBytes) {
        // The prefix is complete, so this is a corrupt record rather than a torn
        // tail: refuse rather than silently discarding bytes.
        return Status::make(Outcome::Corrupt, Reason::ImpossibleLength, length);
      }
      if (bytes.size() - offset - kRecordPrefixBytes < length) {
        if (!options.allow_torn_tail_recovery) {
          return Status::make(Outcome::Corrupt, Reason::TornTail, offset);
        }
        report.torn_tail_recovered = true;
        report.torn_tail_bytes = bytes.size() - offset;
        break;
      }
      const std::string_view payload(bytes.data() + offset + kRecordPrefixBytes, length);
      if (crc32c(payload) != expected_crc) {
        return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, offset);
      }
      JournalRecord record;
      if (auto st = Store::decode_record(payload, record); !st.is_ok()) return st;
      if (record.sequence.value() + 1 <= expected) {
        // Already reflected in the snapshot: a crash between the snapshot rename
        // and the journal rotation. Safe to skip, and the skip is reported.
        offset += kRecordPrefixBytes + length;
        good_end = offset;
        continue;
      }
      if (record.sequence.value() != expected) {
        return Status::make(Outcome::Corrupt, Reason::SequenceRegression, record.sequence.value());
      }
      expected = record.sequence.value() + 1;
      ++report.journal_records;
      report.last_sequence = record.sequence;
      report.last_step = record.step;
      if (record.sequence > store.last_sequence_) store.last_sequence_ = record.sequence;
      offset += kRecordPrefixBytes + length;
      good_end = offset;
    }
    if (report.torn_tail_recovered) {
      // Durable, reported truncation of a genuinely partial trailing record.
      std::FILE* file = std::fopen(store.journal_path_.string().c_str(), "r+b");
      if (file == nullptr) return Status::make(Outcome::Unreachable, Reason::StoreNotFound);
#ifdef _WIN32
      const int rc = _chsize_s(_fileno(file), static_cast<long long>(good_end));
#else
      const int rc = ftruncate(fileno(file), static_cast<off_t>(good_end));
#endif
      std::fclose(file);
      if (rc != 0) return Status::make(Outcome::Unreachable, Reason::EffectNotVerified);
      store.torn_tail_recovered_ = true;
    }
  }

  std::FILE* journal = std::fopen(store.journal_path_.string().c_str(), "ab");
  if (journal == nullptr) return Status::make(Outcome::Unreachable, Reason::StoreNotFound);
  store.file_ = journal;
  out = std::move(store);
  return Status::ok();
}

Status Store::append(const JournalRecord& record) {
  if (file_ == nullptr) return Status::make(Outcome::Closed, Reason::StoreBusy);
  if (!record_kind_valid(static_cast<std::uint16_t>(record.kind))) {
    return Status::make(Outcome::Invalid, Reason::InvalidEnum);
  }
  if (record.sequence.value() != last_sequence_.value() + 1) {
    return Status::make(Outcome::Invalid, Reason::SequenceRegression, record.sequence.value());
  }
  const std::string payload = encode_record(record);
  if (payload.size() > limits::kMaxJournalRecordBytes) {
    return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, payload.size());
  }
  std::string prefix;
  put_u32(prefix, static_cast<std::uint32_t>(payload.size()));
  put_u32(prefix, crc32c(payload));

  auto* file = static_cast<std::FILE*>(file_);
  if (std::fwrite(prefix.data(), 1, prefix.size(), file) != prefix.size()) {
    return Status::make(Outcome::Unreachable, Reason::EffectNotVerified);
  }
  if (std::fwrite(payload.data(), 1, payload.size(), file) != payload.size()) {
    return Status::make(Outcome::Unreachable, Reason::EffectNotVerified);
  }
  // Append/flush ordering: a record is only reported durable after the bytes are
  // flushed to the operating system and forced to stable storage.
  if (auto st = flush_to_disk(file); !st.is_ok()) return st;
  last_sequence_ = record.sequence;
  ++records_appended_;
  return Status::ok();
}

Status Store::flush() {
  if (file_ == nullptr) return Status::make(Outcome::Closed, Reason::StoreBusy);
  return flush_to_disk(static_cast<std::FILE*>(file_));
}

Status Store::checkpoint(std::string_view state_blob, Sequence covers_sequence, Step now) {
  if (file_ == nullptr) return Status::make(Outcome::Closed, Reason::StoreBusy);
  if (!(covers_sequence == last_sequence_)) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, covers_sequence.value());
  }
  if (state_blob.size() > limits::kMaxSnapshotBytes) {
    return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, state_blob.size());
  }
  SnapshotHeader header;
  header.store_id = store_id_;
  header.covers_sequence = covers_sequence;
  header.taken_at = now;
  header.payload_length = state_blob.size();
  header.payload_digest = Digest256::of(state_blob);

  std::string bytes = encode_snapshot_header(header);
  bytes.append(state_blob);
  if (auto st = atomic_write_file(snapshot_path_, bytes); !st.is_ok()) return st;

  // Rotate the journal only after the snapshot is durably in place. A crash
  // between the two leaves a superset journal that recovery skips over.
  if (auto st = flush_to_disk(static_cast<std::FILE*>(file_)); !st.is_ok()) return st;
  std::fclose(static_cast<std::FILE*>(file_));
  file_ = nullptr;
  if (auto st = atomic_write_file(journal_path_, std::string_view{}); !st.is_ok()) {
    return st;
  }
  std::FILE* journal = std::fopen(journal_path_.string().c_str(), "ab");
  if (journal == nullptr) return Status::make(Outcome::Unreachable, Reason::StoreNotFound);
  file_ = journal;
  last_sequence_ = covers_sequence;
  return Status::ok();
}

Status Store::replay(const std::function<Status(const JournalRecord&)>& visitor) const {
  std::error_code ec;
  if (!std::filesystem::exists(journal_path_, ec)) return Status::ok();
  std::string bytes;
  std::uint64_t bound = limits::kMaxFabricStoreBytes;
  if (auto st = read_file_bounded(journal_path_, bound, bytes); !st.is_ok()) return st;
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < kRecordPrefixBytes) break;
    const std::uint32_t length = read_u32(bytes.data() + offset);
    const std::uint32_t expected_crc = read_u32(bytes.data() + offset + 4);
    if (length == 0 || length > limits::kMaxJournalRecordBytes) {
      return Status::make(Outcome::Corrupt, Reason::ImpossibleLength, length);
    }
    if (bytes.size() - offset - kRecordPrefixBytes < length) break;
    const std::string_view payload(bytes.data() + offset + kRecordPrefixBytes, length);
    if (crc32c(payload) != expected_crc) {
      return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, offset);
    }
    JournalRecord record;
    if (auto st = Store::decode_record(payload, record); !st.is_ok()) return st;
    if (auto st = visitor(record); !st.is_ok()) return st;
    offset += kRecordPrefixBytes + length;
  }
  return Status::ok();
}

Status Store::load_snapshot(std::string& blob, SnapshotHeader& header) const {
  std::error_code ec;
  if (!std::filesystem::exists(snapshot_path_, ec)) {
    return Status::make(Outcome::NotFound, Reason::StoreNotFound);
  }
  std::string bytes;
  if (auto st = read_file_bounded(snapshot_path_, limits::kMaxSnapshotBytes + 4096, bytes);
      !st.is_ok()) {
    return st;
  }
  std::size_t consumed = 0;
  if (auto st = decode_snapshot_header(bytes, consumed, header); !st.is_ok()) return st;
  if (bytes.size() - consumed != header.payload_length) {
    return Status::make(Outcome::Corrupt, Reason::ImpossibleLength, bytes.size() - consumed);
  }
  const std::string_view payload(bytes.data() + consumed,
                                 static_cast<std::size_t>(header.payload_length));
  if (!(Digest256::of(payload) == header.payload_digest)) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, consumed);
  }
  blob.assign(payload);
  return Status::ok();
}

}  // namespace sbf
