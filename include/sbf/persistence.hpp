#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "sbf/canonical.hpp"
#include "sbf/digest.hpp"
#include "sbf/ids.hpp"
#include "sbf/status.hpp"

namespace sbf {

// Durable record kinds. Numeric values are part of the on-disk format.
enum class RecordKind : std::uint16_t {
  StoreHeader = 1,
  BootBegin = 2,
  BootEnd = 3,
  PolicyDefine = 4,
  GrantOpen = 5,
  GrantClose = 6,
  Fence = 7,
  ExtentAdopt = 8,
  CommitRecord = 9,
  InterruptMark = 10,
  StoreIdAssign = 11,
  StepAdvance = 12,
  DomainDefine = 13,
  IncarnationAllocate = 14,
};

bool record_kind_valid(std::uint16_t raw) noexcept;
std::string_view to_string(RecordKind kind) noexcept;

struct JournalRecord {
  RecordKind kind = RecordKind::StoreHeader;
  Sequence sequence;                 // must be exactly previous + 1
  Step step;                         // logical step at append time
  Status status;                     // outcome/reason carried for diagnostics
  std::string payload;               // opaque canonical bytes
};

// On-disk layout constants.
inline constexpr std::uint32_t kStoreMagic = 0x31464253u;      // "SBF1"
inline constexpr std::uint16_t kStoreFormatVersion = 1;
inline constexpr std::uint32_t kRecordPrefixBytes = 8;         // u32 length + u32 crc
inline constexpr std::uint32_t kSnapshotHeaderBytes = 64;

struct StoreHeader {
  std::uint32_t magic = kStoreMagic;
  // Field order here mirrors the canonical on-disk encoding exactly.
  std::uint16_t format_version = kStoreFormatVersion;
  std::uint16_t reserved = 0;
  StoreId store_id;
  Step created_at;
  BootId created_by_boot;
  Digest256 header_digest;
};

struct SnapshotHeader {
  std::uint32_t magic = kStoreMagic;
  std::uint16_t format_version = kStoreFormatVersion;
  std::uint16_t reserved = 0;
  StoreId store_id;
  Sequence covers_sequence;         // journal sequence fully reflected in payload
  Step taken_at;
  std::uint64_t payload_length = 0;
  Digest256 payload_digest;
  std::uint32_t header_crc = 0;
};

struct StoreRecoveryReport {
  bool created = false;
  bool snapshot_loaded = false;
  bool torn_tail_recovered = false;
  std::uint64_t torn_tail_bytes = 0;
  std::uint64_t journal_records = 0;
  Sequence last_sequence;
  Step last_step;
  std::uint64_t checkpoints = 0;
};

struct StoreOpenOptions {
  bool create_if_missing = true;
  // Torn-tail recovery is only ever applied to a partially written final
  // record. Complete-but-corrupt records always fail the open.
  bool allow_torn_tail_recovery = true;
  BootId opening_boot;
};

// Versioned, integrity-checked, transactionally replaced durable log.
//
// Guarantees:
//   * every record carries a checked length and CRC-32C;
//   * sequences are strictly contiguous - a gap or regression fails the open;
//   * unknown record kinds and unsupported versions fail the open;
//   * only a genuinely truncated final record may be discarded, and doing so is
//     reported through StoreRecoveryReport;
//   * a checkpoint is written to a staging file, flushed, then renamed over the
//     live snapshot, so a crash never leaves a half-written snapshot visible.
class Store {
 public:
  Store() = default;
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  // Move-only: the durable handle is transferred and nulled in the source, so a
  // moved-from Store can never close the file the destination is still using.
  Store(Store&& other) noexcept;
  Store& operator=(Store&& other) noexcept;
  ~Store();

  static Status open(const std::filesystem::path& directory, const StoreId& store_id,
                     const StoreOpenOptions& options, Store& out,
                     StoreRecoveryReport& report);

  Status append(const JournalRecord& record);
  Status flush();
  // Writes the caller-supplied state blob as the new snapshot and rotates the
  // journal. The blob must already reflect every appended record.
  Status checkpoint(std::string_view state_blob, Sequence covers_sequence, Step now);

  Status replay(const std::function<Status(const JournalRecord&)>& visitor) const;
  Status load_snapshot(std::string& blob, SnapshotHeader& header) const;

  Sequence last_sequence() const noexcept { return last_sequence_; }
  const StoreId& store_id() const noexcept { return store_id_; }
  const std::filesystem::path& directory() const noexcept { return directory_; }
  std::uint64_t records_appended() const noexcept { return records_appended_; }
  bool torn_tail_recovered() const noexcept { return torn_tail_recovered_; }

  static std::string encode_record(const JournalRecord& record);
  static Status decode_record(std::string_view bytes, JournalRecord& out);

 private:
  std::filesystem::path directory_;
  std::filesystem::path journal_path_;
  std::filesystem::path snapshot_path_;
  StoreId store_id_;
  void* file_ = nullptr;  // std::FILE* kept opaque in the public header
  Sequence last_sequence_;
  std::uint64_t records_appended_ = 0;
  bool torn_tail_recovered_ = false;
};

// Store header codec. The header is self-describing: magic, format version,
// store identity, creation step and creating boot, followed by a CRC and a
// SHA-256 over everything that precedes them.
std::string encode_store_header(const StoreHeader& header);
Status decode_store_header(std::string_view bytes, StoreHeader& out);
Status write_store_header(const std::filesystem::path& path, const StoreHeader& header);
Status read_store_header(const std::filesystem::path& path, StoreHeader& out);

// Atomic file replacement helpers (staging file + flush + rename).
Status atomic_write_file(const std::filesystem::path& target, std::string_view bytes);
Status read_file_bounded(const std::filesystem::path& path, std::uint64_t max_bytes,
                         std::string& out);
Status remove_file_if_exists(const std::filesystem::path& path);
Status ensure_directory(const std::filesystem::path& dir);

}  // namespace sbf
