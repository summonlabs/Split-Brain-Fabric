#include "sbf/fabric_store.hpp"

#include <algorithm>
#include "sbf/protocol.hpp"
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace sbf {
namespace {

constexpr std::uint32_t kFabricRecordPrefix = 8;

void put_u32(std::string& out, std::uint32_t v) {
  out.push_back(static_cast<char>(v & 0xFFu));
  out.push_back(static_cast<char>((v >> 8) & 0xFFu));
  out.push_back(static_cast<char>((v >> 16) & 0xFFu));
  out.push_back(static_cast<char>((v >> 24) & 0xFFu));
}

std::uint32_t read_u32(const char* p) {
  return static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[0])) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[1])) << 8) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[2])) << 16) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[3])) << 24);
}

Status flush_to_disk(std::FILE* file) {
  if (std::fflush(file) != 0) return Status::make(Outcome::Unreachable, Reason::EffectNotVerified, 1);
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

bool operation_valid(std::string_view operation) noexcept {
  if (operation.empty() || operation.size() > limits::kMaxTextLength) return false;
  for (const char raw : operation) {
    const auto c = static_cast<unsigned char>(raw);
    if (c < 0x20 || c > 0x7E) return false;
  }
  return true;
}

}  // namespace

std::string encode(const MutationRecord& record) {
  CanonicalWriter writer;
  writer.counter(record.store_sequence);
  writer.text(record.domain.view());
  writer.blob(encode(record.scope));
  writer.counter(record.epoch);
  writer.counter(record.incarnation);
  writer.counter(record.grant);
  writer.counter(record.fence_token);
  writer.counter(record.committed_at);
  writer.text(record.operation);
  writer.digest(record.payload_digest);
  writer.digest(record.record_digest);
  return std::move(writer).take();
}

Digest256 compute_record_digest(const MutationRecord& record) {
  CanonicalWriter writer;
  writer.counter(record.store_sequence);
  writer.text(record.domain.view());
  writer.blob(encode(record.scope));
  writer.counter(record.epoch);
  writer.counter(record.incarnation);
  writer.counter(record.grant);
  writer.counter(record.fence_token);
  writer.counter(record.committed_at);
  writer.text(record.operation);
  writer.digest(record.payload_digest);
  return Digest256::of(writer.bytes());
}

Status decode(CanonicalReader& reader, MutationRecord& record) {
  if (auto st = reader.counter(record.store_sequence); !st.is_ok()) return st;
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto domain_id = DomainId::try_make(domain);
  if (!domain_id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  record.domain = *domain_id;
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, record.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(record.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(record.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(record.grant); !st.is_ok()) return st;
  if (auto st = reader.counter(record.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(record.committed_at); !st.is_ok()) return st;
  if (auto st = reader.text(record.operation); !st.is_ok()) return st;
  if (!operation_valid(record.operation)) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, record.operation.size());
  }
  if (auto st = reader.digest(record.payload_digest); !st.is_ok()) return st;
  if (auto st = reader.digest(record.record_digest); !st.is_ok()) return st;
  if (!(record.record_digest == compute_record_digest(record))) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch);
  }
  return Status::ok();
}

FabricStore::~FabricStore() {
  if (file_ != nullptr) {
    std::fclose(static_cast<std::FILE*>(file_));
    file_ = nullptr;
  }
}

FabricStore::FabricStore(FabricStore&& other) noexcept
    : path_(std::move(other.path_)),
      file_(other.file_),
      store_id_(std::move(other.store_id_)),
      fences_(std::move(other.fences_)),
      owners_(std::move(other.owners_)),
      records_(std::move(other.records_)),
      last_sequence_(other.last_sequence_),
      bytes_written_(other.bytes_written_),
      torn_tail_recovered_(other.torn_tail_recovered_) {
  other.file_ = nullptr;
}

FabricStore& FabricStore::operator=(FabricStore&& other) noexcept {
  if (this != &other) {
    if (file_ != nullptr) std::fclose(static_cast<std::FILE*>(file_));
    path_ = std::move(other.path_);
    file_ = other.file_;
    store_id_ = std::move(other.store_id_);
    fences_ = std::move(other.fences_);
    owners_ = std::move(other.owners_);
    records_ = std::move(other.records_);
    last_sequence_ = other.last_sequence_;
    bytes_written_ = other.bytes_written_;
    torn_tail_recovered_ = other.torn_tail_recovered_;
    other.file_ = nullptr;
  }
  return *this;
}

Status FabricStore::open(const std::filesystem::path& directory, const StoreId& store_id,
                         const StoreOpenOptions& options, FabricStore& out,
                         StoreRecoveryReport& report) {
  if (store_id.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  if (auto st = ensure_directory(directory); !st.is_ok()) return st;

  FabricStore store;
  store.path_ = directory / "sbf.fabric";
  store.store_id_ = store_id;
  store.last_sequence_ = Sequence{0};

  const std::filesystem::path header_path = directory / "sbf.fabric.store";
  std::error_code ec;
  if (!std::filesystem::exists(header_path, ec)) {
    if (!options.create_if_missing) return Status::make(Outcome::NotFound, Reason::StoreNotFound);
    StoreHeader header;
    header.store_id = store_id;
    header.created_at = Step{1};
    header.created_by_boot = options.opening_boot;
    if (auto st = write_store_header(header_path, header); !st.is_ok()) return st;
    report.created = true;
  } else {
    StoreHeader header;
    if (auto st = read_store_header(header_path, header); !st.is_ok()) return st;
    if (!(header.store_id == store_id)) {
      return Status::make(Outcome::Conflict, Reason::StoreNotFound);
    }
  }

  if (std::filesystem::exists(store.path_, ec)) {
    std::string bytes;
    if (auto st = read_file_bounded(store.path_, limits::kMaxFabricStoreBytes, bytes); !st.is_ok()) {
      return st;
    }
    std::size_t offset = 0;
    std::size_t good_end = 0;
    std::uint64_t expected_sequence = 1;
    std::vector<ExtentFenceState> owners;
    while (offset < bytes.size()) {
      if (bytes.size() - offset < kFabricRecordPrefix) {
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
        return Status::make(Outcome::Corrupt, Reason::ImpossibleLength, length);
      }
      if (bytes.size() - offset - kFabricRecordPrefix < length) {
        if (!options.allow_torn_tail_recovery) {
          return Status::make(Outcome::Corrupt, Reason::TornTail, offset);
        }
        report.torn_tail_recovered = true;
        report.torn_tail_bytes = bytes.size() - offset;
        break;
      }
      const std::string_view payload(bytes.data() + offset + kFabricRecordPrefix, length);
      if (crc32c(payload) != expected_crc) {
        return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, offset);
      }
      CanonicalReader reader(payload);
      MutationRecord record;
      if (auto st = decode(reader, record); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      if (record.store_sequence.value() != expected_sequence) {
        return Status::make(Outcome::Corrupt, Reason::SequenceRegression,
                            record.store_sequence.value());
      }
      expected_sequence = record.store_sequence.value() + 1;
      store.last_sequence_ = record.store_sequence;
      store.record_owner(record);
      store.records_.push_back(record);
      offset += kFabricRecordPrefix + length;
      good_end = offset;
      ++report.journal_records;
      report.last_sequence = record.store_sequence;
      report.last_step = record.committed_at;
    }
    if (report.torn_tail_recovered) {
      std::FILE* file = std::fopen(store.path_.string().c_str(), "r+b");
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
    if (store.records_.size() > limits::kMaxSnapshotRecords) {
      // Retained window is bounded; the complete history always remains on disk
      // and is reachable through load().
      store.records_.erase(store.records_.begin(),
                           store.records_.begin() + static_cast<std::ptrdiff_t>(
                               store.records_.size() - limits::kMaxSnapshotRecords));
    }
  }

  std::FILE* file = std::fopen(store.path_.string().c_str(), "ab");
  if (file == nullptr) return Status::make(Outcome::Unreachable, Reason::StoreNotFound);
  store.file_ = file;
  out = std::move(store);
  return Status::ok();
}

void FabricStore::record_owner(const MutationRecord& record) {
  for (const auto& extent : record.scope.extents()) {
    ExtentFenceState state;
    state.extent = extent;
    state.high_water_token = record.fence_token;
    state.high_water_epoch = record.epoch;
    state.owner_incarnation = record.incarnation;
    state.owner_grant = record.grant;
    state.updated_at = record.committed_at;
    const auto it = std::lower_bound(owners_.begin(), owners_.end(), extent,
                                     [](const ExtentFenceState& s, const ExtentId& key) {
                                       return s.extent < key;
                                     });
    if (it != owners_.end() && it->extent == extent) {
      *it = state;
    } else {
      owners_.insert(it, state);
    }
  }
}

Status FabricStore::admit(const DomainId& domain, FenceToken token, const Scope& scope,
                          Epoch epoch, IncarnationId incarnation, GrantId grant,
                          std::string_view operation, const Digest256& payload_digest, Step now,
                          MutationRecord& record) {
  if (file_ == nullptr) return Status::make(Outcome::Closed, Reason::StoreBusy);
  if (domain.empty()) return Status::make(Outcome::Invalid, Reason::DomainNotRegistered);
  if (scope.empty()) return Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
  if (token.is_none()) return Status::make(Outcome::Invalid, Reason::FenceTokenMissing);
  if (incarnation.is_none()) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  if (!operation_valid(operation)) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, operation.size());
  }
  if (scope.size() > limits::kMaxExtentsPerScope) {
    return Status::make(Outcome::Exhausted, Reason::ScopeTooLarge, scope.size());
  }

  // ---- the gate --------------------------------------------------------------
  // This check is deliberately independent of any live authority state: it uses
  // only the durable per-extent high-water marks.
  for (const auto& extent : scope.extents()) {
    const ExtentFenceState* state = owner_of(extent);
    if (state == nullptr) continue;
    if (state->high_water_token > token) {
      return Status::make(Outcome::Fenced, Reason::TokenFloorRejected,
                          state->high_water_token.value());
    }
    if (state->high_water_token == token && state->owner_incarnation != incarnation) {
      return Status::make(Outcome::Conflict, Reason::StoreOwnerMismatch,
                          state->owner_incarnation.value());
    }
  }

  MutationRecord candidate;
  candidate.store_sequence = Sequence{last_sequence_.value() + 1};
  candidate.domain = domain;
  candidate.scope = scope;
  candidate.epoch = epoch;
  candidate.incarnation = incarnation;
  candidate.grant = grant;
  candidate.fence_token = token;
  candidate.committed_at = now;
  candidate.operation.assign(operation);
  candidate.payload_digest = payload_digest;
  candidate.record_digest = compute_record_digest(candidate);

  const std::string payload = encode(candidate);
  if (payload.size() > limits::kMaxJournalRecordBytes) {
    return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, payload.size());
  }
  std::string prefix;
  put_u32(prefix, static_cast<std::uint32_t>(payload.size()));
  put_u32(prefix, crc32c(payload));

  auto* file = static_cast<std::FILE*>(file_);
  if (std::fwrite(prefix.data(), 1, prefix.size(), file) != prefix.size()) {
    return Status::make(Outcome::Unknown, Reason::EffectNotVerified, 1);
  }
  if (std::fwrite(payload.data(), 1, payload.size(), file) != payload.size()) {
    return Status::make(Outcome::Unknown, Reason::EffectNotVerified, 2);
  }
  if (auto st = flush_to_disk(file); !st.is_ok()) {
    // The effect may or may not be durable. The caller must treat this as
    // UNKNOWN, never as success and never as a clean refusal.
    return Status::make(Outcome::Unknown, Reason::EffectNotVerified, st.aux);
  }

  record = candidate;
  last_sequence_ = candidate.store_sequence;
  bytes_written_ += prefix.size() + payload.size();
  record_owner(candidate);
  if (records_.size() >= limits::kMaxSnapshotRecords) {
    records_.erase(records_.begin());
  }
  records_.push_back(candidate);
  return Status::ok();
}

FenceToken FabricStore::high_water(const ExtentId& extent) const noexcept {
  const ExtentFenceState* state = owner_of(extent);
  return state == nullptr ? FenceToken{} : state->high_water_token;
}

const ExtentFenceState* FabricStore::owner_of(const ExtentId& extent) const noexcept {
  const auto it = std::lower_bound(owners_.begin(), owners_.end(), extent,
                                   [](const ExtentFenceState& s, const ExtentId& key) {
                                     return s.extent < key;
                                   });
  if (it == owners_.end() || !(it->extent == extent)) return nullptr;
  return &*it;
}

Status FabricStore::load(const std::function<Status(const MutationRecord&)>& visitor) const {
  std::error_code ec;
  if (!std::filesystem::exists(path_, ec)) return Status::ok();
  std::string bytes;
  if (auto st = read_file_bounded(path_, limits::kMaxFabricStoreBytes, bytes); !st.is_ok()) {
    return st;
  }
  std::size_t offset = 0;
  std::uint64_t expected_sequence = 1;
  while (offset < bytes.size()) {
    if (bytes.size() - offset < kFabricRecordPrefix) break;
    const std::uint32_t length = read_u32(bytes.data() + offset);
    const std::uint32_t expected_crc = read_u32(bytes.data() + offset + 4);
    if (length == 0 || length > limits::kMaxJournalRecordBytes) {
      return Status::make(Outcome::Corrupt, Reason::ImpossibleLength, length);
    }
    if (bytes.size() - offset - kFabricRecordPrefix < length) break;
    const std::string_view payload(bytes.data() + offset + kFabricRecordPrefix, length);
    if (crc32c(payload) != expected_crc) {
      return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, offset);
    }
    CanonicalReader reader(payload);
    MutationRecord record;
    if (auto st = decode(reader, record); !st.is_ok()) return st;
    if (auto st = reader.finish(); !st.is_ok()) return st;
    if (record.store_sequence.value() != expected_sequence) {
      return Status::make(Outcome::Corrupt, Reason::SequenceRegression,
                          record.store_sequence.value());
    }
    expected_sequence = record.store_sequence.value() + 1;
    if (auto st = visitor(record); !st.is_ok()) return st;
    offset += kFabricRecordPrefix + length;
  }
  return Status::ok();
}

}  // namespace sbf
