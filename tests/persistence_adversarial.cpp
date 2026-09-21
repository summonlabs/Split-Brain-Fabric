#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "sbf/persistence.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

namespace {

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(std::string_view name) {
    path = std::filesystem::temp_directory_path() /
           ("sbf-test-" + std::string(name) + "-" + std::to_string(counter()));
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    std::filesystem::create_directories(path, ec);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
  static std::uint64_t counter() {
    static std::uint64_t value = 0;
    return ++value;
  }
};

JournalRecord record_of(RecordKind kind, std::uint64_t sequence, std::string payload) {
  JournalRecord record;
  record.kind = kind;
  record.sequence = Sequence{sequence};
  record.step = Step{sequence};
  record.status = Status::ok();
  record.payload = std::move(payload);
  return record;
}

}  // namespace

SBF_TEST(persistence, append_reopen_and_sequence_continuity) {
  TempDir directory("persistence-basic");
  const StoreId store_id = StoreId::make("store-1");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(directory.path, store_id, options, store, report));
  CHECK(report.created);
  for (std::uint64_t sequence = 1; sequence <= 32; ++sequence) {
    CHECK_OK(store.append(record_of(RecordKind::StepAdvance, sequence, "x")));
  }
  CHECK_EQ(store.last_sequence().value(), std::uint64_t{32});
  // A non-contiguous sequence is refused at append time, not silently accepted.
  CHECK_OUTCOME(store.append(record_of(RecordKind::StepAdvance, 40, "x")), Outcome::Invalid);
  CHECK_OUTCOME(store.append(record_of(RecordKind::StepAdvance, 32, "x")), Outcome::Invalid);
  store.flush();

  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OK(Store::open(directory.path, store_id, options, reopened, reopened_report));
  CHECK(!reopened_report.created);
  CHECK_EQ(reopened_report.journal_records, std::uint64_t{32});
  CHECK_EQ(reopened.last_sequence().value(), std::uint64_t{32});
  CHECK(!reopened_report.torn_tail_recovered);
  CHECK_OK(reopened.append(record_of(RecordKind::StepAdvance, 33, "x")));

  // A different store identity is refused against the same directory.
  Store mismatch;
  StoreRecoveryReport mismatch_report;
  CHECK_OUTCOME(Store::open(directory.path, StoreId::make("other"), options, mismatch,
                            mismatch_report),
                Outcome::Conflict);
}

SBF_TEST(persistence, checkpoint_round_trip_and_recovery) {
  TempDir directory("persistence-checkpoint");
  const StoreId store_id = StoreId::make("store-1");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(directory.path, store_id, options, store, report));
  for (std::uint64_t sequence = 1; sequence <= 8; ++sequence) {
    CHECK_OK(store.append(record_of(RecordKind::StepAdvance, sequence, "y")));
  }
  const std::string state = "durable-state-blob";
  CHECK_OK(store.checkpoint(state, Sequence{8}, Step{8}));
  // Checkpointing at a sequence the store has not reached is refused.
  CHECK_OUTCOME(store.checkpoint(state, Sequence{9}, Step{9}), Outcome::Invalid);
  CHECK_OK(store.append(record_of(RecordKind::StepAdvance, 9, "y")));

  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OK(Store::open(directory.path, store_id, options, reopened, reopened_report));
  CHECK(reopened_report.snapshot_loaded);
  std::string loaded;
  SnapshotHeader header;
  CHECK_OK(reopened.load_snapshot(loaded, header));
  CHECK_EQ(loaded, state);
  CHECK_EQ(header.covers_sequence.value(), std::uint64_t{8});
  std::vector<std::uint64_t> replayed;
  CHECK_OK(reopened.replay([&](const JournalRecord& record) {
    replayed.push_back(record.sequence.value());
    return Status::ok();
  }));
  CHECK_EQ(replayed.size(), std::size_t{1});
  CHECK_EQ(replayed.front(), std::uint64_t{9});
}

SBF_TEST(persistence, torn_tail_is_recovered_and_reported) {
  TempDir directory("persistence-torn");
  const StoreId store_id = StoreId::make("store-1");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(directory.path, store_id, options, store, report));
  for (std::uint64_t sequence = 1; sequence <= 4; ++sequence) {
    CHECK_OK(store.append(record_of(RecordKind::StepAdvance, sequence, "z")));
  }
  store.flush();
  const auto journal = directory.path / "sbf.journal";
  const auto size = std::filesystem::file_size(journal);

  // Truncate inside the final record: a genuine torn tail.
  std::filesystem::resize_file(journal, size - 3);
  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OK(Store::open(directory.path, store_id, options, reopened, reopened_report));
  CHECK(reopened_report.torn_tail_recovered);
  CHECK(reopened.torn_tail_recovered());
  CHECK_EQ(reopened_report.journal_records, std::uint64_t{3});
  CHECK_EQ(reopened.last_sequence().value(), std::uint64_t{3});
  // The file is truncated to the last complete record boundary, so a later
  // append continues the sequence without leaving a hole.
  CHECK(std::filesystem::file_size(journal) <= size - 3);
  CHECK_OK(reopened.append(record_of(RecordKind::StepAdvance, 4, "z")));
  CHECK_EQ(reopened.last_sequence().value(), std::uint64_t{4});
}

SBF_TEST(persistence, complete_but_corrupt_records_are_never_truncated) {
  TempDir directory("persistence-corrupt");
  const StoreId store_id = StoreId::make("store-1");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(directory.path, store_id, options, store, report));
  for (std::uint64_t sequence = 1; sequence <= 3; ++sequence) {
    CHECK_OK(store.append(record_of(RecordKind::StepAdvance, sequence, "payload")));
  }
  store.flush();
  const auto journal = directory.path / "sbf.journal";
  std::string bytes;
  CHECK_OK(read_file_bounded(journal, 1u << 20, bytes));
  // Flip a bit inside the final record's payload. The record is complete, so
  // this is corruption, not a torn tail, and must fail the open.
  bytes[bytes.size() - 1] ^= 0x01;
  std::ofstream out(journal, std::ios::binary | std::ios::trunc);
  out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  out.close();
  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OUTCOME(Store::open(directory.path, store_id, options, reopened, reopened_report),
                Outcome::Corrupt);
  CHECK(!reopened_report.torn_tail_recovered);
}

SBF_TEST(persistence, impossible_length_and_unsupported_version_are_refused) {
  TempDir directory("persistence-length");
  const StoreId store_id = StoreId::make("store-1");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(directory.path, store_id, options, store, report));
  CHECK_OK(store.append(record_of(RecordKind::StepAdvance, 1, "one")));
  store.flush();
  const auto journal = directory.path / "sbf.journal";
  std::string bytes;
  CHECK_OK(read_file_bounded(journal, 1u << 20, bytes));
  // A zero declared length is impossible and refused.
  std::string zero = bytes;
  zero[0] = 0;
  zero[1] = 0;
  zero[2] = 0;
  zero[3] = 0;
  {
    std::ofstream out(journal, std::ios::binary | std::ios::trunc);
    out.write(zero.data(), static_cast<std::streamsize>(zero.size()));
  }
  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OUTCOME(Store::open(directory.path, store_id, options, reopened, reopened_report),
                Outcome::Corrupt);

  // A huge declared length is refused for the same reason.
  std::string huge = bytes;
  huge[0] = static_cast<char>(0xFF);
  huge[1] = static_cast<char>(0xFF);
  huge[2] = static_cast<char>(0xFF);
  huge[3] = static_cast<char>(0x7F);
  {
    std::ofstream out(journal, std::ios::binary | std::ios::trunc);
    out.write(huge.data(), static_cast<std::streamsize>(huge.size()));
  }
  Store second;
  StoreRecoveryReport second_report;
  CHECK_OUTCOME(Store::open(directory.path, store_id, options, second, second_report),
                Outcome::Corrupt);
}

SBF_TEST(persistence, sequence_gap_in_the_journal_is_refused) {
  TempDir directory("persistence-regression");
  const StoreId store_id = StoreId::make("store-1");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(directory.path, store_id, options, store, report));
  store.flush();
  const auto journal = directory.path / "sbf.journal";

  // Build a journalled stream whose records are individually intact - correct
  // length, correct CRC, valid kind - but whose sequence jumps from 2 to 9.
  std::string bytes;
  for (const std::uint64_t sequence : {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{9}}) {
    const std::string payload = Store::encode_record(record_of(RecordKind::StepAdvance, sequence, "p"));
    const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
    const std::uint32_t crc = crc32c(payload);
    bytes.push_back(static_cast<char>(length & 0xFF));
    bytes.push_back(static_cast<char>((length >> 8) & 0xFF));
    bytes.push_back(static_cast<char>((length >> 16) & 0xFF));
    bytes.push_back(static_cast<char>((length >> 24) & 0xFF));
    bytes.push_back(static_cast<char>(crc & 0xFF));
    bytes.push_back(static_cast<char>((crc >> 8) & 0xFF));
    bytes.push_back(static_cast<char>((crc >> 16) & 0xFF));
    bytes.push_back(static_cast<char>((crc >> 24) & 0xFF));
    bytes.append(payload);
  }
  {
    std::ofstream out(journal, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OUTCOME(Store::open(directory.path, store_id, options, reopened, reopened_report),
                Outcome::Corrupt);
}

SBF_TEST(persistence, unknown_record_kind_and_trailing_garbage_are_refused) {
  JournalRecord unknown;
  unknown.kind = RecordKind::StepAdvance;
  unknown.sequence = Sequence{1};
  std::string encoded = Store::encode_record(unknown);
  encoded[0] = static_cast<char>(0xEE);
  encoded[1] = static_cast<char>(0xEE);
  JournalRecord decoded;
  CHECK_OUTCOME(Store::decode_record(encoded, decoded), Outcome::Invalid);

  JournalRecord valid;
  valid.kind = RecordKind::StepAdvance;
  valid.sequence = Sequence{1};
  const std::string bytes = Store::encode_record(valid);
  CHECK_OK(Store::decode_record(bytes, decoded));
  CHECK_OUTCOME(Store::decode_record(bytes + "\x01", decoded), Outcome::Invalid);
  CHECK_OUTCOME(Store::decode_record(bytes.substr(0, bytes.size() - 1), decoded), Outcome::Invalid);
  CHECK_OUTCOME(Store::decode_record("", decoded), Outcome::Invalid);
}

SBF_TEST(persistence, snapshot_integrity_is_enforced) {
  TempDir directory("persistence-snapshot");
  const StoreId store_id = StoreId::make("store-1");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(directory.path, store_id, options, store, report));
  CHECK_OK(store.append(record_of(RecordKind::StepAdvance, 1, "p")));
  CHECK_OK(store.checkpoint("state-blob", Sequence{1}, Step{1}));

  const auto snapshot = directory.path / "sbf.snapshot";
  std::string bytes;
  CHECK_OK(read_file_bounded(snapshot, 1u << 20, bytes));
  bytes.back() ^= 0x01;   // corrupt the payload
  {
    std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OUTCOME(Store::open(directory.path, store_id, options, reopened, reopened_report),
                Outcome::Corrupt);
}

SBF_TEST(persistence, atomic_write_never_leaves_a_partial_target) {
  TempDir directory("persistence-atomic");
  const auto target = directory.path / "file.bin";
  CHECK_OK(atomic_write_file(target, "first"));
  CHECK_OK(atomic_write_file(target, "second-version"));
  std::string value;
  CHECK_OK(read_file_bounded(target, 1024, value));
  CHECK_EQ(value, std::string("second-version"));
  CHECK(!std::filesystem::exists(directory.path / "file.bin.staging"));
  CHECK_OUTCOME(read_file_bounded(directory.path / "missing.bin", 1024, value), Outcome::NotFound);
  CHECK_OUTCOME(read_file_bounded(target, 2, value), Outcome::Invalid);
}
SBF_TEST_MAIN
