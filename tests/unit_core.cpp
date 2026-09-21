#include <string>
#include <vector>

#include "sbf/canonical.hpp"
#include "sbf/clock.hpp"
#include "sbf/digest.hpp"
#include "sbf/evidence.hpp"
#include "sbf/fence.hpp"
#include "sbf/ids.hpp"
#include "sbf/lineage.hpp"
#include "sbf/scope.hpp"
#include "sbf/text.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

SBF_TEST(ids, validation_and_charset) {
  CHECK(DomainId::try_make("domain-a").has_value());
  CHECK(DomainId::try_make("a.b_c:d-e").has_value());
  CHECK(!DomainId::try_make("").has_value());
  CHECK(!DomainId::try_make("has space").has_value());
  CHECK(!DomainId::try_make("slash/here").has_value());
  CHECK(!DomainId::try_make("dot.dot." + std::string(limits::kMaxIdLength, 'x')).has_value());
  CHECK_EQ(DomainId::try_make("abc")->view(), std::string_view("abc"));
  // Strong typing: these are different types, so the following would not compile:
  //   WitnessId w = DomainId::make("x");
  CHECK(DomainId::make("x") == DomainId::make("x"));
  CHECK(!(DomainId::make("x") == DomainId::make("y")));
  // An invalid identifier fails closed to empty rather than being stored.
  CHECK(DomainId::make("bad id").empty());
}

SBF_TEST(counters, checked_increment_and_overflow) {
  Epoch epoch{5};
  CHECK(epoch.try_increment());
  CHECK_EQ(epoch.value(), std::uint64_t{6});
  Epoch top = Epoch::max();
  CHECK(!top.try_increment());
  CHECK_EQ(top.value(), Epoch::max_value());
  CHECK(Epoch{}.is_none());
  CHECK(Epoch{1}.is_set());
  CHECK(Epoch{1} < Epoch{2});
}

SBF_TEST(text, parsing_is_overflow_checked) {
  std::uint64_t value = 0;
  CHECK_OK(text::parse_u64("0", value));
  CHECK_EQ(value, std::uint64_t{0});
  CHECK_OK(text::parse_u64("18446744073709551615", value));
  CHECK_EQ(value, std::uint64_t{18446744073709551615ull});
  CHECK_OUTCOME(text::parse_u64("18446744073709551616", value), Outcome::Invalid);
  CHECK_OUTCOME(text::parse_u64("-1", value), Outcome::Invalid);
  CHECK_OUTCOME(text::parse_u64("", value), Outcome::Invalid);
  std::int64_t signed_value = 0;
  CHECK_OK(text::parse_i64("-9223372036854775808", signed_value));
  CHECK_EQ(signed_value, std::int64_t{-9223372036854775807LL - 1});
  CHECK_OUTCOME(text::parse_i64("9223372036854775808", signed_value), Outcome::Invalid);
  CHECK(text::equals_ci("TrUe", "true"));
  CHECK_EQ(text::split("a,b,,c", ',').size(), std::size_t{4});
  CHECK_EQ(text::hex_u64(0).substr(0, 2), std::string_view("0x"));
}

SBF_TEST(digest, known_answer_vectors) {
  // CRC-32C (Castagnoli) check value for "123456789".
  CHECK_EQ(crc32c(std::string_view("123456789")), 0xE3069283u);
  CHECK_EQ(crc32c(std::string_view("")), 0x00000000u);
  // FIPS 180-4 SHA-256 known answers.
  CHECK_EQ(Digest256::of(std::string_view("")).hex(),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  CHECK_EQ(Digest256::of(std::string_view("abc")).hex(),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  CHECK_EQ(Digest256::of(std::string_view(
               "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
               .hex(),
           std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  Digest256 parsed;
  CHECK_OK(Digest256::parse("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", parsed));
  CHECK(parsed == Digest256::of(std::string_view("abc")));
  CHECK_OUTCOME(Digest256::parse("zz", parsed), Outcome::Invalid);
  Digest256 upper;
  CHECK_OK(Digest256::parse("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", upper));
  CHECK(upper == parsed);
}

SBF_TEST(canonical, round_trip_and_bounds) {
  const std::string encoded = canonical_encode([](CanonicalWriter& writer) {
    writer.u8(7);
    writer.u16(300);
    writer.u32(70000);
    writer.u64(1ull << 40);
    writer.i64(-5);
    writer.boolean(true);
    writer.text("hello");
    writer.blob(std::string(1000, 'x'));
    writer.counter(Epoch{9});
  });
  CanonicalReader reader(encoded);
  std::uint8_t a = 0;
  std::uint16_t b = 0;
  std::uint32_t c = 0;
  std::uint64_t d = 0;
  std::int64_t e = 0;
  bool f = false;
  std::string g;
  std::string h;
  Epoch i;
  CHECK_OK(reader.u8(a));
  CHECK_OK(reader.u16(b));
  CHECK_OK(reader.u32(c));
  CHECK_OK(reader.u64(d));
  CHECK_OK(reader.i64(e));
  CHECK_OK(reader.boolean(f));
  CHECK_OK(reader.text(g));
  CHECK_OK(reader.blob(h));
  CHECK_OK(reader.counter(i));
  CHECK_OK(reader.finish());
  CHECK_EQ(a, std::uint8_t{7});
  CHECK_EQ(b, std::uint16_t{300});
  CHECK_EQ(c, std::uint32_t{70000});
  CHECK_EQ(d, std::uint64_t{1ull << 40});
  CHECK_EQ(e, std::int64_t{-5});
  CHECK(f);
  CHECK_EQ(g, std::string("hello"));
  CHECK_EQ(h.size(), std::size_t{1000});
  CHECK_EQ(i.value(), std::uint64_t{9});

  // Trailing bytes are an error, not silently ignored.
  auto consume_all = [](CanonicalReader& reader) {
    std::uint8_t v8 = 0;
    std::uint16_t v16 = 0;
    std::uint32_t v32 = 0;
    std::uint64_t v64 = 0;
    std::int64_t i64 = 0;
    bool flag = false;
    std::string text_value;
    std::string blob_value;
    Epoch epoch;
    Status status = reader.u8(v8);
    if (status.is_ok()) status = reader.u16(v16);
    if (status.is_ok()) status = reader.u32(v32);
    if (status.is_ok()) status = reader.u64(v64);
    if (status.is_ok()) status = reader.i64(i64);
    if (status.is_ok()) status = reader.boolean(flag);
    if (status.is_ok()) status = reader.text(text_value);
    if (status.is_ok()) status = reader.blob(blob_value);
    if (status.is_ok()) status = reader.counter(epoch);
    return status;
  };
  // The reader holds a view, so the backing buffer must outlive it: an owning
  // local is kept rather than a temporary.
  const std::string extended = encoded + std::string(1, '\0');
  CanonicalReader trailing(extended);
  CHECK_OK(consume_all(trailing));
  CHECK_OUTCOME(trailing.finish(), Outcome::Invalid);
  const std::string exact_bytes = encoded;
  CanonicalReader exact(exact_bytes);
  CHECK_OK(consume_all(exact));
  CHECK_OK(exact.finish());

  // A truncated prefix fails with a specific reason.
  const std::string prefix = encoded.substr(0, 3);
  CanonicalReader truncated(prefix);
  CHECK_OUTCOME(truncated.u32(c), Outcome::Invalid);

  // A collection count larger than the remaining bytes is refused before any
  // allocation is attempted.
  CanonicalWriter bomb;
  bomb.u32(0xFFFFFFFFu);
  CanonicalReader bomb_reader(bomb.bytes());
  std::uint32_t count = 0;
  CHECK_OUTCOME(bomb_reader.count(1000000, count), Outcome::Exhausted);
}

SBF_TEST(scope, canonicalisation_and_rejection) {
  Scope scope;
  // Duplicates are rejected rather than silently collapsed: a caller that
  // believes it declared two extents must not silently get one.
  CHECK_OUTCOME(Scope::parse("port-2,port-1,port-1", scope), Outcome::Invalid);
  CHECK_OUTCOME(Scope::parse("port-1,port-1", scope), Outcome::Invalid);
  CHECK_OUTCOME(Scope::parse("", scope), Outcome::Invalid);
  CHECK_OUTCOME(Scope::parse("port 1", scope), Outcome::Invalid);
  CHECK_OK(Scope::parse("port-2,port-1", scope));
  CHECK_EQ(scope.csv(), std::string("port-1,port-2"));
  CHECK_OK(Scope::parse("port-3", scope));
  CHECK_EQ(scope.size(), std::size_t{1});
  std::string huge;
  for (std::size_t i = 0; i < limits::kMaxExtentsPerScope + 1; ++i) {
    if (i != 0) huge.push_back(',');
    huge.append("extent-").append(std::to_string(i));
  }
  CHECK_OUTCOME(Scope::parse(huge, scope), Outcome::Exhausted);
}

SBF_TEST(scope, overlap_and_containment) {
  Scope a;
  Scope b;
  Scope c;
  CHECK_OK(Scope::parse("p1,p2,p3", a));
  CHECK_OK(Scope::parse("p3,p4", b));
  CHECK_OK(Scope::parse("p4,p5", c));
  CHECK(a.overlaps(b));
  CHECK(!a.overlaps(c));
  CHECK(a.is_superset_of(b) == false);
  Scope subset;
  CHECK_OK(Scope::parse("p1,p2", subset));
  CHECK(a.is_superset_of(subset));
  CHECK(!subset.is_superset_of(a));
  CHECK_EQ(intersect_merge(a, c).size(), std::size_t{0});
  CHECK_EQ(intersect_merge(a, b).size(), std::size_t{1});
}

SBF_TEST(scope, differential_intersection_against_reference) {
  Rng rng(0x5BF01ull);
  std::printf("seed=%llu\n", static_cast<unsigned long long>(rng.state()));
  for (int iteration = 0; iteration < 4000; ++iteration) {
    const std::size_t left_size = static_cast<std::size_t>(rng.bounded(9));
    const std::size_t right_size = static_cast<std::size_t>(rng.bounded(9));
    std::vector<ExtentId> left;
    std::vector<ExtentId> right;
    for (std::size_t i = 0; i < left_size; ++i) {
      left.push_back(ExtentId::make("e" + std::to_string(rng.bounded(20))));
    }
    for (std::size_t i = 0; i < right_size; ++i) {
      right.push_back(ExtentId::make("e" + std::to_string(rng.bounded(20))));
    }
    auto left_scope = Scope::try_make(left);
    auto right_scope = Scope::try_make(right);
    if (!left_scope.has_value() || !right_scope.has_value()) continue;  // empty set
    const auto fast = intersect_merge(*left_scope, *right_scope);
    const auto slow = intersect_reference(*left_scope, *right_scope);
    CHECK(fast == slow);
    CHECK_EQ(left_scope->overlaps(*right_scope), !fast.empty());
  }
}

SBF_TEST(scope_index, bounded_search_reports_indeterminate) {
  ScopeIndex index;
  Scope scope;
  CHECK_OK(Scope::parse("a,b,c,d", scope));
  for (int i = 0; i < 8; ++i) {
    CHECK_OK(index.add(ClaimId::make("claim-" + std::to_string(i)), scope));
  }
  std::vector<ClaimId> hits;
  CHECK(index.query(scope, hits, 1000) == SearchResult::Found);
  CHECK_EQ(hits.size(), std::size_t{8});
  // A starved budget must never be reported as "no overlap".
  CHECK(index.query(scope, hits, 2) == SearchResult::Indeterminate);
  CHECK(hits.empty());
  Scope other;
  CHECK_OK(Scope::parse("zz", other));
  CHECK(index.query(other, hits, 1000) == SearchResult::Absent);
}

SBF_TEST(clock, monotone_steps_and_wall_clock_regression) {
  StepClock clock;
  CHECK_EQ(clock.now().value(), std::uint64_t{0});
  CHECK(clock.advance());
  CHECK(clock.advance(10));
  CHECK_EQ(clock.now().value(), std::uint64_t{11});
  CHECK(clock.observe_persisted(Step{100}));
  CHECK_EQ(clock.now().value(), std::uint64_t{100});
  CHECK(clock.observe_persisted(Step{50}));  // never moves backwards
  CHECK_EQ(clock.now().value(), std::uint64_t{100});
  StepClock full;
  CHECK(full.observe_persisted(Step{Step::max_value() - 1}));
  CHECK(!full.advance(5));

  WallClockObserver observer;
  observer.observe(1'000);
  const WallClockReading backwards = observer.observe(400);
  CHECK(backwards.observed_regression);
  CHECK_EQ(observer.regression_count(), std::uint64_t{1});
  CHECK_EQ(observer.max_regression_nanos(), std::uint64_t{600});
  const WallClockReading forward = observer.observe(2'000);
  CHECK(!forward.observed_regression);
}

SBF_TEST(status, reason_codes_are_stable_and_round_trip) {
  CHECK_EQ(static_cast<std::uint16_t>(Reason::EmptyValue), std::uint16_t{1});
  CHECK_EQ(to_string(Reason::ConflictingAttestations), std::string_view("ConflictingAttestations"));
  Reason parsed = Reason::None;
  CHECK(reason_from_code(27, parsed));
  CHECK(parsed == Reason::ConflictingAttestations);
  CHECK(!reason_from_code(60000, parsed));
  const Status status{Outcome::Fenced, Reason::TokenFloorRejected, 7};
  CHECK_EQ(to_string(status), std::string("Fenced:TokenFloorRejected#0x7"));
  CHECK(!is_positive(Outcome::Unknown));
  CHECK(is_positive(Outcome::Ok));

  Explanation explanation;
  CHECK(explanation.add(Reason::StaleEpoch));
  CHECK(explanation.add(Reason::StaleEpoch));  // deduplicated
  CHECK_EQ(explanation.size(), std::size_t{1});
  for (std::size_t i = 0; i < limits::kMaxExplanationCodes; ++i) {
    explanation.add(static_cast<Reason>(200 + i));
  }
  CHECK(explanation.full());
  CHECK(!explanation.add(Reason::EpochRegression));
  const std::string rendered = explanation.render("subject", status);
  CHECK(rendered.size() <= limits::kMaxExplanationBytes);
}

SBF_TEST(fence, tokens_are_monotone_and_never_reusable) {
  Scope scope;
  CHECK_OK(Scope::parse("p1,p2", scope));
  FenceTable table;
  CHECK_OK(table.adopt(scope, FenceToken{5}, Epoch{1}, IncarnationId{9}, GrantId{1}, Step{1}));
  CHECK_EQ(table.high_water(ExtentId::make("p1")).value(), std::uint64_t{5});

  // The same token with a different incarnation is a conflict, not a success.
  CHECK_OUTCOME(table.adopt(scope, FenceToken{5}, Epoch{1}, IncarnationId{10}, GrantId{2}, Step{2}),
                Outcome::Conflict);
  // A lower token is fenced.
  CHECK_OUTCOME(table.adopt(scope, FenceToken{4}, Epoch{1}, IncarnationId{11}, GrantId{3}, Step{3}),
                Outcome::Fenced);

  FenceAdmission admission = table.admit(FenceToken{5}, scope, IncarnationId{9}, GrantId{1});
  CHECK(admission.admitted);
  admission = table.admit(FenceToken{4}, scope, IncarnationId{9}, GrantId{1});
  CHECK(!admission.admitted);
  CHECK(admission.status.outcome == Outcome::Fenced);
  admission = table.admit(FenceToken{5}, scope, IncarnationId{42}, GrantId{1});
  CHECK(!admission.admitted);
  CHECK(admission.status.outcome == Outcome::Conflict);
  CHECK_EQ(table.generation().value(), std::uint64_t{2});

  FenceRecord record;
  record.token = FenceToken{6};
  record.domain = DomainId::make("d");
  record.scope = scope.digest();
  record.fenced_epoch = Epoch{1};
  record.fenced_incarnation = IncarnationId{9};
  record.issued_at = Step{4};
  CHECK_OK(table.apply(record, scope));
  CHECK(table.incarnation_fenced(IncarnationId{9}));
  CHECK(table.epoch_fenced(DomainId::make("d"), Epoch{1}));
  // A record below the high-water mark is refused rather than rewinding it.
  FenceRecord stale = record;
  stale.token = FenceToken{5};
  CHECK_OUTCOME(table.apply(stale, scope), Outcome::Fenced);
  CHECK_OK(table.validate());
}

SBF_TEST(lineage, grants_are_monotone_and_epochs_never_reopen) {
  LineageTable lineage;
  Scope scope;
  CHECK_OK(Scope::parse("p1", scope));
  EpochGrant first;
  first.id = GrantId{1};
  first.domain = DomainId::make("d");
  first.scope = scope.digest();
  first.extents = scope;
  first.epoch = Epoch{1};
  first.incarnation = IncarnationId{2};
  first.boot = BootId{2};
  first.fence_token = FenceToken{1};
  first.opened_at = Step{1};
  CHECK_OK(lineage.open_grant(first));

  EpochGrant duplicate = first;
  duplicate.id = GrantId{2};
  CHECK_OUTCOME(lineage.open_grant(duplicate), Outcome::Conflict);

  EpochGrant reopen = first;
  reopen.id = GrantId{3};
  reopen.incarnation = IncarnationId{5};
  CHECK_OUTCOME(lineage.open_grant(reopen), Outcome::Conflict);

  CHECK_OK(lineage.close_grant(GrantId{1}, GrantState::Fenced, Reason::CompensatingFenceRequired,
                               Step{5}));
  EpochGrant second = first;
  second.id = GrantId{4};
  second.incarnation = IncarnationId{6};
  second.epoch = Epoch{2};
  second.fence_token = FenceToken{2};
  CHECK_OK(lineage.open_grant(second));
  CHECK_EQ(lineage.max_epoch(DomainId::make("d")).value(), std::uint64_t{2});
  // Closing twice is reported, never silently accepted.
  CHECK_OUTCOME(lineage.close_grant(GrantId{1}, GrantState::Closed, Reason::None, Step{9}),
                Outcome::AlreadyExists);
  CHECK_OK(lineage.validate());

  // Imported state must satisfy exactly the same invariants.
  std::vector<EpochGrant> corrupt;
  corrupt.push_back(second);
  corrupt.push_back(first);  // epoch regression
  LineageTable imported;
  CHECK_OUTCOME(imported.import(corrupt, {}), Outcome::Corrupt);
}

SBF_TEST(lineage, reconciliation_preserves_lineage_and_surfaces_conflicts) {
  Scope scope;
  CHECK_OK(Scope::parse("p1", scope));
  EpochGrant local;
  local.id = GrantId{1};
  local.domain = DomainId::make("d");
  local.scope = scope.digest();
  local.extents = scope;
  local.epoch = Epoch{1};
  local.incarnation = IncarnationId{2};
  local.boot = BootId{2};
  local.fence_token = FenceToken{1};
  local.registry_sequence = Sequence{1};

  EpochGrant remote = local;
  remote.epoch = Epoch{9};
  remote.incarnation = IncarnationId{77};

  EpochGrant extra = local;
  extra.id = GrantId{2};
  extra.registry_sequence = Sequence{2};

  const ReconciliationResult conflicted = reconcile({local}, {remote});
  CHECK(conflicted.outcome == Outcome::Conflict);
  CHECK_EQ(conflicted.conflicts.size(), std::size_t{1});
  CHECK(conflicted.requires_operator);
  CHECK_EQ(conflicted.merged_history.size(), std::size_t{1});  // nothing is dropped

  const ReconciliationResult clean = reconcile({local}, {extra});
  CHECK(clean.outcome == Outcome::Ok);
  CHECK(clean.conflicts.empty());
  CHECK_EQ(clean.merged_history.size(), std::size_t{2});
  CHECK(!clean.requires_operator);
}
SBF_TEST_MAIN
