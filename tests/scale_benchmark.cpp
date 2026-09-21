// Scale and benchmark harness.
//
// Completed work is measured, not submission latency: every number below counts
// operations that finished. Sizes are chosen to expose accidental quadratic or
// history-dependent behaviour, and retained state is checked for boundedness.

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "sbf/audit.hpp"
#include "sbf/arbiter.hpp"
#include "sbf/persistence.hpp"
#include "sbf/registry.hpp"
#include "sbf/witness.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

namespace {

std::filesystem::path scratch(std::string_view name) {
  static std::uint64_t counter = 0;
  const auto path = std::filesystem::temp_directory_path() /
                    ("sbf-scale-" + std::string(name) + "-" + std::to_string(++counter));
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
  std::filesystem::create_directories(path, ec);
  return path;
}

double seconds_since(std::chrono::steady_clock::time_point start) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

// Runs the planner over a deterministic instance of the given size and reports
// the work actually completed.
void plan_scale(std::size_t candidates, std::size_t extents) {
  Rng rng(0x5CA1Eull ^ static_cast<std::uint64_t>(candidates));
  ArbiterPolicy policy = policy_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
  FenceTable fences;
  LineageTable lineage;
  std::vector<AuthorityRequest> requests;
  const Step now{10};
  for (std::size_t i = 0; i < candidates; ++i) {
    std::vector<ExtentId> extent_ids;
    for (std::size_t j = 0; j < 2; ++j) {
      extent_ids.push_back(ExtentId::make("e" + std::to_string(rng.bounded(extents))));
    }
    auto scope = Scope::try_make(extent_ids);
    if (!scope.has_value()) continue;
    const DomainId domain = DomainId::make("domain-" + std::to_string(i));
    const Epoch epoch{static_cast<std::uint64_t>(i + 1)};
    const IncarnationId incarnation{static_cast<std::uint64_t>(i + 1)};
    const FenceToken token{static_cast<std::uint64_t>(i + 1)};
    const GrantId grant{static_cast<std::uint64_t>(i + 1)};
    std::vector<WitnessAttestation> attestations;
    attestations.push_back(attestation_of(policy.quorum, 0, domain, *scope, epoch, incarnation,
                                          token, Sequence{1}));
    requests.push_back(request_of(domain, *scope, epoch, incarnation, token,
                                  bundle_with(policy.quorum, *scope, now, attestations),
                                  AuthorityMode::ExclusiveMutation,
                                  ClaimId::make("claim-" + std::to_string(i))));
  }
  ArbiterView view;
  view.policy = &policy;
  view.fences = &fences;
  view.lineage = &lineage;
  view.now = now;
  const auto start = std::chrono::steady_clock::now();
  const AuthorityPlan plan = select_authority_set(requests, view, limits::kMaxSearchNodes);
  const double elapsed = seconds_since(start);
  std::printf("plan candidates=%zu extents=%zu authorised=%zu nodes=%llu proven=%d seconds=%.6f\n",
              candidates, extents, plan.authorized.size(),
              static_cast<unsigned long long>(plan.nodes_explored),
              plan.optimality_proven ? 1 : 0, elapsed);
  CHECK(plan.authorized.size() <= requests.size());
  CHECK_OK(validate_plan(plan, requests, view) == Status::ok()
               ? Status::ok()
               : Status::make(Outcome::Corrupt, Reason::InternalInvariantViolation));
}

}  // namespace

SBF_TEST(scale, planner_work_grows_predictably_and_is_always_valid) {
  for (const std::size_t candidates : {std::size_t{8}, std::size_t{12}, std::size_t{16},
                                       std::size_t{18}, std::size_t{20}}) {
    plan_scale(candidates, 4);
  }
}

SBF_TEST(scale, scope_overlap_computation_is_not_quadratic_in_extent_count) {
  // Two independent measurements of the same relation: doubling the extent
  // count must not quadruple the measured work by more than a small factor.
  const auto measure = [](std::size_t extents) {
    std::vector<ExtentId> left;
    std::vector<ExtentId> right;
    for (std::size_t i = 0; i < extents; ++i) {
      left.push_back(ExtentId::make("e" + std::to_string(i)));
      right.push_back(ExtentId::make("e" + std::to_string(i + extents / 2)));
    }
    auto a = Scope::try_make(left);
    auto b = Scope::try_make(right);
    CHECK(a.has_value());
    CHECK(b.has_value());
    const auto start = std::chrono::steady_clock::now();
    std::uint64_t found = 0;
    for (int repeat = 0; repeat < 200; ++repeat) {
      found += intersect_merge(*a, *b).size();
    }
    const double elapsed = seconds_since(start);
    std::printf("overlap extents=%zu found=%llu seconds=%.6f\n", extents,
                static_cast<unsigned long long>(found / 200), elapsed);
    return elapsed;
  };
  // 64 and 256 extents: a 4x input, both inside the bound on a single scope.
  const double small = measure(64);
  const double large = measure(256);
  std::printf("overlap ratio(4x extents)=%.2f\n", large / (small > 0 ? small : 1e-9));
  // A 4x input must not cost more than roughly 8x; the merge is linear.
  CHECK(large < 12.0 * small + 0.05);
}

SBF_TEST(scale, durable_append_cost_is_stable_and_retention_is_bounded) {
  const auto root = scratch("append");
  const StoreId store_id = StoreId::make("scale-store");
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  CHECK_OK(Store::open(root, store_id, options, store, report));

  constexpr std::uint64_t kRecords = 4000;
  const auto start = std::chrono::steady_clock::now();
  for (std::uint64_t sequence = 1; sequence <= kRecords; ++sequence) {
    JournalRecord record;
    record.kind = RecordKind::StepAdvance;
    record.sequence = Sequence{sequence};
    record.step = Step{sequence};
    record.payload = std::string(64, 'p');
    CHECK_OK(store.append(record));
  }
  const double elapsed = seconds_since(start);
  std::printf("durable appends=%llu seconds=%.6f per_append_us=%.2f\n",
              static_cast<unsigned long long>(kRecords), elapsed,
              elapsed * 1e6 / static_cast<double>(kRecords));
  CHECK_EQ(store.last_sequence().value(), kRecords);

  // Checkpointing bounds the journal: after a checkpoint the journal is empty
  // and reopening replays only the snapshot.
  CHECK_OK(store.checkpoint("state", store.last_sequence(), Step{kRecords}));
  CHECK_OK(store.append([] {
    JournalRecord record;
    record.kind = RecordKind::StepAdvance;
    record.sequence = Sequence{kRecords + 1};
    record.step = Step{kRecords + 1};
    return record;
  }()));
  Store reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OK(Store::open(root, store_id, options, reopened, reopened_report));
  CHECK(reopened_report.snapshot_loaded);
  CHECK_EQ(reopened_report.journal_records, std::uint64_t{1});
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(scale, fence_table_and_lineage_stay_bounded_under_sustained_load) {
  FenceTable fences;
  LineageTable lineage;
  constexpr std::size_t kRounds = 2000;
  Scope scope = Scope::try_parse("p1,p2,p3").value();
  for (std::size_t i = 0; i < kRounds; ++i) {
    EpochGrant grant;
    grant.id = GrantId{static_cast<std::uint64_t>(i + 1)};
    grant.domain = DomainId::make("domain");
    grant.scope = scope.digest();
    grant.extents = scope;
    grant.epoch = Epoch{static_cast<std::uint64_t>(i + 1)};
    grant.incarnation = IncarnationId{static_cast<std::uint64_t>(i + 1)};
    grant.boot = BootId{static_cast<std::uint64_t>(i + 1)};
    grant.fence_token = FenceToken{static_cast<std::uint64_t>(i + 1)};
    grant.opened_at = Step{static_cast<std::uint64_t>(i + 1)};
    grant.registry_sequence = Sequence{static_cast<std::uint64_t>(i + 1)};
    const Status opened = lineage.open_grant(grant);
    if (!opened.is_ok()) break;  // the bounded table refuses rather than growing
    CHECK_OK(lineage.close_grant(grant.id, GrantState::Closed, Reason::None, Step{1}));
    FenceRecord record;
    record.token = grant.fence_token;
    record.domain = grant.domain;
    record.scope = scope.digest();
    record.fenced_epoch = grant.epoch;
    record.fenced_incarnation = grant.incarnation;
    record.issued_at = grant.opened_at;
    record.superseded_grant = grant.id;
    const Status applied = fences.apply(record, scope);
    if (!applied.is_ok()) break;
  }
  CHECK(lineage.grants().size() <= limits::kMaxLineageEntries);
  CHECK(fences.records().size() <= limits::kMaxFenceRecords);
  CHECK(fences.size() <= limits::kMaxIndexedExtents);
  CHECK_OK(lineage.validate());
  CHECK_OK(fences.validate());
  std::printf("retained grants=%zu fence_records=%zu extents=%zu\n", lineage.grants().size(),
              fences.records().size(), fences.size());
}

SBF_TEST(scale, witness_subject_table_is_bounded_and_refuses_deterministically) {
  WitnessConfig config;
  config.witness = WitnessId::make("witness-0");
  config.fault_domain = FaultDomainId::make("fd-0");
  config.max_subjects = 16;
  WitnessService service;
  CHECK_OK(service.configure(config));
  CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));

  std::uint64_t accepted = 0;
  Status last = Status::ok();
  for (std::uint64_t i = 0; i < 64; ++i) {
    AttestRequest request;
    request.subject_domain = DomainId::make("domain");
    request.subject_scope = Scope::try_parse("p" + std::to_string(i)).value();
    request.epoch = Epoch{1};
    request.incarnation = IncarnationId{1};
    request.fence_token = FenceToken{1};
    request.policy_generation = Generation{1};
    request.requester_step = Step{1};
    AttestResponse response;
    last = service.attest(request, response, Step{1});
    if (!last.is_ok()) break;
    ++accepted;
  }
  CHECK_EQ(accepted, std::uint64_t{16});
  CHECK(last.outcome == Outcome::Exhausted);
  service.stop();
}
SBF_TEST_MAIN
