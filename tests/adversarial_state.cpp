// Adversarial state machine: replayed leases, stale epochs, clock skew,
// duplicate witness messages, delayed completions and restarts at every
// meaningful durable boundary.
//
// Where the state is synthesised rather than produced by real hardware or real
// peers it is labelled SYNTHETIC.

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "sbf/audit.hpp"
#include "sbf/coordinator.hpp"
#include "sbf/registry.hpp"
#include "sbf/text.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

namespace {

std::filesystem::path scratch(std::string_view name) {
  static std::uint64_t counter = 0;
  const auto path = std::filesystem::temp_directory_path() /
                    ("sbf-adv-" + std::string(name) + "-" + std::to_string(++counter));
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
  std::filesystem::create_directories(path, ec);
  return path;
}

RegistryConfig config_for(StoreId store_id, std::string_view csv) {
  RegistryConfig config;
  config.store_id = store_id;
  config.node = NodeId::make("registry-1");
  config.lease_horizon_steps = Step{1000};
  config.policy = policy_of(3);
  (void)csv;
  return config;
}

DomainDefinition definition_of(std::string_view domain, std::string_view csv,
                               const PolicyId& policy) {
  DomainDefinition definition;
  definition.domain = DomainId::make(domain);
  definition.node = NodeId::make("coordinator");
  definition.policy = policy;
  definition.scope = Scope::try_parse(csv).value_or(Scope{});
  return definition;
}

}  // namespace

SBF_TEST(adversarial, replayed_lease_from_a_superseded_epoch_is_stale) {
  // SYNTHETIC evidence: a lease captured under epoch 1 is presented again while
  // the registry is at epoch 3.
  Fixture fixture;
  auto bundle = fixture.full_evidence();
  bundle.has_lease = true;
  bundle.lease.id = LeaseId{1};
  bundle.lease.grant = fixture.grant;
  bundle.lease.domain = fixture.domain;
  bundle.lease.scope = fixture.scope.digest();
  bundle.lease.epoch = Epoch{1};
  bundle.lease.incarnation = fixture.incarnation;
  bundle.lease.fence_token = fixture.token;
  bundle.lease.generation = Generation{1};
  bundle.lease.policy_generation = Generation{1};
  bundle.lease.valid_from = Step{1};
  bundle.lease.valid_until = Step{100000};

  auto view = fixture.view();
  auto request = request_of(fixture.domain, fixture.scope, fixture.epoch, fixture.incarnation,
                            fixture.token, bundle);
  CHECK(decide_authority(request, view).is_authoritative());

  // The same lease, presented for a different epoch, is stale.
  request.epoch = Epoch{2};
  const AuthorityDecision stale = decide_authority(request, view);
  CHECK(stale.verdict == AuthorityVerdict::Stale);
  CHECK(stale.explanation.contains(Reason::LeaseEpochMismatch));

  // And a lease bound to another incarnation is stale too.
  request.epoch = fixture.epoch;
  request.incarnation = IncarnationId{99};
  const AuthorityDecision foreign = decide_authority(request, view);
  CHECK(foreign.verdict == AuthorityVerdict::Stale);
  CHECK(foreign.explanation.contains(Reason::LeaseIncarnationMismatch));
  (void)view;
}

SBF_TEST(adversarial, expired_lease_is_stale_even_with_a_full_quorum) {
  Fixture fixture;
  auto bundle = fixture.full_evidence();
  bundle.has_lease = true;
  bundle.lease.id = LeaseId{1};
  bundle.lease.grant = fixture.grant;
  bundle.lease.domain = fixture.domain;
  bundle.lease.scope = fixture.scope.digest();
  bundle.lease.epoch = fixture.epoch;
  bundle.lease.incarnation = fixture.incarnation;
  bundle.lease.fence_token = fixture.token;
  bundle.lease.generation = Generation{1};
  bundle.lease.policy_generation = Generation{1};
  bundle.lease.valid_from = Step{1};
  bundle.lease.valid_until = Step{5};
  const auto view = fixture.view();   // now = 10 > 5
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, bundle);
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(decision.verdict == AuthorityVerdict::Stale);
  CHECK(decision.explanation.contains(Reason::LeaseExpired));
}

SBF_TEST(adversarial, witness_sequence_replay_below_the_floor_is_refused) {
  Fixture fixture;
  const auto view = fixture.view();
  auto bundle = fixture.full_evidence();
  const EvidenceRequest request{fixture.domain, fixture.scope.digest(), fixture.epoch,
                                fixture.incarnation, fixture.token, view.now};
  std::vector<WitnessFloor> floors;
  for (const auto& slot : fixture.policy.quorum.witnesses) {
    floors.push_back(WitnessFloor{slot.witness, Sequence{50}, Generation{1}});
  }
  const auto assessment = assess_evidence(request, fixture.policy.quorum, bundle, floors);
  CHECK(assessment.state != EvidenceState::Current);
  CHECK(assessment.replayed_attestations >= 1);
  CHECK_EQ(assessment.distinct_supporting_witnesses, std::uint32_t{0});
}

SBF_TEST(adversarial, clock_skew_and_backwards_clock_never_grant_authority) {
  Fixture fixture;
  auto bundle = fixture.full_evidence();
  // A witness that saw a clock go backwards, and attestations issued in the
  // future relative to the registry's step, must not become authority.
  for (auto& attestation : bundle.attestations) {
    attestation.observed_at.unix_nanos = -1000000;
    attestation.observed_at.observed_regression = true;
    attestation.issued_at = Step{1000000};   // far in the registry's future
  }
  const auto view = fixture.view();
  const auto request = request_of(fixture.domain, fixture.scope, fixture.epoch,
                                  fixture.incarnation, fixture.token, bundle);
  const AuthorityDecision decision = decide_authority(request, view);
  CHECK(!decision.is_authoritative());
  CHECK(decision.verdict == AuthorityVerdict::Unknown ||
        decision.verdict == AuthorityVerdict::Stale);
}

SBF_TEST(adversarial, delayed_completion_after_succession_is_fenced) {
  const auto root = scratch("delayed");
  const StoreId store_id = StoreId::make("adv-store");
  StoreRecoveryReport report;
  StoreOpenOptions options;
  Store store;
  CHECK_OK(Store::open(root / "registry", store_id, options, store, report));
  FabricStore fabric;
  CHECK_OK(FabricStore::open(root / "registry", store_id, options, fabric, report));

  const Scope scope = Scope::try_parse("p1,p2").value();
  // Epoch 1 opened under token 1 and mutated once.
  MutationRecord first;
  CHECK_OK(fabric.admit(DomainId::make("domain-a"), FenceToken{1}, scope, Epoch{1},
                        IncarnationId{2}, GrantId{1}, "switch-port",
                        Digest256::of(std::string_view("a")), Step{1}, first));
  // A successor opens epoch 2 under token 2.
  MutationRecord second;
  CHECK_OK(fabric.admit(DomainId::make("domain-a"), FenceToken{2}, scope, Epoch{2},
                        IncarnationId{3}, GrantId{2}, "switch-port",
                        Digest256::of(std::string_view("b")), Step{2}, second));
  // The delayed completion of the fenced incarnation arrives late.
  MutationRecord delayed;
  CHECK_OUTCOME(fabric.admit(DomainId::make("domain-a"), FenceToken{1}, scope, Epoch{1},
                             IncarnationId{2}, GrantId{1}, "switch-port",
                             Digest256::of(std::string_view("c")), Step{3}, delayed),
                Outcome::Fenced);
  // A different incarnation cannot append under the current owner's token.
  MutationRecord foreign;
  CHECK_OUTCOME(fabric.admit(DomainId::make("domain-a"), FenceToken{2}, scope, Epoch{2},
                             IncarnationId{99}, GrantId{2}, "switch-port",
                             Digest256::of(std::string_view("d")), Step{4}, foreign),
                Outcome::Conflict);

  const AuditReport audit = audit_fabric_history(fabric.records());
  CHECK_EQ(audit.mutations, std::uint64_t{2});
  CHECK(audit.mutually_exclusive_effect_history);
  CHECK_EQ(audit.token_regressions, std::uint64_t{0});
  CHECK_EQ(audit.foreign_owner_appends, std::uint64_t{0});

  // Reopening the fabric store preserves the token floor durably.
  FabricStore reopened;
  StoreRecoveryReport reopened_report;
  CHECK_OK(FabricStore::open(root / "registry", store_id, options, reopened, reopened_report));
  CHECK_EQ(reopened.high_water(ExtentId::make("p1")).value(), std::uint64_t{2});
  MutationRecord late;
  CHECK_OUTCOME(reopened.admit(DomainId::make("domain-a"), FenceToken{1}, scope, Epoch{1},
                               IncarnationId{2}, GrantId{1}, "switch-port",
                               Digest256::of(std::string_view("e")), Step{5}, late),
                Outcome::Fenced);
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(adversarial, restart_at_every_durable_boundary_is_conservative) {
  // The registry is opened, mutated, closed and reopened repeatedly. Each boot
  // must fence every pre-restart authority and every epoch must strictly
  // advance; no pre-restart grant may remain open.
  const auto root = scratch("restart");
  const StoreId store_id = StoreId::make("restart-store");
  const Scope scope = Scope::try_parse("p1,p2").value();
  std::vector<Epoch> epochs;
  std::vector<IncarnationId> incarnations;

  for (int cycle = 0; cycle < 4; ++cycle) {
    RegistryConfig config = config_for(store_id, "p1,p2");
    // A single-witness threshold quorum keeps this test about restart semantics.
    config.policy.quorum = quorum_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
    RegistryService service;
    StoreRecoveryReport report;
    CHECK_OK(service.open(config, root / "registry", report));
    CHECK_OK(service.define_domain(definition_of("domain-a", "p1,p2", config.policy.policy)));
    CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
    service.start();

    RegistryClient client;
    HelloRequest hello;
    hello.node = NodeId::make("coordinator");
    hello.kind = ClientKind::Coordinator;
    CHECK_OK(client.connect(service.endpoint(), hello));
    AllocateEpochResponse allocated;
    CHECK_OK(client.allocate_epoch(DomainId::make("domain-a"), scope, client.binding().incarnation,
                                   client.binding().boot, Sequence{1}, allocated));
    CHECK_OK(allocated.status);
    epochs.push_back(allocated.epoch);
    incarnations.push_back(client.binding().incarnation);
    client.close();

    // Hard stop without a clean release: the next boot must find an open grant
    // and fence it.
    service.stop();
    service.join();
  }

  for (std::size_t i = 1; i < epochs.size(); ++i) {
    CHECK(epochs[i] > epochs[i - 1]);
    CHECK(incarnations[i] > incarnations[i - 1]);
  }

  // Final inspection: nothing is left open and every interrupted grant was
  // recorded rather than silently forgotten.
  RegistryConfig config = config_for(store_id, "p1,p2");
  config.policy.quorum = quorum_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
  RegistryService service;
  StoreRecoveryReport report;
  CHECK_OK(service.open(config, root / "registry", report));
  CHECK_EQ(service.state().lineage().open_grants().size(), std::size_t{0});
  CHECK(service.state().interrupts().size() >= epochs.size() - 1);
  const AuditReport audit = audit_registry_state(service.state());
  CHECK_EQ(audit.uninterruptible_grants, std::uint64_t{0});
  CHECK_EQ(audit.duplicate_exclusive_grants, std::uint64_t{0});
  CHECK_EQ(audit.epoch_regressions, std::uint64_t{0});
  service.stop();
  service.join();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(adversarial, corrupt_snapshot_refuses_to_open_rather_than_losing_state) {
  const auto root = scratch("corrupt-snapshot");
  const StoreId store_id = StoreId::make("corrupt-store");
  {
    RegistryConfig config = config_for(store_id, "p1,p2");
    config.policy.quorum = quorum_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
    config.checkpoint_every_records = 1;
    RegistryService service;
    StoreRecoveryReport report;
    CHECK_OK(service.open(config, root / "registry", report));
    CHECK_OK(service.define_domain(definition_of("domain-a", "p1,p2", config.policy.policy)));
    CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
    service.start();
    service.stop();
    service.join();
  }
  const auto snapshot = root / "registry" / "sbf.snapshot";
  CHECK(std::filesystem::exists(snapshot));
  std::string bytes;
  CHECK_OK(read_file_bounded(snapshot, 1u << 20, bytes));
  bytes[bytes.size() / 2] ^= 0x20;
  {
    std::ofstream out(snapshot, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  RegistryConfig config = config_for(store_id, "p1,p2");
  config.policy.quorum = quorum_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
  RegistryService service;
  StoreRecoveryReport report;
  CHECK_OUTCOME(service.open(config, root / "registry", report), Outcome::Corrupt);
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(adversarial, truncated_journal_tail_is_recovered_and_reported) {
  const auto root = scratch("torn-tail");
  const StoreId store_id = StoreId::make("torn-store");
  {
    RegistryConfig config = config_for(store_id, "p1,p2");
    config.policy.quorum = quorum_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
    RegistryService service;
    StoreRecoveryReport report;
    CHECK_OK(service.open(config, root / "registry", report));
    for (int i = 0; i < 4; ++i) {
      CHECK_OK(service.define_domain(definition_of("domain-" + std::to_string(i), "p1",
                                                   config.policy.policy)));
    }
  }
  const auto journal = root / "registry" / "sbf.journal";
  const auto size = std::filesystem::file_size(journal);
  std::filesystem::resize_file(journal, size - 4);
  RegistryConfig config = config_for(store_id, "p1,p2");
  config.policy.quorum = quorum_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
  RegistryService service;
  StoreRecoveryReport report;
  CHECK_OK(service.open(config, root / "registry", report));
  CHECK(report.torn_tail_recovered);
  CHECK_EQ(service.state().domains().size(), std::size_t{3});  // the torn record is gone
  service.stop();
  service.join();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}
SBF_TEST_MAIN
