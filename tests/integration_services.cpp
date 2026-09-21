#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "sbf/audit.hpp"
#include "sbf/coordinator.hpp"
#include "sbf/registry.hpp"
#include "sbf/text.hpp"
#include "sbf/witness.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

namespace {

std::filesystem::path fresh_root(std::string_view name) {
  static std::uint64_t counter = 0;
  const auto path = std::filesystem::temp_directory_path() /
                    ("sbf-it-" + std::string(name) + "-" + std::to_string(++counter));
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
  std::filesystem::create_directories(path, ec);
  return path;
}

// A complete loopback fabric: N witnesses plus one registry, all in this
// process. Loopback sockets are real; the processes are not, which is why the
// multiprocess suite exists separately.
struct Fabric {
  std::filesystem::path root;
  std::vector<std::unique_ptr<WitnessService>> witnesses;
  std::unique_ptr<RegistryService> registry;
  RegistryConfig registry_config;
  std::vector<WitnessConfig> witness_configs;

  Status start(std::size_t witness_count, std::size_t quorum_threshold,
               std::string_view store_name = "store-1") {
    root = fresh_root(store_name);
    for (std::size_t i = 0; i < witness_count; ++i) {
      WitnessConfig config;
      config.witness = WitnessId::make("witness-" + std::to_string(i));
      config.fault_domain = FaultDomainId::make("fd-" + std::to_string(i));
      config.attestation_horizon_steps = 100000;
      auto service = std::make_unique<WitnessService>();
      if (auto st = service->configure(config); !st.is_ok()) return st;
      if (auto st = service->bind(net::Endpoint{"127.0.0.1", 0}); !st.is_ok()) return st;
      service->start();
      witness_configs.push_back(config);
      witnesses.push_back(std::move(service));
    }

    registry_config.store_id = StoreId::make("test-store");
    registry_config.node = NodeId::make("registry-1");
    registry_config.lease_horizon_steps = Step{100000};
    registry_config.policy.policy = PolicyId::make("fabric-policy");
    registry_config.policy.generation = Generation{1};
    registry_config.policy.quorum = quorum_of(witness_count, QuorumMode::ThresholdDistinctWitnesses,
                                              static_cast<std::uint32_t>(quorum_threshold));
    for (std::size_t i = 0; i < witness_count; ++i) {
      registry_config.policy.quorum.witnesses[i] =
          WitnessSlot{witness_configs[i].witness, witness_configs[i].fault_domain};
    }
    registry = std::make_unique<RegistryService>();
    StoreRecoveryReport report;
    if (auto st = registry->open(registry_config, root / "registry", report); !st.is_ok()) return st;
    if (auto st = registry->bind(net::Endpoint{"127.0.0.1", 0}); !st.is_ok()) return st;
    registry->start();
    return Status::ok();
  }

  Status define(std::string_view domain, std::string_view scope_csv) {
    DomainDefinition definition;
    definition.domain = DomainId::make(domain);
    definition.node = NodeId::make("coordinator");
    definition.policy = registry_config.policy.policy;
    if (auto st = Scope::parse(scope_csv, definition.scope); !st.is_ok()) return st;
    return registry->define_domain(definition);
  }

  CoordinatorConfig coordinator_config(std::string_view domain, std::string_view scope_csv,
                                       std::size_t witness_count) const {
    CoordinatorConfig config;
    config.node = NodeId::make("coordinator");
    config.domain = DomainId::make(domain);
    config.scope = Scope::try_parse(scope_csv).value_or(Scope{});
    config.registry = registry->endpoint();
    for (std::size_t i = 0; i < witness_count; ++i) {
      config.witnesses.emplace_back(witness_configs[i].witness, witness_configs[i].fault_domain,
                                    witnesses[i]->endpoint());
    }
    return config;
  }

  void stop() {
    if (registry) {
      registry->stop();
      registry->join();
    }
    for (auto& witness : witnesses) {
      witness->stop();
      witness->join();
    }
    witnesses.clear();
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
  }
};

}  // namespace

SBF_TEST(integration, full_authority_cycle_commits_through_the_effect_boundary) {
  Fabric fabric;
  CHECK_OK(fabric.start(3, 2));
  CHECK_OK(fabric.define("domain-a", "p1,p2"));

  Coordinator coordinator(fabric.coordinator_config("domain-a", "p1,p2", 3));
  HelloRequest hello;
  hello.node = coordinator.config().node;
  CHECK_OK(coordinator.connect(hello));
  CHECK_EQ(coordinator.incarnation().value() > 0, true);

  CoordinatorReport report;
  CHECK_OK(coordinator.mutate("switch-port", 5, report));
  CHECK_EQ(report.applied, std::uint64_t{5});
  CHECK_EQ(report.fenced, std::uint64_t{0});
  CHECK(report.attempts.front().outcome == MutationOutcome::Applied);
  CHECK(report.attempts.front().effect_digest.bytes().size() == 32);

  const AuditReport audit = audit_fabric_history(fabric.registry->state().fabric().records());
  CHECK_EQ(audit.mutations, std::uint64_t{5});
  CHECK(audit.mutually_exclusive_effect_history);
  CHECK_EQ(audit.fence_escapes, std::uint64_t{0});
  const AuditReport state_audit = audit_registry_state(fabric.registry->state());
  CHECK_EQ(state_audit.uninterruptible_grants, std::uint64_t{0});
  CHECK_EQ(state_audit.duplicate_exclusive_grants, std::uint64_t{0});

  coordinator.close();
  fabric.stop();
}

SBF_TEST(integration, two_coordinators_over_the_same_scope_never_both_commit) {
  Fabric fabric;
  CHECK_OK(fabric.start(3, 2));
  CHECK_OK(fabric.define("domain-a", "p1,p2"));

  Coordinator first(fabric.coordinator_config("domain-a", "p1,p2", 3));
  HelloRequest hello;
  hello.node = first.config().node;
  CHECK_OK(first.connect(hello));
  CoordinatorReport first_report;
  CHECK_OK(first.mutate("switch-port", 4, first_report));
  CHECK_EQ(first_report.applied, std::uint64_t{4});
  const FenceToken first_token = first_report.final_token;

  CoordinatorConfig second_config = fabric.coordinator_config("domain-a", "p1,p2", 3);
  second_config.node = NodeId::make("coordinator-b");
  Coordinator successor(std::move(second_config));
  HelloRequest successor_hello;
  successor_hello.node = NodeId::make("coordinator-b");
  CHECK_OK(successor.connect(successor_hello));
  CoordinatorReport successor_report;
  CHECK_OK(successor.mutate("switch-port", 4, successor_report));
  CHECK_EQ(successor_report.applied, std::uint64_t{4});
  CHECK(successor_report.final_token > first_token);

  // The superseded coordinator cannot commit again: its token is below the
  // durable floor and its epoch is stale.
  CoordinatorReport stale_report;
  CHECK_OK(first.mutate("switch-port", 2, stale_report));
  CHECK_EQ(stale_report.applied, std::uint64_t{0});
  CHECK(stale_report.fenced + stale_report.refused + stale_report.unknown >= 1);

  const AuditReport audit = audit_fabric_history(fabric.registry->state().fabric().records());
  CHECK_EQ(audit.mutations, std::uint64_t{8});
  CHECK_EQ(audit.fence_escapes, std::uint64_t{0});
  CHECK_EQ(audit.token_regressions, std::uint64_t{0});
  CHECK_EQ(audit.foreign_owner_appends, std::uint64_t{0});
  CHECK(audit.mutually_exclusive_effect_history);
  CHECK_EQ(audit.distinct_owners, std::uint64_t{2});

  first.close();
  successor.close();
  fabric.stop();
}

SBF_TEST(integration, non_overlapping_domains_are_both_authoritative) {
  Fabric fabric;
  CHECK_OK(fabric.start(3, 2));
  CHECK_OK(fabric.define("domain-a", "p1,p2"));
  CHECK_OK(fabric.define("domain-b", "p7,p8"));

  Coordinator a(fabric.coordinator_config("domain-a", "p1,p2", 3));
  CoordinatorConfig b_config = fabric.coordinator_config("domain-b", "p7,p8", 3);
  b_config.node = NodeId::make("coordinator-b");
  Coordinator b2(std::move(b_config));
  HelloRequest hello_a;
  hello_a.node = NodeId::make("coordinator");
  CHECK_OK(a.connect(hello_a));
  HelloRequest hello_b;
  hello_b.node = NodeId::make("coordinator-b");
  CHECK_OK(b2.connect(hello_b));

  CoordinatorReport report_a;
  CoordinatorReport report_b;
  CHECK_OK(a.mutate("switch-port", 3, report_a));
  CHECK_OK(b2.mutate("switch-port", 3, report_b));
  CHECK_EQ(report_a.applied, std::uint64_t{3});
  CHECK_EQ(report_b.applied, std::uint64_t{3});

  const AuditReport audit = audit_fabric_history(fabric.registry->state().fabric().records());
  CHECK_EQ(audit.mutations, std::uint64_t{6});
  CHECK(audit.mutually_exclusive_effect_history);
  a.close();
  b2.close();
  fabric.stop();
}

SBF_TEST(integration, partition_leaves_both_sides_non_authoritative) {
  Fabric fabric;
  CHECK_OK(fabric.start(3, 2));
  CHECK_OK(fabric.define("domain-a", "p1,p2"));

  // Only one witness out of three is reachable for this coordinator: a
  // minority partition. It must not be able to assemble a quorum.
  CoordinatorConfig minority = fabric.coordinator_config("domain-a", "p1,p2", 1);
  Coordinator coordinator(std::move(minority));
  HelloRequest hello;
  hello.node = NodeId::make("coordinator");
  CHECK_OK(coordinator.connect(hello));

  // Acquisition succeeds (the registry is reachable) but the decision cannot:
  // evidence is insufficient, so no mutation happens.
  CoordinatorReport report;
  CHECK_OK(coordinator.mutate("switch-port", 3, report));
  CHECK_EQ(report.applied, std::uint64_t{0});
  CHECK(report.unknown + report.refused >= 3);
  CHECK(!report.holds_authority);
  CHECK_EQ(fabric.registry->state().fabric().records().size(), std::size_t{0});

  // The other side of the partition - a coordinator that can reach the full
  // witness set - is a fresh incarnation, so it fences the first and proceeds.
  CoordinatorConfig majority = fabric.coordinator_config("domain-a", "p1,p2", 3);
  majority.node = NodeId::make("coordinator-b");
  Coordinator other(std::move(majority));
  HelloRequest other_hello;
  other_hello.node = NodeId::make("coordinator-b");
  CHECK_OK(other.connect(other_hello));
  CoordinatorReport other_report;
  CHECK_OK(other.mutate("switch-port", 2, other_report));
  CHECK_EQ(other_report.applied, std::uint64_t{2});

  // The partitioned side can never commit afterwards. Whether the refusal
  // arrives as a status or as a zero-applied report, nothing is applied.
  CoordinatorReport retry;
  const Status retry_status = coordinator.mutate("switch-port", 2, retry);
  CHECK_EQ(retry.applied, std::uint64_t{0});
  CHECK(!retry_status.is_ok() || retry.fenced + retry.refused + retry.unknown > 0);

  const AuditReport audit = audit_fabric_history(fabric.registry->state().fabric().records());
  CHECK_EQ(audit.mutations, std::uint64_t{2});
  CHECK_EQ(audit.distinct_owners, std::uint64_t{1});
  CHECK(audit.mutually_exclusive_effect_history);

  coordinator.close();
  other.close();
  fabric.stop();
}

SBF_TEST(integration, operator_cannot_obtain_mutation_authority) {
  Fabric fabric;
  CHECK_OK(fabric.start(1, 1));
  CHECK_OK(fabric.define("domain-a", "p1"));

  RegistryClient client;
  HelloRequest hello;
  hello.node = NodeId::make("operator");
  hello.kind = ClientKind::Observer;
  CHECK_OK(client.connect(fabric.registry->endpoint(), hello));
  AllocateEpochResponse response;
  // The session's own identity is used, so this isolates the client-kind gate
  // rather than the session-binding gate.
  CHECK_OUTCOME(client.allocate_epoch(DomainId::make("domain-a"),
                                      Scope::try_parse("p1").value_or(Scope{}),
                                      client.binding().incarnation, client.binding().boot,
                                      Sequence{1}, response),
                Outcome::Refused);
  // Declaring another incarnation than the session's own is refused outright.
  AllocateEpochResponse foreign;
  CHECK_OUTCOME(client.allocate_epoch(DomainId::make("domain-a"),
                                      Scope::try_parse("p1").value_or(Scope{}),
                                      IncarnationId{12345}, client.binding().boot, Sequence{2},
                                      foreign),
                Outcome::Invalid);
  client.close();
  fabric.stop();
}

SBF_TEST(integration, unregistered_scope_is_refused_at_allocation) {
  Fabric fabric;
  CHECK_OK(fabric.start(1, 1));
  CHECK_OK(fabric.define("domain-a", "p1"));

  CoordinatorConfig config = fabric.coordinator_config("domain-a", "p1,p2", 1);
  Coordinator coordinator(std::move(config));
  HelloRequest hello;
  hello.node = NodeId::make("coordinator");
  CHECK_OK(coordinator.connect(hello));
  Epoch epoch;
  FenceToken token;
  GrantId grant;
  // The coordinator may only claim the exact scope it was registered for.
  CHECK(!coordinator.acquire_authority(0, epoch, token, grant).is_ok());
  coordinator.close();
  fabric.stop();
}

SBF_TEST(integration, release_fences_the_released_incarnation) {
  Fabric fabric;
  CHECK_OK(fabric.start(2, 2));
  CHECK_OK(fabric.define("domain-a", "p1"));

  CoordinatorConfig config = fabric.coordinator_config("domain-a", "p1", 2);
  Coordinator coordinator(std::move(config));
  HelloRequest hello;
  hello.node = NodeId::make("coordinator");
  CHECK_OK(coordinator.connect(hello));
  CoordinatorReport report;
  CHECK_OK(coordinator.mutate("switch-port", 1, report));
  CHECK_EQ(report.applied, std::uint64_t{1});
  const FenceToken held = coordinator.token();
  coordinator.release(Reason::None);

  // After release the durable high-water mark has advanced, so the same token is
  // no longer admissible at the effect boundary.
  CHECK(fabric.registry->state().fences().high_water(ExtentId::make("p1")) > held);

  // A fresh coordinator takes over cleanly.
  CoordinatorConfig successor_config = fabric.coordinator_config("domain-a", "p1", 2);
  successor_config.node = NodeId::make("coordinator-b");
  Coordinator successor(std::move(successor_config));
  HelloRequest successor_hello;
  successor_hello.node = NodeId::make("coordinator-b");
  CHECK_OK(successor.connect(successor_hello));
  CoordinatorReport successor_report;
  CHECK_OK(successor.mutate("switch-port", 1, successor_report));
  CHECK_EQ(successor_report.applied, std::uint64_t{1});

  const AuditReport audit = audit_fabric_history(fabric.registry->state().fabric().records());
  CHECK_EQ(audit.mutations, std::uint64_t{2});
  CHECK(audit.mutually_exclusive_effect_history);
  coordinator.close();
  successor.close();
  fabric.stop();
}

SBF_TEST(integration, shutdown_request_stops_the_service) {
  // Regression: a shutdown request used to be answered but never acted on, so
  // the registry kept running and the operator had no way to stop it.
  const auto root = fresh_root("shutdown-request");
  RegistryConfig config;
  config.store_id = StoreId::make("shutdown-store");
  config.node = NodeId::make("registry-1");
  config.policy = policy_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);

  RegistryService service;
  StoreRecoveryReport report;
  CHECK_OK(service.open(config, root / "registry", report));
  CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
  service.start();

  RegistryClient operator_client;
  HelloRequest hello;
  hello.node = NodeId::make("operator");
  hello.kind = ClientKind::Operator;
  CHECK_OK(operator_client.connect(service.endpoint(), hello));
  CHECK_OK(operator_client.shutdown_server());
  operator_client.close();

  // The service must reach Stopped without anyone else asking it to.
  service.join();
  CHECK(service.phase() == RegistryPhase::Stopped);
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(integration, max_sessions_is_enforced_without_instability) {
  Fabric fabric;
  CHECK_OK(fabric.start(1, 1));
  CHECK_OK(fabric.define("domain-a", "p1"));

  std::vector<std::unique_ptr<RegistryClient>> clients;
  Status last = Status::ok();
  for (std::size_t i = 0; i < limits::kMaxSessions + 4; ++i) {
    auto client = std::make_unique<RegistryClient>();
    HelloRequest hello;
    hello.node = NodeId::make("client-" + std::to_string(i));
    hello.kind = ClientKind::Observer;
    last = client->connect(fabric.registry->endpoint(), hello);
    if (!last.is_ok()) break;
    clients.push_back(std::move(client));
  }
  CHECK(!last.is_ok());
  CHECK(last.outcome == Outcome::Exhausted);
  CHECK_EQ(clients.size(), limits::kMaxSessions);
  for (auto& client : clients) client->close();
  fabric.stop();
}
SBF_TEST_MAIN
