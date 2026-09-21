// Concurrency and lifecycle proof.
//
// Synchronisation is expressed with deterministic latches and condition
// variables - never with sleeps. If a shutdown ordering is wrong the test
// blocks, which is the signal we want: a hang here is a defect, not something to
// paper over with a watchdog.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "sbf/audit.hpp"
#include "sbf/registry.hpp"
#include "sbf/witness.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

namespace {

// A latch that releases when the expected number of participants arrive. Used to
// line threads up exactly, with no reliance on scheduling luck.
class Barrier {
 public:
  explicit Barrier(std::size_t expected) : expected_(expected) {}

  void arrive_and_wait() {
    std::unique_lock<std::mutex> lock(mutex_);
    ++arrived_;
    if (arrived_ == expected_) {
      released_ = true;
      condition_.notify_all();
      return;
    }
    condition_.wait(lock, [this]() { return released_; });
  }

 private:
  std::mutex mutex_;
  std::condition_variable condition_;
  std::size_t expected_;
  std::size_t arrived_ = 0;
  bool released_ = false;
};

std::filesystem::path scratch(std::string_view name) {
  static std::uint64_t counter = 0;
  const auto path = std::filesystem::temp_directory_path() /
                    ("sbf-conc-" + std::string(name) + "-" + std::to_string(++counter));
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
  std::filesystem::create_directories(path, ec);
  return path;
}

}  // namespace

SBF_TEST(lifecycle, registry_shutdown_is_prompt_and_releases_blocked_accepts) {
  const auto root = scratch("shutdown");
  RegistryConfig config;
  config.store_id = StoreId::make("conc-store");
  config.node = NodeId::make("registry-1");
  config.policy = policy_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);

  RegistryService service;
  StoreRecoveryReport report;
  CHECK_OK(service.open(config, root / "registry", report));
  CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
  service.start();

  // A client that connects and then goes idle must not prevent shutdown: stop()
  // shuts the live socket down, which unblocks the connection thread's recv.
  RegistryClient idle;
  HelloRequest hello;
  hello.node = NodeId::make("idle");
  hello.kind = ClientKind::Observer;
  CHECK_OK(idle.connect(service.endpoint(), hello));

  std::atomic<bool> stopped{false};
  std::thread stopper([&]() {
    service.stop();
    service.join();
    stopped.store(true);
  });
  stopper.join();
  CHECK(stopped.load());
  CHECK(service.phase() == RegistryPhase::Stopped);
  idle.close();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(lifecycle, many_concurrent_clients_are_serialised_without_loss) {
  const auto root = scratch("concurrent");
  RegistryConfig config;
  config.store_id = StoreId::make("conc-store");
  config.node = NodeId::make("registry-1");
  config.policy = policy_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
  config.checkpoint_every_records = 16;

  RegistryService service;
  StoreRecoveryReport report;
  CHECK_OK(service.open(config, root / "registry", report));
  for (int i = 0; i < 8; ++i) {
    DomainDefinition definition;
    definition.domain = DomainId::make("domain-" + std::to_string(i));
    definition.node = NodeId::make("coordinator");
    definition.policy = config.policy.policy;
    definition.scope = Scope::try_parse("p" + std::to_string(i)).value();
    CHECK_OK(service.define_domain(definition));
  }
  CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
  service.start();

  constexpr std::size_t kThreads = 8;
  constexpr std::size_t kRounds = 25;
  Barrier barrier(kThreads);
  std::atomic<std::uint64_t> successes{0};
  std::atomic<std::uint64_t> failures{0};
  std::mutex diagnosis_mutex;
  std::string diagnosis;
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < kThreads; ++i) {
    threads.emplace_back([&, i]() {
      Barrier& start = barrier;
      start.arrive_and_wait();
      RegistryClient client;
      HelloRequest hello;
      hello.node = NodeId::make("client-" + std::to_string(i));
      hello.kind = ClientKind::Coordinator;
      if (!client.connect(service.endpoint(), hello).is_ok()) {
        failures.fetch_add(1);
        return;
      }
      for (std::size_t round = 0; round < kRounds; ++round) {
        AllocateEpochResponse response;
        const Status status = client.allocate_epoch(
            DomainId::make("domain-" + std::to_string(i)),
            Scope::try_parse("p" + std::to_string(i)).value(), client.binding().incarnation,
            client.binding().boot, Sequence{round + 1}, response);
        if (status.is_ok() && response.status.is_ok()) {
          successes.fetch_add(1);
        } else {
          failures.fetch_add(1);
          std::lock_guard<std::mutex> guard(diagnosis_mutex);
          if (diagnosis.empty()) {
            diagnosis = "thread " + std::to_string(i) + " round " + std::to_string(round) +
                        " status=" + sbf::to_string(status) +
                        " response=" + sbf::to_string(response.status);
          }
        }
      }
      client.close();
    });
  }
  for (auto& thread : threads) thread.join();
  if (!diagnosis.empty()) std::printf("first failure: %s\n", diagnosis.c_str());
  CHECK_EQ(successes.load(), static_cast<std::uint64_t>(kThreads * kRounds));
  CHECK_EQ(failures.load(), std::uint64_t{0});

  // Every allocation is durable and the lineage has no duplicate epochs.
  const AuditReport audit = audit_registry_state(service.state());
  CHECK_EQ(audit.epoch_regressions, std::uint64_t{0});
  CHECK_EQ(audit.duplicate_exclusive_grants, std::uint64_t{0});
  for (int i = 0; i < 8; ++i) {
    const auto grants = service.state().lineage().grants_for(DomainId::make("domain-" + std::to_string(i)));
    Epoch previous;
    for (const auto& grant : grants) {
      CHECK(grant.epoch > previous);
      previous = grant.epoch;
    }
  }

  service.stop();
  service.join();
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(lifecycle, witness_shutdown_releases_blocked_sessions) {
  WitnessConfig config;
  config.witness = WitnessId::make("witness-0");
  config.fault_domain = FaultDomainId::make("fd-0");
  WitnessService service;
  CHECK_OK(service.configure(config));
  CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
  service.start();

  std::vector<std::unique_ptr<WitnessClient>> clients;
  for (int i = 0; i < 4; ++i) {
    auto client = std::make_unique<WitnessClient>(WitnessId::make("witness-0"),
                                                  FaultDomainId::make("fd-0"),
                                                  service.endpoint());
    HelloRequest hello;
    hello.node = NodeId::make("coordinator-" + std::to_string(i));
    hello.kind = ClientKind::Coordinator;
    CHECK_OK(client->connect(hello));
    clients.push_back(std::move(client));
  }
  service.stop();
  service.join();
  for (auto& client : clients) client->close();
}

SBF_TEST(lifecycle, repeated_open_close_cycles_do_not_leak_or_deadlock) {
  const auto root = scratch("cycles");
  for (int cycle = 0; cycle < 6; ++cycle) {
    RegistryConfig config;
    config.store_id = StoreId::make("cycle-store");
    config.node = NodeId::make("registry-1");
    config.policy = policy_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
    RegistryService service;
    StoreRecoveryReport report;
    CHECK_OK(service.open(config, root / "registry", report));
    CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
    service.start();
    RegistryClient client;
    HelloRequest hello;
    hello.node = NodeId::make("client");
    hello.kind = ClientKind::Observer;
    CHECK_OK(client.connect(service.endpoint(), hello));
    InspectResponse inspected;
    CHECK_OK(client.inspect(DomainId::make("domain-a"), Scope::try_parse("p1").value(),
                            IncarnationId{}, inspected));
    CHECK_OK(inspected.status);
    client.close();
    service.stop();
    service.join();
    CHECK(service.phase() == RegistryPhase::Stopped);
  }
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}

SBF_TEST(lifecycle, stopping_twice_and_joining_twice_is_safe) {
  const auto root = scratch("double-stop");
  RegistryConfig config;
  config.store_id = StoreId::make("double-store");
  config.node = NodeId::make("registry-1");
  config.policy = policy_of(1, QuorumMode::ThresholdDistinctWitnesses, 1);
  RegistryService service;
  StoreRecoveryReport report;
  CHECK_OK(service.open(config, root / "registry", report));
  CHECK_OK(service.bind(net::Endpoint{"127.0.0.1", 0}));
  service.start();
  service.stop();
  service.stop();
  service.join();
  service.join();
  CHECK(service.phase() == RegistryPhase::Stopped);
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
}
SBF_TEST_MAIN
