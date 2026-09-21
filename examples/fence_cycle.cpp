// Example: a complete authority cycle against in-process services.
//
// This is a walkthrough of the runtime's contract:
//   1. a witness and a registry are started on loopback;
//   2. a domain is defined over a scope;
//   3. a coordinator acquires an epoch and a durable fence token;
//   4. it collects quorum evidence and asks for a decision;
//   5. it mutates through the fenced effect boundary;
//   6. a restarted coordinator must obtain a new epoch, and the previous
//      incarnation is refused from then on.

#include <chrono>
#include <cstdio>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "sbf/audit.hpp"
#include "sbf/coordinator.hpp"
#include "sbf/registry.hpp"
#include "sbf/text.hpp"
#include "sbf/witness.hpp"

namespace {

void wait_for_ready(const std::function<bool()>& predicate) {
  // The example coordinates two in-process services; it waits on an observable
  // state transition rather than a fixed delay.
  while (!predicate()) {
    std::this_thread::yield();
  }
}

int run() {
  using namespace sbf;
  const std::filesystem::path root = std::filesystem::temp_directory_path() / "sbf-example";
  std::error_code ec;
  std::filesystem::remove_all(root, ec);
  std::filesystem::create_directories(root, ec);

  const auto store_id = StoreId::make("example-store");
  const auto node_id = NodeId::make("example-registry");

  WitnessConfig witness_config;
  witness_config.witness = WitnessId::make("witness-a");
  witness_config.fault_domain = FaultDomainId::make("rack-a");
  witness_config.attestation_horizon_steps = 100000;
  WitnessService witness;
  if (auto st = witness.configure(witness_config); !st.is_ok()) {
    std::cerr << "witness configure failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  if (auto st = witness.bind(net::Endpoint{"127.0.0.1", 0}); !st.is_ok()) {
    std::cerr << "witness bind failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  witness.start();

  RegistryConfig registry_config;
  registry_config.store_id = store_id;
  registry_config.node = node_id;
  registry_config.lease_horizon_steps = Step{5000};
  registry_config.policy.policy = PolicyId::make("example-policy");
  registry_config.policy.quorum.policy = registry_config.policy.policy;
  registry_config.policy.quorum.witnesses.push_back(
      WitnessSlot{witness_config.witness, witness_config.fault_domain});
  registry_config.policy.quorum.mode = QuorumMode::ThresholdDistinctWitnesses;
  registry_config.policy.quorum.threshold = 1;

  RegistryService registry;
  StoreRecoveryReport report;
  if (auto st = registry.open(registry_config, root / "registry", report); !st.is_ok()) {
    std::cerr << "registry open failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  DomainDefinition definition;
  definition.domain = DomainId::make("domain-a");
  definition.node = NodeId::make("coordinator-a");
  definition.policy = registry_config.policy.policy;
  if (auto st = Scope::parse("port-1,port-2", definition.scope); !st.is_ok()) {
    std::cerr << "scope parse failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  if (auto st = registry.define_domain(definition); !st.is_ok()) {
    std::cerr << "define domain failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  if (auto st = registry.bind(net::Endpoint{"127.0.0.1", 0}); !st.is_ok()) {
    std::cerr << "registry bind failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  registry.start();
  wait_for_ready([&]() { return registry.phase() == RegistryPhase::Ready; });

  CoordinatorConfig coordinator_config;
  coordinator_config.node = definition.node;
  coordinator_config.domain = definition.domain;
  coordinator_config.scope = definition.scope;
  coordinator_config.registry = registry.endpoint();
  coordinator_config.witnesses.emplace_back(witness_config.witness, witness_config.fault_domain,
                                            witness.endpoint());

  Coordinator coordinator(std::move(coordinator_config));
  HelloRequest hello;
  hello.node = definition.node;
  if (auto st = coordinator.connect(hello); !st.is_ok()) {
    std::cerr << "connect failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  CoordinatorReport coordinator_report;
  if (auto st = coordinator.mutate("switch-port", 3, coordinator_report); !st.is_ok()) {
    std::cerr << "mutate failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  std::cout << "first incarnation applied=" << coordinator_report.applied
            << " epoch=" << coordinator_report.final_epoch.value()
            << " token=" << coordinator_report.final_token.value()
            << " refused=" << coordinator_report.refused
            << " unknown=" << coordinator_report.unknown
            << " unreachable=" << coordinator_report.unreachable
            << " attempts=" << coordinator_report.attempts.size();
  if (!coordinator_report.attempts.empty()) {
    std::cout << " first_outcome="
              << sbf::to_string(coordinator_report.attempts.front().outcome)
              << " first_status="
              << sbf::to_string(coordinator_report.attempts.front().status);
  }
  std::cout << std::endl;

  // A second coordinator over the same exclusive scope supersedes the first: the
  // registry fences the incumbent before opening the new epoch.
  CoordinatorConfig successor_config;
  successor_config.node = NodeId::make("coordinator-b");
  successor_config.domain = definition.domain;
  successor_config.scope = definition.scope;
  successor_config.registry = registry.endpoint();
  successor_config.witnesses.emplace_back(witness_config.witness, witness_config.fault_domain,
                                          witness.endpoint());
  const NodeId successor_node = successor_config.node;
  Coordinator successor(std::move(successor_config));
  HelloRequest successor_hello;
  successor_hello.node = successor_node;
  if (auto st = successor.connect(successor_hello); !st.is_ok()) {
    std::cerr << "successor connect failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  CoordinatorReport successor_report;
  if (auto st = successor.mutate("switch-port", 2, successor_report); !st.is_ok()) {
    std::cerr << "successor mutate failed: " << sbf::to_string(st) << "\n";
    return 1;
  }
  std::cout << "successor applied=" << successor_report.applied
            << " epoch=" << successor_report.final_epoch.value()
            << " token=" << successor_report.final_token.value() << std::endl;

  const AuditReport audit = audit_fabric_history(registry.state().fabric().records());
  std::cout << "mutations=" << audit.mutations
            << " distinct_owners=" << audit.distinct_owners
            << " ownership_transitions=" << audit.ownership_transitions
            << " fence_escapes=" << audit.fence_escapes
            << " mutually_exclusive=" << (audit.mutually_exclusive_effect_history ? 1 : 0)
            << std::endl;

  coordinator.close();
  successor.close();
  registry.stop();
  registry.join();
  witness.stop();
  witness.join();

  const bool ok = audit.mutually_exclusive_effect_history &&
                  coordinator_report.applied == 3 && successor_report.applied == 2;
  std::cout << (ok ? "EXAMPLE OK" : "EXAMPLE FAILED") << std::endl;
  return ok ? 0 : 1;
}

}  // namespace

int main() {
  try {
    return run();
  } catch (const std::exception& error) {
    std::cerr << "example failed: " << error.what() << "\n";
    return 1;
  }
}
