// sbfctl: operator tooling.
//
//   sbfctl version
//   sbfctl inspect  --registry host:port --node id
//   sbfctl define   --registry host:port --node id --domain d --scope a,b --policy p
//   sbfctl witness-status --witness host:port --node id
//   sbfctl shutdown --registry host:port --node id
//   sbfctl audit    --dir <store-dir> --store <id>        (offline verifier)
//   sbfctl plan     --cases <n> --seed <n>                (authority planner)
//   sbfctl selftest

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "cli_support.hpp"
#include "sbf/audit.hpp"
#include "sbf/coordinator.hpp"
#include "sbf/registry.hpp"
#include "sbf/text.hpp"
#include "sbf/version.hpp"
#include "sbf/witness.hpp"

namespace {

using namespace sbf;

Status connect_registry(const cli::Options& options, RegistryClient& client, NodeId& node_out) {
  auto node = NodeId::try_make(options.str("node", "sbfctl"));
  if (!node.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  node_out = *node;
  net::Endpoint endpoint;
  if (auto st = net::Endpoint::parse(options.str("registry", "127.0.0.1:9000"), endpoint);
      !st.is_ok()) {
    return st;
  }
  HelloRequest hello;
  hello.node = *node;
  hello.kind = ClientKind::Operator;
  hello.client_protocol = kFrameVersion;
  return client.connect(endpoint, hello);
}

int cmd_inspect(const cli::Options& options) {
  RegistryClient client;
  NodeId node;
  if (auto st = connect_registry(options, client, node); !st.is_ok()) {
    return cli::fail("connect failed: " + sbf::to_string(st));
  }
  Scope scope;
  if (auto st = Scope::parse(options.str("scope", "port-1"), scope); !st.is_ok()) {
    return cli::fail("--scope: " + sbf::to_string(st));
  }
  auto domain = DomainId::try_make(options.str("domain", "domain-a"));
  if (!domain.has_value()) return cli::fail("--domain must be a valid identifier");
  InspectResponse response;
  if (auto st = client.inspect(*domain, scope, IncarnationId{}, response); !st.is_ok()) {
    return cli::fail("inspect failed: " + sbf::to_string(st));
  }
  std::cout << "status=" << sbf::to_string(response.status) << "\n"
            << "registry_generation=" << response.registry_generation.value() << "\n"
            << "last_registry_sequence=" << response.last_registry_sequence.value() << "\n"
            << response.report << std::endl;
  return response.status.is_ok() ? 0 : 1;
}

int cmd_define(const cli::Options& options) {
  RegistryClient client;
  NodeId node;
  if (auto st = connect_registry(options, client, node); !st.is_ok()) {
    return cli::fail("connect failed: " + sbf::to_string(st));
  }
  DomainDefinition definition;
  auto domain = DomainId::try_make(options.str("domain"));
  auto owner = NodeId::try_make(options.str("owner", options.str("node", "sbfctl")));
  auto policy = PolicyId::try_make(options.str("policy", "fabric-policy"));
  if (!domain.has_value() || !owner.has_value() || !policy.has_value()) {
    return cli::fail("--domain, --owner and --policy must be valid identifiers");
  }
  definition.domain = *domain;
  definition.node = *owner;
  definition.policy = *policy;
  if (auto st = Scope::parse(options.str("scope"), definition.scope); !st.is_ok()) {
    return cli::fail("--scope: " + sbf::to_string(st));
  }
  definition.exclusive = options.str("exclusive", "true") == "true";
  DefineDomainResponse response;
  if (auto st = client.define_domain(definition, response); !st.is_ok()) {
    return cli::fail("define failed: " + sbf::to_string(st));
  }
  std::cout << "status=" << sbf::to_string(response.status)
            << " domain_generation=" << response.domain_generation.value() << std::endl;
  return response.status.is_ok() ? 0 : 1;
}

int cmd_witness_status(const cli::Options& options) {
  auto node = NodeId::try_make(options.str("node", "sbfctl"));
  auto witness_id = WitnessId::try_make(options.str("id", "witness-1"));
  if (!node.has_value() || !witness_id.has_value()) return cli::fail("invalid identifier");
  net::Endpoint endpoint;
  if (auto st = net::Endpoint::parse(options.str("witness", "127.0.0.1:9100"), endpoint);
      !st.is_ok()) {
    return cli::fail("--witness expects host:port");
  }
  WitnessClient client(*witness_id, FaultDomainId{}, endpoint);
  HelloRequest hello;
  hello.node = *node;
  hello.kind = ClientKind::Operator;
  hello.client_protocol = kFrameVersion;
  if (auto st = client.connect(hello); !st.is_ok()) {
    return cli::fail("connect failed: " + sbf::to_string(st));
  }
  std::cout << "witness=" << witness_id->view() << " endpoint=" << endpoint.to_string()
            << " connected=1" << std::endl;
  return 0;
}

int cmd_shutdown(const cli::Options& options) {
  RegistryClient client;
  NodeId node;
  if (auto st = connect_registry(options, client, node); !st.is_ok()) {
    return cli::fail("connect failed: " + sbf::to_string(st));
  }
  if (auto st = client.shutdown_server(); !st.is_ok()) {
    return cli::fail("shutdown failed: " + sbf::to_string(st));
  }
  std::cout << "shutdown requested" << std::endl;
  return 0;
}

int cmd_audit(const cli::Options& options) {
  const std::filesystem::path directory = options.str("dir", "sbf-registry-state");
  auto store_id = StoreId::try_make(options.str("store", "fabric-store"));
  if (!store_id.has_value()) return cli::fail("--store must be a valid identifier");

  RegistryConfig config;
  config.store_id = *store_id;
  auto node = NodeId::try_make("offline-auditor");
  if (!node.has_value()) return cli::fail("invalid node");
  config.node = *node;
  config.policy.policy = PolicyId::make("fabric-policy");
  config.policy.quorum.policy = config.policy.policy;
  config.policy.quorum.witnesses.push_back(
      WitnessSlot{WitnessId::make("offline-witness"), FaultDomainId::make("offline-fd")});
  config.policy.quorum.mode = QuorumMode::ThresholdDistinctWitnesses;
  config.policy.quorum.threshold = 1;

  StoreOpenOptions open_options;
  open_options.create_if_missing = false;
  open_options.allow_torn_tail_recovery = true;
  Store store;
  StoreRecoveryReport report;
  if (auto st = Store::open(directory, *store_id, open_options, store, report); !st.is_ok()) {
    return cli::fail("open failed: " + sbf::to_string(st));
  }
  RegistryState state;
  StepClock clock;
  BootRecord boot;
  boot.node = *node;
  if (auto st = state.initialise(config, clock, boot); !st.is_ok()) {
    return cli::fail("state init failed: " + sbf::to_string(st));
  }
  std::string blob;
  SnapshotHeader header;
  Sequence covers;
  if (store.load_snapshot(blob, header).is_ok()) {
    if (auto st = state.deserialize(blob); !st.is_ok()) {
      return cli::fail("snapshot rejected: " + sbf::to_string(st));
    }
    covers = header.covers_sequence;
  }
  const Status replayed = store.replay([&](const JournalRecord& record) {
    if (record.sequence.value() <= covers.value()) return Status::ok();
    return state.apply(record);
  });
  if (!replayed.is_ok()) return cli::fail("journal rejected: " + sbf::to_string(replayed));
  if (auto st = state.rebuild(); !st.is_ok()) {
    return cli::fail("state rebuild failed: " + sbf::to_string(st));
  }

  FabricStore fabric;
  if (auto st = FabricStore::open(directory, *store_id, open_options, fabric, report); !st.is_ok()) {
    return cli::fail("fabric open failed: " + sbf::to_string(st));
  }

  const AuditReport state_audit = audit_registry_state(state);
  const AuditReport fabric_audit = audit_fabric_history(fabric.records());

  std::cout << "store=" << store_id->view() << " dir=" << directory.string() << "\n"
            << "boot=" << state.boot().boot.value()
            << " incarnation=" << state.boot().incarnation.value()
            << " token_counter=" << state.token_counter().value()
            << " interrupts=" << state.interrupts().size() << "\n"
            << "snapshot_loaded=" << (report.snapshot_loaded ? 1 : 0)
            << " torn_tail=" << (report.torn_tail_recovered ? 1 : 0)
            << " journal_records=" << report.journal_records << "\n"
            << "registry: outcome=" << sbf::to_string(state_audit.status)
            << " checks=" << state_audit.checks_run
            << " findings=" << state_audit.findings_total
            << " grants=" << state_audit.grants
            << " open_grants=" << state_audit.open_grants
            << " epoch_regressions=" << state_audit.epoch_regressions
            << " duplicate_exclusive_grants=" << state_audit.duplicate_exclusive_grants
            << " fenced_open_grants=" << state_audit.uninterruptible_grants << "\n"
            << "fabric: outcome=" << sbf::to_string(fabric_audit.status)
            << " mutations=" << fabric_audit.mutations
            << " distinct_owners=" << fabric_audit.distinct_owners
            << " ownership_transitions=" << fabric_audit.ownership_transitions
            << " token_regressions=" << fabric_audit.token_regressions
            << " foreign_owner_appends=" << fabric_audit.foreign_owner_appends
            << " fence_escapes=" << fabric_audit.fence_escapes
            << " sequence_gaps=" << fabric_audit.sequence_gaps
            << " mutually_exclusive=" << (fabric_audit.mutually_exclusive_effect_history ? 1 : 0)
            << "\n";
  for (const auto& finding : state_audit.findings) {
    std::cout << "  registry-finding " << sbf::to_string(finding.outcome) << " "
              << sbf::to_string(finding.reason) << " " << finding.subject << ": " << finding.detail
              << "\n";
  }
  for (const auto& finding : fabric_audit.findings) {
    std::cout << "  fabric-finding " << sbf::to_string(finding.outcome) << " "
              << sbf::to_string(finding.reason) << " " << finding.subject << ": " << finding.detail
              << "\n";
  }
  const bool ok = state_audit.findings_total == 0 && fabric_audit.findings_total == 0 &&
                  fabric_audit.mutually_exclusive_effect_history;
  std::cout << (ok ? "AUDIT OK" : "AUDIT FAILED") << std::endl;
  return ok ? 0 : 1;
}

int cmd_plan(const cli::Options& options) {
  const std::uint64_t cases = options.number("cases", 128);
  const std::uint64_t seed = options.number("seed", 1);
  std::cout << "plan seed=" << seed << " cases=" << cases << std::endl;
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cout << "usage: sbfctl <version|inspect|define|witness-status|shutdown|audit|plan>"
              << std::endl;
    return 2;
  }
  const std::string command = argv[1];
  // Global flags, accepted before the subcommand for consistency with the other
  // tools in this repository.
  if (command == "--version" || command == "-v" || command == "--help" || command == "-h") {
    std::cout << build_description() << "\n"
              << "usage: sbfctl <version|inspect|define|witness-status|shutdown|audit|plan>"
              << std::endl;
    return 0;
  }
  cli::Options options;
  std::string error;
  if (!cli::parse(argc, argv, 2, options, error)) return cli::fail(error);
  if (auto st = net::initialize(); !st.is_ok()) return cli::fail("network init failed");

  if (command == "version") {
    std::cout << build_description() << std::endl;
    return 0;
  }
  if (command == "inspect") return cmd_inspect(options);
  if (command == "define") return cmd_define(options);
  if (command == "witness-status") return cmd_witness_status(options);
  if (command == "shutdown") return cmd_shutdown(options);
  if (command == "audit") return cmd_audit(options);
  if (command == "plan") return cmd_plan(options);
  return cli::fail("unknown command: " + command);
}
