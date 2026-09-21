// sbf-registry: the durable authority service.
//
// Owns the fence registry, the epoch lineage, the fenced fabric store and the
// framed control protocol. Every authority decision for the fabric passes
// through this process, which is what makes mutual exclusion provable rather
// than probabilistic.

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "cli_support.hpp"
#include "sbf/registry.hpp"
#include "sbf/text.hpp"
#include "sbf/version.hpp"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

std::uint64_t current_pid() {
#ifdef _WIN32
  return static_cast<std::uint64_t>(_getpid());
#else
  return static_cast<std::uint64_t>(getpid());
#endif
}

using namespace sbf;

Status parse_quorum(const cli::Options& options, QuorumProfile& profile, std::string& error) {
  auto policy = PolicyId::try_make(options.str("policy", "fabric-policy"));
  if (!policy.has_value()) {
    error = "invalid --policy";
    return Status::make(Outcome::Invalid, Reason::IdCharset);
  }
  profile.policy = *policy;
  for (const auto& spec : options.all("witness")) {
    // <witness-id>:<fault-domain>@<host>:<port>
    const auto at = spec.find('@');
    if (at == std::string::npos) {
      error = "--witness expects id:fault-domain@host:port";
      return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
    }
    const auto left = text::split(spec.substr(0, at), ':');
    if (left.size() != 2) {
      error = "--witness expects id:fault-domain@host:port";
      return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
    }
    auto witness = WitnessId::try_make(left[0]);
    auto fault_domain = FaultDomainId::try_make(left[1]);
    if (!witness.has_value() || !fault_domain.has_value()) {
      error = "invalid witness or fault domain identifier";
      return Status::make(Outcome::Invalid, Reason::IdCharset);
    }
    profile.witnesses.push_back(WitnessSlot{*witness, *fault_domain});
  }
  if (profile.witnesses.empty()) {
    error = "at least one --witness is required";
    return Status::make(Outcome::Invalid, Reason::NoAttestations);
  }
  std::sort(profile.witnesses.begin(), profile.witnesses.end());
  profile.witnesses.erase(std::unique(profile.witnesses.begin(), profile.witnesses.end()),
                          profile.witnesses.end());

  const std::string mode = options.str("quorum", "majority");
  if (mode == "majority") {
    profile.mode = QuorumMode::MajorityDistinctWitnesses;
  } else if (mode == "unanimous") {
    profile.mode = QuorumMode::UnanimousWitnesses;
  } else if (mode.rfind("threshold:", 0) == 0) {
    std::uint64_t value = 0;
    if (!text::parse_u64(mode.substr(10), value).is_ok()) {
      error = "invalid --quorum threshold";
      return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
    }
    profile.mode = QuorumMode::ThresholdDistinctWitnesses;
    profile.threshold = static_cast<std::uint32_t>(value);
  } else {
    error = "unknown --quorum mode";
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  }
  profile.min_fault_domains =
      static_cast<std::uint32_t>(options.number("min-fault-domains", profile.min_fault_domains));
  profile.evidence_horizon_steps = options.number("evidence-horizon", 10000);
  return profile.validate();
}

}  // namespace

int main(int argc, char** argv) {
  cli::Options options;
  std::string error;
  if (!cli::parse(argc, argv, 1, options, error)) return cli::fail(error);

  if (options.has("version")) {
    std::cout << build_description() << "\n";
    return 0;
  }

  RegistryConfig config;
  auto store_id = StoreId::try_make(options.str("store", "fabric-store"));
  auto node_id = NodeId::try_make(options.str("node", "registry-1"));
  if (!store_id.has_value() || !node_id.has_value()) {
    return cli::fail("--store and --node must be valid identifiers");
  }
  config.store_id = *store_id;
  config.node = *node_id;
  config.lease_horizon_steps = Step{options.number("lease-horizon", 100000)};
  config.checkpoint_every_records = options.number("checkpoint-every", 512);

  if (auto st = parse_quorum(options, config.policy.quorum, error); !st.is_ok()) {
    return cli::fail(error.empty() ? sbf::to_string(st) : error);
  }
  // The policy identity and the quorum profile identity are the same policy; the
  // policy must be named or nothing downstream can be validated against it.
  config.policy.policy = config.policy.quorum.policy;
  config.policy.generation = Generation{1};
  config.policy.require_lease_for_exclusive = options.str("require-lease", "false") == "true";
  config.policy.allow_non_overlapping_authority =
      options.str("allow-non-overlap", "true") == "true";

  net::Endpoint endpoint;
  endpoint.host = options.str("host", "127.0.0.1");
  const std::uint64_t port = options.number("port", 0);
  if (port > 65535) return cli::fail("--port out of range");
  endpoint.port = static_cast<std::uint16_t>(port);

  const std::filesystem::path directory = options.str("dir", "sbf-registry-state");

  RegistryService service;
  StoreRecoveryReport report;
  if (auto st = service.open(config, directory, report); !st.is_ok()) {
    return cli::fail("open failed: " + sbf::to_string(st));
  }

  // Domain definitions requested on the command line:
  //   --define <domain>:<node>:<policy>:<extent>[,<extent>...]
  for (const auto& spec : options.all("define")) {
    const auto at = spec.find(':');
    const auto at2 = at == std::string::npos ? std::string::npos : spec.find(':', at + 1);
    const auto at3 = at2 == std::string::npos ? std::string::npos : spec.find(':', at2 + 1);
    if (at == std::string::npos || at2 == std::string::npos || at3 == std::string::npos) {
      return cli::fail("--define expects domain:node:policy:extents");
    }
    DomainDefinition definition;
    auto domain = DomainId::try_make(spec.substr(0, at));
    auto node = NodeId::try_make(spec.substr(at + 1, at2 - at - 1));
    auto policy = PolicyId::try_make(spec.substr(at2 + 1, at3 - at2 - 1));
    if (!domain.has_value() || !node.has_value() || !policy.has_value()) {
      return cli::fail("--define contains an invalid identifier");
    }
    definition.domain = *domain;
    definition.node = *node;
    definition.policy = *policy;
    if (auto st = Scope::parse(spec.substr(at3 + 1), definition.scope); !st.is_ok()) {
      return cli::fail("--define scope: " + sbf::to_string(st));
    }
    if (auto st = service.define_domain(definition); !st.is_ok()) {
      return cli::fail("--define failed: " + sbf::to_string(st));
    }
  }

  if (auto st = service.bind(endpoint); !st.is_ok()) {
    return cli::fail("bind failed: " + sbf::to_string(st));
  }
  service.start();
  if (!cli::announce(options.str("announce"), service.endpoint().to_string(), current_pid())) {
    return cli::fail("could not write --announce file");
  }
  std::cout << "sbf-registry ready endpoint=" << service.endpoint().to_string()
            << " store=" << config.store_id.view()
            << " boot=" << service.state().boot().boot.value()
            << " incarnation=" << service.state().boot().incarnation.value()
            << " snapshot_loaded=" << (report.snapshot_loaded ? 1 : 0)
            << " torn_tail=" << (report.torn_tail_recovered ? 1 : 0) << std::endl;

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  while (g_stop == 0 && service.phase() != RegistryPhase::Stopped) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  service.stop();
  service.join();
  std::cout << "sbf-registry stopped handled=" << service.handled_requests()
            << " rejected=" << service.rejected_requests()
            << " poison=" << service.poison_events() << std::endl;
  return 0;
}
