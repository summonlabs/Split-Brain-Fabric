// sbf-coordinator: a fabric control-domain coordinator.
//
// A coordinator never self-authorizes. It acquires an epoch and a fence token
// from the registry, collects quorum evidence from real witnesses, asks the
// registry to decide, and only then attempts a mutation - which the registry's
// fenced effect boundary may still refuse. When it cannot prove authority it
// performs no mutation at all.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "cli_support.hpp"
#include "sbf/coordinator.hpp"
#include "sbf/text.hpp"
#include "sbf/version.hpp"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace {

std::uint64_t current_pid() {
#ifdef _WIN32
  return static_cast<std::uint64_t>(_getpid());
#else
  return static_cast<std::uint64_t>(getpid());
#endif
}

}  // namespace

int main(int argc, char** argv) {
  using namespace sbf;
  cli::Options options;
  std::string error;
  if (!cli::parse(argc, argv, 1, options, error)) return cli::fail(error);

  if (options.has("version")) {
    std::cout << build_description() << "\n";
    return 0;
  }

  CoordinatorConfig config;
  auto node = NodeId::try_make(options.str("node", "coordinator-1"));
  auto domain = DomainId::try_make(options.str("domain", "domain-a"));
  if (!node.has_value() || !domain.has_value()) {
    return cli::fail("--node and --domain must be valid identifiers");
  }
  config.node = *node;
  config.domain = *domain;
  if (auto st = Scope::parse(options.str("scope", "port-1"), config.scope); !st.is_ok()) {
    return cli::fail("--scope: " + sbf::to_string(st));
  }

  net::Endpoint registry;
  if (auto st = net::Endpoint::parse(options.str("registry", "127.0.0.1:9000"), registry);
      !st.is_ok()) {
    return cli::fail("--registry expects host:port");
  }
  config.registry = registry;
  config.require_quorum = options.str("require-quorum", "true") == "true";

  std::uint32_t index = 0;
  for (const auto& spec : options.all("witness-target")) {
    // <witness-id>:<fault-domain>@<host>:<port>
    const auto at = spec.find('@');
    if (at == std::string::npos) return cli::fail("--witness-target expects id:fd@host:port");
    const auto left = text::split(spec.substr(0, at), ':');
    net::Endpoint endpoint;
    if (left.size() != 2 || !net::Endpoint::parse(spec.substr(at + 1), endpoint).is_ok()) {
      return cli::fail("--witness-target expects id:fd@host:port");
    }
    auto witness_id = WitnessId::try_make(left[0]);
    auto fault_domain = FaultDomainId::try_make(left[1]);
    if (!witness_id.has_value() || !fault_domain.has_value()) {
      return cli::fail("--witness-target contains an invalid identifier");
    }
    config.witnesses.emplace_back(*witness_id, *fault_domain, endpoint);
    ++index;
  }

  const std::uint64_t operations = options.number("ops", 1);
  if (operations > limits::kMaxBenchmarkOperations) return cli::fail("--ops out of range");
  const std::string operation = options.str("operation", "switch-port");

  Coordinator coordinator(std::move(config));
  HelloRequest hello;
  hello.node = coordinator.config().node;
  if (auto st = coordinator.connect(hello); !st.is_ok()) {
    return cli::fail("connect failed: " + sbf::to_string(st));
  }

  if (!cli::announce(options.str("announce"),
                     coordinator.registry().binding().session.is_set() ? "connected" : "none",
                     current_pid())) {
    return cli::fail("could not write --announce file");
  }

  CoordinatorReport report;
  const Status mutated = coordinator.mutate(operation, operations, report);

  std::cout << "coordinator node=" << coordinator.config().node.view()
            << " domain=" << coordinator.config().domain.view()
            << " incarnation=" << coordinator.incarnation().value()
            << " status=" << sbf::to_string(mutated)
            << " attempted=" << report.attempted << " applied=" << report.applied
            << " refused=" << report.refused << " fenced=" << report.fenced
            << " conflict=" << report.conflicts << " unknown=" << report.unknown
            << " unreachable=" << report.unreachable
            << " final_epoch=" << report.final_epoch.value()
            << " final_token=" << report.final_token.value()
            << " final_grant=" << report.final_grant.value() << std::endl;

  if (options.str("release", "false") == "true") {
    coordinator.release(Reason::None);
  }
  coordinator.close();
  // Exit code 0 means the run completed; the reported counters say what
  // happened. A refusal is a legitimate, expected outcome.
  return 0;
}
