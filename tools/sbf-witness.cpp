// sbf-witness: one quorum witness.
//
// A witness attests at most one incarnation per (domain, scope, epoch). That
// refusal is what makes two coordinators mutually exclusive under partition:
// whichever side cannot assemble the required distinct witnesses cannot become
// authoritative, and an epoch can only advance through the durable registry,
// which fences the previous owner first.

#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#include "cli_support.hpp"
#include "sbf/text.hpp"
#include "sbf/version.hpp"
#include "sbf/witness.hpp"

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

  auto witness_id = WitnessId::try_make(options.str("id", "witness-1"));
  auto fault_domain = FaultDomainId::try_make(options.str("fault-domain", "fd-1"));
  if (!witness_id.has_value() || !fault_domain.has_value()) {
    return cli::fail("--id and --fault-domain must be valid identifiers");
  }

  WitnessConfig config;
  config.witness = *witness_id;
  config.fault_domain = *fault_domain;
  config.attestation_horizon_steps = options.number("horizon", 100000);
  config.max_subjects = static_cast<std::uint32_t>(options.number("max-subjects", 512));

  net::Endpoint endpoint;
  endpoint.host = options.str("host", "127.0.0.1");
  const std::uint64_t port = options.number("port", 0);
  if (port > 65535) return cli::fail("--port out of range");
  endpoint.port = static_cast<std::uint16_t>(port);

  WitnessService service;
  if (auto st = service.configure(config); !st.is_ok()) {
    return cli::fail("configure failed: " + sbf::to_string(st));
  }
  if (auto st = service.bind(endpoint); !st.is_ok()) {
    return cli::fail("bind failed: " + sbf::to_string(st));
  }
  service.start();
  if (!cli::announce(options.str("announce"), service.endpoint().to_string(), current_pid())) {
    return cli::fail("could not write --announce file");
  }
  std::cout << "sbf-witness ready witness=" << config.witness.view()
            << " fault_domain=" << config.fault_domain.view()
            << " endpoint=" << service.endpoint().to_string() << std::endl;

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  while (g_stop == 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  service.stop();
  service.join();
  std::cout << "sbf-witness stopped issued=" << service.attestations_issued()
            << " refusals_conflict=" << service.refusals_conflict()
            << " refusals_replay=" << service.refusals_replay()
            << " refusals_regression=" << service.refusals_regression() << std::endl;
  return 0;
}
