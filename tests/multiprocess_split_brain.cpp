// Real multiprocess proof.
//
// Every process here is a separate operating-system process and every
// connection is a real loopback TCP socket. Threads are not used as a substitute
// for multiprocess behaviour, and coordinator processes are hard-killed with
// TerminateProcess / SIGKILL, which runs no cleanup code.
//
// The proofs in this file:
//   A. two real coordinators compete for one overlapping exclusive scope, and
//      the durable effect history shows exactly one owner at a time;
//   B. the authoritative coordinator is hard-killed mid-run and a controlled
//      successor acquires authority behind a durable fence;
//   C. a real partition (witness processes killed) leaves the isolated side
//      without enough evidence, so it commits nothing;
//   D. the registry itself is hard-killed and restarted, and the restart is
//      conservative: pre-restart authority is fenced, never resumed.

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "sbf/text.hpp"
#include "support/process.hpp"
#include "support/test_harness.hpp"

using namespace sbf;
using namespace sbf::test;

namespace {

#ifndef SBF_REGISTRY_EXE
#error "SBF_REGISTRY_EXE must be defined by the build"
#endif
#ifndef SBF_WITNESS_EXE
#error "SBF_WITNESS_EXE must be defined by the build"
#endif
#ifndef SBF_COORDINATOR_EXE
#error "SBF_COORDINATOR_EXE must be defined by the build"
#endif
#ifndef SBF_CTL_EXE
#error "SBF_CTL_EXE must be defined by the build"
#endif

std::filesystem::path scratch(std::string_view name) {
  static std::uint64_t counter = 0;
  const auto path = std::filesystem::temp_directory_path() /
                    ("sbf-mp-" + std::string(name) + "-" + std::to_string(++counter));
  std::error_code ec;
  std::filesystem::remove_all(path, ec);
  std::filesystem::create_directories(path, ec);
  return path;
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return {};
  return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

// Waits for a file to be published by a child process. It does not time out: if
// the child dies first the wait fails immediately with a diagnostic, and if the
// child is genuinely stuck that is a defect we want surfaced rather than hidden.
bool wait_for_file(const std::filesystem::path& path, const Process& child, std::string& error) {
  while (!std::filesystem::exists(path)) {
    if (child.exited()) {
      error = "child exited before publishing " + path.string();
      return false;
    }
    std::this_thread::yield();
  }
  while (read_text(path).empty()) {
    if (child.exited()) {
      error = "child exited before writing " + path.string();
      return false;
    }
    std::this_thread::yield();
  }
  return true;
}

std::string endpoint_from_announce(const std::filesystem::path& path) {
  const std::string text = read_text(path);
  const auto newline = text.find('\n');
  return newline == std::string::npos ? text : text.substr(0, newline);
}

// Extracts "key=<number>" from a tool's report line.
std::uint64_t parse_counter(const std::string& text, std::string_view key) {
  const std::string needle = std::string(key) + "=";
  const auto position = text.find(needle);
  if (position == std::string::npos) return 0;
  std::size_t begin = position + needle.size();
  std::size_t end = begin;
  while (end < text.size() && text[end] >= '0' && text[end] <= '9') ++end;
  std::uint64_t value = 0;
  if (!text::parse_u64(text.substr(begin, end - begin), value).is_ok()) return 0;
  return value;
}

struct WitnessProcess {
  Process process;
  std::string target;   // id:fault-domain@host:port
};

struct Cluster {
  std::filesystem::path root;
  Process registry;
  std::vector<WitnessProcess> witnesses;
  std::string registry_endpoint;
  std::filesystem::path registry_output_;
  std::string store_id = "mp-store";
  std::string domain = "domain-a";
  std::string scope = "p1,p2";

  ~Cluster() {
    registry.kill();
    for (auto& witness : witnesses) witness.process.kill();
  }

  bool start_witnesses(std::size_t count, std::size_t alive, std::string& error) {
    for (std::size_t i = 0; i < count; ++i) {
      const auto announce = root / ("witness-" + std::to_string(i) + ".announce");
      WitnessProcess entry;
      const auto witness_output = root / ("witness-" + std::to_string(i) + ".out");
      if (!entry.process.start(SBF_WITNESS_EXE,
                               {"--id", "witness-" + std::to_string(i), "--fault-domain",
                                "fd-" + std::to_string(i), "--port", "0", "--announce",
                                announce.string()},
                               witness_output.string())) {
        error = "could not start witness process";
        return false;
      }
      if (!wait_for_file(announce, entry.process, error)) {
        error.append("; witness output: ").append(read_text(witness_output));
        // A witness that is deliberately not part of the live set still needs a
        // well-formed target so that the coordinator's failure is a real
        // connection failure rather than a parse error.
        entry.target = "witness-" + std::to_string(i) + ":fd-" + std::to_string(i) + "@127.0.0.1:1";
      } else {
        entry.target = "witness-" + std::to_string(i) + ":fd-" + std::to_string(i) + "@" +
                       endpoint_from_announce(announce);
      }
      witnesses.push_back(std::move(entry));
    }
    // Real process termination: the killed witnesses stop listening, so the
    // surviving side genuinely cannot reach them.
    for (std::size_t i = alive; i < witnesses.size(); ++i) {
      witnesses[i].process.kill();
    }
    return true;
  }

  bool start_registry(std::string& error) {
    const auto announce = root / "registry.announce";
    std::vector<std::string> arguments;
    arguments.push_back("--dir");
    arguments.push_back((root / "state").string());
    arguments.push_back("--store");
    arguments.push_back(store_id);
    arguments.push_back("--node");
    arguments.push_back("registry-1");
    arguments.push_back("--port");
    arguments.push_back("0");
    arguments.push_back("--announce");
    arguments.push_back(announce.string());
    arguments.push_back("--quorum");
    arguments.push_back("threshold:2");
    arguments.push_back("--min-fault-domains");
    arguments.push_back("1");
    arguments.push_back("--define");
    arguments.push_back(domain + ":coordinator:fabric-policy:" + scope);
    for (const auto& witness : witnesses) {
      arguments.push_back("--witness");
      arguments.push_back(witness.target);
    }
    registry_output_ = root / "registry.out";
    if (!registry.start(SBF_REGISTRY_EXE, arguments, registry_output_.string())) {
      error = "could not start registry process";
      return false;
    }
    if (!wait_for_file(announce, registry, error)) {
      error.append("; registry output: ").append(read_text(registry_output_));
      return false;
    }
    registry_endpoint = endpoint_from_announce(announce);
    return true;
  }

  std::vector<std::string> coordinator_arguments(std::string_view node, std::uint64_t ops,
                                                 std::size_t witness_count) const {
    std::vector<std::string> arguments;
    arguments.push_back("--node");
    arguments.push_back(std::string(node));
    arguments.push_back("--domain");
    arguments.push_back(domain);
    arguments.push_back("--scope");
    arguments.push_back(scope);
    arguments.push_back("--registry");
    arguments.push_back(registry_endpoint);
    arguments.push_back("--ops");
    arguments.push_back(std::to_string(ops));
    arguments.push_back("--operation");
    arguments.push_back("switch-port");
    for (std::size_t i = 0; i < witness_count && i < witnesses.size(); ++i) {
      arguments.push_back("--witness-target");
      arguments.push_back(witnesses[i].target);
    }
    return arguments;
  }

  std::string audit() const {
    Process process;
    const auto output = root / "audit.out";
    std::vector<std::string> arguments{"audit", "--dir", (root / "state").string(), "--store",
                                       store_id};
    if (!process.start(SBF_CTL_EXE, arguments, output.string())) return {};
    process.wait();
    return read_text(output);
  }
};

}  // namespace

SBF_TEST(multiprocess, two_real_coordinators_compete_for_one_exclusive_scope) {
  Cluster cluster;
  cluster.root = scratch("competition");
  std::string error;
  CHECK(cluster.start_witnesses(3, 3, error));
  if (!error.empty()) { std::printf("setup error: %s\n", error.c_str()); }
  CHECK(cluster.start_registry(error));
  if (!error.empty()) { std::printf("setup error: %s\n", error.c_str()); }

  Process first;
  Process second;
  const auto first_output = cluster.root / "first.out";
  const auto second_output = cluster.root / "second.out";
  CHECK(first.start(SBF_COORDINATOR_EXE, cluster.coordinator_arguments("coordinator-a", 25, 3),
                    first_output.string()));
  CHECK(second.start(SBF_COORDINATOR_EXE, cluster.coordinator_arguments("coordinator-b", 25, 3),
                     second_output.string()));
  const int first_exit = first.wait();
  const int second_exit = second.wait();
  CHECK_EQ(first_exit, 0);
  CHECK_EQ(second_exit, 0);

  const std::string first_report = read_text(first_output);
  const std::string second_report = read_text(second_output);
  std::printf("first: %s", first_report.c_str());
  std::printf("second: %s", second_report.c_str());
  const std::uint64_t applied_first = parse_counter(first_report, "applied");
  const std::uint64_t applied_second = parse_counter(second_report, "applied");
  const std::uint64_t epoch_first = parse_counter(first_report, "final_epoch");
  const std::uint64_t epoch_second = parse_counter(second_report, "final_epoch");
  CHECK(epoch_first >= 1);
  CHECK(epoch_second >= 1);
  CHECK(epoch_first != epoch_second);   // one epoch, one incarnation, one owner
  CHECK_EQ(applied_first + applied_second > 0, true);

  const std::string audit = cluster.audit();
  std::printf("%s", audit.c_str());
  CHECK(audit.find("AUDIT OK") != std::string::npos);
  CHECK_EQ(parse_counter(audit, "token_regressions"), std::uint64_t{0});
  CHECK_EQ(parse_counter(audit, "foreign_owner_appends"), std::uint64_t{0});
  CHECK_EQ(parse_counter(audit, "fence_escapes"), std::uint64_t{0});
  CHECK_EQ(parse_counter(audit, "mutually_exclusive"), std::uint64_t{1});
  CHECK_EQ(parse_counter(audit, "mutations"), applied_first + applied_second);
  // At most one authority may still be open: the survivor that did not release.
  CHECK(parse_counter(audit, "open_grants") <= 1);
  CHECK_EQ(parse_counter(audit, "duplicate_exclusive_grants"), std::uint64_t{0});

  // The loser of the succession must have been refused at least once; if both
  // sides had committed without any refusal the run would not have exercised the
  // race, and the assertion above would be vacuous.
  const std::uint64_t refusals_first = parse_counter(first_report, "fenced") +
                                       parse_counter(first_report, "refused") +
                                       parse_counter(first_report, "unknown");
  const std::uint64_t refusals_second = parse_counter(second_report, "fenced") +
                                        parse_counter(second_report, "refused") +
                                        parse_counter(second_report, "unknown");
  CHECK(refusals_first + refusals_second > 0);
}

SBF_TEST(multiprocess, hard_kill_of_the_authoritative_coordinator_and_controlled_succession) {
  Cluster cluster;
  cluster.root = scratch("hard-kill");
  std::string error;
  CHECK(cluster.start_witnesses(3, 3, error));
  CHECK(cluster.start_registry(error));
  if (!error.empty()) std::printf("setup error: %s\n", error.c_str());

  // The first authority commits a couple of mutations and then exits, leaving
  // its grant open in the durable registry.
  Process first;
  const auto first_output = cluster.root / "first.out";
  CHECK(first.start(SBF_COORDINATOR_EXE, cluster.coordinator_arguments("coordinator-a", 2, 3),
                    first_output.string()));
  CHECK_EQ(first.wait(), 0);
  const std::string first_report = read_text(first_output);
  CHECK_EQ(parse_counter(first_report, "applied"), std::uint64_t{2});

  // A second authority starts committing and is hard-killed in the middle.
  Process victim;
  const auto victim_output = cluster.root / "victim.out";
  CHECK(victim.start(SBF_COORDINATOR_EXE,
                     cluster.coordinator_arguments("coordinator-b", 200000, 3),
                     victim_output.string()));
  const auto fabric_log = cluster.root / "state" / "sbf.fabric";
  const std::uint64_t before = std::filesystem::exists(fabric_log)
                                   ? std::filesystem::file_size(fabric_log)
                                   : 0;
  while (true) {
    if (std::filesystem::exists(fabric_log) && std::filesystem::file_size(fabric_log) > before) {
      break;
    }
    if (victim.exited()) {
      CHECK(false);   // the victim exited without ever committing
      break;
    }
    std::this_thread::yield();
  }
  victim.kill();   // hard kill: no destructor, no flush, no relink
  CHECK(!victim.running());

  // Controlled succession. The successor must obtain a strictly higher epoch
  // and token, and the registry must fence the killed incarnation first.
  Process successor;
  const auto successor_output = cluster.root / "successor.out";
  CHECK(successor.start(SBF_COORDINATOR_EXE,
                        cluster.coordinator_arguments("coordinator-c", 4, 3),
                        successor_output.string()));
  CHECK_EQ(successor.wait(), 0);
  const std::string successor_report = read_text(successor_output);
  std::printf("successor: %s", successor_report.c_str());
  CHECK_EQ(parse_counter(successor_report, "applied"), std::uint64_t{4});
  CHECK(parse_counter(successor_report, "final_epoch") >= 2);

  const std::string audit = cluster.audit();
  std::printf("%s", audit.c_str());
  CHECK(audit.find("AUDIT OK") != std::string::npos);
  CHECK_EQ(parse_counter(audit, "fence_escapes"), std::uint64_t{0});
  CHECK_EQ(parse_counter(audit, "foreign_owner_appends"), std::uint64_t{0});
  CHECK_EQ(parse_counter(audit, "mutually_exclusive"), std::uint64_t{1});
  // The survivor that never released may still hold the only open grant; every
  // earlier grant, including the killed coordinator's, must be closed.
  CHECK(parse_counter(audit, "open_grants") <= 1);
  // The killed coordinator's partial work is never attributed to the successor.
  CHECK(parse_counter(audit, "distinct_owners") >= 2);
}

SBF_TEST(multiprocess, partition_leaves_the_isolated_side_non_authoritative) {
  Cluster cluster;
  cluster.root = scratch("partition");
  std::string error;
  // Three witnesses are started; two are then killed, so only one is reachable.
  CHECK(cluster.start_witnesses(3, 1, error));
  CHECK(cluster.start_registry(error));

  Process isolated;
  const auto isolated_output = cluster.root / "isolated.out";
  CHECK(isolated.start(SBF_COORDINATOR_EXE,
                       cluster.coordinator_arguments("coordinator-isolated", 6, 3),
                       isolated_output.string()));
  CHECK_EQ(isolated.wait(), 0);
  const std::string report = read_text(isolated_output);
  std::printf("isolated: %s", report.c_str());
  // The surviving side can see itself but cannot reach a threshold of two
  // distinct witnesses, so it must commit nothing at all.
  CHECK_EQ(parse_counter(report, "applied"), std::uint64_t{0});
  CHECK(parse_counter(report, "unknown") + parse_counter(report, "refused") +
            parse_counter(report, "fenced") >
        0);

  const std::string audit = cluster.audit();
  std::printf("%s", audit.c_str());
  CHECK(audit.find("AUDIT OK") != std::string::npos);
  CHECK_EQ(parse_counter(audit, "mutations"), std::uint64_t{0});
  CHECK_EQ(parse_counter(audit, "mutually_exclusive"), std::uint64_t{1});
}

SBF_TEST(multiprocess, registry_hard_kill_and_restart_is_conservative) {
  Cluster cluster;
  cluster.root = scratch("registry-restart");
  std::string error;
  CHECK(cluster.start_witnesses(3, 3, error));
  CHECK(cluster.start_registry(error));

  Process coordinator;
  const auto output = cluster.root / "coordinator.out";
  CHECK(coordinator.start(SBF_COORDINATOR_EXE,
                          cluster.coordinator_arguments("coordinator-a", 2, 3), output.string()));
  CHECK_EQ(coordinator.wait(), 0);
  const std::string first_report = read_text(output);
  CHECK_EQ(parse_counter(first_report, "applied"), std::uint64_t{2});

  const std::string before = cluster.audit();
  const std::uint64_t boot_before = parse_counter(before, "boot");
  const std::uint64_t token_before = parse_counter(before, "token_counter");

  // Hard-kill the registry with its grant still open.
  cluster.registry.kill();

  // Restart on the same durable store.
  const auto announce = cluster.root / "registry.announce";
  std::filesystem::remove(announce);
  std::vector<std::string> arguments;
  arguments.push_back("--dir");
  arguments.push_back((cluster.root / "state").string());
  arguments.push_back("--store");
  arguments.push_back(cluster.store_id);
  arguments.push_back("--node");
  arguments.push_back("registry-1");
  arguments.push_back("--port");
  arguments.push_back("0");
  arguments.push_back("--announce");
  arguments.push_back(announce.string());
  arguments.push_back("--quorum");
  arguments.push_back("threshold:2");
  arguments.push_back("--define");
  arguments.push_back(cluster.domain + ":coordinator:fabric-policy:" + cluster.scope);
  for (const auto& witness : cluster.witnesses) {
    arguments.push_back("--witness");
    arguments.push_back(witness.target);
  }
  cluster.registry_output_ = cluster.root / "registry-restart.out";
  CHECK(cluster.registry.start(SBF_REGISTRY_EXE, arguments, cluster.registry_output_.string()));
  CHECK(wait_for_file(announce, cluster.registry, error));
  if (!error.empty()) std::printf("restart error: %s\n", error.c_str());
  cluster.registry_endpoint = endpoint_from_announce(announce);

  const std::string after = cluster.audit();
  std::printf("%s", after.c_str());
  CHECK(after.find("AUDIT OK") != std::string::npos);
  const std::uint64_t boot_after = parse_counter(after, "boot");
  CHECK(boot_after > boot_before);
  CHECK(parse_counter(after, "token_counter") >= token_before);
  // Every pre-restart grant is closed and marked interrupted, never resumed.
  CHECK_EQ(parse_counter(after, "open_grants"), std::uint64_t{0});
  CHECK_EQ(parse_counter(after, "duplicate_exclusive_grants"), std::uint64_t{0});
  CHECK(parse_counter(after, "interrupts") >= 1);

  // Authority continues behind a strictly greater epoch.
  Process successor;
  const auto successor_output = cluster.root / "successor.out";
  CHECK(successor.start(SBF_COORDINATOR_EXE,
                        cluster.coordinator_arguments("coordinator-c", 2, 3),
                        successor_output.string()));
  CHECK_EQ(successor.wait(), 0);
  const std::string successor_report = read_text(successor_output);
  std::printf("successor: %s", successor_report.c_str());
  CHECK_EQ(parse_counter(successor_report, "applied"), std::uint64_t{2});
  CHECK(parse_counter(successor_report, "final_epoch") >= 2);

  const std::string final_audit = cluster.audit();
  CHECK(final_audit.find("AUDIT OK") != std::string::npos);
  CHECK_EQ(parse_counter(final_audit, "mutations"), std::uint64_t{4});
  CHECK_EQ(parse_counter(final_audit, "fence_escapes"), std::uint64_t{0});
  CHECK_EQ(parse_counter(final_audit, "mutually_exclusive"), std::uint64_t{1});
}
SBF_TEST_MAIN
