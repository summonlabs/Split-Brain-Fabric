#pragma once

// Minimal, dependency-free test harness.
//
// Deliberate design choices:
//   * no timeouts anywhere - a hanging test is a defect to be diagnosed, not
//     hidden behind a watchdog;
//   * every check is recorded with file and line so failures are actionable;
//   * suites print their deterministic seed so a failing property case can be
//     reproduced exactly.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <string>
#include <vector>

#include "sbf/status.hpp"

namespace sbf::test {

struct Case {
  const char* suite;
  const char* name;
  void (*fn)();
};

inline std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}

inline std::uint64_t& check_count() {
  static std::uint64_t count = 0;
  return count;
}

inline std::uint64_t& failure_count() {
  static std::uint64_t count = 0;
  return count;
}

struct Registrar {
  Registrar(const char* suite, const char* name, void (*fn)()) {
    registry().push_back(Case{suite, name, fn});
  }
};

inline void report_failure(const char* file, int line, const std::string& message) {
  ++failure_count();
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
  std::fflush(stderr);
}

inline void check(bool condition, const char* expression, const char* file, int line) {
  ++check_count();
  if (!condition) report_failure(file, line, std::string("expected: ") + expression);
}

template <class A, class B>
void check_eq(const A& left, const B& right, const char* expression, const char* file, int line) {
  ++check_count();
  if (!(left == right)) report_failure(file, line, std::string("expected equal: ") + expression);
}

inline void check_status(const sbf::Status& status, const char* expression, const char* file,
                         int line) {
  ++check_count();
  if (!status.is_ok()) {
    report_failure(file, line,
                   std::string("expected ok: ") + expression + " got " + sbf::to_string(status));
  }
}

inline void check_failed_status(const sbf::Status& status, sbf::Outcome expected,
                                const char* expression, const char* file, int line) {
  ++check_count();
  if (status.is_ok() || status.outcome != expected) {
    report_failure(file, line, std::string("expected ") + std::string(sbf::to_string(expected)) +
                                  " from " + expression + " got " + sbf::to_string(status));
  }
}

// Deterministic xorshift64* generator. Every property suite prints its seed and
// accepts --seed to reproduce a run exactly.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}

  std::uint64_t next() {
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return state_;
  }

  std::uint64_t bounded(std::uint64_t limit) { return limit == 0 ? 0 : next() % limit; }

  bool coin() { return (next() & 1u) != 0; }

  std::uint64_t state() const { return state_; }

 private:
  std::uint64_t state_;
};

inline int run_all(int argc, char** argv) {
  std::uint64_t only_seed = 0;
  std::string filter;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--seed" && i + 1 < argc) {
      only_seed = std::strtoull(argv[++i], nullptr, 10);
    } else if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    }
  }
  (void)only_seed;

  std::uint64_t executed = 0;
  for (const auto& test_case : registry()) {
    const std::string full = std::string(test_case.suite) + "." + test_case.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) continue;
    ++executed;
    try {
      test_case.fn();
    } catch (const std::exception& error) {
      report_failure(test_case.name, 0, std::string("uncaught exception: ") + error.what());
    } catch (...) {
      report_failure(test_case.name, 0, "uncaught non-standard exception");
    }
  }
  std::printf("cases=%llu checks=%llu failures=%llu\n",
              static_cast<unsigned long long>(executed),
              static_cast<unsigned long long>(check_count()),
              static_cast<unsigned long long>(failure_count()));
  std::fflush(stdout);
  return failure_count() == 0 ? 0 : 1;
}

}  // namespace sbf::test

#define SBF_TEST(suite, name)                                                            \
  static void sbf_test_##suite##_##name();                                               \
  static ::sbf::test::Registrar sbf_registrar_##suite##_##name(#suite, #name,            \
                                                              &sbf_test_##suite##_##name); \
  static void sbf_test_##suite##_##name()

#define CHECK(condition) ::sbf::test::check((condition), #condition, __FILE__, __LINE__)
#define CHECK_EQ(left, right) \
  ::sbf::test::check_eq((left), (right), #left " == " #right, __FILE__, __LINE__)
#define CHECK_OK(expression) ::sbf::test::check_status((expression), #expression, __FILE__, __LINE__)
#define CHECK_OUTCOME(expression, outcome) \
  ::sbf::test::check_failed_status((expression), (outcome), #expression, __FILE__, __LINE__)
#define SBF_TEST_MAIN int main(int argc, char** argv) { return ::sbf::test::run_all(argc, argv); }
