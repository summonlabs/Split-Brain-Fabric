#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "sbf/arbiter.hpp"
#include "sbf/registry.hpp"
#include "sbf/witness.hpp"

namespace sbf {

struct CoordinatorConfig {
  NodeId node;
  DomainId domain;
  Scope scope;
  net::Endpoint registry;
  std::vector<WitnessClient> witnesses;  // owned by value: one connection each
  Generation policy_generation{1};
  std::uint64_t operation_budget = 0;    // 0 = unbounded
  bool verify_effect = true;             // read the effect back before reporting success
  bool require_quorum = true;
};

// What actually happened to one attempted mutation. Acknowledgement is not
// application: only Applied means the effect was durably committed and - when
// verify_effect is on - read back from the durable log.
enum class MutationOutcome : std::uint8_t {
  Applied = 0,
  AcknowledgedNotVerified = 1,
  Refused = 2,
  Fenced = 3,
  Unknown = 4,
  Conflict = 5,
  Invalid = 6,
  Unreachable = 7,
  Interrupted = 8,
};

std::string_view to_string(MutationOutcome outcome) noexcept;

struct MutationAttempt {
  Sequence attempt;
  MutationOutcome outcome = MutationOutcome::Unknown;
  Status status;
  Epoch epoch;
  FenceToken fence_token;
  Sequence store_sequence;
  Digest256 effect_digest;
  std::string operation;
};

struct CoordinatorReport {
  std::uint64_t attempted = 0;
  std::uint64_t applied = 0;
  std::uint64_t refused = 0;
  std::uint64_t fenced = 0;
  std::uint64_t unreachable = 0;
  std::uint64_t unknown = 0;
  std::uint64_t acknowledged_not_verified = 0;
  std::uint64_t conflicts = 0;
  std::vector<MutationAttempt> attempts;   // bounded by the configured budget
  Epoch final_epoch;
  FenceToken final_token;
  GrantId final_grant;
  bool holds_authority = false;
};

// A fabric control-domain coordinator. It never self-authorizes: without a
// positive Authoritative decision from the registry it performs no mutation at
// all, and it fails closed when the registry or quorum is unreachable.
class Coordinator {
 public:
  explicit Coordinator(CoordinatorConfig config);
  ~Coordinator();
  Coordinator(const Coordinator&) = delete;
  Coordinator& operator=(const Coordinator&) = delete;

  Status connect(const HelloRequest& hello);

  // Requests (or reuses) an epoch and fence token for this incarnation.
  Status acquire_authority(std::uint64_t requested_lease_steps, Epoch& epoch_out,
                           FenceToken& token_out, GrantId& grant_out);

  Status collect_evidence(Epoch epoch, IncarnationId incarnation, FenceToken token,
                          EvidenceBundle& bundle);
  Status evaluate(Epoch epoch, IncarnationId incarnation, FenceToken token,
                  AuthorityMode mode, const EvidenceBundle& bundle,
                  AuthorityDecision& decision);
  Status mutate(std::string_view operation, std::uint64_t count, CoordinatorReport& report);

  void close();
  void release(Reason cause);

  const CoordinatorConfig& config() const noexcept { return config_; }
  const CoordinatorReport& report() const noexcept { return report_; }
  Epoch epoch() const noexcept { return epoch_; }
  FenceToken token() const noexcept { return token_; }
  GrantId grant() const noexcept { return grant_; }
  IncarnationId incarnation() const noexcept { return incarnation_; }
  bool connected() const noexcept { return client_.connected(); }
  RegistryClient& registry() noexcept { return client_; }

 private:
  CoordinatorConfig config_;
  RegistryClient client_;
  IncarnationId incarnation_;
  BootId boot_;
  Epoch epoch_;
  FenceToken token_;
  GrantId grant_;
  Sequence attempt_sequence_;
  PolicyId policy_;
  Generation policy_generation_;
  Step allocation_step_;
  CoordinatorReport report_;
  bool authority_ = false;
};

}  // namespace sbf
