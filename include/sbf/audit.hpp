#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sbf/fabric_store.hpp"
#include "sbf/registry.hpp"

namespace sbf {

struct AuditFinding {
  Outcome outcome = Outcome::Ok;
  Reason reason = Reason::None;
  std::string subject;
  std::string detail;
};

struct AuditReport {
  Status status;
  Outcome outcome = Outcome::Unknown;
  std::uint64_t checks_run = 0;
  std::uint64_t findings_total = 0;
  std::vector<AuditFinding> findings;   // bounded
  std::uint64_t findings_dropped = 0;

  // Effect-history accounting.
  std::uint64_t mutations = 0;
  std::uint64_t ownership_transitions = 0;
  std::uint64_t distinct_owners = 0;
  std::uint64_t token_regressions = 0;
  std::uint64_t foreign_owner_appends = 0;
  std::uint64_t fence_escapes = 0;
  std::uint64_t sequence_gaps = 0;
  bool mutually_exclusive_effect_history = false;
  Digest256 head_digest;

  // Lineage accounting.
  std::uint64_t grants = 0;
  std::uint64_t open_grants = 0;
  std::uint64_t epoch_regressions = 0;
  std::uint64_t duplicate_exclusive_grants = 0;
  std::uint64_t uninterruptible_grants = 0;
};

// Checks the durable fabric history for the product-defining invariant:
// no two authority vectors are ever simultaneously responsible for an
// overlapping exclusive extent, and no fenced token ever appears after a higher
// token for the same extent.
AuditReport audit_fabric_history(const std::vector<MutationRecord>& records);

// Checks the durable registry state: epoch monotonicity, grant lifecycle,
// fence/token monotonicity, and the absence of pre-restart dynamic authority.
AuditReport audit_registry_state(const RegistryState& state);

// Compares two authority vectors for the total, deterministic succession order
// used throughout the runtime: (epoch, fence token, grant id).
bool succession_precedes(const MutationRecord& earlier, const MutationRecord& later) noexcept;

}  // namespace sbf
