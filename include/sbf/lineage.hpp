#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "sbf/digest.hpp"
#include "sbf/ids.hpp"
#include "sbf/limits.hpp"
#include "sbf/scope.hpp"
#include "sbf/status.hpp"

namespace sbf {

// Lifecycle of an authority grant. A grant is the durable record that an epoch
// was opened for an incarnation; every mutation must fall inside an open grant.
enum class GrantState : std::uint8_t {
  Open = 0,
  Closed = 1,
  Fenced = 2,
  Interrupted = 3,
};

std::string_view to_string(GrantState state) noexcept;

struct EpochGrant {
  GrantId id;
  DomainId domain;
  Digest256 scope;      // identity of the extent set
  Scope extents;        // the extent set itself, so overlap is decidable offline
  Sequence attempt;     // caller attempt id: makes allocation idempotent
  Epoch epoch;
  IncarnationId incarnation;
  BootId boot;
  FenceToken fence_token;
  Step opened_at;
  Step closed_at;            // 0 while open
  GrantState state = GrantState::Open;
  Sequence registry_sequence = Sequence{1};
  Generation lineage_generation;
  Generation policy_generation;
  Generation evidence_generation;
  Reason close_reason = Reason::None;
};

// A process incarnation. Boot ids and incarnation ids are allocated from the
// same durable counter on every start, so they are strictly increasing across
// restarts and can never be reused.
struct BootRecord {
  BootId boot;
  IncarnationId incarnation;
  NodeId node;
  Step started_at;
  Step ended_at;          // 0 while live
  bool clean_stop = false;
  bool interrupted = false;
  Sequence registry_sequence = Sequence{1};
};

// Durable history. Truncation is bounded and always drops the oldest entries;
// the newest authority-bearing state is never evicted.
class LineageTable {
 public:
  Status open_grant(EpochGrant grant);
  Status close_grant(GrantId id, GrantState state, Reason reason, Step now);
  const EpochGrant* find(GrantId id) const noexcept;
  std::vector<EpochGrant> grants_for(const DomainId& domain) const;

  // Highest epoch ever opened for the domain, whether or not it is still open.
  Epoch max_epoch(const DomainId& domain) const noexcept;
  // Epoch of the currently open grant for (domain, scope), if any.
  const EpochGrant* open_grant_for(const DomainId& domain, const Digest256& scope) const noexcept;
  std::vector<const EpochGrant*> open_grants() const;

  Status begin_boot(BootRecord record);
  Status end_boot(BootId boot, Step now, bool clean);
  const BootRecord* find_boot(BootId boot) const noexcept;
  std::vector<BootRecord> boots() const noexcept { return boots_; }

  const std::vector<EpochGrant>& grants() const noexcept { return grants_; }
  Status import(const std::vector<EpochGrant>& grants, const std::vector<BootRecord>& boots);

  Generation generation() const noexcept { return generation_; }
  void bump_generation() noexcept { generation_.try_increment(); }

  Status validate() const noexcept;

 private:
  std::vector<EpochGrant> grants_;   // append order; oldest truncated first
  std::vector<BootRecord> boots_;
  Generation generation_{1};
};

// Reconciliation between two durable histories. Conflicts are surfaced, never
// silently resolved; both input histories remain intact.
enum class ReconciliationKind : std::uint8_t {
  Identical = 0,
  LocalAhead = 1,
  RemoteAhead = 2,
  Divergent = 3,
};

struct ReconciliationConflict {
  Digest256 scope;
  DomainId domain;
  Epoch local_epoch;
  Epoch remote_epoch;
  IncarnationId local_incarnation;
  IncarnationId remote_incarnation;
  ReconciliationKind kind = ReconciliationKind::Divergent;
  Reason reason = Reason::None;
};

struct ReconciliationResult {
  Status status;
  Outcome outcome = Outcome::Unknown;
  std::vector<EpochGrant> merged_history;   // union, ordered by registry sequence
  std::vector<ReconciliationConflict> conflicts;
  std::uint64_t conflicts_surfaced = 0;
  std::uint64_t conflicts_dropped = 0;      // exceeded kMaxReconcileConflicts
  bool requires_operator = false;
};

ReconciliationResult reconcile(const std::vector<EpochGrant>& local,
                               const std::vector<EpochGrant>& remote);

}  // namespace sbf
