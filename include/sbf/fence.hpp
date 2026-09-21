#pragma once

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "sbf/digest.hpp"
#include "sbf/ids.hpp"
#include "sbf/limits.hpp"
#include "sbf/scope.hpp"
#include "sbf/status.hpp"

namespace sbf {

// A durable fence record. Fencing is monotone: tokens are issued strictly
// increasing, are never reused, and raising an extent's high-water token
// permanently disqualifies every lower token for that extent.
struct FenceRecord {
  FenceToken token;
  DomainId domain;                 // domain that was fenced
  Digest256 scope;                 // exact extent set that was fenced
  Epoch fenced_epoch;
  IncarnationId fenced_incarnation;
  Reason cause = Reason::None;
  Step issued_at;
  GrantId superseded_grant;
  Sequence registry_sequence = Sequence{1};
  FenceToken previous_high_water;
};

// Per-extent durable high-water mark. This is the structure that makes a fenced
// authority permanently unable to act, even after a restart.
struct ExtentFenceState {
  ExtentId extent;
  FenceToken high_water_token;
  Epoch high_water_epoch;
  IncarnationId owner_incarnation;
  GrantId owner_grant;
  Step updated_at;
  friend bool operator==(const ExtentFenceState&, const ExtentFenceState&) = default;
};

struct FenceAdmission {
  bool admitted = false;
  Status status;
  Explanation explanation;
  FenceToken current_high_water;
};

// Bounded, deterministic fence table. Entries are kept sorted by extent so that
// enumeration never depends on insertion order.
class FenceTable {
 public:
  FenceToken high_water(const ExtentId& extent) const noexcept;
  const ExtentFenceState* find(const ExtentId& extent) const noexcept;

  // Raises the high-water mark for every extent of the scope. Returns Fenced
  // when any extent already carries a token greater than or equal to the
  // presented one and the presented incarnation is not the current owner.
  Status apply(const FenceRecord& record, const Scope& scope);

  // Ownership claim made when a grant is opened: records the owning incarnation
  // and grant for each extent and raises the high-water token.
  Status adopt(const Scope& scope, FenceToken token, Epoch epoch,
               IncarnationId incarnation, GrantId grant, Step now);

  // The single predicate that gates a mutation at the effect boundary.
  FenceAdmission admit(FenceToken presented, const Scope& scope,
                       IncarnationId incarnation, GrantId grant) const;

  bool incarnation_fenced(IncarnationId incarnation) const noexcept;
  bool epoch_fenced(const DomainId& domain, Epoch epoch) const noexcept;

  const std::vector<ExtentFenceState>& extents() const noexcept { return extents_; }
  const std::vector<FenceRecord>& records() const noexcept { return records_; }

  Generation generation() const noexcept { return generation_; }
  void bump_generation() noexcept { generation_.try_increment(); }

  Status validate() const noexcept;
  std::size_t size() const noexcept { return extents_.size(); }

  // Restart support: restore the table from durable state, then fence every
  // incarnation that was live before the restart.
  Status import(const std::vector<ExtentFenceState>& extents,
                const std::vector<FenceRecord>& records);

 private:
  std::vector<ExtentFenceState> extents_;  // sorted by extent
  std::vector<FenceRecord> records_;       // append order, bounded
  std::vector<IncarnationId> fenced_incarnations_;  // sorted
  std::vector<std::pair<std::string, std::uint64_t>> fenced_epochs_;  // sorted (domain, epoch)
  Generation generation_{1};
};

}  // namespace sbf
