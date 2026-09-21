#include "sbf/lineage.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace sbf {

std::string_view to_string(GrantState state) noexcept {
  switch (state) {
    case GrantState::Open: return "Open";
    case GrantState::Closed: return "Closed";
    case GrantState::Fenced: return "Fenced";
    case GrantState::Interrupted: return "Interrupted";
  }
  return "Unknown";
}

Status LineageTable::open_grant(EpochGrant grant) {
  if (grant.id.is_none()) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  if (grant.domain.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  if (grant.epoch.is_none()) return Status::make(Outcome::Invalid, Reason::EpochUnknown);
  if (grant.incarnation.is_none()) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  if (grant.fence_token.is_none()) return Status::make(Outcome::Invalid, Reason::FenceTokenMissing);
  if (grant.state != GrantState::Open) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  }
  if (find(grant.id) != nullptr) {
    return Status::make(Outcome::AlreadyExists, Reason::DuplicateEntry, grant.id.value());
  }
  const Epoch highest = max_epoch(grant.domain);
  if (grant.epoch < highest) {
    // An epoch may never be reopened: that would let a superseded generation
    // return to authority through replay.
    return Status::make(Outcome::Stale, Reason::EpochRegression, highest.value());
  }
  if (open_grant_for(grant.domain, grant.scope) != nullptr) {
    return Status::make(Outcome::Conflict, Reason::OverlappingExclusiveClaim, grant.id.value());
  }

  while (grants_.size() >= limits::kMaxLineageEntries) {
    const auto victim = std::find_if(grants_.begin(), grants_.end(), [](const EpochGrant& g) {
      return g.state != GrantState::Open;
    });
    if (victim == grants_.end()) {
      return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, grants_.size());
    }
    grants_.erase(victim);
  }

  grants_.push_back(grant);
  bump_generation();
  return Status::ok();
}

Status LineageTable::close_grant(GrantId id, GrantState state, Reason reason, Step now) {
  if (state == GrantState::Open) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  }
  for (auto& grant : grants_) {
    if (grant.id == id) {
      if (grant.state != GrantState::Open) {
        // Closing twice is not an error: the durable outcome is already the one
        // being requested. It is reported so that duplicate completions remain
        // visible.
        return Status::make(Outcome::AlreadyExists, Reason::DuplicateEntry, id.value());
      }
      grant.state = state;
      grant.close_reason = reason;
      grant.closed_at = now;
      bump_generation();
      return Status::ok();
    }
  }
  return Status::make(Outcome::NotFound, Reason::GrantNotRegistered, id.value());
}

const EpochGrant* LineageTable::find(GrantId id) const noexcept {
  for (const auto& grant : grants_) {
    if (grant.id == id) return &grant;
  }
  return nullptr;
}

std::vector<EpochGrant> LineageTable::grants_for(const DomainId& domain) const {
  std::vector<EpochGrant> out;
  for (const auto& grant : grants_) {
    if (grant.domain == domain) out.push_back(grant);
  }
  std::sort(out.begin(), out.end(), [](const EpochGrant& a, const EpochGrant& b) {
    if (auto c = a.epoch <=> b.epoch; c != 0) return c < 0;
    return a.id < b.id;
  });
  return out;
}

Epoch LineageTable::max_epoch(const DomainId& domain) const noexcept {
  Epoch highest;
  for (const auto& grant : grants_) {
    if (grant.domain == domain && grant.epoch > highest) highest = grant.epoch;
  }
  return highest;
}

const EpochGrant* LineageTable::open_grant_for(const DomainId& domain,
                                               const Digest256& scope) const noexcept {
  for (const auto& grant : grants_) {
    if (grant.state == GrantState::Open && grant.domain == domain && grant.scope == scope) {
      return &grant;
    }
  }
  return nullptr;
}

std::vector<const EpochGrant*> LineageTable::open_grants() const {
  std::vector<const EpochGrant*> out;
  for (const auto& grant : grants_) {
    if (grant.state == GrantState::Open) out.push_back(&grant);
  }
  std::sort(out.begin(), out.end(), [](const EpochGrant* a, const EpochGrant* b) {
    return a->id < b->id;
  });
  return out;
}

Status LineageTable::begin_boot(BootRecord record) {
  if (record.boot.is_none() || record.incarnation.is_none()) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  }
  if (find_boot(record.boot) != nullptr) {
    return Status::make(Outcome::AlreadyExists, Reason::DuplicateEntry, record.boot.value());
  }
  if (boots_.size() >= limits::kMaxLineageEntries) {
    boots_.erase(boots_.begin());
  }
  boots_.push_back(record);
  bump_generation();
  return Status::ok();
}

Status LineageTable::end_boot(BootId boot, Step now, bool clean) {
  for (auto& record : boots_) {
    if (record.boot == boot) {
      if (record.ended_at.is_set()) {
        return Status::make(Outcome::AlreadyExists, Reason::DuplicateEntry, boot.value());
      }
      record.ended_at = now;
      record.clean_stop = clean;
      record.interrupted = !clean;
      bump_generation();
      return Status::ok();
    }
  }
  return Status::make(Outcome::NotFound, Reason::BootNotRegistered);
}

const BootRecord* LineageTable::find_boot(BootId boot) const noexcept {
  for (const auto& record : boots_) {
    if (record.boot == boot) return &record;
  }
  return nullptr;
}

Status LineageTable::import(const std::vector<EpochGrant>& grants,
                            const std::vector<BootRecord>& boots) {
  if (grants.size() > limits::kMaxLineageEntries || boots.size() > limits::kMaxLineageEntries) {
    return Status::make(Outcome::Exhausted, Reason::BoundedTableFull,
                        std::max(grants.size(), boots.size()));
  }
  LineageTable fresh;
  fresh.grants_ = grants;
  fresh.boots_ = boots;
  // Imported state must satisfy the same invariants as live state: duplicate
  // grants, regressed epochs or duplicate boots mean the durable bytes were not
  // produced by this runtime.
  std::set<std::uint64_t> ids;
  std::map<std::string, std::uint64_t> highest;
  std::set<std::pair<std::string, std::string>> open_keys;
  for (const auto& grant : fresh.grants_) {
    if (grant.id.is_none() || grant.domain.empty() || grant.epoch.is_none()) {
      return Status::make(Outcome::Corrupt, Reason::ValueOutOfRange, grant.id.value());
    }
    if (!ids.insert(grant.id.value()).second) {
      return Status::make(Outcome::Corrupt, Reason::DuplicateEntry, grant.id.value());
    }
    auto& top = highest[grant.domain.str()];
    if (grant.epoch.value() < top) {
      return Status::make(Outcome::Corrupt, Reason::EpochRegression, grant.epoch.value());
    }
    top = grant.epoch.value();
    if (grant.state == GrantState::Open) {
      const std::pair<std::string, std::string> key{grant.domain.str(), grant.scope.hex()};
      if (!open_keys.insert(key).second) {
        return Status::make(Outcome::Corrupt, Reason::OverlappingExclusiveClaim, grant.id.value());
      }
    }
  }
  std::set<std::uint64_t> boot_ids;
  for (const auto& boot : fresh.boots_) {
    if (boot.boot.is_none() || boot.incarnation.is_none()) {
      return Status::make(Outcome::Corrupt, Reason::ValueOutOfRange, boot.boot.value());
    }
    if (!boot_ids.insert(boot.boot.value()).second) {
      return Status::make(Outcome::Corrupt, Reason::DuplicateEntry, boot.boot.value());
    }
  }
  *this = std::move(fresh);
  return Status::ok();
}

Status LineageTable::validate() const noexcept {
  std::map<std::string, std::uint64_t> highest;
  std::set<std::pair<std::string, std::string>> open_keys;
  std::set<std::uint64_t> ids;
  for (const auto& grant : grants_) {
    if (grant.id.is_none()) return Status::make(Outcome::Corrupt, Reason::ValueOutOfRange);
    if (!ids.insert(grant.id.value()).second) {
      return Status::make(Outcome::Corrupt, Reason::DuplicateEntry, grant.id.value());
    }
    auto& top = highest[grant.domain.str()];
    if (grant.epoch.value() < top) {
      return Status::make(Outcome::Corrupt, Reason::EpochRegression, grant.epoch.value());
    }
    top = grant.epoch.value();
    if (grant.state == GrantState::Open) {
      const std::pair<std::string, std::string> key{grant.domain.str(), grant.scope.hex()};
      if (!open_keys.insert(key).second) {
        return Status::make(Outcome::Corrupt, Reason::OverlappingExclusiveClaim, grant.id.value());
      }
    }
  }
  return Status::ok();
}

ReconciliationResult reconcile(const std::vector<EpochGrant>& local,
                               const std::vector<EpochGrant>& remote) {
  ReconciliationResult result;
  if (local.size() > limits::kMaxReconcileInputs || remote.size() > limits::kMaxReconcileInputs) {
    result.status = Status::make(Outcome::Exhausted, Reason::BoundedTableFull,
                                 std::max(local.size(), remote.size()));
    result.outcome = Outcome::Exhausted;
    return result;
  }

  // Lineage is preserved: the merged history is the union keyed by grant id,
  // ordered by registry sequence. Nothing is dropped and nothing is chosen.
  std::map<std::uint64_t, EpochGrant> by_id;
  for (const auto& grant : local) {
    if (!by_id.insert({grant.id.value(), grant}).second) {
      result.status = Status::make(Outcome::Corrupt, Reason::DuplicateEntry, grant.id.value());
      result.outcome = Outcome::Corrupt;
      return result;
    }
  }
  for (const auto& grant : remote) {
    const auto it = by_id.find(grant.id.value());
    if (it == by_id.end()) {
      by_id.insert({grant.id.value(), grant});
      continue;
    }
    const EpochGrant& existing = it->second;
    if (!(existing.domain == grant.domain) || !(existing.scope == grant.scope) ||
        existing.epoch != grant.epoch || existing.incarnation != grant.incarnation ||
        existing.fence_token != grant.fence_token) {
      ReconciliationConflict conflict;
      conflict.scope = existing.scope;
      conflict.domain = existing.domain;
      conflict.local_epoch = existing.epoch;
      conflict.remote_epoch = grant.epoch;
      conflict.local_incarnation = existing.incarnation;
      conflict.remote_incarnation = grant.incarnation;
      conflict.kind = ReconciliationKind::Divergent;
      conflict.reason = Reason::LineageDivergence;
      if (result.conflicts.size() < limits::kMaxReconcileConflicts) {
        result.conflicts.push_back(conflict);
      } else {
        ++result.conflicts_dropped;
      }
    }
  }

  for (const auto& [id, grant] : by_id) {
    (void)id;
    result.merged_history.push_back(grant);
  }
  std::sort(result.merged_history.begin(), result.merged_history.end(),
            [](const EpochGrant& a, const EpochGrant& b) {
              if (a.registry_sequence != b.registry_sequence) {
                return a.registry_sequence < b.registry_sequence;
              }
              return a.id < b.id;
            });

  result.conflicts_surfaced = result.conflicts.size();
  result.requires_operator = !result.conflicts.empty();
  if (result.conflicts.empty()) {
    result.status = Status::ok();
    result.outcome = Outcome::Ok;
  } else {
    result.status = Status::make(Outcome::Conflict, Reason::ReconciliationRequired,
                                 result.conflicts_surfaced);
    result.outcome = Outcome::Conflict;
  }
  return result;
}

}  // namespace sbf
