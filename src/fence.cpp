#include "sbf/fence.hpp"

#include <algorithm>

namespace sbf {
namespace {

bool extent_state_less(const ExtentFenceState& a, const ExtentFenceState& b) noexcept {
  return a.extent < b.extent;
}

}  // namespace

FenceToken FenceTable::high_water(const ExtentId& extent) const noexcept {
  const auto it = std::lower_bound(extents_.begin(), extents_.end(), extent,
                                   [](const ExtentFenceState& state, const ExtentId& key) {
                                     return state.extent < key;
                                   });
  if (it == extents_.end() || !(it->extent == extent)) return FenceToken{};
  return it->high_water_token;
}

const ExtentFenceState* FenceTable::find(const ExtentId& extent) const noexcept {
  const auto it = std::lower_bound(extents_.begin(), extents_.end(), extent,
                                   [](const ExtentFenceState& state, const ExtentId& key) {
                                     return state.extent < key;
                                   });
  if (it == extents_.end() || !(it->extent == extent)) return nullptr;
  return &*it;
}

Status FenceTable::adopt(const Scope& scope, FenceToken token, Epoch epoch,
                         IncarnationId incarnation, GrantId grant, Step now) {
  if (scope.empty()) return Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
  if (token.is_none()) return Status::make(Outcome::Invalid, Reason::FenceTokenMissing);
  if (incarnation.is_none()) return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);

  for (const auto& extent : scope.extents()) {
    const auto it = std::lower_bound(extents_.begin(), extents_.end(), extent,
                                     [](const ExtentFenceState& state, const ExtentId& key) {
                                       return state.extent < key;
                                     });
    if (it != extents_.end() && it->extent == extent) {
      if (it->high_water_token > token) {
        return Status::make(Outcome::Fenced, Reason::FenceTokenRegressed,
                            it->high_water_token.value());
      }
      if (it->high_water_token == token && it->owner_incarnation != incarnation) {
        return Status::make(Outcome::Conflict, Reason::StoreOwnerMismatch,
                            it->owner_incarnation.value());
      }
    }
  }

  if (extents_.size() + scope.size() > limits::kMaxIndexedExtents) {
    return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, extents_.size());
  }

  for (const auto& extent : scope.extents()) {
    const ExtentFenceState state{extent, token, epoch, incarnation, grant, now};
    const auto it = std::lower_bound(extents_.begin(), extents_.end(), extent,
                                     [](const ExtentFenceState& s, const ExtentId& key) {
                                       return s.extent < key;
                                     });
    if (it != extents_.end() && it->extent == extent) {
      *it = state;
    } else {
      extents_.insert(it, state);
    }
  }
  bump_generation();
  return Status::ok();
}

Status FenceTable::apply(const FenceRecord& record, const Scope& scope) {
  if (scope.empty()) return Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
  if (record.token.is_none()) return Status::make(Outcome::Invalid, Reason::FenceTokenMissing);

  if (records_.size() >= limits::kMaxFenceRecords) {
    // The fence history is bounded. Dropping the oldest *audit* record is safe
    // because the monotone high-water marks - not the history - are what carry
    // enforcement.
    records_.erase(records_.begin());
  }

  if (extents_.size() + scope.size() > limits::kMaxIndexedExtents) {
    return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, extents_.size());
  }

  for (const auto& extent : scope.extents()) {
    const auto it = std::lower_bound(extents_.begin(), extents_.end(), extent,
                                     [](const ExtentFenceState& s, const ExtentId& key) {
                                       return s.extent < key;
                                     });
    if (it != extents_.end() && it->extent == extent) {
      if (it->high_water_token > record.token) {
        return Status::make(Outcome::Fenced, Reason::FenceTokenRegressed,
                            it->high_water_token.value());
      }
      it->high_water_token = record.token;
      it->high_water_epoch = record.fenced_epoch;
      it->updated_at = record.issued_at;
      if (record.fenced_incarnation.is_set()) {
        it->owner_incarnation = record.fenced_incarnation;
      }
      it->owner_grant = record.superseded_grant;
    } else {
      ExtentFenceState state;
      state.extent = extent;
      state.high_water_token = record.token;
      state.high_water_epoch = record.fenced_epoch;
      state.owner_incarnation = record.fenced_incarnation;
      state.owner_grant = record.superseded_grant;
      state.updated_at = record.issued_at;
      extents_.insert(it, state);
    }
  }

  if (record.fenced_incarnation.is_set()) {
    const auto it = std::lower_bound(fenced_incarnations_.begin(), fenced_incarnations_.end(),
                                     record.fenced_incarnation);
    if (it == fenced_incarnations_.end() || !(*it == record.fenced_incarnation)) {
      if (fenced_incarnations_.size() < limits::kMaxFenceRecords) {
        fenced_incarnations_.insert(it, record.fenced_incarnation);
      }
    }
  }
  if (!record.domain.empty() && record.fenced_epoch.is_set()) {
    const std::pair<std::string, std::uint64_t> key{record.domain.str(), record.fenced_epoch.value()};
    const auto it = std::lower_bound(fenced_epochs_.begin(), fenced_epochs_.end(), key);
    if (it == fenced_epochs_.end() || *it != key) {
      if (fenced_epochs_.size() < limits::kMaxFenceRecords) {
        fenced_epochs_.insert(it, key);
      }
    }
  }

  records_.push_back(record);
  bump_generation();
  return Status::ok();
}

FenceAdmission FenceTable::admit(FenceToken presented, const Scope& scope,
                                 IncarnationId incarnation, GrantId grant) const {
  FenceAdmission result;
  if (scope.empty()) {
    result.status = Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
    result.explanation.add(Reason::EmptyExtentSet);
    return result;
  }
  if (presented.is_none()) {
    result.status = Status::make(Outcome::Invalid, Reason::FenceTokenMissing);
    result.explanation.add(Reason::FenceTokenMissing);
    return result;
  }
  FenceToken highest;
  for (const auto& extent : scope.extents()) {
    const ExtentFenceState* state = find(extent);
    if (state == nullptr) {
      // No durable mark for this extent yet: any positive token may claim it.
      continue;
    }
    if (state->high_water_token > presented) {
      result.status = Status::make(Outcome::Fenced, Reason::TokenFloorRejected,
                                   state->high_water_token.value());
      result.explanation.add(Reason::TokenFloorRejected);
      result.current_high_water = state->high_water_token;
      return result;
    }
    if (state->high_water_token == presented && state->owner_incarnation != incarnation) {
      result.status = Status::make(Outcome::Conflict, Reason::StoreOwnerMismatch,
                                   state->owner_incarnation.value());
      result.explanation.add(Reason::StoreOwnerMismatch);
      result.current_high_water = state->high_water_token;
      return result;
    }
    if (state->high_water_token == presented && state->owner_grant.is_set() &&
        state->owner_grant != grant) {
      result.status = Status::make(Outcome::Conflict, Reason::StoreOwnerMismatch,
                                   state->owner_grant.value());
      result.explanation.add(Reason::StoreOwnerMismatch);
      result.current_high_water = state->high_water_token;
      return result;
    }
    if (state->high_water_token > highest) highest = state->high_water_token;
  }
  result.admitted = true;
  result.status = Status::ok();
  result.current_high_water = highest;
  return result;
}

bool FenceTable::incarnation_fenced(IncarnationId incarnation) const noexcept {
  if (incarnation.is_none()) return false;
  return std::binary_search(fenced_incarnations_.begin(), fenced_incarnations_.end(), incarnation);
}

bool FenceTable::epoch_fenced(const DomainId& domain, Epoch epoch) const noexcept {
  if (domain.empty() || epoch.is_none()) return false;
  const std::pair<std::string, std::uint64_t> key{domain.str(), epoch.value()};
  return std::binary_search(fenced_epochs_.begin(), fenced_epochs_.end(), key);
}

Status FenceTable::validate() const noexcept {
  for (std::size_t i = 0; i < extents_.size(); ++i) {
    if (extents_[i].extent.empty()) return Status::make(Outcome::Corrupt, Reason::EmptyValue, i);
    if (extents_[i].high_water_token.is_none()) {
      return Status::make(Outcome::Corrupt, Reason::FenceTokenMissing, i);
    }
    if (i > 0 && !(extents_[i - 1].extent < extents_[i].extent)) {
      return Status::make(Outcome::Corrupt, Reason::DuplicateEntry, i);
    }
  }
  return Status::ok();
}

Status FenceTable::import(const std::vector<ExtentFenceState>& extents,
                          const std::vector<FenceRecord>& records) {
  if (extents.size() > limits::kMaxIndexedExtents) {
    return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, extents.size());
  }
  std::vector<ExtentFenceState> sorted = extents;
  std::sort(sorted.begin(), sorted.end(), extent_state_less);
  FenceTable fresh;
  fresh.extents_ = std::move(sorted);
  if (auto st = fresh.validate(); !st.is_ok()) return st;
  fresh.records_ = records;
  if (fresh.records_.size() > limits::kMaxFenceRecords) {
    fresh.records_.erase(fresh.records_.begin(),
                         fresh.records_.begin() +
                             static_cast<std::ptrdiff_t>(fresh.records_.size() - limits::kMaxFenceRecords));
  }
  for (const auto& record : fresh.records_) {
    if (record.fenced_incarnation.is_set()) {
      fresh.fenced_incarnations_.push_back(record.fenced_incarnation);
    }
    if (!record.domain.empty() && record.fenced_epoch.is_set()) {
      fresh.fenced_epochs_.emplace_back(record.domain.str(), record.fenced_epoch.value());
    }
  }
  for (const auto& state : fresh.extents_) {
    if (state.owner_incarnation.is_set()) {
      fresh.fenced_incarnations_.push_back(state.owner_incarnation);
    }
    if (!state.extent.empty()) {
      // no epoch tracking from extent state
    }
  }
  std::sort(fresh.fenced_incarnations_.begin(), fresh.fenced_incarnations_.end());
  fresh.fenced_incarnations_.erase(
      std::unique(fresh.fenced_incarnations_.begin(), fresh.fenced_incarnations_.end()),
      fresh.fenced_incarnations_.end());
  std::sort(fresh.fenced_epochs_.begin(), fresh.fenced_epochs_.end());
  fresh.fenced_epochs_.erase(std::unique(fresh.fenced_epochs_.begin(), fresh.fenced_epochs_.end()),
                             fresh.fenced_epochs_.end());
  *this = std::move(fresh);
  return Status::ok();
}

}  // namespace sbf
