#include "sbf/scope.hpp"

#include <algorithm>

#include "sbf/canonical.hpp"
#include "sbf/limits.hpp"
#include "sbf/text.hpp"

namespace sbf {

Status Scope::make(std::vector<ExtentId> extents, Scope& out) {
  if (extents.empty()) return Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
  if (extents.size() > limits::kMaxExtentsPerScope) {
    return Status::make(Outcome::Exhausted, Reason::ScopeTooLarge, extents.size());
  }
  for (const auto& extent : extents) {
    if (extent.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  }
  std::sort(extents.begin(), extents.end());
  for (std::size_t i = 1; i < extents.size(); ++i) {
    if (extents[i] == extents[i - 1]) {
      return Status::make(Outcome::Invalid, Reason::DuplicateExtent, i);
    }
  }
  out.extents_ = std::move(extents);
  return Status::ok();
}

Status Scope::parse(std::string_view comma_separated, Scope& out) {
  std::vector<ExtentId> extents;
  const auto fields = text::split(comma_separated, ',');
  if (fields.empty()) return Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
  if (fields.size() > limits::kMaxExtentsPerScope) {
    return Status::make(Outcome::Exhausted, Reason::ScopeTooLarge, fields.size());
  }
  extents.reserve(fields.size());
  for (const auto& field : fields) {
    const auto trimmed = text::trim(field);
    auto id = ExtentId::try_make(trimmed);
    if (!id.has_value()) {
      return Status::make(Outcome::Invalid, Reason::IdCharset, trimmed.size());
    }
    extents.push_back(std::move(*id));
  }
  return make(std::move(extents), out);
}

bool Scope::contains_extent(const ExtentId& extent) const noexcept {
  return std::binary_search(extents_.begin(), extents_.end(), extent);
}

bool Scope::overlaps(const Scope& other) const noexcept {
  std::size_t i = 0;
  std::size_t j = 0;
  while (i < extents_.size() && j < other.extents_.size()) {
    if (extents_[i] == other.extents_[j]) return true;
    if (extents_[i] < other.extents_[j]) ++i;
    else ++j;
  }
  return false;
}

bool Scope::is_superset_of(const Scope& other) const noexcept {
  std::size_t i = 0;
  std::size_t j = 0;
  while (j < other.extents_.size()) {
    if (i >= extents_.size()) return false;
    if (extents_[i] == other.extents_[j]) {
      ++i;
      ++j;
    } else if (extents_[i] < other.extents_[j]) {
      ++i;
    } else {
      return false;
    }
  }
  return true;
}

Digest256 Scope::digest() const {
  CanonicalWriter writer;
  writer.sequence(extents_.size(), [&](std::size_t i) { writer.text(extents_[i].view()); });
  return Digest256::of(writer.bytes());
}

std::string Scope::csv() const {
  std::string out;
  for (std::size_t i = 0; i < extents_.size(); ++i) {
    if (i != 0) out.push_back(',');
    out.append(extents_[i].view());
  }
  return out;
}

std::vector<ExtentId> intersect_reference(const Scope& a, const Scope& b) {
  // Deliberately naive O(n*m) double loop: this is the independent oracle used
  // by the differential tests, so it must not share structure with the
  // production merge below.
  std::vector<ExtentId> result;
  for (const auto& left : a.extents()) {
    for (const auto& right : b.extents()) {
      if (left == right) {
        result.push_back(left);
        break;
      }
    }
  }
  std::sort(result.begin(), result.end());
  result.erase(std::unique(result.begin(), result.end()), result.end());
  return result;
}

std::vector<ExtentId> intersect_merge(const Scope& a, const Scope& b) {
  std::vector<ExtentId> result;
  const auto& left = a.extents();
  const auto& right = b.extents();
  result.reserve(std::min(left.size(), right.size()));
  std::size_t i = 0;
  std::size_t j = 0;
  while (i < left.size() && j < right.size()) {
    if (left[i] == right[j]) {
      result.push_back(left[i]);
      ++i;
      ++j;
    } else if (left[i] < right[j]) {
      ++i;
    } else {
      ++j;
    }
  }
  return result;
}

Status ScopeIndex::add(const ClaimId& claim, const Scope& scope) {
  if (claim.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  if (scope.empty()) return Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
  for (const auto& extent : scope.extents()) {
    if (entries_.size() >= limits::kMaxIndexedExtents) {
      return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, entries_.size());
    }
    Entry entry{extent, claim};
    const auto it = std::lower_bound(entries_.begin(), entries_.end(), entry);
    if (it != entries_.end() && *it == entry) continue;  // already indexed
    entries_.insert(it, entry);
  }
  return Status::ok();
}

Status ScopeIndex::remove(const ClaimId& claim) {
  const auto it = std::remove_if(entries_.begin(), entries_.end(),
                                 [&](const Entry& e) { return e.claim == claim; });
  entries_.erase(it, entries_.end());
  return Status::ok();
}

SearchResult ScopeIndex::query(const Scope& query, std::vector<ClaimId>& out,
                               std::uint64_t node_budget) const noexcept {
  out.clear();
  std::uint64_t nodes = 0;
  for (const auto& extent : query.extents()) {
    Entry probe{extent, ClaimId{}};
    auto it = std::lower_bound(entries_.begin(), entries_.end(), probe);
    while (it != entries_.end() && it->extent == extent) {
      if (++nodes > node_budget) {
        out.clear();
        return SearchResult::Indeterminate;
      }
      out.push_back(it->claim);
      ++it;
    }
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out.empty() ? SearchResult::Absent : SearchResult::Found;
}

SearchResult ScopeIndex::overlapping_pairs(std::vector<std::pair<ClaimId, ClaimId>>& out,
                                           std::uint64_t node_budget) const noexcept {
  out.clear();
  std::uint64_t nodes = 0;
  std::size_t i = 0;
  while (i < entries_.size()) {
    std::size_t j = i;
    while (j < entries_.size() && entries_[j].extent == entries_[i].extent) ++j;
    for (std::size_t a = i; a < j; ++a) {
      for (std::size_t b = a + 1; b < j; ++b) {
        if (++nodes > node_budget) {
          out.clear();
          return SearchResult::Indeterminate;
        }
        if (entries_[a].claim == entries_[b].claim) continue;
        out.emplace_back(entries_[a].claim, entries_[b].claim);
      }
    }
    i = j;
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out.empty() ? SearchResult::Absent : SearchResult::Found;
}

}  // namespace sbf
