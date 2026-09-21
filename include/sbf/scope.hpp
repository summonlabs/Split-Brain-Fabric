#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sbf/digest.hpp"
#include "sbf/ids.hpp"
#include "sbf/status.hpp"

namespace sbf {

// A fabric scope is a canonical set of extents: sorted, unique, bounded.
//
// Scope semantics are set semantics. Two scopes overlap when their extent sets
// intersect, and that relation - not wall-clock recency and not identifier
// comparison - decides whether two control domains contend for the same fabric.
class Scope {
 public:
  Scope() = default;

  // Sorts, rejects duplicates, rejects an empty set and enforces the size bound.
  static Status make(std::vector<ExtentId> extents, Scope& out);
  static Status parse(std::string_view comma_separated, Scope& out);

  static std::optional<Scope> try_make(std::vector<ExtentId> extents) {
    Scope scope;
    if (!make(std::move(extents), scope).is_ok()) return std::nullopt;
    return scope;
  }
  static std::optional<Scope> try_parse(std::string_view text) {
    Scope scope;
    if (!parse(text, scope).is_ok()) return std::nullopt;
    return scope;
  }

  bool empty() const noexcept { return extents_.empty(); }
  std::size_t size() const noexcept { return extents_.size(); }
  const std::vector<ExtentId>& extents() const noexcept { return extents_; }

  bool contains_extent(const ExtentId& extent) const noexcept;
  bool overlaps(const Scope& other) const noexcept;
  bool is_superset_of(const Scope& other) const noexcept;

  // Content identity of the exact extent set.
  Digest256 digest() const;
  std::string csv() const;

  friend bool operator==(const Scope&, const Scope&) = default;
  friend std::strong_ordering operator<=>(const Scope& a, const Scope& b) noexcept {
    return a.extents_ <=> b.extents_;
  }

 private:
  std::vector<ExtentId> extents_;
};

// Independent reference intersection: the obvious O(n*m) double loop. It is the
// oracle for the differential tests and is never used on a hot path. The result
// is a canonical, sorted, possibly empty extent list (an empty intersection is
// represented by an empty vector, not by an invalid empty Scope).
std::vector<ExtentId> intersect_reference(const Scope& a, const Scope& b);

// Production intersection: single merge pass over two canonical sequences.
// Requires canonical (sorted, unique) inputs, which Scope guarantees.
std::vector<ExtentId> intersect_merge(const Scope& a, const Scope& b);

// Result of a bounded containment/overlap query. Absent is only ever returned
// when the search provably completed; running out of budget yields
// Indeterminate.
enum class SearchResult : std::uint8_t {
  Found = 0,
  Absent = 1,
  Indeterminate = 2,
};

// Deterministic overlap index over a bounded set of (claim, scope) entries.
// Implemented as a sorted vector of (extent, claim) pairs with binary search:
// no hashing, therefore results never depend on hash seed or insertion order.
class ScopeIndex {
 public:
  Status add(const ClaimId& claim, const Scope& scope);
  Status remove(const ClaimId& claim);
  void clear() noexcept { entries_.clear(); }

  // Collects the claims whose scope shares at least one extent with the query.
  // Output is sorted by ClaimId and deduplicated.
  SearchResult query(const Scope& query, std::vector<ClaimId>& out,
                     std::uint64_t node_budget) const noexcept;

  // Enumerates every pair of overlapping entries. Bounded by node_budget.
  SearchResult overlapping_pairs(std::vector<std::pair<ClaimId, ClaimId>>& out,
                                 std::uint64_t node_budget) const noexcept;

  std::size_t size() const noexcept { return entries_.size(); }

 private:
  struct Entry {
    ExtentId extent;
    ClaimId claim;
    friend bool operator==(const Entry&, const Entry&) = default;
    friend std::strong_ordering operator<=>(const Entry& a, const Entry& b) noexcept {
      if (auto c = a.extent <=> b.extent; c != 0) return c;
      return a.claim <=> b.claim;
    }
  };
  std::vector<Entry> entries_;  // kept sorted and unique
};

}  // namespace sbf
