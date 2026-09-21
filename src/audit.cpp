#include "sbf/audit.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>

#include "sbf/canonical.hpp"
#include "sbf/text.hpp"

namespace sbf {
namespace {

constexpr std::size_t kMaxAuditFindings = 256;

void add_finding(AuditReport& report, Outcome outcome, Reason reason, std::string subject,
                 std::string detail) {
  ++report.findings_total;
  if (report.findings.size() >= kMaxAuditFindings) {
    ++report.findings_dropped;
    return;
  }
  AuditFinding finding;
  finding.outcome = outcome;
  finding.reason = reason;
  finding.subject = std::move(subject);
  finding.detail = std::move(detail);
  report.findings.push_back(std::move(finding));
}

}  // namespace

bool succession_precedes(const MutationRecord& earlier, const MutationRecord& later) noexcept {
  if (earlier.epoch != later.epoch) return earlier.epoch < later.epoch;
  if (earlier.fence_token != later.fence_token) return earlier.fence_token < later.fence_token;
  return earlier.grant < later.grant;
}

AuditReport audit_fabric_history(const std::vector<MutationRecord>& records) {
  AuditReport report;
  report.outcome = Outcome::Ok;
  report.status = Status::ok();

  CanonicalWriter chain;
  std::map<std::string, MutationRecord> owner;   // extent -> last writer
  std::set<std::string> owners;
  std::uint64_t expected_sequence = 1;
  MutationRecord previous;
  bool has_previous = false;

  for (const auto& record : records) {
    ++report.checks_run;
    if (record.store_sequence.value() != expected_sequence) {
      ++report.sequence_gaps;
      add_finding(report, Outcome::Corrupt, Reason::SequenceRegression,
                  text::hex_u64(record.store_sequence.value()),
                  "fabric log sequence is not contiguous");
      report.outcome = Outcome::Corrupt;
    }
    expected_sequence = record.store_sequence.value() + 1;

    if (!(compute_record_digest(record) == record.record_digest)) {
      add_finding(report, Outcome::Corrupt, Reason::IntegrityMismatch,
                  text::hex_u64(record.store_sequence.value()),
                  "mutation record digest does not match its contents");
      report.outcome = Outcome::Corrupt;
    }

    const std::string owner_key =
        record.domain.str() + "/" + text::hex_u64(record.incarnation.value()) + "/" +
        text::hex_u64(record.fence_token.value());
    if (owners.insert(owner_key).second) ++report.distinct_owners;

    for (const auto& extent : record.scope.extents()) {
      const auto it = owner.find(extent.str());
      if (it != owner.end()) {
        const MutationRecord& prior = it->second;
        if (prior.fence_token > record.fence_token) {
          ++report.token_regressions;
          add_finding(report, Outcome::Fenced, Reason::TokenFloorRejected, extent.str(),
                      "a mutation was appended under a token below the durable high-water mark");
          report.outcome = Outcome::Fenced;
        } else if (prior.fence_token == record.fence_token &&
                   !(prior.incarnation == record.incarnation)) {
          ++report.foreign_owner_appends;
          add_finding(report, Outcome::Conflict, Reason::StoreOwnerMismatch, extent.str(),
                      "two incarnations appended under the same fence token");
          report.outcome = Outcome::Conflict;
        } else if (!(prior.incarnation == record.incarnation) &&
                   succession_precedes(record, prior)) {
          ++report.fence_escapes;
          add_finding(report, Outcome::Fenced, Reason::EpochRegression, extent.str(),
                      "authority succession went backwards for this extent");
          report.outcome = Outcome::Fenced;
        }
        if (!(prior.incarnation == record.incarnation) &&
            !(prior.fence_token == record.fence_token)) {
          ++report.ownership_transitions;
        }
      }
    }
    for (const auto& extent : record.scope.extents()) {
      owner[extent.str()] = record;
    }

    if (has_previous && !(previous.incarnation == record.incarnation)) {
      // Succession must be ordered: a later record may never carry a strictly
      // smaller authority vector for an overlapping extent.
      bool overlaps = false;
      for (const auto& extent : record.scope.extents()) {
        if (previous.scope.contains_extent(extent)) {
          overlaps = true;
          break;
        }
      }
      if (overlaps && succession_precedes(record, previous)) {
        ++report.fence_escapes;
        add_finding(report, Outcome::Fenced, Reason::EpochRegression,
                    text::hex_u64(record.store_sequence.value()),
                    "a fenced authority resumed after its successor committed");
        report.outcome = Outcome::Fenced;
      }
    }
    previous = record;
    has_previous = true;
    chain.digest(record.record_digest);
    ++report.mutations;
  }

  report.head_digest = Digest256::of(chain.bytes());
  report.mutually_exclusive_effect_history =
      report.token_regressions == 0 && report.foreign_owner_appends == 0 &&
      report.fence_escapes == 0 && report.sequence_gaps == 0;
  if (!report.mutually_exclusive_effect_history && report.status.is_ok()) {
    report.status = Status::make(report.outcome, Reason::InternalInvariantViolation,
                                 report.findings_total);
  }
  return report;
}

AuditReport audit_registry_state(const RegistryState& state) {
  AuditReport report;
  report.outcome = Outcome::Ok;
  report.status = Status::ok();

  if (auto st = state.fences().validate(); !st.is_ok()) {
    add_finding(report, Outcome::Corrupt, st.reason, "fence-table", sbf::to_string(st));
    report.outcome = Outcome::Corrupt;
  }
  ++report.checks_run;
  if (auto st = state.lineage().validate(); !st.is_ok()) {
    add_finding(report, Outcome::Corrupt, st.reason, "lineage", sbf::to_string(st));
    report.outcome = Outcome::Corrupt;
  }
  ++report.checks_run;

  std::map<std::string, Epoch> highest_epoch;
  std::map<GrantId, const EpochGrant*> by_id;
  report.grants = state.lineage().grants().size();
  for (const auto& grant : state.lineage().grants()) {
    ++report.checks_run;
    if (!by_id.emplace(grant.id, &grant).second) {
      add_finding(report, Outcome::Corrupt, Reason::DuplicateEntry,
                  text::hex_u64(grant.id.value()), "duplicate grant id");
      report.outcome = Outcome::Corrupt;
    }
    Epoch& top = highest_epoch[grant.domain.str()];
    if (grant.epoch < top) {
      ++report.epoch_regressions;
      add_finding(report, Outcome::Stale, Reason::EpochRegression, grant.domain.str(),
                  "grant epoch went backwards for this domain");
      report.outcome = Outcome::Stale;
    }
    if (grant.epoch > top) top = grant.epoch;
    if (grant.state == GrantState::Open) {
      ++report.open_grants;
      if (state.fences().incarnation_fenced(grant.incarnation)) {
        ++report.uninterruptible_grants;
        add_finding(report, Outcome::Fenced, Reason::IncarnationFenced, grant.domain.str(),
                    "an open grant belongs to an incarnation that is already fenced");
        report.outcome = Outcome::Fenced;
      }
    }
  }

  // Pairwise overlap check over open exclusive grants. Bounded by the number of
  // open grants, which is itself bounded by the policy's session limits.
  std::vector<const EpochGrant*> open;
  for (const auto& grant : state.lineage().grants()) {
    if (grant.state == GrantState::Open) open.push_back(&grant);
  }
  for (std::size_t i = 0; i < open.size(); ++i) {
    for (std::size_t j = i + 1; j < open.size(); ++j) {
      ++report.checks_run;
      if (!open[i]->extents.overlaps(open[j]->extents)) continue;
      if (open[i]->incarnation == open[j]->incarnation) continue;
      ++report.duplicate_exclusive_grants;
      add_finding(report, Outcome::Conflict, Reason::OverlappingExclusiveClaim,
                  open[i]->domain.str(),
                  "two open grants claim overlapping extents for different incarnations");
      report.outcome = Outcome::Conflict;
    }
  }

  for (const auto& grant : state.lineage().grants()) {
    if (grant.state != GrantState::Open) continue;
    ++report.checks_run;
    for (const auto& extent : grant.extents.extents()) {
      const FenceToken high = state.fences().high_water(extent);
      if (high > grant.fence_token) {
        add_finding(report, Outcome::Fenced, Reason::TokenFloorRejected, extent.str(),
                    "an open grant sits below the durable fence high-water mark");
        report.outcome = Outcome::Fenced;
      }
    }
  }

  report.mutually_exclusive_effect_history = report.duplicate_exclusive_grants == 0 &&
                                             report.epoch_regressions == 0 &&
                                             report.uninterruptible_grants == 0;
  if (!report.findings.empty() && report.status.is_ok()) {
    report.status = Status::make(report.outcome, Reason::InternalInvariantViolation,
                                 report.findings_total);
  }
  return report;
}

}  // namespace sbf
