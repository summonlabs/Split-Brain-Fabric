#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "sbf/canonical.hpp"
#include "sbf/registry.hpp"
#include "sbf/text.hpp"

namespace sbf {
namespace {

constexpr std::uint32_t kStateFormatVersion = 1;

// ---- durable payload codecs --------------------------------------------------

std::string encode_boot_record(const BootRecord& boot) {
  CanonicalWriter writer;
  writer.counter(boot.boot);
  writer.counter(boot.incarnation);
  writer.text(boot.node.view());
  writer.counter(boot.started_at);
  writer.counter(boot.ended_at);
  writer.boolean(boot.clean_stop);
  writer.boolean(boot.interrupted);
  writer.counter(boot.registry_sequence);
  return std::move(writer).take();
}

Status decode_boot_record(CanonicalReader& reader, BootRecord& boot) {
  if (auto st = reader.counter(boot.boot); !st.is_ok()) return st;
  if (auto st = reader.counter(boot.incarnation); !st.is_ok()) return st;
  std::string node;
  if (auto st = reader.text(node); !st.is_ok()) return st;
  auto node_id = NodeId::try_make(node);
  if (!node_id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  boot.node = *node_id;
  if (auto st = reader.counter(boot.started_at); !st.is_ok()) return st;
  if (auto st = reader.counter(boot.ended_at); !st.is_ok()) return st;
  if (auto st = reader.boolean(boot.clean_stop); !st.is_ok()) return st;
  if (auto st = reader.boolean(boot.interrupted); !st.is_ok()) return st;
  return reader.counter(boot.registry_sequence);
}

Status decode_scope_blob(CanonicalReader& reader, Scope& scope) {
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  CanonicalReader nested(blob);
  if (auto st = decode(nested, scope); !st.is_ok()) return st;
  return nested.finish();
}

std::string encode_grant(const EpochGrant& grant) {
  CanonicalWriter writer;
  writer.counter(grant.id);
  writer.text(grant.domain.view());
  writer.digest(grant.scope);
  writer.blob(encode(grant.extents));
  writer.counter(grant.attempt);
  writer.counter(grant.epoch);
  writer.counter(grant.incarnation);
  writer.counter(grant.boot);
  writer.counter(grant.fence_token);
  writer.counter(grant.opened_at);
  writer.counter(grant.closed_at);
  writer.u16(static_cast<std::uint16_t>(grant.state));
  writer.counter(grant.registry_sequence);
  writer.counter(grant.lineage_generation);
  writer.counter(grant.policy_generation);
  writer.counter(grant.evidence_generation);
  writer.reason(grant.close_reason);
  return std::move(writer).take();
}

Status decode_grant(CanonicalReader& reader, EpochGrant& grant) {
  if (auto st = reader.counter(grant.id); !st.is_ok()) return st;
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto domain_id = DomainId::try_make(domain);
  if (!domain_id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  grant.domain = *domain_id;
  if (auto st = reader.digest(grant.scope); !st.is_ok()) return st;
  if (auto st = decode_scope_blob(reader, grant.extents); !st.is_ok()) return st;
  if (!(grant.extents.digest() == grant.scope)) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch);
  }
  if (auto st = reader.counter(grant.attempt); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.boot); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.opened_at); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.closed_at); !st.is_ok()) return st;
  std::uint16_t state = 0;
  if (auto st = reader.u16(state); !st.is_ok()) return st;
  if (state > static_cast<std::uint16_t>(GrantState::Interrupted)) {
    return Status::make(Outcome::Corrupt, Reason::InvalidEnum, state);
  }
  grant.state = static_cast<GrantState>(state);
  if (auto st = reader.counter(grant.registry_sequence); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.lineage_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.policy_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(grant.evidence_generation); !st.is_ok()) return st;
  return reader.reason(grant.close_reason);
}

std::string encode_interrupt(const InterruptMark& mark) {
  CanonicalWriter writer;
  writer.counter(mark.grant);
  writer.text(mark.domain.view());
  writer.counter(mark.epoch);
  writer.counter(mark.incarnation);
  writer.counter(mark.boot);
  writer.counter(mark.marked_at);
  writer.reason(mark.reason);
  return std::move(writer).take();
}

Status decode_interrupt(CanonicalReader& reader, InterruptMark& mark) {
  if (auto st = reader.counter(mark.grant); !st.is_ok()) return st;
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto domain_id = DomainId::try_make(domain);
  if (!domain_id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  mark.domain = *domain_id;
  if (auto st = reader.counter(mark.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(mark.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(mark.boot); !st.is_ok()) return st;
  if (auto st = reader.counter(mark.marked_at); !st.is_ok()) return st;
  return reader.reason(mark.reason);
}

std::string encode_idempotency(const IdempotencyEntry& entry) {
  CanonicalWriter writer;
  writer.counter(entry.incarnation);
  writer.counter(entry.attempt);
  writer.counter(entry.epoch);
  writer.counter(entry.token);
  writer.counter(entry.grant);
  writer.counter(entry.valid_until);
  writer.counter(entry.registry_sequence);
  return std::move(writer).take();
}

Status decode_idempotency(CanonicalReader& reader, IdempotencyEntry& entry) {
  if (auto st = reader.counter(entry.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(entry.attempt); !st.is_ok()) return st;
  if (auto st = reader.counter(entry.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(entry.token); !st.is_ok()) return st;
  if (auto st = reader.counter(entry.grant); !st.is_ok()) return st;
  if (auto st = reader.counter(entry.valid_until); !st.is_ok()) return st;
  return reader.counter(entry.registry_sequence);
}

std::string encode_domain(const DomainDefinition& definition) {
  CanonicalWriter writer;
  writer.text(definition.domain.view());
  writer.text(definition.node.view());
  writer.blob(encode(definition.scope));
  writer.text(definition.policy.view());
  writer.boolean(definition.exclusive);
  return std::move(writer).take();
}

Status decode_domain(CanonicalReader& reader, DomainDefinition& definition) {
  std::string domain;
  std::string node;
  std::string policy;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  if (auto st = reader.text(node); !st.is_ok()) return st;
  auto domain_id = DomainId::try_make(domain);
  auto node_id = NodeId::try_make(node);
  if (!domain_id.has_value() || !node_id.has_value()) {
    return Status::make(Outcome::Corrupt, Reason::IdCharset);
  }
  definition.domain = *domain_id;
  definition.node = *node_id;
  // Field order must mirror encode_domain exactly.
  if (auto st = decode_scope_blob(reader, definition.scope); !st.is_ok()) return st;
  if (auto st = reader.text(policy); !st.is_ok()) return st;
  auto policy_id = PolicyId::try_make(policy);
  if (!policy_id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  definition.policy = *policy_id;
  return reader.boolean(definition.exclusive);
}

std::string encode_policy(const ArbiterPolicy& policy) {
  CanonicalWriter writer;
  writer.text(policy.policy.view());
  writer.counter(policy.generation);
  writer.blob(encode(policy.quorum));
  writer.boolean(policy.require_quorum_for_exclusive);
  writer.boolean(policy.require_lease_for_exclusive);
  writer.boolean(policy.allow_non_overlapping_authority);
  writer.boolean(policy.fence_lower_epoch_claimants);
  writer.boolean(policy.equal_epoch_conflict_is_fatal);
  writer.u64(policy.lease_default_horizon_steps);
  return std::move(writer).take();
}

Status decode_policy(CanonicalReader& reader, ArbiterPolicy& policy) {
  std::string id;
  if (auto st = reader.text(id); !st.is_ok()) return st;
  auto policy_id = PolicyId::try_make(id);
  if (!policy_id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  policy.policy = *policy_id;
  if (auto st = reader.counter(policy.generation); !st.is_ok()) return st;
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  CanonicalReader nested(blob);
  if (auto st = decode(nested, policy.quorum); !st.is_ok()) return st;
  if (auto st = nested.finish(); !st.is_ok()) return st;
  if (auto st = reader.boolean(policy.require_quorum_for_exclusive); !st.is_ok()) return st;
  if (auto st = reader.boolean(policy.require_lease_for_exclusive); !st.is_ok()) return st;
  if (auto st = reader.boolean(policy.allow_non_overlapping_authority); !st.is_ok()) return st;
  if (auto st = reader.boolean(policy.fence_lower_epoch_claimants); !st.is_ok()) return st;
  if (auto st = reader.boolean(policy.equal_epoch_conflict_is_fatal); !st.is_ok()) return st;
  return reader.u64(policy.lease_default_horizon_steps);
}

std::string encode_extent_state(const ExtentFenceState& state) {
  CanonicalWriter writer;
  writer.text(state.extent.view());
  writer.counter(state.high_water_token);
  writer.counter(state.high_water_epoch);
  writer.counter(state.owner_incarnation);
  writer.counter(state.owner_grant);
  writer.counter(state.updated_at);
  return std::move(writer).take();
}

Status decode_extent_state(CanonicalReader& reader, ExtentFenceState& state) {
  std::string extent;
  if (auto st = reader.text(extent); !st.is_ok()) return st;
  auto id = ExtentId::try_make(extent);
  if (!id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  state.extent = *id;
  if (auto st = reader.counter(state.high_water_token); !st.is_ok()) return st;
  if (auto st = reader.counter(state.high_water_epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(state.owner_incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(state.owner_grant); !st.is_ok()) return st;
  return reader.counter(state.updated_at);
}

}  // namespace

std::string encode_fence_payload(const FenceRecord& record, const Scope& scope) {
  CanonicalWriter writer;
  writer.counter(record.token);
  writer.text(record.domain.view());
  writer.digest(record.scope);
  writer.blob(encode(scope));
  writer.counter(record.fenced_epoch);
  writer.counter(record.fenced_incarnation);
  writer.reason(record.cause);
  writer.counter(record.issued_at);
  writer.counter(record.superseded_grant);
  writer.counter(record.registry_sequence);
  writer.counter(record.previous_high_water);
  return std::move(writer).take();
}

Status decode_fence_payload(CanonicalReader& reader, FenceRecord& record, Scope& scope) {
  if (auto st = reader.counter(record.token); !st.is_ok()) return st;
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto domain_id = DomainId::try_make(domain);
  if (!domain_id.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  record.domain = *domain_id;
  if (auto st = reader.digest(record.scope); !st.is_ok()) return st;
  if (auto st = decode_scope_blob(reader, scope); !st.is_ok()) return st;
  if (!(scope.digest() == record.scope)) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch);
  }
  if (auto st = reader.counter(record.fenced_epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(record.fenced_incarnation); !st.is_ok()) return st;
  if (auto st = reader.reason(record.cause); !st.is_ok()) return st;
  if (auto st = reader.counter(record.issued_at); !st.is_ok()) return st;
  if (auto st = reader.counter(record.superseded_grant); !st.is_ok()) return st;
  if (auto st = reader.counter(record.registry_sequence); !st.is_ok()) return st;
  return reader.counter(record.previous_high_water);
}

std::string claim_id_for_grant(const EpochGrant& grant) {
  std::string out = "claim-";
  out.append(grant.domain.view());
  out.append("-");
  const std::string hex = text::hex_u64(grant.id.value());
  out.append(hex.size() > 2 ? hex.substr(2) : hex);
  if (out.size() > limits::kMaxIdLength) out.resize(limits::kMaxIdLength);
  return out;
}

// ---- state -------------------------------------------------------------------

Status RegistryState::initialise(const RegistryConfig& config, StepClock clock, BootRecord boot) {
  if (config.store_id.empty() || config.node.empty()) {
    return Status::make(Outcome::Invalid, Reason::EmptyValue);
  }
  if (auto st = config.policy.validate(); !st.is_ok()) return st;
  if (config.lease_horizon_steps.is_none() ||
      config.lease_horizon_steps.value() > limits::kMaxLeaseHorizonSteps) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange,
                        config.lease_horizon_steps.value());
  }
  config_ = config;
  store_id_ = config.store_id;
  clock_ = clock;
  last_step_ = clock.now();
  boot_ = boot;
  policy_ = config.policy;
  registry_sequence_ = Sequence{0};
  phase_ = RegistryPhase::Ready;
  return Status::ok();
}

Status RegistryState::emit(std::vector<JournalRecord>& out_records, RecordKind kind,
                           std::string payload, Status status, Step now) {
  JournalRecord record;
  record.kind = kind;
  record.sequence = Sequence{registry_sequence_.value() + 1};
  record.step = now;
  record.status = status;
  record.payload = std::move(payload);
  // The record is applied to in-memory state through exactly the same code path
  // that recovery uses, so live state and replayed state cannot diverge.
  if (auto st = apply(record); !st.is_ok()) return st;
  generation_.try_increment();
  out_records.push_back(std::move(record));
  return Status::ok();
}

Status RegistryState::apply(const JournalRecord& record) {
  if (!record.sequence.is_set()) {
    return Status::make(Outcome::Corrupt, Reason::ValueOutOfRange);
  }
  if (record.sequence.value() > registry_sequence_.value() + 1) {
    return Status::make(Outcome::Corrupt, Reason::SequenceRegression, record.sequence.value());
  }
  registry_sequence_ = record.sequence;
  if (record.step > last_step_) last_step_ = record.step;
  clock_.observe_persisted(record.step);

  switch (record.kind) {
    case RecordKind::StoreHeader:
    case RecordKind::StoreIdAssign:
    case RecordKind::StepAdvance:
      return Status::ok();
    case RecordKind::BootBegin: {
      CanonicalReader reader(record.payload);
      BootRecord boot;
      if (auto st = decode_boot_record(reader, boot); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      boot_ = boot;
      if (boot.incarnation.value() > incarnation_counter_.value()) {
        incarnation_counter_ = BootId{boot.incarnation.value()};
      }
      auto st = lineage_.begin_boot(boot);
      if (st.outcome == Outcome::AlreadyExists) return Status::ok();
      return st;
    }
    case RecordKind::BootEnd: {
      CanonicalReader reader(record.payload);
      BootRecord boot;
      if (auto st = decode_boot_record(reader, boot); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      auto st = lineage_.end_boot(boot.boot, boot.ended_at, boot.clean_stop);
      if (st.outcome == Outcome::AlreadyExists) return Status::ok();
      return st;
    }
    case RecordKind::PolicyDefine: {
      CanonicalReader reader(record.payload);
      ArbiterPolicy policy;
      if (auto st = decode_policy(reader, policy); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      policy_ = policy;
      return Status::ok();
    }
    case RecordKind::DomainDefine: {
      CanonicalReader reader(record.payload);
      DomainDefinition definition;
      if (auto st = decode_domain(reader, definition); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      const auto it = domains_.find(definition.domain);
      if (it != domains_.end()) {
        if (it->second.scope == definition.scope && it->second.node == definition.node &&
            it->second.policy == definition.policy &&
            it->second.exclusive == definition.exclusive) {
          return Status::ok();
        }
        return Status::make(Outcome::Corrupt, Reason::DuplicateEntry);
      }
      if (domains_.size() >= limits::kMaxDomains) {
        return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, domains_.size());
      }
      domains_.emplace(definition.domain, definition);
      remember_scope(definition.scope);
      return Status::ok();
    }
    case RecordKind::GrantOpen: {
      CanonicalReader reader(record.payload);
      EpochGrant grant;
      if (auto st = decode_grant(reader, grant); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      if (grant.id > grant_counter_) grant_counter_ = grant.id;
      if (grant.fence_token > token_counter_) token_counter_ = grant.fence_token;
      return lineage_.open_grant(grant);
    }
    case RecordKind::GrantClose: {
      CanonicalReader reader(record.payload);
      EpochGrant grant;
      if (auto st = decode_grant(reader, grant); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      auto st = lineage_.close_grant(grant.id, grant.state, grant.close_reason, grant.closed_at);
      if (st.outcome == Outcome::AlreadyExists) return Status::ok();
      return st;
    }
    case RecordKind::Fence: {
      CanonicalReader reader(record.payload);
      FenceRecord fence;
      Scope scope;
      if (auto st = decode_fence_payload(reader, fence, scope); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      if (fence.token > token_counter_) token_counter_ = fence.token;
      remember_scope(scope);
      auto st = fences_.apply(fence, scope);
      if (st.outcome == Outcome::AlreadyExists) return Status::ok();
      return st;
    }
    case RecordKind::ExtentAdopt: {
      CanonicalReader reader(record.payload);
      FenceRecord fence;
      Scope scope;
      if (auto st = decode_fence_payload(reader, fence, scope); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      if (fence.token > token_counter_) token_counter_ = fence.token;
      remember_scope(scope);
      return fences_.adopt(scope, fence.token, fence.fenced_epoch, fence.fenced_incarnation,
                           fence.superseded_grant, fence.issued_at);
    }
    case RecordKind::CommitRecord: {
      ++commits_;
      return Status::ok();
    }
    case RecordKind::IncarnationAllocate: {
      CanonicalReader reader(record.payload);
      std::uint64_t value = 0;
      if (auto st = reader.u64(value); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      if (value <= incarnation_counter_.value()) {
        return Status::make(Outcome::Corrupt, Reason::SequenceRegression, value);
      }
      incarnation_counter_ = BootId{value};
      return Status::ok();
    }
    case RecordKind::InterruptMark: {
      CanonicalReader reader(record.payload);
      InterruptMark mark;
      if (auto st = decode_interrupt(reader, mark); !st.is_ok()) return st;
      if (auto st = reader.finish(); !st.is_ok()) return st;
      if (interrupts_.size() >= limits::kMaxInterruptedMarks) interrupts_.erase(interrupts_.begin());
      interrupts_.push_back(mark);
      return Status::ok();
    }
  }
  return Status::make(Outcome::Corrupt, Reason::InvalidEnum,
                      static_cast<std::uint16_t>(record.kind));
}

void RegistryState::remember_scope(const Scope& scope) {
  if (scope.empty()) return;
  const std::string key = scope.digest().hex();
  if (scopes_.size() >= limits::kMaxIndexedExtents) {
    // The table is bounded. Evicting an entry can only cost a diagnostic, never
    // authority: enforcement lives in the fence table and the effect boundary.
    auto it = scopes_.begin();
    if (it != scopes_.end() && it->first != key) scopes_.erase(it);
  }
  scopes_.emplace(key, scope);
}

bool RegistryState::has_scope(const Digest256& digest) const {
  return scopes_.find(digest.hex()) != scopes_.end();
}

Status RegistryState::rebuild() {
  if (auto st = fences_.validate(); !st.is_ok()) return st;
  if (auto st = lineage_.validate(); !st.is_ok()) return st;
  for (const auto& state : fences_.extents()) {
    if (state.high_water_token > token_counter_) token_counter_ = state.high_water_token;
  }
  for (const auto& grant : lineage_.grants()) {
    if (grant.id > grant_counter_) grant_counter_ = grant.id;
    if (grant.fence_token > token_counter_) token_counter_ = grant.fence_token;
  }
  for (const auto& record : fences_.records()) {
    if (record.token > token_counter_) token_counter_ = record.token;
  }
  // The effect boundary dominates the registry's own counters: if the durable
  // fabric log ever reached a higher token than this process remembers, the
  // registry resumes above it instead of reissuing a token that was already
  // used to mutate the fabric.
  for (const auto& extent : fabric_.fence_view().extents()) {
    if (extent.high_water_token > token_counter_) token_counter_ = extent.high_water_token;
  }
  for (const auto& record : fabric_.records()) {
    if (record.fence_token > token_counter_) token_counter_ = record.fence_token;
    if (record.grant > grant_counter_) grant_counter_ = record.grant;
  }
  for (const auto& boot : lineage_.boots()) {
    if (boot.incarnation.value() > incarnation_counter_.value()) {
      incarnation_counter_ = BootId{boot.incarnation.value()};
    }
  }
  for (const auto& mark : interrupts_) {
    if (mark.incarnation.value() > incarnation_counter_.value()) {
      incarnation_counter_ = BootId{mark.incarnation.value()};
    }
  }
  return policy_.validate();
}

Status RegistryState::fence_scope(const DomainId& domain, const Scope& scope, Epoch epoch,
                                  IncarnationId incarnation, GrantId superseded, Reason cause,
                                  bool fence_incarnation, Step now,
                                  std::vector<JournalRecord>& out_records, FenceToken& token_out) {
  if (token_counter_.value() == FenceToken::max_value()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  const FenceToken token{token_counter_.value() + 1};
  FenceToken previous;
  for (const auto& extent : scope.extents()) {
    const FenceToken high = fences_.high_water(extent);
    if (high > previous) previous = high;
  }
  FenceRecord record;
  record.token = token;
  record.domain = domain;
  record.scope = scope.digest();
  record.fenced_epoch = epoch;
  record.fenced_incarnation = fence_incarnation ? incarnation : IncarnationId{};
  record.cause = cause;
  record.issued_at = now;
  record.superseded_grant = superseded;
  record.registry_sequence = Sequence{registry_sequence_.value() + 1};
  record.previous_high_water = previous;
  if (auto st = emit(out_records, RecordKind::Fence, encode_fence_payload(record, scope),
                     Status::make(Outcome::Fenced, cause, token.value()), now);
      !st.is_ok()) {
    return st;
  }
  token_out = token;
  return Status::ok();
}

Status RegistryState::close_grant(EpochGrant grant, GrantState state, Reason reason, Step now,
                                  std::vector<JournalRecord>& out_records) {
  grant.state = state;
  grant.close_reason = reason;
  grant.closed_at = now;
  grant.registry_sequence = Sequence{registry_sequence_.value() + 1};
  return emit(out_records, RecordKind::GrantClose, encode_grant(grant),
              Status::make(Outcome::Fenced, reason), now);
}

Status RegistryState::recover_after_restart(std::vector<JournalRecord>& out_records, Step now) {
  // Close every previous boot that was still open. A boot with a durable end
  // record keeps the outcome that is already recorded.
  for (auto record : lineage_.boots()) {
    if (!record.ended_at.is_set()) {
      record.ended_at = now;
      record.clean_stop = false;
      record.interrupted = true;
      if (auto st = emit(out_records, RecordKind::BootEnd, encode_boot_record(record),
                         Status::make(Outcome::Interrupted, Reason::InterruptedByRestart), now);
          !st.is_ok()) {
        return st;
      }
    }
  }

  // Fence every grant that was open when the process died. The pre-restart
  // incarnation is recorded in the fence table and can never act again.
  const std::vector<const EpochGrant*> open = lineage_.open_grants();
  for (const EpochGrant* grant : open) {
    const EpochGrant snapshot = *grant;
    FenceToken token;
    if (auto st = fence_scope(snapshot.domain, snapshot.extents, snapshot.epoch,
                              snapshot.incarnation, snapshot.id, Reason::InterruptedByRestart, true,
                              now, out_records, token);
        !st.is_ok()) {
      return st;
    }
    InterruptMark mark;
    mark.grant = snapshot.id;
    mark.domain = snapshot.domain;
    mark.epoch = snapshot.epoch;
    mark.incarnation = snapshot.incarnation;
    mark.boot = snapshot.boot;
    mark.marked_at = now;
    mark.reason = Reason::InterruptedByRestart;
    if (auto st = emit(out_records, RecordKind::InterruptMark, encode_interrupt(mark),
                       Status::make(Outcome::Interrupted, Reason::InterruptedByRestart), now);
        !st.is_ok()) {
      return st;
    }
    if (auto st = close_grant(snapshot, GrantState::Interrupted, Reason::InterruptedByRestart, now,
                              out_records);
        !st.is_ok()) {
      return st;
    }
    ++restart_fences_;
  }

  if (incarnation_counter_.value() == BootId::max_value()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  const BootId next{incarnation_counter_.value() + 1};
  incarnation_counter_ = next;
  BootRecord fresh;
  fresh.boot = next;
  fresh.incarnation = IncarnationId{next.value()};
  fresh.node = config_.node;
  fresh.started_at = now;
  fresh.registry_sequence = Sequence{registry_sequence_.value() + 1};
  return emit(out_records, RecordKind::BootBegin, encode_boot_record(fresh), Status::ok(), now);
}

Status RegistryState::allocate_incarnation(std::vector<JournalRecord>& out_records, Step now,
                                          IncarnationId& out) {
  if (incarnation_counter_.value() == BootId::max_value()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  const std::uint64_t next = incarnation_counter_.value() + 1;
  CanonicalWriter writer;
  writer.u64(next);
  if (auto st = emit(out_records, RecordKind::IncarnationAllocate, std::move(writer).take(),
                     Status::ok(), now);
      !st.is_ok()) {
    return st;
  }
  out = IncarnationId{next};
  return Status::ok();
}

Status RegistryState::define_domain(const DomainDefinition& definition,
                                    std::vector<JournalRecord>& out_records, Step now) {
  if (definition.domain.empty() || definition.node.empty()) {
    return Status::make(Outcome::Invalid, Reason::EmptyValue);
  }
  if (definition.scope.empty()) {
    return Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
  }
  const auto it = domains_.find(definition.domain);
  if (it != domains_.end()) {
    if (it->second.scope == definition.scope && it->second.node == definition.node &&
        it->second.policy == definition.policy && it->second.exclusive == definition.exclusive) {
      return Status::ok();
    }
    return Status::make(Outcome::AlreadyExists, Reason::DuplicateEntry);
  }
  if (domains_.size() >= limits::kMaxDomains) {
    return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, domains_.size());
  }
  return emit(out_records, RecordKind::DomainDefine, encode_domain(definition), Status::ok(), now);
}

Status RegistryState::define_policy(const ArbiterPolicy& policy,
                                    std::vector<JournalRecord>& out_records, Step now) {
  if (auto st = policy.validate(); !st.is_ok()) return st;
  ArbiterPolicy next = policy;
  next.generation = Generation{policy_.generation.value() + 1};
  return emit(out_records, RecordKind::PolicyDefine, encode_policy(next), Status::ok(), now);
}

Status RegistryState::allocate_epoch(const AllocateEpochRequest& request,
                                     AllocateEpochResponse& response,
                                     std::vector<JournalRecord>& out_records, Step now) {
  response = AllocateEpochResponse{};
  if (request.domain.empty()) {
    response.status = Status::make(Outcome::Invalid, Reason::DomainNotRegistered);
    return response.status;
  }
  if (request.scope.empty()) {
    response.status = Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
    return response.status;
  }
  if (request.incarnation.is_none() || request.boot.is_none()) {
    response.status = Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
    return response.status;
  }
  const auto domain_it = domains_.find(request.domain);
  if (domain_it == domains_.end()) {
    response.status = Status::make(Outcome::NotFound, Reason::DomainNotRegistered);
    return response.status;
  }
  if (!(domain_it->second.scope == request.scope)) {
    // A domain may only claim the exact scope it was registered for. Anything
    // else would let a caller silently widen its own authority.
    response.status = Status::make(Outcome::Invalid, Reason::ScopeNotRegistered);
    return response.status;
  }
  if (fences_.incarnation_fenced(request.incarnation)) {
    // A previously fenced incarnation can never return to authority, not even
    // by asking again.
    response.status = Status::make(Outcome::Fenced, Reason::IncarnationFenced,
                                   request.incarnation.value());
    return response.status;
  }
  // Incarnations are issued monotonically and journalled before use. One above
  // the durable counter was never issued, and one at or below the boot
  // incarnation predates this process: neither may allocate.
  if (request.incarnation.value() > incarnation_counter_.value() ||
      request.incarnation.value() <= boot_.incarnation.value()) {
    response.status = Status::make(Outcome::Fenced, Reason::IncarnationNotCurrent,
                                   incarnation_counter_.value());
    return response.status;
  }

  // Idempotency: a retried allocation for the same (incarnation, attempt) that
  // is still open returns the very same grant instead of churning the epoch.
  for (const auto& grant : lineage_.grants()) {
    if (grant.incarnation == request.incarnation && grant.attempt == request.attempt_sequence &&
        grant.domain == request.domain && grant.state == GrantState::Open) {
      response.epoch = grant.epoch;
      response.fence_token = grant.fence_token;
      response.grant = grant.id;
      response.lineage_generation = lineage_.generation();
      response.policy_generation = policy_.generation;
      response.fence_generation = fences_.generation();
      response.valid_until = Step{now.value() + config_.lease_horizon_steps.value()};
      response.policy = policy_.policy;
      response.allocation_step = now;
      response.status = Status::ok();
      ++idempotency_hits_;
      return response.status;
    }
  }

  // Fence every open grant that overlaps the requested scope, whichever domain
  // owns it. This is what makes overlapping exclusive authority structurally
  // impossible rather than merely unlikely.
  for (const EpochGrant* grant : lineage_.open_grants()) {
    if (!grant->extents.overlaps(request.scope)) continue;
    const EpochGrant snapshot = *grant;
    FenceToken token;
    // Superseding a live process's own previous epoch must not disqualify that
    // process: only a *different* incarnation is fenced here.
    const bool fence_predecessor = !(snapshot.incarnation == request.incarnation);
    if (auto st = fence_scope(snapshot.domain, snapshot.extents, snapshot.epoch,
                              snapshot.incarnation, snapshot.id,
                              Reason::CompensatingFenceRequired, fence_predecessor, now,
                              out_records, token);
        !st.is_ok()) {
      response.status = st;
      return response.status;
    }
    if (auto st = close_grant(snapshot, GrantState::Fenced, Reason::CompensatingFenceRequired, now,
                              out_records);
        !st.is_ok()) {
      response.status = st;
      return response.status;
    }
  }

  const Epoch next_epoch = Epoch{lineage_.max_epoch(request.domain).value() + 1};
  if (next_epoch.is_none()) {
    response.status = Status::make(Outcome::Exhausted, Reason::CounterOverflow);
    return response.status;
  }
  if (token_counter_.value() == FenceToken::max_value() ||
      grant_counter_.value() == GrantId::max_value()) {
    response.status = Status::make(Outcome::Exhausted, Reason::CounterOverflow);
    return response.status;
  }
  const FenceToken token{token_counter_.value() + 1};
  const GrantId grant_id{grant_counter_.value() + 1};

  EpochGrant grant;
  grant.id = grant_id;
  grant.domain = request.domain;
  grant.scope = request.scope.digest();
  grant.extents = request.scope;
  grant.attempt = request.attempt_sequence;
  grant.epoch = next_epoch;
  grant.incarnation = request.incarnation;
  grant.boot = request.boot;
  grant.fence_token = token;
  grant.opened_at = now;
  grant.state = GrantState::Open;
  grant.registry_sequence = Sequence{registry_sequence_.value() + 1};
  grant.lineage_generation = Generation{lineage_.generation().value() + 1};
  grant.policy_generation = policy_.generation;
  grant.evidence_generation = Generation{};

  // 1. adopt the scope under the new token.
  FenceRecord adopt;
  adopt.token = token;
  adopt.domain = request.domain;
  adopt.scope = request.scope.digest();
  adopt.fenced_epoch = next_epoch;
  adopt.fenced_incarnation = request.incarnation;
  adopt.cause = Reason::None;
  adopt.issued_at = now;
  adopt.superseded_grant = grant_id;
  adopt.registry_sequence = Sequence{registry_sequence_.value() + 1};
  if (auto st = emit(out_records, RecordKind::ExtentAdopt, encode_fence_payload(adopt, request.scope),
                     Status::ok(), now);
      !st.is_ok()) {
    response.status = st;
    return response.status;
  }
  // 2. open the grant.
  if (auto st = emit(out_records, RecordKind::GrantOpen, encode_grant(grant), Status::ok(), now);
      !st.is_ok()) {
    response.status = st;
    return response.status;
  }

  response.status = Status::ok();
  response.epoch = next_epoch;
  response.fence_token = token;
  response.grant = grant_id;
  response.valid_until = Step{now.value() + config_.lease_horizon_steps.value()};
  response.lineage_generation = lineage_.generation();
  response.policy_generation = policy_.generation;
  response.fence_generation = fences_.generation();
  response.policy = policy_.policy;
  response.allocation_step = now;
  return response.status;
}

Status RegistryState::decide(const DecideRequest& request, DecideResponse& response, Step now) {
  response = DecideResponse{};
  if (request.domain.empty() || request.scope.empty()) {
    response.status = Status::make(Outcome::Invalid, Reason::EmptyValue);
    return response.status;
  }
  const auto domain_it = domains_.find(request.domain);
  if (domain_it == domains_.end()) {
    response.status = Status::make(Outcome::NotFound, Reason::DomainNotRegistered);
    return response.status;
  }
  if (!(domain_it->second.scope == request.scope)) {
    response.status = Status::make(Outcome::Invalid, Reason::ScopeNotRegistered);
    return response.status;
  }

  const EpochGrant* grant = nullptr;
  for (const auto& candidate : lineage_.grants()) {
    if (candidate.domain == request.domain && candidate.epoch == request.epoch &&
        candidate.incarnation == request.incarnation && candidate.state == GrantState::Open &&
        candidate.extents == request.scope) {
      grant = &candidate;
      break;
    }
  }
  if (grant == nullptr) {
    // Either the epoch was never opened, was superseded, or the process was
    // fenced. All three are refusals, and the reason distinguishes them.
    const Epoch highest = lineage_.max_epoch(request.domain);
    if (request.epoch < highest) {
      response.status = Status::make(Outcome::Stale, Reason::StaleEpoch, highest.value());
    } else if (fences_.incarnation_fenced(request.incarnation)) {
      response.status = Status::make(Outcome::Fenced, Reason::IncarnationFenced,
                                     request.incarnation.value());
    } else {
      response.status = Status::make(Outcome::Fenced, Reason::ExtentFenced);
    }
    response.decision.verdict = response.status.outcome == Outcome::Stale
                                    ? AuthorityVerdict::Stale
                                    : AuthorityVerdict::Fenced;
    response.decision.status = response.status;
    response.decision.explanation.add(response.status.reason);
    // The subject is identified as far as it can be: the domain and scope are
    // known even though no open grant matched, and the decision deliberately
    // names no claim because none was found.
    response.decision.claim = ClaimId{};
    response.decision.scope = request.scope;
    response.decision.vector.domain = request.domain;
    response.decision.vector.scope = request.scope.digest();
    response.decision.vector.epoch = request.epoch;
    response.decision.vector.incarnation = request.incarnation;
    response.decision.vector.fence_token = request.presented_fence_token;
    return response.status;
  }
  if (!(grant->fence_token == request.presented_fence_token)) {
    response.status = Status::make(Outcome::Fenced, Reason::FenceTokenRegressed,
                                   grant->fence_token.value());
    response.decision.verdict = AuthorityVerdict::Fenced;
    response.decision.status = response.status;
    response.decision.explanation.add(Reason::FenceTokenRegressed);
    response.decision.claim = ClaimId::make(claim_id_for_grant(*grant));
    response.decision.scope = grant->extents;
    response.decision.vector.domain = grant->domain;
    response.decision.vector.scope = grant->scope;
    response.decision.vector.epoch = grant->epoch;
    response.decision.vector.incarnation = grant->incarnation;
    response.decision.vector.fence_token = grant->fence_token;
    response.decision.vector.grant = grant->id;
    return response.status;
  }

  AuthorityRequest authority;
  authority.claim = ClaimId::make(claim_id_for_grant(*grant));
  authority.domain = request.domain;
  authority.scope = request.scope;
  authority.epoch = request.epoch;
  authority.incarnation = request.incarnation;
  authority.boot = request.boot;
  authority.presented_fence_token = request.presented_fence_token;
  authority.mode = request.mode;
  authority.attempt_sequence = request.attempt_sequence;
  authority.evidence = request.evidence;
  // The registry's own logical step is used, not the caller's, so a caller can
  // neither rewind nor fast-forward the window its evidence is judged in.
  authority.evidence.as_of = now;
  authority.requested_at = request.requested_at;

  ArbiterView view;
  view.policy = &policy_;
  view.fences = &fences_;
  view.lineage = &lineage_;
  view.now = now;
  view.registry_generation = generation_;
  view.domain_generation = Generation{static_cast<std::uint64_t>(domains_.size())};
  for (const EpochGrant* other : lineage_.open_grants()) {
    if (other->id == grant->id) continue;
    CompetingClaim claim;
    claim.claim = ClaimId::make(claim_id_for_grant(*other));
    claim.domain = other->domain;
    claim.scope = other->extents;
    claim.epoch = other->epoch;
    claim.incarnation = other->incarnation;
    claim.fence_token = other->fence_token;
    claim.grant = other->id;
    claim.mode = AuthorityMode::ExclusiveMutation;
    // The registry's own durable grant is current evidence of registry-side
    // authority; it is not an assumption about another process's liveness.
    claim.evidence_state = EvidenceState::Current;
    claim.active = true;
    view.competing.push_back(claim);
  }

  response.decision = decide_authority(authority, view);
  response.status = response.decision.status;
  if (response.decision.is_authoritative()) {
    response.decision.valid_until = Step{now.value() + config_.lease_horizon_steps.value()};
  }
  return response.status;
}

Status RegistryState::commit(const CommitRequest& request, CommitResponse& response,
                             std::vector<JournalRecord>& out_records, Step now) {
  response = CommitResponse{};
  if (request.domain.empty() || request.scope.empty()) {
    response.status = Status::make(Outcome::Invalid, Reason::EmptyValue);
    return response.status;
  }
  if (request.operation.empty() || request.operation.size() > limits::kMaxTextLength) {
    response.status = Status::make(Outcome::Invalid, Reason::ValueOutOfRange,
                                   request.operation.size());
    return response.status;
  }
  const auto domain_it = domains_.find(request.domain);
  if (domain_it == domains_.end()) {
    response.status = Status::make(Outcome::NotFound, Reason::DomainNotRegistered);
    return response.status;
  }
  if (!(domain_it->second.scope == request.scope)) {
    response.status = Status::make(Outcome::Invalid, Reason::ScopeNotRegistered);
    return response.status;
  }
  const EpochGrant* grant = lineage_.find(request.grant);
  if (grant == nullptr || grant->state != GrantState::Open) {
    response.status = Status::make(Outcome::Fenced, Reason::ExtentFenced,
                                   request.grant.value());
    return response.status;
  }
  if (!(grant->domain == request.domain) || !(grant->extents == request.scope) ||
      grant->epoch != request.epoch || grant->incarnation != request.incarnation) {
    // The grant exists but does not authorise this subject. Identity is not
    // authority: every binding is compared.
    response.status = Status::make(Outcome::Invalid, Reason::StoreOwnerMismatch);
    return response.status;
  }
  if (!(grant->fence_token == request.fence_token)) {
    response.status = Status::make(Outcome::Fenced, Reason::FenceTokenRegressed,
                                   grant->fence_token.value());
    return response.status;
  }

  MutationRecord record;
  const Status admitted =
      fabric_.admit(request.domain, request.fence_token, request.scope, request.epoch,
                    request.incarnation, request.grant, request.operation,
                    request.payload_digest, now, record);
  if (!admitted.is_ok()) {
    response.status = admitted;
    return response.status;
  }

  CanonicalWriter writer;
  writer.counter(record.store_sequence);
  writer.digest(record.record_digest);
  if (auto st = emit(out_records, RecordKind::CommitRecord, std::move(writer).take(),
                     Status::ok(), now);
      !st.is_ok()) {
    response.status = st;
    return response.status;
  }

  response.status = Status::ok();
  response.store_sequence = record.store_sequence;
  response.admitted_token = record.fence_token;
  response.effect_digest = record.record_digest;
  // "Verified" means the record was read back from the durable log file. The
  // bytes have been flushed to the operating system, not necessarily to media;
  // see the README's durability statement.
  response.verified = true;
  return response.status;
}

Status RegistryState::fence(const FenceRequest& request, FenceResponse& response,
                            std::vector<JournalRecord>& out_records, Step now) {
  response = FenceResponse{};
  if (request.domain.empty() || request.scope.empty()) {
    response.status = Status::make(Outcome::Invalid, Reason::EmptyValue);
    return response.status;
  }
  const auto domain_it = domains_.find(request.domain);
  if (domain_it == domains_.end()) {
    response.status = Status::make(Outcome::NotFound, Reason::DomainNotRegistered);
    return response.status;
  }
  if (!(domain_it->second.scope == request.scope)) {
    response.status = Status::make(Outcome::Invalid, Reason::ScopeNotRegistered);
    return response.status;
  }

  bool fenced_any = false;
  for (const EpochGrant* grant : lineage_.open_grants()) {
    if (!(grant->domain == request.domain)) continue;
    if (!(grant->extents == request.scope)) continue;
    if (request.epoch.is_set() && !(grant->epoch == request.epoch)) continue;
    const EpochGrant snapshot = *grant;
    FenceToken token;
    if (auto st = fence_scope(snapshot.domain, snapshot.extents, snapshot.epoch,
                              snapshot.incarnation, snapshot.id,
                              request.cause == Reason::None ? Reason::ExtentFenced : request.cause,
                              true, now, out_records, token);
        !st.is_ok()) {
      response.status = st;
      return response.status;
    }
    response.new_high_water = token;
    if (auto st = close_grant(snapshot, GrantState::Fenced,
                              request.cause == Reason::None ? Reason::ExtentFenced : request.cause,
                              now, out_records);
        !st.is_ok()) {
      response.status = st;
      return response.status;
    }
    fenced_any = true;
  }
  if (!fenced_any) {
    // Fencing a scope with no open grant is still meaningful: it raises the
    // durable high-water mark so that any late writer is refused.
    FenceToken token;
    if (auto st = fence_scope(request.domain, request.scope, request.epoch,
                              request.incarnation, GrantId{},
                              request.cause == Reason::None ? Reason::ExtentFenced : request.cause,
                              true, now, out_records, token);
        !st.is_ok()) {
      response.status = st;
      return response.status;
    }
    response.new_high_water = token;
  }
  response.registry_sequence = registry_sequence_;
  response.status = Status::ok();
  return response.status;
}

Status RegistryState::release(const ReleaseRequest& request, ReleaseResponse& response,
                              std::vector<JournalRecord>& out_records, Step now) {
  response = ReleaseResponse{};
  const EpochGrant* grant = lineage_.find(request.grant);
  if (grant == nullptr) {
    response.status = Status::make(Outcome::NotFound, Reason::GrantNotRegistered,
                                   request.grant.value());
    return response.status;
  }
  if (grant->state != GrantState::Open) {
    response.status = Status::make(Outcome::AlreadyExists, Reason::DuplicateEntry,
                                   request.grant.value());
    response.closed_epoch = grant->epoch;
    return response.status;
  }
  const EpochGrant snapshot = *grant;
  // Releasing raises the high-water mark: after this point any late mutation
  // from the released incarnation is refused by the effect boundary.
  FenceToken token;
  const Reason cause = request.cause == Reason::None ? Reason::CompensatingFenceRequired
                                                     : request.cause;
  if (auto st = fence_scope(snapshot.domain, snapshot.extents, snapshot.epoch,
                            snapshot.incarnation, snapshot.id, cause, true, now, out_records,
                            token);
      !st.is_ok()) {
    response.status = st;
    return response.status;
  }
  if (auto st = close_grant(snapshot, GrantState::Closed, cause, now, out_records); !st.is_ok()) {
    response.status = st;
    return response.status;
  }
  response.status = Status::ok();
  response.closed_epoch = snapshot.epoch;
  response.new_high_water = token;
  return response.status;
}

std::string RegistryState::serialize() const {
  CanonicalWriter writer;
  writer.u32(kStateFormatVersion);
  writer.text(store_id_.view());
  writer.counter(clock_.now());
  writer.counter(last_step_);
  writer.blob(encode_boot_record(boot_));
  writer.counter(incarnation_counter_);
  writer.counter(token_counter_);
  writer.counter(grant_counter_);
  writer.counter(registry_sequence_);
  writer.counter(generation_);
  writer.u64(commits_);
  writer.blob(encode_policy(policy_));
  writer.sequence(domains_.size(), [&](std::size_t i) {
    auto it = domains_.begin();
    std::advance(it, static_cast<std::ptrdiff_t>(i));
    writer.blob(encode_domain(it->second));
  });
  const auto& extents = fences_.extents();
  writer.sequence(extents.size(), [&](std::size_t i) { writer.blob(encode_extent_state(extents[i])); });
  const auto& fence_records = fences_.records();
  writer.sequence(fence_records.size(), [&](std::size_t i) {
    // Every fence record's extent list is retained in the durable scope table,
    // so the record round-trips with full fidelity.
    const auto it = scopes_.find(fence_records[i].scope.hex());
    const Scope empty;
    writer.blob(encode_fence_payload(fence_records[i],
                                     it == scopes_.end() ? empty : it->second));
  });
  const auto& grants = lineage_.grants();
  writer.sequence(grants.size(), [&](std::size_t i) { writer.blob(encode_grant(grants[i])); });
  const auto& boots = lineage_.boots();
  writer.sequence(boots.size(), [&](std::size_t i) { writer.blob(encode_boot_record(boots[i])); });
  writer.sequence(idempotency_.size(),
                  [&](std::size_t i) { writer.blob(encode_idempotency(idempotency_[i])); });
  writer.sequence(interrupts_.size(),
                  [&](std::size_t i) { writer.blob(encode_interrupt(interrupts_[i])); });
  const std::string body = std::move(writer).take();
  std::string out = body;
  CanonicalWriter trailer;
  trailer.digest(Digest256::of(body));
  out.append(trailer.bytes());
  return out;
}

Status RegistryState::deserialize(std::string_view bytes) {
  if (bytes.size() < 32) return Status::make(Outcome::Corrupt, Reason::TruncatedFrame);
  const std::string_view body = bytes.substr(0, bytes.size() - 32);
  CanonicalReader trailer(bytes.substr(bytes.size() - 32));
  Digest256 expected;
  if (auto st = trailer.digest(expected); !st.is_ok()) return st;
  if (!(expected == Digest256::of(body))) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch);
  }

  CanonicalReader reader(body);
  std::uint32_t version = 0;
  if (auto st = reader.u32(version); !st.is_ok()) return st;
  if (version != kStateFormatVersion) {
    return Status::make(Outcome::Unsupported, Reason::UnsupportedVersion, version);
  }
  std::string store_id;
  if (auto st = reader.text(store_id); !st.is_ok()) return st;
  auto store_id_value = StoreId::try_make(store_id);
  if (!store_id_value.has_value()) return Status::make(Outcome::Corrupt, Reason::IdCharset);
  std::uint64_t clock_value = 0;
  std::uint64_t last_step = 0;
  if (auto st = reader.u64(clock_value); !st.is_ok()) return st;
  if (auto st = reader.u64(last_step); !st.is_ok()) return st;
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  BootRecord boot;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_boot_record(nested, boot); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::uint64_t incarnation_counter = 0;
  std::uint64_t token_counter = 0;
  std::uint64_t grant_counter = 0;
  std::uint64_t registry_sequence = 0;
  std::uint64_t generation = 0;
  std::uint64_t commits = 0;
  if (auto st = reader.u64(incarnation_counter); !st.is_ok()) return st;
  if (auto st = reader.u64(token_counter); !st.is_ok()) return st;
  if (auto st = reader.u64(grant_counter); !st.is_ok()) return st;
  if (auto st = reader.u64(registry_sequence); !st.is_ok()) return st;
  if (auto st = reader.u64(generation); !st.is_ok()) return st;
  if (auto st = reader.u64(commits); !st.is_ok()) return st;

  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  ArbiterPolicy policy;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_policy(nested, policy); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }

  std::map<DomainId, DomainDefinition> domains;
  std::uint32_t domain_count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxDomains), domain_count);
      !st.is_ok()) {
    return st;
  }
  for (std::uint32_t i = 0; i < domain_count; ++i) {
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    DomainDefinition definition;
    if (auto st = decode_domain(nested, definition); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    if (!domains.emplace(definition.domain, definition).second) {
      return Status::make(Outcome::Corrupt, Reason::DuplicateEntry);
    }
  }

  std::vector<ExtentFenceState> extents;
  std::uint32_t extent_count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxIndexedExtents), extent_count);
      !st.is_ok()) {
    return st;
  }
  extents.reserve(extent_count);
  for (std::uint32_t i = 0; i < extent_count; ++i) {
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    ExtentFenceState state;
    if (auto st = decode_extent_state(nested, state); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    extents.push_back(state);
  }

  std::vector<FenceRecord> fence_records;
  std::uint32_t fence_count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxFenceRecords), fence_count);
      !st.is_ok()) {
    return st;
  }
  fence_records.reserve(fence_count);
  for (std::uint32_t i = 0; i < fence_count; ++i) {
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    FenceRecord record;
    Scope scope;
    if (auto st = decode_fence_payload(nested, record, scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    fence_records.push_back(record);
  }

  std::vector<EpochGrant> grants;
  std::uint32_t grant_count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxLineageEntries), grant_count);
      !st.is_ok()) {
    return st;
  }
  grants.reserve(grant_count);
  for (std::uint32_t i = 0; i < grant_count; ++i) {
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    EpochGrant grant;
    if (auto st = decode_grant(nested, grant); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    grants.push_back(grant);
  }

  std::vector<BootRecord> boots;
  std::uint32_t boot_count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxLineageEntries), boot_count);
      !st.is_ok()) {
    return st;
  }
  boots.reserve(boot_count);
  for (std::uint32_t i = 0; i < boot_count; ++i) {
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    BootRecord record;
    if (auto st = decode_boot_record(nested, record); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    boots.push_back(record);
  }

  std::vector<IdempotencyEntry> idempotency;
  std::uint32_t idempotency_count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxDedupEntries),
                             idempotency_count);
      !st.is_ok()) {
    return st;
  }
  idempotency.reserve(idempotency_count);
  for (std::uint32_t i = 0; i < idempotency_count; ++i) {
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    IdempotencyEntry entry;
    if (auto st = decode_idempotency(nested, entry); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    idempotency.push_back(entry);
  }

  std::vector<InterruptMark> interrupts;
  std::uint32_t interrupt_count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxInterruptedMarks),
                             interrupt_count);
      !st.is_ok()) {
    return st;
  }
  interrupts.reserve(interrupt_count);
  for (std::uint32_t i = 0; i < interrupt_count; ++i) {
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    InterruptMark mark;
    if (auto st = decode_interrupt(nested, mark); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    interrupts.push_back(mark);
  }
  if (auto st = reader.finish(); !st.is_ok()) return st;

  FenceTable fences;
  if (auto st = fences.import(extents, fence_records); !st.is_ok()) return st;
  LineageTable lineage;
  if (auto st = lineage.import(grants, boots); !st.is_ok()) return st;

  store_id_ = *store_id_value;
  clock_ = StepClock{};
  clock_.observe_persisted(Step{clock_value});
  last_step_ = Step{last_step};
  boot_ = boot;
  incarnation_counter_ = BootId{incarnation_counter};
  token_counter_ = FenceToken{token_counter};
  grant_counter_ = GrantId{grant_counter};
  registry_sequence_ = Sequence{registry_sequence};
  generation_ = Generation{generation == 0 ? 1 : generation};
  commits_ = commits;
  policy_ = policy;
  domains_ = std::move(domains);
  fences_ = std::move(fences);
  lineage_ = std::move(lineage);
  idempotency_ = std::move(idempotency);
  interrupts_ = std::move(interrupts);
  scopes_.clear();
  for (const auto& [id, definition] : domains_) remember_scope(definition.scope);
  for (const auto& grant : lineage_.grants()) remember_scope(grant.extents);
  if (auto st = rebuild(); !st.is_ok()) return st;
  // A fence record whose extents cannot be resolved would make a future
  // checkpoint lossy, so that is refused here rather than discovered later.
  for (const auto& record : fences_.records()) {
    if (!record.scope.bytes().empty() && !has_scope(record.scope)) {
      return Status::make(Outcome::Corrupt, Reason::ScopeNotRegistered);
    }
  }
  return Status::ok();
}

}  // namespace sbf
