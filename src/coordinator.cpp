#include "sbf/coordinator.hpp"

#include <algorithm>
#include <string>

#include "sbf/canonical.hpp"
#include "sbf/text.hpp"

namespace sbf {

std::string_view to_string(MutationOutcome outcome) noexcept {
  switch (outcome) {
    case MutationOutcome::Applied: return "APPLIED";
    case MutationOutcome::AcknowledgedNotVerified: return "ACKNOWLEDGED_NOT_VERIFIED";
    case MutationOutcome::Refused: return "REFUSED";
    case MutationOutcome::Fenced: return "FENCED";
    case MutationOutcome::Unknown: return "UNKNOWN";
    case MutationOutcome::Conflict: return "CONFLICT";
    case MutationOutcome::Invalid: return "INVALID";
    case MutationOutcome::Unreachable: return "UNREACHABLE";
    case MutationOutcome::Interrupted: return "INTERRUPTED";
  }
  return "UNKNOWN";
}

namespace {

MutationOutcome classify(const Status& status) noexcept {
  switch (status.outcome) {
    case Outcome::Ok: return MutationOutcome::Applied;
    case Outcome::Fenced: return MutationOutcome::Fenced;
    case Outcome::Conflict: return MutationOutcome::Conflict;
    case Outcome::Unknown: return MutationOutcome::Unknown;
    case Outcome::Unreachable:
    case Outcome::Closed:
      return MutationOutcome::Unreachable;
    case Outcome::Interrupted: return MutationOutcome::Interrupted;
    case Outcome::Invalid:
    case Outcome::Unsupported:
    case Outcome::Refused:
    case Outcome::Exhausted:
    case Outcome::Indeterminate:
    case Outcome::SearchLimitReached:
    case Outcome::NotFound:
    case Outcome::AlreadyExists:
    case Outcome::Corrupt:
      return MutationOutcome::Refused;
    case Outcome::Stale: return MutationOutcome::Fenced;
  }
  return MutationOutcome::Unknown;
}

Digest256 operation_digest(std::string_view operation, Sequence attempt) {
  CanonicalWriter writer;
  writer.text(operation);
  writer.counter(attempt);
  return Digest256::of(writer.bytes());
}

}  // namespace

Coordinator::Coordinator(CoordinatorConfig config) : config_(std::move(config)) {}

Coordinator::~Coordinator() { close(); }

Status Coordinator::connect(const HelloRequest& hello) {
  HelloRequest request = hello;
  request.node = config_.node;
  request.kind = ClientKind::Coordinator;
  request.client_protocol = kFrameVersion;
  if (auto st = client_.connect(config_.registry, request); !st.is_ok()) return st;
  boot_ = client_.binding().boot;
  incarnation_ = client_.binding().incarnation;
  for (auto& witness : config_.witnesses) {
    HelloRequest witness_hello;
    witness_hello.node = config_.node;
    witness_hello.kind = ClientKind::Coordinator;
    witness_hello.client_protocol = kFrameVersion;
    if (auto st = witness.connect(witness_hello); !st.is_ok()) {
      // A witness that cannot be reached lowers the achievable quorum; it never
      // lowers the required one. The attempt continues so that the refusal is
      // observable and attributable.
      continue;
    }
  }
  return Status::ok();
}

Status Coordinator::acquire_authority(std::uint64_t requested_lease_steps, Epoch& epoch_out,
                                      FenceToken& token_out, GrantId& grant_out) {
  (void)requested_lease_steps;  // the registry owns the lease horizon
  if (!client_.connected()) {
    return Status::make(Outcome::Unreachable, Reason::DependencyUnreachable);
  }
  if (!attempt_sequence_.try_increment()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  AllocateEpochResponse response;
  if (auto st = client_.allocate_epoch(config_.domain, config_.scope, incarnation_, boot_,
                                       attempt_sequence_, response);
      !st.is_ok()) {
    return st;
  }
  if (!response.status.is_ok()) return response.status;
  epoch_ = response.epoch;
  token_ = response.fence_token;
  grant_ = response.grant;
  policy_ = response.policy;
  policy_generation_ = response.policy_generation;
  allocation_step_ = response.allocation_step;
  authority_ = true;
  epoch_out = epoch_;
  token_out = token_;
  grant_out = grant_;
  return Status::ok();
}

Status Coordinator::collect_evidence(Epoch epoch, IncarnationId incarnation, FenceToken token,
                                     EvidenceBundle& bundle) {
  bundle = EvidenceBundle{};
  if (policy_.empty()) {
    return Status::make(Outcome::Invalid, Reason::PolicyNotRegistered);
  }
  bundle.policy = policy_;
  bundle.policy_generation = policy_generation_;
  bundle.as_of = allocation_step_;
  bundle.fence_generation = Generation{};
  for (auto& witness : config_.witnesses) {
    AttestResponse response;
    if (auto st = witness.attest(config_.domain, config_.scope, epoch, incarnation, token,
                                 policy_generation_, allocation_step_, response);
        !st.is_ok()) {
      continue;
    }
    if (!response.status.is_ok()) continue;
    if (bundle.attestations.size() >= limits::kMaxAttestationsPerBundle) break;
    bundle.attestations.push_back(response.attestation);
  }
  return Status::ok();
}

Status Coordinator::evaluate(Epoch epoch, IncarnationId incarnation, FenceToken token,
                             AuthorityMode mode, const EvidenceBundle& bundle,
                             AuthorityDecision& decision) {
  DecideRequest request;
  request.domain = config_.domain;
  request.scope = config_.scope;
  request.epoch = epoch;
  request.incarnation = incarnation;
  request.boot = boot_;
  request.presented_fence_token = token;
  request.mode = mode;
  request.attempt_sequence = attempt_sequence_;
  request.evidence = bundle;
  DecideResponse response;
  if (auto st = client_.decide(request, response); !st.is_ok()) return st;
  decision = response.decision;
  if (!response.status.is_ok()) return response.status;
  return Status::ok();
}

Status Coordinator::mutate(std::string_view operation, std::uint64_t count,
                           CoordinatorReport& report) {
  if (operation.empty() || operation.size() > limits::kMaxTextLength) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
  }
  report = CoordinatorReport{};
  report.attempts.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(count, 4096)));

  if (!authority_) {
    if (auto st = acquire_authority(0, epoch_, token_, grant_); !st.is_ok()) {
      ++report.unreachable;
      report.final_epoch = epoch_;
      report.final_token = token_;
      report.final_grant = grant_;
      report.holds_authority = false;
      return st;
    }
  }
  report.final_epoch = epoch_;
  report.final_token = token_;
  report.final_grant = grant_;

  for (std::uint64_t i = 0; i < count; ++i) {
    ++report.attempted;
    if (!attempt_sequence_.try_increment()) {
      return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
    }
    MutationAttempt attempt;
    attempt.attempt = attempt_sequence_;
    attempt.operation.assign(operation);
    attempt.epoch = epoch_;
    attempt.fence_token = token_;

    // Evidence is re-collected per attempt: a cached attestation is not
    // evidence that the authority is still current.
    EvidenceBundle bundle;
    if (config_.require_quorum) {
      collect_evidence(epoch_, incarnation_, token_, bundle);
    } else {
      bundle.policy = policy_;
      bundle.policy_generation = policy_generation_;
      bundle.as_of = allocation_step_;
    }

    AuthorityDecision decision;
    const Status evaluated =
        evaluate(epoch_, incarnation_, token_, AuthorityMode::ExclusiveMutation, bundle, decision);
    if (!evaluated.is_ok() || !verdict_permits_mutation(decision.verdict)) {
      attempt.outcome = decision.verdict == AuthorityVerdict::Unknown
                            ? MutationOutcome::Unknown
                            : classify(evaluated.is_ok() ? decision.status : evaluated);
      attempt.status = evaluated.is_ok() ? decision.status : evaluated;
      ++report.refused;
      switch (attempt.outcome) {
        case MutationOutcome::Fenced: ++report.fenced; break;
        case MutationOutcome::Unreachable: ++report.unreachable; break;
        case MutationOutcome::Conflict: ++report.conflicts; break;
        case MutationOutcome::Unknown: ++report.unknown; break;
        default: break;
      }
      if (report.attempts.size() < 4096) report.attempts.push_back(attempt);
      report.holds_authority = false;
      authority_ = false;
      continue;
    }

    CommitRequest commit;
    commit.domain = config_.domain;
    commit.scope = config_.scope;
    commit.epoch = epoch_;
    commit.incarnation = incarnation_;
    commit.grant = grant_;
    commit.fence_token = token_;
    commit.attempt_sequence = attempt_sequence_;
    commit.operation.assign(operation);
    commit.payload_digest = operation_digest(operation, attempt_sequence_);
    CommitResponse response;
    const Status committed = client_.commit(commit, response);
    if (!committed.is_ok()) {
      attempt.outcome = MutationOutcome::Unreachable;
      attempt.status = committed;
      ++report.unreachable;
      if (report.attempts.size() < 4096) report.attempts.push_back(attempt);
      report.holds_authority = false;
      authority_ = false;
      continue;
    }
    if (!response.status.is_ok()) {
      attempt.outcome = classify(response.status);
      attempt.status = response.status;
      attempt.store_sequence = response.store_sequence;
      switch (attempt.outcome) {
        case MutationOutcome::Fenced: ++report.fenced; break;
        case MutationOutcome::Conflict: ++report.conflicts; break;
        case MutationOutcome::Unknown: ++report.unknown; break;
        default: ++report.refused; break;
      }
      if (report.attempts.size() < 4096) report.attempts.push_back(attempt);
      // Losing the effect boundary means the authority is gone: fail closed and
      // re-acquire rather than retrying under the same epoch.
      authority_ = false;
      report.holds_authority = false;
      continue;
    }

    attempt.store_sequence = response.store_sequence;
    attempt.fence_token = response.admitted_token;
    attempt.effect_digest = response.effect_digest;
    if (response.verified) {
      attempt.outcome = MutationOutcome::Applied;
      ++report.applied;
    } else {
      attempt.outcome = MutationOutcome::AcknowledgedNotVerified;
      ++report.acknowledged_not_verified;
    }
    attempt.status = Status::ok();
    if (report.attempts.size() < 4096) report.attempts.push_back(attempt);
  }
  report.holds_authority = authority_;
  return Status::ok();
}

void Coordinator::close() {
  for (auto& witness : config_.witnesses) witness.close();
  client_.close();
  authority_ = false;
}

void Coordinator::release(Reason cause) {
  if (!client_.connected() || grant_.is_none()) return;
  ReleaseRequest request;
  request.grant = grant_;
  request.cause = cause;
  ReleaseResponse response;
  if (client_.release(request, response).is_ok() && response.status.is_ok()) {
    authority_ = false;
  }
}

}  // namespace sbf
