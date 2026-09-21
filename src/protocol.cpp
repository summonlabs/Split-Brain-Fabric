#include "sbf/protocol.hpp"

#include <cstring>

namespace sbf {
namespace {

void put_u16(std::string& out, std::uint16_t v) {
  out.push_back(static_cast<char>(v & 0xFFu));
  out.push_back(static_cast<char>((v >> 8) & 0xFFu));
}

void put_u32(std::string& out, std::uint32_t v) {
  out.push_back(static_cast<char>(v & 0xFFu));
  out.push_back(static_cast<char>((v >> 8) & 0xFFu));
  out.push_back(static_cast<char>((v >> 16) & 0xFFu));
  out.push_back(static_cast<char>((v >> 24) & 0xFFu));
}

void put_u64(std::string& out, std::uint64_t v) {
  put_u32(out, static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
  put_u32(out, static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFu));
}

std::uint16_t read_u16(const char* p) {
  return static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[0])) |
         static_cast<std::uint16_t>(static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[1])) << 8);
}

std::uint32_t read_u32(const char* p) {
  return static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[0])) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[1])) << 8) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[2])) << 16) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[3])) << 24);
}

std::uint64_t read_u64(const char* p) {
  return static_cast<std::uint64_t>(read_u32(p)) |
         (static_cast<std::uint64_t>(read_u32(p + 4)) << 32);
}

Status encode_wall_clock(CanonicalWriter& writer, const WallClockReading& reading) {
  writer.i64(reading.unix_nanos);
  writer.u64(reading.source);
  writer.boolean(reading.observed_regression);
  return Status::ok();
}

Status decode_wall_clock(CanonicalReader& reader, WallClockReading& reading) {
  if (auto st = reader.i64(reading.unix_nanos); !st.is_ok()) return st;
  if (auto st = reader.u64(reading.source); !st.is_ok()) return st;
  return reader.boolean(reading.observed_regression);
}

void write_client_kind(CanonicalWriter& writer, ClientKind kind) {
  writer.u16(static_cast<std::uint16_t>(kind));
}

Status read_client_kind(CanonicalReader& reader, ClientKind& out) {
  std::uint16_t raw = 0;
  if (auto st = reader.u16(raw); !st.is_ok()) return st;
  if (raw > static_cast<std::uint16_t>(ClientKind::Operator)) {
    return Status::make(Outcome::Invalid, Reason::InvalidEnum, raw);
  }
  out = static_cast<ClientKind>(raw);
  return Status::ok();
}

void write_mode(CanonicalWriter& writer, AuthorityMode mode) {
  writer.u16(static_cast<std::uint16_t>(mode));
}

Status read_mode(CanonicalReader& reader, AuthorityMode& out) {
  std::uint16_t raw = 0;
  if (auto st = reader.u16(raw); !st.is_ok()) return st;
  if (raw > static_cast<std::uint16_t>(AuthorityMode::ExclusiveMutation)) {
    return Status::make(Outcome::Invalid, Reason::InvalidEnum, raw);
  }
  out = static_cast<AuthorityMode>(raw);
  return Status::ok();
}

void write_verdict(CanonicalWriter& writer, AuthorityVerdict verdict) {
  writer.u16(static_cast<std::uint16_t>(verdict));
}

Status read_verdict(CanonicalReader& reader, AuthorityVerdict& out) {
  std::uint16_t raw = 0;
  if (auto st = reader.u16(raw); !st.is_ok()) return st;
  if (raw > static_cast<std::uint16_t>(AuthorityVerdict::Interrupted)) {
    return Status::make(Outcome::Invalid, Reason::InvalidEnum, raw);
  }
  out = static_cast<AuthorityVerdict>(raw);
  return Status::ok();
}

Status read_quorum_mode(CanonicalReader& reader, QuorumMode& out) {
  std::uint16_t raw = 0;
  if (auto st = reader.u16(raw); !st.is_ok()) return st;
  if (raw > static_cast<std::uint16_t>(QuorumMode::UnanimousWitnesses)) {
    return Status::make(Outcome::Invalid, Reason::InvalidEnum, raw);
  }
  out = static_cast<QuorumMode>(raw);
  return Status::ok();
}

Status write_bounded_text(CanonicalWriter& writer, std::string_view value, std::size_t bound) {
  if (value.size() > bound || value.size() > 0xFFFFu) {
    return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, value.size());
  }
  writer.text(value);
  return Status::ok();
}

}  // namespace

bool message_type_valid(std::uint16_t raw) noexcept {
  switch (static_cast<MessageType>(raw)) {
    case MessageType::Invalid:
    case MessageType::HelloRequest:
    case MessageType::HelloResponse:
    case MessageType::PingRequest:
    case MessageType::PingResponse:
    case MessageType::ShutdownRequest:
    case MessageType::ShutdownResponse:
    case MessageType::ErrorResponse:
    case MessageType::DefineDomainRequest:
    case MessageType::DefineDomainResponse:
    case MessageType::DefinePolicyRequest:
    case MessageType::DefinePolicyResponse:
    case MessageType::AllocateEpochRequest:
    case MessageType::AllocateEpochResponse:
    case MessageType::DecideRequest:
    case MessageType::DecideResponse:
    case MessageType::CommitRequest:
    case MessageType::CommitResponse:
    case MessageType::FenceRequest:
    case MessageType::FenceResponse:
    case MessageType::ReleaseRequest:
    case MessageType::ReleaseResponse:
    case MessageType::InspectRequest:
    case MessageType::InspectResponse:
    case MessageType::PlanRequest:
    case MessageType::PlanResponse:
    case MessageType::AttestRequest:
    case MessageType::AttestResponse:
    case MessageType::WitnessStatusRequest:
    case MessageType::WitnessStatusResponse:
      return true;
  }
  return false;
}

std::string_view to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::Invalid: return "Invalid";
    case MessageType::HelloRequest: return "HelloRequest";
    case MessageType::HelloResponse: return "HelloResponse";
    case MessageType::PingRequest: return "PingRequest";
    case MessageType::PingResponse: return "PingResponse";
    case MessageType::ShutdownRequest: return "ShutdownRequest";
    case MessageType::ShutdownResponse: return "ShutdownResponse";
    case MessageType::ErrorResponse: return "ErrorResponse";
    case MessageType::DefineDomainRequest: return "DefineDomainRequest";
    case MessageType::DefineDomainResponse: return "DefineDomainResponse";
    case MessageType::DefinePolicyRequest: return "DefinePolicyRequest";
    case MessageType::DefinePolicyResponse: return "DefinePolicyResponse";
    case MessageType::AllocateEpochRequest: return "AllocateEpochRequest";
    case MessageType::AllocateEpochResponse: return "AllocateEpochResponse";
    case MessageType::DecideRequest: return "DecideRequest";
    case MessageType::DecideResponse: return "DecideResponse";
    case MessageType::CommitRequest: return "CommitRequest";
    case MessageType::CommitResponse: return "CommitResponse";
    case MessageType::FenceRequest: return "FenceRequest";
    case MessageType::FenceResponse: return "FenceResponse";
    case MessageType::ReleaseRequest: return "ReleaseRequest";
    case MessageType::ReleaseResponse: return "ReleaseResponse";
    case MessageType::InspectRequest: return "InspectRequest";
    case MessageType::InspectResponse: return "InspectResponse";
    case MessageType::PlanRequest: return "PlanRequest";
    case MessageType::PlanResponse: return "PlanResponse";
    case MessageType::AttestRequest: return "AttestRequest";
    case MessageType::AttestResponse: return "AttestResponse";
    case MessageType::WitnessStatusRequest: return "WitnessStatusRequest";
    case MessageType::WitnessStatusResponse: return "WitnessStatusResponse";
  }
  return "Invalid";
}

Status validate_frame_header(const FrameHeader& header) noexcept {
  if (header.magic != kFrameMagic) {
    return Status::make(Outcome::Invalid, Reason::BadMagic, header.magic);
  }
  if (header.version != kFrameVersion) {
    return Status::make(Outcome::Unsupported, Reason::UnsupportedVersion, header.version);
  }
  if (!message_type_valid(static_cast<std::uint16_t>(header.type))) {
    return Status::make(Outcome::Invalid, Reason::InvalidEnum,
                        static_cast<std::uint16_t>(header.type));
  }
  return Status::ok();
}

std::string encode_frame(const Frame& frame) {
  std::string out;
  out.reserve(limits::kFrameHeaderBytes + frame.payload.size());
  put_u32(out, frame.header.magic);
  put_u16(out, frame.header.version);
  put_u16(out, static_cast<std::uint16_t>(frame.header.type));
  put_u32(out, frame.header.flags);
  put_u64(out, frame.header.request_id.value());
  put_u32(out, static_cast<std::uint32_t>(frame.payload.size()));
  const std::uint32_t header_crc = crc32c(std::string_view(out.data(), out.size()));
  put_u32(out, header_crc);
  put_u32(out, crc32c(frame.payload));
  out.append(frame.payload);
  return out;
}

Status decode_frame(std::string_view bytes, Frame& out, std::uint32_t max_payload) {
  FrameDecoder decoder(max_payload);
  std::vector<Frame> frames;
  if (auto st = decoder.push(bytes, frames); !st.is_ok()) return st;
  if (frames.size() != 1) {
    return Status::make(Outcome::Invalid, Reason::TruncatedFrame, frames.size());
  }
  out = std::move(frames.front());
  return Status::ok();
}

Status FrameDecoder::push(std::string_view chunk, std::vector<Frame>& out) {
  if (poisoned_) return Status::make(Outcome::Invalid, Reason::StickyFailure);
  buffer_.append(chunk);
  for (;;) {
    if (buffer_.size() < limits::kFrameHeaderBytes) break;
    const char* base = buffer_.data();
    FrameHeader header;
    header.magic = read_u32(base);
    header.version = read_u16(base + 4);
    const std::uint16_t type_raw = read_u16(base + 6);
    header.flags = read_u32(base + 8);
    header.request_id = RequestId{read_u64(base + 12)};
    header.payload_length = read_u32(base + 20);
    header.header_crc = read_u32(base + 24);
    header.payload_crc = read_u32(base + 28);
    if (header.magic != kFrameMagic) {
      poison(Status::make(Outcome::Invalid, Reason::BadMagic, header.magic));
      return failure_;
    }
    if (header.version != kFrameVersion) {
      poison(Status::make(Outcome::Unsupported, Reason::UnsupportedVersion, header.version));
      return failure_;
    }
    if (!message_type_valid(type_raw)) {
      poison(Status::make(Outcome::Invalid, Reason::InvalidEnum, type_raw));
      return failure_;
    }
    header.type = static_cast<MessageType>(type_raw);
    // The declared length is validated *before* any allocation for the payload.
    if (header.payload_length > max_payload_) {
      poison(Status::make(Outcome::Exhausted, Reason::OversizedPayload, header.payload_length));
      return failure_;
    }
    if (crc32c(std::string_view(base, 24)) != header.header_crc) {
      poison(Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, 24));
      return failure_;
    }
    if (buffer_.size() < limits::kFrameHeaderBytes + header.payload_length) break;
    const std::string_view payload(base + limits::kFrameHeaderBytes, header.payload_length);
    if (crc32c(payload) != header.payload_crc) {
      poison(Status::make(Outcome::Corrupt, Reason::IntegrityMismatch, 28));
      return failure_;
    }
    Frame frame;
    frame.header = header;
    frame.payload.assign(payload);
    out.push_back(std::move(frame));
    buffer_.erase(0, limits::kFrameHeaderBytes + header.payload_length);
  }
  if (buffer_.size() > limits::kFrameHeaderBytes + max_payload_) {
    poison(Status::make(Outcome::Exhausted, Reason::OversizedPayload, buffer_.size()));
    return failure_;
  }
  return Status::ok();
}

void FrameDecoder::poison(Status why) {
  poisoned_ = true;
  failure_ = why;
  buffer_.clear();
  buffer_.shrink_to_fit();
}

void FrameDecoder::reset() noexcept {
  buffer_.clear();
  poisoned_ = false;
  failure_ = Status::ok();
}

std::string_view to_string(ClientKind kind) noexcept {
  switch (kind) {
    case ClientKind::Coordinator: return "Coordinator";
    case ClientKind::Observer: return "Observer";
    case ClientKind::Witness: return "Witness";
    case ClientKind::Operator: return "Operator";
  }
  return "Unknown";
}

Status RequestEnvelope::validate_against(const SessionBinding& binding) const noexcept {
  if (session.is_none() || !(session == binding.session)) {
    return Status::make(Outcome::Invalid, Reason::SessionMismatch, session.value());
  }
  if (!(node == binding.node)) {
    return Status::make(Outcome::Invalid, Reason::SessionMismatch, 1);
  }
  if (boot != binding.boot) {
    return Status::make(Outcome::Invalid, Reason::SessionMismatch, 2);
  }
  if (incarnation != binding.incarnation) {
    return Status::make(Outcome::Invalid, Reason::SessionMismatch, 3);
  }
  return Status::ok();
}

// ---- payload codecs ----------------------------------------------------------

std::string encode(const Status& status) {
  CanonicalWriter writer;
  writer.outcome(status.outcome);
  writer.reason(status.reason);
  writer.u64(status.aux);
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, Status& status) {
  if (auto st = reader.outcome(status.outcome); !st.is_ok()) return st;
  if (auto st = reader.reason(status.reason); !st.is_ok()) return st;
  return reader.u64(status.aux);
}

std::string encode(const Scope& scope) {
  CanonicalWriter writer;
  writer.sequence(scope.extents().size(), [&](std::size_t i) { writer.text(scope.extents()[i].view()); });
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, Scope& scope) {
  std::vector<ExtentId> extents;
  std::uint32_t count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxExtentsPerScope), count);
      !st.is_ok()) {
    return st;
  }
  extents.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string value;
    if (auto st = reader.text(value); !st.is_ok()) return st;
    auto id = ExtentId::try_make(value);
    if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
    extents.push_back(std::move(*id));
  }
  if (extents.empty()) {
    // An empty extent list is the wire representation of "no scope", which is
    // legal in a decision that refuses before a subject is established. A scope
    // that is required to be present is validated by its own decode site.
    scope = Scope{};
    return Status::ok();
  }
  return Scope::make(std::move(extents), scope);
}

std::string encode(const QuorumProfile& profile) {
  CanonicalWriter writer;
  writer.text(profile.policy.view());
  writer.counter(profile.generation);
  writer.sequence(profile.witnesses.size(), [&](std::size_t i) {
    writer.text(profile.witnesses[i].witness.view());
    writer.text(profile.witnesses[i].fault_domain.view());
  });
  writer.u16(static_cast<std::uint16_t>(profile.mode));
  writer.u32(profile.threshold);
  writer.u32(profile.min_fault_domains);
  writer.u64(profile.evidence_horizon_steps);
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, QuorumProfile& profile) {
  std::string policy;
  if (auto st = reader.text(policy); !st.is_ok()) return st;
  auto policy_id = PolicyId::try_make(policy);
  if (!policy_id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  profile.policy = *policy_id;
  if (auto st = reader.counter(profile.generation); !st.is_ok()) return st;
  std::uint32_t count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxWitnessesPerProfile), count);
      !st.is_ok()) {
    return st;
  }
  profile.witnesses.clear();
  profile.witnesses.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string witness;
    std::string domain;
    if (auto st = reader.text(witness); !st.is_ok()) return st;
    if (auto st = reader.text(domain); !st.is_ok()) return st;
    auto witness_id = WitnessId::try_make(witness);
    auto domain_id = FaultDomainId::try_make(domain);
    if (!witness_id.has_value() || !domain_id.has_value()) {
      return Status::make(Outcome::Invalid, Reason::IdCharset);
    }
    profile.witnesses.push_back(WitnessSlot{*witness_id, *domain_id});
  }
  if (auto st = read_quorum_mode(reader, profile.mode); !st.is_ok()) return st;
  if (auto st = reader.u32(profile.threshold); !st.is_ok()) return st;
  if (auto st = reader.u32(profile.min_fault_domains); !st.is_ok()) return st;
  return reader.u64(profile.evidence_horizon_steps);
}

std::string encode(const Lease& lease) {
  CanonicalWriter writer;
  writer.counter(lease.id);
  writer.counter(lease.grant);
  writer.text(lease.domain.view());
  writer.digest(lease.scope);
  writer.counter(lease.epoch);
  writer.counter(lease.incarnation);
  writer.counter(lease.fence_token);
  writer.counter(lease.generation);
  writer.counter(lease.policy_generation);
  writer.counter(lease.valid_from);
  writer.counter(lease.valid_until);
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, Lease& lease) {
  if (auto st = reader.counter(lease.id); !st.is_ok()) return st;
  if (auto st = reader.counter(lease.grant); !st.is_ok()) return st;
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto id = DomainId::try_make(domain);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  lease.domain = *id;
  if (auto st = reader.digest(lease.scope); !st.is_ok()) return st;
  if (auto st = reader.counter(lease.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(lease.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(lease.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(lease.generation); !st.is_ok()) return st;
  if (auto st = reader.counter(lease.policy_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(lease.valid_from); !st.is_ok()) return st;
  return reader.counter(lease.valid_until);
}

std::string encode(const WitnessAttestation& attestation) {
  CanonicalWriter writer;
  writer.text(attestation.witness.view());
  writer.text(attestation.subject_domain.view());
  writer.digest(attestation.subject_scope);
  writer.counter(attestation.epoch);
  writer.counter(attestation.incarnation);
  writer.counter(attestation.fence_token);
  writer.counter(attestation.witness_generation);
  writer.counter(attestation.policy_generation);
  writer.counter(attestation.issued_at);
  writer.counter(attestation.valid_until);
  writer.counter(attestation.witness_sequence);
  writer.boolean(attestation.support);
  encode_wall_clock(writer, attestation.observed_at);
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, WitnessAttestation& attestation) {
  std::string witness;
  std::string domain;
  if (auto st = reader.text(witness); !st.is_ok()) return st;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto witness_id = WitnessId::try_make(witness);
  auto domain_id = DomainId::try_make(domain);
  if (!witness_id.has_value() || !domain_id.has_value()) {
    return Status::make(Outcome::Invalid, Reason::IdCharset);
  }
  attestation.witness = *witness_id;
  attestation.subject_domain = *domain_id;
  if (auto st = reader.digest(attestation.subject_scope); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.witness_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.policy_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.issued_at); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.valid_until); !st.is_ok()) return st;
  if (auto st = reader.counter(attestation.witness_sequence); !st.is_ok()) return st;
  if (auto st = reader.boolean(attestation.support); !st.is_ok()) return st;
  return decode_wall_clock(reader, attestation.observed_at);
}

std::string encode(const EvidenceBundle& bundle) {
  CanonicalWriter writer;
  writer.text(bundle.policy.view());
  writer.counter(bundle.policy_generation);
  writer.counter(bundle.as_of);
  writer.counter(bundle.fence_generation);
  writer.sequence(bundle.attestations.size(),
                  [&](std::size_t i) { writer.blob(encode(bundle.attestations[i])); });
  writer.optional(bundle.has_lease, [&]() { writer.blob(encode(bundle.lease)); });
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, EvidenceBundle& bundle) {
  std::string policy;
  if (auto st = reader.text(policy); !st.is_ok()) return st;
  auto policy_id = PolicyId::try_make(policy);
  if (!policy_id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  bundle.policy = *policy_id;
  if (auto st = reader.counter(bundle.policy_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(bundle.as_of); !st.is_ok()) return st;
  if (auto st = reader.counter(bundle.fence_generation); !st.is_ok()) return st;
  std::uint32_t count = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxAttestationsPerBundle), count);
      !st.is_ok()) {
    return st;
  }
  bundle.attestations.clear();
  bundle.attestations.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string blob;
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    WitnessAttestation attestation;
    if (auto st = decode(nested, attestation); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    bundle.attestations.push_back(std::move(attestation));
  }
  return reader.optional([&]() {
    std::string blob;
    if (auto st = reader.blob(blob); !st.is_ok()) return st;
    CanonicalReader nested(blob);
    if (auto st = decode(nested, bundle.lease); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
    bundle.has_lease = true;
    return Status::ok();
  });
}

std::string encode(const AuthorityVector& vector) {
  CanonicalWriter writer;
  writer.text(vector.domain.view());
  writer.digest(vector.scope);
  writer.counter(vector.epoch);
  writer.counter(vector.incarnation);
  writer.counter(vector.fence_token);
  writer.counter(vector.grant);
  writer.counter(vector.authority_sequence);
  writer.counter(vector.policy_generation);
  writer.counter(vector.evidence_generation);
  writer.counter(vector.fence_generation);
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, AuthorityVector& vector) {
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  // A vector that names no domain is the honest representation of a decision
  // that refused before a subject was established. Refusals must always be
  // transportable, otherwise a refusal looks like a transport failure.
  if (!domain.empty()) {
    auto id = DomainId::try_make(domain);
    if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
    vector.domain = *id;
  }
  if (auto st = reader.digest(vector.scope); !st.is_ok()) return st;
  if (auto st = reader.counter(vector.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(vector.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(vector.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(vector.grant); !st.is_ok()) return st;
  if (auto st = reader.counter(vector.authority_sequence); !st.is_ok()) return st;
  if (auto st = reader.counter(vector.policy_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(vector.evidence_generation); !st.is_ok()) return st;
  return reader.counter(vector.fence_generation);
}

std::string encode(const AuthorityDecision& decision) {
  CanonicalWriter writer;
  write_verdict(writer, decision.verdict);
  writer.blob(encode(decision.status));
  writer.sequence(decision.explanation.size(),
                  [&](std::size_t i) { writer.reason(decision.explanation.at(i)); });
  writer.blob(encode(decision.vector));
  writer.text(decision.claim.view());
  writer.blob(encode(decision.scope));
  writer.counter(decision.valid_from);
  writer.counter(decision.valid_until);
  writer.sequence(decision.must_fence.size(),
                  [&](std::size_t i) { writer.text(decision.must_fence[i].view()); });
  writer.sequence(decision.fenced_extents.size(),
                  [&](std::size_t i) { writer.text(decision.fenced_extents[i].view()); });
  writer.counter(decision.decision_sequence);
  writer.boolean(decision.revocable);
  writer.digest(decision.digest());
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, AuthorityDecision& decision) {
  if (auto st = read_verdict(reader, decision.verdict); !st.is_ok()) return st;
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, decision.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::uint32_t reasons = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxExplanationCodes), reasons);
      !st.is_ok()) {
    return st;
  }
  for (std::uint32_t i = 0; i < reasons; ++i) {
    Reason reason = Reason::None;
    if (auto st = reader.reason(reason); !st.is_ok()) return st;
    decision.explanation.add(reason);
  }
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, decision.vector); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string claim;
  if (auto st = reader.text(claim); !st.is_ok()) return st;
  if (!claim.empty()) {
    auto claim_id = ClaimId::try_make(claim);
    if (!claim_id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
    decision.claim = *claim_id;
  } else {
    decision.claim = ClaimId{};
  }
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, decision.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(decision.valid_from); !st.is_ok()) return st;
  if (auto st = reader.counter(decision.valid_until); !st.is_ok()) return st;
  std::uint32_t fences = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxCompetingClaims), fences);
      !st.is_ok()) {
    return st;
  }
  decision.must_fence.clear();
  for (std::uint32_t i = 0; i < fences; ++i) {
    std::string value;
    if (auto st = reader.text(value); !st.is_ok()) return st;
    auto id = ClaimId::try_make(value);
    if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
    decision.must_fence.push_back(*id);
  }
  std::uint32_t extents = 0;
  if (auto st = reader.count(static_cast<std::uint32_t>(limits::kMaxExtentsPerScope), extents);
      !st.is_ok()) {
    return st;
  }
  decision.fenced_extents.clear();
  for (std::uint32_t i = 0; i < extents; ++i) {
    std::string value;
    if (auto st = reader.text(value); !st.is_ok()) return st;
    auto id = ExtentId::try_make(value);
    if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
    decision.fenced_extents.push_back(*id);
  }
  if (auto st = reader.counter(decision.decision_sequence); !st.is_ok()) return st;
  if (auto st = reader.boolean(decision.revocable); !st.is_ok()) return st;
  Digest256 digest;
  if (auto st = reader.digest(digest); !st.is_ok()) return st;
  // The digest travels with the decision so that a transport-level corruption
  // that happens to preserve the CRC structure still fails closed.
  if (!(digest == decision.digest())) {
    return Status::make(Outcome::Corrupt, Reason::IntegrityMismatch);
  }
  return Status::ok();
}

std::string encode(const RequestEnvelope& envelope) {
  CanonicalWriter writer;
  writer.counter(envelope.session);
  writer.text(envelope.node.view());
  writer.counter(envelope.boot);
  writer.counter(envelope.incarnation);
  return std::move(writer).take();
}

Status decode_envelope(CanonicalReader& reader, RequestEnvelope& envelope) {
  if (auto st = reader.counter(envelope.session); !st.is_ok()) return st;
  std::string node;
  if (auto st = reader.text(node); !st.is_ok()) return st;
  auto id = NodeId::try_make(node);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  envelope.node = *id;
  if (auto st = reader.counter(envelope.boot); !st.is_ok()) return st;
  return reader.counter(envelope.incarnation);
}

std::string encode(const HelloRequest& value) {
  CanonicalWriter writer;
  writer.text(value.node.view());
  write_client_kind(writer, value.kind);
  writer.u16(value.client_protocol);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, HelloRequest& value) {
  CanonicalReader reader(bytes);
  std::string node;
  if (auto st = reader.text(node); !st.is_ok()) return st;
  auto id = NodeId::try_make(node);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.node = *id;
  if (auto st = read_client_kind(reader, value.kind); !st.is_ok()) return st;
  if (auto st = reader.u16(value.client_protocol); !st.is_ok()) return st;
  if (value.client_protocol != kFrameVersion) {
    return Status::make(Outcome::Unsupported, Reason::UnsupportedVersion, value.client_protocol);
  }
  return reader.finish();
}

std::string encode(const HelloResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.counter(value.session);
  writer.counter(value.boot);
  writer.counter(value.incarnation);
  writer.u16(value.server_protocol);
  writer.text(value.server_identity);
  writer.counter(value.first_request);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, HelloResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.session); !st.is_ok()) return st;
  if (auto st = reader.counter(value.boot); !st.is_ok()) return st;
  if (auto st = reader.counter(value.incarnation); !st.is_ok()) return st;
  if (auto st = reader.u16(value.server_protocol); !st.is_ok()) return st;
  if (auto st = reader.text(value.server_identity); !st.is_ok()) return st;
  if (auto st = reader.counter(value.first_request); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const AllocateEpochRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.text(value.domain.view());
  writer.blob(encode(value.scope));
  writer.counter(value.incarnation);
  writer.counter(value.boot);
  writer.counter(value.attempt_sequence);
  encode_wall_clock(writer, value.requested_at);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, AllocateEpochRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto id = DomainId::try_make(domain);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.domain = *id;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.boot); !st.is_ok()) return st;
  if (auto st = reader.counter(value.attempt_sequence); !st.is_ok()) return st;
  if (auto st = decode_wall_clock(reader, value.requested_at); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const AllocateEpochResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.counter(value.epoch);
  writer.counter(value.fence_token);
  writer.counter(value.grant);
  writer.counter(value.valid_until);
  writer.counter(value.lineage_generation);
  writer.counter(value.policy_generation);
  writer.counter(value.fence_generation);
  writer.text(value.policy.view());
  writer.counter(value.allocation_step);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, AllocateEpochResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(value.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(value.grant); !st.is_ok()) return st;
  if (auto st = reader.counter(value.valid_until); !st.is_ok()) return st;
  if (auto st = reader.counter(value.lineage_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.policy_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.fence_generation); !st.is_ok()) return st;
  std::string policy;
  if (auto st = reader.text(policy); !st.is_ok()) return st;
  if (!policy.empty()) {
    auto id = PolicyId::try_make(policy);
    if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
    value.policy = *id;
  }
  if (auto st = reader.counter(value.allocation_step); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const DecideRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.text(value.domain.view());
  writer.blob(encode(value.scope));
  writer.counter(value.epoch);
  writer.counter(value.incarnation);
  writer.counter(value.boot);
  writer.counter(value.presented_fence_token);
  write_mode(writer, value.mode);
  writer.counter(value.attempt_sequence);
  writer.blob(encode(value.evidence));
  encode_wall_clock(writer, value.requested_at);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, DecideRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto id = DomainId::try_make(domain);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.domain = *id;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(value.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.boot); !st.is_ok()) return st;
  if (auto st = reader.counter(value.presented_fence_token); !st.is_ok()) return st;
  if (auto st = read_mode(reader, value.mode); !st.is_ok()) return st;
  if (auto st = reader.counter(value.attempt_sequence); !st.is_ok()) return st;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.evidence); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = decode_wall_clock(reader, value.requested_at); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const DecideResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.blob(encode(value.decision));
  return std::move(writer).take();
}

Status decode(std::string_view bytes, DecideResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.decision); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  return reader.finish();
}

std::string encode(const CommitRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.text(value.domain.view());
  writer.blob(encode(value.scope));
  writer.counter(value.epoch);
  writer.counter(value.incarnation);
  writer.counter(value.grant);
  writer.counter(value.fence_token);
  writer.counter(value.attempt_sequence);
  if (!write_bounded_text(writer, value.operation, limits::kMaxTextLength).is_ok()) {
    return std::string{};
  }
  writer.digest(value.payload_digest);
  encode_wall_clock(writer, value.requested_at);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, CommitRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto id = DomainId::try_make(domain);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.domain = *id;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(value.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.grant); !st.is_ok()) return st;
  if (auto st = reader.counter(value.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(value.attempt_sequence); !st.is_ok()) return st;
  if (auto st = reader.text(value.operation); !st.is_ok()) return st;
  if (value.operation.size() > limits::kMaxTextLength) {
    return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, value.operation.size());
  }
  if (auto st = reader.digest(value.payload_digest); !st.is_ok()) return st;
  if (auto st = decode_wall_clock(reader, value.requested_at); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const CommitResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.counter(value.store_sequence);
  writer.counter(value.admitted_token);
  writer.digest(value.effect_digest);
  writer.boolean(value.verified);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, CommitResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.store_sequence); !st.is_ok()) return st;
  if (auto st = reader.counter(value.admitted_token); !st.is_ok()) return st;
  if (auto st = reader.digest(value.effect_digest); !st.is_ok()) return st;
  if (auto st = reader.boolean(value.verified); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const FenceRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.text(value.domain.view());
  writer.blob(encode(value.scope));
  writer.counter(value.epoch);
  writer.counter(value.incarnation);
  writer.reason(value.cause);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, FenceRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto id = DomainId::try_make(domain);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.domain = *id;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(value.incarnation); !st.is_ok()) return st;
  if (auto st = reader.reason(value.cause); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const FenceResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.counter(value.new_high_water);
  writer.counter(value.registry_sequence);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, FenceResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.new_high_water); !st.is_ok()) return st;
  if (auto st = reader.counter(value.registry_sequence); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const ReleaseRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.counter(value.grant);
  writer.reason(value.cause);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, ReleaseRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.grant); !st.is_ok()) return st;
  if (auto st = reader.reason(value.cause); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const ReleaseResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.counter(value.closed_epoch);
  writer.counter(value.new_high_water);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, ReleaseResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.closed_epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(value.new_high_water); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const InspectRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.text(value.domain.view());
  writer.blob(encode(value.scope));
  writer.counter(value.incarnation);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, InspectRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto id = DomainId::try_make(domain);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.domain = *id;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.incarnation); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const InspectResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  if (!write_bounded_text(writer, value.report, limits::kMaxExplanationBytes * 8).is_ok()) {
    return std::string{};
  }
  writer.counter(value.registry_generation);
  writer.counter(value.last_registry_sequence);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, InspectResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.text(value.report); !st.is_ok()) return st;
  if (value.report.size() > limits::kMaxExplanationBytes * 8) {
    return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, value.report.size());
  }
  if (auto st = reader.counter(value.registry_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.last_registry_sequence); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const AttestRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.text(value.subject_domain.view());
  writer.blob(encode(value.subject_scope));
  writer.counter(value.epoch);
  writer.counter(value.incarnation);
  writer.counter(value.fence_token);
  writer.counter(value.policy_generation);
  writer.counter(value.requester_step);
  encode_wall_clock(writer, value.requested_at);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, AttestRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string domain;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto id = DomainId::try_make(domain);
  if (!id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.subject_domain = *id;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.subject_scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.epoch); !st.is_ok()) return st;
  if (auto st = reader.counter(value.incarnation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.fence_token); !st.is_ok()) return st;
  if (auto st = reader.counter(value.policy_generation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.requester_step); !st.is_ok()) return st;
  if (auto st = decode_wall_clock(reader, value.requested_at); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const AttestResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.blob(encode(value.attestation));
  return std::move(writer).take();
}

Status decode(std::string_view bytes, AttestResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.attestation); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  return reader.finish();
}

std::string encode(const WitnessStatusRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  return std::move(writer).take();
}

Status decode(std::string_view bytes, WitnessStatusRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  return reader.finish();
}

std::string encode(const WitnessStatusResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.text(value.witness.view());
  writer.text(value.fault_domain.view());
  writer.counter(value.generation);
  writer.counter(value.last_sequence);
  writer.u64(value.attestations_issued);
  writer.u64(value.refusals_conflict);
  writer.u64(value.refusals_replay);
  writer.u64(value.refusals_epoch_regression);
  writer.counter(value.step);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, WitnessStatusResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  std::string witness;
  std::string domain;
  if (auto st = reader.text(witness); !st.is_ok()) return st;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  auto witness_id = WitnessId::try_make(witness);
  auto domain_id = FaultDomainId::try_make(domain);
  if (!witness_id.has_value() || !domain_id.has_value()) {
    return Status::make(Outcome::Invalid, Reason::IdCharset);
  }
  value.witness = *witness_id;
  value.fault_domain = *domain_id;
  if (auto st = reader.counter(value.generation); !st.is_ok()) return st;
  if (auto st = reader.counter(value.last_sequence); !st.is_ok()) return st;
  if (auto st = reader.u64(value.attestations_issued); !st.is_ok()) return st;
  if (auto st = reader.u64(value.refusals_conflict); !st.is_ok()) return st;
  if (auto st = reader.u64(value.refusals_replay); !st.is_ok()) return st;
  if (auto st = reader.u64(value.refusals_epoch_regression); !st.is_ok()) return st;
  if (auto st = reader.counter(value.step); !st.is_ok()) return st;
  return reader.finish();
}

std::string encode(const DomainDefinition& value) {
  CanonicalWriter writer;
  writer.text(value.domain.view());
  writer.text(value.node.view());
  writer.blob(encode(value.scope));
  writer.text(value.policy.view());
  writer.boolean(value.exclusive);
  return std::move(writer).take();
}

Status decode(CanonicalReader& reader, DomainDefinition& value) {
  std::string domain;
  std::string node;
  std::string policy;
  if (auto st = reader.text(domain); !st.is_ok()) return st;
  if (auto st = reader.text(node); !st.is_ok()) return st;
  auto domain_id = DomainId::try_make(domain);
  auto node_id = NodeId::try_make(node);
  if (!domain_id.has_value() || !node_id.has_value()) {
    return Status::make(Outcome::Invalid, Reason::IdCharset);
  }
  value.domain = *domain_id;
  value.node = *node_id;
  // Field order must mirror encode exactly.
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.scope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.text(policy); !st.is_ok()) return st;
  auto policy_id = PolicyId::try_make(policy);
  if (!policy_id.has_value()) return Status::make(Outcome::Invalid, Reason::IdCharset);
  value.policy = *policy_id;
  return reader.boolean(value.exclusive);
}

std::string encode(const DefineDomainRequest& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.envelope));
  writer.blob(encode(value.definition));
  return std::move(writer).take();
}

Status decode(std::string_view bytes, DefineDomainRequest& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode_envelope(nested, value.envelope); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.definition); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  return reader.finish();
}

std::string encode(const DefineDomainResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  writer.counter(value.domain_generation);
  return std::move(writer).take();
}

Status decode(std::string_view bytes, DefineDomainResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.counter(value.domain_generation); !st.is_ok()) return st;
  return reader.finish();
}

namespace {
template <class T, class Fn>
Status decode_complete(std::string_view bytes, T& out, Fn&& fn) {
  CanonicalReader reader(bytes);
  if (auto st = fn(reader, out); !st.is_ok()) return st;
  return reader.finish();
}
}  // namespace

Status decode(std::string_view bytes, Scope& out) {
  return decode_complete(bytes, out, [](CanonicalReader& r, Scope& v) { return decode(r, v); });
}
Status decode(std::string_view bytes, QuorumProfile& out) {
  return decode_complete(bytes, out, [](CanonicalReader& r, QuorumProfile& v) { return decode(r, v); });
}
Status decode(std::string_view bytes, Lease& out) {
  return decode_complete(bytes, out, [](CanonicalReader& r, Lease& v) { return decode(r, v); });
}
Status decode(std::string_view bytes, WitnessAttestation& out) {
  return decode_complete(bytes, out,
                         [](CanonicalReader& r, WitnessAttestation& v) { return decode(r, v); });
}
Status decode(std::string_view bytes, EvidenceBundle& out) {
  return decode_complete(bytes, out, [](CanonicalReader& r, EvidenceBundle& v) { return decode(r, v); });
}
Status decode(std::string_view bytes, AuthorityVector& out) {
  return decode_complete(bytes, out,
                         [](CanonicalReader& r, AuthorityVector& v) { return decode(r, v); });
}
Status decode(std::string_view bytes, AuthorityDecision& out) {
  return decode_complete(bytes, out,
                         [](CanonicalReader& r, AuthorityDecision& v) { return decode(r, v); });
}
Status decode(std::string_view bytes, DomainDefinition& out) {
  return decode_complete(bytes, out,
                         [](CanonicalReader& r, DomainDefinition& v) { return decode(r, v); });
}

std::string encode(const ErrorResponse& value) {
  CanonicalWriter writer;
  writer.blob(encode(value.status));
  if (!write_bounded_text(writer, value.detail, limits::kMaxExplanationBytes).is_ok()) {
    return std::string{};
  }
  return std::move(writer).take();
}

Status decode(std::string_view bytes, ErrorResponse& value) {
  CanonicalReader reader(bytes);
  std::string blob;
  if (auto st = reader.blob(blob); !st.is_ok()) return st;
  {
    CanonicalReader nested(blob);
    if (auto st = decode(nested, value.status); !st.is_ok()) return st;
    if (auto st = nested.finish(); !st.is_ok()) return st;
  }
  if (auto st = reader.text(value.detail); !st.is_ok()) return st;
  if (value.detail.size() > limits::kMaxExplanationBytes) {
    return Status::make(Outcome::Exhausted, Reason::ImpossibleLength, value.detail.size());
  }
  return reader.finish();
}

}  // namespace sbf
