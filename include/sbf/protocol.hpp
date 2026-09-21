#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sbf/authority.hpp"
#include "sbf/canonical.hpp"
#include "sbf/digest.hpp"
#include "sbf/evidence.hpp"
#include "sbf/ids.hpp"
#include "sbf/limits.hpp"
#include "sbf/scope.hpp"
#include "sbf/status.hpp"

namespace sbf {

// Wire format: one bounded, framed message stream.
//
//   offset  size  field
//   0       4     magic      0x31464253 ("SBF1" little-endian)
//   4       2     version
//   6       2     message type
//   8       4     flags
//   12      8     request id
//   20      4     payload length
//   24      4     header CRC-32C over bytes [0,24)
//   28      4     payload CRC-32C over the payload bytes
//   32      N     payload
//
// The declared payload length is validated against the configured maximum
// *before* any allocation. Decoding is total: every malformed input maps to a
// specific reason, and a decoder that has seen a malformed frame refuses all
// further frames (sticky failure).
inline constexpr std::uint32_t kFrameMagic = 0x31464253u;
inline constexpr std::uint16_t kFrameVersion = 1;

enum class MessageType : std::uint16_t {
  Invalid = 0,
  HelloRequest = 1,
  HelloResponse = 2,
  PingRequest = 3,
  PingResponse = 4,
  ShutdownRequest = 5,
  ShutdownResponse = 6,
  ErrorResponse = 7,

  DefineDomainRequest = 20,
  DefineDomainResponse = 21,
  DefinePolicyRequest = 22,
  DefinePolicyResponse = 23,

  AllocateEpochRequest = 40,
  AllocateEpochResponse = 41,
  DecideRequest = 42,
  DecideResponse = 43,
  CommitRequest = 44,
  CommitResponse = 45,
  FenceRequest = 46,
  FenceResponse = 47,
  ReleaseRequest = 48,
  ReleaseResponse = 49,
  InspectRequest = 50,
  InspectResponse = 51,
  PlanRequest = 52,
  PlanResponse = 53,

  AttestRequest = 80,
  AttestResponse = 81,
  WitnessStatusRequest = 82,
  WitnessStatusResponse = 83,
};

bool message_type_valid(std::uint16_t raw) noexcept;
std::string_view to_string(MessageType type) noexcept;

struct FrameHeader {
  std::uint32_t magic = kFrameMagic;
  std::uint16_t version = kFrameVersion;
  MessageType type = MessageType::Invalid;
  std::uint32_t flags = 0;
  RequestId request_id;
  std::uint32_t payload_length = 0;
  std::uint32_t header_crc = 0;
  std::uint32_t payload_crc = 0;
};

struct Frame {
  FrameHeader header;
  std::string payload;
};

std::string encode_frame(const Frame& frame);
// Decodes one complete frame from a buffer that must contain exactly one frame.
Status decode_frame(std::string_view bytes, Frame& out,
                    std::uint32_t max_payload = limits::kMaxFramePayloadBytes);

// Incremental decoder. total: it accepts arbitrary chunk boundaries and either
// yields whole frames or fails with a specific reason, after which every further
// push fails with StickyFailure until reset().
class FrameDecoder {
 public:
  explicit FrameDecoder(std::uint32_t max_payload = limits::kMaxFramePayloadBytes)
      : max_payload_(max_payload) {}

  Status push(std::string_view chunk, std::vector<Frame>& out);
  bool poisoned() const noexcept { return poisoned_; }
  Status failure() const noexcept { return failure_; }
  void reset() noexcept;

  std::size_t buffered() const noexcept { return buffer_.size(); }

 private:
  void poison(Status why);

  std::string buffer_;
  std::uint32_t max_payload_;
  bool poisoned_ = false;
  Status failure_;
};

Status validate_frame_header(const FrameHeader& header) noexcept;

// ---- session binding ---------------------------------------------------------
//
// The transport establishes a session identity binding: node, boot, incarnation
// and client kind. It is a *binding*, not an authentication - see README's trust
// boundary. A session may never act under another session's identity, boot or
// epoch, and a request whose declared identity differs from its session binding
// is rejected and poisons the connection.
enum class ClientKind : std::uint8_t {
  Coordinator = 0,
  Observer = 1,
  Witness = 2,
  Operator = 3,
};

std::string_view to_string(ClientKind kind) noexcept;

struct SessionBinding {
  SessionId session;
  NodeId node;
  BootId boot;
  IncarnationId incarnation;
  ClientKind kind = ClientKind::Coordinator;
  RequestId last_request;      // strictly increasing within a session
  Sequence accepted_requests;
};

// Handshake. The client declares who it is; the server assigns the session and
// the incarnation. A client may never choose its own incarnation: that is what
// stops a restarted or duplicated process from re-entering an old identity.
struct HelloRequest {
  NodeId node;
  ClientKind kind = ClientKind::Coordinator;
  std::uint16_t client_protocol = kFrameVersion;
};

struct HelloResponse {
  Status status;
  SessionId session;
  BootId boot;               // incarnation authority of the serving process
  IncarnationId incarnation; // assigned to this session
  std::uint16_t server_protocol = kFrameVersion;
  std::string server_identity;
  RequestId first_request;   // the first request id the client must use
};

// Common envelope carried by every request after the handshake.
struct RequestEnvelope {
  SessionId session;
  NodeId node;
  BootId boot;
  IncarnationId incarnation;
  Status validate_against(const SessionBinding& binding) const noexcept;
};

struct DomainDefinition {
  DomainId domain;
  NodeId node;
  Scope scope;
  PolicyId policy;
  bool exclusive = true;
};

struct AllocateEpochRequest {
  RequestEnvelope envelope;
  DomainId domain;
  Scope scope;
  IncarnationId incarnation;
  BootId boot;
  Sequence attempt_sequence;    // idempotency key together with incarnation
  WallClockReading requested_at;
};

struct AllocateEpochResponse {
  Status status;
  Epoch epoch;
  FenceToken fence_token;
  GrantId grant;
  Step valid_until;
  Generation lineage_generation;
  // The generations the allocation was legal under. The coordinator echoes them
  // back with its evidence so that a policy change between allocation and
  // decision is detected instead of assumed harmless.
  Generation policy_generation;
  Generation fence_generation;
  PolicyId policy;
  // The registry's logical step when the grant was opened. Evidence validity
  // windows are expressed in this single shared step space.
  Step allocation_step;
};

struct DecideRequest {
  RequestEnvelope envelope;
  DomainId domain;
  Scope scope;
  Epoch epoch;
  IncarnationId incarnation;
  BootId boot;
  FenceToken presented_fence_token;
  AuthorityMode mode = AuthorityMode::ExclusiveMutation;
  Sequence attempt_sequence;
  EvidenceBundle evidence;
  WallClockReading requested_at;
};

struct DecideResponse {
  Status status;
  AuthorityDecision decision;
};

struct CommitRequest {
  RequestEnvelope envelope;
  DomainId domain;
  Scope scope;
  Epoch epoch;
  IncarnationId incarnation;
  GrantId grant;
  FenceToken fence_token;
  Sequence attempt_sequence;
  std::string operation;      // bounded, validated
  Digest256 payload_digest;
  WallClockReading requested_at;
};

struct CommitResponse {
  Status status;
  Sequence store_sequence;    // position in the durable fabric log
  FenceToken admitted_token;
  Digest256 effect_digest;    // digest of the record as durably committed
  bool verified = false;      // true only after the effect was read back
};

struct FenceRequest {
  RequestEnvelope envelope;
  DomainId domain;
  Scope scope;
  Epoch epoch;
  IncarnationId incarnation;
  Reason cause = Reason::None;
};

struct FenceResponse {
  Status status;
  FenceToken new_high_water;
  Sequence registry_sequence;
};

struct ReleaseRequest {
  RequestEnvelope envelope;
  GrantId grant;
  Reason cause = Reason::None;
};

struct ReleaseResponse {
  Status status;
  Epoch closed_epoch;
  FenceToken new_high_water;
};

struct DefineDomainRequest {
  RequestEnvelope envelope;
  DomainDefinition definition;
};

struct DefineDomainResponse {
  Status status;
  Generation domain_generation;
};

struct InspectRequest {
  RequestEnvelope envelope;
  DomainId domain;
  Scope scope;
  IncarnationId incarnation;
};

struct InspectResponse {
  Status status;
  std::string report;
  Generation registry_generation;
  Sequence last_registry_sequence;
};

struct AttestRequest {
  RequestEnvelope envelope;
  DomainId subject_domain;
  Scope subject_scope;
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken fence_token;
  Generation policy_generation;
  Step requester_step;
  WallClockReading requested_at;
};

struct AttestResponse {
  Status status;
  WitnessAttestation attestation;
};

struct WitnessStatusRequest {
  RequestEnvelope envelope;
};

struct WitnessStatusResponse {
  Status status;
  WitnessId witness;
  FaultDomainId fault_domain;
  Generation generation;
  Sequence last_sequence;
  std::uint64_t attestations_issued = 0;
  std::uint64_t refusals_conflict = 0;
  std::uint64_t refusals_replay = 0;
  std::uint64_t refusals_epoch_regression = 0;
  Step step;
};

struct ErrorResponse {
  Status status;
  std::string detail;
};

// Payload codecs. Every encoder writes canonical bytes; every decoder validates
// enums, bounds and trailing bytes.
std::string encode(const HelloRequest&);
Status decode(std::string_view, HelloRequest&);
std::string encode(const HelloResponse&);
Status decode(std::string_view, HelloResponse&);
std::string encode(const AllocateEpochRequest&);
Status decode(std::string_view, AllocateEpochRequest&);
std::string encode(const AllocateEpochResponse&);
Status decode(std::string_view, AllocateEpochResponse&);
std::string encode(const DecideRequest&);
Status decode(std::string_view, DecideRequest&);
std::string encode(const DecideResponse&);
Status decode(std::string_view, DecideResponse&);
std::string encode(const CommitRequest&);
Status decode(std::string_view, CommitRequest&);
std::string encode(const CommitResponse&);
Status decode(std::string_view, CommitResponse&);
std::string encode(const FenceRequest&);
Status decode(std::string_view, FenceRequest&);
std::string encode(const FenceResponse&);
Status decode(std::string_view, FenceResponse&);
std::string encode(const ReleaseRequest&);
Status decode(std::string_view, ReleaseRequest&);
std::string encode(const ReleaseResponse&);
Status decode(std::string_view, ReleaseResponse&);
std::string encode(const InspectRequest&);
Status decode(std::string_view, InspectRequest&);
std::string encode(const InspectResponse&);
Status decode(std::string_view, InspectResponse&);
std::string encode(const AttestRequest&);
Status decode(std::string_view, AttestRequest&);
std::string encode(const AttestResponse&);
Status decode(std::string_view, AttestResponse&);
std::string encode(const WitnessStatusRequest&);
Status decode(std::string_view, WitnessStatusRequest&);
std::string encode(const WitnessStatusResponse&);
Status decode(std::string_view, WitnessStatusResponse&);
std::string encode(const DefineDomainRequest&);
Status decode(std::string_view, DefineDomainRequest&);
std::string encode(const DefineDomainResponse&);
Status decode(std::string_view, DefineDomainResponse&);
std::string encode(const ErrorResponse&);
Status decode(std::string_view, ErrorResponse&);

std::string encode(const RequestEnvelope&);
Status decode_envelope(CanonicalReader&, RequestEnvelope&);

// ---- shared small codecs -----------------------------------------------------
std::string encode(const Status&);
Status decode(CanonicalReader&, Status&);
std::string encode(const Scope&);
Status decode(CanonicalReader&, Scope&);
std::string encode(const QuorumProfile&);
Status decode(CanonicalReader&, QuorumProfile&);
std::string encode(const Lease&);
Status decode(CanonicalReader&, Lease&);
std::string encode(const WitnessAttestation&);
Status decode(CanonicalReader&, WitnessAttestation&);
std::string encode(const EvidenceBundle&);
Status decode(CanonicalReader&, EvidenceBundle&);
std::string encode(const AuthorityDecision&);
Status decode(CanonicalReader&, AuthorityDecision&);
std::string encode(const DomainDefinition&);
Status decode(CanonicalReader&, DomainDefinition&);
std::string encode(const AuthorityVector&);
Status decode(CanonicalReader&, AuthorityVector&);

// Convenience wrappers: decode a complete buffer and require that every byte was
// consumed.
Status decode(std::string_view bytes, Scope& out);
Status decode(std::string_view bytes, QuorumProfile& out);
Status decode(std::string_view bytes, Lease& out);
Status decode(std::string_view bytes, WitnessAttestation& out);
Status decode(std::string_view bytes, EvidenceBundle& out);
Status decode(std::string_view bytes, AuthorityVector& out);
Status decode(std::string_view bytes, AuthorityDecision& out);
Status decode(std::string_view bytes, DomainDefinition& out);

}  // namespace sbf
