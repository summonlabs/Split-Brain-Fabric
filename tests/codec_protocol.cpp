#include <algorithm>
#include <string>
#include <vector>

#include "sbf/protocol.hpp"
#include "support/test_harness.hpp"

using namespace sbf;

namespace {

Scope make_scope(std::string_view csv) {
  auto scope = Scope::try_parse(csv);
  return scope.value_or(Scope{});
}

QuorumProfile make_profile() {
  QuorumProfile profile;
  profile.policy = PolicyId::make("policy-1");
  profile.generation = Generation{1};
  profile.witnesses.push_back(WitnessSlot{WitnessId::make("w-a"), FaultDomainId::make("fd-a")});
  profile.witnesses.push_back(WitnessSlot{WitnessId::make("w-b"), FaultDomainId::make("fd-b")});
  profile.mode = QuorumMode::MajorityDistinctWitnesses;
  profile.min_fault_domains = 2;
  return profile;
}

WitnessAttestation make_attestation(std::string_view witness, std::uint64_t sequence) {
  WitnessAttestation attestation;
  attestation.witness = WitnessId::make(witness);
  attestation.subject_domain = DomainId::make("domain-a");
  attestation.subject_scope = make_scope("p1,p2").digest();
  attestation.epoch = Epoch{3};
  attestation.incarnation = IncarnationId{4};
  attestation.fence_token = FenceToken{5};
  attestation.witness_generation = Generation{2};
  attestation.policy_generation = Generation{1};
  attestation.issued_at = Step{10};
  attestation.valid_until = Step{100};
  attestation.witness_sequence = Sequence{sequence};
  attestation.support = true;
  attestation.observed_at.unix_nanos = -12345;
  return attestation;
}

template <class T, class EncodeFn>
void round_trip(const T& value, EncodeFn encode_fn, std::string_view label) {
  const std::string bytes = encode_fn(value);
  T decoded;
  const Status status = decode(bytes, decoded);
  CHECK_OK(status);
  const std::string again = encode_fn(decoded);
  CHECK_EQ(bytes, again);
  (void)label;
}

}  // namespace

SBF_TEST(frame, round_trip_and_header_validation) {
  Frame frame;
  frame.header.type = MessageType::PingRequest;
  frame.header.request_id = RequestId{42};
  frame.payload = "payload-bytes";
  const std::string bytes = encode_frame(frame);
  CHECK_EQ(bytes.size(), std::size_t{limits::kFrameHeaderBytes + 13});
  Frame decoded;
  CHECK_OK(decode_frame(bytes, decoded));
  CHECK(decoded.header.type == MessageType::PingRequest);
  CHECK_EQ(decoded.header.request_id.value(), std::uint64_t{42});
  CHECK_EQ(decoded.payload, std::string("payload-bytes"));

  // Corrupt magic.
  std::string bad_magic = bytes;
  bad_magic[0] = 'X';
  CHECK_OUTCOME(decode_frame(bad_magic, decoded), Outcome::Invalid);
  // Corrupt version.
  std::string bad_version = bytes;
  bad_version[4] = 99;
  CHECK_OUTCOME(decode_frame(bad_version, decoded), Outcome::Unsupported);
  // Corrupt type.
  std::string bad_type = bytes;
  bad_type[6] = static_cast<char>(0xEE);
  bad_type[7] = static_cast<char>(0xEE);
  CHECK_OUTCOME(decode_frame(bad_type, decoded), Outcome::Invalid);
  // Corrupt payload integrity.
  std::string bad_payload = bytes;
  bad_payload[limits::kFrameHeaderBytes] ^= 0x01;
  CHECK_OUTCOME(decode_frame(bad_payload, decoded), Outcome::Corrupt);
  // Corrupt header integrity.
  std::string bad_header = bytes;
  bad_header[20] ^= 0x01;
  CHECK_OUTCOME(decode_frame(bad_header, decoded), Outcome::Corrupt);
}

SBF_TEST(frame, every_truncated_prefix_is_rejected) {
  Frame frame;
  frame.header.type = MessageType::AttestRequest;
  frame.header.request_id = RequestId{7};
  frame.payload = std::string(64, 'p');
  const std::string bytes = encode_frame(frame);
  for (std::size_t length = 0; length < bytes.size(); ++length) {
    FrameDecoder decoder;
    std::vector<Frame> frames;
    const Status status = decoder.push(bytes.substr(0, length), frames);
    CHECK_OK(status);
    CHECK(frames.empty());
    CHECK(!decoder.poisoned());
  }
  FrameDecoder decoder;
  std::vector<Frame> frames;
  CHECK_OK(decoder.push(bytes, frames));
  CHECK_EQ(frames.size(), std::size_t{1});
}

SBF_TEST(frame, oversized_declared_length_is_refused_before_allocation) {
  Frame frame;
  frame.header.type = MessageType::PingRequest;
  frame.payload = "x";
  std::string bytes = encode_frame(frame);
  // Rewrite the declared length to a huge value and repair the header CRC so
  // that only the length check can catch it.
  const std::uint32_t huge = 0xFFFFFF00u;
  bytes[20] = static_cast<char>(huge & 0xFFu);
  bytes[21] = static_cast<char>((huge >> 8) & 0xFFu);
  bytes[22] = static_cast<char>((huge >> 16) & 0xFFu);
  bytes[23] = static_cast<char>((huge >> 24) & 0xFFu);
  const std::uint32_t header_crc = crc32c(std::string_view(bytes.data(), 24));
  bytes[24] = static_cast<char>(header_crc & 0xFFu);
  bytes[25] = static_cast<char>((header_crc >> 8) & 0xFFu);
  bytes[26] = static_cast<char>((header_crc >> 16) & 0xFFu);
  bytes[27] = static_cast<char>((header_crc >> 24) & 0xFFu);
  FrameDecoder decoder;
  std::vector<Frame> frames;
  CHECK_OUTCOME(decoder.push(bytes, frames), Outcome::Exhausted);
  CHECK(decoder.poisoned());
  // Sticky: every later push fails, even with well-formed input.
  Frame good;
  good.header.type = MessageType::PingRequest;
  CHECK_OUTCOME(decoder.push(encode_frame(good), frames), Outcome::Invalid);
  decoder.reset();
  CHECK(!decoder.poisoned());
  CHECK_OK(decoder.push(encode_frame(good), frames));
}

SBF_TEST(frame, decoder_handles_arbitrary_chunk_boundaries) {
  std::string stream;
  for (int i = 0; i < 16; ++i) {
    Frame frame;
    frame.header.type = MessageType::PingRequest;
    frame.header.request_id = RequestId{static_cast<std::uint64_t>(i + 1)};
    frame.payload = std::string(static_cast<std::size_t>(i) * 7, 'z');
    stream.append(encode_frame(frame));
  }
  for (std::size_t chunk = 1; chunk <= 17; ++chunk) {
    FrameDecoder decoder;
    std::vector<Frame> frames;
    std::size_t offset = 0;
    while (offset < stream.size()) {
      const std::size_t take = std::min(chunk, stream.size() - offset);
      CHECK_OK(decoder.push(stream.substr(offset, take), frames));
      offset += take;
    }
    CHECK_EQ(frames.size(), std::size_t{16});
    for (std::size_t i = 0; i < frames.size(); ++i) {
      CHECK_EQ(frames[i].header.request_id.value(), static_cast<std::uint64_t>(i + 1));
    }
  }
}

SBF_TEST(codec, hello_and_envelope_round_trip) {
  HelloRequest request;
  request.node = NodeId::make("node-1");
  request.kind = ClientKind::Coordinator;
  round_trip(request, [](const HelloRequest& value) { return encode(value); }, "hello");
  HelloResponse response;
  response.status = Status::ok();
  response.session = SessionId{4};
  response.boot = BootId{2};
  response.incarnation = IncarnationId{3};
  response.server_identity = "registry-1";
  response.first_request = RequestId{1};
  round_trip(response, [](const HelloResponse& value) { return encode(value); }, "hello-response");

  RequestEnvelope envelope;
  envelope.session = SessionId{4};
  envelope.node = NodeId::make("node-1");
  envelope.boot = BootId{2};
  envelope.incarnation = IncarnationId{3};
  SessionBinding binding;
  binding.session = SessionId{4};
  binding.node = NodeId::make("node-1");
  binding.boot = BootId{2};
  binding.incarnation = IncarnationId{3};
  CHECK_OK(envelope.validate_against(binding));
  SessionBinding other = binding;
  other.incarnation = IncarnationId{99};
  CHECK_OUTCOME(envelope.validate_against(other), Outcome::Invalid);
  other = binding;
  other.session = SessionId{5};
  CHECK_OUTCOME(envelope.validate_against(other), Outcome::Invalid);
}

SBF_TEST(codec, registry_messages_round_trip) {
  AllocateEpochRequest allocate;
  allocate.envelope.session = SessionId{1};
  allocate.envelope.node = NodeId::make("coordinator");
  allocate.envelope.boot = BootId{2};
  allocate.envelope.incarnation = IncarnationId{3};
  allocate.domain = DomainId::make("domain-a");
  allocate.scope = make_scope("p1,p2");
  allocate.incarnation = IncarnationId{3};
  allocate.boot = BootId{2};
  allocate.attempt_sequence = Sequence{9};
  round_trip(allocate, [](const AllocateEpochRequest& v) { return encode(v); }, "allocate");

  AllocateEpochResponse allocated;
  allocated.status = Status::ok();
  allocated.epoch = Epoch{2};
  allocated.fence_token = FenceToken{7};
  allocated.grant = GrantId{3};
  allocated.valid_until = Step{1000};
  allocated.policy = PolicyId::make("policy-1");
  allocated.allocation_step = Step{12};
  round_trip(allocated, [](const AllocateEpochResponse& v) { return encode(v); }, "allocated");

  DecideRequest decide;
  decide.envelope = allocate.envelope;
  decide.domain = allocate.domain;
  decide.scope = allocate.scope;
  decide.epoch = Epoch{2};
  decide.incarnation = IncarnationId{3};
  decide.boot = BootId{2};
  decide.presented_fence_token = FenceToken{7};
  decide.mode = AuthorityMode::ExclusiveMutation;
  decide.attempt_sequence = Sequence{10};
  decide.evidence.policy = PolicyId::make("policy-1");
  decide.evidence.policy_generation = Generation{1};
  decide.evidence.as_of = Step{12};
  decide.evidence.attestations.push_back(make_attestation("w-a", 1));
  decide.evidence.attestations.push_back(make_attestation("w-b", 2));
  decide.evidence.has_lease = true;
  decide.evidence.lease.id = LeaseId{1};
  decide.evidence.lease.grant = GrantId{3};
  decide.evidence.lease.domain = allocate.domain;
  decide.evidence.lease.scope = decide.scope.digest();
  decide.evidence.lease.epoch = Epoch{2};
  decide.evidence.lease.incarnation = IncarnationId{3};
  decide.evidence.lease.fence_token = FenceToken{7};
  decide.evidence.lease.generation = Generation{1};
  decide.evidence.lease.policy_generation = Generation{1};
  decide.evidence.lease.valid_from = Step{12};
  decide.evidence.lease.valid_until = Step{900};
  round_trip(decide, [](const DecideRequest& v) { return encode(v); }, "decide");

  CommitRequest commit;
  commit.envelope = allocate.envelope;
  commit.domain = allocate.domain;
  commit.scope = allocate.scope;
  commit.epoch = Epoch{2};
  commit.incarnation = IncarnationId{3};
  commit.grant = GrantId{3};
  commit.fence_token = FenceToken{7};
  commit.attempt_sequence = Sequence{11};
  commit.operation = "switch-port";
  commit.payload_digest = Digest256::of(std::string_view("payload"));
  round_trip(commit, [](const CommitRequest& v) { return encode(v); }, "commit");

  CommitResponse committed;
  committed.status = Status::ok();
  committed.store_sequence = Sequence{5};
  committed.admitted_token = FenceToken{7};
  committed.effect_digest = Digest256::of(std::string_view("effect"));
  committed.verified = true;
  round_trip(committed, [](const CommitResponse& v) { return encode(v); }, "committed");

  FenceRequest fence;
  fence.envelope = allocate.envelope;
  fence.domain = allocate.domain;
  fence.scope = allocate.scope;
  fence.epoch = Epoch{2};
  fence.incarnation = IncarnationId{3};
  fence.cause = Reason::InterruptedByRestart;
  round_trip(fence, [](const FenceRequest& v) { return encode(v); }, "fence");
  FenceResponse fenced;
  fenced.status = Status::ok();
  fenced.new_high_water = FenceToken{8};
  fenced.registry_sequence = Sequence{13};
  round_trip(fenced, [](const FenceResponse& v) { return encode(v); }, "fenced");

  ReleaseRequest release;
  release.envelope = allocate.envelope;
  release.grant = GrantId{3};
  release.cause = Reason::None;
  round_trip(release, [](const ReleaseRequest& v) { return encode(v); }, "release");
  ReleaseResponse released;
  released.status = Status::ok();
  released.closed_epoch = Epoch{2};
  released.new_high_water = FenceToken{9};
  round_trip(released, [](const ReleaseResponse& v) { return encode(v); }, "released");

  InspectRequest inspect;
  inspect.envelope = allocate.envelope;
  inspect.domain = allocate.domain;
  inspect.scope = allocate.scope;
  inspect.incarnation = IncarnationId{3};
  round_trip(inspect, [](const InspectRequest& v) { return encode(v); }, "inspect");
  InspectResponse inspected;
  inspected.status = Status::ok();
  inspected.report = "store=example boot=0x1";
  inspected.registry_generation = Generation{5};
  inspected.last_registry_sequence = Sequence{21};
  round_trip(inspected, [](const InspectResponse& v) { return encode(v); }, "inspected");

  DefineDomainRequest define;
  define.envelope = allocate.envelope;
  define.definition.domain = DomainId::make("domain-a");
  define.definition.node = NodeId::make("coordinator");
  define.definition.policy = PolicyId::make("policy-1");
  define.definition.scope = make_scope("p1,p2");
  define.definition.exclusive = true;
  round_trip(define, [](const DefineDomainRequest& v) { return encode(v); }, "define");
  DefineDomainResponse defined;
  defined.status = Status::ok();
  defined.domain_generation = Generation{3};
  round_trip(defined, [](const DefineDomainResponse& v) { return encode(v); }, "defined");

  ErrorResponse error;
  error.status = Status::make(Outcome::Fenced, Reason::TokenFloorRejected, 4);
  error.detail = "refused";
  round_trip(error, [](const ErrorResponse& v) { return encode(v); }, "error");
}

SBF_TEST(codec, witness_messages_round_trip) {
  AttestRequest request;
  request.envelope.session = SessionId{1};
  request.envelope.node = NodeId::make("coordinator");
  request.envelope.boot = BootId{1};
  request.envelope.incarnation = IncarnationId{2};
  request.subject_domain = DomainId::make("domain-a");
  request.subject_scope = make_scope("p1");
  request.epoch = Epoch{4};
  request.incarnation = IncarnationId{2};
  request.fence_token = FenceToken{6};
  request.policy_generation = Generation{1};
  request.requester_step = Step{30};
  round_trip(request, [](const AttestRequest& v) { return encode(v); }, "attest");
  AttestResponse response;
  response.status = Status::ok();
  response.attestation = make_attestation("w-a", 3);
  round_trip(response, [](const AttestResponse& v) { return encode(v); }, "attest-response");

  WitnessStatusRequest status_request;
  status_request.envelope = request.envelope;
  round_trip(status_request, [](const WitnessStatusRequest& v) { return encode(v); }, "wstatus");
  WitnessStatusResponse status_response;
  status_response.status = Status::ok();
  status_response.witness = WitnessId::make("w-a");
  status_response.fault_domain = FaultDomainId::make("fd-a");
  status_response.generation = Generation{2};
  status_response.last_sequence = Sequence{11};
  status_response.attestations_issued = 9;
  status_response.step = Step{44};
  round_trip(status_response, [](const WitnessStatusResponse& v) { return encode(v); },
             "wstatus-response");
}

SBF_TEST(codec, decision_round_trip_and_digest_binding) {
  AuthorityDecision decision;
  decision.verdict = AuthorityVerdict::Authoritative;
  decision.status = Status::ok();
  decision.claim = ClaimId::make("claim-domain-a-1");
  decision.scope = make_scope("p1,p2");
  decision.vector.domain = DomainId::make("domain-a");
  decision.vector.scope = decision.scope.digest();
  decision.vector.epoch = Epoch{3};
  decision.vector.incarnation = IncarnationId{4};
  decision.vector.fence_token = FenceToken{5};
  decision.vector.grant = GrantId{6};
  decision.vector.policy_generation = Generation{1};
  decision.vector.evidence_generation = Generation{2};
  decision.vector.fence_generation = Generation{3};
  decision.valid_from = Step{10};
  decision.valid_until = Step{200};
  decision.decision_sequence = Sequence{7};
  decision.explanation.add(Reason::NonOverlappingAllowed);
  decision.must_fence.push_back(ClaimId::make("other"));
  decision.fenced_extents.push_back(ExtentId::make("p3"));
  round_trip(decision, [](const AuthorityDecision& v) { return encode(v); }, "decision");

  // Tampering with any authority-bearing byte must be detected. The digest is
  // carried inside the encoded decision, so a bit flip in the vector is caught
  // even if the CRC structure were recomputed by an attacker without the digest.
  std::string bytes = encode(decision);
  bytes[60] ^= 0x01;
  AuthorityDecision decoded;
  CHECK(!decode(bytes, decoded).is_ok());
}

SBF_TEST(codec, malformed_encodings_are_total) {
  // Every prefix of a valid encoding either decodes or fails with a reason.
  AllocateEpochRequest request;
  request.envelope.session = SessionId{1};
  request.envelope.node = NodeId::make("coordinator");
  request.domain = DomainId::make("domain-a");
  request.scope = make_scope("p1");
  request.incarnation = IncarnationId{1};
  request.boot = BootId{1};
  request.attempt_sequence = Sequence{1};
  const std::string bytes = encode(request);
  for (std::size_t length = 0; length <= bytes.size(); ++length) {
    AllocateEpochRequest decoded;
    const Status status = decode(bytes.substr(0, length), decoded);
    if (length == bytes.size()) CHECK_OK(status);
    else CHECK(!status.is_ok());
  }
  // Trailing garbage is rejected.
  AllocateEpochRequest decoded;
  CHECK(!decode(bytes + std::string(1, '\0'), decoded).is_ok());
  CHECK(!decode(bytes + std::string(64, 'g'), decoded).is_ok());

  // An invalid enum value inside an otherwise well-formed payload is rejected.
  // HelloRequest lays out as text(node) followed by the client kind, so the two
  // bytes after the node text are the enum under test.
  HelloRequest hello;
  hello.node = NodeId::make("node-1");
  hello.kind = ClientKind::Coordinator;
  std::string hello_bytes = encode(hello);
  const std::size_t kind_offset = 2 + hello.node.str().size();
  hello_bytes[kind_offset] = static_cast<char>(0x7F);
  hello_bytes[kind_offset + 1] = static_cast<char>(0x7F);
  HelloRequest decoded_hello;
  CHECK(!decode(hello_bytes, decoded_hello).is_ok());

  // A payload claiming an impossible collection count is refused.
  std::string bomb;
  bomb.push_back(static_cast<char>(0xFF));
  bomb.push_back(static_cast<char>(0xFF));
  bomb.push_back(static_cast<char>(0xFF));
  bomb.push_back(static_cast<char>(0x7F));
  CHECK(!decode(bomb, decoded).is_ok());
}
SBF_TEST_MAIN
