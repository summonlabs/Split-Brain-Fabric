#include <string>
#include <vector>

#include "sbf/registry.hpp"
#include "sbf/text.hpp"

namespace sbf {

RegistryClient::~RegistryClient() { close(); }

Status RegistryClient::connect(const net::Endpoint& endpoint, const HelloRequest& hello) {
  close();
  if (auto st = net::connect(endpoint, socket_); !st.is_ok()) {
    last_failure_ = st;
    return st;
  }
  decoder_.reset();
  pending_.clear();

  Frame frame;
  frame.header.type = MessageType::HelloRequest;
  frame.header.request_id = RequestId{0};
  frame.payload = encode(hello);
  if (auto st = socket_.write_all(encode_frame(frame)); !st.is_ok()) {
    last_failure_ = st;
    close();
    return st;
  }
  std::string response_payload;
  MessageType response_type = MessageType::Invalid;
  if (auto st = read_frame(response_type, response_payload); !st.is_ok()) {
    last_failure_ = st;
    close();
    return st;
  }
  if (response_type != MessageType::HelloResponse) {
    last_failure_ = Status::make(Outcome::Invalid, Reason::InvalidEnum,
                                 static_cast<std::uint16_t>(response_type));
    close();
    return last_failure_;
  }
  HelloResponse response;
  if (auto st = decode(response_payload, response); !st.is_ok()) {
    last_failure_ = st;
    close();
    return st;
  }
  if (!response.status.is_ok()) {
    last_failure_ = response.status;
    close();
    return response.status;
  }
  if (response.server_protocol != kFrameVersion) {
    last_failure_ = Status::make(Outcome::Unsupported, Reason::UnsupportedVersion,
                                 response.server_protocol);
    close();
    return last_failure_;
  }
  binding_ = SessionBinding{};
  binding_.session = response.session;
  binding_.node = hello.node;
  binding_.boot = response.boot;
  binding_.incarnation = response.incarnation;
  binding_.kind = hello.kind;
  binding_.last_request = RequestId{0};
  binding_.accepted_requests = Sequence{0};
  next_request_ = response.first_request.is_set() ? response.first_request : RequestId{1};
  connected_ = true;
  return Status::ok();
}

void RegistryClient::close() {
  if (socket_.valid()) {
    socket_.shutdown();
    socket_.close();
  }
  pending_.clear();
  connected_ = false;
}

Status RegistryClient::read_frame(MessageType& type, std::string& payload) {
  for (;;) {
    if (!pending_.empty()) {
      Frame frame = std::move(pending_.front());
      pending_.erase(pending_.begin());
      type = frame.header.type;
      payload = std::move(frame.payload);
      return Status::ok();
    }
    std::string chunk;
    std::size_t read = 0;
    if (auto st = socket_.read_some(chunk, 65536, read); !st.is_ok()) {
      connected_ = false;
      return st;
    }
    if (read == 0) {
      connected_ = false;
      return Status::make(Outcome::Closed, Reason::ConnectionClosed);
    }
    if (auto st = decoder_.push(chunk, pending_); !st.is_ok()) {
      connected_ = false;
      return st;
    }
  }
}

Status RegistryClient::transact(MessageType type, const std::string& payload, MessageType expected,
                                std::string& response_payload) {
  if (!connected_) return Status::make(Outcome::Closed, Reason::ConnectionClosed);
  if (requests_sent_ >= limits::kMaxRequestsPerSession) {
    return Status::make(Outcome::Exhausted, Reason::ResourceExhausted, requests_sent_);
  }
  Frame frame;
  frame.header.type = type;
  frame.header.request_id = next_request_;
  frame.payload = payload;
  if (!next_request_.try_increment()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  if (auto st = socket_.write_all(encode_frame(frame)); !st.is_ok()) {
    last_failure_ = st;
    connected_ = false;
    return st;
  }
  ++requests_sent_;
  binding_.last_request = frame.header.request_id;
  binding_.accepted_requests.try_increment();

  MessageType response_type = MessageType::Invalid;
  if (auto st = read_frame(response_type, response_payload); !st.is_ok()) {
    last_failure_ = st;
    return st;
  }
  if (response_type == MessageType::ErrorResponse) {
    ErrorResponse error;
    if (auto st = decode(response_payload, error); !st.is_ok()) {
      last_failure_ = st;
      return st;
    }
    last_failure_ = error.status;
    return error.status;
  }
  if (response_type != expected) {
    last_failure_ = Status::make(Outcome::Invalid, Reason::InvalidEnum,
                                 static_cast<std::uint16_t>(response_type));
    return last_failure_;
  }
  return Status::ok();
}

RequestEnvelope RegistryClient::envelope() const {
  RequestEnvelope out;
  out.session = binding_.session;
  out.node = binding_.node;
  out.boot = binding_.boot;
  out.incarnation = binding_.incarnation;
  return out;
}

Status RegistryClient::allocate_epoch(const DomainId& domain, const Scope& scope,
                                      IncarnationId incarnation, BootId boot, Sequence attempt,
                                      AllocateEpochResponse& response) {
  AllocateEpochRequest request;
  request.envelope = envelope();
  request.domain = domain;
  request.scope = scope;
  request.incarnation = incarnation;
  request.boot = boot;
  request.attempt_sequence = attempt;
  std::string payload;
  if (!connected_) return Status::make(Outcome::Closed, Reason::ConnectionClosed);
  if (auto st = transact(MessageType::AllocateEpochRequest, encode(request),
                         MessageType::AllocateEpochResponse, payload);
      !st.is_ok()) {
    return st;
  }
  return decode(payload, response);
}

Status RegistryClient::decide(const DecideRequest& request, DecideResponse& response) {
  DecideRequest copy = request;
  copy.envelope = envelope();
  std::string payload;
  if (auto st = transact(MessageType::DecideRequest, encode(copy), MessageType::DecideResponse,
                         payload);
      !st.is_ok()) {
    return st;
  }
  return decode(payload, response);
}

Status RegistryClient::commit(const CommitRequest& request, CommitResponse& response) {
  CommitRequest copy = request;
  copy.envelope = envelope();
  std::string payload;
  if (auto st = transact(MessageType::CommitRequest, encode(copy), MessageType::CommitResponse,
                         payload);
      !st.is_ok()) {
    return st;
  }
  return decode(payload, response);
}

Status RegistryClient::fence(const FenceRequest& request, FenceResponse& response) {
  FenceRequest copy = request;
  copy.envelope = envelope();
  std::string payload;
  if (auto st = transact(MessageType::FenceRequest, encode(copy), MessageType::FenceResponse,
                         payload);
      !st.is_ok()) {
    return st;
  }
  return decode(payload, response);
}

Status RegistryClient::release(const ReleaseRequest& request, ReleaseResponse& response) {
  ReleaseRequest copy = request;
  copy.envelope = envelope();
  std::string payload;
  if (auto st = transact(MessageType::ReleaseRequest, encode(copy), MessageType::ReleaseResponse,
                         payload);
      !st.is_ok()) {
    return st;
  }
  return decode(payload, response);
}

Status RegistryClient::inspect(const DomainId& domain, const Scope& scope,
                               IncarnationId incarnation, InspectResponse& response) {
  InspectRequest request;
  request.envelope = envelope();
  request.domain = domain;
  request.scope = scope;
  request.incarnation = incarnation;
  std::string payload;
  if (auto st = transact(MessageType::InspectRequest, encode(request), MessageType::InspectResponse,
                         payload);
      !st.is_ok()) {
    return st;
  }
  return decode(payload, response);
}

Status RegistryClient::define_domain(const DomainDefinition& definition,
                                     DefineDomainResponse& response) {
  DefineDomainRequest request;
  request.envelope = envelope();
  request.definition = definition;
  std::string payload;
  if (auto st = transact(MessageType::DefineDomainRequest, encode(request),
                         MessageType::DefineDomainResponse, payload);
      !st.is_ok()) {
    return st;
  }
  return decode(payload, response);
}

Status RegistryClient::shutdown_server() {
  std::string payload;
  MessageType type = MessageType::Invalid;
  if (auto st = transact(MessageType::ShutdownRequest, std::string{}, MessageType::ShutdownResponse,
                         payload);
      !st.is_ok()) {
    return st;
  }
  (void)type;
  return Status::ok();
}

}  // namespace sbf
