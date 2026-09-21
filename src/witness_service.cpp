#include <algorithm>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "conn_hub.hpp"
#include "sbf/text.hpp"
#include "sbf/witness.hpp"

namespace sbf {
namespace {

using SubjectKey = std::pair<std::string, std::string>;

SubjectKey key_for(const DomainId& domain, const Scope& scope) {
  return SubjectKey{domain.str(), scope.digest().hex()};
}

}  // namespace

WitnessService::~WitnessService() {
  stop();
  join();
}

Status WitnessService::configure(const WitnessConfig& config) {
  if (config.witness.empty() || config.fault_domain.empty()) {
    return Status::make(Outcome::Invalid, Reason::EmptyValue);
  }
  if (config.attestation_horizon_steps == 0 ||
      config.attestation_horizon_steps > limits::kMaxLeaseHorizonSteps) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange,
                        config.attestation_horizon_steps);
  }
  if (config.max_subjects == 0 || config.max_subjects > 65536) {
    return Status::make(Outcome::Invalid, Reason::ValueOutOfRange, config.max_subjects);
  }
  config_ = config;
  return Status::ok();
}

Status WitnessService::bind(const net::Endpoint& endpoint) {
  if (auto st = net::initialize(); !st.is_ok()) return st;
  if (auto st = listener_.listen(endpoint, listener_, limits::kListenBacklog); !st.is_ok()) {
    return st;
  }
  endpoint_ = listener_.endpoint();
  return Status::ok();
}

void WitnessService::start() {
  if (thread_.joinable()) return;
  stopping_.store(false);
  if (!clock_.advance()) return;
  thread_ = std::thread([this]() { run(); });
}

void WitnessService::stop() {
  if (stopping_.exchange(true)) return;
  listener_.stop();
  std::shared_ptr<void> raw = hub_;
  if (raw) static_cast<internal::ConnectionHub*>(raw.get())->begin_stop();
}

void WitnessService::join() {
  if (thread_.joinable()) thread_.join();
}

Status WitnessService::attest(const AttestRequest& request, AttestResponse& response, Step now) {
  response = AttestResponse{};
  if (request.subject_domain.empty()) {
    response.status = Status::make(Outcome::Invalid, Reason::DomainNotRegistered);
    return response.status;
  }
  if (request.subject_scope.empty()) {
    response.status = Status::make(Outcome::Invalid, Reason::EmptyExtentSet);
    return response.status;
  }
  if (request.epoch.is_none() || request.incarnation.is_none() ||
      request.fence_token.is_none()) {
    response.status = Status::make(Outcome::Invalid, Reason::ValueOutOfRange);
    return response.status;
  }
  if (request.requester_step.is_none()) {
    // Evidence windows live in the registry's logical step space. Without a
    // step there is no way to say anything about validity, so the witness says
    // nothing rather than guessing.
    response.status = Status::make(Outcome::Unknown, Reason::ValueOutOfRange);
    return response.status;
  }
  if (!clock_.advance()) {
    response.status = Status::make(Outcome::Exhausted, Reason::CounterOverflow);
    return response.status;
  }

  const SubjectKey key = key_for(request.subject_domain, request.subject_scope);
  const auto it = subjects_.find(key);
  if (it != subjects_.end()) {
    const AttestedSubject& previous = it->second;
    if (request.epoch < previous.epoch) {
      // A superseded epoch can never come back, no matter who asks.
      ++refusals_regression_;
      response.status = Status::make(Outcome::Stale, Reason::EpochRegression,
                                     previous.epoch.value());
      return response.status;
    }
    if (request.epoch == previous.epoch && previous.incarnation != request.incarnation) {
      // Two incarnations claiming the same epoch for the same scope is exactly
      // the split brain. The witness refuses both, which is what keeps a
      // partitioned coordinator from assembling a quorum.
      ++refusals_conflict_;
      response.status = Status::make(Outcome::Conflict, Reason::ConflictingAttestations,
                                     previous.incarnation.value());
      return response.status;
    }
    if (request.epoch == previous.epoch && request.fence_token != previous.fence_token) {
      ++refusals_conflict_;
      response.status = Status::make(Outcome::Conflict, Reason::FenceTokenRegressed,
                                     previous.fence_token.value());
      return response.status;
    }
  } else if (subjects_.size() >= config_.max_subjects) {
    response.status = Status::make(Outcome::Exhausted, Reason::BoundedTableFull,
                                   subjects_.size());
    return response.status;
  }

  if (last_sequence_.value() == Sequence::max_value()) {
    response.status = Status::make(Outcome::Exhausted, Reason::CounterOverflow);
    return response.status;
  }
  last_sequence_ = Sequence{last_sequence_.value() + 1};

  AttestedSubject subject;
  subject.domain = request.subject_domain;
  subject.scope = request.subject_scope.digest();
  subject.epoch = request.epoch;
  subject.incarnation = request.incarnation;
  subject.fence_token = request.fence_token;
  subject.generation = it == subjects_.end()
                           ? Generation{1}
                           : Generation{it->second.generation.value() + 1};
  subject.sequence = last_sequence_;
  subject.issued_at = request.requester_step;
  subject.valid_until = Step{request.requester_step.value() + config_.attestation_horizon_steps};
  subject.attestations = it == subjects_.end() ? 1 : it->second.attestations + 1;
  subjects_[key] = subject;

  WitnessAttestation attestation;
  attestation.witness = config_.witness;
  attestation.subject_domain = request.subject_domain;
  attestation.subject_scope = request.subject_scope.digest();
  attestation.epoch = request.epoch;
  attestation.incarnation = request.incarnation;
  attestation.fence_token = request.fence_token;
  attestation.witness_generation = subject.generation;
  attestation.policy_generation = request.policy_generation;
  attestation.issued_at = subject.issued_at;
  attestation.valid_until = subject.valid_until;
  attestation.witness_sequence = subject.sequence;
  attestation.support = true;
  attestation.observed_at = request.requested_at;

  response.attestation = attestation;
  response.status = Status::ok();
  ++issued_;
  (void)now;
  return response.status;
}

void WitnessService::run() {
  auto hub = std::make_shared<internal::ConnectionHub>();
  {
    std::lock_guard<std::mutex> guard(hub_mutex_);
    hub_ = hub;
  }
  while (!stopping_.load()) {
    auto socket = std::make_shared<net::Socket>();
    const Status accepted = listener_.accept(*socket);
    if (!accepted.is_ok()) {
      if (accepted.outcome == Outcome::Closed) break;
      continue;
    }
    if (stopping_.load()) break;
    hub->add(socket);
    std::thread worker([this, hub, socket]() {
      FrameDecoder decoder;
      std::vector<Frame> frames;
      SessionBinding binding;
      for (;;) {
        if (hub->stopping()) break;
        bool readable = false;
        if (const Status waited = socket->wait_readable(25, readable); !waited.is_ok()) break;
        if (!readable) continue;
        std::string chunk;
        std::size_t read = 0;
        if (const Status st = socket->read_some(chunk, 65536, read); !st.is_ok() || read == 0) break;
        if (const Status st = decoder.push(chunk, frames); !st.is_ok()) break;
        bool stop_connection = false;
        for (auto& frame : frames) {
          std::string payload;
          MessageType type = MessageType::ErrorResponse;
          Status handled = Status::make(Outcome::Invalid, Reason::InvalidEnum);
          if (!binding.session.is_set()) {
            if (frame.header.type == MessageType::HelloRequest) {
              HelloRequest request;
              handled = decode(frame.payload, request);
              HelloResponse response;
              if (handled.is_ok()) {
                if (request.client_protocol != kFrameVersion) {
                  handled = Status::make(Outcome::Unsupported, Reason::UnsupportedVersion,
                                         request.client_protocol);
                }
              }
              if (handled.is_ok()) {
                std::lock_guard<std::mutex> guard(mutex_);
                if (sessions_.size() >= limits::kMaxSessions) {
                  handled = Status::make(Outcome::Exhausted, Reason::BoundedTableFull);
                } else {
                  next_session_.try_increment();
                  next_incarnation_.try_increment();
                  binding.session = next_session_;
                  binding.node = request.node;
                  binding.boot = BootId{next_incarnation_.value()};
                  binding.incarnation = IncarnationId{next_incarnation_.value()};
                  binding.kind = request.kind;
                  binding.last_request = RequestId{0};
                  binding.accepted_requests = Sequence{0};
                  sessions_.push_back(binding);
                  response.status = Status::ok();
                  response.session = binding.session;
                  response.boot = binding.boot;
                  response.incarnation = binding.incarnation;
                  response.server_protocol = kFrameVersion;
                  response.server_identity = config_.witness.str();
                  response.first_request = RequestId{1};
                }
              }
              if (!handled.is_ok()) {
                response.status = handled;
                response.server_identity = config_.witness.str();
                stop_connection = true;
              }
              payload = encode(response);
              type = MessageType::HelloResponse;
            } else {
              stop_connection = true;
            }
          } else if (frame.header.request_id.value() <= binding.last_request.value()) {
            ErrorResponse error;
            error.status = Status::make(Outcome::Invalid, Reason::RequestIdRegression,
                                        frame.header.request_id.value());
            error.detail = "request id must strictly increase";
            payload = encode(error);
            type = MessageType::ErrorResponse;
            stop_connection = true;
          } else {
            binding.last_request = frame.header.request_id;
            if (frame.header.type == MessageType::AttestRequest) {
              AttestRequest request;
              handled = decode(frame.payload, request);
              AttestResponse response;
              if (handled.is_ok()) handled = request.envelope.validate_against(binding);
              if (handled.is_ok()) {
                std::lock_guard<std::mutex> guard(mutex_);
                handled = attest(request, response, clock_.now());
              }
              if (!handled.is_ok()) {
                response.status = handled;
                stop_connection = handled.reason == Reason::SessionMismatch;
              }
              payload = encode(response);
              type = MessageType::AttestResponse;
            } else if (frame.header.type == MessageType::WitnessStatusRequest) {
              WitnessStatusRequest request;
              handled = decode(frame.payload, request);
              WitnessStatusResponse response;
              if (handled.is_ok()) {
                std::lock_guard<std::mutex> guard(mutex_);
                response.status = Status::ok();
                response.witness = config_.witness;
                response.fault_domain = config_.fault_domain;
                response.generation = Generation{subjects_.size()};
                response.last_sequence = last_sequence_;
                response.step = clock_.now();
              } else {
                response.status = handled;
              }
              response.attestations_issued = issued_.load();
              response.refusals_conflict = refusals_conflict_.load();
              response.refusals_replay = refusals_replay_.load();
              response.refusals_epoch_regression = refusals_regression_.load();
              payload = encode(response);
              type = MessageType::WitnessStatusResponse;
            } else {
              ErrorResponse error;
              error.status = Status::make(Outcome::Unsupported, Reason::InvalidEnum);
              error.detail = "unsupported message type";
              payload = encode(error);
              type = MessageType::ErrorResponse;
            }
          }
          Frame reply;
          reply.header.type = type;
          reply.header.request_id = frame.header.request_id;
          reply.payload = std::move(payload);
          if (!socket->write_all(encode_frame(reply)).is_ok()) {
            stop_connection = true;
            break;
          }
        }
        frames.clear();
        handled_.fetch_add(1);
        if (stop_connection || stopping_.load()) break;
      }
      socket->shutdown();
      socket->close();
      hub->remove(socket);
    });
    worker.detach();
  }
  if (stopping_.load()) listener_.stop();
  hub->begin_stop();
  hub->wait_drained();
}

WitnessClient::WitnessClient(WitnessId id, FaultDomainId domain, net::Endpoint endpoint)
    : id_(std::move(id)), fault_domain_(std::move(domain)), endpoint_(std::move(endpoint)) {}

WitnessClient::~WitnessClient() { close(); }

WitnessClient::WitnessClient(WitnessClient&& other) noexcept
    : pending_(std::move(other.pending_)),
      id_(std::move(other.id_)),
      fault_domain_(std::move(other.fault_domain_)),
      endpoint_(std::move(other.endpoint_)),
      socket_(std::move(other.socket_)),
      binding_(other.binding_),
      decoder_(std::move(other.decoder_)),
      connected_(other.connected_),
      last_failure_(other.last_failure_),
      next_request_(other.next_request_),
      collected_(other.collected_),
      failures_(other.failures_) {
  other.connected_ = false;
}

WitnessClient& WitnessClient::operator=(WitnessClient&& other) noexcept {
  if (this != &other) {
    close();
    pending_ = std::move(other.pending_);
    id_ = std::move(other.id_);
    fault_domain_ = std::move(other.fault_domain_);
    endpoint_ = std::move(other.endpoint_);
    socket_ = std::move(other.socket_);
    binding_ = other.binding_;
    decoder_ = std::move(other.decoder_);
    connected_ = other.connected_;
    last_failure_ = other.last_failure_;
    next_request_ = other.next_request_;
    collected_ = other.collected_;
    failures_ = other.failures_;
    other.connected_ = false;
  }
  return *this;
}

Status WitnessClient::connect(const HelloRequest& hello) {
  close();
  if (auto st = net::connect(endpoint_, socket_); !st.is_ok()) {
    last_failure_ = st;
    ++failures_;
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
  MessageType type = MessageType::Invalid;
  std::string payload;
  if (auto st = read_frame(type, payload); !st.is_ok()) {
    last_failure_ = st;
    close();
    return st;
  }
  if (type != MessageType::HelloResponse) {
    last_failure_ = Status::make(Outcome::Invalid, Reason::InvalidEnum);
    close();
    return last_failure_;
  }
  HelloResponse response;
  if (auto st = decode(payload, response); !st.is_ok()) {
    last_failure_ = st;
    close();
    return st;
  }
  if (!response.status.is_ok()) {
    last_failure_ = response.status;
    close();
    return response.status;
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

void WitnessClient::close() {
  if (socket_.valid()) {
    socket_.shutdown();
    socket_.close();
  }
  pending_.clear();
  connected_ = false;
}

Status WitnessClient::read_frame(MessageType& type, std::string& payload) {
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

Status WitnessClient::attest(const DomainId& domain, const Scope& scope, Epoch epoch,
                             IncarnationId incarnation, FenceToken token,
                             Generation policy_generation, Step requester_step,
                             AttestResponse& response) {
  response = AttestResponse{};
  if (!connected_) {
    ++failures_;
    last_failure_ = Status::make(Outcome::Unreachable, Reason::QuorumUnreachable);
    return last_failure_;
  }
  AttestRequest request;
  request.envelope.session = binding_.session;
  request.envelope.node = binding_.node;
  request.envelope.boot = binding_.boot;
  request.envelope.incarnation = binding_.incarnation;
  request.subject_domain = domain;
  request.subject_scope = scope;
  request.epoch = epoch;
  request.incarnation = incarnation;
  request.fence_token = token;
  request.policy_generation = policy_generation;
  request.requester_step = requester_step;
  Frame frame;
  frame.header.type = MessageType::AttestRequest;
  frame.header.request_id = next_request_;
  frame.payload = encode(request);
  if (!next_request_.try_increment()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  if (auto st = socket_.write_all(encode_frame(frame)); !st.is_ok()) {
    ++failures_;
    last_failure_ = st;
    connected_ = false;
    return st;
  }
  MessageType type = MessageType::Invalid;
  std::string payload;
  if (auto st = read_frame(type, payload); !st.is_ok()) {
    ++failures_;
    last_failure_ = st;
    return st;
  }
  if (type == MessageType::ErrorResponse) {
    ErrorResponse error;
    if (auto st = decode(payload, error); !st.is_ok()) {
      ++failures_;
      last_failure_ = st;
      return st;
    }
    ++failures_;
    last_failure_ = error.status;
    return error.status;
  }
  if (type != MessageType::AttestResponse) {
    ++failures_;
    last_failure_ = Status::make(Outcome::Invalid, Reason::InvalidEnum);
    return last_failure_;
  }
  if (auto st = decode(payload, response); !st.is_ok()) {
    ++failures_;
    last_failure_ = st;
    return st;
  }
  if (!response.status.is_ok()) {
    ++failures_;
    last_failure_ = response.status;
    return response.status;
  }
  ++collected_;
  return Status::ok();
}

}  // namespace sbf
