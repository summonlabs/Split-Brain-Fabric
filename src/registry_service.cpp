#include <algorithm>
#include <cstdio>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "conn_hub.hpp"
#include "sbf/registry.hpp"
#include "sbf/text.hpp"

namespace sbf {
namespace {

bool closes_connection(Reason reason) noexcept {
  // Identity/binding violations and framing-level failures are terminal for the
  // connection. Semantic refusals are not.
  switch (reason) {
    case Reason::SessionMismatch:
    case Reason::BadMagic:
    case Reason::InvalidEnum:
    case Reason::TruncatedFrame:
    case Reason::OversizedPayload:
    case Reason::StickyFailure:
    case Reason::IntegrityMismatch:
    case Reason::UnsupportedVersion:
      return true;
    default:
      return false;
  }
}

}  // namespace

RegistryService::~RegistryService() {
  stop();
  join();
}

Status RegistryService::open(const RegistryConfig& config, const std::filesystem::path& directory,
                             StoreRecoveryReport& report) {
  if (auto st = net::initialize(); !st.is_ok()) return st;
  config_ = config;
  directory_ = directory;
  if (auto st = ensure_directory(directory); !st.is_ok()) return st;

  StoreOpenOptions options;
  options.create_if_missing = true;
  options.allow_torn_tail_recovery = true;
  options.opening_boot = BootId{};
  if (auto st = Store::open(directory, config.store_id, options, store_, report); !st.is_ok()) {
    return st;
  }
  recovery_ = report;

  // The fenced effect boundary is opened before any authority is restored, so
  // that the durable token floor is available to the recovery step below.
  FabricStore fabric;
  if (auto st = FabricStore::open(directory, config.store_id, options, fabric, report); !st.is_ok()) {
    return st;
  }
  state_.set_fabric(std::move(fabric));

  StepClock clock;
  BootRecord placeholder;
  placeholder.node = config.node;
  if (auto st = state_.initialise(config, clock, placeholder); !st.is_ok()) return st;

  // 1. Durable definitions, lineage, fences and committed outcomes.
  std::string blob;
  SnapshotHeader header;
  if (store_.load_snapshot(blob, header).is_ok()) {
    if (auto st = state_.deserialize(blob); !st.is_ok()) return st;
    if (!(state_.store_id() == config.store_id)) {
      return Status::make(Outcome::Conflict, Reason::StoreNotFound);
    }
    report.snapshot_loaded = true;
  } else {
    header.covers_sequence = Sequence{0};
  }

  // 2. Journal tail. Records already covered by the snapshot are skipped, which
  //    is exactly what a crash between the snapshot rename and the journal
  //    rotation leaves behind.
  const Status replay_status = store_.replay([&](const JournalRecord& record) {
    if (record.sequence.value() <= header.covers_sequence.value()) return Status::ok();
    return state_.apply(record);
  });
  if (!replay_status.is_ok()) return replay_status;
  if (auto st = state_.rebuild(); !st.is_ok()) return st;

  // 3. Conservative restart: every pre-restart authority is fenced and surfaced
  //    as interrupted, and a fresh incarnation opens.
  std::vector<JournalRecord> records;
  if (!state_.clock().advance()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  const Step now = state_.clock().now();
  if (auto st = state_.recover_after_restart(records, now); !st.is_ok()) return st;
  if (auto st = append_records(records); !st.is_ok()) return st;

  recovery_ = report;
  recovery_.last_sequence = store_.last_sequence();
  phase_.store(RegistryPhase::Ready);
  next_session_id_ = SessionId{0};
  return Status::ok();
}

Status RegistryService::define_domain(const DomainDefinition& definition) {
  std::lock_guard<std::mutex> guard(state_mutex_);
  if (!state_.clock().advance()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  std::vector<JournalRecord> records;
  if (auto st = state_.define_domain(definition, records, state_.clock().now()); !st.is_ok()) {
    return st;
  }
  return append_records(records);
}

Status RegistryService::append_records(std::vector<JournalRecord>& records) {
  for (auto& record : records) {
    if (auto st = store_.append(record); !st.is_ok()) return st;
    ++records_since_checkpoint_;
  }
  records.clear();
  if (records_since_checkpoint_ >= config_.checkpoint_every_records) {
    if (auto st = store_.checkpoint(state_.serialize(), store_.last_sequence(),
                                    state_.clock().now());
        !st.is_ok()) {
      return st;
    }
    records_since_checkpoint_ = 0;
  }
  return Status::ok();
}

Status RegistryService::bind(const net::Endpoint& endpoint) {
  if (auto st = listener_.listen(endpoint, listener_, limits::kListenBacklog); !st.is_ok()) {
    return st;
  }
  endpoint_ = listener_.endpoint();
  return Status::ok();
}

void RegistryService::start() {
  if (thread_.joinable()) return;
  stopping_.store(false);
  thread_ = std::thread([this]() { run(); });
}

void RegistryService::stop() {
  if (stopping_.exchange(true)) return;
  listener_.stop();
  phase_.store(RegistryPhase::Draining);
  std::shared_ptr<internal::ConnectionHub> hub;
  {
    hub = hub_;
  }
  if (hub) hub->begin_stop();
}

void RegistryService::join() {
  if (thread_.joinable()) thread_.join();
  phase_.store(RegistryPhase::Stopped);
}

void RegistryService::release_session(SessionId session) {
  std::lock_guard<std::mutex> guard(state_mutex_);
  sessions_.erase(session);
}

void RegistryService::run() {
  auto hub = std::make_shared<internal::ConnectionHub>();
  {
    std::lock_guard<std::mutex> guard(state_mutex_);
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
        // A blocked recv is not reliably interrupted by shutting the socket
        // down on every supported platform, so the worker waits for readability
        // in bounded increments and observes the stop flag between them.
        if (hub->stopping()) break;
        bool readable = false;
        if (const Status waited = socket->wait_readable(25, readable); !waited.is_ok()) break;
        if (!readable) continue;
        std::string chunk;
        std::size_t read = 0;
        const Status read_status = socket->read_some(chunk, 65536, read);
        if (!read_status.is_ok() || read == 0) break;
        if (const Status pushed = decoder.push(chunk, frames); !pushed.is_ok()) {
          poison_events_.fetch_add(1);
          break;  // sticky failure: no reply is possible on an untrusted stream
        }
        bool stop_connection = false;
        for (auto& frame : frames) {
          std::string response_payload;
          MessageType response_type = MessageType::ErrorResponse;

          if (!binding.session.is_set()) {
            if (frame.header.type != MessageType::HelloRequest) {
              ErrorResponse error;
              error.status = Status::make(Outcome::Invalid, Reason::SessionMismatch);
              error.detail = "first frame must be a hello";
              response_payload = encode(error);
              response_type = MessageType::ErrorResponse;
              stop_connection = true;
            } else {
              HelloRequest request;
              Status handled = decode(frame.payload, request);
              HelloResponse response;
              response.server_identity = config_.node.str();
              if (handled.is_ok()) {
                handled = handle_hello(request, response, binding);
              }
              if (!handled.is_ok()) {
                // A failed handshake must be reported as a failed handshake; the
                // response status is the only place the peer can learn that no
                // session was established.
                response.status = handled;
                stop_connection = true;
                rejected_requests_.fetch_add(1);
              } else {
                handled_requests_.fetch_add(1);
              }
              response_payload = encode(response);
              response_type = MessageType::HelloResponse;
            }
          } else if (frame.header.request_id.value() <= binding.last_request.value()) {
            ErrorResponse error;
            error.status = Status::make(Outcome::Invalid, Reason::RequestIdRegression,
                                        frame.header.request_id.value());
            error.detail = "request id must strictly increase within a session";
            response_payload = encode(error);
            response_type = MessageType::ErrorResponse;
            stop_connection = true;
            rejected_requests_.fetch_add(1);
          } else {
            binding.last_request = frame.header.request_id;
            binding.accepted_requests.try_increment();
            const Status handled = handle_frame(frame, binding, response_payload, response_type);
            if (!handled.is_ok()) {
              ErrorResponse error;
              error.status = handled;
              error.detail = sbf::to_string(handled);
              response_payload = encode(error);
              response_type = MessageType::ErrorResponse;
              rejected_requests_.fetch_add(1);
              stop_connection = closes_connection(handled.reason);
            } else {
              handled_requests_.fetch_add(1);
            }
          }

          Frame reply;
          reply.header.type = response_type;
          reply.header.request_id = frame.header.request_id;
          reply.payload = std::move(response_payload);
          if (!socket->write_all(encode_frame(reply)).is_ok()) {
            stop_connection = true;
            break;
          }
          if (response_type == MessageType::ShutdownResponse) {
            // A shutdown request is honoured after the reply is on the wire, so
            // the client always learns that the request was accepted. Stopping
            // the listener wakes the accept loop, which then drains every other
            // session and finishes the run thread.
            stopping_.store(true);
            listener_.stop();
            stop_connection = true;
            break;
          }
        }
        frames.clear();
        if (stop_connection) break;
        if (stopping_.load()) break;
      }
      if (binding.session.is_set()) release_session(binding.session);
      socket->shutdown();
      socket->close();
      hub->remove(socket);
    });
    worker.detach();
  }
  if (stopping_.load()) listener_.stop();
  hub->begin_stop();
  hub->wait_drained();
  phase_.store(RegistryPhase::Stopped);
}

Status RegistryService::handle_hello(const HelloRequest& request, HelloResponse& response,
                                     SessionBinding& binding_out) {
  if (request.node.empty()) {
    return Status::make(Outcome::Invalid, Reason::EmptyValue);
  }
  if (request.client_protocol != kFrameVersion) {
    return Status::make(Outcome::Unsupported, Reason::UnsupportedVersion,
                        request.client_protocol);
  }
  std::lock_guard<std::mutex> guard(state_mutex_);
  if (sessions_.size() >= config_.max_sessions) {
    return Status::make(Outcome::Exhausted, Reason::BoundedTableFull, sessions_.size());
  }
  if (!state_.clock().advance()) {
    return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
  }
  IncarnationId incarnation;
  std::vector<JournalRecord> records;
  if (auto st = state_.allocate_incarnation(records, state_.clock().now(), incarnation);
      !st.is_ok()) {
    return st;
  }
  if (auto st = append_records(records); !st.is_ok()) return st;

  next_session_id_.try_increment();
  SessionBinding binding;
  binding.session = next_session_id_;
  binding.node = request.node;
  binding.boot = state_.boot().boot;
  binding.incarnation = incarnation;
  binding.kind = request.kind;
  binding.last_request = RequestId{0};
  binding.accepted_requests = Sequence{0};
  sessions_.emplace(binding.session, binding);
  binding_out = binding;
  response.status = Status::ok();
  response.session = binding.session;
  response.boot = binding.boot;
  response.incarnation = binding.incarnation;
  response.server_protocol = kFrameVersion;
  response.server_identity = config_.node.str();
  response.first_request = RequestId{1};
  return Status::ok();
}

Status RegistryService::check_envelope(const RequestEnvelope& envelope,
                                       const SessionBinding& binding) {
  if (auto st = envelope.validate_against(binding); !st.is_ok()) return st;
  if (envelope.incarnation != binding.incarnation) {
    return Status::make(Outcome::Invalid, Reason::SessionMismatch, 4);
  }
  return Status::ok();
}

Status RegistryService::handle_frame(const Frame& frame, const SessionBinding& binding,
                                     std::string& response_payload, MessageType& response_type) {
  switch (frame.header.type) {
    case MessageType::PingRequest:
      response_payload.clear();
      response_type = MessageType::PingResponse;
      return Status::ok();
    case MessageType::ShutdownRequest:
      response_payload.clear();
      response_type = MessageType::ShutdownResponse;
      return Status::ok();
    default:
      break;
  }

  if (!binding.session.is_set()) {
    return Status::make(Outcome::Invalid, Reason::SessionMismatch);
  }

  std::vector<JournalRecord> records;
  switch (frame.header.type) {
    case MessageType::DefineDomainRequest: {
      DefineDomainRequest request;
      if (auto st = decode(frame.payload, request); !st.is_ok()) return st;
      if (auto st = check_envelope(request.envelope, binding); !st.is_ok()) return st;
      std::lock_guard<std::mutex> guard(state_mutex_);
      if (!state_.clock().advance()) {
        return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
      }
      DefineDomainResponse response;
      response.status = state_.define_domain(request.definition, records, state_.clock().now());
      response.domain_generation = state_.generation();
      if (auto st = append_records(records); !st.is_ok()) return st;
      response_payload = encode(response);
      response_type = MessageType::DefineDomainResponse;
      return Status::ok();
    }
    case MessageType::AllocateEpochRequest: {
      AllocateEpochRequest request;
      if (auto st = decode(frame.payload, request); !st.is_ok()) return st;
      if (auto st = check_envelope(request.envelope, binding); !st.is_ok()) return st;
      if (request.incarnation != request.envelope.incarnation ||
          !(request.boot == request.envelope.boot)) {
        return Status::make(Outcome::Invalid, Reason::SessionMismatch, 5);
      }
      if (binding.kind != ClientKind::Coordinator) {
        return Status::make(Outcome::Refused, Reason::EligibilityNotAuthorization);
      }
      std::lock_guard<std::mutex> guard(state_mutex_);
      if (!state_.clock().advance()) {
        return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
      }
      AllocateEpochResponse response;
      response.status = state_.allocate_epoch(request, response, records, state_.clock().now());
      if (auto st = append_records(records); !st.is_ok()) return st;
      response_payload = encode(response);
      response_type = MessageType::AllocateEpochResponse;
      return Status::ok();
    }
    case MessageType::DecideRequest: {
      DecideRequest request;
      if (auto st = decode(frame.payload, request); !st.is_ok()) return st;
      if (auto st = check_envelope(request.envelope, binding); !st.is_ok()) return st;
      std::lock_guard<std::mutex> guard(state_mutex_);
      if (!state_.clock().advance()) {
        return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
      }
      DecideResponse response;
      response.status = state_.decide(request, response, state_.clock().now());
      response_payload = encode(response);
      response_type = MessageType::DecideResponse;
      return Status::ok();
    }
    case MessageType::CommitRequest: {
      CommitRequest request;
      if (auto st = decode(frame.payload, request); !st.is_ok()) return st;
      if (auto st = check_envelope(request.envelope, binding); !st.is_ok()) return st;
      if (binding.kind != ClientKind::Coordinator) {
        return Status::make(Outcome::Refused, Reason::EligibilityNotAuthorization);
      }
      std::lock_guard<std::mutex> guard(state_mutex_);
      if (!state_.clock().advance()) {
        return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
      }
      CommitResponse response;
      response.status = state_.commit(request, response, records, state_.clock().now());
      if (auto st = append_records(records); !st.is_ok()) return st;
      response_payload = encode(response);
      response_type = MessageType::CommitResponse;
      return Status::ok();
    }
    case MessageType::FenceRequest: {
      FenceRequest request;
      if (auto st = decode(frame.payload, request); !st.is_ok()) return st;
      if (auto st = check_envelope(request.envelope, binding); !st.is_ok()) return st;
      std::lock_guard<std::mutex> guard(state_mutex_);
      if (!state_.clock().advance()) {
        return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
      }
      FenceResponse response;
      response.status = state_.fence(request, response, records, state_.clock().now());
      if (auto st = append_records(records); !st.is_ok()) return st;
      response_payload = encode(response);
      response_type = MessageType::FenceResponse;
      return Status::ok();
    }
    case MessageType::ReleaseRequest: {
      ReleaseRequest request;
      if (auto st = decode(frame.payload, request); !st.is_ok()) return st;
      if (auto st = check_envelope(request.envelope, binding); !st.is_ok()) return st;
      std::lock_guard<std::mutex> guard(state_mutex_);
      if (!state_.clock().advance()) {
        return Status::make(Outcome::Exhausted, Reason::CounterOverflow);
      }
      ReleaseResponse response;
      response.status = state_.release(request, response, records, state_.clock().now());
      if (auto st = append_records(records); !st.is_ok()) return st;
      response_payload = encode(response);
      response_type = MessageType::ReleaseResponse;
      return Status::ok();
    }
    case MessageType::InspectRequest: {
      InspectRequest request;
      if (auto st = decode(frame.payload, request); !st.is_ok()) return st;
      if (auto st = check_envelope(request.envelope, binding); !st.is_ok()) return st;
      std::lock_guard<std::mutex> guard(state_mutex_);
      InspectResponse response;
      response.status = Status::ok();
      response.registry_generation = state_.generation();
      response.last_registry_sequence = state_.registry_sequence();
      std::string detail;
      detail.append("store=");
      detail.append(state_.store_id().view());
      detail.append(" boot=");
      detail.append(text::hex_u64(state_.boot().boot.value()));
      detail.append(" incarnation=");
      detail.append(text::hex_u64(state_.boot().incarnation.value()));
      detail.append(" step=");
      detail.append(text::hex_u64(state_.clock().now().value()));
      detail.append(" grants=");
      detail.append(std::to_string(state_.lineage().grants().size()));
      detail.append(" open=");
      detail.append(std::to_string(state_.lineage().open_grants().size()));
      detail.append(" extents=");
      detail.append(std::to_string(state_.fences().size()));
      detail.append(" interrupts=");
      detail.append(std::to_string(state_.interrupts().size()));
      detail.append(" mutations=");
      detail.append(std::to_string(state_.fabric().records().size()));
      detail.append(" commits=");
      detail.append(std::to_string(state_.commits()));
      detail.append(" token_counter=");
      detail.append(text::hex_u64(state_.token_counter().value()));
      response.report = std::move(detail);
      response_payload = encode(response);
      response_type = MessageType::InspectResponse;
      return Status::ok();
    }
    default:
      return Status::make(Outcome::Unsupported, Reason::InvalidEnum,
                          static_cast<std::uint16_t>(frame.header.type));
  }
}

}  // namespace sbf
