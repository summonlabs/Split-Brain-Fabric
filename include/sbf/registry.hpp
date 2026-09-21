#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "sbf/arbiter.hpp"
#include "sbf/clock.hpp"
#include "sbf/fabric_store.hpp"
#include "sbf/net.hpp"
#include "sbf/persistence.hpp"
#include "sbf/protocol.hpp"

namespace sbf {

namespace internal {
class ConnectionHub;
}  // namespace internal

// Durable registry state.
//
// Persisted (survives restart): store identity, logical step floor, boot and
// incarnation counters, domain definitions, policy, the fence table, the grant
// lineage, committed fabric effects, interrupt marks and the idempotency table
// for epoch allocation.
//
// Deliberately NOT persisted (dynamic liveness): leases, attestations, evidence
// bundles, session bindings, in-flight attempts and any open socket state.
// Persistence never converts those into current authority.
struct IdempotencyEntry {
  IncarnationId incarnation;
  Sequence attempt;
  Epoch epoch;
  FenceToken token;
  GrantId grant;
  Step valid_until;
  Sequence registry_sequence;
  friend bool operator==(const IdempotencyEntry&, const IdempotencyEntry&) = default;
};

struct InterruptMark {
  GrantId grant;
  DomainId domain;
  Epoch epoch;
  IncarnationId incarnation;
  BootId boot;
  Step marked_at;
  Reason reason = Reason::InterruptedByRestart;
};

enum class RegistryPhase : std::uint8_t {
  Uninitialised = 0,
  Ready = 1,
  Draining = 2,
  Stopped = 3,
};

struct RegistryConfig {
  StoreId store_id;
  NodeId node;
  net::Endpoint endpoint;
  ArbiterPolicy policy;
  Step lease_horizon_steps{1000};
  std::uint64_t checkpoint_every_records = 512;
  std::uint32_t max_sessions = static_cast<std::uint32_t>(limits::kMaxSessions);
};

// The registry owns every durable authority decision. It is a single
// serialization point, which is what makes mutual exclusion provable rather
// than probabilistic.
class RegistryState {
 public:
  RegistryState() = default;

  Status initialise(const RegistryConfig& config, StepClock clock, BootRecord boot);

  // Re-applies one durable record during recovery.
  Status apply(const JournalRecord& record);
  // Rebuilds every derived index from the durable tables and raises the internal
  // counters above anything the durable state already contains.
  Status rebuild();

  // Fences all pre-restart dynamic authority and opens a new boot. Emits the
  // durable records that make the transition survive a second crash.
  Status recover_after_restart(std::vector<JournalRecord>& out_records, Step now);

  // Allocates a durable, strictly monotone incarnation for a new session. The
  // allocation is journalled before it is handed out, so a crash can never let
  // the same incarnation be issued twice.
  Status allocate_incarnation(std::vector<JournalRecord>& out_records, Step now,
                              IncarnationId& out);
  Status define_domain(const DomainDefinition& definition, std::vector<JournalRecord>& out_records,
                       Step now);
  Status define_policy(const ArbiterPolicy& policy, std::vector<JournalRecord>& out_records,
                       Step now);

  // Allocates an epoch and a fresh fence token, fence-adopting the scope. Every
  // open grant whose scope overlaps the requested scope - regardless of domain -
  // is fenced first, so succession is ordered through the durable fence table.
  Status allocate_epoch(const AllocateEpochRequest& request, AllocateEpochResponse& response,
                        std::vector<JournalRecord>& out_records, Step now);

  Status decide(const DecideRequest& request, DecideResponse& response, Step now);

  Status commit(const CommitRequest& request, CommitResponse& response,
                std::vector<JournalRecord>& out_records, Step now);

  Status fence(const FenceRequest& request, FenceResponse& response,
               std::vector<JournalRecord>& out_records, Step now);

  Status release(const ReleaseRequest& request, ReleaseResponse& response,
                 std::vector<JournalRecord>& out_records, Step now);

  // Serialises the complete durable state (no dynamic liveness) for checkpointing.
  std::string serialize() const;
  Status deserialize(std::string_view bytes);

  const FenceTable& fences() const noexcept { return fences_; }
  const LineageTable& lineage() const noexcept { return lineage_; }
  FabricStore& fabric() noexcept { return fabric_; }
  const FabricStore& fabric() const noexcept { return fabric_; }
  void set_fabric(FabricStore&& fabric) noexcept { fabric_ = std::move(fabric); }
  const ArbiterPolicy& policy() const noexcept { return policy_; }
  ArbiterPolicy& mutable_policy() noexcept { return policy_; }
  const std::map<DomainId, DomainDefinition>& domains() const noexcept { return domains_; }
  Sequence registry_sequence() const noexcept { return registry_sequence_; }
  Generation generation() const noexcept { return generation_; }
  const BootRecord& boot() const noexcept { return boot_; }
  StepClock& clock() noexcept { return clock_; }
  const StepClock& clock() const noexcept { return clock_; }
  Step last_step() const noexcept { return last_step_; }
  void set_last_step(Step step) noexcept { last_step_ = step; }
  const std::vector<InterruptMark>& interrupts() const noexcept { return interrupts_; }
  const std::vector<IdempotencyEntry>& idempotency() const noexcept { return idempotency_; }
  const StoreId& store_id() const noexcept { return store_id_; }
  FenceToken token_counter() const noexcept { return token_counter_; }
  GrantId grant_counter() const noexcept { return grant_counter_; }
  std::uint64_t commits() const noexcept { return commits_; }
  std::uint64_t idempotency_hits() const noexcept { return idempotency_hits_; }
  std::uint64_t restart_fences() const noexcept { return restart_fences_; }

 private:
  void remember_scope(const Scope& scope);
  bool has_scope(const Digest256& digest) const;
  Status emit(std::vector<JournalRecord>& out_records, RecordKind kind, std::string payload,
              Status status, Step now);
  Status close_grant(EpochGrant grant, GrantState state, Reason reason, Step now,
                     std::vector<JournalRecord>& out_records);
  // Raises the durable high-water mark for a scope and records the fence. When
  // fence_incarnation is false the epoch is fenced but the incarnation is left
  // live: that is the case where a still-current process supersedes its own
  // previous epoch for the same scope, which must not disqualify it.
  Status fence_scope(const DomainId& domain, const Scope& scope, Epoch epoch,
                     IncarnationId incarnation, GrantId superseded, Reason cause,
                     bool fence_incarnation, Step now, std::vector<JournalRecord>& out_records,
                     FenceToken& token_out);

  RegistryConfig config_;
  StoreId store_id_;
  StepClock clock_;
  Step last_step_;
  BootRecord boot_;
  Sequence registry_sequence_;
  Generation generation_{1};
  FenceTable fences_;
  LineageTable lineage_;
  FabricStore fabric_;
  std::map<DomainId, DomainDefinition> domains_;
  ArbiterPolicy policy_;
  std::vector<IdempotencyEntry> idempotency_;
  std::vector<InterruptMark> interrupts_;
  // Durable scope table: digest -> extent set. Populated by every record that
  // carries extents, so that a fence record (which stores only the digest) can
  // always be re-emitted with its full extent list.
  std::map<std::string, Scope> scopes_;
  FenceToken token_counter_;
  GrantId grant_counter_;
  BootId incarnation_counter_;
  std::uint64_t commits_ = 0;
  std::uint64_t idempotency_hits_ = 0;
  std::uint64_t restart_fences_ = 0;
  RegistryPhase phase_ = RegistryPhase::Uninitialised;
};

// Executable registry service: owns a RegistryState, a durable Store and a
// framed TCP listener. All state mutation happens on the single service thread,
// so the ownership audit is simple by construction: no callback, log sink or
// response encoder is ever invoked while a state lock is held, and no lock is
// held across a socket write.
class RegistryService {
 public:
  RegistryService() = default;
  ~RegistryService();
  RegistryService(const RegistryService&) = delete;
  RegistryService& operator=(const RegistryService&) = delete;

  Status open(const RegistryConfig& config, const std::filesystem::path& directory,
              StoreRecoveryReport& report);
  // Registers a domain definition durably. Safe to call before start().
  Status define_domain(const DomainDefinition& definition);
  // Binds the listener; call before start() so that the effective port is known.
  Status bind(const net::Endpoint& endpoint);
  void start();
  // Natural, prompt shutdown: stops the listener, wakes accept, closes sessions.
  void stop();
  void join();

  const RegistryState& state() const noexcept { return state_; }
  RegistryState& state() noexcept { return state_; }
  net::Endpoint endpoint() const noexcept { return endpoint_; }
  RegistryPhase phase() const noexcept { return phase_.load(); }
  std::uint64_t handled_requests() const noexcept { return handled_requests_.load(); }
  std::uint64_t rejected_requests() const noexcept { return rejected_requests_.load(); }
  std::uint64_t poison_events() const noexcept { return poison_events_.load(); }
  Sequence last_sequence() const noexcept { return store_.last_sequence(); }
  const StoreRecoveryReport& recovery() const noexcept { return recovery_; }

 private:
  void run();
  Status handle_frame(const Frame& frame, const SessionBinding& binding,
                      std::string& response_payload, MessageType& response_type);
  Status handle_hello(const HelloRequest& request, HelloResponse& response,
                      SessionBinding& binding_out);
  Status check_envelope(const RequestEnvelope& envelope, const SessionBinding& binding);
  Status append_records(std::vector<JournalRecord>& records);
  void release_session(SessionId session);

  RegistryConfig config_;
  std::filesystem::path directory_;
  Store store_;
  RegistryState state_;
  net::Listener listener_;
  net::Endpoint endpoint_;
  std::thread thread_;
  std::atomic<bool> stopping_{false};
  std::atomic<RegistryPhase> phase_{RegistryPhase::Uninitialised};
  std::atomic<std::uint64_t> handled_requests_{0};
  std::atomic<std::uint64_t> rejected_requests_{0};
  std::atomic<std::uint64_t> poison_events_{0};
  std::map<SessionId, SessionBinding> sessions_;
  SessionId next_session_id_;
  std::uint64_t records_since_checkpoint_ = 0;
  StoreRecoveryReport recovery_;
  // Serialises every state transition. Held only for the duration of a
  // transition, never across a socket write and never across a callback.
  std::mutex state_mutex_;
  std::shared_ptr<internal::ConnectionHub> hub_;
};

// Client side of the registry protocol. One connection, one session binding,
// strictly increasing request ids.
class RegistryClient {
 public:
  RegistryClient() = default;
  ~RegistryClient();
  RegistryClient(const RegistryClient&) = delete;
  RegistryClient& operator=(const RegistryClient&) = delete;

  Status connect(const net::Endpoint& endpoint, const HelloRequest& hello);
  void close();

  Status allocate_epoch(const DomainId& domain, const Scope& scope, IncarnationId incarnation,
                        BootId boot, Sequence attempt, AllocateEpochResponse& response);
  Status decide(const DecideRequest& request, DecideResponse& response);
  Status commit(const CommitRequest& request, CommitResponse& response);
  Status fence(const FenceRequest& request, FenceResponse& response);
  Status release(const ReleaseRequest& request, ReleaseResponse& response);
  Status inspect(const DomainId& domain, const Scope& scope, IncarnationId incarnation,
                 InspectResponse& response);
  Status define_domain(const DomainDefinition& definition, DefineDomainResponse& response);
  Status shutdown_server();

  const SessionId& session() const noexcept { return binding_.session; }
  const SessionBinding& binding() const noexcept { return binding_; }
  bool connected() const noexcept { return connected_; }
  Status last_failure() const noexcept { return last_failure_; }
  std::uint64_t requests_sent() const noexcept { return requests_sent_; }

 private:
  Status transact(MessageType type, const std::string& payload, MessageType expected,
                  std::string& response_payload);
  Status read_frame(MessageType& type, std::string& payload);
  RequestEnvelope envelope() const;

  std::vector<Frame> pending_;
  net::Socket socket_;
  SessionBinding binding_;
  FrameDecoder decoder_;
  bool connected_ = false;
  Status last_failure_;
  std::uint64_t requests_sent_ = 0;
  RequestId next_request_;
};

// Durable helpers shared by the services.
std::string encode_fence_payload(const FenceRecord& record, const Scope& scope);
Status decode_fence_payload(CanonicalReader& reader, FenceRecord& record, Scope& scope);
std::string claim_id_for_grant(const EpochGrant& grant);

}  // namespace sbf
