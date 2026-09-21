#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "sbf/clock.hpp"
#include "sbf/net.hpp"
#include "sbf/protocol.hpp"

namespace sbf {

namespace internal {
class ConnectionHub;
}  // namespace internal

// One witness's memory of what it has already attested.
//
// The witness refuses to attest two different incarnations for the same
// (domain, scope, epoch). That refusal is what makes competing coordinators
// mutually exclusive in the presence of a partition: neither side can collect a
// majority for the same epoch, and the epoch can only be advanced through the
// durable registry, which fences the previous owner first.
struct AttestedSubject {
  DomainId domain;
  Digest256 scope;
  Epoch epoch;
  IncarnationId incarnation;
  FenceToken fence_token;
  Generation generation;
  Sequence sequence;
  Step issued_at;
  Step valid_until;
  std::uint64_t attestations = 0;
};

struct WitnessConfig {
  WitnessId witness;
  FaultDomainId fault_domain;
  net::Endpoint endpoint;
  std::uint64_t attestation_horizon_steps = 1000;
  std::uint32_t max_subjects = 512;
};

class WitnessService {
 public:
  WitnessService() = default;
  ~WitnessService();
  WitnessService(const WitnessService&) = delete;
  WitnessService& operator=(const WitnessService&) = delete;

  Status configure(const WitnessConfig& config);
  Status bind(const net::Endpoint& endpoint);
  void start();
  void stop();
  void join();

  // Pure decision used both by the service and by the unit tests.
  Status attest(const AttestRequest& request, AttestResponse& response, Step now);

  net::Endpoint endpoint() const noexcept { return endpoint_; }
  std::uint64_t attestations_issued() const noexcept { return issued_.load(); }
  std::uint64_t refusals_conflict() const noexcept { return refusals_conflict_.load(); }
  std::uint64_t refusals_replay() const noexcept { return refusals_replay_.load(); }
  std::uint64_t refusals_regression() const noexcept { return refusals_regression_.load(); }
  std::uint64_t handled_requests() const noexcept { return handled_.load(); }
  const WitnessConfig& config() const noexcept { return config_; }

 private:
  void run();
  Status handle_frame(const Frame& frame, std::string& payload, MessageType& type);

  WitnessConfig config_;
  std::mutex hub_mutex_;
  std::shared_ptr<internal::ConnectionHub> hub_;
  std::mutex mutex_;
  std::vector<SessionBinding> sessions_;
  SessionId next_session_;
  IncarnationId next_incarnation_;
  net::Listener listener_;
  net::Endpoint endpoint_;
  std::thread thread_;
  std::atomic<bool> stopping_{false};
  std::atomic<std::uint64_t> issued_{0};
  std::atomic<std::uint64_t> refusals_conflict_{0};
  std::atomic<std::uint64_t> refusals_replay_{0};
  std::atomic<std::uint64_t> refusals_regression_{0};
  std::atomic<std::uint64_t> handled_{0};
  std::map<std::pair<std::string, std::string>, AttestedSubject> subjects_;
  std::map<WitnessId, Step> epoch_high_water_;
  Sequence last_sequence_;
  StepClock clock_;
};

// Client used by coordinators to collect quorum evidence.
class WitnessClient {
 public:
  WitnessClient() = default;
  WitnessClient(WitnessId id, FaultDomainId domain, net::Endpoint endpoint);
  ~WitnessClient();
  WitnessClient(const WitnessClient&) = delete;
  WitnessClient& operator=(const WitnessClient&) = delete;
  WitnessClient(WitnessClient&& other) noexcept;
  WitnessClient& operator=(WitnessClient&& other) noexcept;

  Status connect(const HelloRequest& hello);
  void close();
  Status attest(const DomainId& domain, const Scope& scope, Epoch epoch,
                IncarnationId incarnation, FenceToken token, Generation policy_generation,
                Step requester_step, AttestResponse& response);

  const WitnessId& id() const noexcept { return id_; }
  const FaultDomainId& fault_domain() const noexcept { return fault_domain_; }
  const net::Endpoint& endpoint() const noexcept { return endpoint_; }
  bool connected() const noexcept { return connected_; }
  Status last_failure() const noexcept { return last_failure_; }
  std::uint64_t attestations_collected() const noexcept { return collected_; }
  std::uint64_t failures() const noexcept { return failures_; }

 private:
  Status read_frame(MessageType& type, std::string& payload);

  std::vector<Frame> pending_;
  WitnessId id_;
  FaultDomainId fault_domain_;
  net::Endpoint endpoint_;
  net::Socket socket_;
  SessionBinding binding_;
  FrameDecoder decoder_;
  bool connected_ = false;
  Status last_failure_;
  RequestId next_request_;
  std::uint64_t collected_ = 0;
  std::uint64_t failures_ = 0;
};

}  // namespace sbf
