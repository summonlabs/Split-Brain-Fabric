#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "sbf/canonical.hpp"
#include "sbf/digest.hpp"
#include "sbf/fence.hpp"
#include "sbf/ids.hpp"
#include "sbf/persistence.hpp"
#include "sbf/scope.hpp"
#include "sbf/status.hpp"

namespace sbf {

// One durably committed fabric mutation. The authority vector is carried in the
// record itself, so the effect history is self-describing and can be audited
// without trusting any live process.
struct MutationRecord {
  Sequence store_sequence;     // position in the fabric log, strictly increasing
  DomainId domain;
  Scope scope;
  Epoch epoch;
  IncarnationId incarnation;
  GrantId grant;
  FenceToken fence_token;
  Step committed_at;
  std::string operation;
  Digest256 payload_digest;
  Digest256 record_digest;
};

// The effect boundary.
//
// This is the last line of defence and it is deliberately independent of any
// in-memory authority state: a mutation is written only when the presented fence
// token is at least the durable high-water mark of every extent in scope, and a
// foreign incarnation may never append under the current owner's token. A
// coordinator that was fenced while partitioned therefore cannot mutate the
// fabric even if it still believes - wrongly - that it holds authority.
class FabricStore {
 public:
  FabricStore() = default;
  FabricStore(const FabricStore&) = delete;
  FabricStore& operator=(const FabricStore&) = delete;
  FabricStore(FabricStore&& other) noexcept;
  FabricStore& operator=(FabricStore&& other) noexcept;
  ~FabricStore();

  static Status open(const std::filesystem::path& directory, const StoreId& store_id,
                     const StoreOpenOptions& options, FabricStore& out,
                     StoreRecoveryReport& report);

  // The gate. Returns:
  //   Ok              - appended and flushed; record filled in
  //   Fenced          - token below the durable high-water mark of some extent
  //   Conflict        - token equal to high-water but a different incarnation
  //   Invalid         - malformed operation/scope
  Status admit(const DomainId& domain, FenceToken token, const Scope& scope, Epoch epoch,
               IncarnationId incarnation, GrantId grant, std::string_view operation,
               const Digest256& payload_digest, Step now, MutationRecord& record);

  FenceToken high_water(const ExtentId& extent) const noexcept;
  const ExtentFenceState* owner_of(const ExtentId& extent) const noexcept;

  const std::vector<MutationRecord>& records() const noexcept { return records_; }
  const FenceTable& fence_view() const noexcept { return fences_; }
  Sequence last_sequence() const noexcept { return last_sequence_; }
  std::uint64_t bytes_written() const noexcept { return bytes_written_; }
  bool torn_tail_recovered() const noexcept { return torn_tail_recovered_; }
  const std::filesystem::path& path() const noexcept { return path_; }

  Status load(const std::function<Status(const MutationRecord&)>& visitor) const;

 private:
  void record_owner(const MutationRecord& record);

  std::filesystem::path path_;
  void* file_ = nullptr;
  StoreId store_id_;
  FenceTable fences_;
  std::vector<ExtentFenceState> owners_;   // sorted by extent
  std::vector<MutationRecord> records_;
  Sequence last_sequence_;
  std::uint64_t bytes_written_ = 0;
  bool torn_tail_recovered_ = false;
};

std::string encode(const MutationRecord&);
Status decode(CanonicalReader&, MutationRecord&);
Digest256 compute_record_digest(const MutationRecord&);

}  // namespace sbf
