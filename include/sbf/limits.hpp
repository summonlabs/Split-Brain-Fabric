#pragma once

#include <cstddef>
#include <cstdint>

// Every bound enforced by the runtime lives here so that resource behaviour is
// auditable in one place. All limits are hard limits: exceeding one produces a
// deterministic refusal (Exhausted / Invalid / Oversized), never a crash and
// never silent truncation.
namespace sbf::limits {

// ---- identifiers and text ----------------------------------------------------
inline constexpr std::size_t kMaxIdLength = 64;
inline constexpr std::size_t kMaxTextLength = 256;
inline constexpr std::size_t kMaxExplanationCodes = 16;
inline constexpr std::size_t kMaxExplanationBytes = 640;

// ---- scopes ------------------------------------------------------------------
inline constexpr std::size_t kMaxExtentsPerScope = 256;
inline constexpr std::size_t kMaxIndexedExtents = 4096;
// Node budget for any bounded search. Reaching it yields SearchLimitReached and
// never a negative (\"no solution\") answer.
inline constexpr std::uint64_t kMaxSearchNodes = 200000;
// Exact subset selection is exponential; above this candidate count the planner
// refuses to claim optimality and reports Indeterminate.
inline constexpr std::size_t kMaxExactSelectionCandidates = 20;

// ---- evidence ----------------------------------------------------------------
inline constexpr std::size_t kMaxWitnessesPerProfile = 32;
inline constexpr std::size_t kMaxAttestationsPerBundle = 64;
inline constexpr std::size_t kMaxFaultDomainsPerProfile = 16;
inline constexpr std::size_t kMaxCompetingClaims = 128;
inline constexpr std::size_t kMaxLeaseHorizonSteps = 1'000'000;

// ---- retained authority state ------------------------------------------------
inline constexpr std::size_t kMaxDomains = 64;
inline constexpr std::size_t kMaxLineageEntries = 4096;
inline constexpr std::size_t kMaxFenceRecords = 8192;
inline constexpr std::size_t kMaxOpenGrants = 4096;
inline constexpr std::size_t kMaxDedupEntries = 4096;
inline constexpr std::size_t kMaxPendingAttempts = 4096;
inline constexpr std::size_t kMaxInterruptedMarks = 4096;

// ---- persistence -------------------------------------------------------------
inline constexpr std::uint32_t kMaxJournalRecordBytes = 256 * 1024;
inline constexpr std::uint64_t kMaxSnapshotBytes = 32ull * 1024 * 1024;
inline constexpr std::uint64_t kMaxFabricStoreBytes = 512ull * 1024 * 1024;
inline constexpr std::size_t kMaxJournalRecordsBeforeSnapshot = 4096;
inline constexpr std::size_t kMaxSnapshotRecords = 200000;
// Canonical document nesting/collection bounds.
inline constexpr std::size_t kMaxDocumentItems = 65536;
inline constexpr std::size_t kMaxDocumentDepth = 8;

// ---- transport ---------------------------------------------------------------
inline constexpr std::uint32_t kMaxFramePayloadBytes = 256 * 1024;
inline constexpr std::uint32_t kFrameHeaderBytes = 32;
inline constexpr std::size_t kMaxSessions = 256;
inline constexpr std::size_t kMaxQueuedRequests = 64;
inline constexpr std::uint64_t kMaxRequestsPerSession = 1'000'000;
inline constexpr std::uint32_t kListenBacklog = 64;

// ---- reconciliation ----------------------------------------------------------
inline constexpr std::size_t kMaxReconcileConflicts = 1024;
inline constexpr std::size_t kMaxReconcileInputs = 64;

// ---- benchmark / scale harness ----------------------------------------------
inline constexpr std::size_t kMaxBenchmarkOperations = 200000;

}  // namespace sbf::limits
