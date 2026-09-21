// Downstream consumer smoke test.
//
// Exercises the parts of the installed API that a real integrator depends on:
// typed identities, scopes, the evidence model, the deterministic authority
// decision, the planner with its explicit indeterminate outcome, and the durable
// log with its integrity checks.

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <sbf/arbiter.hpp>
#include <sbf/audit.hpp>
#include <sbf/persistence.hpp>
#include <sbf/version.hpp>

namespace {

int failures = 0;

void expect(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "consumer check failed: %s\n", what);
    ++failures;
  }
}

}  // namespace

int main() {
  using namespace sbf;

  expect(kVersion == std::string_view("1.0.0"), "installed version is 1.0.0");
  expect(!build_description().empty(), "build description is available");

  auto scope = Scope::try_parse("port-1,port-2");
  expect(scope.has_value(), "scope parses");

  ArbiterPolicy policy;
  policy.policy = PolicyId::make("policy-1");
  policy.quorum.policy = policy.policy;
  policy.quorum.witnesses.push_back(
      WitnessSlot{WitnessId::make("w0"), FaultDomainId::make("fd0")});
  policy.quorum.witnesses.push_back(
      WitnessSlot{WitnessId::make("w1"), FaultDomainId::make("fd1")});
  policy.quorum.mode = QuorumMode::MajorityDistinctWitnesses;
  expect(policy.quorum.required_witnesses() == 2, "majority of two requires two");

  FenceTable fences;
  LineageTable lineage;
  const DomainId domain = DomainId::make("domain-a");
  const Epoch epoch{1};
  const IncarnationId incarnation{2};
  const FenceToken token{1};
  const GrantId grant{1};
  expect(fences.adopt(*scope, token, epoch, incarnation, grant, Step{1}).is_ok(), "adopt");
  EpochGrant record;
  record.id = grant;
  record.domain = domain;
  record.scope = scope->digest();
  record.extents = *scope;
  record.epoch = epoch;
  record.incarnation = incarnation;
  record.boot = BootId{2};
  record.fence_token = token;
  record.opened_at = Step{1};
  record.registry_sequence = Sequence{1};
  expect(lineage.open_grant(record).is_ok(), "open grant");

  ArbiterView view;
  view.policy = &policy;
  view.fences = &fences;
  view.lineage = &lineage;
  view.now = Step{10};

  EvidenceBundle bundle;
  bundle.policy = policy.policy;
  bundle.policy_generation = policy.generation;
  bundle.as_of = view.now;
  // No attestations: the consumer must observe an explicit refusal, never a
  // silent success.
  AuthorityRequest request;
  request.claim = ClaimId::make("claim-a");
  request.domain = domain;
  request.scope = *scope;
  request.epoch = epoch;
  request.incarnation = incarnation;
  request.boot = BootId{2};
  request.presented_fence_token = token;
  request.mode = AuthorityMode::ExclusiveMutation;
  request.attempt_sequence = Sequence{1};
  request.evidence = bundle;

  const AuthorityDecision refused = decide_authority(request, view);
  expect(!refused.is_authoritative(), "no evidence is not authority");
  expect(refused.verdict == AuthorityVerdict::Unknown, "no evidence is UNKNOWN");
  expect(!verdict_permits_mutation(refused.verdict), "UNKNOWN never permits mutation");

  // Add a quorum and the same request becomes authoritative.
  for (std::size_t i = 0; i < policy.quorum.witnesses.size(); ++i) {
    WitnessAttestation attestation;
    attestation.witness = policy.quorum.witnesses[i].witness;
    attestation.subject_domain = domain;
    attestation.subject_scope = scope->digest();
    attestation.epoch = epoch;
    attestation.incarnation = incarnation;
    attestation.fence_token = token;
    attestation.witness_generation = Generation{1};
    attestation.policy_generation = policy.generation;
    attestation.issued_at = Step{1};
    attestation.valid_until = Step{1000};
    attestation.witness_sequence = Sequence{i + 1};
    attestation.support = true;
    bundle.attestations.push_back(attestation);
  }
  request.evidence = bundle;
  const AuthorityDecision granted = decide_authority(request, view);
  expect(granted.is_authoritative(), "quorum evidence grants authority");
  expect(granted.digest() == decide_authority(request, view).digest(), "decisions are pure");

  // The planner reports a bounded search honestly.
  std::vector<AuthorityRequest> candidates{request};
  const AuthorityPlan plan = select_authority_set(candidates, view, 1000);
  expect(plan.validated, "emitted plan is independently validated");
  expect(plan.authorized.size() <= 1, "plan is bounded by the candidate set");

  // Durable log round trip through the installed API.
  const auto directory = std::filesystem::temp_directory_path() / "sbf-consumer-state";
  std::error_code ec;
  std::filesystem::remove_all(directory, ec);
  StoreOpenOptions options;
  StoreRecoveryReport report;
  Store store;
  expect(Store::open(directory, StoreId::make("consumer-store"), options, store, report).is_ok(),
         "store opens");
  JournalRecord journal;
  journal.kind = RecordKind::StepAdvance;
  journal.sequence = Sequence{1};
  journal.step = Step{1};
  expect(store.append(journal).is_ok(), "record appends and flushes");
  expect(!store.append(journal).is_ok(), "a repeated sequence is refused");
  std::filesystem::remove_all(directory, ec);

  if (failures == 0) {
    std::cout << "sbf-consumer OK version=" << kVersion << std::endl;
    return 0;
  }
  return 1;
}
