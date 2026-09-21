#include "sbf/authority.hpp"

#include "sbf/canonical.hpp"
#include "sbf/text.hpp"

namespace sbf {
namespace {

void encode_vector(CanonicalWriter& writer, const AuthorityVector& vector) {
  writer.text(vector.domain.view());
  writer.digest(vector.scope);
  writer.counter(vector.epoch);
  writer.counter(vector.incarnation);
  writer.counter(vector.fence_token);
  writer.counter(vector.grant);
  writer.counter(vector.authority_sequence);
  writer.counter(vector.policy_generation);
  writer.counter(vector.evidence_generation);
  writer.counter(vector.fence_generation);
}

}  // namespace

std::string_view to_string(AuthorityMode mode) noexcept {
  switch (mode) {
    case AuthorityMode::Observation: return "Observation";
    case AuthorityMode::EligibilityProbe: return "EligibilityProbe";
    case AuthorityMode::RecommendationRequest: return "RecommendationRequest";
    case AuthorityMode::SharedRead: return "SharedRead";
    case AuthorityMode::ExclusiveMutation: return "ExclusiveMutation";
  }
  return "Unknown";
}

std::string_view to_string(AuthorityVerdict verdict) noexcept {
  switch (verdict) {
    case AuthorityVerdict::Authoritative: return "AUTHORITATIVE";
    case AuthorityVerdict::Fenced: return "FENCED";
    case AuthorityVerdict::ObserveOnly: return "OBSERVE_ONLY";
    case AuthorityVerdict::Eligible: return "ELIGIBLE";
    case AuthorityVerdict::Recommended: return "RECOMMENDED";
    case AuthorityVerdict::Acknowledged: return "ACKNOWLEDGED";
    case AuthorityVerdict::Applied: return "APPLIED";
    case AuthorityVerdict::Unknown: return "UNKNOWN";
    case AuthorityVerdict::Stale: return "STALE";
    case AuthorityVerdict::Conflict: return "CONFLICT";
    case AuthorityVerdict::Invalid: return "INVALID";
    case AuthorityVerdict::Unsupported: return "UNSUPPORTED";
    case AuthorityVerdict::Refused: return "REFUSED";
    case AuthorityVerdict::Interrupted: return "INTERRUPTED";
  }
  return "UNKNOWN";
}

bool verdict_carries_authority(AuthorityVerdict verdict) noexcept {
  return verdict == AuthorityVerdict::Authoritative;
}

bool verdict_permits_mutation(AuthorityVerdict verdict) noexcept {
  // Exactly one verdict authorises a mutation. In particular Applied - a report
  // about an effect that already happened - does not.
  return verdict == AuthorityVerdict::Authoritative;
}

Digest256 AuthorityVector::digest() const {
  CanonicalWriter writer;
  encode_vector(writer, *this);
  return Digest256::of(writer.bytes());
}

Digest256 AuthorityDecision::digest() const {
  CanonicalWriter writer;
  writer.u16(static_cast<std::uint16_t>(verdict));
  writer.outcome(status.outcome);
  writer.reason(status.reason);
  writer.u64(status.aux);
  encode_vector(writer, vector);
  writer.counter(decision_sequence);
  writer.boolean(revocable);
  return Digest256::of(writer.bytes());
}

std::string describe(const AuthorityVector& vector) {
  std::string out;
  out.reserve(160);
  out.append("domain=");
  out.append(vector.domain.view());
  out.append(" scope=");
  out.append(vector.scope.hex().substr(0, 16));
  out.append(" epoch=");
  out.append(text::hex_u64(vector.epoch.value()));
  out.append(" incarnation=");
  out.append(text::hex_u64(vector.incarnation.value()));
  out.append(" token=");
  out.append(text::hex_u64(vector.fence_token.value()));
  out.append(" grant=");
  out.append(text::hex_u64(vector.grant.value()));
  return out;
}

std::string describe(const AuthorityDecision& decision) {
  std::string out = describe(decision.vector);
  out.append(" verdict=");
  out.append(to_string(decision.verdict));
  out.append(" status=");
  out.append(sbf::to_string(decision.status));
  return out;
}

}  // namespace sbf
