#include "sbf/ids.hpp"

#include "sbf/limits.hpp"

namespace sbf {
namespace {

bool id_charset_ok(std::string_view value) noexcept {
  for (const char raw : value) {
    const auto c = static_cast<unsigned char>(raw);
    const bool alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    const bool punctuation = c == '.' || c == '_' || c == ':' || c == '-';
    if (!alnum && !punctuation) return false;
  }
  return true;
}

}  // namespace

template <class Tag>
Status Id<Tag>::validate(std::string_view value) noexcept {
  if (value.empty()) return Status::make(Outcome::Invalid, Reason::EmptyValue);
  if (value.size() > limits::kMaxIdLength) {
    return Status::make(Outcome::Invalid, Reason::IdTooLong, value.size());
  }
  if (!id_charset_ok(value)) return Status::make(Outcome::Invalid, Reason::IdCharset, value.size());
  return Status::ok();
}

template <class Tag>
Id<Tag> Id<Tag>::make(std::string_view value) {
  Id id;
  if (!validate(value).is_ok()) {
    // Fail closed: an invalid identifier becomes empty, which every downstream
    // validation rejects. Callers that accept untrusted input use try_make.
    return id;
  }
  id.value_.assign(value);
  return id;
}

template class Id<DomainIdTag>;
template class Id<ExtentIdTag>;
template class Id<WitnessIdTag>;
template class Id<StoreIdTag>;
template class Id<PolicyIdTag>;
template class Id<ClaimIdTag>;
template class Id<NodeIdTag>;
template class Id<FaultDomainIdTag>;

}  // namespace sbf
