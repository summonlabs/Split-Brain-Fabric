#include "sbf/version.hpp"

namespace sbf {

std::string_view build_description() noexcept {
  return "Split-Brain Fabric " SBF_VERSION_STRING
         " (authority fencing and split-brain prevention runtime)";
}

}  // namespace sbf
