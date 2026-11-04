// Magicmida - C++ port
// API set (OneCoreUAP) lookup, generated from OneCoreUAP.pas.
#include "onecore_uap.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <cstring>
#include <string_view>

namespace magicmida {
namespace {

struct ApiSetEntry {
  const char* api;
  const char* module;
};

constexpr ApiSetEntry kApiSetApis[] = {
#include "onecore_uap_table.inc"
};

}  // namespace

std::string GetOneCoreUAPModuleByAPI(const std::string& api) {
  const auto it = std::lower_bound(
      std::begin(kApiSetApis), std::end(kApiSetApis), api,
      [](const ApiSetEntry& entry, const std::string& value) {
        return std::string_view(entry.api) < value;
      });

  if (it == std::end(kApiSetApis) || api != it->api) {
    return {};
  }
  return it->module;
}

}  // namespace magicmida
