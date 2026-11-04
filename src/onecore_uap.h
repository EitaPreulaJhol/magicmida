// Magicmida - C++ port
// API set (OneCoreUAP) lookup, generated from OneCoreUAP.pas.
#pragma once

#include <string>

namespace magicmida {

// Returns the api-set DLL that hosts `api`, or an empty string when unknown.
std::string GetOneCoreUAPModuleByAPI(const std::string& api);

}  // namespace magicmida
