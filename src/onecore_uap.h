// Magicmida - C++ port
// API set (OneCoreUAP) lookup, generated from OneCoreUAP.pas.
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_ONECORE_UAP_H_
#define MAGICMIDA_ONECORE_UAP_H_

#include <string>

namespace magicmida {

// Returns the api-set DLL that hosts `api`, or an empty string when unknown.
std::string GetOneCoreUapModuleByApi(const std::string& api);

}  // namespace magicmida

#endif  // MAGICMIDA_ONECORE_UAP_H_
