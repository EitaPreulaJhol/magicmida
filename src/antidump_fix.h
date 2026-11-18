// Magicmida - C++ port
// VM anti-dump mitigation (ported from AntiDumpFix.pas).
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_ANTIDUMP_FIX_H_
#define MAGICMIDA_ANTIDUMP_FIX_H_

#include <cstdint>

#include "common.h"

namespace magicmida {

// This fixes only one type of anti dump, and it's not guaranteed that it'll be
// the type used for the OEP. If your binary uses virtualization in other parts
// of the program, it will very likely crash.
class AntiDumpFixer {
 public:
  AntiDumpFixer(HANDLE process, uintptr_t image_base);

  void RedirectOep(uintptr_t oep, uintptr_t iat);

 private:
  bool Rpm(uintptr_t address, void* buf, size_t buf_size);

  HANDLE process_;
  uintptr_t image_base_;
};

}  // namespace magicmida

#endif  // MAGICMIDA_ANTIDUMP_FIX_H_
