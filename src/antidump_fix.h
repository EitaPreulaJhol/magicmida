// Magicmida - C++ port
// VM anti-dump mitigation (ported from AntiDumpFix.pas).
#pragma once

#include "common.h"

#include <cstdint>

namespace magicmida {

// This fixes only one type of anti dump, and it's not guaranteed that it'll be
// the type used for the OEP. If your binary uses virtualization in other parts
// of the program, it will very likely crash.
class AntiDumpFixer {
 public:
  AntiDumpFixer(HANDLE process, uintptr_t imageBase);

  void RedirectOEP(uintptr_t oep, uintptr_t iat);

 private:
  bool RPM(uintptr_t address, void* buf, size_t bufSize);

  HANDLE process_;
  uintptr_t imageBase_;
};

}  // namespace magicmida
