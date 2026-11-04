// Magicmida - C++ port
// Single-step tracer used while resolving protected IAT entries.
#pragma once

#include "common.h"

#include <functional>

namespace magicmida {

class Tracer {
 public:
  using Predicate = std::function<bool(Tracer&, CONTEXT&)>;

  Tracer(DWORD processId, DWORD threadId, HANDLE threadHandle,
         Predicate predicate);

  void Trace(uintptr_t address, uint32_t limit);

  uintptr_t StartAddress() const { return startAddress_; }
  uint32_t Counter() const { return counter_; }
  bool LimitReached() const { return limitReached_; }

 private:
  DWORD OnSingleStep(const DEBUG_EVENT& debugEvent);

  DWORD processId_;
  DWORD threadId_;
  HANDLE threadHandle_;
  Predicate predicate_;
  uint32_t counter_ = 0;
  uint32_t limit_ = 0;
  bool limitReached_ = false;
  uintptr_t startAddress_ = 0;
};

}  // namespace magicmida
