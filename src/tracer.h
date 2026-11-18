// Magicmida - C++ port
// Single-step tracer used while resolving protected IAT entries.
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_TRACER_H_
#define MAGICMIDA_TRACER_H_

#include <functional>

#include "common.h"

namespace magicmida {

class Tracer {
 public:
  using Predicate = std::function<bool(Tracer&, CONTEXT&)>;

  Tracer(DWORD process_id, DWORD thread_id, HANDLE thread_handle,
         Predicate predicate);

  void Trace(uintptr_t address, uint32_t limit);

  uintptr_t StartAddress() const { return start_address_; }
  uint32_t Counter() const { return counter_; }
  bool LimitReached() const { return limit_reached_; }

 private:
  DWORD OnSingleStep(const DEBUG_EVENT& debug_event);

  DWORD process_id_;
  DWORD thread_id_;
  HANDLE thread_handle_;
  Predicate predicate_;
  uint32_t counter_ = 0;
  uint32_t limit_ = 0;
  bool limit_reached_ = false;
  uintptr_t start_address_ = 0;
};

}  // namespace magicmida

#endif  // MAGICMIDA_TRACER_H_
