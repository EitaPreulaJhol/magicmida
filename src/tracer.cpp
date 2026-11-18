// Magicmida - C++ port
// Single-step tracer used while resolving protected IAT entries.
#include "tracer.h"

#include <stdexcept>
#include <utility>

namespace magicmida {

Tracer::Tracer(DWORD process_id, DWORD thread_id, HANDLE thread_handle,
               Predicate predicate)
    : process_id_(process_id),
      thread_id_(thread_id),
      thread_handle_(thread_handle),
      predicate_(std::move(predicate)) {}

void Tracer::Trace(uintptr_t address, uint32_t limit) {
  counter_ = 0;
  limit_ = limit;
  limit_reached_ = false;
  start_address_ = address;

  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL;
  if (!GetThreadContext(thread_handle_, &context)) {
    throw std::runtime_error(
        Format("GetThreadContext failed (error %lu)", GetLastError()));
  }

#if defined(_WIN64)
  context.Rip = address;
#else
  context.Eip = address;
#endif
  context.EFlags |= 0x100;  // Trap
  if (!SetThreadContext(thread_handle_, &context)) {
    throw std::runtime_error(
        Format("SetThreadContext failed (error %lu)", GetLastError()));
  }

  if (!ContinueDebugEvent(process_id_, thread_id_, DBG_CONTINUE)) {
    throw std::runtime_error(
        Format("ContinueDebugEvent failed during tracing (error %lu)",
               GetLastError()));
  }

  DWORD status = DBG_EXCEPTION_NOT_HANDLED;
  for (;;) {
    if (IsCancellationRequested()) {
      throw std::runtime_error("Cancelled by the user");
    }

    DEBUG_EVENT debug_event{};
    if (!WaitForDebugEvent(&debug_event, 200)) {
      const DWORD error = GetLastError();
      if (error == ERROR_SEM_TIMEOUT) {
        continue;
      }
      throw std::runtime_error(
          Format("WaitForDebugEvent failed during tracing (error %lu)", error));
    }

    if (debug_event.dwThreadId != thread_id_) {
      LogF(kLogInfo, "Suspending spurious thread %lu", debug_event.dwThreadId);
      HANDLE thread =
          OpenThread(THREAD_SUSPEND_RESUME, FALSE,
                     debug_event.dwThreadId);  // 2 == THREAD_SUSPEND_RESUME
      if (thread != nullptr && thread != INVALID_HANDLE_VALUE) {
        SuspendThread(thread);
        CloseHandle(thread);
      }
      ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId,
                         DBG_CONTINUE);
      continue;
    }

    switch (debug_event.dwDebugEventCode) {
      case EXCEPTION_DEBUG_EVENT:
        if (MM_EVENT_FIELD(debug_event, Exception)
                .ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
          status = OnSingleStep(debug_event);
          if (status == DBG_CONTROL_BREAK) {
            // Leave the single-step event pending on purpose: the target
            // stays stopped at the traced address until the next Trace()
            // redirects it. The caller terminates the target before dumping.
            return;
          }
        } else {
          throw std::runtime_error(Format(
              "Unexpected exception during tracing: %.8X at %p in thread %lu",
              MM_EVENT_FIELD(debug_event, Exception)
                  .ExceptionRecord.ExceptionCode,
              MM_EVENT_FIELD(debug_event, Exception)
                  .ExceptionRecord.ExceptionAddress,
              debug_event.dwThreadId));
        }
        break;

      default:
        status = DBG_CONTINUE;
        break;
    }

    ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, status);
  }
}

DWORD Tracer::OnSingleStep(const DEBUG_EVENT& /*debugEvent*/) {
  ++counter_;
  if (limit_ != 0 && counter_ > limit_) {
    limit_reached_ = true;
    Log(kLogInfo, "Giving up trace due to instruction limit");
    return DBG_CONTROL_BREAK;
  }

  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL;
  if (!GetThreadContext(thread_handle_, &context)) {
    throw std::runtime_error(
        Format("GetThreadContext failed (error %lu)", GetLastError()));
  }

  DWORD result = DBG_CONTINUE;
  if (predicate_ && predicate_(*this, context)) {
    result = DBG_CONTROL_BREAK;
  }

  context.EFlags |= 0x100;
  if (!SetThreadContext(thread_handle_, &context)) {
    throw std::runtime_error(
        Format("SetThreadContext failed (error %lu)", GetLastError()));
  }
  return result;
}

}  // namespace magicmida
