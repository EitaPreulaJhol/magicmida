// Magicmida - C++ port
// Single-step tracer used while resolving protected IAT entries.
#include "tracer.h"

#include <stdexcept>
#include <utility>

namespace magicmida {

Tracer::Tracer(DWORD processId, DWORD threadId, HANDLE threadHandle,
               Predicate predicate)
    : process_id_(processId),
      thread_id_(threadId),
      thread_handle_(threadHandle),
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

    DEBUG_EVENT debugEvent{};
    if (!WaitForDebugEvent(&debugEvent, 200)) {
      const DWORD error = GetLastError();
      if (error == ERROR_SEM_TIMEOUT) {
        continue;
      }
      throw std::runtime_error(
          Format("WaitForDebugEvent failed during tracing (error %lu)", error));
    }

    if (debugEvent.dwThreadId != thread_id_) {
      LogF(kLogInfo, "Suspending spurious thread %lu", debugEvent.dwThreadId);
      HANDLE thread =
          OpenThread(THREAD_SUSPEND_RESUME, FALSE,
                     debugEvent.dwThreadId);  // 2 == THREAD_SUSPEND_RESUME
      if (thread != nullptr && thread != INVALID_HANDLE_VALUE) {
        SuspendThread(thread);
        CloseHandle(thread);
      }
      ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId,
                         DBG_CONTINUE);
      continue;
    }

    switch (debugEvent.dwDebugEventCode) {
      case EXCEPTION_DEBUG_EVENT:
        if (MM_EVENT_FIELD(debugEvent, Exception)
                .ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
          status = OnSingleStep(debugEvent);
          if (status == DBG_CONTROL_BREAK) {
            // Leave the single-step event pending on purpose: the target
            // stays stopped at the traced address until the next Trace()
            // redirects it. The caller terminates the target before dumping.
            return;
          }
        } else {
          throw std::runtime_error(Format(
              "Unexpected exception during tracing: %.8X at %p in thread %lu",
              MM_EVENT_FIELD(debugEvent, Exception)
                  .ExceptionRecord.ExceptionCode,
              MM_EVENT_FIELD(debugEvent, Exception)
                  .ExceptionRecord.ExceptionAddress,
              debugEvent.dwThreadId));
        }
        break;

      default:
        status = DBG_CONTINUE;
        break;
    }

    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, status);
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
