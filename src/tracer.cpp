// Magicmida - C++ port
// Single-step tracer used while resolving protected IAT entries.
#include "tracer.h"

namespace magicmida {

Tracer::Tracer(DWORD processId, DWORD threadId, HANDLE threadHandle,
               Predicate predicate)
    : processId_(processId),
      threadId_(threadId),
      threadHandle_(threadHandle),
      predicate_(std::move(predicate)) {}

void Tracer::Trace(uintptr_t address, uint32_t limit) {
  counter_ = 0;
  limit_ = limit;
  limitReached_ = false;
  startAddress_ = address;

  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL;
  if (!GetThreadContext(threadHandle_, &context)) {
    throw std::runtime_error(Format("GetThreadContext failed (error %lu)",
                                    GetLastError()));
  }

#if defined(_WIN64)
  context.Rip = address;
#else
  context.Eip = address;
#endif
  context.EFlags |= 0x100;  // Trap
  if (!SetThreadContext(threadHandle_, &context)) {
    throw std::runtime_error(Format("SetThreadContext failed (error %lu)",
                                    GetLastError()));
  }

  if (!ContinueDebugEvent(processId_, threadId_, DBG_CONTINUE)) {
    return;
  }

  DWORD status = DBG_EXCEPTION_NOT_HANDLED;
  DEBUG_EVENT debugEvent{};
  while (WaitForDebugEvent(&debugEvent, INFINITE)) {
    if (debugEvent.dwThreadId != threadId_) {
      LogF(ltInfo, "Suspending spurious thread %lu", debugEvent.dwThreadId);
      HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE,
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
        if (MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionCode ==
            EXCEPTION_SINGLE_STEP) {
          status = OnSingleStep(debugEvent);
          if (status == DBG_CONTROL_BREAK) {
            return;
          }
        } else {
          LogF(ltFatal,
               "Unexpected exception during tracing: %.8X at %p in thread %lu",
               MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionCode,
               MM_EVENT_FIELD(debugEvent, Exception).ExceptionRecord.ExceptionAddress,
               debugEvent.dwThreadId);
          return;
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
    limitReached_ = true;
    Log(ltInfo, "Giving up trace due to instruction limit");
    return DBG_CONTROL_BREAK;
  }

  CONTEXT context{};
  context.ContextFlags = CONTEXT_CONTROL;
  if (!GetThreadContext(threadHandle_, &context)) {
    throw std::runtime_error(Format("GetThreadContext failed (error %lu)",
                                    GetLastError()));
  }

  DWORD result = DBG_CONTINUE;
  if (predicate_ && predicate_(*this, context)) {
    result = DBG_CONTROL_BREAK;
  }

  context.EFlags |= 0x100;
  if (!SetThreadContext(threadHandle_, &context)) {
    throw std::runtime_error(Format("SetThreadContext failed (error %lu)",
                                    GetLastError()));
  }
  return result;
}

}  // namespace magicmida
