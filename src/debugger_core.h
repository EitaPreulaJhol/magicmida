// Magicmida - C++ port
// Debugger primitives: process creation, debug loop, HW/SW breakpoints.
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_DEBUGGER_CORE_H_
#define MAGICMIDA_DEBUGGER_CORE_H_

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "common.h"

namespace magicmida {

enum class HwbpType : uint8_t {
  kExecute = 0,
  kWrite = 1,
  kReserved = 2,
  kAccess = 3,
};

struct Breakpoint {
  uintptr_t address = 0;
  HwbpType type = HwbpType::kExecute;
  bool disabled = false;

  void Change(uintptr_t new_address, HwbpType new_type) {
    address = new_address;
    type = new_type;
    disabled = false;
  }

  bool IsSet() const { return !disabled && address > 0; }
};

enum class SoftBpAction {
  kKeepContinue,
  kClearContinue,
  kKeepContinueNoStep,
};

class DebuggerCore {
 public:
  DebuggerCore(const std::wstring& executable, const std::wstring& parameters);
  explicit DebuggerCore(DWORD attach_pid);
  virtual ~DebuggerCore() = default;

  DebuggerCore(const DebuggerCore&) = delete;
  DebuggerCore& operator=(const DebuggerCore&) = delete;

  // Alias of the original TThread.Execute + WaitFor pair.
  void Run();

  void Detach();

  bool Succeeded() const { return succeeded_; }

  HANDLE ProcessHandle() const { return process_.hProcess; }
  const PROCESS_INFORMATION& ProcessInfo() const { return process_; }
  DWORD CurrentThreadId() const { return current_thread_id_; }
  uintptr_t ImageBase() const { return image_base_; }

 protected:
  void MarkSuccess() { succeeded_ = true; }

  HANDLE GetThread(DWORD thread_id);

  void FetchMemoryRegions();
  bool Rpm(uintptr_t address, void* buf, size_t buf_size);

  void SetBreakpoint(uintptr_t address, HwbpType type = HwbpType::kExecute,
                     bool refresh_contexts = true);
  bool DisableBreakpoint(uintptr_t address);
  void EnableBreakpoints();
  void ResetBreakpoint(uintptr_t address);
  bool IsHwBreakpoint(uintptr_t address);
  void ApplyDebugRegisters(CONTEXT& context);
  void UpdateDr(HANDLE thread);

  void SetSoftBp(uintptr_t address);
  void SoftBpClear();

  // Hooks (original virtual methods).
  virtual void OnDebugStart(HANDLE& file_handle, HANDLE thread_handle) = 0;
  virtual DWORD OnAccessViolation(HANDLE thread_handle,
                                  const EXCEPTION_RECORD& exception_record);
  virtual void OnDllLoad(const std::wstring& file_name, void* base_address);
  virtual void OnHardwareBreakpoint(HANDLE thread_handle, uintptr_t bp_address,
                                    CONTEXT& context) = 0;
  virtual SoftBpAction OnSoftwareBreakpoint(HANDLE thread_handle,
                                            uintptr_t bp_address) = 0;
  virtual void OnUnsolicitedSoftwareBreakpoint(HANDLE thread_handle,
                                               uintptr_t bp_address);
  virtual DWORD OnSinglestep(uintptr_t bp_address);

  // State shared with the Themida-specific implementations.
  std::wstring executable_;
  std::wstring parameters_;
  bool is_dll_ = false;
  PROCESS_INFORMATION process_{};
  DWORD current_thread_id_ = 0;
  uintptr_t image_base_ = 0;
  std::vector<MemoryRegion> mem_regions_;
  bool hide_thread_end_ = false;

 private:
  bool PeExecute();
  void PeInspect();
  void MakeDllExecutable();

  DWORD OnCreateThreadDebugEvent(DEBUG_EVENT& debug_event);
  DWORD OnCreateProcessDebugEvent(DEBUG_EVENT& debug_event);
  DWORD OnExitThreadDebugEvent(DEBUG_EVENT& debug_event);
  DWORD OnLoadDllDebugEvent(DEBUG_EVENT& debug_event);
  DWORD OnExitProcessDebugEvent(DEBUG_EVENT& debug_event);
  DWORD OnUnloadDllDebugEvent(DEBUG_EVENT& debug_event);
  DWORD OnOutputDebugStringEvent(DEBUG_EVENT& debug_event);
  DWORD OnRipEvent(DEBUG_EVENT& debug_event);
  DWORD OnHardwareBreakpointEvent(DEBUG_EVENT& debug_event);
  DWORD OnSoftwareBreakpointEvent(DEBUG_EVENT& debug_event);

  bool WriteByte(uintptr_t address, uint8_t value);

  // Releases the process/thread handles owned by the debug loop and makes
  // sure the target does not stay alive when unpacking fails.
  void TerminateDebuggee();
  void CloseProcessHandles();
  void DeleteDllCopy();

  DWORD attach_pid_ = 0;
  std::wstring dll_executable_;
  Breakpoint hw_[4];
  std::unordered_map<DWORD, HANDLE> threads_;
  std::unordered_map<uintptr_t, uint8_t> soft_bps_;
  uintptr_t soft_bp_reenable_ = 0;
  bool succeeded_ = false;
};

}  // namespace magicmida

#endif  // MAGICMIDA_DEBUGGER_CORE_H_
