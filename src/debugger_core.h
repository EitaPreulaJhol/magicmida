// Magicmida - C++ port
// Debugger primitives: process creation, debug loop, HW/SW breakpoints.
#pragma once

#include "common.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace magicmida {

enum class HWBPType : uint8_t {
  Execute = 0,
  Write = 1,
  Reserved = 2,
  Access = 3,
};

struct Breakpoint {
  uintptr_t Address = 0;
  HWBPType Type = HWBPType::Execute;
  bool Disabled = false;

  void Change(uintptr_t address, HWBPType type) {
    Address = address;
    Type = type;
    Disabled = false;
  }

  bool IsSet() const { return !Disabled && Address > 0; }
};

enum class SoftBPAction {
  KeepContinue,
  ClearContinue,
  KeepContinueNoStep,
};

class DebuggerCore {
 public:
  DebuggerCore(const std::wstring& executable, const std::wstring& parameters);
  explicit DebuggerCore(DWORD attachPid);
  virtual ~DebuggerCore() = default;

  DebuggerCore(const DebuggerCore&) = delete;
  DebuggerCore& operator=(const DebuggerCore&) = delete;

  // Alias of the original TThread.Execute + WaitFor pair.
  void Run();

  void Detach();

  bool Succeeded() const { return succeeded_; }

  HANDLE ProcessHandle() const { return process_.hProcess; }
  const PROCESS_INFORMATION& ProcessInfo() const { return process_; }
  DWORD CurrentThreadId() const { return currentThreadId_; }
  uintptr_t ImageBase() const { return imageBase_; }

 protected:
  void MarkSuccess() { succeeded_ = true; }

  HANDLE GetThread(DWORD threadId);

  void FetchMemoryRegions();
  bool RPM(uintptr_t address, void* buf, size_t bufSize);

  void SetBreakpoint(uintptr_t address, HWBPType type = HWBPType::Execute,
                     bool refreshContexts = true);
  bool DisableBreakpoint(uintptr_t address);
  void EnableBreakpoints();
  void ResetBreakpoint(uintptr_t address);
  bool IsHWBreakpoint(uintptr_t address);
  void ApplyDebugRegisters(CONTEXT& context);
  void UpdateDR(HANDLE thread);

  void SetSoftBP(uintptr_t address);
  void SoftBPClear();

  // Hooks (original virtual methods).
  virtual void OnDebugStart(HANDLE& hPE, HANDLE hThread) = 0;
  virtual DWORD OnAccessViolation(HANDLE hThread, const EXCEPTION_RECORD& exceptionRecord);
  virtual void OnDLLLoad(const std::wstring& fileName, void* baseAddress);
  virtual void OnHardwareBreakpoint(HANDLE hThread, uintptr_t bpAddress, CONTEXT& context) = 0;
  virtual SoftBPAction OnSoftwareBreakpoint(HANDLE hThread, uintptr_t bpAddress) = 0;
  virtual void OnUnsolicitedSoftwareBreakpoint(HANDLE hThread, uintptr_t bpAddress);
  virtual DWORD OnSinglestep(uintptr_t bpAddress);

  // State shared with the Themida-specific implementations.
  std::wstring executable_;
  std::wstring parameters_;
  bool isDll_ = false;
  PROCESS_INFORMATION process_{};
  DWORD currentThreadId_ = 0;
  uintptr_t imageBase_ = 0;
  std::vector<MemoryRegion> memRegions_;
  bool hideThreadEnd_ = false;

 private:
  bool PEExecute();
  void PEInspect();
  void MakeDLLExecutable();

  DWORD OnCreateThreadDebugEvent(DEBUG_EVENT& debugEvent);
  DWORD OnCreateProcessDebugEvent(DEBUG_EVENT& debugEvent);
  DWORD OnExitThreadDebugEvent(DEBUG_EVENT& debugEvent);
  DWORD OnLoadDllDebugEvent(DEBUG_EVENT& debugEvent);
  DWORD OnExitProcessDebugEvent(DEBUG_EVENT& debugEvent);
  DWORD OnUnloadDllDebugEvent(DEBUG_EVENT& debugEvent);
  DWORD OnOutputDebugStringEvent(DEBUG_EVENT& debugEvent);
  DWORD OnRipEvent(DEBUG_EVENT& debugEvent);
  DWORD OnHardwareBreakpointEvent(DEBUG_EVENT& debugEvent);
  DWORD OnSoftwareBreakpointEvent(DEBUG_EVENT& debugEvent);

  bool WriteByte(uintptr_t address, uint8_t value);

  // Releases the process/thread handles owned by the debug loop and makes
  // sure the target does not stay alive when unpacking fails.
  void TerminateDebuggee();
  void CloseProcessHandles();
  void DeleteDllCopy();

  DWORD attachPid_ = 0;
  std::wstring dllExecutable_;
  Breakpoint hw_[4];
  std::unordered_map<DWORD, HANDLE> threads_;
  std::unordered_map<uintptr_t, uint8_t> softBPs_;
  uintptr_t softBPReenable_ = 0;
  bool succeeded_ = false;
};

}  // namespace magicmida
