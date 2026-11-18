// Magicmida - C++ port
// 64-bit Themida/WinLicense unpacking logic (ported from Themida64.pas).
#ifndef MAGICMIDA_THEMIDA64_H_
#define MAGICMIDA_THEMIDA64_H_

#include "themida_common.h"

#include <cstdint>
#include <string>

namespace magicmida {

class ThemidaDebugger64 : public ThemidaCommon {
 public:
  ThemidaDebugger64(const std::wstring& executable,
                    const std::wstring& parameters, bool createData,
                    bool use_scylla_hide = true, bool fix_relocations = false);
  ~ThemidaDebugger64() override = default;

 protected:
  bool TraceIsAtAPI(Tracer& tracer, CONTEXT& context) override;

  void OnDebugStart(HANDLE& hPE, HANDLE hThread) override;
  DWORD OnAccessViolation(HANDLE hThread,
                          const EXCEPTION_RECORD& exceptionRecord) override;
  void OnDLLLoad(const std::wstring& fileName, void* baseAddress) override;
  DWORD OnSinglestep(uintptr_t bpAddress) override;
  void OnHardwareBreakpoint(HANDLE hThread, uintptr_t bpAddress,
                            CONTEXT& context) override;
  SoftBPAction OnSoftwareBreakpoint(HANDLE hThread,
                                    uintptr_t bpAddress) override;

 private:
  void DumpContext(DWORD threadId);
  bool InImageBounds(uintptr_t address) const;

  void SelectThemidaSection(uintptr_t address);
  void TMInit(HANDLE& hPE);

  void InstallCodeSectionGuard();
  bool IsGuardedAddress(uintptr_t address);
  DWORD ProcessGuardedAccess(HANDLE hThread,
                             const EXCEPTION_RECORD& exceptionRecord);

  void FinishUnpacking(uintptr_t oep);

  uintptr_t TryFindCorrectOEP(uintptr_t hitAddress);
  void WriteMSVCOEP(uintptr_t crtStartup);

  void* close_handle_api_ = nullptr;
  void* virtual_alloc_api_ = nullptr;
  void* cor_exe_main_ = nullptr;

  uintptr_t guard_start_ = 0;
  uintptr_t guard_end_ = 0;
  bool guard_stepping_ = false;
  bool tm_guard_ = false;
  bool trace_msvc_oep_ = false;

  uintptr_t msvc_init_cookie_ = 0;
  uintptr_t msvc_oep_ = 0;

  uint32_t tls_counter_ = 0;
  uint32_t tls_total_ = 0;
};

}  // namespace magicmida

#endif  // MAGICMIDA_THEMIDA64_H_
