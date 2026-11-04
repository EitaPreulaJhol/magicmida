// Magicmida - C++ port
// 64-bit Themida/WinLicense unpacking logic (ported from Themida64.pas).
#pragma once

#include "themida_common.h"

#include <cstdint>
#include <string>

namespace magicmida {

class ThemidaDebugger64 : public ThemidaCommon {
 public:
  ThemidaDebugger64(const std::wstring& executable,
                    const std::wstring& parameters, bool createData,
                    bool useScyllaHide = true,
                    bool fixRelocations = false);
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
  SoftBPAction OnSoftwareBreakpoint(HANDLE hThread, uintptr_t bpAddress) override;

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

  void* closeHandleAPI_ = nullptr;
  void* virtualAllocAPI_ = nullptr;
  void* corExeMain_ = nullptr;

  uintptr_t guardStart_ = 0;
  uintptr_t guardEnd_ = 0;
  bool guardStepping_ = false;
  bool tmGuard_ = false;
  bool traceMSVCOEP_ = false;

  uintptr_t msvcInitCookie_ = 0;
  uintptr_t msvcOEP_ = 0;

  uint32_t tlsCounter_ = 0;
  uint32_t tlsTotal_ = 0;
};

}  // namespace magicmida
