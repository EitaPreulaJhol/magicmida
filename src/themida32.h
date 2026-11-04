// Magicmida - C++ port
// 32-bit Themida/WinLicense unpacking logic (ported from Themida.pas).
#pragma once

#include "themida_common.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace magicmida {

class ThemidaDebugger : public ThemidaCommon {
 public:
  ThemidaDebugger(const std::wstring& executable, const std::wstring& parameters,
                  bool createData, bool useScyllaHide = true);
  ~ThemidaDebugger() override = default;

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
  struct EFLRecord {
    uintptr_t Address = 0;
    std::vector<uint8_t> Original;
  };

  bool TMFinderCheck(CONTEXT* context);
  void SelectThemidaSection(uintptr_t eip);
  void TMInit(HANDLE& hPE);
  void TMIATFix(uintptr_t eip);
  void TMIATFix2();
  void TMIATFix3(uintptr_t eip);
  void TMIATFix4();
  void TMIATFix5(uintptr_t eax);
  void TMIATFixThemidaV1(uintptr_t baseCompare1);
  bool GetIATBPAddressNew(uintptr_t& result);
  bool InstallEFLPatch(uintptr_t eip, CONTEXT& context, EFLRecord& record);

  void InstallCodeSectionGuard(uint32_t protection);
  bool IsGuardedAddress(uintptr_t address);
  DWORD ProcessGuardedAccess(HANDLE hThread,
                             const EXCEPTION_RECORD& exceptionRecord);

  void RestoreStolenOEPForMSVC6(HANDLE hThread, uintptr_t& oep);
  void RestoreStolenOEPForMSVC9DLL(HANDLE hThread, uintptr_t& oep);
  uintptr_t TryFindCorrectOEP(uintptr_t oep);
  bool IsTMExceptionHandler(uintptr_t address);
  void FixupAPICallSites(uintptr_t iat);
  void FinishUnpacking(uintptr_t oep);

  bool wow64_ = false;

  int baseAccessCount_ = 0;
  bool compressed_ = false;
  uintptr_t base1_ = 0;
  uintptr_t repEIP_ = 0;
  uintptr_t ntQIP_ = 0;

  void* closeHandleAPI_ = nullptr;
  void* allocMemAPI_ = nullptr;
  void* allocHeapAPI_ = nullptr;
  void* kiFastSystemCall_ = nullptr;
  void* ntSIT_ = nullptr;
  void* ntQIP64_ = nullptr;
  void* virtualProtectAPI_ = nullptr;
  void* corExeMain_ = nullptr;

  void* cmpImgBase_ = nullptr;
  void* magicJump_ = nullptr;
  void* magicJumpV1_ = nullptr;

  bool baseAccessed_ = false;
  bool newVer_ = false;
  bool ancientVer_ = false;
  int allocMemCounter_ = 0;

  uintptr_t iJumper_ = 0;
  uintptr_t mj1_ = 0;
  uintptr_t mj2_ = 0;
  uintptr_t mj3_ = 0;
  uintptr_t mj4_ = 0;
  std::array<EFLRecord, 3> efls_{};
  bool themidaV2BySections_ = false;

  uintptr_t guardStart_ = 0;
  uintptr_t guardEnd_ = 0;
  uint32_t guardProtection_ = 0;
  bool guardStepping_ = false;

  uint32_t tlsAddressesOfCallbacks_ = 0;
  uint32_t tlsCounter_ = 0;
  uint32_t tlsTotal_ = 0;
};

}  // namespace magicmida
