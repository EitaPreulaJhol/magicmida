// Magicmida - C++ port
// 32-bit Themida/WinLicense unpacking logic (ported from Themida.pas).
#ifndef MAGICMIDA_THEMIDA32_H_
#define MAGICMIDA_THEMIDA32_H_

#include "themida_common.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace magicmida {

class ThemidaDebugger : public ThemidaCommon {
 public:
  ThemidaDebugger(const std::wstring& executable,
                  const std::wstring& parameters, bool createData,
                  bool use_scylla_hide = true, bool fix_relocations = false);
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
  SoftBPAction OnSoftwareBreakpoint(HANDLE hThread,
                                    uintptr_t bpAddress) override;

 private:
  struct EFLRecord {
    uintptr_t address = 0;
    std::vector<uint8_t> original;
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

  int base_access_count_ = 0;
  bool compressed_ = false;
  uintptr_t base1_ = 0;
  uintptr_t rep_eip_ = 0;
  uintptr_t nt_qip_ = 0;

  void* close_handle_api_ = nullptr;
  void* alloc_mem_api_ = nullptr;
  void* alloc_heap_api_ = nullptr;
  void* ki_fast_system_call_ = nullptr;
  void* nt_sit_ = nullptr;
  void* nt_qip64_ = nullptr;
  void* virtual_protect_api_ = nullptr;
  void* cor_exe_main_ = nullptr;

  void* cmp_img_base_ = nullptr;
  void* magic_jump_ = nullptr;
  void* magic_jump_v1_ = nullptr;

  bool base_accessed_ = false;
  bool new_ver_ = false;
  bool ancient_ver_ = false;
  int alloc_mem_counter_ = 0;

  uintptr_t iat_jumper_ = 0;
  uintptr_t mj1_ = 0;
  uintptr_t mj2_ = 0;
  uintptr_t mj3_ = 0;
  uintptr_t mj4_ = 0;
  std::array<EFLRecord, 3> efls_{};
  bool themida_v2_by_sections_ = false;

  uintptr_t guard_start_ = 0;
  uintptr_t guard_end_ = 0;
  uint32_t guard_protection_ = 0;
  bool guard_stepping_ = false;

  uint32_t tls_addresses_of_callbacks_ = 0;
  uint32_t tls_counter_ = 0;
  uint32_t tls_total_ = 0;
};

}  // namespace magicmida

#endif  // MAGICMIDA_THEMIDA32_H_
