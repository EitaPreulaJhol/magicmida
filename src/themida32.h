// Magicmida - C++ port
// 32-bit Themida/WinLicense unpacking logic (ported from Themida.pas).
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_THEMIDA32_H_
#define MAGICMIDA_THEMIDA32_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "themida_common.h"

namespace magicmida {

class ThemidaDebugger : public ThemidaCommon {
 public:
  ThemidaDebugger(const std::wstring& executable,
                  const std::wstring& parameters, bool create_data,
                  bool use_scylla_hide = true, bool fix_relocations = false);
  ~ThemidaDebugger() override = default;

 protected:
  bool TraceIsAtApi(Tracer& tracer, CONTEXT& context) override;

  void OnDebugStart(HANDLE& file_handle, HANDLE thread_handle) override;
  DWORD OnAccessViolation(HANDLE thread_handle,
                          const EXCEPTION_RECORD& exception_record) override;
  void OnDllLoad(const std::wstring& file_name, void* base_address) override;
  DWORD OnSinglestep(uintptr_t bp_address) override;
  void OnHardwareBreakpoint(HANDLE thread_handle, uintptr_t bp_address,
                            CONTEXT& context) override;
  SoftBpAction OnSoftwareBreakpoint(HANDLE thread_handle,
                                    uintptr_t bp_address) override;

 private:
  struct EflRecord {
    uintptr_t address = 0;
    std::vector<uint8_t> original;
  };

  bool TmFinderCheck(CONTEXT* context);
  void SelectThemidaSection(uintptr_t eip);
  void TmInit(HANDLE& file_handle);
  void TmIatFix(uintptr_t eip);
  void TmIatFix2();
  void TmIatFix3(uintptr_t eip);
  void TmIatFix4();
  void TmIatFix5(uintptr_t eax);
  void TmIatFixThemidaV1(uintptr_t base_compare1);
  bool GetIatBpAddressNew(uintptr_t& result);
  bool InstallEflPatch(uintptr_t eip, CONTEXT& context, EflRecord& record);

  void InstallCodeSectionGuard(uint32_t protection);
  bool IsGuardedAddress(uintptr_t address);
  DWORD ProcessGuardedAccess(HANDLE thread_handle,
                             const EXCEPTION_RECORD& exception_record);

  void RestoreStolenOepForMsvc6(HANDLE thread_handle, uintptr_t& oep);
  void RestoreStolenOepForMsvc9Dll(HANDLE thread_handle, uintptr_t& oep);
  uintptr_t TryFindCorrectOep(uintptr_t oep);
  bool IsTmExceptionHandler(uintptr_t address);
  void FixupApiCallSites(uintptr_t iat);
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
  std::array<EflRecord, 3> efls_{};
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
