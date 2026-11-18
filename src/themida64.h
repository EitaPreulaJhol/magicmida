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
                    const std::wstring& parameters, bool create_data,
                    bool use_scylla_hide = true, bool fix_relocations = false);
  ~ThemidaDebugger64() override = default;

 protected:
  bool TraceIsAtAPI(Tracer& tracer, CONTEXT& context) override;

  void OnDebugStart(HANDLE& file_handle, HANDLE thread_handle) override;
  DWORD OnAccessViolation(HANDLE thread_handle,
                          const EXCEPTION_RECORD& exception_record) override;
  void OnDLLLoad(const std::wstring& file_name, void* base_address) override;
  DWORD OnSinglestep(uintptr_t bp_address) override;
  void OnHardwareBreakpoint(HANDLE thread_handle, uintptr_t bp_address,
                            CONTEXT& context) override;
  SoftBPAction OnSoftwareBreakpoint(HANDLE thread_handle,
                                    uintptr_t bp_address) override;

 private:
  void DumpContext(DWORD thread_id);
  bool InImageBounds(uintptr_t address) const;

  void SelectThemidaSection(uintptr_t address);
  void TMInit(HANDLE& file_handle);

  void InstallCodeSectionGuard();
  bool IsGuardedAddress(uintptr_t address);
  DWORD ProcessGuardedAccess(HANDLE thread_handle,
                             const EXCEPTION_RECORD& exception_record);

  void FinishUnpacking(uintptr_t oep);

  uintptr_t TryFindCorrectOEP(uintptr_t hit_address);
  void WriteMSVCOEP(uintptr_t crt_startup);

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
