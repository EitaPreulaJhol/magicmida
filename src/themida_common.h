// Magicmida - C++ port
// Shared Themida-unpacking logic (ported from ThemidaCommon.pas).
#ifndef MAGICMIDA_THEMIDA_COMMON_H_
#define MAGICMIDA_THEMIDA_COMMON_H_

#include "common.h"
#include "debugger_core.h"
#include "disasm.h"
#include "dumper.h"
#include "tracer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace magicmida {

class ThemidaCommon : public DebuggerCore {
 public:
  using DebuggerCore::DebuggerCore;
  ~ThemidaCommon() override = default;

 protected:
  bool create_data_sections_ = false;
  bool use_scylla_hide_ = true;
  bool fix_relocations_ = false;
  uintptr_t base_of_data_ = 0;
  uintptr_t image_boundary_ = 0;
  std::vector<IMAGE_SECTION_HEADER> pe_sections_;
  uint8_t major_linker_version_ = 0;

  std::unique_ptr<uint8_t[]> tm_sect_storage_;
  uint8_t* tm_sect_ = nullptr;
  MemoryRegion tm_sect_r_;

  bool themida_v3_ = false;
  bool is_vm_oep_ = false;

  std::vector<uintptr_t> guard_addrs_;

  // Used by TraceIsAtAPI.
  uintptr_t traced_api_ = 0;
  uintptr_t sleep_api_ = 0;
  uintptr_t lstrlen_api_ = 0;
  uintptr_t trace_start_sp_ = 0;
  bool trace_in_vm_ = false;

  void InitPEDetails(IMAGE_NT_HEADERS* nt);
  void CheckVirtualizedOEP(uintptr_t oep);

  uintptr_t DetermineIATAddress(uintptr_t oep, Dumper& dumper);
  void TraceImports(uintptr_t iat, Dumper& dumper);

  uint32_t FindDynamicTM(const std::string& pattern, uintptr_t offset = 0);
  uint32_t FindStaticTM(const std::string& pattern, uintptr_t offset = 0);

  virtual bool TraceIsAtAPI(Tracer& tracer, CONTEXT& context) = 0;
};

}  // namespace magicmida

#endif  // MAGICMIDA_THEMIDA_COMMON_H_
