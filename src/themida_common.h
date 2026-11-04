// Magicmida - C++ port
// Shared Themida-unpacking logic (ported from ThemidaCommon.pas).
#pragma once

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
  bool createDataSections_ = false;
  bool useScyllaHide_ = true;
  uintptr_t baseOfData_ = 0;
  uintptr_t imageBoundary_ = 0;
  std::vector<IMAGE_SECTION_HEADER> peSections_;
  uint8_t majorLinkerVersion_ = 0;

  std::unique_ptr<uint8_t[]> tmSectStorage_;
  uint8_t* tmSect_ = nullptr;
  MemoryRegion tmSectR_;

  bool themidaV3_ = false;
  bool isVMOEP_ = false;

  std::vector<uintptr_t> guardAddrs_;

  // Used by TraceIsAtAPI.
  uintptr_t tracedAPI_ = 0;
  uintptr_t sleepAPI_ = 0;
  uintptr_t lstrlenAPI_ = 0;
  uintptr_t traceStartSP_ = 0;
  bool traceInVM_ = false;

  void InitPEDetails(IMAGE_NT_HEADERS* nt);
  void CheckVirtualizedOEP(uintptr_t oep);

  uintptr_t DetermineIATAddress(uintptr_t oep, Dumper& dumper);
  void TraceImports(uintptr_t iat, Dumper& dumper);

  uint32_t FindDynamicTM(const std::string& pattern, uintptr_t offset = 0);
  uint32_t FindStaticTM(const std::string& pattern, uintptr_t offset = 0);

  virtual bool TraceIsAtAPI(Tracer& tracer, CONTEXT& context) = 0;
};

}  // namespace magicmida
