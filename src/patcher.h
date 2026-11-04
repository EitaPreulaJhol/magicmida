// Magicmida - C++ port
// Post-processing of unpacked files (ported from Patcher.pas).
#pragma once

#include "common.h"
#include "pe_info.h"
#include "stream.h"

#include <memory>
#include <string>

namespace magicmida {

class Patcher {
 public:
  explicit Patcher(const std::wstring& fileName);
  ~Patcher() = default;

  Patcher(const Patcher&) = delete;
  Patcher& operator=(const Patcher&) = delete;

  void ProcessShrink();
  bool ProcessMkData();

  // Rewrites the raw file layout (SizeOfHeaders, PointerToRawData,
  // SizeOfRawData) to the conventional aligned layout used by linkers. Must
  // run after all RVA-based edits (imports, data sections, shrink, relocs).
  void NormalizeLayout();

  void DumpProcessCode(HANDLE process);

 private:
  void RelocateExceptionTable();
  void ShrinkPE();
  void ShrinkExportSect();
  // Expands a normalized layout back to file-offset == RVA for the legacy
  // data-section finders.
  void FlattenLayout();

  // Proper section characteristics are important for MSVC applications
  // because they check them during C runtime initialization (especially
  // .rdata).
  bool MapleCreateDataSections();
  bool MSVCCreateDataSections();

  uintptr_t FindDataStartMSVC6();
  bool FindDynTLSMSVC14(uintptr_t& dynTlsInit);

  std::wstring fileName_;
  MemoryStream stream_;
  std::unique_ptr<PEHeader> pe_;
};

// Convenience wrapper for callers that only have the file path.
void NormalizePEFile(const std::wstring& fileName);

}  // namespace magicmida
