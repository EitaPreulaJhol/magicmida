// Magicmida - C++ port
// Post-processing of unpacked files (ported from Patcher.pas).
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_PATCHER_H_
#define MAGICMIDA_PATCHER_H_

#include <memory>
#include <string>

#include "common.h"
#include "pe_info.h"
#include "stream.h"

namespace magicmida {

class Patcher {
 public:
  explicit Patcher(const std::wstring& file_name);
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
  void ShrinkPe();
  void ShrinkExportSect();
  // Expands a normalized layout back to file-offset == RVA for the legacy
  // data-section finders.
  void FlattenLayout();

  // Proper section characteristics are important for MSVC applications
  // because they check them during C runtime initialization (especially
  // .rdata).
  bool MapleCreateDataSections();
  bool MsvcCreateDataSections();

  uintptr_t FindDataStartMsvc6();
  bool FindDynTlsMsvc14(uintptr_t& dyn_tls_init);

  std::wstring file_name_;
  MemoryStream stream_;
  std::unique_ptr<PeHeader> pe_;
};

// Convenience wrapper for callers that only have the file path.
void NormalizePeFile(const std::wstring& file_name);

}  // namespace magicmida

#endif  // MAGICMIDA_PATCHER_H_
