// Magicmida - C++ port
// Import reconstruction and process dumping (ported from Dumper.pas).
#ifndef MAGICMIDA_DUMPER_H_
#define MAGICMIDA_DUMPER_H_

#include "common.h"
#include "pe_info.h"
#include "stream.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace magicmida {

constexpr size_t kMaxIatSize = 5120 * sizeof(void*);

using ExportTable = std::unordered_map<uintptr_t, std::string>;

struct Forward {
  std::string key;
  uintptr_t value = 0;
};

struct RemoteModule {
  uintptr_t base = 0;
  uintptr_t end_off = 0;
  std::string name;
  ExportTable export_tbl;
  std::vector<Forward> forwards;
};

struct ForwardOrigin {
  RemoteModule* source_module = nullptr;
  uintptr_t source_address = 0;
};

using ForwardMap = std::unordered_map<uintptr_t, std::vector<ForwardOrigin>>;

struct OriginalImport {
  std::string dll_name;
  std::string func_name;
};

class Dumper {
 public:
  Dumper(const PROCESS_INFORMATION& process, const std::wstring& original_file,
         uintptr_t image_base, uintptr_t oep);
  ~Dumper();

  Dumper(const Dumper&) = delete;
  Dumper& operator=(const Dumper&) = delete;

  std::unique_ptr<PEHeader> Process();
  void DumpToFile(const std::wstring& file_name, PEHeader& pe,
                  bool is_dll = false);

  uint32_t DetermineIATSize(const uint8_t* iat);
  bool IsAPIAddress(uintptr_t address);

  // Changes the manifest type between EXE/DLL so side-by-side functionality
  // (like pinned MSVC versions) works properly.
  static void SwitchSxSManifestType(Stream& stream, PEHeader& pe,
                                    int switch_from, int switch_to);

  // Virtual address of the IAT in the target process.
  uintptr_t iat_ = 0;

 private:
  void GatherModuleExportsFromRemoteProcess(RemoteModule& module);
  void ResolveForwards(RemoteModule& module);
  void TakeModuleSnapshot();
  RemoteModule* GetRemoteModule(const std::string& name);
  RemoteModule* GetRemoteModule(HMODULE base);
  bool RPM(uintptr_t address, void* buf, size_t size);
  void MakeMemoryReadable(uintptr_t base, uintptr_t size);
  std::vector<OriginalImport> GetOriginalImports(const std::wstring& file_name);
  bool HasOriginalImport(const std::string& dll, const std::string& func) const;

#if !defined(_WIN64)
  void CollectSpecialUser32Forwards(RemoteModule& user32);
#endif

  PROCESS_INFORMATION process_{};
  uintptr_t oep_ = 0;
  uintptr_t image_base_ = 0;
  ForwardMap forwards_;
  std::vector<std::unique_ptr<RemoteModule>> all_modules_;
  bool snapshot_taken_ = false;
  std::vector<uint8_t> header_snapshot_;
  std::vector<uint8_t> iat_image_;
  uint32_t iat_image_size_ = 0;
  std::vector<OriginalImport> original_imports_;

#if !defined(_WIN64)
  std::wstring usr_module_path_;
  uintptr_t usr_module_ = 0;
#endif
};

class DumperDotnet {
 public:
  DumperDotnet(const PROCESS_INFORMATION& process, uintptr_t image_base);

  void DumpToFile(const std::wstring& file_name);

 private:
  PROCESS_INFORMATION process_{};
  uintptr_t image_base_ = 0;
};

}  // namespace magicmida

#endif  // MAGICMIDA_DUMPER_H_
