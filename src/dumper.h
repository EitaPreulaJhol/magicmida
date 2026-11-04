// Magicmida - C++ port
// Import reconstruction and process dumping (ported from Dumper.pas).
#pragma once

#include "common.h"
#include "pe_info.h"
#include "stream.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace magicmida {

constexpr size_t MAX_IAT_SIZE = 5120 * sizeof(void*);

using ExportTable = std::unordered_map<uintptr_t, std::string>;

struct Forward {
  std::string Key;
  uintptr_t Value = 0;
};

struct RemoteModule {
  uintptr_t Base = 0;
  uintptr_t EndOff = 0;
  std::string Name;
  ExportTable ExportTbl;
  std::vector<Forward> Forwards;
};

struct ForwardOrigin {
  RemoteModule* SourceModule = nullptr;
  uintptr_t SourceAddress = 0;
};

using ForwardMap = std::unordered_map<uintptr_t, std::vector<ForwardOrigin>>;

class ImportThunk {
 public:
  explicit ImportThunk(RemoteModule* module);

  RemoteModule* Module = nullptr;
  std::string Name;
  std::vector<uintptr_t*> Addresses;
};

struct OriginalImport {
  std::string DllName;
  std::string FuncName;
};

class Dumper {
 public:
  Dumper(const PROCESS_INFORMATION& process, const std::wstring& originalFile,
         uintptr_t imageBase, uintptr_t oep);
  ~Dumper();

  Dumper(const Dumper&) = delete;
  Dumper& operator=(const Dumper&) = delete;

  std::unique_ptr<PEHeader> Process();
  void DumpToFile(const std::wstring& fileName, PEHeader& pe, bool isDll = false);

  uint32_t DetermineIATSize(const uint8_t* iat);
  bool IsAPIAddress(uintptr_t address);

  // Changes the manifest type between EXE/DLL so side-by-side functionality
  // (like pinned MSVC versions) works properly.
  static void SwitchSxSManifestType(Stream& stream, PEHeader& pe,
                                    int switchFrom, int switchTo);

  // Virtual address of the IAT in the target process.
  uintptr_t IAT = 0;

 private:
  void GatherModuleExportsFromRemoteProcess(RemoteModule& module);
  void ResolveForwards(RemoteModule& module);
  void TakeModuleSnapshot();
  RemoteModule* GetRemoteModule(const std::string& name);
  RemoteModule* GetRemoteModule(HMODULE base);
  bool RPM(uintptr_t address, void* buf, size_t size);
  void MakeMemoryReadable(uintptr_t base, uintptr_t size);
  std::vector<OriginalImport> GetOriginalImports(const std::wstring& fileName);
  bool HasOriginalImport(const std::string& dll, const std::string& func) const;

#if !defined(_WIN64)
  void CollectSpecialUser32Forwards(RemoteModule& user32);
#endif

  PROCESS_INFORMATION process_{};
  uintptr_t oep_ = 0;
  uintptr_t imageBase_ = 0;
  ForwardMap forwards_;
  std::vector<std::unique_ptr<RemoteModule>> allModules_;
  bool snapshotTaken_ = false;
  std::vector<uint8_t> iatImage_;
  uint32_t iatImageSize_ = 0;
  std::vector<OriginalImport> originalImports_;

#if !defined(_WIN64)
  std::wstring usrPath_;
  uintptr_t hUsr_ = 0;
#endif
};

class DumperDotnet {
 public:
  DumperDotnet(const PROCESS_INFORMATION& process, uintptr_t imageBase);

  void DumpToFile(const std::wstring& fileName);

 private:
  PROCESS_INFORMATION process_{};
  uintptr_t imageBase_ = 0;
};

}  // namespace magicmida
