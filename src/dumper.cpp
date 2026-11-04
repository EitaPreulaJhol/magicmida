// Magicmida - C++ port
// Import reconstruction and process dumping (ported from Dumper.pas).
#include "dumper.h"

#include "onecore_uap.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace magicmida {
namespace {

const char* const kForwardPreferences[] = {
    "kernel32.dll",  // prioritize over kernelbase/ntdll
    "ole32.dll",     // prioritize over combase
    "advapi32.dll",  // prioritize over cryptbase
    "netapi32.dll",  // prioritize over netutils
    "comdlg32.dll",  // prioritize over shlwapi
    "crypt32.dll",   // prioritize over dpapi
    "gdi32.dll",     // prioritize over gdi32full
    "dbghelp.dll",   // prioritize over dbgcore
    "setupapi.dll",  // prioritize over cfgmgr32
};

int PreferenceScore(const std::string& name) {
  int result = 0;
  for (const char* preferred : kForwardPreferences) {
    if (AsciiSameText(name, preferred)) {
      ++result;
    }
  }
  return result;
}

// Emulates the original's pointer arithmetic into the export directory image.
const uint8_t* RemoteExportPointer(const std::vector<uint8_t>& buffer,
                                   uint32_t directoryRva, uint32_t rva) {
  const uintptr_t base = reinterpret_cast<uintptr_t>(buffer.data());
  return reinterpret_cast<const uint8_t*>(base + rva - directoryRva);
}

}  // namespace

// --------------------------------------------------------------------------
// Dumper
// --------------------------------------------------------------------------

Dumper::Dumper(const PROCESS_INFORMATION& process,
               const std::wstring& originalFile, uintptr_t imageBase,
               uintptr_t oep)
    : process_(process), oep_(oep), imageBase_(imageBase) {
#if !defined(_WIN64)
  if (GetWindowsMajorVersion() > 5) {
    // user32 has an internal function 'PatchExportTableForwarders' that
    // patches the AddressOfFunctions table.
    usrPath_ = ExtractFilePath(GetExecutablePath()) + L"mmusr32.dll";
    if (CopyFileW(L"C:\\Windows\\system32\\user32.dll", usrPath_.c_str(), FALSE)) {
      const HMODULE module = LoadLibraryExW(usrPath_.c_str(), nullptr, 0x20);
      if (module != nullptr) {
        // Data-file handles are tagged with +2 by the loader.
        hUsr_ = reinterpret_cast<uintptr_t>(module) - 2;
      }
    }
  }
#endif

  originalImports_ = GetOriginalImports(originalFile);
}

Dumper::~Dumper() {
#if !defined(_WIN64)
  if (hUsr_ != 0) {
    FreeLibrary(reinterpret_cast<HMODULE>(hUsr_ + 2));
    DeleteFileW(usrPath_.c_str());
  }
#endif
}

void Dumper::DumpToFile(const std::wstring& fileName, PEHeader& pe,
                        bool isDll) {
  FileStream file(fileName, FileStream::Mode::Create);

  uint32_t size = pe.DumpSize();
  std::vector<uint8_t> buffer(size);
  MakeMemoryReadable(imageBase_, size);
  if (!RPM(imageBase_, buffer.data(), size)) {
    throw std::runtime_error(
        Format("DumpToFile RPM failed (base: %llX, size: %X)",
               static_cast<unsigned long long>(imageBase_), size));
  }

  uint32_t iatRawOffset = static_cast<uint32_t>(IAT - imageBase_);
  // TrimHugeSections may adjust iatRawOffset depending on what is trimmed.
  const uint32_t delta = pe.TrimHugeSections(buffer.data(), iatRawOffset);
  size -= delta;
  file.Write(buffer.data(), size);

  const size_t numberOfSections = pe.ntHeaders.FileHeader.NumberOfSections;
  for (size_t i = numberOfSections; i < pe.Sections().size(); ++i) {
    const PESection& section = pe.Sections()[i];
    const uint32_t rawSize = section.Header.SizeOfRawData;
    const size_t available = std::min<size_t>(section.Data.size(), rawSize);
    if (available > 0) {
      file.Write(section.Data.data(), available);
    }
    if (available < rawSize) {
      std::vector<uint8_t> zeros(rawSize - available);
      file.Write(zeros.data(), zeros.size());
    }
  }

  pe.ntHeaders.FileHeader.NumberOfSections =
      static_cast<WORD>(pe.Sections().size());
  pe.ntHeaders.OptionalHeader.AddressOfEntryPoint =
      static_cast<uint32_t>(oep_ - imageBase_);

  if (isDll) {
    pe.ntHeaders.FileHeader.Characteristics |= IMAGE_FILE_DLL;
    SwitchSxSManifestType(file, pe, 1, 2);  // Switch back
  }

  if ((pe.ntHeaders.OptionalHeader.DllCharacteristics & 0x40) != 0) {
    Log(ltInfo, "Executable is ASLR-aware - disabling the flag in the dump");
    pe.ntHeaders.OptionalHeader.DllCharacteristics &= ~0x40;
  }

  pe.SaveToStream(file);

  file.Seek(iatRawOffset, Stream::Origin::Begin);
  file.Write(iatImage_.data(), iatImageSize_);
}

uint32_t Dumper::DetermineIATSize(const uint8_t* iat) {
  uint32_t lastValidOffset = 0;
  uint32_t i = 0;
  uintptr_t value = 0;

  while (i < MAX_IAT_SIZE &&
         (lastValidOffset == 0 || i < lastValidOffset + 0x100)) {
    std::memcpy(&value, iat + i, sizeof(value));
    if (IsAPIAddress(value)) {
      lastValidOffset = i;
    }
    i += static_cast<uint32_t>(sizeof(void*));
  }

  return lastValidOffset + static_cast<uint32_t>(sizeof(void*));
}

namespace {

struct ResolutionCandidate {
  uintptr_t Address = 0;
  RemoteModule* Module = nullptr;
};

struct IATSlot {
  std::vector<ResolutionCandidate> Candidates;
  int ChosenCandidate = -1;
  bool IsZero = false;
};

struct ModuleVote {
  std::string Name;
  int Votes = 0;
  int FirstSeen = 0;
};

}  // namespace

std::unique_ptr<PEHeader> Dumper::Process() {
  if (IAT == 0) {
    throw std::runtime_error("Must set IAT before calling Process()");
  }

  // Read header from memory.
  std::vector<uint8_t> sectionData(0x1000);
  if (!RPM(imageBase_, sectionData.data(), sectionData.size())) {
    throw std::runtime_error("Dumper::Process: reading image header failed");
  }
  auto pe = std::make_unique<PEHeader>(sectionData.data(), sectionData.size());
  pe->Sanitize();

  std::vector<uint8_t> iat(MAX_IAT_SIZE);
  if (!RPM(IAT, iat.data(), iat.size())) {
    throw std::runtime_error("Dumper::Process: reading IAT failed");
  }

  const uint32_t iatSize = DetermineIATSize(iat.data());
  LogF(ltInfo, "Determined IAT size: %X", iatSize);

  auto& iatDirectory =
      pe->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
  iatDirectory.VirtualAddress = static_cast<uint32_t>(IAT - imageBase_);
  iatDirectory.Size = iatSize + static_cast<uint32_t>(sizeof(void*));

  if (!snapshotTaken_) {
    TakeModuleSnapshot();
  }

  bool allowApiSets = false;
  for (const OriginalImport& import : originalImports_) {
    if (import.DllName.rfind("api-ms-win", 0) == 0) {
      allowApiSets = true;
      break;
    }
  }

  const int slotCount = static_cast<int>(iatSize / sizeof(uintptr_t));
  std::vector<IATSlot> slots(static_cast<size_t>(slotCount));

  auto readSlot = [&](int index) {
    uintptr_t value = 0;
    std::memcpy(&value, iat.data() + static_cast<size_t>(index) * sizeof(uintptr_t),
                sizeof(value));
    return value;
  };
  auto writeSlot = [&](int index, uintptr_t value) {
    std::memcpy(iat.data() + static_cast<size_t>(index) * sizeof(uintptr_t),
                &value, sizeof(value));
  };

  // =======================================================================
  // PASS 1: Collect all candidates for every IAT slot.
  // =======================================================================
  for (int i = 0; i < slotCount; ++i) {
    IATSlot& slot = slots[static_cast<size_t>(i)];
    slot.IsZero = readSlot(i) == 0;

    if (slot.IsZero) {
      continue;
    }

    const uintptr_t slotValue = readSlot(i);

    // --- Variant A: no forwarding ---
    ResolutionCandidate candidate;
    candidate.Address = slotValue;
    candidate.Module = nullptr;
    for (const auto& rmPtr : allModules_) {
      RemoteModule& rm = *rmPtr;
      if (candidate.Address > rm.Base && candidate.Address < rm.EndOff) {
        if (rm.ExportTbl.find(candidate.Address) != rm.ExportTbl.end()) {
          candidate.Module = &rm;
          slot.Candidates.push_back(candidate);
        }
        break;  // only one module owns this address
      }
    }

    // --- Variant B: forwards_ (e.g. ntdll stub -> kernelbase real) ---
    const auto forwardIt = forwards_.find(slotValue);
    if (forwardIt != forwards_.end()) {
      for (const ForwardOrigin& origin : forwardIt->second) {
        candidate.Address = origin.SourceAddress;
        candidate.Module = origin.SourceModule;
        slot.Candidates.push_back(candidate);
      }
    }

    if (slot.Candidates.empty()) {
      LogF(ltInfo, "IAT slot %08llX -> %08llX unresolvable",
           static_cast<unsigned long long>(
               IAT + static_cast<uintptr_t>(i) * sizeof(uintptr_t)),
           static_cast<unsigned long long>(slotValue));
    }
  }

  // =======================================================================
  // PASS 2: For each zero-delimited group, vote on the best module and pin
  //         every slot to a candidate from that module.
  // =======================================================================
  std::vector<std::unique_ptr<ImportThunk>> thunks;

  int i = 0;
  while (i < slotCount) {
    // Skip zero separators (they just end the current thunk naturally).
    if (slots[static_cast<size_t>(i)].IsZero) {
      ++i;
      continue;
    }

    // Find contiguous non-zero run = one raw group.
    const int groupStart = i;
    int groupEnd = i;
    while (groupEnd + 1 < slotCount &&
           !slots[static_cast<size_t>(groupEnd + 1)].IsZero) {
      ++groupEnd;
    }

    // Vote: for each slot in group, each candidate casts one vote for its
    // module.
    std::vector<ModuleVote> votes;
    for (int j = groupStart; j <= groupEnd; ++j) {
      for (const ResolutionCandidate& candidate :
           slots[static_cast<size_t>(j)].Candidates) {
        const std::string& moduleName = candidate.Module->Name;
        auto it = std::find_if(votes.begin(), votes.end(),
                               [&](const ModuleVote& vote) {
                                 return vote.Name == moduleName;
                               });
        if (it == votes.end()) {
          votes.push_back(ModuleVote{moduleName, 1, static_cast<int>(votes.size())});
        } else {
          ++it->Votes;
        }
      }
    }

    // Find the module with the most votes; apply scoring in ambiguous cases.
    std::string winnerName;
    int winnerVotes = -1;
    int winnerPreference = 0;
    RemoteModule* winnerModule = nullptr;

    for (const ModuleVote& vote : votes) {
      const int preference = PreferenceScore(vote.Name);
      if (vote.Votes > winnerVotes ||
          (vote.Votes == winnerVotes && preference > winnerPreference)) {
        winnerVotes = vote.Votes;
        winnerName = vote.Name;
        winnerPreference = preference;
      }
    }

    // Pin each slot to the winning module's candidate.
    for (int j = groupStart; j <= groupEnd; ++j) {
      IATSlot& slot = slots[static_cast<size_t>(j)];
      for (size_t k = 0; k < slot.Candidates.size(); ++k) {
        if (slot.Candidates[k].Module->Name == winnerName) {
          slot.ChosenCandidate = static_cast<int>(k);
          if (winnerModule == nullptr) {
            winnerModule = slot.Candidates[k].Module;
          }
          break;
        }
      }
    }

    std::string apiSetName;
    if (allowApiSets) {
      for (int j = groupStart; j <= groupEnd; ++j) {
        const IATSlot& slot = slots[static_cast<size_t>(j)];
        if (slot.ChosenCandidate < 0 && slot.Candidates.empty()) {
          continue;
        }

        std::string funcName;
        if (slot.ChosenCandidate < 0) {
          funcName = slot.Candidates[0].Module->ExportTbl.at(
              slot.Candidates[0].Address);
        } else if (winnerModule != nullptr) {
          funcName = winnerModule->ExportTbl.at(
              slot.Candidates[static_cast<size_t>(slot.ChosenCandidate)].Address);
        }

        if (funcName.rfind("RtlQueryPerformance", 0) == 0) {
          funcName.erase(0, 3);  // Hack for api-ms-win-core-profile-l1-1-0.dll
        }

        if (j == groupStart) {
          apiSetName = GetOneCoreUAPModuleByAPI(funcName);
        } else if (!apiSetName.empty() &&
                   GetOneCoreUAPModuleByAPI(funcName) != apiSetName) {
          apiSetName.clear();
        }
      }
    }

    // If using an ApiSet, remap so the slot is not skipped as bogus. Looking
    // for the same name in winnerModule is a bit risky, but so far this has
    // happened between kernel32 and kernelbase.
    if (!apiSetName.empty() && winnerModule != nullptr) {
      for (int j = groupStart; j <= groupEnd; ++j) {
        IATSlot& slot = slots[static_cast<size_t>(j)];
        if (slot.ChosenCandidate >= 0 || slot.Candidates.empty()) {
          continue;
        }

        const std::string funcName =
            slot.Candidates[0].Module->ExportTbl.at(slot.Candidates[0].Address);
        // Find the address of this function in winnerModule's export table.
        for (const auto& exportEntry : winnerModule->ExportTbl) {
          if (exportEntry.second == funcName) {
            slot.Candidates[0].Address = exportEntry.first;
            slot.ChosenCandidate = 0;
            LogF(ltInfo, "IAT slot %08llX: remapped apiset member %s",
                 static_cast<unsigned long long>(
                     IAT + static_cast<uintptr_t>(j) * sizeof(uintptr_t)),
                 funcName.c_str());
            break;
          }
        }
      }
    }

    // Now walk the group and build thunks, respecting the chosen candidates.
    // Within a zero-free group we stay in one thunk for the winner module.
    ImportThunk* thunk = nullptr;
    for (int j = groupStart; j <= groupEnd; ++j) {
      IATSlot& slot = slots[static_cast<size_t>(j)];
      if (slot.ChosenCandidate < 0) {
        LogF(ltFatal,
             "IAT slot %08llX  has no candidate for winning module %s (bogus entry)",
             static_cast<unsigned long long>(
                 IAT + static_cast<uintptr_t>(j) * sizeof(uintptr_t)),
             winnerName.c_str());
        continue;
      }

      if (thunk == nullptr) {
        thunks.push_back(std::make_unique<ImportThunk>(winnerModule));
        thunk = thunks.back().get();
        thunk->Name = winnerName;
      }

      // Write the resolved pointer back into the IAT image.
      const ResolutionCandidate& candidate =
          slot.Candidates[static_cast<size_t>(slot.ChosenCandidate)];
      writeSlot(j, candidate.Address);
      thunk->Addresses.push_back(reinterpret_cast<uintptr_t*>(
          iat.data() + static_cast<size_t>(j) * sizeof(uintptr_t)));
    }

    if (!apiSetName.empty() && thunk != nullptr && winnerModule != nullptr) {
      const uintptr_t firstAddress = *thunk->Addresses.front();
      const auto firstImport = winnerModule->ExportTbl.find(firstAddress);
      if (firstImport != winnerModule->ExportTbl.end() &&
          !HasOriginalImport(thunk->Name, firstImport->second)) {
        LogF(ltInfo, "OneCoreUAP: Using %s instead of %s", apiSetName.c_str(),
             winnerName.c_str());
        thunk->Name = apiSetName;
      }
    }

    i = groupEnd + 1;
  }

  PESection* importSection = pe->CreateSection(".import", 0x1000);
  std::vector<uint8_t> importData(importSection->Header.SizeOfRawData, 0);

  const size_t descriptorCount = thunks.size() + 1;  // Last descriptor is empty
  size_t stringsOffset = descriptorCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);

  auto ensureImportCapacity = [&](size_t required) {
    while (required > importData.size()) {
      importSection->Header.SizeOfRawData += 0x1000;
      importSection->Header.Misc.VirtualSize += 0x1000;
      pe->ntHeaders.OptionalHeader.SizeOfImage += 0x1000;
      importData.resize(importSection->Header.SizeOfRawData, 0);
    }
  };

  for (size_t thunkIndex = 0; thunkIndex < thunks.size(); ++thunkIndex) {
    ImportThunk& thunk = *thunks[thunkIndex];
    auto* descriptors =
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(importData.data());

    descriptors[thunkIndex].FirstThunk =
        static_cast<uint32_t>(IAT - imageBase_ +
                              reinterpret_cast<uintptr_t>(
                                  thunk.Addresses.front()) -
                              reinterpret_cast<uintptr_t>(iat.data()));
    descriptors[thunkIndex].Name = pe->ConvertOffsetToRVAVector(
        importSection->Header.PointerToRawData +
        static_cast<uint32_t>(stringsOffset));

    const std::string& moduleName = thunk.Name;
    ensureImportCapacity(stringsOffset + moduleName.size() + 1);
    std::memcpy(importData.data() + stringsOffset, moduleName.c_str(),
                moduleName.size());
    stringsOffset += moduleName.size() + 1;

    RemoteModule* remoteModule = thunk.Module;
    LogF(ltInfo, "Thunk %s - first import: %s", thunk.Name.c_str(),
         remoteModule->ExportTbl.at(*thunk.Addresses.front()).c_str());

    for (size_t j = 0; j < thunk.Addresses.size(); ++j) {
      std::string funcName = remoteModule->ExportTbl.at(*thunk.Addresses[j]);
      if (!funcName.empty() && funcName[0] == '#') {
        const uint32_t ordinalIndex =
            static_cast<uint32_t>(std::strtoul(funcName.c_str() + 1, nullptr, 10));
        *thunk.Addresses[j] =
            static_cast<uintptr_t>(IMAGE_ORDINAL_FLAG) | ordinalIndex;
        continue;
      }

      if (funcName.rfind("RtlQueryPerformance", 0) == 0 &&
          thunk.Name.rfind("api-ms-win", 0) == 0) {
        funcName.erase(0, 3);
      }

      // Hint (2 bytes, already zero) followed by the name.
      const size_t hintOffset = stringsOffset;
      stringsOffset += 2;
      *thunk.Addresses[j] = static_cast<uintptr_t>(
          pe->ConvertOffsetToRVAVector(importSection->Header.PointerToRawData +
                                       static_cast<uint32_t>(hintOffset)));

      ensureImportCapacity(stringsOffset + funcName.size() + 1);
      std::memcpy(importData.data() + stringsOffset, funcName.c_str(),
                  funcName.size());
      stringsOffset += funcName.size() + 1;

      if (stringsOffset > importData.size() - 0x100) {
        importSection->Header.SizeOfRawData += 0x1000;
        importSection->Header.Misc.VirtualSize += 0x1000;
        pe->ntHeaders.OptionalHeader.SizeOfImage += 0x1000;
        importData.resize(importSection->Header.SizeOfRawData, 0);
      }
    }
  }

  importSection->Data = std::move(importData);

  auto& importDirectory =
      pe->ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  importDirectory.VirtualAddress = importSection->Header.VirtualAddress;
  importDirectory.Size =
      static_cast<uint32_t>(thunks.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));

  iatImage_ = std::move(iat);
  iatImageSize_ = iatSize;
  return pe;
}

void Dumper::GatherModuleExportsFromRemoteProcess(RemoteModule& module) {
  std::vector<uint8_t> head(0x1000);
  if (!RPM(module.Base, head.data(), head.size())) {
    return;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(head.data());
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(head.data() +
                                                             dos->e_lfanew);
  const IMAGE_DATA_DIRECTORY exportDirectory =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  if (exportDirectory.VirtualAddress == 0 ||
      exportDirectory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
    return;
  }

  std::vector<uint8_t> exportData(exportDirectory.Size);
  if (!RPM(module.Base + exportDirectory.VirtualAddress, exportData.data(),
           exportData.size())) {
    return;
  }

  const auto* directory =
      reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(exportData.data());
  const auto* functions = reinterpret_cast<const uint32_t*>(
      RemoteExportPointer(exportData, exportDirectory.VirtualAddress,
                          directory->AddressOfFunctions));
  const auto* names = reinterpret_cast<const uint32_t*>(
      RemoteExportPointer(exportData, exportDirectory.VirtualAddress,
                          directory->AddressOfNames));
  const auto* ordinals = reinterpret_cast<const uint16_t*>(
      RemoteExportPointer(exportData, exportDirectory.VirtualAddress,
                          directory->AddressOfNameOrdinals));

  std::vector<uint8_t> named(directory->NumberOfFunctions, 0);

  for (uint32_t index = 0; index < directory->NumberOfNames; ++index) {
    const uint32_t functionIndex = ordinals[index];
    if (functionIndex >= named.size()) {
      continue;
    }
    named[functionIndex] = 1;
    const char* functionName = reinterpret_cast<const char*>(
        RemoteExportPointer(exportData, exportDirectory.VirtualAddress,
                            names[index]));
    module.ExportTbl[module.Base + functions[functionIndex]] = functionName;
  }

  for (uint32_t index = 0; index < directory->NumberOfFunctions; ++index) {
    // Add ordinals.
    if (index < named.size() && !named[index]) {
      const uint32_t functionIndex = directory->Base + index;
      module.ExportTbl[module.Base + functions[index]] =
          "#" + std::to_string(functionIndex);
    }

    // Check if entry is forward.
    if (functions[index] > exportDirectory.VirtualAddress &&
        functions[index] < exportDirectory.VirtualAddress +
                              exportDirectory.Size) {
      const char* forward = reinterpret_cast<const char*>(
          RemoteExportPointer(exportData, exportDirectory.VirtualAddress,
                              functions[index]));
      if (std::string(forward).find(".#") == std::string::npos) {
        module.Forwards.push_back({forward, module.Base + functions[index]});
      }
    }
  }
}

#if !defined(_WIN64)
void Dumper::CollectSpecialUser32Forwards(RemoteModule& user32) {
  // Scan the specially loaded user32 copy, because forwards are patched out
  // in normally loaded user32 images.
  const auto* modScan = reinterpret_cast<const uint8_t*>(hUsr_);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(modScan);
  const auto* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(modScan + dos->e_lfanew);
  const IMAGE_DATA_DIRECTORY exportDirectory =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  const auto* directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
      modScan + exportDirectory.VirtualAddress);
  const auto* functions = reinterpret_cast<const uint32_t*>(
      modScan + directory->AddressOfFunctions);

  for (uint32_t index = 0; index < directory->NumberOfFunctions; ++index) {
    const char* forward = reinterpret_cast<const char*>(
        modScan + functions[index]);
    const uintptr_t forwardAddress = reinterpret_cast<uintptr_t>(forward);
    if (forwardAddress > reinterpret_cast<uintptr_t>(modScan) +
                              exportDirectory.VirtualAddress &&
        forwardAddress < reinterpret_cast<uintptr_t>(modScan) +
                             exportDirectory.VirtualAddress +
                             exportDirectory.Size &&
        std::string(forward).find(".#") == std::string::npos) {
      user32.Forwards.push_back({forward, 0});
    }
  }
}
#endif

void Dumper::ResolveForwards(RemoteModule& module) {
  for (const Forward& forward : module.Forwards) {
    const size_t dotPos = forward.Key.find('.');
    if (dotPos == std::string::npos) {
      continue;
    }

    const std::string forwardModuleName = forward.Key.substr(0, dotPos);
    RemoteModule* forwardModule = nullptr;

    // api-ms-win, ext-ms-win
    if (forwardModuleName.find("-ms-win-") == 3) {
      // Take a shortcut by resolving this locally.
      const HMODULE resolved = GetModuleHandleA(forwardModuleName.c_str());
      if (resolved != nullptr) {
        forwardModule = GetRemoteModule(resolved);
      }
    } else {
      forwardModule = GetRemoteModule(forwardModuleName + ".dll");
    }

    if (forwardModule == nullptr) {
      continue;
    }

    const std::string forwardApiName =
        forward.Key.substr(dotPos + 1, 50);
    uintptr_t procedureAddress = 0;
    for (const auto& exportEntry : forwardModule->ExportTbl) {
      if (exportEntry.second == forwardApiName) {
        procedureAddress = exportEntry.first;
        break;
      }
    }

    if (procedureAddress != 0) {
      auto& origins = forwards_[procedureAddress];
      uintptr_t forwardValue = forward.Value;
#if !defined(_WIN64)
      if (module.Name == "user32.dll") {
        forwardValue = procedureAddress;  // user32 ExportTbl has resolved values
      }
#endif
      origins.push_back({&module, forwardValue});
    }
  }
}

RemoteModule* Dumper::GetRemoteModule(HMODULE base) {
  for (const auto& module : allModules_) {
    if (module->Base == reinterpret_cast<uintptr_t>(base)) {
      return module.get();
    }
  }
  return nullptr;
}

RemoteModule* Dumper::GetRemoteModule(const std::string& name) {
  const std::string lowered = AsciiLowerCase(name);
  for (const auto& module : allModules_) {
    if (module->Name == lowered) {
      return module.get();
    }
  }
  return nullptr;
}

bool Dumper::IsAPIAddress(uintptr_t address) {
  if (!snapshotTaken_) {
    TakeModuleSnapshot();
  }

  for (const auto& module : allModules_) {
    if (address >= module->Base && address < module->EndOff) {
      return module->ExportTbl.find(address) != module->ExportTbl.end();
    }
  }
  return false;
}

void Dumper::TakeModuleSnapshot() {
  snapshotTaken_ = true;

  const HANDLE snapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_.dwProcessId);
  if (snapshot == INVALID_HANDLE_VALUE) {
    throw std::runtime_error(
        Format("CreateToolhelp32Snapshot failed (error %lu)", GetLastError()));
  }

  MODULEENTRY32W moduleEntry{};
  moduleEntry.dwSize = sizeof(moduleEntry);
  if (!Module32FirstW(snapshot, &moduleEntry)) {
    CloseHandle(snapshot);
    throw std::runtime_error("Module32First");
  }

  do {
    if (reinterpret_cast<uintptr_t>(moduleEntry.hModule) != imageBase_) {
      auto module = std::make_unique<RemoteModule>();
      module->Base = reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
      module->EndOff = module->Base + moduleEntry.modBaseSize;
      module->Name = AsciiLowerCase(WideToUtf8(moduleEntry.szModule));
      GatherModuleExportsFromRemoteProcess(*module);
#if !defined(_WIN64)
      if (module->Name == "user32.dll" && hUsr_ != 0) {
        CollectSpecialUser32Forwards(*module);
      }
#endif
      allModules_.push_back(std::move(module));
    }
  } while (Module32NextW(snapshot, &moduleEntry));

  CloseHandle(snapshot);

  for (const auto& module : allModules_) {
    ResolveForwards(*module);
  }
}

bool Dumper::RPM(uintptr_t address, void* buf, size_t size) {
  const BOOL result =
      ReadProcessMemory(process_.hProcess, reinterpret_cast<void*>(address),
                        buf, size, nullptr);
  if (!result) {
    Log(ltFatal, "RPM failed");
  }
  return result != FALSE;
}

void Dumper::MakeMemoryReadable(uintptr_t base, uintptr_t size) {
  uintptr_t address = base;
  const uintptr_t endAddress = address + size;

  while (address < endAddress) {
    MEMORY_BASIC_INFORMATION mbi{};
    const SIZE_T bytesReturned =
        VirtualQueryEx(process_.hProcess, reinterpret_cast<void*>(address),
                       &mbi, sizeof(mbi));
    if (bytesReturned == 0) {
      break;
    }

    if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_NOACCESS) {
      DWORD oldProtect = 0;
      VirtualProtectEx(process_.hProcess, mbi.BaseAddress, mbi.RegionSize,
                       PAGE_READONLY, &oldProtect);
    }

    address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
  }
}

void Dumper::SwitchSxSManifestType(Stream& stream, PEHeader& pe,
                                   int switchFrom, int switchTo) {
  const auto& resourceDirectory =
      pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if (resourceDirectory.VirtualAddress == 0) {
    return;
  }

  PESection* resourceSection = pe.GetSectionByVA(resourceDirectory.VirtualAddress);
  if (resourceSection == nullptr) {
    return;
  }

  const uint32_t resourceSize = resourceDirectory.Size;
  if (resourceSize < 0x10) {
    return;
  }

  stream.Seek(resourceSection->Header.PointerToRawData, Stream::Origin::Begin);
  std::vector<uint8_t> resourceData(resourceSize);
  stream.Read(resourceData.data(), resourceData.size());

  const auto readWord = [&](uint32_t offset) -> uint16_t {
    if (static_cast<size_t>(offset) + sizeof(uint16_t) > resourceData.size()) {
      return 0;
    }
    uint16_t value = 0;
    std::memcpy(&value, resourceData.data() + offset, sizeof(value));
    return value;
  };
  const auto readDword = [&](uint32_t offset) -> uint32_t {
    if (static_cast<size_t>(offset) + sizeof(uint32_t) > resourceData.size()) {
      return 0;
    }
    uint32_t value = 0;
    std::memcpy(&value, resourceData.data() + offset, sizeof(value));
    return value;
  };

  const uint16_t numNamed = readWord(0xC);
  const uint16_t numIds = readWord(0xE);
  if (numIds == 0) {
    return;
  }

  const uint32_t offset = 0x10 + static_cast<uint32_t>(numNamed) * 8;
  uint32_t manifestSubDir = 0;
  for (uint16_t index = 0; index < numIds; ++index) {
    const uint32_t entryOffset = offset + static_cast<uint32_t>(index) * 8;
    if (readDword(entryOffset) == 24) {  // MANIFEST
      manifestSubDir = readDword(entryOffset + 4);
      break;
    }
  }

  if (manifestSubDir == 0 || (manifestSubDir >> 31) != 1) {
    return;
  }

  manifestSubDir &= 0x7FFFFFFF;
  if (readWord(manifestSubDir + 0xC) != 0 || readWord(manifestSubDir + 0xE) != 1) {
    Log(ltInfo, "Encountered weird manifest resource dir");
    return;
  }

  const uint32_t idOffset = manifestSubDir + 0x10;
  if (static_cast<int32_t>(readDword(idOffset)) != switchFrom) {
    return;
  }

  stream.Seek(resourceSection->Header.PointerToRawData + idOffset,
              Stream::Origin::Begin);
  const int32_t value = switchTo;
  stream.Write(&value, sizeof(value));
}

std::vector<OriginalImport> Dumper::GetOriginalImports(
    const std::wstring& fileName) {
  std::vector<OriginalImport> result;

  FileStream file(fileName, FileStream::Mode::Read);
  std::vector<uint8_t> headerBuffer(0x1000);
  const int64_t fileSize = file.Size();
  const size_t toRead =
      std::min<size_t>(headerBuffer.size(), static_cast<size_t>(fileSize));
  if (toRead < sizeof(IMAGE_DOS_HEADER)) {
    return result;
  }
  file.Read(headerBuffer.data(), toRead);

  PEHeader filePe(headerBuffer.data(), toRead);
  const IMAGE_DATA_DIRECTORY importDirectory =
      filePe.ntHeaders.OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0) {
    return result;
  }

  PESection* section = filePe.GetSectionByVA(importDirectory.VirtualAddress);
  if (section == nullptr || section->Header.SizeOfRawData == 0) {
    return result;
  }

  std::vector<uint8_t> sectionBuffer(section->Header.SizeOfRawData);
  file.Seek(section->Header.PointerToRawData, Stream::Origin::Begin);
  file.Read(sectionBuffer.data(), sectionBuffer.size());

  const uint64_t sectionRva = section->Header.VirtualAddress;
  const auto readCStringAtRva = [&](uint32_t rva, uint32_t extra) {
    const uint64_t offset = static_cast<uint64_t>(rva) - sectionRva + extra;
    if (offset >= sectionBuffer.size()) {
      return std::string();
    }
    const uint64_t remaining = sectionBuffer.size() - offset;
    const char* text =
        reinterpret_cast<const char*>(sectionBuffer.data() + offset);
    size_t length = 0;
    while (length < remaining && text[length] != '\0') {
      ++length;
    }
    return std::string(text, static_cast<size_t>(length));
  };

  if (importDirectory.VirtualAddress < sectionRva) {
    return result;
  }

  const uint64_t descriptorOffset =
      static_cast<uint64_t>(importDirectory.VirtualAddress) - sectionRva;
  if (descriptorOffset >= sectionBuffer.size()) {
    return result;
  }

  size_t descriptorIndex = 0;
  for (;;) {
    const uint64_t currentOffset =
        descriptorOffset + descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (currentOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) >
        sectionBuffer.size()) {
      break;
    }

    const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        sectionBuffer.data() + currentOffset);
    if (descriptor->Name == 0) {
      break;
    }

    const std::string dllName = readCStringAtRva(descriptor->Name, 0);

    if (descriptor->FirstThunk < sectionRva) {
      break;
    }
    const uint64_t thunkOffset =
        static_cast<uint64_t>(descriptor->FirstThunk) - sectionRva;
    if (thunkOffset >= sectionBuffer.size()) {
      break;
    }

    auto* thunkAddress = reinterpret_cast<const uintptr_t*>(
        sectionBuffer.data() + thunkOffset);
    const size_t maxThunks =
        (sectionBuffer.size() - static_cast<size_t>(thunkOffset)) /
        sizeof(uintptr_t);

    for (size_t thunkIndex = 0; thunkIndex < maxThunks; ++thunkIndex) {
      const uintptr_t thunk = thunkAddress[thunkIndex];
      if (thunk == 0) {
        break;
      }

      OriginalImport import;
      import.DllName = AsciiLowerCase(dllName);
      if ((thunk & IMAGE_ORDINAL_FLAG) != 0) {
        import.FuncName = "#" + std::to_string(thunk & 0xFFFF);
      } else {
        import.FuncName = readCStringAtRva(
            static_cast<uint32_t>(thunk), 2);
      }
      result.push_back(std::move(import));
    }

    ++descriptorIndex;
  }

  return result;
}

bool Dumper::HasOriginalImport(const std::string& dll,
                               const std::string& func) const {
  for (const OriginalImport& import : originalImports_) {
    if (import.DllName == dll && import.FuncName == func) {
      return true;
    }
  }
  return false;
}

// --------------------------------------------------------------------------
// ImportThunk
// --------------------------------------------------------------------------

ImportThunk::ImportThunk(RemoteModule* module) : Module(module) {
  if (module != nullptr) {
    Name = module->Name;
  }
}

// --------------------------------------------------------------------------
// DumperDotnet
// --------------------------------------------------------------------------

DumperDotnet::DumperDotnet(const PROCESS_INFORMATION& process,
                           uintptr_t imageBase)
    : process_(process), imageBase_(imageBase) {}

void DumperDotnet::DumpToFile(const std::wstring& fileName) {
  // Dumping Themida .NET binaries appears to be quite simple because no
  // special imports processing is required.
  uint8_t header[0x1000]{};
  if (!ReadProcessMemory(process_.hProcess,
                         reinterpret_cast<void*>(imageBase_), header,
                         sizeof(header), nullptr)) {
    throw std::runtime_error("DumpToFile header RPM failed");
  }

  PEHeader pe(header, sizeof(header));
  if (pe.Sections().empty()) {
    throw std::runtime_error("DumpToFile: PE has no sections");
  }

  const PESection& lastSection = pe.Sections().back();
  uint32_t size = lastSection.Header.VirtualAddress +
                  lastSection.Header.Misc.VirtualSize;

  FileStream file(fileName, FileStream::Mode::Create);
  std::vector<uint8_t> buffer(size);

  uint32_t physicalSize = size;
  pe.FileAlign(physicalSize);
  uint32_t imageSize = physicalSize;
  pe.SectionAlign(imageSize);
  pe.ntHeaders.OptionalHeader.SizeOfImage = imageSize;
  pe.Sections()[0].Rename(".text");

  LogF(ltInfo, "Output has %d sections, determined size to be 0x%X",
       pe.ntHeaders.FileHeader.NumberOfSections, size);

  uint32_t done = 0;
  while (done < size) {
    MEMORY_BASIC_INFORMATION mbi{};
    mbi.RegionSize = 0x1000;
    const uintptr_t currentAddress = imageBase_ + done;
    if (VirtualQueryEx(process_.hProcess,
                       reinterpret_cast<void*>(currentAddress), &mbi,
                       sizeof(mbi)) == 0) {
      throw std::runtime_error(
          Format("VirtualQueryEx failed at %llX",
                 static_cast<unsigned long long>(currentAddress)));
    }
    if (mbi.RegionSize == 0) {
      throw std::runtime_error(
          Format("VirtualQueryEx returned a zero region at %llX",
                 static_cast<unsigned long long>(currentAddress)));
    }

    const size_t chunk =
        std::min<size_t>(size - done, static_cast<size_t>(mbi.RegionSize));
    if (mbi.State == MEM_COMMIT) {
      if (!ReadProcessMemory(process_.hProcess,
                             reinterpret_cast<void*>(currentAddress),
                             buffer.data() + done, chunk, nullptr)) {
        throw std::runtime_error("DumpToFile RPM failed");
      }
    } else if (mbi.State == MEM_RESERVE) {
      // We could mess with the section addresses and leave this chunk out of
      // the physical file, but eh...
      std::memset(buffer.data() + done, 0, chunk);
    } else {
      throw std::runtime_error(
          Format("Got unexpected region state %X at %llX", mbi.State,
                 static_cast<unsigned long long>(currentAddress)));
    }

    done += static_cast<uint32_t>(mbi.RegionSize);
  }

  file.Write(buffer.data(), buffer.size());
  if (size < physicalSize) {
    // Pad to file alignment.
    std::vector<uint8_t> padding(physicalSize - size, 0);
    file.Write(padding.data(), padding.size());
  }

  pe.SaveToStream(file);
}

}  // namespace magicmida
