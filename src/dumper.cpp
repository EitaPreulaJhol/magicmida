// Magicmida - C++ port
// Import reconstruction and process dumping (ported from Dumper.pas).
// SPDX-License-Identifier: GPL-3.0-only
#include "dumper.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "onecore_uap.h"

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
                                   uint32_t directory_rva, uint32_t rva) {
  const uintptr_t base = reinterpret_cast<uintptr_t>(buffer.data());
  return reinterpret_cast<const uint8_t*>(base + rva - directory_rva);
}

constexpr uint16_t kExpectedOptionalMagic = sizeof(void*) == 8 ? 0x20B : 0x10B;

// Rejects headers that were zeroed/truncated by an anti-dump. A plausible
// header must have a section table that fits in the snapshot and sections
// that fit in SizeOfImage.
bool IsPlausiblePeHeader(const std::vector<uint8_t>& data) {
  if (data.size() < 0x1000) {
    return false;
  }
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew > 0xF00 ||
      static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) >
          data.size()) {
    return false;
  }

  const auto* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(data.data() + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE ||
      nt->OptionalHeader.Magic != kExpectedOptionalMagic) {
    return false;
  }

  const uint16_t section_count = nt->FileHeader.NumberOfSections;
  if (section_count == 0 || section_count > 96) {
    return false;
  }
  const size_t section_offset =
      static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS);
  const size_t section_bytes =
      static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER);
  if (section_offset + section_bytes > data.size()) {
    return false;
  }

  const uint64_t size_of_image = nt->OptionalHeader.SizeOfImage;
  if (size_of_image == 0 || size_of_image > 0x40000000ull ||
      nt->OptionalHeader.ImageBase == 0) {
    return false;
  }

  const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
      data.data() + section_offset);
  uint64_t max_end = 0;
  bool any_content = false;
  for (uint16_t i = 0; i < section_count; ++i) {
    const uint64_t start = sections[i].VirtualAddress;
    const uint64_t end =
        start + std::max<uint32_t>(sections[i].Misc.VirtualSize,
                                   sections[i].SizeOfRawData);
    max_end = std::max(max_end, end);
    if (sections[i].Misc.VirtualSize != 0 || sections[i].SizeOfRawData != 0) {
      any_content = true;
    }
  }
  if (!any_content || max_end > size_of_image + 0x1000) {
    return false;
  }
  return true;
}

void LogHeaderDiff(const std::vector<uint8_t>& live,
                   const std::vector<uint8_t>& snapshot) {
  if (live.size() < sizeof(IMAGE_DOS_HEADER) ||
      snapshot.size() < sizeof(IMAGE_DOS_HEADER)) {
    return;
  }
  const auto* live_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(live.data());
  const auto* snap_dos =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(snapshot.data());
  if (live_dos->e_lfanew != snap_dos->e_lfanew) {
    Log(kLogInfo, "PE header: e_lfanew changed.");
    return;
  }
  const size_t nt_offset = static_cast<size_t>(live_dos->e_lfanew);
  if (nt_offset + sizeof(IMAGE_NT_HEADERS) > live.size() ||
      nt_offset + sizeof(IMAGE_NT_HEADERS) > snapshot.size()) {
    return;
  }
  const auto* live_nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(live.data() + nt_offset);
  const auto* snap_nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(snapshot.data() + nt_offset);
  if (live_nt->Signature != IMAGE_NT_SIGNATURE ||
      snap_nt->Signature != IMAGE_NT_SIGNATURE) {
    Log(kLogInfo, "PE header: signature changed.");
    return;
  }

  if (live_nt->FileHeader.NumberOfSections !=
      snap_nt->FileHeader.NumberOfSections) {
    LogF(kLogInfo, "PE header: NumberOfSections %u -> %u.",
         snap_nt->FileHeader.NumberOfSections,
         live_nt->FileHeader.NumberOfSections);
  }
  if (live_nt->FileHeader.Characteristics !=
      snap_nt->FileHeader.Characteristics) {
    LogF(kLogInfo, "PE header: Characteristics %04X -> %04X.",
         snap_nt->FileHeader.Characteristics,
         live_nt->FileHeader.Characteristics);
  }
  if (live_nt->OptionalHeader.AddressOfEntryPoint !=
      snap_nt->OptionalHeader.AddressOfEntryPoint) {
    LogF(kLogInfo, "PE header: AddressOfEntryPoint %X -> %X.",
         snap_nt->OptionalHeader.AddressOfEntryPoint,
         live_nt->OptionalHeader.AddressOfEntryPoint);
  }
  if (live_nt->OptionalHeader.SizeOfImage !=
      snap_nt->OptionalHeader.SizeOfImage) {
    LogF(kLogInfo, "PE header: SizeOfImage %X -> %X.",
         snap_nt->OptionalHeader.SizeOfImage,
         live_nt->OptionalHeader.SizeOfImage);
  }
  if (live_nt->OptionalHeader.ImageBase != snap_nt->OptionalHeader.ImageBase) {
    LogF(kLogInfo, "PE header: ImageBase %llX -> %llX.",
         static_cast<uint64_t>(snap_nt->OptionalHeader.ImageBase),
         static_cast<uint64_t>(live_nt->OptionalHeader.ImageBase));
  }
  if (live_nt->OptionalHeader.DllCharacteristics !=
      snap_nt->OptionalHeader.DllCharacteristics) {
    LogF(kLogInfo, "PE header: DllCharacteristics %04X -> %04X.",
         snap_nt->OptionalHeader.DllCharacteristics,
         live_nt->OptionalHeader.DllCharacteristics);
  }

  const size_t section_offset = nt_offset + sizeof(IMAGE_NT_HEADERS);
  const size_t section_bytes =
      std::min<size_t>(
          static_cast<size_t>(live_nt->FileHeader.NumberOfSections),
          static_cast<size_t>(snap_nt->FileHeader.NumberOfSections)) *
      sizeof(IMAGE_SECTION_HEADER);
  if (section_bytes != 0 &&
      (section_offset + section_bytes > live.size() ||
       section_offset + section_bytes > snapshot.size() ||
       std::memcmp(live.data() + section_offset,
                   snapshot.data() + section_offset, section_bytes) != 0)) {
    Log(kLogInfo, "PE header: section table changed.");
  }
}

}  // namespace

// --------------------------------------------------------------------------
// Dumper
// --------------------------------------------------------------------------

Dumper::Dumper(const PROCESS_INFORMATION& process,
               const std::wstring& original_file, uintptr_t image_base,
               uintptr_t oep)
    : process_(process), oep_(oep), image_base_(image_base) {
#if !defined(_WIN64)
  if (GetWindowsMajorVersion() > 5) {
    // user32 has an internal function 'PatchExportTableForwarders' that
    // patches the AddressOfFunctions table.
    usr_module_path_ = ExtractFilePath(GetExecutablePath()) + L"mmusr32.dll";
    if (CopyFileW(L"C:\\Windows\\system32\\user32.dll",
                  usr_module_path_.c_str(), FALSE)) {
      const HMODULE module =
          LoadLibraryExW(usr_module_path_.c_str(), nullptr, 0x20);
      if (module != nullptr) {
        // Data-file handles are tagged with +2 by the loader.
        usr_module_ = reinterpret_cast<uintptr_t>(module) - 2;
      }
    }
  }
#endif

  original_imports_ = GetOriginalImports(original_file);

  // Capture the header at the OEP, before import tracing/anti-dump fixes can
  // modify it. Process() falls back to this snapshot when the live header
  // looks corrupted.
  header_snapshot_.resize(0x1000);
  if (!Rpm(image_base_, header_snapshot_.data(), header_snapshot_.size())) {
    MakeMemoryReadable(image_base_, header_snapshot_.size());
    if (!Rpm(image_base_, header_snapshot_.data(), header_snapshot_.size())) {
      header_snapshot_.clear();
      Log(kLogWarning, "Could not capture the PE header before tracing.");
    } else {
      Log(kLogInfo, "Captured the PE header at OEP.");
    }
  }
}

Dumper::~Dumper() {
#if !defined(_WIN64)
  if (usr_module_ != 0) {
    FreeLibrary(reinterpret_cast<HMODULE>(usr_module_ + 2));
    DeleteFileW(usr_module_path_.c_str());
  }
#endif
}

void Dumper::DumpToFile(const std::wstring& file_name, PeHeader& pe,
                        bool is_dll) {
  FileStream file(file_name, FileStream::Mode::kCreate);

  uint32_t size = pe.DumpSize();
  std::vector<uint8_t> buffer(size);
  MakeMemoryReadable(image_base_, size);
  if (!Rpm(image_base_, buffer.data(), size)) {
    throw std::runtime_error(
        Format("DumpToFile RPM failed (base: %llX, size: %X)",
               static_cast<uint64_t>(image_base_), size));
  }

  uint32_t iat_raw_offset = static_cast<uint32_t>(iat_ - image_base_);
  // TrimHugeSections may adjust iatRawOffset depending on what is trimmed.
  const uint32_t delta = pe.TrimHugeSections(buffer.data(), iat_raw_offset);
  size -= delta;
  file.Write(buffer.data(), size);

  const size_t number_of_sections = pe.nt_headers().FileHeader.NumberOfSections;
  for (size_t i = number_of_sections; i < pe.Sections().size(); ++i) {
    const PeSection& section = pe.Sections()[i];
    const uint32_t raw_size = section.header.SizeOfRawData;
    const size_t available = std::min<size_t>(section.data.size(), raw_size);
    if (available > 0) {
      file.Write(section.data.data(), available);
    }
    if (available < raw_size) {
      std::vector<uint8_t> zeros(raw_size - available);
      file.Write(zeros.data(), zeros.size());
    }
  }

  pe.nt_headers().FileHeader.NumberOfSections =
      static_cast<WORD>(pe.Sections().size());
  pe.nt_headers().OptionalHeader.AddressOfEntryPoint =
      static_cast<uint32_t>(oep_ - image_base_);

  if (is_dll) {
    pe.nt_headers().FileHeader.Characteristics |= IMAGE_FILE_DLL;
    SwitchSxsManifestType(file, pe, 1, 2);  // Switch back
  }

  if ((pe.nt_headers().OptionalHeader.DllCharacteristics & 0x40) != 0) {
    Log(kLogInfo, "Executable is ASLR-aware - disabling the flag in the dump");
    pe.nt_headers().OptionalHeader.DllCharacteristics &= ~0x40;
  }

  // The dumped bytes were read from image_base_. If the loader relocated the
  // image, the in-memory header still reports the preferred base, and every
  // absolute address in the dump is relative to image_base_ instead. Keep the
  // header consistent with the contents.
  if (static_cast<uintptr_t>(pe.nt_headers().OptionalHeader.ImageBase) !=
      image_base_) {
    LogF(kLogWarning,
         "Header image base %llX does not match the load address %llX; "
         "updating the dump header.",
         static_cast<uint64_t>(pe.nt_headers().OptionalHeader.ImageBase),
         static_cast<uint64_t>(image_base_));
    pe.nt_headers().OptionalHeader.ImageBase =
        static_cast<decltype(pe.nt_headers().OptionalHeader.ImageBase)>(
            image_base_);
  }

  pe.SaveToStream(file);

  file.Seek(iat_raw_offset, Stream::Origin::kBegin);
  file.Write(iat_image_.data(), iat_image_size_);
}

uint32_t Dumper::DetermineIatSize(const uint8_t* iat) {
  uint32_t last_valid_offset = 0;
  uint32_t i = 0;
  uintptr_t value = 0;

  while (i < kMaxIatSize &&
         (last_valid_offset == 0 || i < last_valid_offset + 0x100)) {
    std::memcpy(&value, iat + i, sizeof(value));
    if (IsApiAddress(value)) {
      last_valid_offset = i;
    }
    i += static_cast<uint32_t>(sizeof(void*));
  }

  return last_valid_offset + static_cast<uint32_t>(sizeof(void*));
}

namespace {

struct ImportThunk {
  RemoteModule* module = nullptr;
  std::string name;
  std::vector<uintptr_t*> addresses;

  explicit ImportThunk(RemoteModule* source_module) : module(source_module) {
    if (source_module != nullptr) {
      name = source_module->name;
    }
  }
};

struct ResolutionCandidate {
  uintptr_t address = 0;
  RemoteModule* module = nullptr;
};

struct IatSlot {
  std::vector<ResolutionCandidate> candidates;
  int chosen_candidate = -1;
  bool is_zero = false;
};

struct ModuleVote {
  std::string name;
  int votes = 0;
  int first_seen = 0;
};

}  // namespace

std::unique_ptr<PeHeader> Dumper::Process() {
  if (iat_ == 0) {
    throw std::runtime_error("Must set IAT before calling Process()");
  }

  // Read header from memory.
  std::vector<uint8_t> section_data(0x1000);
  if (!Rpm(image_base_, section_data.data(), section_data.size())) {
    throw std::runtime_error("Dumper::Process: reading image header failed");
  }

  if (!header_snapshot_.empty() &&
      header_snapshot_.size() == section_data.size() &&
      std::memcmp(section_data.data(), header_snapshot_.data(),
                  section_data.size()) != 0) {
    Log(kLogWarning, "The PE header changed between OEP and dump.");
    LogHeaderDiff(section_data, header_snapshot_);
    const bool live_plausible = IsPlausiblePeHeader(section_data);
    const bool snapshot_plausible = IsPlausiblePeHeader(header_snapshot_);
    if (!live_plausible && snapshot_plausible) {
      Log(kLogWarning,
          "The live PE header looks corrupted; using the pre-trace snapshot.");
      section_data = header_snapshot_;
    } else if (live_plausible) {
      Log(kLogInfo, "The live PE header still looks valid; keeping it.");
    } else {
      Log(kLogWarning, "Both PE headers look invalid; keeping the live one.");
    }
  }

  auto pe =
      std::make_unique<PeHeader>(section_data.data(), section_data.size());
  pe->Sanitize();

  std::vector<uint8_t> iat(kMaxIatSize);
  if (!Rpm(iat_, iat.data(), iat.size())) {
    throw std::runtime_error("Dumper::Process: reading IAT failed");
  }

  const uint32_t iat_size = DetermineIatSize(iat.data());
  LogF(kLogInfo, "Determined IAT size: %X", iat_size);

  auto& iat_directory =
      pe->nt_headers().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
  iat_directory.VirtualAddress = static_cast<uint32_t>(iat_ - image_base_);
  iat_directory.Size = iat_size + static_cast<uint32_t>(sizeof(void*));

  if (!snapshot_taken_) {
    TakeModuleSnapshot();
  }

  bool allow_api_sets = false;
  for (const OriginalImport& import : original_imports_) {
    if (import.dll_name.rfind("api-ms-win", 0) == 0) {
      allow_api_sets = true;
      break;
    }
  }

  const int slot_count = static_cast<int>(iat_size / sizeof(uintptr_t));
  std::vector<IatSlot> slots(static_cast<size_t>(slot_count));

  auto read_slot = [&](int index) {
    uintptr_t value = 0;
    std::memcpy(&value,
                iat.data() + static_cast<size_t>(index) * sizeof(uintptr_t),
                sizeof(value));
    return value;
  };
  auto write_slot = [&](int index, uintptr_t value) {
    std::memcpy(iat.data() + static_cast<size_t>(index) * sizeof(uintptr_t),
                &value, sizeof(value));
  };

  // =======================================================================
  // PASS 1: Collect all candidates for every IAT slot.
  // =======================================================================
  for (int i = 0; i < slot_count; ++i) {
    IatSlot& slot = slots[static_cast<size_t>(i)];
    slot.is_zero = read_slot(i) == 0;

    if (slot.is_zero) {
      continue;
    }

    const uintptr_t slot_value = read_slot(i);

    // --- Variant A: no forwarding ---
    ResolutionCandidate candidate;
    candidate.address = slot_value;
    candidate.module = nullptr;
    for (const auto& rm_ptr : all_modules_) {
      RemoteModule& rm = *rm_ptr;
      if (candidate.address > rm.base && candidate.address < rm.end_off) {
        if (rm.export_tbl.find(candidate.address) != rm.export_tbl.end()) {
          candidate.module = &rm;
          slot.candidates.push_back(candidate);
        }
        break;  // only one module owns this address
      }
    }

    // --- Variant B: forwards_ (e.g. ntdll stub -> kernelbase real) ---
    const auto forward_it = forwards_.find(slot_value);
    if (forward_it != forwards_.end()) {
      for (const ForwardOrigin& origin : forward_it->second) {
        candidate.address = origin.source_address;
        candidate.module = origin.source_module;
        slot.candidates.push_back(candidate);
      }
    }

    if (slot.candidates.empty()) {
      LogF(kLogInfo, "IAT slot %08llX -> %08llX unresolvable",
           static_cast<uint64_t>(iat_ +
                                 static_cast<uintptr_t>(i) * sizeof(uintptr_t)),
           static_cast<uint64_t>(slot_value));
    }
  }

  // =======================================================================
  // PASS 2: For each zero-delimited group, vote on the best module and pin
  //         every slot to a candidate from that module.
  // =======================================================================
  std::vector<std::unique_ptr<ImportThunk>> thunks;

  int i = 0;
  while (i < slot_count) {
    // Skip zero separators (they just end the current thunk naturally).
    if (slots[static_cast<size_t>(i)].is_zero) {
      ++i;
      continue;
    }

    // Find contiguous non-zero run = one raw group.
    const int group_start = i;
    int group_end = i;
    while (group_end + 1 < slot_count &&
           !slots[static_cast<size_t>(group_end + 1)].is_zero) {
      ++group_end;
    }

    // Vote: for each slot in group, each candidate casts one vote for its
    // module.
    std::vector<ModuleVote> votes;
    for (int j = group_start; j <= group_end; ++j) {
      for (const ResolutionCandidate& candidate :
           slots[static_cast<size_t>(j)].candidates) {
        const std::string& module_name = candidate.module->name;
        auto it = std::find_if(
            votes.begin(), votes.end(),
            [&](const ModuleVote& vote) { return vote.name == module_name; });
        if (it == votes.end()) {
          votes.push_back(
              ModuleVote{module_name, 1, static_cast<int>(votes.size())});
        } else {
          ++it->votes;
        }
      }
    }

    // Find the module with the most votes; apply scoring in ambiguous cases.
    std::string winner_name;
    int winner_votes = -1;
    int winner_preference = 0;
    RemoteModule* winner_module = nullptr;

    for (const ModuleVote& vote : votes) {
      const int preference = PreferenceScore(vote.name);
      if (vote.votes > winner_votes ||
          (vote.votes == winner_votes && preference > winner_preference)) {
        winner_votes = vote.votes;
        winner_name = vote.name;
        winner_preference = preference;
      }
    }

    // Pin each slot to the winning module's candidate.
    for (int j = group_start; j <= group_end; ++j) {
      IatSlot& slot = slots[static_cast<size_t>(j)];
      for (size_t k = 0; k < slot.candidates.size(); ++k) {
        if (slot.candidates[k].module->name == winner_name) {
          slot.chosen_candidate = static_cast<int>(k);
          if (winner_module == nullptr) {
            winner_module = slot.candidates[k].module;
          }
          break;
        }
      }
    }

    std::string api_set_name;
    if (allow_api_sets) {
      for (int j = group_start; j <= group_end; ++j) {
        const IatSlot& slot = slots[static_cast<size_t>(j)];
        if (slot.chosen_candidate < 0 && slot.candidates.empty()) {
          continue;
        }

        std::string func_name;
        if (slot.chosen_candidate < 0) {
          func_name = slot.candidates[0].module->export_tbl.at(
              slot.candidates[0].address);
        } else if (winner_module != nullptr) {
          func_name = winner_module->export_tbl.at(
              slot.candidates[static_cast<size_t>(slot.chosen_candidate)]
                  .address);
        }

        if (func_name.rfind("RtlQueryPerformance", 0) == 0) {
          func_name.erase(0, 3);  // Hack for api-ms-win-core-profile-l1-1-0.dll
        }

        if (j == group_start) {
          api_set_name = GetOneCoreUapModuleByApi(func_name);
        } else if (!api_set_name.empty() &&
                   GetOneCoreUapModuleByApi(func_name) != api_set_name) {
          api_set_name.clear();
        }
      }
    }

    // If using an ApiSet, remap so the slot is not skipped as bogus. Looking
    // for the same name in winnerModule is a bit risky, but so far this has
    // happened between kernel32 and kernelbase.
    if (!api_set_name.empty() && winner_module != nullptr) {
      for (int j = group_start; j <= group_end; ++j) {
        IatSlot& slot = slots[static_cast<size_t>(j)];
        if (slot.chosen_candidate >= 0 || slot.candidates.empty()) {
          continue;
        }

        const std::string func_name = slot.candidates[0].module->export_tbl.at(
            slot.candidates[0].address);
        // Find the address of this function in winnerModule's export table.
        for (const auto& export_entry : winner_module->export_tbl) {
          if (export_entry.second == func_name) {
            slot.candidates[0].address = export_entry.first;
            slot.chosen_candidate = 0;
            LogF(kLogInfo, "IAT slot %08llX: remapped apiset member %s",
                 static_cast<uint64_t>(iat_ + static_cast<uintptr_t>(j) *
                                                  sizeof(uintptr_t)),
                 func_name.c_str());
            break;
          }
        }
      }
    }

    // Now walk the group and build thunks, respecting the chosen candidates.
    // Within a zero-free group we stay in one thunk for the winner module.
    ImportThunk* thunk = nullptr;
    for (int j = group_start; j <= group_end; ++j) {
      IatSlot& slot = slots[static_cast<size_t>(j)];
      if (slot.chosen_candidate < 0) {
        LogF(kLogFatal,
             "IAT slot %08llX  has no candidate for winning module %s (bogus "
             "entry)",
             static_cast<uint64_t>(iat_ + static_cast<uintptr_t>(j) *
                                              sizeof(uintptr_t)),
             winner_name.c_str());
        continue;
      }

      if (thunk == nullptr) {
        thunks.push_back(std::make_unique<ImportThunk>(winner_module));
        thunk = thunks.back().get();
        thunk->name = winner_name;
      }

      // Write the resolved pointer back into the IAT image.
      const ResolutionCandidate& candidate =
          slot.candidates[static_cast<size_t>(slot.chosen_candidate)];
      write_slot(j, candidate.address);
      thunk->addresses.push_back(reinterpret_cast<uintptr_t*>(
          iat.data() + static_cast<size_t>(j) * sizeof(uintptr_t)));
    }

    if (!api_set_name.empty() && thunk != nullptr && winner_module != nullptr) {
      const uintptr_t first_address = *thunk->addresses.front();
      const auto first_import = winner_module->export_tbl.find(first_address);
      if (first_import != winner_module->export_tbl.end() &&
          !HasOriginalImport(thunk->name, first_import->second)) {
        LogF(kLogInfo, "OneCoreUAP: Using %s instead of %s",
             api_set_name.c_str(), winner_name.c_str());
        thunk->name = api_set_name;
      }
    }

    i = group_end + 1;
  }

  PeSection* import_section = pe->CreateSection(".import", 0x1000);
  std::vector<uint8_t> import_data(import_section->header.SizeOfRawData, 0);

  const size_t descriptor_count =
      thunks.size() + 1;  // Last descriptor is empty
  size_t strings_offset = descriptor_count * sizeof(IMAGE_IMPORT_DESCRIPTOR);

  auto ensure_import_capacity = [&](size_t required) {
    while (required > import_data.size()) {
      import_section->header.SizeOfRawData += 0x1000;
      import_section->header.Misc.VirtualSize += 0x1000;
      pe->nt_headers().OptionalHeader.SizeOfImage += 0x1000;
      import_data.resize(import_section->header.SizeOfRawData, 0);
    }
  };

  for (size_t thunk_index = 0; thunk_index < thunks.size(); ++thunk_index) {
    ImportThunk& thunk = *thunks[thunk_index];
    auto* descriptors =
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(import_data.data());

    descriptors[thunk_index].FirstThunk = static_cast<uint32_t>(
        iat_ - image_base_ +
        reinterpret_cast<uintptr_t>(thunk.addresses.front()) -
        reinterpret_cast<uintptr_t>(iat.data()));
    descriptors[thunk_index].Name =
        pe->ConvertOffsetToRvaVector(import_section->header.PointerToRawData +
                                     static_cast<uint32_t>(strings_offset));

    const std::string& module_name = thunk.name;
    ensure_import_capacity(strings_offset + module_name.size() + 1);
    std::memcpy(import_data.data() + strings_offset, module_name.c_str(),
                module_name.size());
    strings_offset += module_name.size() + 1;

    RemoteModule* remote_module = thunk.module;
    LogF(kLogInfo, "Thunk %s - first import: %s", thunk.name.c_str(),
         remote_module->export_tbl.at(*thunk.addresses.front()).c_str());

    for (size_t j = 0; j < thunk.addresses.size(); ++j) {
      std::string func_name = remote_module->export_tbl.at(*thunk.addresses[j]);
      if (!func_name.empty() && func_name[0] == '#') {
        const uint32_t ordinal_index = static_cast<uint32_t>(
            std::strtoul(func_name.c_str() + 1, nullptr, 10));
        *thunk.addresses[j] =
            static_cast<uintptr_t>(IMAGE_ORDINAL_FLAG) | ordinal_index;
        continue;
      }

      if (func_name.rfind("RtlQueryPerformance", 0) == 0 &&
          thunk.name.rfind("api-ms-win", 0) == 0) {
        func_name.erase(0, 3);
      }

      // Hint (2 bytes, already zero) followed by the name.
      const size_t hint_offset = strings_offset;
      strings_offset += 2;
      *thunk.addresses[j] = static_cast<uintptr_t>(
          pe->ConvertOffsetToRvaVector(import_section->header.PointerToRawData +
                                       static_cast<uint32_t>(hint_offset)));

      ensure_import_capacity(strings_offset + func_name.size() + 1);
      std::memcpy(import_data.data() + strings_offset, func_name.c_str(),
                  func_name.size());
      strings_offset += func_name.size() + 1;

      if (strings_offset > import_data.size() - 0x100) {
        import_section->header.SizeOfRawData += 0x1000;
        import_section->header.Misc.VirtualSize += 0x1000;
        pe->nt_headers().OptionalHeader.SizeOfImage += 0x1000;
        import_data.resize(import_section->header.SizeOfRawData, 0);
      }
    }
  }

  import_section->data = std::move(import_data);

  auto& import_directory =
      pe->nt_headers()
          .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  import_directory.VirtualAddress = import_section->header.VirtualAddress;
  import_directory.Size =
      static_cast<uint32_t>(thunks.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));

  iat_image_ = std::move(iat);
  iat_image_size_ = iat_size;
  return pe;
}

void Dumper::GatherModuleExportsFromRemoteProcess(RemoteModule& module) {
  std::vector<uint8_t> head(0x1000);
  if (!Rpm(module.base, head.data(), head.size())) {
    return;
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(head.data());
  const auto* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(head.data() + dos->e_lfanew);
  const IMAGE_DATA_DIRECTORY export_directory =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  if (export_directory.VirtualAddress == 0 ||
      export_directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
    return;
  }

  std::vector<uint8_t> export_data(export_directory.Size);
  if (!Rpm(module.base + export_directory.VirtualAddress, export_data.data(),
           export_data.size())) {
    return;
  }

  const auto* directory =
      reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(export_data.data());
  const auto* functions = reinterpret_cast<const uint32_t*>(
      RemoteExportPointer(export_data, export_directory.VirtualAddress,
                          directory->AddressOfFunctions));
  const auto* names = reinterpret_cast<const uint32_t*>(RemoteExportPointer(
      export_data, export_directory.VirtualAddress, directory->AddressOfNames));
  const auto* ordinals = reinterpret_cast<const uint16_t*>(
      RemoteExportPointer(export_data, export_directory.VirtualAddress,
                          directory->AddressOfNameOrdinals));

  std::vector<uint8_t> named(directory->NumberOfFunctions, 0);

  for (uint32_t index = 0; index < directory->NumberOfNames; ++index) {
    const uint32_t function_index = ordinals[index];
    if (function_index >= named.size()) {
      continue;
    }
    named[function_index] = 1;
    const char* function_name =
        reinterpret_cast<const char*>(RemoteExportPointer(
            export_data, export_directory.VirtualAddress, names[index]));
    module.export_tbl[module.base + functions[function_index]] = function_name;
  }

  for (uint32_t index = 0; index < directory->NumberOfFunctions; ++index) {
    // Add ordinals.
    if (index < named.size() && !named[index]) {
      const uint32_t function_index = directory->Base + index;
      module.export_tbl[module.base + functions[index]] =
          "#" + std::to_string(function_index);
    }

    // Check if entry is forward.
    if (functions[index] > export_directory.VirtualAddress &&
        functions[index] <
            export_directory.VirtualAddress + export_directory.Size) {
      const char* forward = reinterpret_cast<const char*>(RemoteExportPointer(
          export_data, export_directory.VirtualAddress, functions[index]));
      if (std::string(forward).find(".#") == std::string::npos) {
        module.forwards.push_back({forward, module.base + functions[index]});
      }
    }
  }
}

#if !defined(_WIN64)
void Dumper::CollectSpecialUser32Forwards(RemoteModule& user32) {
  // Scan the specially loaded user32 copy, because forwards are patched out
  // in normally loaded user32 images.
  const auto* mod_scan = reinterpret_cast<const uint8_t*>(usr_module_);
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod_scan);
  const auto* nt =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(mod_scan + dos->e_lfanew);
  const IMAGE_DATA_DIRECTORY export_directory =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  const auto* directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
      mod_scan + export_directory.VirtualAddress);
  const auto* functions = reinterpret_cast<const uint32_t*>(
      mod_scan + directory->AddressOfFunctions);

  for (uint32_t index = 0; index < directory->NumberOfFunctions; ++index) {
    const char* forward =
        reinterpret_cast<const char*>(mod_scan + functions[index]);
    const uintptr_t forward_address = reinterpret_cast<uintptr_t>(forward);
    if (forward_address > reinterpret_cast<uintptr_t>(mod_scan) +
                              export_directory.VirtualAddress &&
        forward_address < reinterpret_cast<uintptr_t>(mod_scan) +
                              export_directory.VirtualAddress +
                              export_directory.Size &&
        std::string(forward).find(".#") == std::string::npos) {
      user32.forwards.push_back({forward, 0});
    }
  }
}
#endif

void Dumper::ResolveForwards(RemoteModule& module) {
  for (const Forward& forward : module.forwards) {
    const size_t dot_pos = forward.key.find('.');
    if (dot_pos == std::string::npos) {
      continue;
    }

    const std::string forward_module_name = forward.key.substr(0, dot_pos);
    RemoteModule* forward_module = nullptr;

    // api-ms-win, ext-ms-win
    if (forward_module_name.find("-ms-win-") == 3) {
      // Take a shortcut by resolving this locally.
      const HMODULE resolved = GetModuleHandleA(forward_module_name.c_str());
      if (resolved != nullptr) {
        forward_module = GetRemoteModule(resolved);
      }
    } else {
      forward_module = GetRemoteModule(forward_module_name + ".dll");
    }

    if (forward_module == nullptr) {
      continue;
    }

    const std::string forward_api_name = forward.key.substr(dot_pos + 1, 50);
    uintptr_t procedure_address = 0;
    for (const auto& export_entry : forward_module->export_tbl) {
      if (export_entry.second == forward_api_name) {
        procedure_address = export_entry.first;
        break;
      }
    }

    if (procedure_address != 0) {
      auto& origins = forwards_[procedure_address];
      uintptr_t forward_value = forward.value;
#if !defined(_WIN64)
      if (module.name == "user32.dll") {
        forward_value =
            procedure_address;  // user32 export_tbl has resolved values
      }
#endif
      origins.push_back({&module, forward_value});
    }
  }
}

RemoteModule* Dumper::GetRemoteModule(HMODULE base) {
  for (const auto& module : all_modules_) {
    if (module->base == reinterpret_cast<uintptr_t>(base)) {
      return module.get();
    }
  }
  return nullptr;
}

RemoteModule* Dumper::GetRemoteModule(const std::string& name) {
  const std::string lowered = AsciiLowerCase(name);
  for (const auto& module : all_modules_) {
    if (module->name == lowered) {
      return module.get();
    }
  }
  return nullptr;
}

bool Dumper::IsApiAddress(uintptr_t address) {
  if (!snapshot_taken_) {
    TakeModuleSnapshot();
  }

  for (const auto& module : all_modules_) {
    if (address >= module->base && address < module->end_off) {
      return module->export_tbl.find(address) != module->export_tbl.end();
    }
  }
  return false;
}

void Dumper::TakeModuleSnapshot() {
  snapshot_taken_ = true;

  const HANDLE snapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_.dwProcessId);
  if (snapshot == INVALID_HANDLE_VALUE) {
    throw std::runtime_error(
        Format("CreateToolhelp32Snapshot failed (error %lu)", GetLastError()));
  }

  MODULEENTRY32W module_entry{};
  module_entry.dwSize = sizeof(module_entry);
  if (!Module32FirstW(snapshot, &module_entry)) {
    CloseHandle(snapshot);
    throw std::runtime_error("Module32First");
  }

  do {
    if (reinterpret_cast<uintptr_t>(module_entry.hModule) != image_base_) {
      auto module = std::make_unique<RemoteModule>();
      module->base = reinterpret_cast<uintptr_t>(module_entry.modBaseAddr);
      module->end_off = module->base + module_entry.modBaseSize;
      module->name = AsciiLowerCase(WideToUtf8(module_entry.szModule));
      GatherModuleExportsFromRemoteProcess(*module);
#if !defined(_WIN64)
      if (module->name == "user32.dll" && usr_module_ != 0) {
        CollectSpecialUser32Forwards(*module);
      }
#endif
      all_modules_.push_back(std::move(module));
    }
  } while (Module32NextW(snapshot, &module_entry));

  CloseHandle(snapshot);

  for (const auto& module : all_modules_) {
    ResolveForwards(*module);
  }
}

bool Dumper::Rpm(uintptr_t address, void* buf, size_t size) {
  const BOOL result = ReadProcessMemory(
      process_.hProcess, reinterpret_cast<void*>(address), buf, size, nullptr);
  if (!result) {
    Log(kLogFatal, "RPM failed");
  }
  return result != FALSE;
}

void Dumper::MakeMemoryReadable(uintptr_t base, uintptr_t size) {
  uintptr_t address = base;
  const uintptr_t end_address = address + size;

  while (address < end_address) {
    MEMORY_BASIC_INFORMATION mbi{};
    const SIZE_T bytes_returned = VirtualQueryEx(
        process_.hProcess, reinterpret_cast<void*>(address), &mbi, sizeof(mbi));
    if (bytes_returned == 0) {
      break;
    }

    if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_NOACCESS) {
      DWORD old_protect = 0;
      VirtualProtectEx(process_.hProcess, mbi.BaseAddress, mbi.RegionSize,
                       PAGE_READONLY, &old_protect);
    }

    address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
  }
}

void Dumper::SwitchSxsManifestType(Stream& stream, PeHeader& pe,
                                   int switch_from, int switch_to) {
  const auto& resource_directory =
      pe.nt_headers()
          .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if (resource_directory.VirtualAddress == 0) {
    return;
  }

  PeSection* resource_section =
      pe.GetSectionByVa(resource_directory.VirtualAddress);
  if (resource_section == nullptr) {
    return;
  }

  const uint32_t resource_size = resource_directory.Size;
  if (resource_size < 0x10) {
    return;
  }

  stream.Seek(resource_section->header.PointerToRawData,
              Stream::Origin::kBegin);
  std::vector<uint8_t> resource_data(resource_size);
  stream.Read(resource_data.data(), resource_data.size());

  const auto read_word = [&](uint32_t offset) -> uint16_t {
    if (static_cast<size_t>(offset) + sizeof(uint16_t) > resource_data.size()) {
      return 0;
    }
    uint16_t value = 0;
    std::memcpy(&value, resource_data.data() + offset, sizeof(value));
    return value;
  };
  const auto read_dword = [&](uint32_t offset) -> uint32_t {
    if (static_cast<size_t>(offset) + sizeof(uint32_t) > resource_data.size()) {
      return 0;
    }
    uint32_t value = 0;
    std::memcpy(&value, resource_data.data() + offset, sizeof(value));
    return value;
  };

  const uint16_t num_named = read_word(0xC);
  const uint16_t num_ids = read_word(0xE);
  if (num_ids == 0) {
    return;
  }

  const uint32_t offset = 0x10 + static_cast<uint32_t>(num_named) * 8;
  uint32_t manifest_sub_dir = 0;
  for (uint16_t index = 0; index < num_ids; ++index) {
    const uint32_t entry_offset = offset + static_cast<uint32_t>(index) * 8;
    if (read_dword(entry_offset) == 24) {  // MANIFEST
      manifest_sub_dir = read_dword(entry_offset + 4);
      break;
    }
  }

  if (manifest_sub_dir == 0 || (manifest_sub_dir >> 31) != 1) {
    return;
  }

  manifest_sub_dir &= 0x7FFFFFFF;
  if (read_word(manifest_sub_dir + 0xC) != 0 ||
      read_word(manifest_sub_dir + 0xE) != 1) {
    Log(kLogInfo, "Encountered weird manifest resource dir");
    return;
  }

  const uint32_t id_offset = manifest_sub_dir + 0x10;
  if (static_cast<int32_t>(read_dword(id_offset)) != switch_from) {
    return;
  }

  stream.Seek(resource_section->header.PointerToRawData + id_offset,
              Stream::Origin::kBegin);
  const int32_t value = switch_to;
  stream.Write(&value, sizeof(value));
}

std::vector<OriginalImport> Dumper::GetOriginalImports(
    const std::wstring& file_name) {
  std::vector<OriginalImport> result;

  FileStream file(file_name, FileStream::Mode::kRead);
  std::vector<uint8_t> header_buffer(0x1000);
  const int64_t file_size = file.Size();
  const size_t to_read =
      std::min<size_t>(header_buffer.size(), static_cast<size_t>(file_size));
  if (to_read < sizeof(IMAGE_DOS_HEADER)) {
    return result;
  }
  file.Read(header_buffer.data(), to_read);

  PeHeader file_pe(header_buffer.data(), to_read);
  const IMAGE_DATA_DIRECTORY import_directory =
      file_pe.nt_headers()
          .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (import_directory.VirtualAddress == 0 || import_directory.Size == 0) {
    return result;
  }

  PeSection* section = file_pe.GetSectionByVa(import_directory.VirtualAddress);
  if (section == nullptr || section->header.SizeOfRawData == 0) {
    return result;
  }

  std::vector<uint8_t> section_buffer(section->header.SizeOfRawData);
  file.Seek(section->header.PointerToRawData, Stream::Origin::kBegin);
  file.Read(section_buffer.data(), section_buffer.size());

  const uint64_t section_rva = section->header.VirtualAddress;
  const auto read_c_string_at_rva = [&](uint32_t rva, uint32_t extra) {
    const uint64_t offset = static_cast<uint64_t>(rva) - section_rva + extra;
    if (offset >= section_buffer.size()) {
      return std::string();
    }
    const uint64_t remaining = section_buffer.size() - offset;
    const char* text =
        reinterpret_cast<const char*>(section_buffer.data() + offset);
    size_t length = 0;
    while (length < remaining && text[length] != '\0') {
      ++length;
    }
    return std::string(text, static_cast<size_t>(length));
  };

  if (import_directory.VirtualAddress < section_rva) {
    return result;
  }

  const uint64_t descriptor_offset =
      static_cast<uint64_t>(import_directory.VirtualAddress) - section_rva;
  if (descriptor_offset >= section_buffer.size()) {
    return result;
  }

  size_t descriptor_index = 0;
  for (;;) {
    const uint64_t current_offset =
        descriptor_offset + descriptor_index * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (current_offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) >
        section_buffer.size()) {
      break;
    }

    const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        section_buffer.data() + current_offset);
    if (descriptor->Name == 0) {
      break;
    }

    const std::string dll_name = read_c_string_at_rva(descriptor->Name, 0);

    if (descriptor->FirstThunk < section_rva) {
      break;
    }
    const uint64_t thunk_offset =
        static_cast<uint64_t>(descriptor->FirstThunk) - section_rva;
    if (thunk_offset >= section_buffer.size()) {
      break;
    }

    auto* thunk_address = reinterpret_cast<const uintptr_t*>(
        section_buffer.data() + thunk_offset);
    const size_t max_thunks =
        (section_buffer.size() - static_cast<size_t>(thunk_offset)) /
        sizeof(uintptr_t);

    for (size_t thunk_index = 0; thunk_index < max_thunks; ++thunk_index) {
      const uintptr_t thunk = thunk_address[thunk_index];
      if (thunk == 0) {
        break;
      }

      OriginalImport import;
      import.dll_name = AsciiLowerCase(dll_name);
      if ((thunk & IMAGE_ORDINAL_FLAG) != 0) {
        import.func_name = "#" + std::to_string(thunk & 0xFFFF);
      } else {
        import.func_name =
            read_c_string_at_rva(static_cast<uint32_t>(thunk), 2);
      }
      result.push_back(std::move(import));
    }

    ++descriptor_index;
  }

  return result;
}

bool Dumper::HasOriginalImport(const std::string& dll,
                               const std::string& func) const {
  for (const OriginalImport& import : original_imports_) {
    if (import.dll_name == dll && import.func_name == func) {
      return true;
    }
  }
  return false;
}

// --------------------------------------------------------------------------
// DumperDotnet
// --------------------------------------------------------------------------

DumperDotnet::DumperDotnet(const PROCESS_INFORMATION& process,
                           uintptr_t image_base)
    : process_(process), image_base_(image_base) {}

void DumperDotnet::DumpToFile(const std::wstring& file_name) {
  // Dumping Themida .NET binaries appears to be quite simple because no
  // special imports processing is required.
  uint8_t header[0x1000]{};
  if (!ReadProcessMemory(process_.hProcess,
                         reinterpret_cast<void*>(image_base_), header,
                         sizeof(header), nullptr)) {
    throw std::runtime_error("DumpToFile header RPM failed");
  }

  PeHeader pe(header, sizeof(header));
  if (pe.Sections().empty()) {
    throw std::runtime_error("DumpToFile: PE has no sections");
  }

  const PeSection& last_section = pe.Sections().back();
  uint32_t size =
      last_section.header.VirtualAddress + last_section.header.Misc.VirtualSize;

  FileStream file(file_name, FileStream::Mode::kCreate);
  std::vector<uint8_t> buffer(size);

  uint32_t physical_size = size;
  pe.FileAlign(physical_size);
  uint32_t image_size = physical_size;
  pe.SectionAlign(image_size);
  pe.nt_headers().OptionalHeader.SizeOfImage = image_size;
  pe.Sections()[0].Rename(".text");

  LogF(kLogInfo, "Output has %d sections, determined size to be 0x%X",
       pe.nt_headers().FileHeader.NumberOfSections, size);

  uint32_t done = 0;
  while (done < size) {
    MEMORY_BASIC_INFORMATION mbi{};
    mbi.RegionSize = 0x1000;
    const uintptr_t current_address = image_base_ + done;
    if (VirtualQueryEx(process_.hProcess,
                       reinterpret_cast<void*>(current_address), &mbi,
                       sizeof(mbi)) == 0) {
      throw std::runtime_error(Format("VirtualQueryEx failed at %llX",
                                      static_cast<uint64_t>(current_address)));
    }
    if (mbi.RegionSize == 0) {
      throw std::runtime_error(
          Format("VirtualQueryEx returned a zero region at %llX",
                 static_cast<uint64_t>(current_address)));
    }

    const size_t chunk =
        std::min<size_t>(size - done, static_cast<size_t>(mbi.RegionSize));
    if (mbi.State == MEM_COMMIT) {
      if (!ReadProcessMemory(process_.hProcess,
                             reinterpret_cast<void*>(current_address),
                             buffer.data() + done, chunk, nullptr)) {
        throw std::runtime_error("DumpToFile RPM failed");
      }
    } else if (mbi.State == MEM_RESERVE) {
      // We could mess with the section addresses and leave this chunk out of
      // the physical file, but eh...
      std::memset(buffer.data() + done, 0, chunk);
    } else {
      throw std::runtime_error(Format("Got unexpected region state %X at %llX",
                                      mbi.State,
                                      static_cast<uint64_t>(current_address)));
    }

    done += static_cast<uint32_t>(mbi.RegionSize);
  }

  file.Write(buffer.data(), buffer.size());
  if (size < physical_size) {
    // Pad to file alignment.
    std::vector<uint8_t> padding(physical_size - size, 0);
    file.Write(padding.data(), padding.size());
  }

  pe.SaveToStream(file);
}

}  // namespace magicmida
