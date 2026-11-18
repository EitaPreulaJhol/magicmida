// Magicmida - C++ port
// Human-readable PE information used by the GUI.
// SPDX-License-Identifier: GPL-3.0-only
#include "pe_report.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common.h"
#include "stream.h"

namespace magicmida {
namespace {

std::string MachineName(uint16_t machine) {
  switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
      return "i386";
    case IMAGE_FILE_MACHINE_AMD64:
      return "amd64";
    case IMAGE_FILE_MACHINE_ARM:
      return "arm";
    case IMAGE_FILE_MACHINE_ARM64:
      return "arm64";
    default:
      return Format("0x%04X", machine);
  }
}

std::string ArchitectureName(uint16_t machine) {
  switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
      return "x86 (32-bit)";
    case IMAGE_FILE_MACHINE_AMD64:
      return "x64 (64-bit)";
    case IMAGE_FILE_MACHINE_ARM:
      return "ARM (32-bit)";
    case IMAGE_FILE_MACHINE_ARM64:
      return "ARM64 (64-bit)";
    default:
      return MachineName(machine);
  }
}

struct ParsedSection {
  std::string name;
  uint32_t virtual_address = 0;
  uint32_t virtual_size = 0;
  uint32_t raw_offset = 0;
  uint32_t raw_size = 0;
  uint32_t characteristics = 0;
};

struct ParsedPe {
  bool valid = false;
  uint16_t machine = 0;
  uint16_t number_of_sections = 0;
  uint16_t linker_major = 0;
  uint16_t linker_minor = 0;
  uint32_t timestamp = 0;
  uint16_t optional_magic = 0;
  uint32_t entry_point = 0;
  uint64_t image_base = 0;
  uint32_t size_of_image = 0;
  uint32_t checksum = 0;
  uint16_t dll_characteristics = 0;
  bool is_dll = false;
  bool relocs_stripped = false;
  uint32_t reloc_rva = 0;
  uint32_t reloc_size = 0;
  uint32_t import_rva = 0;
  uint32_t import_size = 0;
  uint64_t file_size = 0;
  std::vector<ParsedSection> sections;
};

ParsedPe ReadPeInfo(const std::wstring& path) {
  ParsedPe result;

  FileStream file(path, FileStream::Mode::kRead);
  std::vector<uint8_t> header(0x1000);
  result.file_size = static_cast<uint64_t>(file.Size());
  const size_t to_read = static_cast<size_t>(
      std::min<int64_t>(static_cast<int64_t>(header.size()), file.Size()));
  if (to_read < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("File is too small to be a PE file.");
  }
  file.Read(header.data(), to_read);

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header.data());
  const size_t nt_offset = static_cast<size_t>(dos->e_lfanew);
  if (nt_offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > to_read) {
    throw std::runtime_error("Invalid PE header offset.");
  }

  const uint32_t signature =
      *reinterpret_cast<const uint32_t*>(header.data() + nt_offset);
  if (signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("PE signature mismatch.");
  }

  const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(
      header.data() + nt_offset + sizeof(uint32_t));
  result.machine = file_header->Machine;
  result.number_of_sections = file_header->NumberOfSections;
  result.timestamp = file_header->TimeDateStamp;
  result.is_dll = (file_header->Characteristics & IMAGE_FILE_DLL) != 0;
  result.relocs_stripped =
      (file_header->Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;

  const size_t optional_offset =
      nt_offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
  if (optional_offset + 2 > to_read) {
    throw std::runtime_error("Missing optional header.");
  }
  result.optional_magic =
      *reinterpret_cast<const uint16_t*>(header.data() + optional_offset);

  if (result.optional_magic == 0x10B) {
    if (optional_offset + sizeof(IMAGE_OPTIONAL_HEADER32) > to_read) {
      throw std::runtime_error("Truncated PE32 optional header.");
    }
    const auto* optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
        header.data() + optional_offset);
    result.linker_major = optional->MajorLinkerVersion;
    result.linker_minor = optional->MinorLinkerVersion;
    result.entry_point = optional->AddressOfEntryPoint;
    result.image_base = optional->ImageBase;
    result.size_of_image = optional->SizeOfImage;
    result.checksum = optional->CheckSum;
    result.dll_characteristics = optional->DllCharacteristics;
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
      result.reloc_rva =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress;
      result.reloc_size =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
      result.import_rva =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
      result.import_size =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
  } else if (result.optional_magic == 0x20B) {
    if (optional_offset + sizeof(IMAGE_OPTIONAL_HEADER64) > to_read) {
      throw std::runtime_error("Truncated PE32+ optional header.");
    }
    const auto* optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
        header.data() + optional_offset);
    result.linker_major = optional->MajorLinkerVersion;
    result.linker_minor = optional->MinorLinkerVersion;
    result.entry_point = optional->AddressOfEntryPoint;
    result.image_base = optional->ImageBase;
    result.size_of_image = optional->SizeOfImage;
    result.checksum = optional->CheckSum;
    result.dll_characteristics = optional->DllCharacteristics;
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
      result.reloc_rva =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress;
      result.reloc_size =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) {
      result.import_rva =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
      result.import_size =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }
  } else {
    throw std::runtime_error("Unknown optional header magic.");
  }

  const size_t section_offset =
      optional_offset + file_header->SizeOfOptionalHeader;
  const size_t section_size =
      sizeof(IMAGE_SECTION_HEADER) *
      static_cast<size_t>(file_header->NumberOfSections);
  if (section_offset + section_size > to_read) {
    throw std::runtime_error("Truncated section table.");
  }

  result.sections.reserve(file_header->NumberOfSections);
  for (size_t i = 0; i < file_header->NumberOfSections; ++i) {
    const auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        header.data() + section_offset + i * sizeof(IMAGE_SECTION_HEADER));

    char name[9]{};
    std::memcpy(name, section->Name, 8);
    ParsedSection parsed;
    parsed.name = name;
    parsed.virtual_address = section->VirtualAddress;
    parsed.virtual_size = section->Misc.VirtualSize;
    parsed.raw_offset = section->PointerToRawData;
    parsed.raw_size = section->SizeOfRawData;
    parsed.characteristics = section->Characteristics;
    result.sections.push_back(std::move(parsed));
  }

  result.valid = true;
  return result;
}

}  // namespace

uint16_t ReadPeMachine(const std::wstring& target) {
  return ReadPeInfo(target).machine;
}

bool ReadPeIsDll(const std::wstring& target) {
  return ReadPeInfo(target).is_dll;
}

PeFlags ReadPeFlags(const std::wstring& target) {
  const ParsedPe info = ReadPeInfo(target);
  PeFlags flags;
  flags.machine = info.machine;
  flags.is_dll = info.is_dll;
  return flags;
}

void EmitPeInfo(const std::wstring& target,
                const std::function<void(const std::string&)>& emit) {
  const ParsedPe info = ReadPeInfo(target);

  emit(Format("File:             %s", WideToUtf8(target).c_str()));
  emit(Format("Machine:          %s", MachineName(info.machine).c_str()));
  emit(Format("Architecture:     %s", ArchitectureName(info.machine).c_str()));
  emit(Format("Type:             %s", info.is_dll ? "DLL" : "EXE"));
  emit(Format("Linker:           %u.%u", info.linker_major, info.linker_minor));
  emit(Format("Timestamp:        0x%08X", info.timestamp));
  emit(Format("Image base:       0x%llX",
              static_cast<uint64_t>(info.image_base)));
  emit(Format("Entry point:      0x%X", info.entry_point));
  emit(Format("Size of image:    0x%X", info.size_of_image));
  emit(Format("Checksum:         0x%X", info.checksum));
  emit(Format("DLL flags:        0x%04X%s", info.dll_characteristics,
              (info.dll_characteristics & 0x40) ? " (ASLR)" : ""));
  emit(Format("Relocations:      %s (RVA 0x%X, size 0x%X)%s",
              (info.reloc_rva != 0 && info.reloc_size != 0) ? "yes" : "no",
              info.reloc_rva, info.reloc_size,
              info.relocs_stripped ? " [stripped flag set]" : ""));
  emit(Format("Sections:         %u", info.number_of_sections));
  emit("");
  emit(Format("  %-8s %-10s %-10s %-10s %-10s %s", "Name", "VA", "VSize",
              "RawOff", "RawSize", "Flags"));
  for (const ParsedSection& section : info.sections) {
    std::string flags;
    if (section.characteristics & IMAGE_SCN_MEM_READ) flags += "R";
    if (section.characteristics & IMAGE_SCN_MEM_WRITE) flags += "W";
    if (section.characteristics & IMAGE_SCN_MEM_EXECUTE) flags += "X";
    if (section.characteristics & IMAGE_SCN_CNT_CODE) flags += "C";
    if (section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) flags += "I";
    if (section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
      flags += "U";
    emit(Format("  %-8s %08X   %08X   %08X   %08X   %s", section.name.c_str(),
                section.virtual_address, section.virtual_size,
                section.raw_offset, section.raw_size, flags.c_str()));
  }
}

void VerifyDump(const std::wstring& target, bool is_dll,
                bool relocations_expected) {
  ParsedPe info;
  try {
    info = ReadPeInfo(target);
  } catch (const std::exception& error) {
    LogF(kLogFatal, "Dump verification failed: %s", error.what());
    return;
  }

  Log(kLogInfo, "Verifying the dump...");
  bool ok = true;

  const ParsedSection* entry_section = nullptr;
  for (const ParsedSection& section : info.sections) {
    const uint32_t span = std::max(section.virtual_size, section.raw_size);
    if (info.entry_point >= section.virtual_address &&
        info.entry_point < section.virtual_address + span) {
      entry_section = &section;
      break;
    }
  }
  if (info.entry_point == 0) {
    Log(kLogInfo, "No entry point (AddressOfEntryPoint is zero).");
  } else if (entry_section == nullptr) {
    LogF(kLogWarning, "Entry point 0x%X is outside every section.",
         info.entry_point);
    ok = false;
  } else if ((entry_section->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
    LogF(kLogWarning, "Entry point 0x%X is in non-executable section %s.",
         info.entry_point, entry_section->name.c_str());
    ok = false;
  } else {
    LogF(kLogInfo, "Entry point 0x%X is in %s.", info.entry_point,
         entry_section->name.c_str());
  }

  uint64_t virtual_end = 0;
  for (const ParsedSection& section : info.sections) {
    virtual_end = std::max<uint64_t>(
        virtual_end,
        static_cast<uint64_t>(section.virtual_address) + section.virtual_size);
    if (section.raw_size != 0 &&
        static_cast<uint64_t>(section.raw_offset) + section.raw_size >
            info.file_size) {
      LogF(kLogWarning,
           "Section %s raw data (0x%X+0x%X) lies outside the file (0x%llX).",
           section.name.c_str(), section.raw_offset, section.raw_size,
           static_cast<uint64_t>(info.file_size));
      ok = false;
    }
    if ((section.characteristics & IMAGE_SCN_MEM_WRITE) != 0 &&
        (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
      LogF(kLogWarning, "Section %s is both writable and executable.",
           section.name.c_str());
    }
  }
  if (virtual_end > info.size_of_image) {
    LogF(kLogWarning,
         "SizeOfImage 0x%X is smaller than the sections end 0x%llX.",
         info.size_of_image, static_cast<uint64_t>(virtual_end));
    ok = false;
  }

  if (info.import_rva != 0 && info.import_size != 0) {
    LogF(kLogInfo, "Import directory present (RVA 0x%X, size 0x%X).",
         info.import_rva, info.import_size);
  } else {
    Log(kLogWarning, "The dump has no import directory.");
    ok = false;
  }

  if (info.reloc_rva != 0 && info.reloc_size != 0) {
    LogF(kLogInfo, "Relocation directory present (RVA 0x%X, size 0x%X).",
         info.reloc_rva, info.reloc_size);
  } else if (is_dll && relocations_expected) {
    Log(kLogWarning, "Relocations were requested but the dump has none.");
    ok = false;
  } else if (is_dll) {
    Log(kLogWarning,
        "The DLL has no relocation table; it can only load at its ImageBase. "
        "Enable Fix DLL relocations to rebuild it.");
  }

  if (ok) {
    Log(kLogGood, "Dump sanity check passed.");
  } else {
    Log(kLogWarning, "Dump sanity check reported problems.");
  }
}

}  // namespace magicmida
