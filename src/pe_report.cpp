// Magicmida - C++ port
// Human-readable PE information used by the GUI.
#include "pe_report.h"

#include "common.h"
#include "stream.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

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

struct ParsedSection {
  std::string name;
  uint32_t virtualAddress = 0;
  uint32_t virtualSize = 0;
  uint32_t rawOffset = 0;
  uint32_t rawSize = 0;
  uint32_t characteristics = 0;
};

struct ParsedPE {
  bool valid = false;
  uint16_t machine = 0;
  uint16_t numberOfSections = 0;
  uint16_t linkerMajor = 0;
  uint16_t linkerMinor = 0;
  uint32_t timestamp = 0;
  uint16_t optionalMagic = 0;
  uint32_t entryPoint = 0;
  uint64_t imageBase = 0;
  uint32_t sizeOfImage = 0;
  uint32_t checksum = 0;
  uint16_t dllCharacteristics = 0;
  bool isDll = false;
  bool relocsStripped = false;
  uint32_t relocRva = 0;
  uint32_t relocSize = 0;
  std::vector<ParsedSection> sections;
};

ParsedPE ReadPEInfo(const std::wstring& path) {
  ParsedPE result;

  FileStream file(path, FileStream::Mode::Read);
  std::vector<uint8_t> header(0x1000);
  const size_t toRead = static_cast<size_t>(
      std::min<int64_t>(static_cast<int64_t>(header.size()), file.Size()));
  if (toRead < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("File is too small to be a PE file.");
  }
  file.Read(header.data(), toRead);

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header.data());
  const size_t ntOffset = static_cast<size_t>(dos->e_lfanew);
  if (ntOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > toRead) {
    throw std::runtime_error("Invalid PE header offset.");
  }

  const uint32_t signature =
      *reinterpret_cast<const uint32_t*>(header.data() + ntOffset);
  if (signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("PE signature mismatch.");
  }

  const auto* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
      header.data() + ntOffset + sizeof(uint32_t));
  result.machine = fileHeader->Machine;
  result.numberOfSections = fileHeader->NumberOfSections;
  result.timestamp = fileHeader->TimeDateStamp;
  result.isDll = (fileHeader->Characteristics & IMAGE_FILE_DLL) != 0;
  result.relocsStripped =
      (fileHeader->Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;

  const size_t optionalOffset =
      ntOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER);
  if (optionalOffset + 2 > toRead) {
    throw std::runtime_error("Missing optional header.");
  }
  result.optionalMagic =
      *reinterpret_cast<const uint16_t*>(header.data() + optionalOffset);

  if (result.optionalMagic == 0x10B) {
    if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER32) > toRead) {
      throw std::runtime_error("Truncated PE32 optional header.");
    }
    const auto* optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
        header.data() + optionalOffset);
    result.linkerMajor = optional->MajorLinkerVersion;
    result.linkerMinor = optional->MinorLinkerVersion;
    result.entryPoint = optional->AddressOfEntryPoint;
    result.imageBase = optional->ImageBase;
    result.sizeOfImage = optional->SizeOfImage;
    result.checksum = optional->CheckSum;
    result.dllCharacteristics = optional->DllCharacteristics;
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
      result.relocRva =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress;
      result.relocSize =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
  } else if (result.optionalMagic == 0x20B) {
    if (optionalOffset + sizeof(IMAGE_OPTIONAL_HEADER64) > toRead) {
      throw std::runtime_error("Truncated PE32+ optional header.");
    }
    const auto* optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
        header.data() + optionalOffset);
    result.linkerMajor = optional->MajorLinkerVersion;
    result.linkerMinor = optional->MinorLinkerVersion;
    result.entryPoint = optional->AddressOfEntryPoint;
    result.imageBase = optional->ImageBase;
    result.sizeOfImage = optional->SizeOfImage;
    result.checksum = optional->CheckSum;
    result.dllCharacteristics = optional->DllCharacteristics;
    if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
      result.relocRva =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
              .VirtualAddress;
      result.relocSize =
          optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
  } else {
    throw std::runtime_error("Unknown optional header magic.");
  }

  const size_t sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
  const size_t sectionSize =
      sizeof(IMAGE_SECTION_HEADER) * static_cast<size_t>(fileHeader->NumberOfSections);
  if (sectionOffset + sectionSize > toRead) {
    throw std::runtime_error("Truncated section table.");
  }

  result.sections.reserve(fileHeader->NumberOfSections);
  for (size_t i = 0; i < fileHeader->NumberOfSections; ++i) {
    const auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        header.data() + sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));

    char name[9]{};
    std::memcpy(name, section->Name, 8);
    ParsedSection parsed;
    parsed.name = name;
    parsed.virtualAddress = section->VirtualAddress;
    parsed.virtualSize = section->Misc.VirtualSize;
    parsed.rawOffset = section->PointerToRawData;
    parsed.rawSize = section->SizeOfRawData;
    parsed.characteristics = section->Characteristics;
    result.sections.push_back(std::move(parsed));
  }

  result.valid = true;
  return result;
}

}  // namespace

uint16_t ReadPEMachine(const std::wstring& target) {
  return ReadPEInfo(target).machine;
}

bool ReadPEIsDll(const std::wstring& target) {
  return ReadPEInfo(target).isDll;
}

void EmitPEInfo(const std::wstring& target,
                const std::function<void(const std::string&)>& emit) {
  const ParsedPE info = ReadPEInfo(target);

  emit(Format("File:             %s", WideToUtf8(target).c_str()));
  emit(Format("Machine:          %s", MachineName(info.machine).c_str()));
  emit(Format("Type:             %s", info.isDll ? "DLL" : "EXE"));
  emit(Format("Linker:           %u.%u", info.linkerMajor, info.linkerMinor));
  emit(Format("Timestamp:        0x%08X", info.timestamp));
  emit(Format("Image base:       0x%llX",
              static_cast<unsigned long long>(info.imageBase)));
  emit(Format("Entry point:      0x%X", info.entryPoint));
  emit(Format("Size of image:    0x%X", info.sizeOfImage));
  emit(Format("Checksum:         0x%X", info.checksum));
  emit(Format("DLL flags:        0x%04X%s", info.dllCharacteristics,
              (info.dllCharacteristics & 0x40) ? " (ASLR)" : ""));
  emit(Format("Relocations:      %s (RVA 0x%X, size 0x%X)%s",
              (info.relocRva != 0 && info.relocSize != 0) ? "yes" : "no",
              info.relocRva, info.relocSize,
              info.relocsStripped ? " [stripped flag set]" : ""));
  emit(Format("Sections:         %u", info.numberOfSections));
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
    if (section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) flags += "U";
    emit(Format("  %-8s %08X   %08X   %08X   %08X   %s",
                section.name.c_str(), section.virtualAddress,
                section.virtualSize, section.rawOffset, section.rawSize,
                flags.c_str()));
  }
}

}  // namespace magicmida
