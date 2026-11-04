// Magicmida - C++ port
// Post-processing of unpacked files (ported from Patcher.pas).
#include "patcher.h"

#include <psapi.h>

#include <algorithm>
#include <cstring>

namespace magicmida {
namespace {

std::string SectionName(const IMAGE_SECTION_HEADER& header) {
  char name[9]{};
  std::memcpy(name, header.Name, 8);
  return std::string(name);
}

#if !defined(_WIN64)
// Returns a 1-based position like Delphi's Pos(), or 0 when not found.
size_t PosFrom(const std::string& haystack, const std::string& needle,
               size_t offset) {
  const size_t position = haystack.find(needle, offset);
  return position == std::string::npos ? 0 : position + 1;
}
#endif

}  // namespace

Patcher::Patcher(const std::wstring& fileName) : fileName_(fileName) {
  stream_.LoadFromFile(fileName);
  stream_.SetPosition(0);
  pe_ = std::make_unique<PEHeader>(stream_.Memory(),
                                   static_cast<size_t>(stream_.Size()));
}

void Patcher::ProcessShrink() {
  ReportStatus("Shrinking sections");
  ShrinkPE();
  ShrinkExportSect();

  pe_->SaveToStream(stream_);
  stream_.SaveToFile(fileName_);
}

bool Patcher::ProcessMkData() {
  ReportStatus("Creating data sections");
#if defined(_WIN64)
  Log(ltInfo, "Data section creation is not available for 64-bit binaries.");
  return false;
#else
  const std::string lower = AsciiLowerCase(WideToUtf8(fileName_));
  const size_t posMs = lower.rfind("maplestory");
  bool created = false;
  if (posMs != std::string::npos && posMs > 0 &&
      PosFrom(lower, ".exe", posMs) < posMs + 10 + 10) {
    created = MapleCreateDataSections();
  } else if (pe_->ntHeaders.OptionalHeader.MajorLinkerVersion == 14) {
    // MSVC 2015+
    created = MSVCCreateDataSections();
  } else {
    Log(ltInfo, "Data section creation not available for this compiler.");
    return false;
  }

  if (!created) {
    return false;
  }

  pe_->SaveToStream(stream_);
  stream_.SaveToFile(fileName_);
  return true;
#endif
}

void Patcher::ShrinkPE() {
  const uint32_t entryPoint =
      pe_->ntHeaders.OptionalHeader.AddressOfEntryPoint;

  const auto isReferenced = [&](const IMAGE_SECTION_HEADER& header) {
    const uint64_t sectionStart = header.VirtualAddress;
    const uint64_t sectionEnd =
        sectionStart + std::max<uint32_t>(
                          static_cast<uint32_t>(header.Misc.VirtualSize),
                          static_cast<uint32_t>(header.SizeOfRawData));
    for (size_t index = 0; index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
         ++index) {
      // The security directory holds a file offset, not an RVA.
      if (index == IMAGE_DIRECTORY_ENTRY_SECURITY) {
        continue;
      }
      const IMAGE_DATA_DIRECTORY& directory =
          pe_->ntHeaders.OptionalHeader.DataDirectory[index];
      if (directory.VirtualAddress == 0 || directory.Size == 0) {
        continue;
      }
      const uint64_t directoryStart = directory.VirtualAddress;
      const uint64_t directoryEnd =
          directoryStart + static_cast<uint64_t>(directory.Size);
      if (directoryStart < sectionEnd && directoryEnd > sectionStart) {
        return true;
      }
    }
    return false;
  };

  const auto containsEntryPoint = [&](const IMAGE_SECTION_HEADER& header) {
    if (entryPoint == 0) {
      return false;
    }
    const uint64_t sectionStart = header.VirtualAddress;
    const uint64_t sectionEnd =
        sectionStart + std::max<uint32_t>(
                          static_cast<uint32_t>(header.Misc.VirtualSize),
                          static_cast<uint32_t>(header.SizeOfRawData));
    return entryPoint >= sectionStart && entryPoint < sectionEnd;
  };

  std::vector<int> deleted;
  bool removedExecutable = false;
  MemoryStream newStream;
  newStream.CopyFrom(stream_, pe_->Sections()[0].Header.PointerToRawData);

  const int lastIndex = static_cast<int>(pe_->Sections().size()) - 1;

  // Sections without raw data (.bss in regular PEs) must not be used as a
  // file-layout boundary; their raw pointer is usually zero.
  const auto nextRawStart = [&](int index) -> int64_t {
    for (int j = index + 1; j <= lastIndex; ++j) {
      const IMAGE_SECTION_HEADER& next =
          pe_->Sections()[static_cast<size_t>(j)].Header;
      if (next.SizeOfRawData != 0) {
        return static_cast<int64_t>(next.PointerToRawData);
      }
    }
    return stream_.Size();
  };

  for (int i = 0; i <= lastIndex; ++i) {
    const IMAGE_SECTION_HEADER& header = pe_->Sections()[static_cast<size_t>(i)].Header;
    const std::string name = SectionName(header);

    // Keep anything referenced by a data directory, the entry point, and the
    // runtime data that is not covered by a data directory (.CRT, .tls, .bss,
    // .xdata/.pdata, CFG tables). Only code/discardable leftovers should be
    // removed: Themida often renames the app's data sections to spaces, so a
    // name-only rule would delete .rdata/.data/.pdata and break the image.
    const bool protectedByName =
        name == ".data" || name == ".rdata" || name == ".xdata" ||
        name == ".CRT" || name == ".tls" || name == ".bss" ||
        name == ".gfids" || name == ".00cfg" || name == ".gehcont" ||
        // MapleCreateDataSections names the guard table .vmp for old MSVC.
        name == ".vmp";
    // Custom-named uninitialized-data sections still hold runtime state.
    const bool protectedByFlags =
        (header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
    const bool noRawData = header.SizeOfRawData == 0;
    const bool executable =
        (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool discardable =
        (header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
    const bool removable = executable || discardable;
    const bool keep = !removable || i == 0 || isReferenced(header) ||
                      containsEntryPoint(header) || protectedByName ||
                      protectedByFlags || noRawData;

    if (!keep) {
      LogF(executable ? ltWarning : ltInfo,
           "Removing section [%s] (VA %X, size %X, flags %08X)", name.c_str(),
           header.VirtualAddress, header.Misc.VirtualSize,
           header.Characteristics);
      if (executable) {
        removedExecutable = true;
      }
      deleted.push_back(i);
    } else {
      if (containsEntryPoint(header) && !isReferenced(header) &&
          !protectedByName && i != 0) {
        LogF(ltInfo, "Keeping section [%s]: it contains the entry point.",
             name.c_str());
      }
      if (noRawData) {
        continue;
      }

      const int64_t start = static_cast<int64_t>(header.PointerToRawData);
      int64_t end = nextRawStart(i);
      if (end > stream_.Size()) {
        end = stream_.Size();
      }
      if (start < 0 || start >= stream_.Size() || end <= start) {
        continue;
      }
      stream_.Seek(start, Stream::Origin::Begin);
      newStream.CopyFrom(stream_, end - start);
    }
  }

  stream_ = std::move(newStream);

  std::reverse(deleted.begin(), deleted.end());
  for (int index : deleted) {
    pe_->DeleteSection(index);
  }

  if (removedExecutable) {
    Log(ltWarning,
        "Shrink removed executable section(s). If the target no longer "
        "starts, restore the .bak and unvirtualize the target before "
        "shrinking.");
  }
}

void Patcher::ShrinkExportSect() {
  IMAGE_DATA_DIRECTORY* directory =
      &pe_->ntHeaders.OptionalHeader
           .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (directory->VirtualAddress == 0 || directory->Size == 0) {
    return;
  }

  PESection* exportSection = pe_->GetSectionByVA(directory->VirtualAddress);
  if (exportSection == nullptr) {
    return;
  }

  // Only compact a dedicated .edata section whose first byte is the export
  // directory. If the directory lives in .rdata (common for MinGW or merged
  // layouts), moving it would overwrite unrelated data.
  const std::string exportSectionName = SectionName(exportSection->Header);
  if (exportSectionName != ".edata" ||
      directory->VirtualAddress != exportSection->Header.VirtualAddress) {
    Log(ltWarning,
        "Skipping export section compaction: the export directory is not at "
        "the start of a dedicated .edata section.");
    return;
  }

  if (exportSection->Header.SizeOfRawData < 0x1000 ||
      directory->Size > exportSection->Header.SizeOfRawData) {
    Log(ltWarning, "Skipping export section compaction: section is too small.");
    return;
  }

  // The compaction below truncates the section to 0x1000 bytes, so it can
  // only be used when the whole export data fits in that window.
  if (directory->Size > 0x1000) {
    Log(ltWarning,
        "Skipping export section compaction: export data is larger than "
        "0x1000 bytes.");
    return;
  }

  uint8_t* const base = stream_.Memory() + exportSection->Header.PointerToRawData;
  uint8_t* const exportData =
      base + (directory->VirtualAddress - exportSection->Header.VirtualAddress);

  std::memmove(base, exportData, directory->Size);
  if (directory->Size < 0x1000) {
    std::memset(base + directory->Size, 0, 0x1000 - directory->Size);
  }
  directory->VirtualAddress = exportSection->Header.VirtualAddress;

  uint32_t difference = static_cast<uint32_t>(exportData - base);
  auto* exportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base);
  exportDirectory->Name -= difference;
  exportDirectory->AddressOfFunctions -= difference;
  exportDirectory->AddressOfNames -= difference;
  exportDirectory->AddressOfNameOrdinals -= difference;

  auto* names = reinterpret_cast<uint32_t*>(
      base + (exportDirectory->AddressOfNames -
              exportSection->Header.VirtualAddress));
  for (uint32_t i = 0; i < exportDirectory->NumberOfNames; ++i) {
    names[i] -= difference;
  }

  difference = exportSection->Header.SizeOfRawData - 0x1000;
  exportSection->Header.SizeOfRawData -= difference;
  for (PESection& section : pe_->Sections()) {
    if (section.Header.VirtualAddress >
        exportSection->Header.VirtualAddress) {
      section.Header.PointerToRawData -= difference;
    }
  }

  exportSection->Rename(".export");
  exportSection->Header.Characteristics &=
      ~(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);

  stream_.SetPosition(0);
  MemoryStream newStream;
  newStream.CopyFrom(stream_,
                     exportSection->Header.PointerToRawData + 0x1000);
  stream_.Seek(difference, Stream::Origin::Current);
  newStream.CopyFrom(stream_, stream_.Size() - stream_.Position());
  stream_ = std::move(newStream);
}

#if !defined(_WIN64)

bool Patcher::MapleCreateDataSections() {
  if (pe_->Sections().size() < 2) {
    Log(ltFatal, "Data section creation requires at least two sections.");
    return false;
  }

  uint8_t* const memory = stream_.Memory();
  const int64_t streamSize = stream_.Size();

  uintptr_t dataStart = 0;
  if (streamSize > 0x2000000) {
    dataStart = FindStatic("10000000200000004000000060000000",
                           memory + 0x2000000,
                           static_cast<size_t>(streamSize - 0x2000000));
  }

  if (dataStart == 0) {
    if (pe_->ntHeaders.OptionalHeader.MajorLinkerVersion == 6) {
      dataStart = FindDataStartMSVC6();
      if (dataStart == 0) {
        throw std::runtime_error("Data section not found");
      }
    } else {
      constexpr uintptr_t kOldOffset = 0xB00000 - 0x400000;
      if (streamSize <= static_cast<int64_t>(kOldOffset)) {
        throw std::runtime_error("Data section not found");
      }
      dataStart = FindStatic(
          "2E3F41565F636F6D5F6572726F724040", memory + kOldOffset,
          static_cast<size_t>(streamSize - static_cast<int64_t>(kOldOffset)));
      uintptr_t dataStartTw = FindStatic(
          "2E3F41563F245A4C69737440554D4150494E464F4043416374696F6E4672616D6540"
          "404040",
          memory + kOldOffset,
          static_cast<size_t>(streamSize - static_cast<int64_t>(kOldOffset)));  // TW 122+
      if (dataStartTw != 0 && dataStartTw < dataStart) {
        dataStart = dataStartTw;
      }

      if (dataStart == 0) {
        throw std::runtime_error("Data section not found");
      }

      dataStart += kOldOffset - 8;
      if ((dataStart & 0xFFF) == 0xB4 || (dataStart & 0xFFF) == 0xF8 ||
          (dataStart & 0xFFF) == 0xFC) {
        dataStart &= 0xFFFFF000;
      }
      Log(ltInfo, "Old executable");
    }
  } else {
    dataStart += 0x2000000;
  }

  if ((dataStart & 0xFFF) != 0) {
    throw std::runtime_error(
        Format("Data section bytes found, but not aligned: %llX",
               static_cast<unsigned long long>(dataStart)));
  }

  LogF(ltGood, ".data section at %08llX (VA %08llX)",
       static_cast<unsigned long long>(dataStart),
       static_cast<unsigned long long>(dataStart + 0x400000));

  pe_->AddSectionToArray();
  pe_->AddSectionToArray();
  {
    auto& sections = pe_->Sections();
    for (int i = static_cast<int>(sections.size()) - 1; i >= 3; --i) {
      sections[static_cast<size_t>(i)] = sections[static_cast<size_t>(i - 2)];
    }
  }

  uintptr_t zeroEnd = 0;
  uint32_t zeroSize = 0;
  bool locked = false;
  uintptr_t address = pe_->Sections()[3].Header.PointerToRawData - 1;

  for (;;) {
    if (address < dataStart) {
      address = dataStart - 1;
      break;
    }

    if (memory[address] == 0) {
      if (zeroSize == 0) {
        zeroEnd = address + 1;
      }
      ++zeroSize;
      if (zeroSize > 0x2000) {
        locked = true;
      }
    } else {
      if (locked) {
        break;
      }
      zeroSize = 0;
    }

    if (address == dataStart) {
      address = dataStart - 1;
      break;
    }
    --address;
  }
  ++address;

  if (zeroSize == 0) {
    throw std::runtime_error("Data section doesn't contain zeroes");
  }

  // Sometimes first byte of following section is 0.
  if ((zeroEnd & 0xFFF) == 1) {
    --zeroEnd;
    --zeroSize;
  }

  if ((zeroEnd & 0xFFF) != 0) {
    throw std::runtime_error(
        Format("Real .data section end not found (got %llX with a size of %X)",
               static_cast<unsigned long long>(zeroEnd), zeroSize));
  }

  const uintptr_t zeroStart = (address + 0x1000) & 0xFFFFF000;
  zeroSize -= static_cast<uint32_t>(zeroStart - address);

  const uintptr_t gfidsSize =
      pe_->Sections()[3].Header.PointerToRawData - zeroEnd;

  // .data
  uintptr_t dataSize =
      pe_->Sections()[3].Header.PointerToRawData - dataStart - gfidsSize;
  PESection& dataSection = pe_->Sections()[2];
  dataSection = PESection{};
  dataSection.Rename(".data");
  dataSection.Header.Misc.VirtualSize = static_cast<uint32_t>(dataSize);
  dataSection.Header.VirtualAddress = static_cast<uint32_t>(dataStart);
  dataSection.Header.PointerToRawData = static_cast<uint32_t>(dataStart);
  dataSection.Header.SizeOfRawData = static_cast<uint32_t>(dataSize - zeroSize);
  dataSection.Header.Characteristics = IMAGE_SCN_MEM_READ |
                                       IMAGE_SCN_MEM_WRITE |
                                       IMAGE_SCN_CNT_INITIALIZED_DATA;

  // .rdata
  const uintptr_t rdataStart = pe_->ntHeaders.OptionalHeader.BaseOfData;
  const uintptr_t rdataSize = dataStart - rdataStart;
  PESection& rdataSection = pe_->Sections()[1];
  rdataSection = PESection{};
  rdataSection.Rename(".rdata");
  rdataSection.Header.Misc.VirtualSize = static_cast<uint32_t>(rdataSize);
  rdataSection.Header.VirtualAddress = static_cast<uint32_t>(rdataStart);
  rdataSection.Header.PointerToRawData = static_cast<uint32_t>(rdataStart);
  rdataSection.Header.SizeOfRawData = static_cast<uint32_t>(rdataSize);
  rdataSection.Header.Characteristics =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

  // .gfids/.vmp
  if (gfidsSize != 0) {
    pe_->AddSectionToArray();
    {
      auto& sections = pe_->Sections();
      for (int i = static_cast<int>(sections.size()) - 1; i >= 4; --i) {
        sections[static_cast<size_t>(i)] = sections[static_cast<size_t>(i - 1)];
      }
    }

    const bool msvc2015 =
        pe_->ntHeaders.OptionalHeader.MajorLinkerVersion >= 14;
    PESection& gfidsSection = pe_->Sections()[3];
    gfidsSection = PESection{};
    gfidsSection.Rename(msvc2015 ? ".gfids" : ".vmp");
    gfidsSection.Header.Misc.VirtualSize = static_cast<uint32_t>(gfidsSize);
    gfidsSection.Header.VirtualAddress = static_cast<uint32_t>(zeroEnd);
    gfidsSection.Header.PointerToRawData = static_cast<uint32_t>(zeroEnd);
    gfidsSection.Header.SizeOfRawData = static_cast<uint32_t>(gfidsSize);
    gfidsSection.Header.Characteristics = IMAGE_SCN_MEM_READ |
                                          IMAGE_SCN_MEM_WRITE |
                                          IMAGE_SCN_CNT_INITIALIZED_DATA;

    pe_->ntHeaders.FileHeader.NumberOfSections += 3;
  } else {
    if (pe_->ntHeaders.OptionalHeader.MajorLinkerVersion >= 14) {
      Log(ltFatal, ".gfids not found");
    }
    pe_->ntHeaders.FileHeader.NumberOfSections += 2;
  }

  pe_->Sections()[0].Header.Misc.VirtualSize -=
      static_cast<uint32_t>(rdataSize + dataSize + gfidsSize);
  pe_->Sections()[0].Header.SizeOfRawData -=
      static_cast<uint32_t>(rdataSize + dataSize + gfidsSize);

  pe_->Sections()[0].Rename(".text");
  pe_->Sections()[0].Header.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
  return true;
}

uintptr_t Patcher::FindDataStartMSVC6() {
  // In MSVC6 binaries, the second (r/w) data section appears to start with the
  // __cinit func list.
  const int64_t streamSize = stream_.Size();
  if (streamSize <= 0x100000) {
    return 0;
  }

  uint8_t* const memory = stream_.Memory();
  uint32_t cInitCode =
      FindDynamic("68????????68??????00E8????????83C410C3", memory + 0x100000,
                  static_cast<size_t>(streamSize - 0x100000));
  if (cInitCode == 0) {
    return 0;
  }

  cInitCode += 0x100000;
  uintptr_t result = *reinterpret_cast<const uint32_t*>(
      memory + cInitCode + 6);
  if ((result & 0xFFF) != 0) {
    result = 0;
  } else {
    result -= pe_->ntHeaders.OptionalHeader.ImageBase;
  }
  return result;
}

bool Patcher::FindDynTLSMSVC14(uintptr_t& dynTlsInit) {
  // call    __scrt_get_dyn_tls_init_callback
  // mov     esi, eax
  // xor     edi, edi
  // cmp     [esi], edi
  // jz      short ??
  // push    esi
  // call    __scrt_is_nonwritable_in_current_image
  const int64_t streamSize = stream_.Size();
  if (streamSize <= 0x1000) {
    return false;
  }

  uint8_t* const memory = stream_.Memory();
  uint32_t dynTlsCode =
      FindDynamic("8BF033FF393E74??56E8", memory + 0x1000,
                  static_cast<size_t>(streamSize - 0x1000));
  if (dynTlsCode == 0) {
    Log(ltInfo, "DynTLS code sequence not found.");
    return false;
  }

  uint8_t* codePtr = memory + 0x1000 + dynTlsCode;
  if (*(codePtr - 5) != 0xE8) {
    Log(ltInfo, "DynTLS code sequence mismatch.");
    return false;
  }

  uint8_t* getPtrFunc =
      codePtr + *reinterpret_cast<const int32_t*>(codePtr - 4);
  if (*getPtrFunc == 0xE9) {  // another indirection via jmp
    getPtrFunc = getPtrFunc +
                 *reinterpret_cast<const int32_t*>(getPtrFunc + 1) + 5;
  }
  if (*getPtrFunc != 0xB8) {
    Log(ltInfo, "DynTLS call analysis failed.");
    return false;
  }

  dynTlsInit = *reinterpret_cast<const uint32_t*>(getPtrFunc + 1) -
               pe_->ntHeaders.OptionalHeader.ImageBase;
  uint8_t* dynTlsInitPtr = memory + dynTlsInit;

  LogF(ltInfo, "[MSVC] dyn_tls_init at %.8X",
       *reinterpret_cast<const uint32_t*>(dynTlsInitPtr));

  // If the function pointer points to 0, the compiler places this var in a
  // writable section and we can't use it as a separator.
  if (*reinterpret_cast<const uint32_t*>(dynTlsInitPtr) == 0) {
    dynTlsInit = 0;
  }

  return true;
}

bool Patcher::MSVCCreateDataSections() {
  if (pe_->Sections().size() < 2) {
    Log(ltFatal, "Data section creation requires at least two sections.");
    return false;
  }

  const uint32_t baseOfData = pe_->ntHeaders.OptionalHeader.BaseOfData;
  if (!(baseOfData > pe_->Sections()[0].Header.VirtualAddress &&
        baseOfData < pe_->Sections()[0].Header.VirtualAddress +
                         pe_->Sections()[0].Header.Misc.VirtualSize &&
        (baseOfData & 0xFFF) == 0)) {
    Log(ltInfo, "Assuming sections are not merged.");
    return false;
  }

  {
    uintptr_t dynTls = 0;
    if (!FindDynTLSMSVC14(dynTls)) {
      return false;
    }

    // This is by no means exact. We keep the writable data section as large
    // as possible because we can't determine its real size in a generic way
    // and we don't want to risk access violations.
    uint32_t dataStart = 0;
    if (dynTls != 0) {
      dataStart = static_cast<uint32_t>((dynTls + 0x1000) & ~0xFFFull);
    } else {
      dataStart = baseOfData + 0x1000;
      Log(ltInfo,
          "Setting .rdata size to just 1000 (no reference point for actual "
          "size)");
    }

    pe_->AddSectionToArray();
    pe_->AddSectionToArray();
    {
      auto& sections = pe_->Sections();
      for (int i = static_cast<int>(sections.size()) - 1; i >= 3; --i) {
        sections[static_cast<size_t>(i)] = sections[static_cast<size_t>(i - 2)];
      }
    }

    pe_->ntHeaders.FileHeader.NumberOfSections += 2;

    // .data at [2]
    const uint32_t dataSize =
        pe_->Sections()[3].Header.PointerToRawData - dataStart;
    PESection& dataSection = pe_->Sections()[2];
    dataSection = PESection{};
    dataSection.Rename(".data");
    dataSection.Header.Misc.VirtualSize = dataSize;
    dataSection.Header.VirtualAddress = dataStart;
    dataSection.Header.PointerToRawData = dataStart;
    dataSection.Header.SizeOfRawData = dataSize;
    dataSection.Header.Characteristics = IMAGE_SCN_MEM_READ |
                                         IMAGE_SCN_MEM_WRITE |
                                         IMAGE_SCN_CNT_INITIALIZED_DATA;

    // .rdata at [1]
    const uint32_t rdataStart = baseOfData;
    const uint32_t rdataSize = dataStart - rdataStart;
    PESection& rdataSection = pe_->Sections()[1];
    rdataSection = PESection{};
    rdataSection.Rename(".rdata");
    rdataSection.Header.Misc.VirtualSize = rdataSize;
    rdataSection.Header.VirtualAddress = rdataStart;
    rdataSection.Header.PointerToRawData = rdataStart;
    rdataSection.Header.SizeOfRawData = rdataSize;
    rdataSection.Header.Characteristics =
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    pe_->Sections()[0].Header.Misc.VirtualSize -= rdataSize + dataSize;
    pe_->Sections()[0].Header.SizeOfRawData -= rdataSize + dataSize;

    for (int i = 0; i < 3; ++i) {
      const IMAGE_SECTION_HEADER& header = pe_->Sections()[static_cast<size_t>(i)].Header;
      LogF(ltInfo, "%s: %.8x ~ %.8x", SectionName(header).c_str(),
           header.VirtualAddress,
           header.VirtualAddress + header.Misc.VirtualSize);
    }
  }

  // Rename first section and remove WRITE characteristic.
  pe_->Sections()[0].Rename(".text");
  pe_->Sections()[0].Header.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
  return true;
}

#else

bool Patcher::MapleCreateDataSections() {
  throw std::runtime_error(
      "Data section creation is not available for 64-bit binaries.");
}

uintptr_t Patcher::FindDataStartMSVC6() { return 0; }

bool Patcher::FindDynTLSMSVC14(uintptr_t& /*dynTlsInit*/) { return false; }

bool Patcher::MSVCCreateDataSections() {
  throw std::runtime_error(
      "Data section creation is not available for 64-bit binaries.");
}

#endif

void Patcher::DumpProcessCode(HANDLE process) {
#if defined(_WIN64)
  (void)process;
  throw std::runtime_error(
      "Dumping process code is not available for 64-bit binaries.");
#else
  uintptr_t imageBase =
      static_cast<uintptr_t>(pe_->ntHeaders.OptionalHeader.ImageBase);

  // The file's ImageBase is only a hint: the live process may have been
  // relocated (ASLR or an occupied base). Find the module by name and use its
  // real base instead.
  const std::wstring moduleFileName = ExtractFileName(fileName_);
  const std::string targetName =
      AsciiLowerCase(WideToUtf8(moduleFileName));
  bool moduleFound = false;

  HMODULE modules[1024]{};
  DWORD needed = 0;
  if (EnumProcessModules(process, modules, sizeof(modules), &needed)) {
    const size_t count =
        std::min<size_t>(needed / sizeof(HMODULE), _countof(modules));
    for (size_t i = 0; i < count; ++i) {
      wchar_t moduleName[MAX_PATH]{};
      if (GetModuleBaseNameW(process, modules[i], moduleName,
                             _countof(moduleName)) == 0) {
        continue;
      }
      if (AsciiLowerCase(WideToUtf8(moduleName)) == targetName) {
        imageBase = reinterpret_cast<uintptr_t>(modules[i]);
        moduleFound = true;
        break;
      }
    }
  }

  if (moduleFound) {
    LogF(ltInfo, "Using live module base %llX for %s",
         static_cast<unsigned long long>(imageBase),
         WideToUtf8(moduleFileName).c_str());
  } else {
    LogF(ltWarning,
         "Module %s not found in the process; using the header ImageBase "
         "%llX",
         WideToUtf8(moduleFileName).c_str(),
         static_cast<unsigned long long>(imageBase));
  }

  const uintptr_t startAddress =
      imageBase + pe_->Sections()[0].Header.VirtualAddress;
  const uintptr_t endAddress =
      imageBase + pe_->ntHeaders.OptionalHeader.BaseOfData;
  if (endAddress <= startAddress) {
    throw std::runtime_error("Invalid code range in the PE header.");
  }

  std::vector<uint8_t> buffer(static_cast<size_t>(endAddress - startAddress));
  SIZE_T bytesRead = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<void*>(startAddress),
                         buffer.data(), buffer.size(), &bytesRead) ||
      bytesRead != buffer.size()) {
    throw std::runtime_error(
        Format("ReadProcessMemory failed (error %lu)", GetLastError()));
  }

  stream_.Seek(pe_->Sections()[0].Header.PointerToRawData,
               Stream::Origin::Begin);
  stream_.Write(buffer.data(), buffer.size());
  stream_.SaveToFile(ChangeFileExt(fileName_, L".novm.exe"));

  LogF(ltGood, "Dumped %llX bytes.",
       static_cast<unsigned long long>(buffer.size()));
#endif
}

}  // namespace magicmida
