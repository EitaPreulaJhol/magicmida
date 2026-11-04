// Magicmida - C++ port
// Post-processing of unpacked files (ported from Patcher.pas).
#include "patcher.h"

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
  ShrinkPE();
  ShrinkExportSect();

  pe_->SaveToStream(stream_);
  stream_.SaveToFile(fileName_);
}

void Patcher::ProcessMkData() {
#if defined(_WIN64)
  Log(ltInfo, "Data section creation is not available for 64-bit binaries.");
  return;
#else
  const std::string lower = AsciiLowerCase(WideToUtf8(fileName_));
  const size_t posMs = lower.rfind("maplestory");
  if (posMs != std::string::npos && posMs > 0 &&
      PosFrom(lower, ".exe", posMs) < posMs + 10 + 10) {
    MapleCreateDataSections();
  } else if (pe_->ntHeaders.OptionalHeader.MajorLinkerVersion == 14) {
    // MSVC 2015+
    MSVCCreateDataSections();
  } else {
    Log(ltInfo, "Data section creation not available for this compiler.");
    return;
  }

  pe_->SaveToStream(stream_);
  stream_.SaveToFile(fileName_);
#endif
}

void Patcher::ShrinkPE() {
  const auto isReferenced = [&](const IMAGE_SECTION_HEADER& header) {
    for (const IMAGE_DATA_DIRECTORY& directory :
         pe_->ntHeaders.OptionalHeader.DataDirectory) {
      if (directory.VirtualAddress >= header.VirtualAddress &&
          directory.VirtualAddress + directory.Size <=
              header.VirtualAddress + header.Misc.VirtualSize) {
        return true;
      }
    }
    return false;
  };

  std::vector<int> deleted;
  MemoryStream newStream;
  newStream.CopyFrom(stream_, pe_->Sections()[0].Header.PointerToRawData);

  const int lastIndex = static_cast<int>(pe_->Sections().size()) - 1;
  for (int i = 0; i <= lastIndex; ++i) {
    const IMAGE_SECTION_HEADER& header = pe_->Sections()[static_cast<size_t>(i)].Header;
    const std::string name = SectionName(header);
    if (!isReferenced(header) && name != ".data" && name != ".rdata" && i > 0) {
      deleted.push_back(i);
      if (i != lastIndex) {
        stream_.Seek(
            static_cast<int64_t>(pe_->Sections()[static_cast<size_t>(i + 1)]
                                     .Header.PointerToRawData) -
                header.PointerToRawData,
            Stream::Origin::Current);
      }
    } else {
      if (i != lastIndex) {
        newStream.CopyFrom(
            stream_,
            static_cast<int64_t>(
                pe_->Sections()[static_cast<size_t>(i + 1)]
                    .Header.PointerToRawData) -
                header.PointerToRawData);
      } else {
        newStream.CopyFrom(stream_, static_cast<int64_t>(pe_->SizeOfImage()) -
                                        header.PointerToRawData);
      }
    }
  }

  stream_ = std::move(newStream);

  std::reverse(deleted.begin(), deleted.end());
  for (int index : deleted) {
    pe_->DeleteSection(index);
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

  if (exportSection->Header.SizeOfRawData < 0x1000 ||
      directory->Size > exportSection->Header.SizeOfRawData) {
    Log(ltFatal, "Export section is too small, aborting shrink.");
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

void Patcher::MapleCreateDataSections() {
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

void Patcher::MSVCCreateDataSections() {
  const uint32_t baseOfData = pe_->ntHeaders.OptionalHeader.BaseOfData;
  if (baseOfData > pe_->Sections()[0].Header.VirtualAddress &&
      baseOfData < pe_->Sections()[0].Header.VirtualAddress +
                       pe_->Sections()[0].Header.Misc.VirtualSize &&
      (baseOfData & 0xFFF) == 0) {
    uintptr_t dynTls = 0;
    if (!FindDynTLSMSVC14(dynTls)) {
      return;
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
  } else {
    Log(ltInfo, "Assuming sections are not merged.");
  }

  // Rename first section and remove WRITE characteristic.
  pe_->Sections()[0].Rename(".text");
  pe_->Sections()[0].Header.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
}

#else

void Patcher::MapleCreateDataSections() {
  throw std::runtime_error(
      "Data section creation is not available for 64-bit binaries.");
}

uintptr_t Patcher::FindDataStartMSVC6() { return 0; }

bool Patcher::FindDynTLSMSVC14(uintptr_t& /*dynTlsInit*/) { return false; }

void Patcher::MSVCCreateDataSections() {
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
  const uintptr_t startAddress =
      pe_->ntHeaders.OptionalHeader.ImageBase +
      pe_->Sections()[0].Header.VirtualAddress;
  const uintptr_t endAddress = pe_->ntHeaders.OptionalHeader.ImageBase +
                               pe_->ntHeaders.OptionalHeader.BaseOfData;

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
