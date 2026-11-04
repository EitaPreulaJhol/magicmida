// Magicmida - C++ port
// Post-processing of unpacked files (ported from Patcher.pas).
#include "patcher.h"
#include "vm_entry.h"

#include <psapi.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

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
  RelocateExceptionTable();
  ShrinkPE();
  ShrinkExportSect();

  pe_->SaveToStream(stream_);
  stream_.SaveToFile(fileName_);
}

// Converts the flat dump layout (file offset == RVA, raw size == virtual
// size) into the layout a normal linker emits: a compact header area followed
// by file-aligned section data. RVAs and the in-memory image are unchanged.
void Patcher::NormalizeLayout() {
  ReportStatus("Normalizing the PE layout");

  const auto& sections = pe_->Sections();
  if (sections.empty()) {
    throw std::runtime_error("NormalizeLayout: the PE has no sections");
  }

  const uint32_t fileAlignment = pe_->ntHeaders.OptionalHeader.FileAlignment;
  if (fileAlignment < 0x200 || fileAlignment > 0x10000 ||
      (fileAlignment & (fileAlignment - 1)) != 0) {
    LogF(ltWarning,
         "Skipping PE layout normalization: invalid FileAlignment %X.",
         fileAlignment);
    return;
  }

  const int64_t oldFileSize64 = stream_.Size();
  if (oldFileSize64 < 0) {
    throw std::runtime_error("NormalizeLayout: invalid file size");
  }
  const uint64_t oldFileSize = static_cast<uint64_t>(oldFileSize64);

  const uint64_t headerEnd =
      static_cast<uint64_t>(pe_->LFANew()) + sizeof(IMAGE_NT_HEADERS) +
      static_cast<uint64_t>(sections.size()) * sizeof(IMAGE_SECTION_HEADER);
  // PEHeader::SaveToStream zeroes 0x200 bytes after the section table; keep
  // that area inside SizeOfHeaders so it never overwrites section data.
  uint64_t newHeaders64 = headerEnd + 0x200;
  if (newHeaders64 > 0xFFFFFFFFull) {
    throw std::runtime_error("NormalizeLayout: header is too large");
  }
  uint32_t newHeaders = static_cast<uint32_t>(newHeaders64);
  pe_->FileAlign(newHeaders);

  struct SectionLayout {
    uint32_t oldRaw = 0;
    uint32_t oldSize = 0;
    uint32_t newRaw = 0;
    uint32_t newSize = 0;
    uint32_t copySize = 0;
  };
  std::vector<SectionLayout> layouts;
  layouts.reserve(sections.size());

  uint64_t oldSectionEnd = 0;
  uint64_t cursor = newHeaders;

  for (PESection& section : pe_->Sections()) {
    const IMAGE_SECTION_HEADER header = section.Header;
    SectionLayout layout;
    layout.oldRaw = header.PointerToRawData;
    layout.oldSize = header.SizeOfRawData;

    if (header.SizeOfRawData != 0) {
      const uint64_t end = static_cast<uint64_t>(header.PointerToRawData) +
                           header.SizeOfRawData;
      if (end > oldFileSize) {
        throw std::runtime_error(
            "NormalizeLayout: section raw data extends past the file");
      }
      oldSectionEnd = std::max(oldSectionEnd, end);
    }

    if (header.SizeOfRawData != 0) {
      // Preserve every raw byte (including debug data living in alignment
      // padding). When the virtual size is larger, the tail stays zeroed.
      layout.copySize = header.SizeOfRawData;
      layout.newSize = std::max<uint32_t>(header.Misc.VirtualSize,
                                          header.SizeOfRawData);
      pe_->FileAlign(layout.newSize);
      if (layout.newSize == 0) {
        layout.newSize = fileAlignment;
      }
    }

    if (layout.newSize != 0) {
      if (cursor > 0xFFFFFFFFull) {
        throw std::runtime_error("NormalizeLayout: section offset overflow");
      }
      layout.newRaw = static_cast<uint32_t>(cursor);
      if (layout.copySize > 0) {
        const uint64_t sourceEnd =
            static_cast<uint64_t>(layout.oldRaw) + layout.copySize;
        if (sourceEnd > oldFileSize) {
          throw std::runtime_error(
              "NormalizeLayout: section data is truncated");
        }
      }
      cursor += layout.newSize;
    }

    layouts.push_back(layout);
    section.Header.PointerToRawData = layout.newRaw;
    section.Header.SizeOfRawData = layout.newSize;
  }

  const auto mapFileOffset = [&layouts](uint32_t oldOffset) -> uint32_t {
    if (oldOffset == 0) {
      return 0;
    }
    for (const SectionLayout& layout : layouts) {
      if (layout.oldSize != 0 && oldOffset >= layout.oldRaw &&
          oldOffset < layout.oldRaw + layout.oldSize) {
        return layout.newRaw + (oldOffset - layout.oldRaw);
      }
    }
    return 0;
  };

  // File-offset fields in the headers/section table still point at the old
  // layout. Map them into the new one; data outside sections is dropped.
  pe_->ntHeaders.FileHeader.PointerToSymbolTable =
      mapFileOffset(pe_->ntHeaders.FileHeader.PointerToSymbolTable);
  for (PESection& section : pe_->Sections()) {
    if (section.Header.PointerToRelocations != 0) {
      section.Header.PointerToRelocations =
          mapFileOffset(section.Header.PointerToRelocations);
    }
    if (section.Header.PointerToLinenumbers != 0) {
      section.Header.PointerToLinenumbers =
          mapFileOffset(section.Header.PointerToLinenumbers);
    }
  }

  if (cursor > 0xFFFFFFFFull) {
    throw std::runtime_error("NormalizeLayout: file is too large");
  }

  // The certificate table is the only trailing data with a well-defined file
  // offset. Preserve it and move its directory entry; the flat dump padding
  // (and protector bytes left behind by Shrink) is dropped.
  const IMAGE_DATA_DIRECTORY oldSecurity =
      pe_->ntHeaders.OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  uint64_t overlaySize = 0;
  uint64_t oldOverlayStart = 0;
  if (oldSecurity.VirtualAddress != 0 && oldSecurity.Size != 0) {
    const uint64_t start = oldSecurity.VirtualAddress;
    const uint64_t end = start + oldSecurity.Size;
    if (start >= oldSectionEnd && end <= oldFileSize && end > start) {
      oldOverlayStart = start;
      overlaySize = end - start;
    } else {
      Log(ltWarning,
          "Dropping an invalid certificate table while normalizing the PE.");
    }
  }

  if (oldFileSize > oldSectionEnd && overlaySize == 0) {
    LogF(ltInfo, "Dropping %llu trailing bytes of non-certificate data.",
         static_cast<unsigned long long>(oldFileSize - oldSectionEnd));
  }

  const uint64_t newOverlayStart = cursor;
  uint64_t newFileSize = cursor + overlaySize;
  if (newFileSize > 0xFFFFFFFFull) {
    throw std::runtime_error("NormalizeLayout: file is too large");
  }

  IMAGE_DATA_DIRECTORY& security =
      pe_->ntHeaders.OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  if (overlaySize != 0) {
    security.VirtualAddress = static_cast<uint32_t>(newOverlayStart);
    // security.Size stays unchanged.
  } else if (security.VirtualAddress != 0 || security.Size != 0) {
    security.VirtualAddress = 0;
    security.Size = 0;
  }

  pe_->ntHeaders.OptionalHeader.SizeOfHeaders = newHeaders;
  // The file changed, so the old header checksum is meaningless.
  pe_->ntHeaders.OptionalHeader.CheckSum = 0;

  MemoryStream normalized;
  normalized.SetSize(static_cast<int64_t>(newFileSize));
  const uint32_t dosStubSize = pe_->LFANew();
  if (dosStubSize > oldFileSize) {
    throw std::runtime_error("NormalizeLayout: truncated DOS header");
  }
  if (dosStubSize != 0) {
    std::memcpy(normalized.Memory(), stream_.Memory(), dosStubSize);
  }
  pe_->SaveToStream(normalized);

  for (const SectionLayout& layout : layouts) {
    if (layout.copySize == 0) {
      continue;
    }
    std::memcpy(normalized.Memory() + layout.newRaw,
                stream_.Memory() + layout.oldRaw, layout.copySize);
  }

  // IMAGE_DEBUG_DIRECTORY entries hold file offsets (hint: the CodeView
  // record), so they must follow the section data they describe.
  const IMAGE_DATA_DIRECTORY debugDirectory =
      pe_->ntHeaders.OptionalHeader
          .DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  if (debugDirectory.VirtualAddress != 0 &&
      debugDirectory.Size >= sizeof(IMAGE_DEBUG_DIRECTORY)) {
    const PESection* debugSection =
        pe_->GetSectionByVA(debugDirectory.VirtualAddress);
    if (debugSection != nullptr) {
      const uint64_t sectionStart = debugSection->Header.VirtualAddress;
      const uint64_t sectionEnd =
          sectionStart + std::max<uint32_t>(
                             debugSection->Header.Misc.VirtualSize,
                             debugSection->Header.SizeOfRawData);
      const size_t debugIndex = static_cast<size_t>(
          debugSection - pe_->Sections().data());
      const uint64_t newDebugOffset = layouts[debugIndex].newRaw +
                                      (debugDirectory.VirtualAddress -
                                       sectionStart);
      if (debugDirectory.VirtualAddress >= sectionStart &&
          static_cast<uint64_t>(debugDirectory.VirtualAddress) < sectionEnd &&
          layouts[debugIndex].newSize != 0 &&
          newDebugOffset + debugDirectory.Size <= newFileSize) {
        for (uint32_t offset = 0;
             offset + sizeof(IMAGE_DEBUG_DIRECTORY) <= debugDirectory.Size;
             offset += sizeof(IMAGE_DEBUG_DIRECTORY)) {
          auto* entry = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
              normalized.Memory() + newDebugOffset + offset);
          if (entry->PointerToRawData != 0) {
            entry->PointerToRawData =
                mapFileOffset(entry->PointerToRawData);
          }
        }
      }
    }
  }

  if (overlaySize != 0) {
    std::memcpy(normalized.Memory() + newOverlayStart,
                stream_.Memory() + oldOverlayStart,
                static_cast<size_t>(overlaySize));
  }

  normalized.SaveToFile(fileName_);
  stream_ = std::move(normalized);

  LogF(ltInfo,
       "Normalized PE layout: SizeOfHeaders %X, file size %llX -> %llX.",
       newHeaders, static_cast<unsigned long long>(oldFileSize),
       static_cast<unsigned long long>(newFileSize));
}

void Patcher::FlattenLayout() {
  const auto& sections = pe_->Sections();
  if (sections.empty()) {
    return;
  }

  bool flat = true;
  for (const PESection& section : sections) {
    if (section.Header.SizeOfRawData != 0 &&
        section.Header.PointerToRawData != section.Header.VirtualAddress) {
      flat = false;
      break;
    }
  }
  if (flat) {
    return;
  }

  const uint64_t oldFileSize = static_cast<uint64_t>(stream_.Size());
  uint64_t fileSize = pe_->SizeOfImage();
  for (const PESection& section : sections) {
    fileSize = std::max<uint64_t>(
        fileSize, static_cast<uint64_t>(section.Header.VirtualAddress) +
                      std::max<uint32_t>(section.Header.Misc.VirtualSize,
                                         section.Header.SizeOfRawData));
  }
  if (fileSize > 0xFFFFFFFFull) {
    throw std::runtime_error("FlattenLayout: file is too large");
  }

  MemoryStream flatStream;
  flatStream.SetSize(static_cast<int64_t>(fileSize));
  const uint32_t firstVA = sections[0].Header.VirtualAddress;
  const uint64_t oldSizeOfHeaders =
      pe_->ntHeaders.OptionalHeader.SizeOfHeaders;
  // Do not copy section bytes that happen to sit between SizeOfHeaders and
  // the first section RVA in a normalized layout.
  const uint64_t headerCopy =
      std::min<uint64_t>(oldFileSize,
                         std::min<uint64_t>(firstVA, oldSizeOfHeaders));
  if (headerCopy != 0) {
    std::memcpy(flatStream.Memory(), stream_.Memory(),
                static_cast<size_t>(headerCopy));
  }

  for (PESection& section : pe_->Sections()) {
    const uint32_t oldRaw = section.Header.PointerToRawData;
    const uint32_t oldSize = section.Header.SizeOfRawData;
    const uint32_t copySize =
        std::min<uint32_t>(section.Header.Misc.VirtualSize, oldSize);
    if (copySize != 0) {
      if (static_cast<uint64_t>(oldRaw) + copySize > oldFileSize) {
        throw std::runtime_error("FlattenLayout: section data is truncated");
      }
      std::memcpy(flatStream.Memory() + section.Header.VirtualAddress,
                  stream_.Memory() + oldRaw, copySize);
    }
    section.Header.PointerToRawData = section.Header.VirtualAddress;
    section.Header.SizeOfRawData = section.Header.Misc.VirtualSize;
  }

  pe_->ntHeaders.OptionalHeader.SizeOfHeaders = firstVA;
  pe_->SaveToStream(flatStream);
  stream_ = std::move(flatStream);
  Log(ltInfo, "Flattened PE layout for data-section creation.");
}

bool Patcher::ProcessMkData() {
  ReportStatus("Creating data sections");
#if defined(_WIN64)
  Log(ltInfo, "Data section creation is not available for 64-bit binaries.");
  return false;
#else
  FlattenLayout();
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

// Moves the exception directory out of a protector section so Shrink can
// remove that section. The table entries that belong to the protector are
// dropped; application entries keep their original RVAs.
void Patcher::RelocateExceptionTable() {
  if (pe_->Sections().size() < 2) {
    return;
  }

  IMAGE_DATA_DIRECTORY* directory =
      &pe_->ntHeaders.OptionalHeader
           .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  if (directory->VirtualAddress == 0 || directory->Size < 12) {
    return;
  }

  PESection* tableSection = pe_->GetSectionByVA(directory->VirtualAddress);
  if (tableSection == nullptr) {
    return;
  }

  const int tableIndex =
      static_cast<int>(tableSection - pe_->Sections().data());
  if (tableIndex <= 0) {
    return;
  }

  const IMAGE_SECTION_HEADER tableHeader = tableSection->Header;
  const std::string tableName = SectionName(tableHeader);
  const bool protectorSection =
      tableName == ".themida" || tableName == ".boot" ||
      tableName == ".tmd" || tableName == ".winlice" ||
      tableName.rfind(".vmp", 0) == 0;
  if (!protectorSection ||
      (tableHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
      tableHeader.SizeOfRawData == 0) {
    return;
  }

  const uint32_t delta =
      directory->VirtualAddress - tableHeader.VirtualAddress;
  if (delta >= tableHeader.SizeOfRawData) {
    return;
  }
  const int64_t tableOffset =
      static_cast<int64_t>(tableHeader.PointerToRawData) + delta;
  if (tableOffset < 0 ||
      tableOffset + static_cast<int64_t>(directory->Size) > stream_.Size()) {
    return;
  }

  const uint64_t sectionStart = tableHeader.VirtualAddress;
  const uint64_t sectionEnd =
      sectionStart + std::max<uint32_t>(
                         static_cast<uint32_t>(tableHeader.Misc.VirtualSize),
                         static_cast<uint32_t>(tableHeader.SizeOfRawData));
  const auto inTableSection = [&](uint32_t rva) {
    return rva >= sectionStart && rva < sectionEnd;
  };

  std::vector<uint8_t> table;
  table.reserve(directory->Size);
  const size_t count = directory->Size / 12;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* entry = stream_.Memory() + tableOffset +
                           static_cast<int64_t>(i) * 12;
    uint32_t begin = 0;
    uint32_t end = 0;
    uint32_t unwind = 0;
    std::memcpy(&begin, entry, sizeof(begin));
    std::memcpy(&end, entry + 4, sizeof(end));
    std::memcpy(&unwind, entry + 8, sizeof(unwind));
    if (inTableSection(begin) || inTableSection(end) ||
        inTableSection(unwind)) {
      continue;
    }
    table.insert(table.end(), entry, entry + 12);
  }

  if (table.empty()) {
    directory->VirtualAddress = 0;
    directory->Size = 0;
    return;
  }

  std::string sectionName = ".pdata";
  for (const PESection& section : pe_->Sections()) {
    if (SectionName(section.Header) == sectionName) {
      sectionName = ".pdata2";
      break;
    }
  }

  const IMAGE_SECTION_HEADER previous = pe_->Sections().back().Header;
  uint32_t virtualAddress =
      previous.VirtualAddress + previous.Misc.VirtualSize;
  pe_->SectionAlign(virtualAddress);

  uint32_t rawOffset = static_cast<uint32_t>(stream_.Size());
  pe_->FileAlign(rawOffset);
  uint32_t rawSize = static_cast<uint32_t>(table.size());
  pe_->FileAlign(rawSize);
  if (rawSize == 0) {
    rawSize = pe_->ntHeaders.OptionalHeader.FileAlignment;
  }

  pe_->AddSectionToArray();
  PESection& section = pe_->Sections().back();
  section.Rename(sectionName);
  section.Header.VirtualAddress = virtualAddress;
  section.Header.Misc.VirtualSize = static_cast<uint32_t>(table.size());
  section.Header.PointerToRawData = rawOffset;
  section.Header.SizeOfRawData = rawSize;
  section.Header.Characteristics =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

  pe_->ntHeaders.FileHeader.NumberOfSections =
      static_cast<WORD>(pe_->Sections().size());
  directory->VirtualAddress = virtualAddress;
  directory->Size = static_cast<uint32_t>(table.size());

  uint32_t sizeOfImage = virtualAddress + static_cast<uint32_t>(table.size());
  pe_->SectionAlign(sizeOfImage);
  if (sizeOfImage > pe_->ntHeaders.OptionalHeader.SizeOfImage) {
    pe_->ntHeaders.OptionalHeader.SizeOfImage = sizeOfImage;
  }

  if (static_cast<int64_t>(rawOffset) + rawSize > stream_.Size()) {
    stream_.SetSize(static_cast<int64_t>(rawOffset) + rawSize);
  }
  stream_.Seek(rawOffset, Stream::Origin::Begin);
  stream_.Write(table.data(), table.size());
  if (rawSize > table.size()) {
    std::vector<uint8_t> padding(rawSize - table.size(), 0);
    stream_.Write(padding.data(), padding.size());
  }
  stream_.SetPosition(0);

  LogF(ltGood,
       "Relocated exception table to [%s] (RVA %X, %zu entries); dropped "
       "%zu protector entries.",
       sectionName.c_str(), virtualAddress, table.size() / 12,
       count - table.size() / 12);
}

void Patcher::ShrinkPE() {
  const uint32_t entryPoint =
      pe_->ntHeaders.OptionalHeader.AddressOfEntryPoint;
  const uint64_t imageBase =
      static_cast<uint64_t>(pe_->ntHeaders.OptionalHeader.ImageBase);

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

  const auto sectionEnd = [](const IMAGE_SECTION_HEADER& header) {
    return static_cast<uint64_t>(header.VirtualAddress) +
           std::max<uint32_t>(static_cast<uint32_t>(header.Misc.VirtualSize),
                              static_cast<uint32_t>(header.SizeOfRawData));
  };

  const auto containsEntryPoint = [&](const IMAGE_SECTION_HEADER& header) {
    return entryPoint != 0 && entryPoint >= header.VirtualAddress &&
           entryPoint < sectionEnd(header);
  };

  // Maps an RVA inside a section's raw data to the file bytes.
  const auto rvaBytes = [&](uint32_t rva, uint8_t* out, size_t count) -> size_t {
    for (const PESection& section : pe_->Sections()) {
      const IMAGE_SECTION_HEADER& header = section.Header;
      if (rva < header.VirtualAddress ||
          rva - header.VirtualAddress >= header.SizeOfRawData) {
        continue;
      }
      const uint32_t delta = rva - header.VirtualAddress;
      const size_t available = header.SizeOfRawData - delta;
      const size_t bytes = std::min(count, available);
      const int64_t offset =
          static_cast<int64_t>(header.PointerToRawData) + delta;
      if (offset < 0 ||
          offset + static_cast<int64_t>(bytes) > stream_.Size()) {
        return 0;
      }
      std::memcpy(out, stream_.Memory() + offset, bytes);
      return bytes;
    }
    return 0;
  };

  const auto parseAt = [&](uint32_t rva) -> VmStubInfo {
    uint8_t code[16]{};
    const size_t bytes = rvaBytes(rva, code, sizeof(code));
    if (bytes < 2) {
      return {};
    }
    return ParseVmStub(code, bytes, rva, imageBase);
  };

  std::vector<uint32_t> vmTargets;
  const auto addTarget = [&](uint32_t rva) {
    if (rva == 0 || rva >= pe_->SizeOfImage()) {
      return;
    }
    if (std::find(vmTargets.begin(), vmTargets.end(), rva) ==
        vmTargets.end()) {
      vmTargets.push_back(rva);
    }
  };
  const auto addStubTargets = [&](const VmStubInfo& info, uint32_t stubRva) {
    addTarget(stubRva);
    addTarget(info.targetRva);
    addTarget(info.contextRva);
    addTarget(info.contextRva2);
  };

  // Follow the entry stub: push;jmp / push;push;jmp / jmp/call to a stub.
  if (entryPoint != 0) {
    const VmStubInfo entry = parseAt(entryPoint);
    if (entry.kind != VmStubKind::None) {
      addStubTargets(entry, entryPoint);
      if (entry.kind == VmStubKind::DirectJump ||
          entry.kind == VmStubKind::DirectCall ||
          entry.kind == VmStubKind::ShortJump) {
        const VmStubInfo next = parseAt(entry.targetRva);
        if (next.kind != VmStubKind::None) {
          addStubTargets(next, entry.targetRva);
        }
      }
    }
  }

  // Oreans-style reference scan: look for E8/E9 references in the
  // application's code section whose target is a VM entry stub. The final
  // VM target section must survive the shrink.
  if (!pe_->Sections().empty()) {
    const IMAGE_SECTION_HEADER& text = pe_->Sections()[0].Header;
    if (text.SizeOfRawData >= 5 &&
        static_cast<int64_t>(text.PointerToRawData) +
                static_cast<int64_t>(text.SizeOfRawData) <=
            stream_.Size()) {
      const uint8_t* data =
          stream_.Memory() + text.PointerToRawData;
      for (uint32_t offset = 0; offset + 5 <= text.SizeOfRawData; ++offset) {
        if (data[offset] != 0xE8 && data[offset] != 0xE9) {
          continue;
        }
        int32_t displacement = 0;
        std::memcpy(&displacement, data + offset + 1,
                    sizeof(displacement));
        const int64_t target = static_cast<int64_t>(text.VirtualAddress) +
                               offset + 5 + displacement;
        if (target <= 0 ||
            target >= static_cast<int64_t>(pe_->SizeOfImage())) {
          continue;
        }
        VmStubInfo stub = parseAt(static_cast<uint32_t>(target));
        uint32_t stubRva = static_cast<uint32_t>(target);
        if (stub.kind == VmStubKind::DirectJump ||
            stub.kind == VmStubKind::DirectCall ||
            stub.kind == VmStubKind::ShortJump) {
          const VmStubInfo next = parseAt(stub.targetRva);
          if (next.kind != VmStubKind::None) {
            stub = next;
            stubRva = stub.targetRva;
          }
        }
        if (stub.kind == VmStubKind::PushJump ||
            stub.kind == VmStubKind::PushPushJump ||
            stub.kind == VmStubKind::PushRet ||
            stub.kind == VmStubKind::MovEaxJmp ||
            stub.kind == VmStubKind::MovRaxJmp) {
          LogF(ltInfo, "VM entry reference at %X -> %X",
               text.VirtualAddress + offset, stubRva);
          addStubTargets(stub, stubRva);
        }
      }
    }
  }

  const auto containsVmTarget = [&](const IMAGE_SECTION_HEADER& header) {
    for (uint32_t target : vmTargets) {
      if (target >= header.VirtualAddress && target < sectionEnd(header)) {
        return true;
      }
    }
    return false;
  };

  std::vector<int> deleted;
  bool removedExecutable = false;
  MemoryStream newStream;
  stream_.SetPosition(0);
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
    const IMAGE_SECTION_HEADER& header =
        pe_->Sections()[static_cast<size_t>(i)].Header;
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
    const bool vmTargetSection = containsVmTarget(header);
    const bool keep = !removable || i == 0 || isReferenced(header) ||
                      containsEntryPoint(header) || vmTargetSection ||
                      protectedByName || protectedByFlags || noRawData;

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
      if (vmTargetSection && !containsEntryPoint(header) &&
          !isReferenced(header) && !protectedByName && !noRawData) {
        LogF(ltWarning,
             "Keeping section [%s]: it is a VM entry/reference target. "
             "Devirtualize before shrinking to remove it.",
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

void NormalizePEFile(const std::wstring& fileName) {
  Patcher patcher(fileName);
  patcher.NormalizeLayout();
}

}  // namespace magicmida
