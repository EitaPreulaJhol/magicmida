// Magicmida - C++ port
// Rebuilds base relocation tables for unpacked DLLs.
//
// Packed DLLs usually have their .reloc section stripped. The dump is still
// valid, but the loader cannot rebase it, so it only works at the address it
// was dumped at. This module scans the dumped image for values that look like
// absolute pointers into the image and rebuilds a .reloc section from them,
// merging any relocation entries that survived unpacking. It is also used by
// the Shrink command to repair files unpacked by other tools. The
// reconstruction is heuristic by nature (an integer that happens to fall
// inside the image is indistinguishable from a pointer), which is why it is
// opt-in.
#include "reloc_fix.h"

#include "common.h"
#include "pe_info.h"
#include "stream.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace magicmida {
namespace {

constexpr uint32_t kPageMask = 0xFFF;
constexpr uint32_t kBlockHeaderSize =
    static_cast<uint32_t>(sizeof(IMAGE_BASE_RELOCATION));

std::string SectionName(const IMAGE_SECTION_HEADER& header) {
  char name[9]{};
  std::memcpy(name, header.Name, 8);
  return std::string(name);
}

uint32_t AlignUp(uint64_t value, uint32_t alignment) {
  if (alignment == 0) {
    return static_cast<uint32_t>(value);
  }
  const uint64_t remainder = value % alignment;
  return remainder == 0 ? static_cast<uint32_t>(value)
                        : static_cast<uint32_t>(value + alignment - remainder);
}

// Entries grouped by page. Each entry keeps its raw 16-bit representation
// (4 bits of type, 12 bits of page offset), so existing entries can be
// preserved verbatim.
class RelocTable {
 public:
  void Add(uint32_t rva, uint16_t type) {
    const uint16_t entry =
        static_cast<uint16_t>((type << 12) | (rva & kPageMask));
    pages_[rva & ~kPageMask].insert(entry);
  }

  size_t EntryCount() const {
    size_t count = 0;
    for (const auto& page : pages_) {
      count += page.second.size();
    }
    return count;
  }

  size_t PageCount() const { return pages_.size(); }

  std::vector<uint8_t> Build() const {
    std::vector<uint8_t> data;
    for (const auto& page : pages_) {
      const size_t entries = page.second.size();
      // Blocks must be 32-bit aligned: pad with IMAGE_REL_BASED_ABSOLUTE.
      const size_t padded = (entries + 1) & ~static_cast<size_t>(1);
      const uint32_t blockSize = static_cast<uint32_t>(
          kBlockHeaderSize + padded * sizeof(uint16_t));
      const size_t start = data.size();
      data.resize(start + blockSize, 0);

      IMAGE_BASE_RELOCATION block{};
      block.VirtualAddress = page.first;
      block.SizeOfBlock = blockSize;
      std::memcpy(data.data() + start, &block, sizeof(block));

      size_t index = 0;
      for (uint16_t entry : page.second) {
        std::memcpy(data.data() + start + kBlockHeaderSize +
                        index * sizeof(uint16_t),
                    &entry, sizeof(entry));
        ++index;
      }
      // The remaining entries stay zero (IMAGE_REL_BASED_ABSOLUTE padding).
    }
    return data;
  }

 private:
  std::map<uint32_t, std::set<uint16_t>> pages_;
};

}  // namespace

bool FixDllRelocations(const std::wstring& fileName, uintptr_t dumpBase) {
  MemoryStream stream;
  stream.LoadFromFile(fileName);
  const int64_t fileSize = stream.Size();
  PEHeader pe(stream.Memory(), static_cast<size_t>(fileSize));
  if (pe.Sections().empty()) {
    Log(ltWarning, "Relocation fix skipped: the image has no sections.");
    return false;
  }

  IMAGE_NT_HEADERS& nt = pe.ntHeaders;
  if ((nt.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
    Log(ltWarning, "Relocation fix skipped: the file is not a DLL.");
    return false;
  }

  const uintptr_t preferredBase =
      static_cast<uintptr_t>(nt.OptionalHeader.ImageBase);
  const uintptr_t imageBase = dumpBase != 0 ? dumpBase : preferredBase;
  if (imageBase == 0) {
    Log(ltWarning, "Relocation fix skipped: unknown image base.");
    return false;
  }

  if (imageBase != preferredBase) {
    LogF(ltWarning,
         "Image was dumped at %llX but its header says %llX; rebuilding "
         "relocations for the dump base.",
         static_cast<unsigned long long>(imageBase),
         static_cast<unsigned long long>(preferredBase));
    nt.OptionalHeader.ImageBase =
        static_cast<decltype(nt.OptionalHeader.ImageBase)>(imageBase);
  }

  const uint16_t relocType =
      sizeof(void*) == 8 ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW;
  const size_t pointerSize = sizeof(void*);

  RelocTable table;

  // -----------------------------------------------------------------------
  // Preserve the relocation entries that survived unpacking.
  // -----------------------------------------------------------------------
  const IMAGE_DATA_DIRECTORY relocDirectory =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  size_t existingRelocSection = static_cast<size_t>(-1);
  int64_t existingRelocBegin = -1;
  int64_t existingRelocEnd = -1;

  if (relocDirectory.VirtualAddress != 0 && relocDirectory.Size != 0) {
    const auto& sections = pe.Sections();
    for (size_t i = 0; i < sections.size(); ++i) {
      const IMAGE_SECTION_HEADER& header = sections[i].Header;
      const uint32_t span =
          std::max(header.Misc.VirtualSize, header.SizeOfRawData);
      if (relocDirectory.VirtualAddress >= header.VirtualAddress &&
          relocDirectory.VirtualAddress < header.VirtualAddress + span) {
        existingRelocSection = i;
        break;
      }
    }

    if (existingRelocSection < pe.Sections().size()) {
      const IMAGE_SECTION_HEADER& header =
          pe.Sections()[existingRelocSection].Header;
      const uint32_t delta =
          relocDirectory.VirtualAddress - header.VirtualAddress;
      const int64_t begin =
          static_cast<int64_t>(header.PointerToRawData) + delta;
      const int64_t sectionEnd =
          static_cast<int64_t>(header.PointerToRawData) +
          header.SizeOfRawData;
      const int64_t end =
          std::min<int64_t>(begin + relocDirectory.Size,
                            std::min<int64_t>(sectionEnd, fileSize));
      existingRelocBegin = begin;
      existingRelocEnd = end;
      int64_t position = begin;
      size_t preserved = 0;

      while (position + static_cast<int64_t>(kBlockHeaderSize) <= end) {
        IMAGE_BASE_RELOCATION block{};
        std::memcpy(&block, stream.Memory() + position, sizeof(block));
        if (block.SizeOfBlock < kBlockHeaderSize ||
            position + static_cast<int64_t>(block.SizeOfBlock) > end) {
          break;
        }

        const size_t count =
            (block.SizeOfBlock - kBlockHeaderSize) / sizeof(uint16_t);
        for (size_t i = 0; i < count; ++i) {
          uint16_t entry = 0;
          std::memcpy(&entry,
                      stream.Memory() + position + kBlockHeaderSize +
                          i * sizeof(uint16_t),
                      sizeof(entry));
          if ((entry >> 12) != IMAGE_REL_BASED_ABSOLUTE) {
            table.Add(block.VirtualAddress + (entry & kPageMask),
                      static_cast<uint16_t>(entry >> 12));
            ++preserved;
          }
        }
        position += block.SizeOfBlock;
      }

      if (preserved > 0) {
        LogF(ltInfo, "Preserving %zu existing relocation entries.", preserved);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Scan the image for absolute pointers.
  // -----------------------------------------------------------------------
  // Only accept values that point into the headers or into a section. Pointers
  // to the image base itself (e.g. a cached hInstance) are common, so the
  // header range counts as well.
  std::vector<std::pair<uintptr_t, uintptr_t>> validRanges;
  validRanges.emplace_back(imageBase,
                           imageBase + nt.OptionalHeader.SizeOfHeaders);
  for (const PESection& section : pe.Sections()) {
    const IMAGE_SECTION_HEADER& header = section.Header;
    const uint32_t span =
        std::max(header.Misc.VirtualSize, header.SizeOfRawData);
    if (span == 0) {
      continue;
    }
    validRanges.emplace_back(imageBase + header.VirtualAddress,
                             imageBase + header.VirtualAddress + span);
  }

  const auto isImageAddress = [&validRanges](uintptr_t value) {
    for (const auto& range : validRanges) {
      if (value >= range.first && value < range.second) {
        return true;
      }
    }
    return false;
  };

  size_t scannedSections = 0;
  const auto& scanSections = pe.Sections();
  for (size_t index = 0; index < scanSections.size(); ++index) {
    const IMAGE_SECTION_HEADER& header = scanSections[index].Header;
    const std::string name = SectionName(header);

    // .reloc is what we are replacing, .import was synthesized by the dumper
    // and only contains RVAs and strings. Discardable sections (debug info)
    // are not needed at runtime. Sections that are uninitialized in the
    // original file still have raw data in the dump, so they are scanned.
    if (name == ".reloc" || name == ".import" ||
        (header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 ||
        header.SizeOfRawData < pointerSize) {
      continue;
    }

    const int64_t begin = static_cast<int64_t>(header.PointerToRawData);
    const int64_t end = begin + header.SizeOfRawData;
    if (begin < 0 || end > fileSize) {
      LogF(ltWarning, "Skipping section [%s]: raw data outside the file.",
           name.c_str());
      continue;
    }

    ++scannedSections;
    for (int64_t offset = begin;
         offset + static_cast<int64_t>(pointerSize) <= end;
         offset += static_cast<int64_t>(pointerSize)) {
      // Skip the old relocation table itself; its entries are not pointers.
      if (existingRelocBegin >= 0 && offset >= existingRelocBegin &&
          offset < existingRelocEnd) {
        continue;
      }
      uintptr_t value = 0;
      std::memcpy(&value, stream.Memory() + offset, pointerSize);
      if (!isImageAddress(value)) {
        continue;
      }
      const uint32_t rva = header.VirtualAddress +
                           static_cast<uint32_t>(offset - begin);
      table.Add(rva, relocType);
    }
  }

  const size_t entryCount = table.EntryCount();
  LogF(ltInfo, "Scanned %zu sections for absolute pointers.", scannedSections);
  if (entryCount == 0) {
    Log(ltWarning,
        "No image-relative pointers were found; relocation table not rebuilt.");
    return false;
  }

  const std::vector<uint8_t> relocData = table.Build();
  const uint32_t fileAlignment =
      nt.OptionalHeader.FileAlignment != 0 ? nt.OptionalHeader.FileAlignment
                                           : 0x200;
  const uint32_t alignedDataSize =
      AlignUp(relocData.size(), fileAlignment);

  // Reuse the existing .reloc section only when it is the last section and
  // the relocation directory covers exactly its beginning; otherwise append a
  // new section so no unrelated data can be overwritten.
  bool reuse = false;
  {
    const auto& sections = pe.Sections();
    if (existingRelocSection < sections.size() &&
        existingRelocSection == sections.size() - 1) {
      const IMAGE_SECTION_HEADER& header = sections[existingRelocSection].Header;
      reuse = SectionName(header) == ".reloc" &&
              relocDirectory.VirtualAddress == header.VirtualAddress &&
              header.SizeOfRawData >= alignedDataSize;
    }
  }

  PESection* relocSection = nullptr;
  if (reuse) {
    relocSection = &pe.Sections()[existingRelocSection];
    relocSection->Header.Misc.VirtualSize =
        static_cast<uint32_t>(relocData.size());
    Log(ltInfo, "Reusing the existing .reloc section.");
  } else {
    // Rename a stale .reloc section so the new one is unambiguous.
    for (PESection& section : pe.Sections()) {
      if (SectionName(section.Header) == ".reloc") {
        section.Rename(".reloc0");
        Log(ltInfo, "Renamed the old .reloc section to .reloc0.");
      }
    }

    const uint32_t headerLimit = pe.Sections()[0].Header.PointerToRawData;
    const uint64_t sectionTableEnd =
        static_cast<uint64_t>(pe.LFANew()) + sizeof(IMAGE_NT_HEADERS) +
        (static_cast<uint64_t>(pe.Sections().size()) + 1) *
            sizeof(IMAGE_SECTION_HEADER);
    if (sectionTableEnd > headerLimit) {
      throw std::runtime_error(
          "Not enough room in the PE header for a relocation section.");
    }

    const IMAGE_SECTION_HEADER previous = pe.Sections().back().Header;
    uint32_t virtualAddress =
        previous.VirtualAddress + previous.Misc.VirtualSize;
    pe.SectionAlign(virtualAddress);

    pe.AddSectionToArray();
    relocSection = &pe.Sections().back();
    relocSection->Rename(".reloc");
    relocSection->Header.VirtualAddress = virtualAddress;
    relocSection->Header.Misc.VirtualSize =
        static_cast<uint32_t>(relocData.size());
    relocSection->Header.PointerToRawData =
        AlignUp(static_cast<uint64_t>(fileSize), fileAlignment);
    relocSection->Header.SizeOfRawData = alignedDataSize;
    relocSection->Header.Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
        IMAGE_SCN_MEM_DISCARDABLE;
  }

  nt.FileHeader.NumberOfSections =
      static_cast<WORD>(pe.Sections().size());
  nt.FileHeader.Characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED;

  IMAGE_DATA_DIRECTORY& relocDirectoryOut =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  relocDirectoryOut.VirtualAddress = relocSection->Header.VirtualAddress;
  relocDirectoryOut.Size = static_cast<uint32_t>(relocData.size());

  uint32_t sizeOfImage = relocSection->Header.VirtualAddress +
                         relocSection->Header.Misc.VirtualSize;
  pe.SectionAlign(sizeOfImage);
  if (sizeOfImage > nt.OptionalHeader.SizeOfImage) {
    nt.OptionalHeader.SizeOfImage = sizeOfImage;
  }

  // -----------------------------------------------------------------------
  // Write the new section data and the updated headers.
  // -----------------------------------------------------------------------
  const int64_t rawStart =
      static_cast<int64_t>(relocSection->Header.PointerToRawData);
  const int64_t rawEnd =
      rawStart + static_cast<int64_t>(relocSection->Header.SizeOfRawData);
  if (rawEnd > stream.Size()) {
    stream.SetSize(rawEnd);
  }

  stream.Seek(rawStart, Stream::Origin::Begin);
  stream.Write(relocData.data(), relocData.size());
  if (relocSection->Header.SizeOfRawData > relocData.size()) {
    std::vector<uint8_t> padding(
        static_cast<size_t>(relocSection->Header.SizeOfRawData) -
            relocData.size(),
        0);
    stream.Write(padding.data(), padding.size());
  }

  stream.Seek(pe.LFANew(), Stream::Origin::Begin);
  stream.Write(&nt, sizeof(nt));
  for (const PESection& section : pe.Sections()) {
    stream.Write(&section.Header, sizeof(IMAGE_SECTION_HEADER));
  }

  stream.SaveToFile(fileName);

  LogF(ltGood, "Rebuilt DLL relocation table: %zu entries in %zu pages.",
       entryCount, table.PageCount());
  Log(ltWarning,
      "Reconstructed relocations are heuristic; test the DLL when loading it "
      "at another base.");
  return true;
}

}  // namespace magicmida
