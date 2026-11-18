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
// SPDX-License-Identifier: GPL-3.0-only
#include "reloc_fix.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common.h"
#include "pe_info.h"
#include "stream.h"

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
      const uint32_t block_size =
          static_cast<uint32_t>(kBlockHeaderSize + padded * sizeof(uint16_t));
      const size_t start = data.size();
      data.resize(start + block_size, 0);

      IMAGE_BASE_RELOCATION block{};
      block.VirtualAddress = page.first;
      block.SizeOfBlock = block_size;
      std::memcpy(data.data() + start, &block, sizeof(block));

      size_t index = 0;
      for (uint16_t entry : page.second) {
        std::memcpy(
            data.data() + start + kBlockHeaderSize + index * sizeof(uint16_t),
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

bool FixDllRelocations(const std::wstring& file_name, uintptr_t dump_base) {
  ReportStatus("Rebuilding relocations");
  MemoryStream stream;
  stream.LoadFromFile(file_name);
  const int64_t file_size = stream.Size();
  PeHeader pe(stream.Memory(), static_cast<size_t>(file_size));
  if (pe.Sections().empty()) {
    Log(kLogWarning, "Relocation fix skipped: the image has no sections.");
    return false;
  }

  IMAGE_NT_HEADERS& nt = pe.nt_headers();
  if ((nt.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
    Log(kLogWarning, "Relocation fix skipped: the file is not a DLL.");
    return false;
  }

  const uintptr_t preferred_base =
      static_cast<uintptr_t>(nt.OptionalHeader.ImageBase);
  const uintptr_t image_base = dump_base != 0 ? dump_base : preferred_base;
  if (image_base == 0) {
    Log(kLogWarning, "Relocation fix skipped: unknown image base.");
    return false;
  }

  if (image_base != preferred_base) {
    LogF(kLogWarning,
         "Image was dumped at %llX but its header says %llX; rebuilding "
         "relocations for the dump base.",
         static_cast<uint64_t>(image_base),
         static_cast<uint64_t>(preferred_base));
    nt.OptionalHeader.ImageBase =
        static_cast<decltype(nt.OptionalHeader.ImageBase)>(image_base);
  }

  const uint16_t reloc_type =
      sizeof(void*) == 8 ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW;
  const size_t pointer_size = sizeof(void*);

  RelocTable table;

  // -----------------------------------------------------------------------
  // Preserve the relocation entries that survived unpacking.
  // -----------------------------------------------------------------------
  const IMAGE_DATA_DIRECTORY reloc_directory =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  size_t existing_reloc_section = static_cast<size_t>(-1);
  int64_t existing_reloc_begin = -1;
  int64_t existing_reloc_end = -1;

  if (reloc_directory.VirtualAddress != 0 && reloc_directory.Size != 0) {
    const auto& sections = pe.Sections();
    for (size_t i = 0; i < sections.size(); ++i) {
      const IMAGE_SECTION_HEADER& header = sections[i].header;
      const uint32_t span =
          std::max(header.Misc.VirtualSize, header.SizeOfRawData);
      if (reloc_directory.VirtualAddress >= header.VirtualAddress &&
          reloc_directory.VirtualAddress < header.VirtualAddress + span) {
        existing_reloc_section = i;
        break;
      }
    }

    if (existing_reloc_section < pe.Sections().size()) {
      const IMAGE_SECTION_HEADER& header =
          pe.Sections()[existing_reloc_section].header;
      const uint32_t delta =
          reloc_directory.VirtualAddress - header.VirtualAddress;
      const int64_t begin =
          static_cast<int64_t>(header.PointerToRawData) + delta;
      const int64_t section_end =
          static_cast<int64_t>(header.PointerToRawData) + header.SizeOfRawData;
      const int64_t end =
          std::min<int64_t>(begin + reloc_directory.Size,
                            std::min<int64_t>(section_end, file_size));
      existing_reloc_begin = begin;
      existing_reloc_end = end;
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
        LogF(kLogInfo, "Preserving %zu existing relocation entries.",
             preserved);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Scan the image for absolute pointers.
  // -----------------------------------------------------------------------
  // Only accept values that point into the headers or into a section. Pointers
  // to the image base itself (e.g. a cached hInstance) are common, so the
  // header range counts as well.
  std::vector<std::pair<uintptr_t, uintptr_t>> valid_ranges;
  valid_ranges.emplace_back(image_base,
                            image_base + nt.OptionalHeader.SizeOfHeaders);
  for (const PeSection& section : pe.Sections()) {
    const IMAGE_SECTION_HEADER& header = section.header;
    const uint32_t span =
        std::max(header.Misc.VirtualSize, header.SizeOfRawData);
    if (span == 0) {
      continue;
    }
    valid_ranges.emplace_back(image_base + header.VirtualAddress,
                              image_base + header.VirtualAddress + span);
  }

  const auto is_image_address = [&valid_ranges](uintptr_t value) {
    for (const auto& range : valid_ranges) {
      if (value >= range.first && value < range.second) {
        return true;
      }
    }
    return false;
  };

  size_t scanned_sections = 0;
  const auto& scan_sections = pe.Sections();
  for (size_t index = 0; index < scan_sections.size(); ++index) {
    const IMAGE_SECTION_HEADER& header = scan_sections[index].header;
    const std::string name = SectionName(header);

    // .reloc is what we are replacing, .import was synthesized by the dumper
    // and only contains RVAs and strings. Discardable sections (debug info)
    // are not needed at runtime. Sections that are uninitialized in the
    // original file still have raw data in the dump, so they are scanned.
    if (name == ".reloc" || name == ".import" ||
        (header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 ||
        header.SizeOfRawData < pointer_size) {
      continue;
    }

    const int64_t begin = static_cast<int64_t>(header.PointerToRawData);
    const int64_t end = begin + header.SizeOfRawData;
    if (begin < 0 || end > file_size) {
      LogF(kLogWarning, "Skipping section [%s]: raw data outside the file.",
           name.c_str());
      continue;
    }

    ++scanned_sections;
    for (int64_t offset = begin;
         offset + static_cast<int64_t>(pointer_size) <= end;
         offset += static_cast<int64_t>(pointer_size)) {
      // Skip the old relocation table itself; its entries are not pointers.
      if (existing_reloc_begin >= 0 && offset >= existing_reloc_begin &&
          offset < existing_reloc_end) {
        continue;
      }
      uintptr_t value = 0;
      std::memcpy(&value, stream.Memory() + offset, pointer_size);
      if (!is_image_address(value)) {
        continue;
      }
      const uint32_t rva =
          header.VirtualAddress + static_cast<uint32_t>(offset - begin);
      table.Add(rva, reloc_type);
    }
  }

  const size_t entry_count = table.EntryCount();
  LogF(kLogInfo, "Scanned %zu sections for absolute pointers.",
       scanned_sections);
  if (entry_count == 0) {
    Log(kLogWarning,
        "No image-relative pointers were found; relocation table not rebuilt.");
    return false;
  }

  const std::vector<uint8_t> reloc_data = table.Build();
  const uint32_t file_alignment = nt.OptionalHeader.FileAlignment != 0
                                      ? nt.OptionalHeader.FileAlignment
                                      : 0x200;
  const uint32_t aligned_data_size = AlignUp(reloc_data.size(), file_alignment);

  // Reuse the existing .reloc section only when it is the last section and
  // the relocation directory covers exactly its beginning; otherwise append a
  // new section so no unrelated data can be overwritten.
  bool reuse = false;
  {
    const auto& sections = pe.Sections();
    if (existing_reloc_section < sections.size() &&
        existing_reloc_section == sections.size() - 1) {
      const IMAGE_SECTION_HEADER& header =
          sections[existing_reloc_section].header;
      reuse = SectionName(header) == ".reloc" &&
              reloc_directory.VirtualAddress == header.VirtualAddress &&
              header.SizeOfRawData >= aligned_data_size;
    }
  }

  PeSection* reloc_section = nullptr;
  if (reuse) {
    reloc_section = &pe.Sections()[existing_reloc_section];
    reloc_section->header.Misc.VirtualSize =
        static_cast<uint32_t>(reloc_data.size());
    Log(kLogInfo, "Reusing the existing .reloc section.");
  } else {
    // Rename a stale .reloc section so the new one is unambiguous.
    for (PeSection& section : pe.Sections()) {
      if (SectionName(section.header) == ".reloc") {
        section.Rename(".reloc0");
        Log(kLogInfo, "Renamed the old .reloc section to .reloc0.");
      }
    }

    const uint32_t header_limit = pe.Sections()[0].header.PointerToRawData;
    const uint64_t section_table_end =
        static_cast<uint64_t>(pe.LfaNew()) + sizeof(IMAGE_NT_HEADERS) +
        (static_cast<uint64_t>(pe.Sections().size()) + 1) *
            sizeof(IMAGE_SECTION_HEADER);
    if (section_table_end > header_limit) {
      throw std::runtime_error(
          "Not enough room in the PE header for a relocation section.");
    }

    const IMAGE_SECTION_HEADER previous = pe.Sections().back().header;
    uint32_t virtual_address =
        previous.VirtualAddress + previous.Misc.VirtualSize;
    pe.SectionAlign(virtual_address);

    pe.AddSectionToArray();
    reloc_section = &pe.Sections().back();
    reloc_section->Rename(".reloc");
    reloc_section->header.VirtualAddress = virtual_address;
    reloc_section->header.Misc.VirtualSize =
        static_cast<uint32_t>(reloc_data.size());
    reloc_section->header.PointerToRawData =
        AlignUp(static_cast<uint64_t>(file_size), file_alignment);
    reloc_section->header.SizeOfRawData = aligned_data_size;
    reloc_section->header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                            IMAGE_SCN_MEM_READ |
                                            IMAGE_SCN_MEM_DISCARDABLE;
  }

  nt.FileHeader.NumberOfSections = static_cast<WORD>(pe.Sections().size());
  nt.FileHeader.Characteristics &= ~IMAGE_FILE_RELOCS_STRIPPED;

  IMAGE_DATA_DIRECTORY& reloc_directory_out =
      nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  reloc_directory_out.VirtualAddress = reloc_section->header.VirtualAddress;
  reloc_directory_out.Size = static_cast<uint32_t>(reloc_data.size());

  uint32_t size_of_image = reloc_section->header.VirtualAddress +
                           reloc_section->header.Misc.VirtualSize;
  pe.SectionAlign(size_of_image);
  if (size_of_image > nt.OptionalHeader.SizeOfImage) {
    nt.OptionalHeader.SizeOfImage = size_of_image;
  }

  // -----------------------------------------------------------------------
  // Write the new section data and the updated headers.
  // -----------------------------------------------------------------------
  const int64_t raw_start =
      static_cast<int64_t>(reloc_section->header.PointerToRawData);
  const int64_t raw_end =
      raw_start + static_cast<int64_t>(reloc_section->header.SizeOfRawData);
  if (raw_end > stream.Size()) {
    stream.SetSize(raw_end);
  }

  stream.Seek(raw_start, Stream::Origin::kBegin);
  stream.Write(reloc_data.data(), reloc_data.size());
  if (reloc_section->header.SizeOfRawData > reloc_data.size()) {
    std::vector<uint8_t> padding(
        static_cast<size_t>(reloc_section->header.SizeOfRawData) -
            reloc_data.size(),
        0);
    stream.Write(padding.data(), padding.size());
  }

  stream.Seek(pe.LfaNew(), Stream::Origin::kBegin);
  stream.Write(&nt, sizeof(nt));
  for (const PeSection& section : pe.Sections()) {
    stream.Write(&section.header, sizeof(IMAGE_SECTION_HEADER));
  }

  stream.SaveToFile(file_name);

  LogF(kLogGood, "Rebuilt DLL relocation table: %zu entries in %zu pages.",
       entry_count, table.PageCount());
  Log(kLogWarning,
      "Reconstructed relocations are heuristic; test the DLL when loading it "
      "at another base.");
  return true;
}

}  // namespace magicmida
