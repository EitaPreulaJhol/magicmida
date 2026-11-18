// Magicmida - C++ port
// Post-processing of unpacked files (ported from Patcher.pas).
#include "patcher.h"
#include "vm_entry.h"

#include <psapi.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
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

Patcher::Patcher(const std::wstring& file_name) : file_name_(file_name) {
  stream_.LoadFromFile(file_name);
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
  stream_.SaveToFile(file_name_);
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

  const uint32_t file_alignment =
      pe_->nt_headers().OptionalHeader.FileAlignment;
  if (file_alignment < 0x200 || file_alignment > 0x10000 ||
      (file_alignment & (file_alignment - 1)) != 0) {
    LogF(kLogWarning,
         "Skipping PE layout normalization: invalid FileAlignment %X.",
         file_alignment);
    return;
  }

  const int64_t old_file_size64 = stream_.Size();
  if (old_file_size64 < 0) {
    throw std::runtime_error("NormalizeLayout: invalid file size");
  }
  const uint64_t old_file_size = static_cast<uint64_t>(old_file_size64);

  const uint64_t header_end =
      static_cast<uint64_t>(pe_->LFANew()) + sizeof(IMAGE_NT_HEADERS) +
      static_cast<uint64_t>(sections.size()) * sizeof(IMAGE_SECTION_HEADER);
  // PEHeader::SaveToStream zeroes 0x200 bytes after the section table; keep
  // that area inside SizeOfHeaders so it never overwrites section data.
  uint64_t new_headers64 = header_end + 0x200;
  if (new_headers64 > 0xFFFFFFFFull) {
    throw std::runtime_error("NormalizeLayout: header is too large");
  }
  uint32_t new_headers = static_cast<uint32_t>(new_headers64);
  pe_->FileAlign(new_headers);

  struct SectionLayout {
    uint32_t old_raw = 0;
    uint32_t old_size = 0;
    uint32_t new_raw = 0;
    uint32_t new_size = 0;
    uint32_t copy_size = 0;
  };
  std::vector<SectionLayout> layouts;
  layouts.reserve(sections.size());

  uint64_t old_section_end = 0;
  uint64_t cursor = new_headers;

  for (PESection& section : pe_->Sections()) {
    const IMAGE_SECTION_HEADER header = section.header;
    SectionLayout layout;
    layout.old_raw = header.PointerToRawData;
    layout.old_size = header.SizeOfRawData;

    if (header.SizeOfRawData != 0) {
      const uint64_t end =
          static_cast<uint64_t>(header.PointerToRawData) + header.SizeOfRawData;
      if (end > old_file_size) {
        throw std::runtime_error(
            "NormalizeLayout: section raw data extends past the file");
      }
      old_section_end = std::max(old_section_end, end);
    }

    if (header.SizeOfRawData != 0) {
      // Only the raw bytes belong in the file. VirtualSize may be larger
      // (.bss, or a section stretched over removed protector RVA ranges);
      // the loader zero-fills the virtual tail, so do not materialize it.
      layout.copy_size = header.SizeOfRawData;
      layout.new_size = header.SizeOfRawData;
      pe_->FileAlign(layout.new_size);
      if (layout.new_size == 0) {
        layout.new_size = file_alignment;
      }
    }

    if (layout.new_size != 0) {
      if (cursor > 0xFFFFFFFFull) {
        throw std::runtime_error("NormalizeLayout: section offset overflow");
      }
      layout.new_raw = static_cast<uint32_t>(cursor);
      if (layout.copy_size > 0) {
        const uint64_t source_end =
            static_cast<uint64_t>(layout.old_raw) + layout.copy_size;
        if (source_end > old_file_size) {
          throw std::runtime_error(
              "NormalizeLayout: section data is truncated");
        }
      }
      cursor += layout.new_size;
    }

    layouts.push_back(layout);
    section.header.PointerToRawData = layout.new_raw;
    section.header.SizeOfRawData = layout.new_size;
  }

  const auto map_file_offset = [&layouts](uint32_t old_offset) -> uint32_t {
    if (old_offset == 0) {
      return 0;
    }
    for (const SectionLayout& layout : layouts) {
      if (layout.old_size != 0 && old_offset >= layout.old_raw &&
          old_offset < layout.old_raw + layout.old_size) {
        return layout.new_raw + (old_offset - layout.old_raw);
      }
    }
    return 0;
  };

  // File-offset fields in the headers/section table still point at the old
  // layout. Map them into the new one; data outside sections is dropped.
  pe_->nt_headers().FileHeader.PointerToSymbolTable =
      map_file_offset(pe_->nt_headers().FileHeader.PointerToSymbolTable);
  for (PESection& section : pe_->Sections()) {
    if (section.header.PointerToRelocations != 0) {
      section.header.PointerToRelocations =
          map_file_offset(section.header.PointerToRelocations);
    }
    if (section.header.PointerToLinenumbers != 0) {
      section.header.PointerToLinenumbers =
          map_file_offset(section.header.PointerToLinenumbers);
    }
  }

  if (cursor > 0xFFFFFFFFull) {
    throw std::runtime_error("NormalizeLayout: file is too large");
  }

  // The certificate table is the only trailing data with a well-defined file
  // offset. Preserve it and move its directory entry; the flat dump padding
  // (and protector bytes left behind by Shrink) is dropped.
  const IMAGE_DATA_DIRECTORY old_security =
      pe_->nt_headers()
          .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  uint64_t overlay_size = 0;
  uint64_t old_overlay_start = 0;
  if (old_security.VirtualAddress != 0 && old_security.Size != 0) {
    const uint64_t start = old_security.VirtualAddress;
    const uint64_t end = start + old_security.Size;
    if (start >= old_section_end && end <= old_file_size && end > start) {
      old_overlay_start = start;
      overlay_size = end - start;
    } else {
      Log(kLogWarning,
          "Dropping an invalid certificate table while normalizing the PE.");
    }
  }

  if (old_file_size > old_section_end && overlay_size == 0) {
    LogF(kLogInfo, "Dropping %llu trailing bytes of non-certificate data.",
         static_cast<unsigned long long>(old_file_size - old_section_end));
  }

  const uint64_t new_overlay_start = cursor;
  uint64_t new_file_size = cursor + overlay_size;
  if (new_file_size > 0xFFFFFFFFull) {
    throw std::runtime_error("NormalizeLayout: file is too large");
  }

  IMAGE_DATA_DIRECTORY& security =
      pe_->nt_headers()
          .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  if (overlay_size != 0) {
    security.VirtualAddress = static_cast<uint32_t>(new_overlay_start);
    // security.Size stays unchanged.
  } else if (security.VirtualAddress != 0 || security.Size != 0) {
    security.VirtualAddress = 0;
    security.Size = 0;
  }

  pe_->nt_headers().OptionalHeader.SizeOfHeaders = new_headers;
  // The file changed, so the old header checksum is meaningless.
  pe_->nt_headers().OptionalHeader.CheckSum = 0;

  MemoryStream normalized;
  normalized.SetSize(static_cast<int64_t>(new_file_size));
  const uint32_t dos_stub_size = pe_->LFANew();
  if (dos_stub_size > old_file_size) {
    throw std::runtime_error("NormalizeLayout: truncated DOS header");
  }
  if (dos_stub_size != 0) {
    std::memcpy(normalized.Memory(), stream_.Memory(), dos_stub_size);
  }
  pe_->SaveToStream(normalized);

  for (const SectionLayout& layout : layouts) {
    if (layout.copy_size == 0) {
      continue;
    }
    std::memcpy(normalized.Memory() + layout.new_raw,
                stream_.Memory() + layout.old_raw, layout.copy_size);
  }

  // IMAGE_DEBUG_DIRECTORY entries hold file offsets (hint: the CodeView
  // record), so they must follow the section data they describe.
  const IMAGE_DATA_DIRECTORY debug_directory =
      pe_->nt_headers()
          .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  if (debug_directory.VirtualAddress != 0 &&
      debug_directory.Size >= sizeof(IMAGE_DEBUG_DIRECTORY)) {
    const PESection* debug_section =
        pe_->GetSectionByVA(debug_directory.VirtualAddress);
    if (debug_section != nullptr) {
      const uint64_t section_start = debug_section->header.VirtualAddress;
      const uint64_t section_end =
          section_start +
          std::max<uint32_t>(debug_section->header.Misc.VirtualSize,
                             debug_section->header.SizeOfRawData);
      const size_t debug_index =
          static_cast<size_t>(debug_section - pe_->Sections().data());
      const uint64_t new_debug_offset =
          layouts[debug_index].new_raw +
          (debug_directory.VirtualAddress - section_start);
      if (debug_directory.VirtualAddress >= section_start &&
          static_cast<uint64_t>(debug_directory.VirtualAddress) < section_end &&
          layouts[debug_index].new_size != 0 &&
          new_debug_offset + debug_directory.Size <= new_file_size) {
        for (uint32_t offset = 0;
             offset + sizeof(IMAGE_DEBUG_DIRECTORY) <= debug_directory.Size;
             offset += sizeof(IMAGE_DEBUG_DIRECTORY)) {
          auto* entry = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(
              normalized.Memory() + new_debug_offset + offset);
          if (entry->PointerToRawData != 0) {
            entry->PointerToRawData = map_file_offset(entry->PointerToRawData);
          }
        }
      }
    }
  }

  if (overlay_size != 0) {
    std::memcpy(normalized.Memory() + new_overlay_start,
                stream_.Memory() + old_overlay_start,
                static_cast<size_t>(overlay_size));
  }

  normalized.SaveToFile(file_name_);
  stream_ = std::move(normalized);

  LogF(kLogInfo,
       "Normalized PE layout: SizeOfHeaders %X, file size %llX -> %llX.",
       new_headers, static_cast<unsigned long long>(old_file_size),
       static_cast<unsigned long long>(new_file_size));
}

void Patcher::FlattenLayout() {
  const auto& sections = pe_->Sections();
  if (sections.empty()) {
    return;
  }

  bool flat = true;
  for (const PESection& section : sections) {
    if (section.header.SizeOfRawData != 0 &&
        section.header.PointerToRawData != section.header.VirtualAddress) {
      flat = false;
      break;
    }
  }
  if (flat) {
    return;
  }

  const uint64_t old_file_size = static_cast<uint64_t>(stream_.Size());
  uint64_t file_size = pe_->SizeOfImage();
  for (const PESection& section : sections) {
    file_size = std::max<uint64_t>(
        file_size, static_cast<uint64_t>(section.header.VirtualAddress) +
                       std::max<uint32_t>(section.header.Misc.VirtualSize,
                                          section.header.SizeOfRawData));
  }
  if (file_size > 0xFFFFFFFFull) {
    throw std::runtime_error("FlattenLayout: file is too large");
  }

  MemoryStream flat_stream;
  flat_stream.SetSize(static_cast<int64_t>(file_size));
  const uint32_t first_va = sections[0].header.VirtualAddress;
  const uint64_t old_size_of_headers =
      pe_->nt_headers().OptionalHeader.SizeOfHeaders;
  // Do not copy section bytes that happen to sit between SizeOfHeaders and
  // the first section RVA in a normalized layout.
  const uint64_t header_copy = std::min<uint64_t>(
      old_file_size, std::min<uint64_t>(first_va, old_size_of_headers));
  if (header_copy != 0) {
    std::memcpy(flat_stream.Memory(), stream_.Memory(),
                static_cast<size_t>(header_copy));
  }

  for (PESection& section : pe_->Sections()) {
    const uint32_t old_raw = section.header.PointerToRawData;
    const uint32_t old_size = section.header.SizeOfRawData;
    const uint32_t copy_size =
        std::min<uint32_t>(section.header.Misc.VirtualSize, old_size);
    if (copy_size != 0) {
      if (static_cast<uint64_t>(old_raw) + copy_size > old_file_size) {
        throw std::runtime_error("FlattenLayout: section data is truncated");
      }
      std::memcpy(flat_stream.Memory() + section.header.VirtualAddress,
                  stream_.Memory() + old_raw, copy_size);
    }
    section.header.PointerToRawData = section.header.VirtualAddress;
    // Keep the original raw size. The flat stream is SizeOfImage, so the
    // virtual tail is present as zeros for the legacy RVA-based scanners.
    section.header.SizeOfRawData = old_size;
  }

  pe_->nt_headers().OptionalHeader.SizeOfHeaders = first_va;
  pe_->SaveToStream(flat_stream);
  stream_ = std::move(flat_stream);
  Log(kLogInfo, "Flattened PE layout for data-section creation.");
}

bool Patcher::ProcessMkData() {
  ReportStatus("Creating data sections");
#if defined(_WIN64)
  Log(kLogInfo, "Data section creation is not available for 64-bit binaries.");
  return false;
#else
  FlattenLayout();
  const std::string lower = AsciiLowerCase(WideToUtf8(file_name_));
  const size_t pos_ms = lower.rfind("maplestory");
  bool created = false;
  if (pos_ms != std::string::npos && pos_ms > 0 &&
      PosFrom(lower, ".exe", pos_ms) < pos_ms + 10 + 10) {
    created = MapleCreateDataSections();
  } else if (pe_->nt_headers().OptionalHeader.MajorLinkerVersion == 14) {
    // MSVC 2015+
    created = MSVCCreateDataSections();
  } else {
    Log(kLogInfo, "Data section creation not available for this compiler.");
    return false;
  }

  if (!created) {
    return false;
  }

  pe_->SaveToStream(stream_);
  stream_.SaveToFile(file_name_);
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
      &pe_->nt_headers()
           .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  if (directory->VirtualAddress == 0 || directory->Size < 12) {
    return;
  }

  PESection* table_section = pe_->GetSectionByVA(directory->VirtualAddress);
  if (table_section == nullptr) {
    return;
  }

  const int table_index =
      static_cast<int>(table_section - pe_->Sections().data());
  if (table_index <= 0) {
    return;
  }

  const IMAGE_SECTION_HEADER table_header = table_section->header;
  const std::string table_name = SectionName(table_header);
  const bool protector_section =
      table_name == ".themida" || table_name == ".boot" ||
      table_name == ".tmd" || table_name == ".winlice" ||
      table_name.rfind(".vmp", 0) == 0;
  if (!protector_section ||
      (table_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
      table_header.SizeOfRawData == 0) {
    return;
  }

  const uint32_t delta =
      directory->VirtualAddress - table_header.VirtualAddress;
  if (delta >= table_header.SizeOfRawData) {
    return;
  }
  const int64_t table_offset =
      static_cast<int64_t>(table_header.PointerToRawData) + delta;
  if (table_offset < 0 ||
      table_offset + static_cast<int64_t>(directory->Size) > stream_.Size()) {
    return;
  }

  const uint64_t section_start = table_header.VirtualAddress;
  const uint64_t section_end =
      section_start +
      std::max<uint32_t>(static_cast<uint32_t>(table_header.Misc.VirtualSize),
                         static_cast<uint32_t>(table_header.SizeOfRawData));
  const auto in_table_section = [&](uint32_t rva) {
    return rva >= section_start && rva < section_end;
  };

  std::vector<uint8_t> table;
  table.reserve(directory->Size);
  const size_t count = directory->Size / 12;
  for (size_t i = 0; i < count; ++i) {
    const uint8_t* entry =
        stream_.Memory() + table_offset + static_cast<int64_t>(i) * 12;
    uint32_t begin = 0;
    uint32_t end = 0;
    uint32_t unwind = 0;
    std::memcpy(&begin, entry, sizeof(begin));
    std::memcpy(&end, entry + 4, sizeof(end));
    std::memcpy(&unwind, entry + 8, sizeof(unwind));
    if (in_table_section(begin) || in_table_section(end) ||
        in_table_section(unwind)) {
      continue;
    }
    table.insert(table.end(), entry, entry + 12);
  }

  if (table.empty()) {
    directory->VirtualAddress = 0;
    directory->Size = 0;
    return;
  }

  std::string section_name = ".pdata";
  for (const PESection& section : pe_->Sections()) {
    if (SectionName(section.header) == section_name) {
      section_name = ".pdata2";
      break;
    }
  }

  const IMAGE_SECTION_HEADER previous = pe_->Sections().back().header;
  uint32_t virtual_address =
      previous.VirtualAddress + previous.Misc.VirtualSize;
  pe_->SectionAlign(virtual_address);

  uint32_t raw_offset = static_cast<uint32_t>(stream_.Size());
  pe_->FileAlign(raw_offset);
  uint32_t raw_size = static_cast<uint32_t>(table.size());
  pe_->FileAlign(raw_size);
  if (raw_size == 0) {
    raw_size = pe_->nt_headers().OptionalHeader.FileAlignment;
  }

  pe_->AddSectionToArray();
  PESection& section = pe_->Sections().back();
  section.Rename(section_name);
  section.header.VirtualAddress = virtual_address;
  section.header.Misc.VirtualSize = static_cast<uint32_t>(table.size());
  section.header.PointerToRawData = raw_offset;
  section.header.SizeOfRawData = raw_size;
  section.header.Characteristics =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

  pe_->nt_headers().FileHeader.NumberOfSections =
      static_cast<WORD>(pe_->Sections().size());
  directory->VirtualAddress = virtual_address;
  directory->Size = static_cast<uint32_t>(table.size());

  uint32_t size_of_image =
      virtual_address + static_cast<uint32_t>(table.size());
  pe_->SectionAlign(size_of_image);
  if (size_of_image > pe_->nt_headers().OptionalHeader.SizeOfImage) {
    pe_->nt_headers().OptionalHeader.SizeOfImage = size_of_image;
  }

  if (static_cast<int64_t>(raw_offset) + raw_size > stream_.Size()) {
    stream_.SetSize(static_cast<int64_t>(raw_offset) + raw_size);
  }
  stream_.Seek(raw_offset, Stream::Origin::kBegin);
  stream_.Write(table.data(), table.size());
  if (raw_size > table.size()) {
    std::vector<uint8_t> padding(raw_size - table.size(), 0);
    stream_.Write(padding.data(), padding.size());
  }
  stream_.SetPosition(0);

  LogF(kLogGood,
       "Relocated exception table to [%s] (RVA %X, %zu entries); dropped "
       "%zu protector entries.",
       section_name.c_str(), virtual_address, table.size() / 12,
       count - table.size() / 12);
}

void Patcher::ShrinkPE() {
  const uint32_t entry_point =
      pe_->nt_headers().OptionalHeader.AddressOfEntryPoint;
  const uint64_t image_base =
      static_cast<uint64_t>(pe_->nt_headers().OptionalHeader.ImageBase);

  const auto is_referenced = [&](const IMAGE_SECTION_HEADER& header) {
    const uint64_t section_start = header.VirtualAddress;
    const uint64_t section_end =
        section_start +
        std::max<uint32_t>(static_cast<uint32_t>(header.Misc.VirtualSize),
                           static_cast<uint32_t>(header.SizeOfRawData));
    for (size_t index = 0; index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++index) {
      // The security directory holds a file offset, not an RVA.
      if (index == IMAGE_DIRECTORY_ENTRY_SECURITY) {
        continue;
      }
      const IMAGE_DATA_DIRECTORY& directory =
          pe_->nt_headers().OptionalHeader.DataDirectory[index];
      if (directory.VirtualAddress == 0 || directory.Size == 0) {
        continue;
      }
      const uint64_t directory_start = directory.VirtualAddress;
      const uint64_t directory_end =
          directory_start + static_cast<uint64_t>(directory.Size);
      if (directory_start < section_end && directory_end > section_start) {
        return true;
      }
    }
    return false;
  };

  const auto section_end = [](const IMAGE_SECTION_HEADER& header) {
    return static_cast<uint64_t>(header.VirtualAddress) +
           std::max<uint32_t>(static_cast<uint32_t>(header.Misc.VirtualSize),
                              static_cast<uint32_t>(header.SizeOfRawData));
  };

  const auto contains_entry_point = [&](const IMAGE_SECTION_HEADER& header) {
    return entry_point != 0 && entry_point >= header.VirtualAddress &&
           entry_point < section_end(header);
  };

  // Maps an RVA inside a section's raw data to the file bytes.
  const auto rva_bytes = [&](uint32_t rva, uint8_t* out,
                             size_t count) -> size_t {
    for (const PESection& section : pe_->Sections()) {
      const IMAGE_SECTION_HEADER& header = section.header;
      if (rva < header.VirtualAddress ||
          rva - header.VirtualAddress >= header.SizeOfRawData) {
        continue;
      }
      const uint32_t delta = rva - header.VirtualAddress;
      const size_t available = header.SizeOfRawData - delta;
      const size_t bytes = std::min(count, available);
      const int64_t offset =
          static_cast<int64_t>(header.PointerToRawData) + delta;
      if (offset < 0 || offset + static_cast<int64_t>(bytes) > stream_.Size()) {
        return 0;
      }
      std::memcpy(out, stream_.Memory() + offset, bytes);
      return bytes;
    }
    return 0;
  };

  const auto parse_at = [&](uint32_t rva) -> VmStubInfo {
    uint8_t code[16]{};
    const size_t bytes = rva_bytes(rva, code, sizeof(code));
    if (bytes < 2) {
      return {};
    }
    return ParseVmStub(code, bytes, rva, image_base);
  };

  std::vector<uint32_t> vm_targets;
  const auto add_target = [&](uint32_t rva) {
    if (rva == 0 || rva >= pe_->SizeOfImage()) {
      return;
    }
    if (std::find(vm_targets.begin(), vm_targets.end(), rva) ==
        vm_targets.end()) {
      vm_targets.push_back(rva);
    }
  };
  const auto add_stub_targets = [&](const VmStubInfo& info, uint32_t stub_rva) {
    add_target(stub_rva);
    add_target(info.target_rva);
    add_target(info.context_rva);
    add_target(info.context_rva2);
  };

  // Follow the entry stub: push;jmp / push;push;jmp / jmp/call to a stub.
  if (entry_point != 0) {
    const VmStubInfo entry = parse_at(entry_point);
    if (entry.kind != VmStubKind::kNone) {
      add_stub_targets(entry, entry_point);
      if (entry.kind == VmStubKind::kDirectJump ||
          entry.kind == VmStubKind::kDirectCall ||
          entry.kind == VmStubKind::kShortJump) {
        const VmStubInfo next = parse_at(entry.target_rva);
        if (next.kind != VmStubKind::kNone) {
          add_stub_targets(next, entry.target_rva);
        }
      }
    }
  }

  // Oreans-style reference scan: look for E8/E9 references in the
  // application's code section whose target is a VM entry stub. The final
  // VM target section must survive the shrink.
  if (!pe_->Sections().empty()) {
    const IMAGE_SECTION_HEADER& text = pe_->Sections()[0].header;
    if (text.SizeOfRawData >= 5 &&
        static_cast<int64_t>(text.PointerToRawData) +
                static_cast<int64_t>(text.SizeOfRawData) <=
            stream_.Size()) {
      const uint8_t* data = stream_.Memory() + text.PointerToRawData;
      for (uint32_t offset = 0; offset + 5 <= text.SizeOfRawData; ++offset) {
        if (data[offset] != 0xE8 && data[offset] != 0xE9) {
          continue;
        }
        int32_t displacement = 0;
        std::memcpy(&displacement, data + offset + 1, sizeof(displacement));
        const int64_t target = static_cast<int64_t>(text.VirtualAddress) +
                               offset + 5 + displacement;
        if (target <= 0 || target >= static_cast<int64_t>(pe_->SizeOfImage())) {
          continue;
        }
        VmStubInfo stub = parse_at(static_cast<uint32_t>(target));
        uint32_t stub_rva = static_cast<uint32_t>(target);
        if (stub.kind == VmStubKind::kDirectJump ||
            stub.kind == VmStubKind::kDirectCall ||
            stub.kind == VmStubKind::kShortJump) {
          const VmStubInfo next = parse_at(stub.target_rva);
          if (next.kind != VmStubKind::kNone) {
            stub = next;
            stub_rva = stub.target_rva;
          }
        }
        if (stub.kind == VmStubKind::kPushJump ||
            stub.kind == VmStubKind::kPushPushJump ||
            stub.kind == VmStubKind::kPushRet ||
            stub.kind == VmStubKind::kMovEaxJmp ||
            stub.kind == VmStubKind::kMovRaxJmp) {
          LogF(kLogInfo, "VM entry reference at %X -> %X",
               text.VirtualAddress + offset, stub_rva);
          add_stub_targets(stub, stub_rva);
        }
      }
    }
  }

  const auto contains_vm_target = [&](const IMAGE_SECTION_HEADER& header) {
    for (uint32_t target : vm_targets) {
      if (target >= header.VirtualAddress && target < section_end(header)) {
        return true;
      }
    }
    return false;
  };

  std::vector<int> deleted;
  bool removed_executable = false;
  MemoryStream new_stream;
  stream_.SetPosition(0);
  new_stream.CopyFrom(stream_, pe_->Sections()[0].header.PointerToRawData);

  const int last_index = static_cast<int>(pe_->Sections().size()) - 1;

  // Sections without raw data (.bss in regular PEs) must not be used as a
  // file-layout boundary; their raw pointer is usually zero.
  const auto next_raw_start = [&](int index) -> int64_t {
    for (int j = index + 1; j <= last_index; ++j) {
      const IMAGE_SECTION_HEADER& next =
          pe_->Sections()[static_cast<size_t>(j)].header;
      if (next.SizeOfRawData != 0) {
        return static_cast<int64_t>(next.PointerToRawData);
      }
    }
    return stream_.Size();
  };

  for (int i = 0; i <= last_index; ++i) {
    const IMAGE_SECTION_HEADER& header =
        pe_->Sections()[static_cast<size_t>(i)].header;
    const std::string name = SectionName(header);

    // Keep anything referenced by a data directory, the entry point, and the
    // runtime data that is not covered by a data directory (.CRT, .tls, .bss,
    // .xdata/.pdata, CFG tables). Only code/discardable leftovers should be
    // removed: Themida often renames the app's data sections to spaces, so a
    // name-only rule would delete .rdata/.data/.pdata and break the image.
    const bool protected_by_name =
        name == ".data" || name == ".rdata" || name == ".xdata" ||
        name == ".CRT" || name == ".tls" || name == ".bss" ||
        name == ".gfids" || name == ".00cfg" || name == ".gehcont" ||
        // MapleCreateDataSections names the guard table .vmp for old MSVC.
        name == ".vmp";
    // Custom-named uninitialized-data sections still hold runtime state.
    const bool protected_by_flags =
        (header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
    const bool no_raw_data = header.SizeOfRawData == 0;
    const bool executable =
        (header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool discardable =
        (header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
    const bool removable = executable || discardable;
    const bool vm_target_section = contains_vm_target(header);
    const bool keep = !removable || i == 0 || is_referenced(header) ||
                      contains_entry_point(header) || vm_target_section ||
                      protected_by_name || protected_by_flags || no_raw_data;

    if (!keep) {
      LogF(executable ? kLogWarning : kLogInfo,
           "Removing section [%s] (VA %X, size %X, flags %08X)", name.c_str(),
           header.VirtualAddress, header.Misc.VirtualSize,
           header.Characteristics);
      if (executable) {
        removed_executable = true;
      }
      deleted.push_back(i);
    } else {
      if (contains_entry_point(header) && !is_referenced(header) &&
          !protected_by_name && i != 0) {
        LogF(kLogInfo, "Keeping section [%s]: it contains the entry point.",
             name.c_str());
      }
      if (vm_target_section && !contains_entry_point(header) &&
          !is_referenced(header) && !protected_by_name && !no_raw_data) {
        LogF(kLogWarning,
             "Keeping section [%s]: it is a VM entry/reference target. "
             "Devirtualize before shrinking to remove it.",
             name.c_str());
      }
      if (no_raw_data) {
        continue;
      }

      const int64_t start = static_cast<int64_t>(header.PointerToRawData);
      int64_t end = next_raw_start(i);
      if (end > stream_.Size()) {
        end = stream_.Size();
      }
      if (start < 0 || start >= stream_.Size() || end <= start) {
        continue;
      }
      stream_.Seek(start, Stream::Origin::kBegin);
      new_stream.CopyFrom(stream_, end - start);
    }
  }

  stream_ = std::move(new_stream);

  std::reverse(deleted.begin(), deleted.end());
  for (int index : deleted) {
    pe_->DeleteSection(index);
  }

  if (removed_executable) {
    Log(kLogWarning,
        "Shrink removed executable section(s). If the target no longer "
        "starts, restore the .bak and unvirtualize the target before "
        "shrinking.");
  }
}

void Patcher::ShrinkExportSect() {
  IMAGE_DATA_DIRECTORY* directory =
      &pe_->nt_headers()
           .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (directory->VirtualAddress == 0 || directory->Size == 0) {
    return;
  }

  PESection* export_section = pe_->GetSectionByVA(directory->VirtualAddress);
  if (export_section == nullptr) {
    return;
  }

  // Only compact a dedicated .edata section whose first byte is the export
  // directory. If the directory lives in .rdata (common for MinGW or merged
  // layouts), moving it would overwrite unrelated data.
  const std::string export_section_name = SectionName(export_section->header);
  if (export_section_name != ".edata" ||
      directory->VirtualAddress != export_section->header.VirtualAddress) {
    Log(kLogWarning,
        "Skipping export section compaction: the export directory is not at "
        "the start of a dedicated .edata section.");
    return;
  }

  if (export_section->header.SizeOfRawData < 0x1000 ||
      directory->Size > export_section->header.SizeOfRawData) {
    Log(kLogWarning,
        "Skipping export section compaction: section is too small.");
    return;
  }

  // The compaction below truncates the section to 0x1000 bytes, so it can
  // only be used when the whole export data fits in that window.
  if (directory->Size > 0x1000) {
    Log(kLogWarning,
        "Skipping export section compaction: export data is larger than "
        "0x1000 bytes.");
    return;
  }

  uint8_t* const base =
      stream_.Memory() + export_section->header.PointerToRawData;
  uint8_t* const export_data = base + (directory->VirtualAddress -
                                       export_section->header.VirtualAddress);

  std::memmove(base, export_data, directory->Size);
  if (directory->Size < 0x1000) {
    std::memset(base + directory->Size, 0, 0x1000 - directory->Size);
  }
  directory->VirtualAddress = export_section->header.VirtualAddress;

  uint32_t difference = static_cast<uint32_t>(export_data - base);
  auto* export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base);
  export_directory->Name -= difference;
  export_directory->AddressOfFunctions -= difference;
  export_directory->AddressOfNames -= difference;
  export_directory->AddressOfNameOrdinals -= difference;

  auto* names = reinterpret_cast<uint32_t*>(
      base + (export_directory->AddressOfNames -
              export_section->header.VirtualAddress));
  for (uint32_t i = 0; i < export_directory->NumberOfNames; ++i) {
    names[i] -= difference;
  }

  difference = export_section->header.SizeOfRawData - 0x1000;
  export_section->header.SizeOfRawData -= difference;
  for (PESection& section : pe_->Sections()) {
    if (section.header.VirtualAddress > export_section->header.VirtualAddress) {
      section.header.PointerToRawData -= difference;
    }
  }

  export_section->Rename(".export");
  export_section->header.Characteristics &=
      ~(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);

  stream_.SetPosition(0);
  MemoryStream new_stream;
  new_stream.CopyFrom(stream_,
                      export_section->header.PointerToRawData + 0x1000);
  stream_.Seek(difference, Stream::Origin::kCurrent);
  new_stream.CopyFrom(stream_, stream_.Size() - stream_.Position());
  stream_ = std::move(new_stream);
}

#if !defined(_WIN64)

bool Patcher::MapleCreateDataSections() {
  if (pe_->Sections().size() < 2) {
    Log(kLogFatal, "Data section creation requires at least two sections.");
    return false;
  }

  uint8_t* const memory = stream_.Memory();
  const int64_t stream_size = stream_.Size();

  uintptr_t data_start = 0;
  if (stream_size > 0x2000000) {
    data_start =
        FindStatic("10000000200000004000000060000000", memory + 0x2000000,
                   static_cast<size_t>(stream_size - 0x2000000));
  }

  if (data_start == 0) {
    if (pe_->nt_headers().OptionalHeader.MajorLinkerVersion == 6) {
      data_start = FindDataStartMSVC6();
      if (data_start == 0) {
        throw std::runtime_error("Data section not found");
      }
    } else {
      constexpr uintptr_t kOldOffset = 0xB00000 - 0x400000;
      if (stream_size <= static_cast<int64_t>(kOldOffset)) {
        throw std::runtime_error("Data section not found");
      }
      data_start = FindStatic(
          "2E3F41565F636F6D5F6572726F724040", memory + kOldOffset,
          static_cast<size_t>(stream_size - static_cast<int64_t>(kOldOffset)));
      uintptr_t data_start_tw = FindStatic(
          "2E3F41563F245A4C69737440554D4150494E464F4043416374696F6E4672616D6540"
          "404040",
          memory + kOldOffset,
          static_cast<size_t>(stream_size -
                              static_cast<int64_t>(kOldOffset)));  // TW 122+
      if (data_start_tw != 0 && data_start_tw < data_start) {
        data_start = data_start_tw;
      }

      if (data_start == 0) {
        throw std::runtime_error("Data section not found");
      }

      data_start += kOldOffset - 8;
      if ((data_start & 0xFFF) == 0xB4 || (data_start & 0xFFF) == 0xF8 ||
          (data_start & 0xFFF) == 0xFC) {
        data_start &= 0xFFFFF000;
      }
      Log(kLogInfo, "Old executable");
    }
  } else {
    data_start += 0x2000000;
  }

  if ((data_start & 0xFFF) != 0) {
    throw std::runtime_error(
        Format("Data section bytes found, but not aligned: %llX",
               static_cast<unsigned long long>(data_start)));
  }

  LogF(kLogGood, ".data section at %08llX (VA %08llX)",
       static_cast<unsigned long long>(data_start),
       static_cast<unsigned long long>(data_start + 0x400000));

  pe_->AddSectionToArray();
  pe_->AddSectionToArray();
  {
    auto& sections = pe_->Sections();
    for (int i = static_cast<int>(sections.size()) - 1; i >= 3; --i) {
      sections[static_cast<size_t>(i)] = sections[static_cast<size_t>(i - 2)];
    }
  }

  uintptr_t zero_end = 0;
  uint32_t zero_size = 0;
  bool locked = false;
  uintptr_t address = pe_->Sections()[3].header.PointerToRawData - 1;

  for (;;) {
    if (address < data_start) {
      address = data_start - 1;
      break;
    }

    if (memory[address] == 0) {
      if (zero_size == 0) {
        zero_end = address + 1;
      }
      ++zero_size;
      if (zero_size > 0x2000) {
        locked = true;
      }
    } else {
      if (locked) {
        break;
      }
      zero_size = 0;
    }

    if (address == data_start) {
      address = data_start - 1;
      break;
    }
    --address;
  }
  ++address;

  if (zero_size == 0) {
    throw std::runtime_error("Data section doesn't contain zeroes");
  }

  // Sometimes first byte of following section is 0.
  if ((zero_end & 0xFFF) == 1) {
    --zero_end;
    --zero_size;
  }

  if ((zero_end & 0xFFF) != 0) {
    throw std::runtime_error(
        Format("Real .data section end not found (got %llX with a size of %X)",
               static_cast<unsigned long long>(zero_end), zero_size));
  }

  const uintptr_t zero_start = (address + 0x1000) & 0xFFFFF000;
  zero_size -= static_cast<uint32_t>(zero_start - address);

  const uintptr_t gfids_size =
      pe_->Sections()[3].header.PointerToRawData - zero_end;

  // .data
  uintptr_t data_size =
      pe_->Sections()[3].header.PointerToRawData - data_start - gfids_size;
  PESection& data_section = pe_->Sections()[2];
  data_section = PESection{};
  data_section.Rename(".data");
  data_section.header.Misc.VirtualSize = static_cast<uint32_t>(data_size);
  data_section.header.VirtualAddress = static_cast<uint32_t>(data_start);
  data_section.header.PointerToRawData = static_cast<uint32_t>(data_start);
  data_section.header.SizeOfRawData =
      static_cast<uint32_t>(data_size - zero_size);
  data_section.header.Characteristics =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

  // .rdata
  const uintptr_t rdata_start = pe_->nt_headers().OptionalHeader.BaseOfData;
  const uintptr_t rdata_size = data_start - rdata_start;
  PESection& rdata_section = pe_->Sections()[1];
  rdata_section = PESection{};
  rdata_section.Rename(".rdata");
  rdata_section.header.Misc.VirtualSize = static_cast<uint32_t>(rdata_size);
  rdata_section.header.VirtualAddress = static_cast<uint32_t>(rdata_start);
  rdata_section.header.PointerToRawData = static_cast<uint32_t>(rdata_start);
  rdata_section.header.SizeOfRawData = static_cast<uint32_t>(rdata_size);
  rdata_section.header.Characteristics =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

  // .gfids/.vmp
  if (gfids_size != 0) {
    pe_->AddSectionToArray();
    {
      auto& sections = pe_->Sections();
      for (int i = static_cast<int>(sections.size()) - 1; i >= 4; --i) {
        sections[static_cast<size_t>(i)] = sections[static_cast<size_t>(i - 1)];
      }
    }

    const bool msvc2015 =
        pe_->nt_headers().OptionalHeader.MajorLinkerVersion >= 14;
    PESection& gfids_section = pe_->Sections()[3];
    gfids_section = PESection{};
    gfids_section.Rename(msvc2015 ? ".gfids" : ".vmp");
    gfids_section.header.Misc.VirtualSize = static_cast<uint32_t>(gfids_size);
    gfids_section.header.VirtualAddress = static_cast<uint32_t>(zero_end);
    gfids_section.header.PointerToRawData = static_cast<uint32_t>(zero_end);
    gfids_section.header.SizeOfRawData = static_cast<uint32_t>(gfids_size);
    gfids_section.header.Characteristics = IMAGE_SCN_MEM_READ |
                                           IMAGE_SCN_MEM_WRITE |
                                           IMAGE_SCN_CNT_INITIALIZED_DATA;

    pe_->nt_headers().FileHeader.NumberOfSections += 3;
  } else {
    if (pe_->nt_headers().OptionalHeader.MajorLinkerVersion >= 14) {
      Log(kLogFatal, ".gfids not found");
    }
    pe_->nt_headers().FileHeader.NumberOfSections += 2;
  }

  pe_->Sections()[0].header.Misc.VirtualSize -=
      static_cast<uint32_t>(rdata_size + data_size + gfids_size);
  pe_->Sections()[0].header.SizeOfRawData -=
      static_cast<uint32_t>(rdata_size + data_size + gfids_size);

  pe_->Sections()[0].Rename(".text");
  pe_->Sections()[0].header.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
  return true;
}

uintptr_t Patcher::FindDataStartMSVC6() {
  // In MSVC6 binaries, the second (r/w) data section appears to start with the
  // __cinit func list.
  const int64_t stream_size = stream_.Size();
  if (stream_size <= 0x100000) {
    return 0;
  }

  uint8_t* const memory = stream_.Memory();
  uint32_t c_init_code =
      FindDynamic("68????????68??????00E8????????83C410C3", memory + 0x100000,
                  static_cast<size_t>(stream_size - 0x100000));
  if (c_init_code == 0) {
    return 0;
  }

  c_init_code += 0x100000;
  uintptr_t result =
      *reinterpret_cast<const uint32_t*>(memory + c_init_code + 6);
  if ((result & 0xFFF) != 0) {
    result = 0;
  } else {
    result -= pe_->nt_headers().OptionalHeader.ImageBase;
  }
  return result;
}

bool Patcher::FindDynTLSMSVC14(uintptr_t& dyn_tls_init) {
  // call    __scrt_get_dyn_tls_init_callback
  // mov     esi, eax
  // xor     edi, edi
  // cmp     [esi], edi
  // jz      short ??
  // push    esi
  // call    __scrt_is_nonwritable_in_current_image
  const int64_t stream_size = stream_.Size();
  if (stream_size <= 0x1000) {
    return false;
  }

  uint8_t* const memory = stream_.Memory();
  uint32_t dyn_tls_code =
      FindDynamic("8BF033FF393E74??56E8", memory + 0x1000,
                  static_cast<size_t>(stream_size - 0x1000));
  if (dyn_tls_code == 0) {
    Log(kLogInfo, "DynTLS code sequence not found.");
    return false;
  }

  uint8_t* code_ptr = memory + 0x1000 + dyn_tls_code;
  if (*(code_ptr - 5) != 0xE8) {
    Log(kLogInfo, "DynTLS code sequence mismatch.");
    return false;
  }

  uint8_t* get_ptr_func =
      code_ptr + *reinterpret_cast<const int32_t*>(code_ptr - 4);
  if (*get_ptr_func == 0xE9) {  // another indirection via jmp
    get_ptr_func =
        get_ptr_func + *reinterpret_cast<const int32_t*>(get_ptr_func + 1) + 5;
  }
  if (*get_ptr_func != 0xB8) {
    Log(kLogInfo, "DynTLS call analysis failed.");
    return false;
  }

  dyn_tls_init = *reinterpret_cast<const uint32_t*>(get_ptr_func + 1) -
                 pe_->nt_headers().OptionalHeader.ImageBase;
  uint8_t* dyn_tls_init_ptr = memory + dyn_tls_init;

  LogF(kLogInfo, "[MSVC] dyn_tls_init at %.8X",
       *reinterpret_cast<const uint32_t*>(dyn_tls_init_ptr));

  // If the function pointer points to 0, the compiler places this var in a
  // writable section and we can't use it as a separator.
  if (*reinterpret_cast<const uint32_t*>(dyn_tls_init_ptr) == 0) {
    dyn_tls_init = 0;
  }

  return true;
}

bool Patcher::MSVCCreateDataSections() {
  if (pe_->Sections().size() < 2) {
    Log(kLogFatal, "Data section creation requires at least two sections.");
    return false;
  }

  const uint32_t base_of_data = pe_->nt_headers().OptionalHeader.BaseOfData;
  if (!(base_of_data > pe_->Sections()[0].header.VirtualAddress &&
        base_of_data < pe_->Sections()[0].header.VirtualAddress +
                           pe_->Sections()[0].header.Misc.VirtualSize &&
        (base_of_data & 0xFFF) == 0)) {
    Log(kLogInfo, "Assuming sections are not merged.");
    return false;
  }

  {
    uintptr_t dyn_tls = 0;
    if (!FindDynTLSMSVC14(dyn_tls)) {
      return false;
    }

    // This is by no means exact. We keep the writable data section as large
    // as possible because we can't determine its real size in a generic way
    // and we don't want to risk access violations.
    uint32_t data_start = 0;
    if (dyn_tls != 0) {
      data_start = static_cast<uint32_t>((dyn_tls + 0x1000) & ~0xFFFull);
    } else {
      data_start = base_of_data + 0x1000;
      Log(kLogInfo,
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

    pe_->nt_headers().FileHeader.NumberOfSections += 2;

    // .data at [2]
    const uint32_t data_size =
        pe_->Sections()[3].header.PointerToRawData - data_start;
    PESection& data_section = pe_->Sections()[2];
    data_section = PESection{};
    data_section.Rename(".data");
    data_section.header.Misc.VirtualSize = data_size;
    data_section.header.VirtualAddress = data_start;
    data_section.header.PointerToRawData = data_start;
    data_section.header.SizeOfRawData = data_size;
    data_section.header.Characteristics = IMAGE_SCN_MEM_READ |
                                          IMAGE_SCN_MEM_WRITE |
                                          IMAGE_SCN_CNT_INITIALIZED_DATA;

    // .rdata at [1]
    const uint32_t rdata_start = base_of_data;
    const uint32_t rdata_size = data_start - rdata_start;
    PESection& rdata_section = pe_->Sections()[1];
    rdata_section = PESection{};
    rdata_section.Rename(".rdata");
    rdata_section.header.Misc.VirtualSize = rdata_size;
    rdata_section.header.VirtualAddress = rdata_start;
    rdata_section.header.PointerToRawData = rdata_start;
    rdata_section.header.SizeOfRawData = rdata_size;
    rdata_section.header.Characteristics =
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

    pe_->Sections()[0].header.Misc.VirtualSize -= rdata_size + data_size;
    pe_->Sections()[0].header.SizeOfRawData -= rdata_size + data_size;

    for (int i = 0; i < 3; ++i) {
      const IMAGE_SECTION_HEADER& header =
          pe_->Sections()[static_cast<size_t>(i)].header;
      LogF(kLogInfo, "%s: %.8x ~ %.8x", SectionName(header).c_str(),
           header.VirtualAddress,
           header.VirtualAddress + header.Misc.VirtualSize);
    }
  }

  // Rename first section and remove WRITE characteristic.
  pe_->Sections()[0].Rename(".text");
  pe_->Sections()[0].header.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
  return true;
}

#else

bool Patcher::MapleCreateDataSections() {
  throw std::runtime_error(
      "Data section creation is not available for 64-bit binaries.");
}

uintptr_t Patcher::FindDataStartMSVC6() {
  return 0;
}

bool Patcher::FindDynTLSMSVC14(uintptr_t& /*dynTlsInit*/) {
  return false;
}

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
  uintptr_t image_base =
      static_cast<uintptr_t>(pe_->nt_headers().OptionalHeader.ImageBase);

  // The file's ImageBase is only a hint: the live process may have been
  // relocated (ASLR or an occupied base). Find the module by name and use its
  // real base instead.
  const std::wstring module_file_name = ExtractFileName(file_name_);
  const std::string target_name = AsciiLowerCase(WideToUtf8(module_file_name));
  bool module_found = false;

  HMODULE modules[1024]{};
  DWORD needed = 0;
  if (EnumProcessModules(process, modules, sizeof(modules), &needed)) {
    const size_t count =
        std::min<size_t>(needed / sizeof(HMODULE), _countof(modules));
    for (size_t i = 0; i < count; ++i) {
      wchar_t module_name[MAX_PATH]{};
      if (GetModuleBaseNameW(process, modules[i], module_name,
                             _countof(module_name)) == 0) {
        continue;
      }
      if (AsciiLowerCase(WideToUtf8(module_name)) == target_name) {
        image_base = reinterpret_cast<uintptr_t>(modules[i]);
        module_found = true;
        break;
      }
    }
  }

  if (module_found) {
    LogF(kLogInfo, "Using live module base %llX for %s",
         static_cast<unsigned long long>(image_base),
         WideToUtf8(module_file_name).c_str());
  } else {
    LogF(kLogWarning,
         "Module %s not found in the process; using the header ImageBase "
         "%llX",
         WideToUtf8(module_file_name).c_str(),
         static_cast<unsigned long long>(image_base));
  }

  const uintptr_t start_address =
      image_base + pe_->Sections()[0].header.VirtualAddress;
  const uintptr_t end_address =
      image_base + pe_->nt_headers().OptionalHeader.BaseOfData;
  if (end_address <= start_address) {
    throw std::runtime_error("Invalid code range in the PE header.");
  }

  std::vector<uint8_t> buffer(static_cast<size_t>(end_address - start_address));
  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(process, reinterpret_cast<void*>(start_address),
                         buffer.data(), buffer.size(), &bytes_read) ||
      bytes_read != buffer.size()) {
    throw std::runtime_error(
        Format("ReadProcessMemory failed (error %lu)", GetLastError()));
  }

  stream_.Seek(pe_->Sections()[0].header.PointerToRawData,
               Stream::Origin::kBegin);
  stream_.Write(buffer.data(), buffer.size());
  stream_.SaveToFile(ChangeFileExt(file_name_, L".novm.exe"));

  LogF(kLogGood, "Dumped %llX bytes.",
       static_cast<unsigned long long>(buffer.size()));
#endif
}

void NormalizePEFile(const std::wstring& file_name) {
  Patcher patcher(file_name);
  patcher.NormalizeLayout();
}

}  // namespace magicmida
