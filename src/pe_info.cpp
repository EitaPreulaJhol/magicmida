// Magicmida - C++ port
// PE header manipulation (ported from PEInfo.pas).
#include "pe_info.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

namespace magicmida {
namespace {

std::string SectionName(const IMAGE_SECTION_HEADER& header) {
  char name[9]{};
  std::memcpy(name, header.Name, 8);
  return std::string(name);
}

}  // namespace

// --------------------------------------------------------------------------
// PESection
// --------------------------------------------------------------------------

void PESection::Rename(std::string_view newName) {
  const size_t count = std::min(newName.size(), sizeof(header.Name));
  std::memcpy(header.Name, newName.data(), count);
  if (count < sizeof(header.Name)) {
    std::memset(header.Name + count, 0, sizeof(header.Name) - count);
  }
}

// --------------------------------------------------------------------------
// PEHeader
// --------------------------------------------------------------------------

PEHeader::PEHeader(const uint8_t* data, size_t bufferSize) {
  if (data == nullptr || bufferSize < sizeof(IMAGE_DOS_HEADER)) {
    throw std::runtime_error("PEHeader: buffer too small for a DOS header");
  }

  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
  lfa_new_ = static_cast<uint32_t>(dos->e_lfanew);
  if (static_cast<uint64_t>(lfa_new_) + sizeof(IMAGE_NT_HEADERS) > bufferSize) {
    throw std::runtime_error("PEHeader: truncated NT headers");
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + lfa_new_);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("PEHeader: signature mismatch");
  }
  ntHeaders = *nt;
  dump_size_ = ntHeaders.OptionalHeader.SizeOfImage;

  const uint64_t sectionOffset =
      static_cast<uint64_t>(lfa_new_) + sizeof(IMAGE_NT_HEADERS);
  const uint64_t sectionBytes =
      static_cast<uint64_t>(ntHeaders.FileHeader.NumberOfSections) *
      sizeof(IMAGE_SECTION_HEADER);
  if (sectionOffset + sectionBytes > bufferSize) {
    throw std::runtime_error("PEHeader: truncated section table");
  }

  const auto* section =
      reinterpret_cast<const IMAGE_SECTION_HEADER*>(data + sectionOffset);
  sections_.resize(ntHeaders.FileHeader.NumberOfSections);
  if (sections_.empty()) {
    throw std::runtime_error("PEHeader: PE has no sections");
  }
  for (size_t i = 0; i < sections_.size(); ++i) {
    sections_[i].header = section[i];
  }
}

PESection* PEHeader::CreateSection(const std::string& name, uint32_t size) {
  if (sections_.empty()) {
    throw std::runtime_error("CreateSection: PE has no sections");
  }

  const IMAGE_SECTION_HEADER previous = sections_.back().header;
  sections_.emplace_back();
  PESection& result = sections_.back();

  std::memcpy(result.header.Name, name.data(),
              std::min(name.size(), sizeof(result.header.Name)));

  result.header.Misc.VirtualSize = size;
  result.header.VirtualAddress =
      previous.VirtualAddress + previous.Misc.VirtualSize;
  SectionAlign(result.header.VirtualAddress);
  result.header.PointerToRawData = ntHeaders.OptionalHeader.SizeOfImage;
  result.header.SizeOfRawData = size;
  result.header.Characteristics =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;

  ntHeaders.OptionalHeader.SizeOfImage += size;
  // NumberOfSections is handled by the dumper.
  return &result;
}

void PEHeader::DeleteSection(int index) {
  if (index <= 0 || index >= static_cast<int>(sections_.size())) {
    return;
  }

  const bool isLast = index == static_cast<int>(sections_.size()) - 1;
  uint32_t size = 0;

  if (isLast) {
    size = ntHeaders.OptionalHeader.SizeOfImage -
           sections_[index].header.SizeOfRawData;
  } else {
    // Use the next section with raw data as the file-layout boundary;
    // zero-raw sections (.bss in regular PEs) usually have PointerToRawData 0.
    uint32_t nextRaw = 0;
    for (int i = index + 1; i < static_cast<int>(sections_.size()); ++i) {
      if (sections_[i].header.SizeOfRawData != 0) {
        nextRaw = sections_[i].header.PointerToRawData;
        break;
      }
    }
    const uint32_t currentRaw = sections_[index].header.PointerToRawData;
    size = nextRaw > currentRaw ? nextRaw - currentRaw
                                : sections_[index].header.SizeOfRawData;
  }

  for (int i = static_cast<int>(sections_.size()) - 1; i >= index + 1; --i) {
    if (sections_[i].header.SizeOfRawData == 0) {
      continue;  // Keep the conventional zero raw pointer.
    }
    sections_[i].header.PointerToRawData -= size;
  }

  sections_[index - 1].header.Misc.VirtualSize +=
      sections_[index].header.Misc.VirtualSize;
  SectionAlign(sections_[index - 1].header.Misc.VirtualSize);

  if (!isLast) {
    std::move(sections_.begin() + index + 1, sections_.end(),
              sections_.begin() + index);
  }

  sections_.pop_back();
  --ntHeaders.FileHeader.NumberOfSections;
}

PESection* PEHeader::GetSectionByVA(uint32_t va) {
  for (PESection& section : sections_) {
    if (section.header.VirtualAddress + section.header.Misc.VirtualSize > va) {
      return &section;
    }
  }
  return nullptr;
}

void PEHeader::Sanitize() {
  for (PESection& section : sections_) {
    section.header.PointerToRawData = section.header.VirtualAddress;
    section.header.SizeOfRawData = section.header.Misc.VirtualSize;
  }

  if (!sections_.empty()) {
    ntHeaders.OptionalHeader.SizeOfHeaders =
        sections_[0].header.PointerToRawData;
#if !defined(_WIN64)
    // 32-bit packers sometimes merge .text/.data and clear WRITE from the
    // header; keep the old workaround there. On x64 a forced W+X .text is a
    // dump fingerprint, so preserve the original characteristics.
    sections_[0].header.Characteristics |= IMAGE_SCN_MEM_WRITE;
#endif
  }
}

void PEHeader::SaveToStream(Stream& stream) {
  stream.Seek(lfa_new_, Stream::Origin::kBegin);
  stream.Write(&ntHeaders, sizeof(ntHeaders));
  for (const PESection& section : sections_) {
    stream.Write(&section.header, sizeof(IMAGE_SECTION_HEADER));
  }

  // Zero out some leftovers that may be in the header.
  uint8_t zeros[0x200]{};
  stream.Write(zeros, sizeof(zeros));
}

uint32_t PEHeader::TrimHugeSections(uint8_t* buf, uint32_t& iatRawAddr) {
  uint32_t result = 0;

  for (uint32_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
    const uint32_t sectionStart = sections_[i].header.PointerToRawData;
    // Do not trust the header blindly: the raw range must lie inside the
    // dumped image.
    const uint32_t available =
        sectionStart < dump_size_ ? dump_size_ - sectionStart : 0;
    const uint32_t scanSize = std::min<uint32_t>(
        static_cast<uint32_t>(sections_[i].header.SizeOfRawData), available);
    int zeroStart = -1;

    for (int j = static_cast<int>(scanSize / 4) - 1; j >= 0; --j) {
      if (*reinterpret_cast<uint32_t*>(buf + sectionStart +
                                       static_cast<uint32_t>(j) * 4) == 0) {
        zeroStart = j * 4;
      } else {
        break;
      }
    }

    // We could reduce every single section to its minimal raw size, but having
    // file offset == RVA is pretty convenient, so we only trim sections that
    // were obviously bloated up.
    if (zeroStart != -1 &&
        sections_[i].header.SizeOfRawData - static_cast<uint32_t>(zeroStart) >
            1u * 1024 * 1024) {
      uint32_t oldSectionSize = sections_[i].header.SizeOfRawData;
      SectionAlign(oldSectionSize);  // Sanitize() aligned the actual size.
      if (static_cast<uint64_t>(sectionStart) + oldSectionSize > dump_size_) {
        continue;  // Malformed section; leave it untouched.
      }

      uint32_t newSectionSize = static_cast<uint32_t>(zeroStart);
      FileAlign(newSectionSize);
      LogF(kLogInfo, "Reducing size of section [%s]: %X -> %X",
           SectionName(sections_[i].header).c_str(), oldSectionSize,
           newSectionSize);

      const uint32_t delta = oldSectionSize - newSectionSize;
      result += delta;
      sections_[i].header.SizeOfRawData = newSectionSize;

      if (i < sections_.size() - 1) {
        const uint32_t nextRaw = sections_[i + 1].header.PointerToRawData;
        const uint32_t moveSize =
            nextRaw < dump_size_ ? dump_size_ - nextRaw : 0;
        if (nextRaw >= sectionStart + newSectionSize) {
          std::memmove(buf + sectionStart + newSectionSize, buf + nextRaw,
                       moveSize);
        }
        for (size_t j = i + 1; j < sections_.size(); ++j) {
          sections_[j].header.PointerToRawData -= delta;
        }
      }

      if (iatRawAddr >= sectionStart + oldSectionSize) {
        iatRawAddr -= delta;
      }
    }
  }

  return result;
}

void PEHeader::AddSectionToArray() {
  sections_.emplace_back();
}

uint32_t PEHeader::ConvertOffsetToRVAVector(uintptr_t offset) const {
  for (const PESection& section : sections_) {
    if (section.header.PointerToRawData <= offset &&
        static_cast<uintptr_t>(section.header.PointerToRawData) +
                section.header.SizeOfRawData >
            offset) {
      return static_cast<uint32_t>(offset - section.header.PointerToRawData) +
             section.header.VirtualAddress;
    }
  }
  return 0;
}

}  // namespace magicmida
