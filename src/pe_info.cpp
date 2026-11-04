// Magicmida - C++ port
// PE header manipulation (ported from PEInfo.pas).
#include "pe_info.h"

#include <algorithm>
#include <cstring>

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
  const size_t count = std::min(newName.size(), sizeof(Header.Name));
  std::memcpy(Header.Name, newName.data(), count);
  if (count < sizeof(Header.Name)) {
    std::memset(Header.Name + count, 0, sizeof(Header.Name) - count);
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
  lfaNew_ = static_cast<uint32_t>(dos->e_lfanew);
  if (static_cast<uint64_t>(lfaNew_) + sizeof(IMAGE_NT_HEADERS) > bufferSize) {
    throw std::runtime_error("PEHeader: truncated NT headers");
  }

  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(data + lfaNew_);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    throw std::runtime_error("PEHeader: signature mismatch");
  }
  ntHeaders = *nt;
  dumpSize_ = ntHeaders.OptionalHeader.SizeOfImage;

  const uint64_t sectionOffset =
      static_cast<uint64_t>(lfaNew_) + sizeof(IMAGE_NT_HEADERS);
  const uint64_t sectionBytes =
      static_cast<uint64_t>(ntHeaders.FileHeader.NumberOfSections) *
      sizeof(IMAGE_SECTION_HEADER);
  if (sectionOffset + sectionBytes > bufferSize) {
    throw std::runtime_error("PEHeader: truncated section table");
  }

  const auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
      data + sectionOffset);
  sections_.resize(ntHeaders.FileHeader.NumberOfSections);
  for (size_t i = 0; i < sections_.size(); ++i) {
    sections_[i].Header = section[i];
  }
}

PESection* PEHeader::CreateSection(const std::string& name, uint32_t size) {
  if (sections_.empty()) {
    throw std::runtime_error("CreateSection: PE has no sections");
  }

  const IMAGE_SECTION_HEADER previous = sections_.back().Header;
  sections_.emplace_back();
  PESection& result = sections_.back();

  std::memcpy(result.Header.Name, name.data(),
              std::min(name.size(), sizeof(result.Header.Name)));

  result.Header.Misc.VirtualSize = size;
  result.Header.VirtualAddress =
      previous.VirtualAddress + previous.Misc.VirtualSize;
  SectionAlign(result.Header.VirtualAddress);
  result.Header.PointerToRawData = ntHeaders.OptionalHeader.SizeOfImage;
  result.Header.SizeOfRawData = size;
  result.Header.Characteristics =
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
           sections_[index].Header.SizeOfRawData;
  } else {
    size = sections_[index + 1].Header.PointerToRawData -
           sections_[index].Header.PointerToRawData;
  }

  for (int i = static_cast<int>(sections_.size()) - 1; i >= index + 1; --i) {
    sections_[i].Header.PointerToRawData -= size;
  }

  sections_[index - 1].Header.Misc.VirtualSize +=
      sections_[index].Header.Misc.VirtualSize;
  SectionAlign(sections_[index - 1].Header.Misc.VirtualSize);

  if (!isLast) {
    std::move(sections_.begin() + index + 1, sections_.end(),
              sections_.begin() + index);
  }

  sections_.pop_back();
  --ntHeaders.FileHeader.NumberOfSections;
}

PESection* PEHeader::GetSectionByVA(uint32_t va) {
  for (PESection& section : sections_) {
    if (section.Header.VirtualAddress + section.Header.Misc.VirtualSize > va) {
      return &section;
    }
  }
  return nullptr;
}

void PEHeader::Sanitize() {
  for (PESection& section : sections_) {
    section.Header.PointerToRawData = section.Header.VirtualAddress;
    section.Header.SizeOfRawData = section.Header.Misc.VirtualSize;
  }

  if (!sections_.empty()) {
    ntHeaders.OptionalHeader.SizeOfHeaders = sections_[0].Header.PointerToRawData;
    // Must have write access in the code section (in case .text and .data
    // were merged).
    sections_[0].Header.Characteristics |= IMAGE_SCN_MEM_WRITE;
  }
}

void PEHeader::SaveToStream(Stream& stream) {
  stream.Seek(lfaNew_, Stream::Origin::Begin);
  stream.Write(&ntHeaders, sizeof(ntHeaders));
  for (const PESection& section : sections_) {
    stream.Write(&section.Header, sizeof(IMAGE_SECTION_HEADER));
  }

  // Zero out some leftovers that may be in the header.
  uint8_t zeros[0x200]{};
  stream.Write(zeros, sizeof(zeros));
}

uint32_t PEHeader::TrimHugeSections(uint8_t* buf, uint32_t& iatRawAddr) {
  uint32_t result = 0;

  for (uint32_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
    const uint32_t sectionStart = sections_[i].Header.PointerToRawData;
    int zeroStart = -1;

    for (int j = static_cast<int>(sections_[i].Header.SizeOfRawData / 4) - 1;
         j >= 0; --j) {
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
        sections_[i].Header.SizeOfRawData - static_cast<uint32_t>(zeroStart) >
            1u * 1024 * 1024) {
      uint32_t oldSectionSize = sections_[i].Header.SizeOfRawData;
      SectionAlign(oldSectionSize);  // Sanitize() aligned the actual size.

      uint32_t newSectionSize = static_cast<uint32_t>(zeroStart);
      FileAlign(newSectionSize);
      LogF(ltInfo, "Reducing size of section [%s]: %X -> %X",
           SectionName(sections_[i].Header).c_str(), oldSectionSize,
           newSectionSize);

      const uint32_t delta = oldSectionSize - newSectionSize;
      result += delta;
      sections_[i].Header.SizeOfRawData = newSectionSize;

      if (i < sections_.size() - 1) {
        std::memmove(buf + sectionStart + newSectionSize,
                     buf + sections_[i + 1].Header.PointerToRawData,
                     dumpSize_ - sectionStart - oldSectionSize);
        for (size_t j = i + 1; j < sections_.size(); ++j) {
          sections_[j].Header.PointerToRawData -= delta;
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
    if (section.Header.PointerToRawData <= offset &&
        static_cast<uintptr_t>(section.Header.PointerToRawData) +
                section.Header.SizeOfRawData >
            offset) {
      return static_cast<uint32_t>(offset - section.Header.PointerToRawData) +
             section.Header.VirtualAddress;
    }
  }
  return 0;
}

}  // namespace magicmida
