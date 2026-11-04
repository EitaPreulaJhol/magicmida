// Magicmida - C++ port
// PE header manipulation (ported from PEInfo.pas).
#pragma once

#include "common.h"
#include "stream.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace magicmida {

struct PESection {
  IMAGE_SECTION_HEADER Header{};
  // Only populated for sections synthesized by the dumper (e.g. .import).
  std::vector<uint8_t> Data;

  void Rename(std::string_view newName);
};

class PEHeader {
 public:
  // `data` must point to a buffer containing at least a complete PE header
  // (DOS header + NT headers + section table). `bufferSize` is used to
  // validate the section table; pass the real buffer size whenever possible.
  explicit PEHeader(const uint8_t* data,
                    size_t bufferSize = static_cast<size_t>(-1));

  PESection* CreateSection(const std::string& name, uint32_t size);
  void DeleteSection(int index);
  PESection* GetSectionByVA(uint32_t va);

  // Adds an uninitialized entry at the end of the section table.
  void AddSectionToArray();

  uint32_t ConvertOffsetToRVAVector(uintptr_t offset) const;

  // Trims bloated (zero-padded) sections and returns the number of bytes
  // removed. `iatRawAddr` is adjusted if it lies behind a trimmed section.
  uint32_t TrimHugeSections(uint8_t* buf, uint32_t& iatRawAddr);

  void Sanitize();
  void SaveToStream(Stream& stream);

  template <typename T>
  void FileAlign(T& value) const {
    const uint32_t alignment = ntHeaders.OptionalHeader.FileAlignment;
    if (alignment == 0) {
      return;
    }
    const uint32_t delta = static_cast<uint32_t>(value) % alignment;
    if (delta > 0) {
      value = static_cast<T>(value + alignment - delta);
    }
  }

  template <typename T>
  void SectionAlign(T& value) const {
    const uint32_t alignment = ntHeaders.OptionalHeader.SectionAlignment;
    if (alignment == 0) {
      return;
    }
    const uint32_t delta = static_cast<uint32_t>(value) % alignment;
    if (delta > 0) {
      value = static_cast<T>(value + alignment - delta);
    }
  }

  std::vector<PESection>& Sections() { return sections_; }
  const std::vector<PESection>& Sections() const { return sections_; }

  uint32_t LFANew() const { return lfaNew_; }
  uint32_t DumpSize() const { return dumpSize_; }
  uint32_t SizeOfImage() const { return ntHeaders.OptionalHeader.SizeOfImage; }

  IMAGE_NT_HEADERS ntHeaders{};

 private:
  std::vector<PESection> sections_;
  uint32_t dumpSize_ = 0;
  uint32_t lfaNew_ = 0;
};

}  // namespace magicmida
