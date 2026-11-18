// Magicmida - C++ port
// PE header manipulation (ported from PEInfo.pas).
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_PE_INFO_H_
#define MAGICMIDA_PE_INFO_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "common.h"
#include "stream.h"

namespace magicmida {

struct PeSection {
  IMAGE_SECTION_HEADER header{};
  // Only populated for sections synthesized by the dumper (e.g. .import).
  std::vector<uint8_t> data;

  void Rename(std::string_view new_name);
};

class PeHeader {
 public:
  // `data` must point to a buffer containing at least a complete PE header
  // (DOS header + NT headers + section table). `buffer_size` is used to
  // validate the section table; pass the real buffer size whenever possible.
  explicit PeHeader(const uint8_t* data,
                    size_t buffer_size = static_cast<size_t>(-1));

  PeSection* CreateSection(const std::string& name, uint32_t size);
  void DeleteSection(int index);
  PeSection* GetSectionByVa(uint32_t va);

  // Adds an uninitialized entry at the end of the section table.
  void AddSectionToArray();

  uint32_t ConvertOffsetToRvaVector(uintptr_t offset) const;

  // Trims bloated (zero-padded) sections and returns the number of bytes
  // removed. `iat_raw_addr` is adjusted if it lies behind a trimmed section.
  uint32_t TrimHugeSections(uint8_t* buf, uint32_t& iat_raw_addr);

  void Sanitize();
  void SaveToStream(Stream& stream);

  template <typename T>
  void FileAlign(T& value) const {
    const uint32_t alignment = nt_headers_.OptionalHeader.FileAlignment;
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
    const uint32_t alignment = nt_headers_.OptionalHeader.SectionAlignment;
    if (alignment == 0) {
      return;
    }
    const uint32_t delta = static_cast<uint32_t>(value) % alignment;
    if (delta > 0) {
      value = static_cast<T>(value + alignment - delta);
    }
  }

  std::vector<PeSection>& Sections() { return sections_; }
  const std::vector<PeSection>& Sections() const { return sections_; }

  IMAGE_NT_HEADERS& nt_headers() { return nt_headers_; }
  const IMAGE_NT_HEADERS& nt_headers() const { return nt_headers_; }

  uint32_t LfaNew() const { return lfa_new_; }
  uint32_t DumpSize() const { return dump_size_; }
  uint32_t SizeOfImage() const {
    return nt_headers_.OptionalHeader.SizeOfImage;
  }

 private:
  IMAGE_NT_HEADERS nt_headers_{};
  std::vector<PeSection> sections_;
  uint32_t dump_size_ = 0;
  uint32_t lfa_new_ = 0;
};

}  // namespace magicmida

#endif  // MAGICMIDA_PE_INFO_H_
