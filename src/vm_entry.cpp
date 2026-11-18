// Magicmida - C++ port
// Recognition of Oreans/Themida/WinLicense virtual-machine entry stubs.
#include "vm_entry.h"

#include <cstring>

namespace magicmida {
namespace {

template <typename T>
T Read(const uint8_t* code, size_t offset) {
  T value{};
  std::memcpy(&value, code + offset, sizeof(value));
  return value;
}

uint32_t ToRva(uint64_t value, uint64_t image_base) {
  if (value < image_base) {
    return 0;
  }
  const uint64_t rva = value - image_base;
  return rva <= 0xFFFFFFFFull ? static_cast<uint32_t>(rva) : 0;
}

}  // namespace

VmStubInfo ParseVmStub(const uint8_t* code, size_t size, uint32_t stubRva,
                       uint64_t image_base) {
  VmStubInfo info;
  if (code == nullptr || size < 2) {
    return info;
  }

  const auto direct = [&](VmStubKind kind, size_t instruction_size,
                          int32_t displacement, uint32_t operandBias) {
    info.kind = kind;
    info.instruction_size = static_cast<uint32_t>(instruction_size);
    const int64_t target =
        static_cast<int64_t>(stubRva) + operandBias + displacement;
    if (target > 0) {
      info.target_rva = static_cast<uint32_t>(target);
    }
  };

  switch (code[0]) {
    case 0xE9:
      if (size >= 5) {
        direct(VmStubKind::kDirectJump, 5, Read<int32_t>(code, 1), 5);
      }
      return info;
    case 0xE8:
      if (size >= 5) {
        direct(VmStubKind::kDirectCall, 5, Read<int32_t>(code, 1), 5);
      }
      return info;
    case 0xEB:
      if (size >= 2) {
        direct(VmStubKind::kShortJump, 2, Read<int8_t>(code, 1), 2);
      }
      return info;
    case 0x68:
      break;
    case 0xB8:
      if (size >= 7 && code[5] == 0xFF && code[6] == 0xE0) {
        info.kind = VmStubKind::kMovEaxJmp;
        info.instruction_size = 7;
        info.target_rva = ToRva(Read<uint32_t>(code, 1), image_base);
        info.context_rva = info.target_rva;
      }
      return info;
    case 0x48:
      if (size >= 12 && code[1] == 0xB8 && code[10] == 0xFF &&
          code[11] == 0xE0) {
        info.kind = VmStubKind::kMovRaxJmp;
        info.instruction_size = 12;
        info.target_rva = ToRva(Read<uint64_t>(code, 2), image_base);
        info.context_rva = info.target_rva;
      }
      return info;
    default:
      return info;
  }

  // 0x68 (push imm32) forms.
  if (size >= 6 && code[5] == 0xC3) {
    info.kind = VmStubKind::kPushRet;
    info.instruction_size = 6;
    info.target_rva = ToRva(Read<uint32_t>(code, 1), image_base);
    info.context_rva = info.target_rva;
    return info;
  }
  if (size >= 10 && code[5] == 0xE9) {
    info.kind = VmStubKind::kPushJump;
    info.instruction_size = 10;
    const int64_t target =
        static_cast<int64_t>(stubRva) + 10 + Read<int32_t>(code, 6);
    if (target > 0) {
      info.target_rva = static_cast<uint32_t>(target);
    }
    info.context_rva = ToRva(Read<uint32_t>(code, 1), image_base);
    return info;
  }
  if (size >= 15 && code[5] == 0x68 && code[10] == 0xE9) {
    info.kind = VmStubKind::kPushPushJump;
    info.instruction_size = 15;
    const int64_t target =
        static_cast<int64_t>(stubRva) + 15 + Read<int32_t>(code, 11);
    if (target > 0) {
      info.target_rva = static_cast<uint32_t>(target);
    }
    info.context_rva = ToRva(Read<uint32_t>(code, 1), image_base);
    info.context_rva2 = ToRva(Read<uint32_t>(code, 6), image_base);
    return info;
  }

  return info;
}

}  // namespace magicmida
