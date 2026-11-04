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

uint32_t ToRva(uint64_t value, uint64_t imageBase) {
  if (value < imageBase) {
    return 0;
  }
  const uint64_t rva = value - imageBase;
  return rva <= 0xFFFFFFFFull ? static_cast<uint32_t>(rva) : 0;
}

}  // namespace

VmStubInfo ParseVmStub(const uint8_t* code, size_t size, uint32_t stubRva,
                       uint64_t imageBase) {
  VmStubInfo info;
  if (code == nullptr || size < 2) {
    return info;
  }

  const auto direct = [&](VmStubKind kind, size_t instructionSize,
                          int32_t displacement, uint32_t operandBias) {
    info.kind = kind;
    info.instructionSize = static_cast<uint32_t>(instructionSize);
    const int64_t target = static_cast<int64_t>(stubRva) + operandBias +
                           displacement;
    if (target > 0) {
      info.targetRva = static_cast<uint32_t>(target);
    }
  };

  switch (code[0]) {
    case 0xE9:
      if (size >= 5) {
        direct(VmStubKind::DirectJump, 5, Read<int32_t>(code, 1), 5);
      }
      return info;
    case 0xE8:
      if (size >= 5) {
        direct(VmStubKind::DirectCall, 5, Read<int32_t>(code, 1), 5);
      }
      return info;
    case 0xEB:
      if (size >= 2) {
        direct(VmStubKind::ShortJump, 2, Read<int8_t>(code, 1), 2);
      }
      return info;
    case 0x68:
      break;
    case 0xB8:
      if (size >= 7 && code[5] == 0xFF && code[6] == 0xE0) {
        info.kind = VmStubKind::MovEaxJmp;
        info.instructionSize = 7;
        info.targetRva = ToRva(Read<uint32_t>(code, 1), imageBase);
        info.contextRva = info.targetRva;
      }
      return info;
    case 0x48:
      if (size >= 12 && code[1] == 0xB8 && code[10] == 0xFF &&
          code[11] == 0xE0) {
        info.kind = VmStubKind::MovRaxJmp;
        info.instructionSize = 12;
        info.targetRva = ToRva(Read<uint64_t>(code, 2), imageBase);
        info.contextRva = info.targetRva;
      }
      return info;
    default:
      return info;
  }

  // 0x68 (push imm32) forms.
  if (size >= 6 && code[5] == 0xC3) {
    info.kind = VmStubKind::PushRet;
    info.instructionSize = 6;
    info.targetRva = ToRva(Read<uint32_t>(code, 1), imageBase);
    info.contextRva = info.targetRva;
    return info;
  }
  if (size >= 10 && code[5] == 0xE9) {
    info.kind = VmStubKind::PushJump;
    info.instructionSize = 10;
    const int64_t target = static_cast<int64_t>(stubRva) + 10 +
                           Read<int32_t>(code, 6);
    if (target > 0) {
      info.targetRva = static_cast<uint32_t>(target);
    }
    info.contextRva = ToRva(Read<uint32_t>(code, 1), imageBase);
    return info;
  }
  if (size >= 15 && code[5] == 0x68 && code[10] == 0xE9) {
    info.kind = VmStubKind::PushPushJump;
    info.instructionSize = 15;
    const int64_t target = static_cast<int64_t>(stubRva) + 15 +
                           Read<int32_t>(code, 11);
    if (target > 0) {
      info.targetRva = static_cast<uint32_t>(target);
    }
    info.contextRva = ToRva(Read<uint32_t>(code, 1), imageBase);
    info.contextRva2 = ToRva(Read<uint32_t>(code, 6), imageBase);
    return info;
  }

  return info;
}

}  // namespace magicmida
