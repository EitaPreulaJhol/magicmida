// Magicmida - C++ port
// Recognition of Oreans/Themida/WinLicense virtual-machine entry stubs.
// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAGICMIDA_VM_ENTRY_H_
#define MAGICMIDA_VM_ENTRY_H_

#include <cstddef>
#include <cstdint>

namespace magicmida {

enum class VmStubKind {
  kNone,
  kDirectJump,    // E9 rel32
  kDirectCall,    // E8 rel32
  kShortJump,     // EB rel8
  kPushJump,      // 68 imm32; E9 rel32
  kPushPushJump,  // 68 imm32; 68 imm32; E9 rel32 (Fish)
  kPushRet,       // 68 imm32; C3
  kMovEaxJmp,     // B8 imm32; FF E0
  kMovRaxJmp,     // 48 B8 imm64; FF E0
};

struct VmStubInfo {
  VmStubKind kind = VmStubKind::kNone;
  // Number of bytes consumed by the stub.
  uint32_t instruction_size = 0;
  // Final jump/call target, as an RVA.
  uint32_t target_rva = 0;
  // Pushed/moved context value, as an RVA (0 when the value is not in the
  // image or the stub has no context).
  uint32_t context_rva = 0;
  uint32_t context_rva2 = 0;
};

// Parses a VM entry stub from `code` at `stubRva`. `image_base` converts
// absolute immediates (push/mov) into RVAs. Requires at least 16 bytes for
// the longest form; returns kind == kNone when the bytes do not match.
VmStubInfo ParseVmStub(const uint8_t* code, size_t size, uint32_t stub_rva,
                       uint64_t image_base);

}  // namespace magicmida

#endif  // MAGICMIDA_VM_ENTRY_H_
