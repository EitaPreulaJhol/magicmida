// Magicmida - C++ port
// Recognition of Oreans/Themida/WinLicense virtual-machine entry stubs.
#pragma once

#include <cstddef>
#include <cstdint>

namespace magicmida {

enum class VmStubKind {
  None,
  DirectJump,    // E9 rel32
  DirectCall,    // E8 rel32
  ShortJump,     // EB rel8
  PushJump,      // 68 imm32; E9 rel32
  PushPushJump,  // 68 imm32; 68 imm32; E9 rel32 (Fish)
  PushRet,       // 68 imm32; C3
  MovEaxJmp,     // B8 imm32; FF E0
  MovRaxJmp,     // 48 B8 imm64; FF E0
};

struct VmStubInfo {
  VmStubKind kind = VmStubKind::None;
  // Number of bytes consumed by the stub.
  uint32_t instructionSize = 0;
  // Final jump/call target, as an RVA.
  uint32_t targetRva = 0;
  // Pushed/moved context value, as an RVA (0 when the value is not in the
  // image or the stub has no context).
  uint32_t contextRva = 0;
  uint32_t contextRva2 = 0;
};

// Parses a VM entry stub from `code` at `stubRva`. `imageBase` converts
// absolute immediates (push/mov) into RVAs. Requires at least 16 bytes for
// the longest form; returns kind == None when the bytes do not match.
VmStubInfo ParseVmStub(const uint8_t* code, size_t size, uint32_t stubRva,
                       uint64_t imageBase);

}  // namespace magicmida
