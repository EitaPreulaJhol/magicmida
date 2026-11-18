// Magicmida - C++ port
// Thin wrapper around the bundled BeaEngine disassembler.
// SPDX-License-Identifier: GPL-3.0-only
#include "disasm.h"

#include <cstring>
#include <stdexcept>

namespace magicmida {

int DisasmCheck(DISASM& disasm) {
  disasm.Archi = static_cast<uint32_t>(sizeof(void*) * 8);
  const int result = Disasm(&disasm);
  if (result == kUnknownOpcode || result == kOutOfBlock) {
    throw std::runtime_error(Format("Disasm result: %d (EIP = %llX)", result,
                                    static_cast<uint64_t>(disasm.EIP)));
  }
  return result;
}

}  // namespace magicmida
