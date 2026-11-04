// Magicmida - C++ port
// Thin wrapper around the bundled BeaEngine disassembler.
#include "disasm.h"

#include <cstring>

namespace magicmida {

int DisasmCheck(DISASM& disasm) {
  disasm.Archi = static_cast<uint32_t>(sizeof(void*) * 8);
  const int result = Disasm(&disasm);
  if (result == UNKNOWN_OPCODE || result == OUT_OF_BLOCK) {
    throw std::runtime_error(
        Format("Disasm result: %d (EIP = %llX)", result,
               static_cast<unsigned long long>(disasm.EIP)));
  }
  return result;
}

}  // namespace magicmida
