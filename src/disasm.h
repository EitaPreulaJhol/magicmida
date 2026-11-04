// Magicmida - C++ port
// Thin wrapper around the bundled BeaEngine disassembler.
#pragma once

#include "common.h"

#include <cstddef>
#include <cstdint>

namespace magicmida {

constexpr int INSTRUCT_LENGTH = 64;

constexpr int UNKNOWN_OPCODE = -1;
constexpr int OUT_OF_BLOCK = -2;

// The following structures mirror the packed Delphi declarations in
// BeaEngineDelphi.pas (which in turn mirror BeaEngine's public header).
#pragma pack(push, 1)

struct TREX_Struct {
  uint8_t W_;
  uint8_t R_;
  uint8_t X_;
  uint8_t B_;
  uint8_t state;
};

struct TPREFIXINFO {
  int32_t Number;
  int32_t NbUndefined;
  uint8_t LockPrefix;
  uint8_t OperandSize;
  uint8_t AddressSize;
  uint8_t RepnePrefix;
  uint8_t RepPrefix;
  uint8_t FSPrefix;
  uint8_t SSPrefix;
  uint8_t GSPrefix;
  uint8_t ESPrefix;
  uint8_t CSPrefix;
  uint8_t DSPrefix;
  uint8_t BranchTaken;
  uint8_t BranchNotTaken;
  TREX_Struct REX;
  uint8_t alignment[2];
};

struct TEFLStruct {
  uint8_t OF_;
  uint8_t SF_;
  uint8_t ZF_;
  uint8_t AF_;
  uint8_t PF_;
  uint8_t CF_;
  uint8_t TF_;
  uint8_t IF_;
  uint8_t DF_;
  uint8_t NT_;
  uint8_t RF_;
  uint8_t alignment;
};

struct TMEMORYTYPE {
  int64_t BaseRegister;
  int64_t IndexRegister;
  int32_t Scale;
  int64_t Displacement;
};

struct TREGISTERTYPE {
  int64_t rtype;
  int64_t gpr;
  int64_t mmx;
  int64_t xmm;
  int64_t ymm;
  int64_t zmm;
  int64_t special;
  int64_t cr;
  int64_t dr;
  int64_t mem_management;
  int64_t mpx;
  int64_t opmask;
  int64_t segment;
  int64_t fpu;
};

struct TINSTRTYPE {
  int32_t Category;
  int32_t Opcode;
  char Mnemonic[24];
  int32_t BranchType;
  TEFLStruct Flags;
  uint64_t AddrValue;
  int64_t Immediat;
  TREGISTERTYPE ImplicitModifiedRegs;
};

struct TOPTYPE {
  char OpMnemonic[24];
  int64_t OpType;
  int32_t OpSize;
  int32_t OpPosition;
  uint32_t AccessMode;
  TMEMORYTYPE Memory;
  TREGISTERTYPE Registers;
  uint32_t SegmentReg;
};

struct DISASM {
  uintptr_t EIP;
  uint64_t VirtualAddr;
  uint32_t SecurityBlock;
  char CompleteInstr[INSTRUCT_LENGTH];
  uint32_t Archi;
  uint64_t Options;
  TINSTRTYPE Instruction;
  TOPTYPE Operand1;
  TOPTYPE Operand2;
  TOPTYPE Operand3;
  TOPTYPE Operand4;
  TPREFIXINFO Prefix;
  uint32_t Error;
  uint32_t Reserved_[49];
  // Safety margin: the bundled objects are older/newer builds of BeaEngine
  // whose DISASM may have a larger reserved tail. Offsets of all fields used
  // by this project are guaranteed by the assertions below.
  uint8_t AbiSafetyPadding[256];
};

#pragma pack(pop)

static_assert(sizeof(void*) == 4 || sizeof(void*) == 8, "Unsupported pointer size");
static_assert(offsetof(DISASM, VirtualAddr) == (sizeof(void*) == 8 ? 8u : 4u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, CompleteInstr) == (sizeof(void*) == 8 ? 20u : 16u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Archi) == (sizeof(void*) == 8 ? 84u : 80u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Instruction) == (sizeof(void*) == 8 ? 96u : 92u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Operand1) == (sizeof(void*) == 8 ? 272u : 268u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Operand2) == (sizeof(void*) == 8 ? 460u : 456u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Operand3) == (sizeof(void*) == 8 ? 648u : 644u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Operand4) == (sizeof(void*) == 8 ? 836u : 832u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Prefix) == (sizeof(void*) == 8 ? 1024u : 1020u),
              "DISASM layout mismatch");
static_assert(offsetof(DISASM, Error) == (sizeof(void*) == 8 ? 1052u : 1048u),
              "DISASM layout mismatch");
static_assert(offsetof(TINSTRTYPE, AddrValue) == 48u, "INSTRTYPE layout mismatch");
static_assert(offsetof(TOPTYPE, Memory) == 44u, "OPTYPE layout mismatch");
static_assert(offsetof(TMEMORYTYPE, Displacement) == 20u, "MEMORYTYPE layout mismatch");

extern "C" int __stdcall Disasm(DISASM* disasm);
extern "C" const char* __stdcall BeaEngineVersion();

// Equivalent of the original DisasmCheck(): sets the architecture, decodes the
// instruction and throws if the opcode is unknown/out of block.
int DisasmCheck(DISASM& disasm);

// Helpers used by the ported code.
inline uintptr_t DisasmEip(const DISASM& disasm) { return disasm.EIP; }
inline int64_t DisasmMemoryDisplacement(const TOPTYPE& operand) {
  return operand.Memory.Displacement;
}

}  // namespace magicmida
