// Magicmida - C++ port
// VM anti-dump mitigation (ported from AntiDumpFix.pas).
#include "antidump_fix.h"

#include "vm_entry.h"

#include <cstring>
#include <vector>

namespace magicmida {
namespace {

constexpr uint8_t kPushArgsRwProtect[] = {0x6A, 0x00, 0x54, 0x6A, 0x04, 0x68,
                                          0x00, 0x04, 0x00, 0x00, 0x68};
constexpr uint8_t kPushArgsOldProtect[] = {0x54, 0xFF, 0x74, 0x24, 0x04, 0x68,
                                           0x00, 0x04, 0x00, 0x00, 0x68};

#pragma pack(push, 1)
struct NewCode {
  uint8_t PushArgs1[sizeof(kPushArgsRwProtect)];
  uint32_t PushImgBase1;
  uint16_t CallInstr1;
  uint32_t VirtualProtectAddr1;

  uint16_t MovInstr;
  uint32_t OptHdrEntrypoint;
  uint32_t Entrypoint;

  uint8_t PushArgs2[sizeof(kPushArgsOldProtect)];
  uint32_t PushImgBase2;
  uint16_t CallInstr2;
  uint32_t VirtualProtectAddr2;
  uint8_t PopStack;

  uint8_t JmpInstr;
  uint32_t JmpDispl;
};
#pragma pack(pop)

}  // namespace

AntiDumpFixer::AntiDumpFixer(HANDLE process, uintptr_t imageBase)
    : process_(process), imageBase_(imageBase) {}

bool AntiDumpFixer::RPM(uintptr_t address, void* buf, size_t bufSize) {
  return ReadProcessMemory(process_, reinterpret_cast<void*>(address), buf,
                           bufSize, nullptr) != FALSE;
}

void AntiDumpFixer::RedirectOEP(uintptr_t oep, uintptr_t iat) {
  uint8_t code[16]{};
  if (!RPM(oep, code, sizeof(code))) {
    Log(ltFatal, "ReadProcessMemory failed");
    return;
  }

  const VmStubInfo stub = ParseVmStub(
      code, sizeof(code), static_cast<uint32_t>(oep - imageBase_),
      static_cast<uint64_t>(imageBase_));

  size_t prefixSize = 0;
  if (stub.kind == VmStubKind::PushJump) {
    prefixSize = 5;
  } else if (stub.kind == VmStubKind::PushPushJump) {
    prefixSize = 10;
  } else if (stub.kind != VmStubKind::DirectJump) {
    Log(ltWarning,
        "Anti-dump fix skipped: unsupported OEP stub layout.");
    return;
  }
  if (stub.targetRva == 0) {
    Log(ltWarning, "Anti-dump fix skipped: VM target is outside the image.");
    return;
  }

  const uintptr_t virtualProtectAddress = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect"));

  uint32_t virtualProtectIat = 0;
  std::vector<uint32_t> iatData(512);
  RPM(iat, iatData.data(), iatData.size() * sizeof(uint32_t));
  for (size_t i = 0; i < iatData.size(); ++i) {
    if (iatData[i] == virtualProtectAddress) {
      virtualProtectIat = static_cast<uint32_t>(iat + i * 4);
      break;
    }
  }

  if (virtualProtectIat == 0) {
    Log(ltFatal, "VirtualProtect not found in IAT");
    return;
  }

  NewCode newCode{};

  // VirtualProtect(ImageBase, $400, PAGE_READWRITE, OldProtect)
  std::memcpy(newCode.PushArgs1, kPushArgsRwProtect, sizeof(kPushArgsRwProtect));
  newCode.PushImgBase1 = static_cast<uint32_t>(imageBase_);
  newCode.CallInstr1 = 0x15FF;
  newCode.VirtualProtectAddr1 = virtualProtectIat;

  // mov dword ptr [AddressOfEntryPoint], ThemidaEntrypoint
  newCode.MovInstr = 0x05C7;
  uint32_t lfaNew = 0;
  if (!RPM(imageBase_ + 0x3C, &lfaNew, sizeof(lfaNew)) ||
      !RPM(imageBase_ + lfaNew + 0x28, &newCode.Entrypoint,
           sizeof(newCode.Entrypoint))) {
    Log(ltFatal, "ReadProcessMemory failed");
    return;
  }
  newCode.OptHdrEntrypoint = static_cast<uint32_t>(imageBase_ + lfaNew + 0x28);

  // VirtualProtect(ImageBase, $400, OldProtect, _)
  std::memcpy(newCode.PushArgs2, kPushArgsOldProtect,
              sizeof(kPushArgsOldProtect));
  newCode.PushImgBase2 = static_cast<uint32_t>(imageBase_);
  newCode.CallInstr2 = 0x15FF;
  newCode.VirtualProtectAddr2 = virtualProtectIat;
  // pop eax (undo initial "push 0" for OldProtect)
  newCode.PopStack = 0x58;

  // jmp vm: the final target comes from the parsed entry stub.
  const uint32_t vmTarget =
      static_cast<uint32_t>(imageBase_ + stub.targetRva);
  const uint32_t jmpAddress =
      static_cast<uint32_t>(oep + prefixSize + sizeof(NewCode));
  newCode.JmpInstr = 0xE9;
  newCode.JmpDispl = vmTarget - jmpAddress;

  // For push;jmp stubs the original pushed VM context must be preserved in
  // front of the mitigation stub.
  std::vector<uint8_t> stubBytes;
  stubBytes.insert(stubBytes.end(), code, code + prefixSize);
  const auto* newCodeBytes = reinterpret_cast<const uint8_t*>(&newCode);
  stubBytes.insert(stubBytes.end(), newCodeBytes,
                   newCodeBytes + sizeof(newCode));

  if (WriteProcessMemory(process_, reinterpret_cast<void*>(oep),
                         stubBytes.data(), stubBytes.size(), nullptr)) {
    Log(ltGood, "Installed VM anti-dump (PE header) mitigation at OEP");
    Log(ltInfo,
        "NOTE: We assume there is enough space at the entrypoint, which may "
        "not be the case in every binary.");
  } else {
    Log(ltFatal, "WriteProcessMemory failed");
  }
}

}  // namespace magicmida
