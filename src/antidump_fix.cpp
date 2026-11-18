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
  uint8_t push_args1[sizeof(kPushArgsRwProtect)];
  uint32_t push_img_base1;
  uint16_t call_instr1;
  uint32_t virtual_protect_addr1;

  uint16_t mov_instr;
  uint32_t opt_hdr_entrypoint;
  uint32_t entrypoint;

  uint8_t push_args2[sizeof(kPushArgsOldProtect)];
  uint32_t push_img_base2;
  uint16_t call_instr2;
  uint32_t virtual_protect_addr2;
  uint8_t pop_stack;

  uint8_t jmp_instr;
  uint32_t jmp_displ;
};
#pragma pack(pop)

}  // namespace

AntiDumpFixer::AntiDumpFixer(HANDLE process, uintptr_t image_base)
    : process_(process), image_base_(image_base) {}

bool AntiDumpFixer::RPM(uintptr_t address, void* buf, size_t bufSize) {
  return ReadProcessMemory(process_, reinterpret_cast<void*>(address), buf,
                           bufSize, nullptr) != FALSE;
}

void AntiDumpFixer::RedirectOEP(uintptr_t oep, uintptr_t iat) {
  uint8_t code[16]{};
  if (!RPM(oep, code, sizeof(code))) {
    Log(kLogFatal, "ReadProcessMemory failed");
    return;
  }

  const VmStubInfo stub =
      ParseVmStub(code, sizeof(code), static_cast<uint32_t>(oep - image_base_),
                  static_cast<uint64_t>(image_base_));

  size_t prefixSize = 0;
  if (stub.kind == VmStubKind::kPushJump) {
    prefixSize = 5;
  } else if (stub.kind == VmStubKind::kPushPushJump) {
    prefixSize = 10;
  } else if (stub.kind != VmStubKind::kDirectJump) {
    Log(kLogWarning, "Anti-dump fix skipped: unsupported OEP stub layout.");
    return;
  }
  if (stub.target_rva == 0) {
    Log(kLogWarning, "Anti-dump fix skipped: VM target is outside the image.");
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
    Log(kLogFatal, "VirtualProtect not found in IAT");
    return;
  }

  NewCode newCode{};

  // VirtualProtect(ImageBase, $400, PAGE_READWRITE, OldProtect)
  std::memcpy(newCode.push_args1, kPushArgsRwProtect,
              sizeof(kPushArgsRwProtect));
  newCode.push_img_base1 = static_cast<uint32_t>(image_base_);
  newCode.call_instr1 = 0x15FF;
  newCode.virtual_protect_addr1 = virtualProtectIat;

  // mov dword ptr [AddressOfEntryPoint], ThemidaEntrypoint
  newCode.mov_instr = 0x05C7;
  uint32_t lfaNew = 0;
  if (!RPM(image_base_ + 0x3C, &lfaNew, sizeof(lfaNew)) ||
      !RPM(image_base_ + lfaNew + 0x28, &newCode.entrypoint,
           sizeof(newCode.entrypoint))) {
    Log(kLogFatal, "ReadProcessMemory failed");
    return;
  }
  newCode.opt_hdr_entrypoint =
      static_cast<uint32_t>(image_base_ + lfaNew + 0x28);

  // VirtualProtect(ImageBase, $400, OldProtect, _)
  std::memcpy(newCode.push_args2, kPushArgsOldProtect,
              sizeof(kPushArgsOldProtect));
  newCode.push_img_base2 = static_cast<uint32_t>(image_base_);
  newCode.call_instr2 = 0x15FF;
  newCode.virtual_protect_addr2 = virtualProtectIat;
  // pop eax (undo initial "push 0" for OldProtect)
  newCode.pop_stack = 0x58;

  // jmp vm: the final target comes from the parsed entry stub.
  const uint32_t vmTarget =
      static_cast<uint32_t>(image_base_ + stub.target_rva);
  const uint32_t jmpAddress =
      static_cast<uint32_t>(oep + prefixSize + sizeof(NewCode));
  newCode.jmp_instr = 0xE9;
  newCode.jmp_displ = vmTarget - jmpAddress;

  // For push;jmp stubs the original pushed VM context must be preserved in
  // front of the mitigation stub.
  std::vector<uint8_t> stubBytes;
  stubBytes.insert(stubBytes.end(), code, code + prefixSize);
  const auto* newCodeBytes = reinterpret_cast<const uint8_t*>(&newCode);
  stubBytes.insert(stubBytes.end(), newCodeBytes,
                   newCodeBytes + sizeof(newCode));

  if (WriteProcessMemory(process_, reinterpret_cast<void*>(oep),
                         stubBytes.data(), stubBytes.size(), nullptr)) {
    Log(kLogGood, "Installed VM anti-dump (PE header) mitigation at OEP");
    Log(kLogInfo,
        "NOTE: We assume there is enough space at the entrypoint, which may "
        "not be the case in every binary.");
  } else {
    Log(kLogFatal, "WriteProcessMemory failed");
  }
}

}  // namespace magicmida
