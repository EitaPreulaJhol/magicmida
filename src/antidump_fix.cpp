// Magicmida - C++ port
// VM anti-dump mitigation (ported from AntiDumpFix.pas).
// SPDX-License-Identifier: GPL-3.0-only
#include "antidump_fix.h"

#include <cstring>
#include <vector>

#include "vm_entry.h"

namespace magicmida {
namespace {

constexpr uint8_t kPushArgsRwProtect[] = {0x6A, 0x00, 0x54, 0x6A, 0x04, 0x68,
                                          0x00, 0x04, 0x00, 0x00, 0x68};
constexpr uint8_t kPushArgsOldProtect[] = {0x54, 0xFF, 0x74, 0x24, 0x04, 0x68,
                                           0x00, 0x04, 0x00, 0x00, 0x68};

MAGICMIDA_PACK_PUSH_1
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
MAGICMIDA_PACK_POP

}  // namespace

AntiDumpFixer::AntiDumpFixer(HANDLE process, uintptr_t image_base)
    : process_(process), image_base_(image_base) {}

bool AntiDumpFixer::Rpm(uintptr_t address, void* buf, size_t buf_size) {
  return ReadProcessMemory(process_, reinterpret_cast<void*>(address), buf,
                           buf_size, nullptr) != FALSE;
}

void AntiDumpFixer::RedirectOep(uintptr_t oep, uintptr_t iat) {
  uint8_t code[16]{};
  if (!Rpm(oep, code, sizeof(code))) {
    Log(kLogFatal, "ReadProcessMemory failed");
    return;
  }

  const VmStubInfo stub =
      ParseVmStub(code, sizeof(code), static_cast<uint32_t>(oep - image_base_),
                  static_cast<uint64_t>(image_base_));

  size_t prefix_size = 0;
  if (stub.kind == VmStubKind::kPushJump) {
    prefix_size = 5;
  } else if (stub.kind == VmStubKind::kPushPushJump) {
    prefix_size = 10;
  } else if (stub.kind != VmStubKind::kDirectJump) {
    Log(kLogWarning, "Anti-dump fix skipped: unsupported OEP stub layout.");
    return;
  }
  if (stub.target_rva == 0) {
    Log(kLogWarning, "Anti-dump fix skipped: VM target is outside the image.");
    return;
  }

  const uintptr_t virtual_protect_address = reinterpret_cast<uintptr_t>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect"));

  uint32_t virtual_protect_iat = 0;
  std::vector<uint32_t> iat_data(512);
  Rpm(iat, iat_data.data(), iat_data.size() * sizeof(uint32_t));
  for (size_t i = 0; i < iat_data.size(); ++i) {
    if (iat_data[i] == virtual_protect_address) {
      virtual_protect_iat = static_cast<uint32_t>(iat + i * 4);
      break;
    }
  }

  if (virtual_protect_iat == 0) {
    Log(kLogFatal, "VirtualProtect not found in IAT");
    return;
  }

  NewCode new_code{};

  // VirtualProtect(ImageBase, $400, PAGE_READWRITE, OldProtect)
  std::memcpy(new_code.push_args1, kPushArgsRwProtect,
              sizeof(kPushArgsRwProtect));
  new_code.push_img_base1 = static_cast<uint32_t>(image_base_);
  new_code.call_instr1 = 0x15FF;
  new_code.virtual_protect_addr1 = virtual_protect_iat;

  // mov dword ptr [AddressOfEntryPoint], ThemidaEntrypoint
  new_code.mov_instr = 0x05C7;
  uint32_t lfa_new = 0;
  if (!Rpm(image_base_ + 0x3C, &lfa_new, sizeof(lfa_new)) ||
      !Rpm(image_base_ + lfa_new + 0x28, &new_code.entrypoint,
           sizeof(new_code.entrypoint))) {
    Log(kLogFatal, "ReadProcessMemory failed");
    return;
  }
  new_code.opt_hdr_entrypoint =
      static_cast<uint32_t>(image_base_ + lfa_new + 0x28);

  // VirtualProtect(ImageBase, $400, OldProtect, _)
  std::memcpy(new_code.push_args2, kPushArgsOldProtect,
              sizeof(kPushArgsOldProtect));
  new_code.push_img_base2 = static_cast<uint32_t>(image_base_);
  new_code.call_instr2 = 0x15FF;
  new_code.virtual_protect_addr2 = virtual_protect_iat;
  // pop eax (undo initial "push 0" for OldProtect)
  new_code.pop_stack = 0x58;

  // jmp vm: the final target comes from the parsed entry stub.
  const uint32_t vm_target =
      static_cast<uint32_t>(image_base_ + stub.target_rva);
  const uint32_t jmp_address =
      static_cast<uint32_t>(oep + prefix_size + sizeof(NewCode));
  new_code.jmp_instr = 0xE9;
  new_code.jmp_displ = vm_target - jmp_address;

  // For push;jmp stubs the original pushed VM context must be preserved in
  // front of the mitigation stub.
  std::vector<uint8_t> stub_bytes;
  stub_bytes.insert(stub_bytes.end(), code, code + prefix_size);
  const auto* new_code_bytes = reinterpret_cast<const uint8_t*>(&new_code);
  stub_bytes.insert(stub_bytes.end(), new_code_bytes,
                    new_code_bytes + sizeof(new_code));

  if (WriteProcessMemory(process_, reinterpret_cast<void*>(oep),
                         stub_bytes.data(), stub_bytes.size(), nullptr)) {
    Log(kLogGood, "Installed VM anti-dump (PE header) mitigation at OEP");
    Log(kLogInfo,
        "NOTE: We assume there is enough space at the entrypoint, which may "
        "not be the case in every binary.");
  } else {
    Log(kLogFatal, "WriteProcessMemory failed");
  }
}

}  // namespace magicmida
