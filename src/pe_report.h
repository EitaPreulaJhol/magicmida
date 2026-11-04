// Magicmida - C++ port
// Human-readable PE information used by the GUI.
#pragma once

#include <functional>
#include <string>

namespace magicmida {

// Emits the same lines the `info` command has always printed, without a
// trailing newline.  Throws on I/O or malformed-PE errors.
void EmitPEInfo(const std::wstring& target,
                const std::function<void(const std::string&)>& emit);

// Returns IMAGE_FILE_MACHINE_* for the target. Throws on I/O or malformed PE.
uint16_t ReadPEMachine(const std::wstring& target);

struct PEFlags {
  uint16_t machine = 0;
  bool isDll = false;
};

// Returns the machine type and the IMAGE_FILE_DLL flag in one read. Throws on
// I/O or malformed PE.
PEFlags ReadPEFlags(const std::wstring& target);

// Sanity-checks an unpacked dump and logs the findings. `isDll` enables the
// DLL-specific checks; `relocationsExpected` marks a missing relocation table
// as fatal (the relocation fix was requested).
void VerifyDump(const std::wstring& target, bool isDll,
                bool relocationsExpected);

// Returns true when the target PE has IMAGE_FILE_DLL set. Throws on I/O or
// malformed PE.
bool ReadPEIsDll(const std::wstring& target);

}  // namespace magicmida
