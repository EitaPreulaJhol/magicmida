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

// Returns true when the target PE has IMAGE_FILE_DLL set. Throws on I/O or
// malformed PE.
bool ReadPEIsDll(const std::wstring& target);

}  // namespace magicmida
