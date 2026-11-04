// Magicmida - C++ port
// Rebuilds base relocation tables for unpacked DLLs.
#pragma once

#include <cstdint>
#include <string>

namespace magicmida {

// Reconstructs a .reloc section for an unpacked DLL so that the loader can
// rebase it. `dumpBase` is the address the image was loaded at when it was
// dumped (0 keeps the ImageBase stored in the header). The header ImageBase is
// moved to `dumpBase` because the dumped bytes contain addresses relative to
// it. Existing relocation entries are preserved and merged with the
// reconstructed ones. Returns true when a relocation table was written.
bool FixDllRelocations(const std::wstring& fileName, uintptr_t dumpBase);

}  // namespace magicmida
