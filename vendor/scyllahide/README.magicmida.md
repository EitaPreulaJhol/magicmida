# Vendored ScyllaHide

This directory contains a trimmed copy of
[ScyllaHide](https://github.com/x64dbg/ScyllaHide), pinned at commit
`baa5c8e` (`v1.4-5-gbaa5c8e`).

Only the files needed by the embedded integration are present:

- `HookLibrary/` – the payload that is manually mapped into the target.
- `InjectorCLI/` – `ApplyHooking`, `DynamicMapping`, and `RemoteHook`.
  `CliMain.cpp` and the CLI-specific files are not used.
- `Scylla/` – the subset used by the injector and hook library.
- `3rdparty/distorm/` – used to measure instruction lengths for detours.
- `3rdparty/ntdll/` – `ntdll.h` plus the MSVC import libraries.  MinGW links
  against the system `ntdll` import library instead.

`PluginGeneric/Injector.cpp` is not included.  The small
`ReadNtApiInformation` helper was reimplemented in `src/scyllahide.cpp`, and
the settings/profile mapping is compiled in (no `scylla_hide.ini`).

## Local patches

The upstream sources are kept as close as possible.  The changes below are
required for MinGW-w64 cross-compilation on Linux, for headless operation, or
to make the exports visible without the MSVC linker's stdcall fixups.

### Includes / build portability

- `<Windows.h>` and `<Psapi.h>` changed to lowercase where needed so the tree
  builds on case-sensitive filesystems.
- `InjectorCLI/ApplyHooking.h` uses `../HookLibrary/HookMain.h` instead of a
  backslash path.
- `compat/mingw_compat.h` is force-included for MinGW.  It defines an empty
  `__pragma(x)` and provides `_ReturnAddress()` via
  `__builtin_return_address(0)`.  The file is guarded for assembler and C.
- `Scylla/Util.cpp` includes `<commdlg.h>` because magicmida builds with
  `WIN32_LEAN_AND_MEAN`.

### `ntdll.h`

- `RtlQueryHeapInformation` and `RtlSetHeapInformation` are guarded with
  `#ifndef __MINGW32__`; their declarations conflict with MinGW's `winnt.h`.

### Exports / linkage

- `HookLibrary/HookedFunctions.h` wraps the exported declarations in
  `extern "C"`.  `HandleKiUserExceptionDispatcher` stays private to
  `HookedFunctions.cpp` so the MSVC x86 inline assembly keeps its original
  symbol resolution.
- `HookLibrary/HookedFunctions.cpp` defines `HookDllData` with C linkage and
  marks the exported entry points `extern "C"`.
- `HookLibrary/HookHelper.cpp` uses `extern "C" HOOK_DLL_DATA HookDllData;`.
- `HookLibrary/Export.def` now names the library (`LIBRARY HookLibrary`) and
  uses LF line endings; MinGW's linker otherwise rejects the file.

### Freestanding hook DLL (MinGW)

The hook DLL is manually mapped, so every imported DLL must already be loaded
at the same base in the target.  msvcrt.dll is not guaranteed to be loaded by
a Themida target.  The MinGW build therefore links with `-nostdlib` and uses
`HookLibrary/HookLibraryCrt.cpp` for the few C runtime routines the hook code
needs (`memcpy`, `memset`, `memcmp`, `strlen`, `strncmp`, `wcscat`, `wcslen`).
The resulting DLL imports only `ntdll.dll`, which is always present.  MSVC uses
its normal static CRT (`/MT`), matching upstream ScyllaHide.

### Assembly

- MSVC keeps the original MASM files and x86 inline assembly.
- MinGW uses `HookLibrary/AsmGccX64.S` and `HookLibrary/AsmGccX86.S`.
  - The x64 GAS file provides `InstrumentationCallbackAsm` and a
    `HookedKiUserExceptionDispatcher` stub that reads the `CONTEXT` frame at
    `[rsp + 8]`, avoiding `_AddressOfReturnAddress`/frame-pointer assumptions.
  - The x86 GAS file replaces the two naked inline-asm functions.  It calls
    small `extern "C"` cdecl wrappers/getters defined in
    `HookedFunctions.cpp` so the assembler never has to deal with `@N`
    stdcall names or `HOOK_DLL_DATA` offsets.

### Injector

- `RemoteHook.cpp` no longer depends on `Scylla/Settings.h` or
  `g_settings.profile_name()`; the Obsidium profile special case was removed
  because the magicmida profile never selects it.
- `#pragma comment(lib, ...)` directives for distorm/psapi were removed; the
  libraries are linked explicitly by CMake.
- `MessageBoxA` calls in `RemoteHook.cpp` and `DynamicMapping.cpp` were
  replaced with `ScyllaHideMessageBoxA`, implemented in
  `src/scyllahide.cpp`.  It logs the text instead of opening a modal dialog,
  which would hang the CLI.

## Updating

`src/scyllahide.cpp` reports the pinned commit from `Version()`; update it
together with `UPSTREAM` when re-vendoring.

1. Copy the same file set from a newer ScyllaHide snapshot.
2. Re-apply the changes above (or port them from this tree).
3. Rebuild both MinGW and MSVC configurations and run the smoke tests.
