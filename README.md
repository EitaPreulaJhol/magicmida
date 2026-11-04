# Magicmida (C++ port)

Magicmida unpacks Themida/WinLicense-protected applications for 32-bit and
64-bit Windows. This repository is a C++ port of the original Delphi project,
with a native Win32 GUI.

The unpacking logic comes from the Delphi sources: the debugger, breakpoint
choreography, Themida version detection, IAT recovery, import reconstruction,
dump fixups, anti-dump mitigation, shrink, and data-section restoration. All of
it was ported one to one. The intentional differences are about portability and
the user interface.

The distributed `magicmida.exe` is a 64-bit program that handles both target
architectures. 64-bit targets are unpacked in-process. 32-bit targets go to a
32-bit worker embedded in the executable. The worker is written to a temporary
file, started hidden, and deleted when the job finishes.

## What it can do

| Function | Description |
| --- | --- |
| Unpack | Unpacks a Themida/WinLicense-protected executable or DLL. The dump is written next to the input with a `U` suffix, so `app.exe` becomes `appU.exe`. |
| Shrink | Drops sections that are no longer needed after manual unvirtualization. Keeps the entry-point section, referenced sections and runtime data (`.bss`, `.CRT`, `.tls`, `.xdata`, CFG tables), removes only unreferenced executable/discardable sections, keeps the VM section when the entry point jumps into it or when `.text` references a VM entry stub, relocates an exception table that lives inside a removable protector section into a new `.pdata` section, and writes a `.bak` copy before modifying the file. |
| MkData | Restores `.rdata` and `.data`. Needed for MSVC 2015+ targets that use Thread Local Storage, and supported for MapleStory binaries. 32-bit targets only. |
| Dump code | Overwrites `.text` in an already unpacked file with code from a running process. Useful after Oreans Unvirtualizer in OllyDbg. 32-bit targets only. |
| Info | Shows PE headers, architecture and sections. Runs automatically when a target is selected; also available as `--info` in the CLI. |

MkData and Dump code are rejected for 64-bit targets, matching the original
64-bit build.

## Using it

Start `magicmida.exe`, optionally with the target path as the first argument.
Then:

- Select a target or drag one onto the window. The PE info (architecture,
  type, image base, entry point, relocations, sections) is logged automatically
  when a valid target is loaded.
- Pick the function from the drop-down list.
- The **Advanced** menu holds the unpack options. `Create data sections` and
  `Disable ScyllaHide` apply to Unpack. `Fix DLL relocations` applies to
  Unpack and Shrink and is only enabled when the target is a DLL. It rebuilds
  the `.reloc` section so the file can be rebased. For Shrink, the `ImageBase`
  stored in the header is used as the dump base.
- `PID` is used by Dump code.
- `Cancel` stops a running job. For 32-bit targets it also stops the worker;
  the target is terminated by the debugger cleanup.
- The log pane shows all output with timestamps. The File menu holds Open,
  Clear log, Save log (Ctrl+S), Copy log, and Exit; the Advanced menu holds
  the unpack options.
- After unpacking, a dump sanity check reports the entry point, section
  bounds, imports, and relocation directory in the log.

The window has a fixed size and uses classic Windows 2000 controls and fonts.
It cannot be resized or maximized. Visual styles and the Common Controls v6
dependency are disabled on purpose.

The executable needs a 64-bit Windows host. The 32-bit worker is an internal
build artifact and is not distributed as a standalone application.

## Command line

The 64-bit executable can run one job without opening the GUI. Batch
processing is done by calling it once per target from a shell script.

```text
magicmida.exe --unpack [--fix-relocs] [--data-sections] [--no-scylla]
              [--force] <target>
magicmida.exe --shrink [--fix-relocs] <target>
magicmida.exe --mkdata <target>
magicmida.exe --dumpcode --pid <pid> <target>
magicmida.exe --info <target>
magicmida.exe --help
magicmida.exe --version
```

`--force` is required to overwrite an existing dump. Exit codes are `0` for
success, `1` for a failed job, and `2` for usage errors. Log lines go to the
attached console (or a new console when there is no parent console).

Because `magicmida.exe` is a GUI-subsystem executable, `cmd.exe` does not wait
for it. In batch files use `start /wait magicmida.exe ...` (or
`Start-Process -Wait` in PowerShell) so the next command sees the exit code.

## Building

The project builds on Windows only. The scripted MinGW-w64 build produces the
single-file distribution.

### Cross-compiling on Linux with MinGW-w64

```bash
# 1. Build the internal 32-bit worker first.
cmake -S . -B build/x86 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw32.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/x86 -j

# 2. Build the 64-bit executable with the worker embedded.
cmake -S . -B build/x64 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DMAGICMIDA_32BIT_WORKER="$PWD/build/worker/magicmida_worker.exe"
cmake --build build/x64 -j
```

The final distribution is `build/magicmida.exe`. The 32-bit worker lands in
`build/worker/magicmida_worker.exe` and is not meant to be run by users. Both
MinGW outputs are statically linked and need only the Windows system DLLs.

`./build.sh` runs both steps in the right order on Linux. Add `--clean` for a
clean rebuild. On Windows, use `build.ps1` (see below).

### Building on Windows

#### MinGW-w64 with PowerShell

Install CMake, Ninja (or `mingw32-make`), and both MinGW-w64 toolchains
(MSYS2: `mingw-w64-i686-gcc` and `mingw-w64-x86_64-gcc`). If the toolchains
are not on PATH, point the script at their `bin` directories:

```powershell
.\build.ps1
.\build.ps1 -Clean
.\build.ps1 -MinGW32 C:\msys64\mingw32\bin -MinGW64 C:\msys64\mingw64\bin
```

If PowerShell blocks scripts, run
`powershell -ExecutionPolicy Bypass -File .\build.ps1`. The script builds the
32-bit worker first and embeds it into the 64-bit `build\magicmida.exe`; the
worker lands in `build\worker\magicmida_worker.exe`.

#### Visual Studio

Visual Studio can embed a 32-bit worker that you build separately. Build that
worker with MinGW-w64, since the bundled BeaEngine object is produced by GCC:

```bat
cmake -S . -B build/msvc -A x64 ^
  -DMAGICMIDA_32BIT_WORKER=C:\path\to\magicmida_worker.exe
cmake --build build/msvc --config Release
```

### Dependencies

* [BeaEngine 5.1](https://github.com/Hendi48/beaengine) (LGPLv3). The two
  prebuilt object files in `vendor/beaengine/` come from the original
  Magicmida repository and are linked into the executable.
* [ScyllaHide](https://github.com/x64dbg/ScyllaHide) (GPLv3). A pinned, patched
  subset is vendored in `vendor/scyllahide/`. Its injector and driver code is
  compiled into `magicmida.exe`, and the hook libraries are embedded as
  resources. ScyllaHide needs no files at runtime.

## ScyllaHide

Newer Themida versions detect hardware breakpoints, so ScyllaHide is integrated
into Magicmida:

* The injector and driver code is compiled into `magicmida.exe`.
* `HookLibraryx64.dll` is embedded in the 64-bit executable.
* `HookLibraryx86.dll` is embedded in the 32-bit worker.
* Injection runs synchronously at the initial debug breakpoint.
* Nothing has to be shipped or placed next to the executable: no
  `InjectorCLI*.exe`, no `HookLibrary*.dll`, and no `scylla_hide.ini`.

Set `MAGICMIDA_SCYLLA_DEBUG=1` to send ScyllaHide's debug messages and the
active hook/PEB profile to the normal magicmida log. It does not write a
separate ScyllaHide log file.

The `Disable ScyllaHide` checkbox skips injection for diagnostics. 32-bit
targets then fall back to Magicmida's internal anti-anti-debug handling. A
64-bit target will usually be detected by Themida without ScyllaHide.

For 32-bit targets ScyllaHide is optional: if injection fails, Magicmida falls
back to its own anti-anti-debugging breakpoints. For 64-bit targets it is
mandatory, exactly as in the original tool.

## Things to know about unpacked binaries

These limitations come from the original Magicmida:

* Shrink is destructive. A `.bak` copy is written next to the target before
  it is modified. If the shrunk file no longer starts, restore the backup and
  make sure the target was fully unvirtualized before shrinking; removing
  sections that are still used by the protector will break the image. When
  the entry point jumps into the protector section (virtualized OEP), Shrink
  keeps that section and warns instead of breaking startup. When the
  exception table lives inside a removable protector section (`.themida`,
  `.boot`, `.vmp*`), Shrink copies it to a new `.pdata` section and drops the
  protector's own entries before removing the section.
* When unpacking a DLL, Magicmida temporarily creates `<name>MM.exe` next to
  it (the DLL entry-point stub is written into that copy). The copy is removed
  after the run; a leftover from an interrupted session is deleted before the
  next DLL unpack.
* Magicmida does not devirtualize VM bytecode. It detects a virtualized OEP
  (`jmp`/`call`, `push imm32; jmp`, `push imm32; push imm32; jmp`,
  `push imm; ret`, `mov reg, imm; jmp reg`) and, for 32-bit Themida V3,
  installs a PE-header anti-dump stub (also for `push imm32; jmp` entries).
  Shrink also follows `.text` references to Oreans-style VM entry stubs.
  Use a devirtualizer (e.g. Oreans Unvirtualizer) for the VM code itself,
  then run Shrink again if the VM sections are no longer needed.

* VM anti-dumps are not fixed in general. If the entry point or other code is
  virtualized, the dump can be broken, or it may run only on the machine that
  produced it, since many anti-dumps rely on DLL base addresses. One specific
  PE-header anti-dump is mitigated automatically for virtualized entry points.
  The other variants are not. If the loader relocated the image, the dumper
  rewrites the header `ImageBase` to the actual load address, so the dump is at
  least internally consistent.
* Unpacked DLLs lose their relocation information. That can cause trouble when
  loading them into larger applications. The `Fix DLL relocations` option
  scans the dump for absolute pointers into the image and rebuilds a `.reloc`
  section, merging any entries that survived unpacking. The dump header already
  stores the address the image was loaded at, so the reconstructed deltas are
  consistent. The scan is heuristic (an integer that happens to fall inside the
  image looks like a pointer), so verify the DLL after loading it at a
  different base. The option is available for Unpack and Shrink and is off by
  default.
* Targets from 2007 to 2009 may not unpack on modern Windows. Windows XP may be
  required.
* Do not enable compatibility mode for Magicmida or the target. Shimming breaks
  unpacking. Magicmida embeds a manifest to reduce automatic AppCompat patching,
  but stale AppCompat registry entries can still exist. If a target suddenly
  stops unpacking, move it to a different path or check
  `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`.
* `uiAccess="true"` targets need the same signing and trusted-location workaround
  described in the original README.

## Project layout

```text
build.sh              builds the worker and the final executable into build/ (Linux)
build.ps1             same build for Windows/MinGW-w64 (PowerShell)
src/
  gui_main.cpp        application entry point, Win32 GUI, and worker mode
  pe_report.*         human-readable PE info and target-machine detection
  common.*            logging, formatting, paths, pattern scanning, Win32 helpers
  stream.*            TFileStream/TMemoryStream replacements
  pe_info.*           PE header/section editing
  reloc_fix.*         DLL base relocation reconstruction
  disasm.*            packed BeaEngine interface + DisasmCheck
  debugger_core.*     process creation, debug loop, HW/SW breakpoints
  tracer.*            single-step tracer
  themida_common.*    shared Themida logic (IAT search, import tracing)
  themida32.*         32-bit Themida/WinLicense logic
  themida64.*         64-bit Themida/WinLicense logic
  dumper.*            module snapshot, forwards/ApiSets, dump + import rebuild
  patcher.*           shrink, .rdata/.data restoration, dumpcode
  antidump_fix.*      VM anti-dump (PE header) mitigation
  onecore_uap.*       ApiSet (OneCoreUAP) table lookup
  scyllahide.*        embedded ScyllaHide loading/mapping/deferred hooking
vendor/beaengine/     prebuilt BeaEngine objects (from the original repo)
vendor/scyllahide/    pinned ScyllaHide subset + local patches
cmake/                toolchain files, resource and worker-embedding helpers
resources/            manifest and resource script
tools/                helper scripts (ApiSet table generator, build helper)
```

## License

Magicmida is licensed under the GPLv3, like the original project. The bundled
BeaEngine object files and header are LGPLv3. The vendored ScyllaHide subset is
GPLv3; see `vendor/scyllahide/LICENSE`.
