# Changelog

All notable changes to Magicmida (C++ port) are documented here.

## [1.0.0] - 2026-11-04

Initial public release.

- Native Win32 GUI with target drag-and-drop, automatic PE info, status
  reporting, cancellation, and log save/copy.
- Themida/WinLicense unpacking for 32-bit and 64-bit targets. The 64-bit
  executable embeds a 32-bit worker for 32-bit targets.
- Embedded, pinned ScyllaHide (`baa5c8e`) with deferred user32 hooking.
- Import reconstruction, API-set/forwarder resolution, DLL relocation
  reconstruction, `.rdata`/`.data` restoration, and process-code dump.
- Shrink that preserves runtime sections, relocates exception tables out of
  protector sections into `.pdata`, and writes a `.bak` backup.
- PE-header snapshot at the OEP with automatic restore when an anti-dump
  corrupts the live header.
- Final PE layout normalization: aligned headers/section raw data, remapped
  debug/COFF file offsets, preserved certificate table, and zeroed checksum.
- CLI mode for unpack/shrink/mkdata/dumpcode/info with `--version` and
  `--help`.
- Licensing and third-party notices for the original Magicmida, ScyllaHide,
  BeaEngine, and distorm.
