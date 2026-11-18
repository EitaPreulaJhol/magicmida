# Style policy

First-party code in `src/` follows the Google C++ Style Guide. Vendored code
under `vendor/` and generated tables are excluded. CI enforces formatting with
`clang-format` and `cpplint`.

## Exceptions: documented waiver

The Google guide prohibits C++ exceptions. This project intentionally keeps
the exception-based error handling inherited from the Delphi port. A full
migration would change most public signatures (streams, PE editing, dumper,
debugger, GUI) and is tracked as a separate project.

Waiver conditions:

- The current exception sites are frozen in
  `tools/exception_baseline.json`.
- New `throw`, `try`, or `catch` sites are not allowed in `src/`. CI runs
  `tools/check_exceptions.py` and fails when any file grows past the baseline.
  Removing sites is always allowed; refresh the baseline with
  `python3 tools/check_exceptions.py --update` in the same change.
- New constructors must not signal failure through exceptions. Use a factory
  or an `Init()` method with an error output.
- New code should prefer error codes, a `bool` plus an error string, or a
  `Status`-style result.
- The vendor-required `scl::Logger g_log` in `scyllahide.cpp` is the only
  static object with a non-trivial destructor and is documented in the source
  as an exception required by the ScyllaHide sources.

Migration path: reduce the baseline file by file, starting with boundaries
that already return `bool` or error strings, then `Stream`, `PEHeader`,
`Patcher`, and `Dumper`, and finally remove the `try`/`catch` blocks in the
GUI and debug loop. Delete this waiver when the baseline is empty.

## Other known deviations

- `#pragma pack` is used for packed PE/BeaEngine layouts; a portability
  wrapper is still pending.
- Includes are grouped as project, system, then standard library; the
  include-order cleanup is a separate change.
- `DebuggerCore` and `ThemidaCommon` expose `protected` state to their
  subclasses; accessors are pending.
- File-level copyright/license headers are not present yet.
