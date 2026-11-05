# Third-party notices

Magicmida (C++ port) is distributed under the GNU General Public License v3.
See `LICENSE`.

## Original Magicmida

- Project: https://github.com/Hendi48/Magicmida
- License: GPLv3
- This C++ port is derived from the original Delphi sources. The original
  project's copyright and license notices apply to the derived logic.

## ScyllaHide

- Project: https://github.com/x64dbg/ScyllaHide
- License: GPLv3
- Pinned revision: `baa5c8e` (`v1.4-5-gbaa5c8e`)
- A trimmed, locally patched subset is vendored in `vendor/scyllahide/`.
  See `vendor/scyllahide/LICENSE`, `vendor/scyllahide/UPSTREAM`, and
  `vendor/scyllahide/README.magicmida.md` for the local changes.

## BeaEngine

- Project: https://github.com/BeaEngine/beaengine
- License: LGPLv3
- The prebuilt `BeaEngineLib64.obj` and `BeaEngineLibFPC.obj` come from the
  original Magicmida repository and are linked unmodified. The public header
  is mirrored in `src/disasm.h`. See `vendor/beaengine/LICENSE.LGPL` and
  `vendor/beaengine/README.md` for the source-availability statement.

## distorm

- Project: https://github.com/gdabah/distorm
- License: BSD 3-Clause for the decoder sources; `decoder.h` carries a GPLv3
  notice.
- The vendored copy lives in `vendor/scyllahide/3rdparty/distorm/`. See
  `vendor/scyllahide/3rdparty/distorm/COPYING`.

## ntdll import libraries

The MSVC import libraries under `vendor/scyllahide/3rdparty/ntdll/` are part
of the vendored ScyllaHide snapshot and are used only for linking. They are
not redistributed as standalone libraries.

## OneCoreUAP API-set table

`src/onecore_uap_table.inc` is generated from public Windows API-set
metadata; it contains no third-party code.
