#!/usr/bin/env bash
# Compatibility wrapper. The canonical build script is ./build.sh.
set -euo pipefail
exec "$(dirname "$0")/../build.sh" "$@"
