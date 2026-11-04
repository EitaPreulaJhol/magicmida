#!/usr/bin/env bash
# Builds the internal 32-bit worker and the final 64-bit magicmida.exe.
# Final output: build/magicmida.exe
set -euo pipefail

cd "$(dirname "$0")"

if [[ "${1:-}" == "--clean" ]]; then
    rm -rf build
fi

# 1. Internal 32-bit worker (not a standalone application).
cmake -S . -B build/x86 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw32.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/x86 -j

# 2. 64-bit application with the 32-bit worker embedded.
cmake -S . -B build/x64 \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-mingw64.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DMAGICMIDA_32BIT_WORKER="$PWD/build/worker/magicmida_worker.exe"
cmake --build build/x64 -j

echo
echo "Built:"
echo "  build/magicmida.exe"
echo "  internal worker: build/worker/magicmida_worker.exe"
