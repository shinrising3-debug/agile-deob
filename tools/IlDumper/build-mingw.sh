#!/usr/bin/env bash
# Cross-compile the Windows x64 dumper + injector from Linux using MinGW-w64.
#   sudo apt-get install -y mingw-w64
#   ./build-mingw.sh
# Produces build/dumper.dll and build/inject.exe (real PE32+ binaries).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
CXX=x86_64-w64-mingw32-g++
FLAGS="-O2 -static-libgcc -static-libstdc++"
$CXX $FLAGS -shared -o build/dumper.dll dumper.cpp
$CXX $FLAGS        -o build/inject.exe  inject.cpp
echo "built: build/dumper.dll build/inject.exe"
