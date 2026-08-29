# Committed Conan profile — the Linux/GCC-13 lane that must hold.
# Pins EXACT settings so every lane resolves the SAME package_id and can never
# silently fall back to a wrong-config prebuilt (root-cause of the Boost 1.90.0
# torn-header flakes). See ci-boost-stream.md §B.
[settings]
os=Linux
arch=x86_64
build_type=Release
compiler=gcc
compiler.version=13
compiler.cppstd=20
compiler.libcxx=libstdc++11

[buildenv]
CC=gcc-13
CXX=g++-13
