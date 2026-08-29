# Committed Conan profile — Windows / MSVC 2022 lane. Replaces the runtime
# `conan profile detect --force` + `cppstd 14->20` sed on the release Windows
# lane: pins EXACT settings so every lane resolves the SAME package_id and can
# never silently fall back to a wrong-config prebuilt Boost (root cause of the
# 1.90.0 torn-header flakes). See ci-boost-stream.md §B.
[settings]
os=Windows
arch=x86_64
build_type=Release
compiler=msvc
compiler.version=194
compiler.cppstd=20
compiler.runtime=dynamic
compiler.runtime_type=Release
