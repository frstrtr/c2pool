# Committed Conan profile — macOS / apple-clang lane (cppstd=20), per the Boost
# root-fix plan (§B). NOTE: release.yml's macOS lanes currently build against
# Homebrew deps, NOT Conan, so this profile is not yet wired into release.yml.
# It is committed for provenance and for a future macOS->Conan migration; arch
# is per-runner (armv8 on Apple Silicon, x86_64 on Intel), override with -s arch=.
[settings]
os=Macos
arch=armv8
build_type=Release
compiler=apple-clang
compiler.version=16
compiler.cppstd=20
compiler.libcxx=libc++
