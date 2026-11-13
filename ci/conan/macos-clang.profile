# Committed Conan profile — macOS / apple-clang lane (cppstd=20), per the Boost
# root-fix plan (§B). Used by .github/actions/provision-macos-deps for every
# macOS build (release.yml and build.yml). All macOS builds run on an Apple
# Silicon host, so both contexts default to armv8; the x86_64 slice is a Conan
# cross build that retargets only the host context with -s:h arch=x86_64.
# compiler.version is the Apple clang of the build host; every macOS package is
# built from source there, so the value labels the binaries in the runner's
# own cache rather than selecting prebuilt ones.
[settings]
os=Macos
arch=armv8
build_type=Release
compiler=apple-clang
compiler.version=21
compiler.cppstd=20
compiler.libcxx=libc++

[options]
# Boost.Locale is unused by c2pool, and on macOS it would pull libiconv, which
# conan.lock (resolved on Linux, where iconv is part of glibc) does not pin.
boost/*:without_locale=True
