# Reproducible build: `c2pool-v37-xmr`

The CCS milestone ships a release binary. Anyone must be able to check that the
published binary was built from the published source. This page says what
makes the Release build of `c2pool-v37-xmr` byte-reproducible, what an outsider
has to match, and how to check it.

**Claim (measured, one host):** two clean Release builds of the same commit give
the same sha256, for the unstripped binary and for the stripped one. The two
builds may use different source checkouts, build dirs, Conan homes (users or
`$HOME`s), wall-clock times, time zones, locales and umasks.

**Not claimed yet:** the same bytes from a different distro, glibc, compiler or
binutils build. That needs a pinned container image (see *Cross-host* below).

## Check it

```sh
scripts/xmr-release-repro-check.sh            # HEAD
scripts/xmr-release-repro-check.sh v0.x.y     # any commit-ish
```

The script builds the commit twice from scratch with ccache disabled:

| | build A | build B |
|---|---|---|
| source | `<work>/a/src` (git worktree) | `<work>/b/some/deeper/path/src` |
| build dir | `<work>/a/build` | `<work>/b/out/other-build` |
| Conan home | your `conan config home` | `<work>/b/conan-home`, restored from exactly the packages build A resolved |
| start time | T | T + build A + 65 s |
| TZ / LC_ALL / umask | UTC / C / 022 | Asia/Tokyo / C.UTF-8 / 002 |

It then compares sha256 of both binaries, before and after `strip --strip-all`.
Exit code 0 means identical, 1 means they differ, and 2 means a setup or build error.
If they differ, it prints the differing ELF sections (with the number of differing
bytes), the symbol-table delta, and the path classes that leak: source or build dir,
Conan home, RUNPATH, or date-like strings.

The script adds no reproducibility flags of its own. Everything lives in the
build system, so the plain recipe below produces the same bytes.

Environment variables: `REPRO_WORKDIR`, `REPRO_JOBS`, `REPRO_NICE`,
`REPRO_GAP_SECONDS`, `REPRO_CONAN_BUILD` (default `missing`; use `never` on a
warm cache), `REPRO_KEEP=1` (keeps the trees for inspection), and
`REPRO_SAME_CONAN_HOME=1`. Measured runtime on an i7-14700T with `-j8 nice 15`
and a warm Conan cache: about 5.5 min. That is 2 × ~90 s of compile, about 70 s
of `conan cache save/restore`, and the 65 s gap.

## The recipe (what the release builder runs)

```sh
git clone https://github.com/frstrtr/c2pool && cd c2pool
git checkout <release-commit>                  # full clone WITH tags, see "Version string"
conan install . -pr:a=ci/conan/linux-gcc13.profile --lockfile=conan.lock \
      --build=missing --output-folder=build -nr
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
      -DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON
cmake --build build -j"$(nproc)" --target c2pool-v37-xmr
sha256sum build/src/c2pool/c2pool-v37-xmr
strip --strip-all -o c2pool-v37-xmr.stripped build/src/c2pool/c2pool-v37-xmr
sha256sum c2pool-v37-xmr.stripped
```

ccache on or off does not change the output. A cold ccache build and a warm one
(50/50 hits) both gave the same sha256 as the ccache-off builds. The job count
should not matter either, because CMake fixes the link order, but it was not
varied in the measurement (every build used `-j8`).

## What the build system does

| Source of difference | Status on `c2pool-v37-xmr` | Handling |
|---|---|---|
| Conan home path in `__FILE__` (14 Boost.Asio / Boost.Multiprecision throw sites record their header path in `boost::source_location`, which lands in `.rodata`) | **leaked** before this change | `cmake/ReproducibleBuild.cmake`: `-ffile-prefix-map=<CONAN_HOME>=conan-home`. The Conan home is derived from the toolchain's include and library search path (`<home>/p/[b/]<pkg>/p/{include,lib}`). |
| Build RUNPATH `<CONAN_HOME>/p/boost…/p/lib` in `.dynamic` | **leaked** before this change | `SKIP_BUILD_RPATH ON` on `c2pool-v37-xmr`. That directory holds only static archives. The daemon's `NEEDED` list is libstdc++, libgcc_s and libc, so the RUNPATH never resolved anything. |
| Source dir / build dir in `__FILE__` or debug info | not present in this target today (0 strings), but guarded | `-ffile-prefix-map=<src>=.` and `-ffile-prefix-map=<build>=.` (the build dir is listed last so that it wins when nested) |
| `__DATE__` / `__TIME__` / `__TIMESTAMP__` | none in the target (0 date-like strings) | nothing to do. `SOURCE_DATE_EPOCH` is not needed, and the script unsets it to prove that. |
| Version string (`git describe --tags --always --dirty`, generated at build time) | a function of the commit and the tags | see *Version string* |
| build-id | GNU ld's default `--build-id=sha1` is content-derived | identical once the content is identical |
| Static archives (`ar`) | Ubuntu binutils 2.46 `ar` is deterministic (`D`) by default. Member order comes from CMake. | nothing to do |
| LTO / PGO | not used (`-O3 -DNDEBUG`) | the optimisation flags are unchanged |
| Locale, TZ, umask, wall-clock time, ccache | no effect (measured) | none |

The file-prefix maps change **only recorded path strings**. For example, the
Boost throw site now reads `conan-home/p/boostf82ae2881fe5c/p/include/boost/asio/…`
where it used to read `/home/<user>/.conan2/p/…`. A diff of base and fix
disassembly, normalised for addresses, is identical, and so are all the
symbol sizes except `_DYNAMIC`, which is one entry shorter because the RUNPATH
is gone. `--help` output is byte-identical, and `--mock-smoke` passes 83/83 on
both. `-fmacro-prefix-map` (implied by `-ffile-prefix-map`) rewrites
`__FILE__` only. It never rewrites string literals or `-D…="${CMAKE_SOURCE_DIR}/…"`
definitions, so tests that locate data through such defines are unaffected.
The prefix maps apply to every target, and `C2POOL_REPRODUCIBLE_PATHS=OFF`
switches them off.

## What an outsider must match

1. **The commit and its tags.** Use a full clone (`git clone`, not `--depth 1`).
   The embedded version is `git describe --tags --always --dirty`. A shallow or
   tag-less clone yields a different string, and so a different binary. A
   modified tree yields a `-dirty` suffix.
2. **The host OS image.** Measured on Ubuntu 26.04.1 LTS (glibc 2.43) with
   `g++-13` 13.4.0 (`Ubuntu 13.4.0-10ubuntu1`, reached as `/usr/bin/c++`),
   GNU binutils 2.46 (ld, ar, strip), CMake 4.2.3 and Conan 2.31.2. A different
   compiler or binutils build gives different code or layout.
3. **The Conan profile and lockfile.** Use `ci/conan/linux-gcc13.profile`
   (gcc 13, C++20, libstdc++11, Release) and `conan.lock` (recipe revisions).
   Resolving with and without the lockfile gives the same 11 package references
   today.
4. **The Conan package binaries.** Only Boost *headers* reach this binary. The
   daemon links no Conan static library (it links its own static archives, Boost
   headers and the system C++ runtime). The package that matters is therefore
   `boost/1.90.0#cd8d6667856c182d561afc841f1a8252:67d064756c5cd8ddb96f75c0339fe34766849071#f9db09fafacb8c39041f59281e8a6b27`.
   Its package-folder name (`boostf82ae2881fe5c`) is recorded in the
   `conan-home/…` strings. That name is derived from the reference, so it is the
   same in every Conan home that holds this package revision (measured by
   restoring the package into a second home).
5. **The options:** `-DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON`, target
   `c2pool-v37-xmr`, and no extra `CFLAGS`, `CXXFLAGS` or `LDFLAGS` in the
   environment.

No compiled-in pinned snapshot exists on master yet. When one lands as data
compiled into the daemon, the same check covers it, because it is part of the
binary.

## Cross-host (not in this slice)

Getting identical bytes on another machine needs:

- a pinned container image (by digest) that provides the compiler, binutils,
  glibc headers, CMake and Conan listed above;
- the Conan packages as binaries of the exact package revisions above, for
  example from a `conan cache save` archive published next to the release. The
  alternative is Conan recipes that build reproducibly, but `--build=missing`
  from source on another host is not verified;
- a release job that builds and publishes `c2pool-v37-xmr`.
  `.github/workflows/release.yml` does not build this target today.
