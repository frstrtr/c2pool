# macOS builds in CI

Every macOS package c2pool ships is a universal binary (arm64 + x86_64). Since
2026-11-13 all macOS builds, in `release.yml` and `build.yml`, run on one host:
the Apple Silicon build host (self-hosted runner labels `self-hosted, macOS,
ARM64, c2pool-mac-arm`). It builds both slices of every coin, around the clock.
Fork PRs, and release runs dispatched with `force-github-hosted`, use the
GitHub-hosted `macos-14` image instead, which is also Apple Silicon.

## Intel Macs

The Intel Mac that used to build the x86_64 slice is retired as a build host;
it is now a remote-control terminal, not a CI runner. No workflow targets the
`c2pool-mac-intel` labels any more, and the `MAC_INTEL_OFFLINE` and
`MAC_INTEL_PAUSED` repository variables are no longer read by any workflow.

Intel Macs are still a supported target. Every macOS package carries an x86_64
slice, so the same `.dmg` / `.zip` runs natively on Intel and on Apple Silicon.

## How the x86_64 slice is built

The x86_64 slice is cross-compiled on Apple Silicon: Apple clang with
`-arch x86_64` (CMake `CMAKE_OSX_ARCHITECTURES=x86_64`). Nothing is built under
Rosetta; Rosetta 2 is only used to run the result.

Both slices link the same pinned library sources, provisioned per architecture
by `.github/actions/provision-macos-deps`:

| Library | Source | x86_64 slice |
|---|---|---|
| boost, leveldb (+snappy, crc32c), yaml-cpp, nlohmann_json, zeromq, gtest | `conanfile.txt` + `conan.lock`, profile `ci/conan/macos-clang.profile` (the same pins as Linux and Windows) | Conan cross build: `-s:h arch=x86_64`; the build context stays armv8, so tools such as b2 run natively |
| secp256k1 | `scripts/ci/build_macos_deps.sh`, pinned tag and commit | CMake, `CMAKE_OSX_ARCHITECTURES=x86_64` |
| gmp (linked by DASH only) | `scripts/ci/build_macos_deps.sh`, pinned version and SHA-256 | autotools `--host=x86_64-apple-darwin` (generic x86-64 code) |
| dashbls (DASH only) | `scripts/build_dashbls.sh`, dash's own `src/dashbls` at the pinned tag | autotools `--host=x86_64-apple-darwin`; relic backend EASY on x86_64 and GMP on arm64, the same split dash's configure gives dashd |

Homebrew provides build tools only (cmake, conan, autotools, pkg-config,
sccache). No Homebrew library is linked into either slice: Homebrew publishes
arm64-only bottles, and linking them would give the two slices different
library versions. The configure step passes
`CMAKE_IGNORE_PREFIX_PATH="/opt/homebrew;/usr/local"` so nothing is picked up
from there by accident.

All third-party libraries are linked statically. The package bundles only the
in-tree dylibs (for DASH, `libdash_scriptcheck.dylib`), and those are built for
both architectures and lipo-merged like the executable.

On the self-hosted runner the Conan cache and the per-arch library prefixes
live under `~/.c2pool-deps/` and are reused across jobs; only a change to a pin
rebuilds them (a cold Conan build of the whole set takes about five minutes per
arch on the build host).
GitHub-hosted runners restore them from the Actions cache.

## How it is verified

Per-arch job (`macos` in both workflows):

1. `lipo -archs` on the built binary must print exactly the job's arch.
2. The binary must start: arm64 natively, x86_64 under Rosetta 2
   (`arch -x86_64 <binary> --help`, exit status 0;
   `scripts/ci/macos_slice_smoke.sh`). A host without Rosetta 2 fails the job.
3. DASH: the BLS link guard, the `DASH BLS backend: REAL` line, and the BLS
   KATs (`test_dash_bls_verify`, run under Rosetta 2 for x86_64).

Universal job (`macos-universal` in `release.yml`):

1. lipo-merge the two trees. A dylib present in only one tree fails the merge.
2. Ad-hoc re-sign every Mach-O file (this is not a Developer ID signature).
3. `lipo -archs` on the binary and on every bundled dylib must show exactly
   `arm64` and `x86_64`.
4. Start both slices of the signed universal binary again (arm64 natively,
   x86_64 under Rosetta 2). The log also prints each slice's minimum macOS.
5. DASH: the BLS rodata guard on each slice, gmp linked statically where relic
   uses it (or bundled universal), and a REAL backend on both slices.
6. Zip and DMG (`installer/macos/create-dmg.sh --staged ... --arch universal`).

## Limits

- Rosetta 2 runs x86_64 code on Apple Silicon; it is not Intel hardware. The
  x86_64 slice is started and its DASH BLS KATs pass under Rosetta, but no CI
  job runs on a real Intel CPU.
- With `PR_LINUX_ONLY=true` pull requests skip the macOS legs of `build.yml`;
  they run on pushes to master and in every `release.yml` run.
- The macOS legs are serialized on one host, so a full release run takes
  longer than when two machines shared the work.
