# CI wiring for c2wallet-qt

Two prepared patches wire c2wallet-qt into the repo's workflows:

| Patch | Workflow | What it adds |
|---|---|---|
| [`ci-wiring.build-yml.patch`](ci-wiring.build-yml.patch) | `.github/workflows/build.yml` | job **`c2wallet-signer-guard`**: on every PR touching `ui/**` / `src/**`, build the signer, run the network-incapable link-guard, then build and run the whole c2wallet-qt `ctest` |
| [`release-wiring.release-yml.patch`](release-wiring.release-yml.patch) | `.github/workflows/release.yml` | jobs **`c2wallet-linux`**, **`c2wallet-macos`**, **`c2wallet-windows`**, **`c2wallet-companion-linux`**: package the signer for every platform (and the companion for Linux) next to the coin packages, in the same draft and the same `SHA256SUMS`; a `components` dispatch input |

## Why they are delivered as patches

A push that changes a file under `.github/workflows/` needs a token with the
`workflow` OAuth scope, which the pushing token does not carry. The diffs were
made on a scratch copy of the master workflow files, checked with
`git apply --check` against an unmodified copy, applied, and the result parsed
with `yaml.safe_load`; the workflow files themselves are not edited in this
tree.

## Applying them

From the repo root, with a login that has the `workflow` scope:

```sh
git apply --check ui/c2wallet-qt/ci/ci-wiring.build-yml.patch
git apply --check ui/c2wallet-qt/ci/release-wiring.release-yml.patch
git apply ui/c2wallet-qt/ci/ci-wiring.build-yml.patch ui/c2wallet-qt/ci/release-wiring.release-yml.patch
python3 -c "import yaml; [yaml.safe_load(open(f)) for f in ('.github/workflows/build.yml', '.github/workflows/release.yml')]"
git add .github/workflows/build.yml .github/workflows/release.yml
git commit -m "ci: c2wallet-qt link-guard + ctest (build.yml) and signer packages (release.yml)"
git push
```

The two patches are independent; either can be applied alone. If master's
workflows moved and `--check` fails, `git apply -3` uses the blob ids in the
patch headers for a three-way merge.

Acceptance test after applying `release.yml` (no coins built, no draft
created because the ref is not a tag):

```sh
gh workflow run release.yml -f components=c2wallet -f version=0.0.0-test
```

## `build.yml`: `c2wallet-signer-guard`

- Gated on `needs.changes.outputs.qt` (`ui/**`, `src/**`, CMake) or any
  non-PR event; `draft-release` self-hosted runner (NOPASSWD sudo + Qt6),
  `ubuntu-24.04` for forks; `timeout-minutes: 25`.
- apt: `qt6-base-dev`, `libsecp256k1-dev`, `zlib1g-dev`,
  `nlohmann-json3-dev` (the companion needs it), `python3` (the python oracle
  tests), no webengine / webchannel.
- `cmake -S ui/c2wallet-qt -B build-c2wallet -DC2WALLET_QT_BUILD_TESTS=ON`,
  build `c2wallet-qt-signer`, run
  `./ui/c2wallet-qt/ci/check_no_network.sh build-c2wallet/c2wallet-qt-signer`
  (fails fast, before the test build), then build everything and run
  `ctest --test-dir build-c2wallet --output-on-failure`: the hdkeys, convert,
  signer, artifact and DASH KATs (the Dash Core signed-message vectors
  included), the gov-hash and UTXO-export python oracles, the companion KATs,
  the key-free guard and `no_network_link_guard`.

## `release.yml`: the c2wallet jobs

Triggers and versions are the node's: tags `v*` and `workflow_dispatch`; the
`Resolve version` step is copied (tag `vX.Y.Z` -> `X.Y.Z`, the `version`
input, else `0.0.0-<sha8>`). The new `components` input (default
`node,c2wallet`) gates the node jobs (`linux`, `macos`, `macos-universal`,
`windows`) on `node` and the c2wallet jobs on `c2wallet`. The c2wallet
artifacts are named `pkg-c2wallet-*`, so the `checksums` job's `pkg-*`
download picks them up unchanged; its `needs:` gains the four jobs and keeps
`if: always()`, so a red wallet job never blocks the coin packages.

| Job | Runner (self-hosted / fallback) | Produces | Checks on the packaged binary |
|---|---|---|---|
| `c2wallet-linux` | `draft-release` / `ubuntu-24.04` | `c2wallet-qt-signer-<v>-linux-x86_64.AppImage` and `.tar.gz` (same files) | `check_no_network.sh` on `usr/bin/c2wallet-qt-signer` of the extracted AppImage and the tarball, `check_package_no_network.sh`, `MANIFEST.txt` re-check, `--version` via `AppRun` and via the AppImage |
| `c2wallet-macos` | `c2pool-mac-arm` / `macos-14` | `c2wallet-qt-signer-<v>-macos-universal.zip` and `.dmg` | `check_no_network_macho.sh` (both slices), `check_package_no_network.sh` on the `.app`, `codesign --verify --deep --strict`, `--version` (and `arch -x86_64 ... --version` when Rosetta exists) |
| `c2wallet-windows` | VM217 (`c2pool-build`) / `windows-2022` | `c2wallet-qt-signer-<v>-windows-x86_64.zip` and `-setup.exe` | `check_no_network_pe.ps1`, `check_package_no_network.ps1`, `--version` |
| `c2wallet-companion-linux` | `draft-release` / `ubuntu-24.04` | `c2wallet-qt-companion-<v>-linux-x86_64.tar.gz` (GUI + `c2wallet-qt-schedd` + `.service`) | `check_key_free.sh` on both binaries, `check_no_gui_link.sh` on the daemon; green-skip until PR #2123 (the scheduler) is on the ref |

The signer and the companion are never in one package: one is proven
network-incapable, the other key-free.

Qt per platform (dynamic everywhere, bundled by the official deploy tools;
LGPL notices in `licenses/`):

- Linux: apt `qt6-base-dev` 6.4.2, the same package the PR-time guard uses;
  `installer/linux/c2wallet-appimage.sh` runs `linuxdeploy` +
  `linuxdeploy-plugin-qt` and `appimagetool`, each pinned by release tag and
  sha256 (and the AppImage runtime file too). glibc floor 2.39 (Ubuntu 24.04).
- macOS: `aqtinstall==3.3.0`, `aqt install-qt mac desktop 6.8.3 clang_64`
  (one universal Qt), one job with `-DCMAKE_OSX_ARCHITECTURES="arm64;x86_64"`;
  libsecp256k1 `v0.7.1` built universal and static with the recovery module;
  `macdeployqt`, then an ad-hoc `codesign`; `installer/macos/create-dmg.sh`
  in staged mode (unchanged). The two-runner `lipo` fallback is described in
  the job's comment.
- Windows: `aqt install-qt windows desktop 6.8.3 win64_msvc2022_64` (dynamic
  CRT, like the node); zlib `v1.3.1` (static) and libsecp256k1 `v0.7.1`
  (DLL, like the node cell) from pinned tags; `windeployqt --release
  --no-translations --no-opengl-sw --no-system-d3d-compiler
  --no-compiler-runtime --skip-plugin-types
  tls,networkinformation,qmltooling,generic`; Inno Setup with
  `installer/windows/c2wallet-qt-setup.iss` (per user, no admin, no firewall
  rule, launch box unticked).

Qt 6.8.3 is the last open-source 6.8 patch on download.qt.io and needs macOS
12+ / Windows 10 1809+. If the operator's Intel Mac runs macOS 11, set
`QT_VERSION: '6.5.3'` in `c2wallet-macos` and `LSMinimumSystemVersion` in
`packaging/Info.plist.in` to 11.0.

Reproducibility: `SOURCE_DATE_EPOCH` from the commit, `-ffile-prefix-map` on
GCC/clang, `/Brepro` on MSVC, tar with sorted names / fixed mtime / numeric
owner and `gzip -n`. The DMG, `setup.exe` and the AppImage runtime header are
not bit-reproducible; every package carries `MANIFEST.txt` (sha256 of each
file inside) so the inner binary can be compared across builds.

### Runner prerequisites

- `draft-release` (Linux): NOPASSWD sudo for apt (as the PR-time job), `curl`
  to fetch the pinned AppImage tools once (cached in
  `~/.cache/c2wallet-appimage-tools`).
- `c2pool-mac-arm`: Xcode command-line tools, `python3` with `venv` (aqt is
  installed into a private venv per run), Homebrew `cmake`; Rosetta is used
  when present to execute the x86_64 slice.
- VM217: no bash; every step is PowerShell (`-ExecutionPolicy Bypass`) or
  cmd, as in the node cell. Python through the `py` launcher (for `pip install
  aqtinstall`), git, CMake, Visual Studio 2022 (dumpbin is found through
  vswhere), Inno Setup 6 (installed on first use like the node cell).

### Code signing (not wired; operator decision)

Today: macOS ad-hoc signature (mandatory on arm64), Windows unsigned
(SmartScreen "More info" -> "Run anyway"), Linux nothing to sign;
`README-SIGNER.txt` in every package says how to open each. With
certificates, add separate jobs that run only when the secrets exist:

- macOS: Developer ID Application certificate (`APPLE_DEVID_P12`,
  `APPLE_DEVID_P12_PASSWORD`), App Store Connect API key for `notarytool`
  (`APPLE_API_KEY_ID`, `APPLE_API_ISSUER`, `APPLE_API_KEY_P8`), then
  `xcrun stapler staple`.
- Windows: Authenticode certificate (`WIN_CODESIGN_PFX`,
  `WIN_CODESIGN_PASSWORD`), `signtool sign /fd sha256 /tr <rfc3161> /td sha256`.

Signed output is not bit-reproducible (the signature embeds the certificate
and a timestamp).

### SHA256SUMS and `.asc`

CI holds no signing key: `checksums` writes `SHA256SUMS` over every package
(coins and wallet) into the draft. The operator signs it offline,
`gpg --detach-sign --armor SHA256SUMS`, and uploads `SHA256SUMS.asc` to the
draft before publishing.

### Cost

Per tag, on the self-hosted defaults: Linux ~10-14 min, macOS ~20-28 min,
Windows ~22-30 min, companion ~8-10 min, all in parallel with the coin matrix
(which is longer). With `force-github-hosted=true`, macOS minutes bill at 10x
and Windows at 2x: roughly 250 + 60 billed minutes per tag.

## The guard scripts

| Script | Platform | Proves |
|---|---|---|
| [`check_no_network.sh`](check_no_network.sh) | ELF (Linux) | no networking `NEEDED` library, no imported network C-ABI symbol |
| [`check_no_network_macho.sh`](check_no_network_macho.sh) | Mach-O (macOS), every slice | no networking library / framework in the load commands (`otool -L`), no imported network symbol (`nm -u`) |
| [`check_no_network_pe.ps1`](check_no_network_pe.ps1) | PE (Windows) | no networking DLL (`dumpbin /dependents`), no imported network function (`dumpbin /imports`) |
| [`check_package_no_network.sh`](check_package_no_network.sh) / [`.ps1`](check_package_no_network.ps1) | the staged package | no QtNetwork, no `tls` / `networkinformation` plugin, no curl / OpenSSL anywhere in the package |
| [`check_key_free.sh`](check_key_free.sh) | companion | no private-key or signing symbol |

They inspect the signer's own imports and the package's contents. What the
bundled Qt libraries themselves import (on Windows `Qt6Core.dll` imports
`ws2_32.dll` for `gethostname`) is out of scope at this layer; the runtime
seccomp belt (design §5.2 layer 3) is still unimplemented and nothing here
claims it.

Until the patches are applied, the ELF guard still runs locally via `ctest`
(`no_network_link_guard`, registered by `-DC2WALLET_QT_BUILD_TESTS=ON`).
