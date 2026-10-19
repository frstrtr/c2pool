# Build `c2pool-v37-xmr` from source (Ubuntu 24.04)

This page is for an operator who does not want to trust a binary built by
someone else. It builds the daemonless Monero node `c2pool-v37-xmr` from a
public commit on a fresh Ubuntu 24.04 x86_64 machine, checks it, and shows how
to install your own binary with the package scripts.

Every `sh` block below was run in order, by copy-paste, as a normal user
with `sudo` in a clean `ubuntu:24.04` container. The measured numbers are in
[Resources](#resources).

Related pages: [RUN-A-NODE.md](RUN-A-NODE.md) (run and join a pool) and
[REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md) (what makes the bytes
reproducible).

## 0. What you need

- Ubuntu 24.04 LTS, x86_64, with a normal user that can use `sudo`.
- Network access to `github.com`, `pypi.org` and `center2.conan.io`
  (Conan Center, where the dependency recipes and sources come from).
- 8 GB RAM for `JOBS=4` (about 1.5 GB per compile job plus headroom).
- 15 GB free disk in your home directory (source, Conan cache, build tree).
- 30 to 60 minutes. The first run builds Boost and the other dependencies
  from source. Later builds reuse the Conan cache and take a few minutes.

Run everything as your normal user, not as root. Only step 1 uses `sudo`.

## 1. System packages (once)

<!-- run -->
```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential g++-13 gcc-13 binutils make cmake git ca-certificates \
  python3 python3-venv libsecp256k1-dev perl pkg-config file
```

What each one is for:

| Package | Why |
|---|---|
| `g++-13`, `gcc-13` | The pinned compiler. The Conan profile asks for GCC 13 (it is the default `g++` on 24.04). |
| `build-essential`, `binutils`, `make` | `ld`, `ar`, `strip`, `objdump`, libc headers, make. |
| `cmake` | CMake 3.28.3 from Ubuntu. The tree needs 3.22 or newer. |
| `git`, `ca-certificates` | Clone over HTTPS. |
| `python3`, `python3-venv` | A private venv for Conan (Ubuntu 24.04 blocks `pip install` into the system Python). |
| `libsecp256k1-dev` | The one C library taken from the system. All others come from Conan. |
| `perl`, `pkg-config` | Used by some dependency builds. |
| `file` | Only for the check in step 6. |

Boost, zlib, bzip2, ZeroMQ, yaml-cpp, nlohmann_json, LevelDB and gtest are
**not** taken from the system. Conan builds the versions pinned in
`conan.lock`.

## 2. Conan 2 (pinned) in a private venv

<!-- run -->
```sh
python3 -m venv ~/c2pool-tools
~/c2pool-tools/bin/pip install --quiet "conan==2.31.2"
export PATH="$HOME/c2pool-tools/bin:$PATH"
conan --version
cmake --version | head -1
```

Expected: `Conan version 2.31.2` and `cmake version 3.28.3`.

`export PATH=...` lasts only for the current shell. Run it again in every new
shell before you use `conan` (step 5 does it for you).

## 3. Get the source and pin the commit

Pick the ref you build. For a release this is the release tag, and the
release notes (and the `BUILDINFO.txt` inside the release package) give the
full 40-character commit id. **No XMR node release tag exists yet.** Until
one does, build the commit your pool operator names. Every node of one pool
should run the same commit.

Set both values, then clone. Use a full clone (not `--depth 1`): the version
string compiled into the binary is `git describe --tags --always --dirty`,
so a shallow or tag-less clone gives a different binary.

<!-- run -->
```sh
C2POOL_REF="${C2POOL_REF:-09b85f856ad31a471c2128506ed346eb19bac9db}"
C2POOL_COMMIT="${C2POOL_COMMIT:-09b85f856ad31a471c2128506ed346eb19bac9db}"
git clone https://github.com/frstrtr/c2pool.git ~/c2pool
cd ~/c2pool
git checkout --detach "$C2POOL_REF"
test "$(git rev-parse HEAD)" = "$C2POOL_COMMIT" && echo "commit OK: $C2POOL_COMMIT"
git describe --tags --always --dirty
git status --porcelain | wc -l
```

The `test` line must print `commit OK`. The last line must print `0` (a
clean tree; otherwise the version gets a `-dirty` suffix).

A git commit id is a hash over the whole tree and its history, so a matching
40-character id pins every source file. Get the id from a place you trust
(the release notes, or your pool operator over a channel you trust), not from
the same page that hands you a binary.

If the release tag is signed, also check the signature. You need the
signer's public key first (the release notes say where it is published):

```sh
git tag -v "$C2POOL_REF"      # GPG-signed tag
git verify-commit HEAD        # or a signed commit
```

At the time of writing the repository's tags are annotated but not signed,
so `git tag -v` reports `no signature found`. Rely on the commit id then.

## 4. Dependencies with Conan

The profile `ci/conan/linux-gcc13.profile` in the tree pins the settings
(Linux, x86_64, gcc 13, C++20, libstdc++11, Release). `conan.lock` pins the
recipe revisions. `JOBS` is the number of parallel compile jobs: about
1.5 GB RAM each.

<!-- run -->
```sh
cd ~/c2pool
export PATH="$HOME/c2pool-tools/bin:$PATH"
JOBS="${JOBS:-4}"
conan profile detect --force
conan install . -pr:a=ci/conan/linux-gcc13.profile --lockfile=conan.lock \
  --build=missing --output-folder=build -c tools.build:jobs="$JOBS"
```

It ends with `Install finished successfully`. Conan fetches the recipes and
sources pinned by `conan.lock` from Conan Center. Where Conan Center has a
prebuilt binary for this exact profile (in the measured run: Boost, LevelDB,
yaml-cpp and others) it downloads it; the rest it builds here (for example
gtest and ZeroMQ). Only Boost *headers* reach `c2pool-v37-xmr` (see
[REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md#what-an-outsider-must-match)),
so no prebuilt Conan library ends up in the node binary. To build every
dependency from source anyway, use `--build='*'` instead of
`--build=missing`. That takes 20 to 40 minutes longer; its effect on the
binary's bytes was not measured.

## 5. Configure and build the node

The flags are the ones the release package uses
(`scripts/xmr-node/build-release.sh`): Release, RandomX on, libgcc linked in
statically.

<!-- run -->
```sh
cd ~/c2pool
export PATH="$HOME/c2pool-tools/bin:$PATH"
JOBS="${JOBS:-4}"
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON \
  -DCMAKE_EXE_LINKER_FLAGS=-static-libgcc
cmake --build build --target c2pool-v37-xmr -j"$JOBS"
```

- `-DXMR_BUILD_RANDOMX=ON` is required. Without RandomX the node cannot
  verify the proof of work of the blocks it receives.
- Build only the `c2pool-v37-xmr` target. The default target builds every
  coin and all tests.
- Do not set `CFLAGS`, `CXXFLAGS` or `LDFLAGS` in the environment: they
  change the binary.

## 6. Strip, check, hash

<!-- run -->
```sh
cd ~/c2pool
strip --strip-all -o c2pool-v37-xmr build/src/c2pool/c2pool-v37-xmr
./c2pool-v37-xmr --version
file c2pool-v37-xmr
objdump -p c2pool-v37-xmr | grep NEEDED
sha256sum build/src/c2pool/c2pool-v37-xmr c2pool-v37-xmr
```

Where things are:

| What | Path |
|---|---|
| unstripped binary | `~/c2pool/build/src/c2pool/c2pool-v37-xmr` |
| stripped binary (the one to run) | `~/c2pool/c2pool-v37-xmr` |
| dashboard files | `~/c2pool/web-static/` (pass `--dashboard-dir ~/c2pool/web-static`) |
| package scripts | `~/c2pool/scripts/xmr-node/` |

`--version` prints the build (the `git describe` string), the default network
and the pinned snapshot heights and block ids. `NEEDED` lists only
`libstdc++.so.6`, `libm.so.6`, `libc.so.6` and `ld-linux-x86-64.so.2`
(libgcc is linked in).

## 7. Optional: run the XMR tests

This builds every test whose name contains `xmr` (about 90 known-answer
tests and self-checks) in a second build tree and runs them. The second tree
uses Ninja, which compiles many test targets in parallel (with `make`, CMake
builds a list of targets one after the other). It does not touch the
release binary of step 5.

<!-- run -->
```sh
sudo apt-get install -y --no-install-recommends ninja-build
cd ~/c2pool
export PATH="$HOME/c2pool-tools/bin:$PATH"
JOBS="${JOBS:-4}"
cmake -S . -B build-tests -G Ninja -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release -DXMR_BUILD_RANDOMX=ON
XMR_TARGETS="$(ctest --test-dir build-tests -N -R 'xmr|v37_xmr' | awk '/Test +#/{print $3}')"
cmake --build build-tests -j"$JOBS" --target $XMR_TARGETS
ctest --test-dir build-tests -R 'xmr|v37_xmr' -j"$JOBS" --output-on-failure
```

The last line must end with `100% tests passed`.

## 8. Install your own binary with the package scripts

`build-release.sh` packs the build into the same tarball layout as a
published release (`bin/`, `share/web-static/`, docs, `install.sh`,
`node.env.example`, `SHA256SUMS`, `BUILDINFO.txt`). Point it at the build
directory from step 5 and pass the lockfile. The flags are the same as in
step 5, so nothing is recompiled; the script copies and strips the binary.

<!-- run -->
```sh
cd ~/c2pool
export PATH="$HOME/c2pool-tools/bin:$PATH"
JOBS="${JOBS:-4}"
CONAN_EXTRA="--lockfile=conan.lock" \
  scripts/xmr-node/build-release.sh --build-dir build --out-dir dist --jobs "$JOBS"
cd dist
sha256sum -c c2pool-xmr-*-linux-x86_64.tar.gz.sha256
tar xzf c2pool-xmr-*-linux-x86_64.tar.gz
sha256sum c2pool-xmr-*-linux-x86_64/bin/c2pool-v37-xmr ~/c2pool/c2pool-v37-xmr
cd c2pool-xmr-*-linux-x86_64
./install.sh --user
~/.local/c2pool-xmr/bin/c2pool-v37-xmr --version
```

The two `sha256sum` lines must match: the packaged binary is your step 6
binary. `install.sh --user` puts the binary, `run-node.sh` and the dashboard
under `~/.local/c2pool-xmr` and writes `~/.c2pool-xmr/node.env` if there is
none yet. Continue with RUN-A-NODE.md,
[The pinned snapshot](RUN-A-NODE.md#4-the-pinned-snapshot) and
[Join a pool, with the package](RUN-A-NODE.md#61-with-the-package):
edit `node.env`, then start the node the way `install.sh` prints it:

```sh
C2POOL_XMR_WORKDIR=~/.c2pool-xmr ~/.local/c2pool-xmr/bin/run-node.sh ~/.c2pool-xmr/node.env
```

(or add `--systemd` to `install.sh` for a unit file).

Without installing, `run-node.sh` also runs straight from the checkout. It
reads all node flags from `ARGS` in the env file, so add
`--dashboard-dir $HOME/c2pool/web-static` to `ARGS` there:

```sh
cp ~/c2pool/scripts/xmr-node/node.env.example ~/node.env   # then edit ARGS
C2POOL_XMR_BIN=~/c2pool/c2pool-v37-xmr ~/c2pool/scripts/xmr-node/run-node.sh ~/node.env
```

## 9. Compare with a published release

Download the release tarball and its `.sha256`, unpack it, and compare its
binary with yours:

```sh
sha256sum -c c2pool-xmr-<version>-linux-x86_64.tar.gz.sha256
tar xzf c2pool-xmr-<version>-linux-x86_64.tar.gz
cat c2pool-xmr-<version>-linux-x86_64/BUILDINFO.txt
sha256sum c2pool-xmr-<version>-linux-x86_64/bin/c2pool-v37-xmr ~/c2pool/c2pool-v37-xmr
```

Equal hashes mean the published binary is exactly what this source builds.
They can only be equal when all of these match (see
[REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md#what-an-outsider-must-match)):

- the commit (`commit:` in `BUILDINFO.txt`) and a clean, full clone;
- the OS image, compiler and binutils (`built_on:` and `compiler:`). A release
  built on Ubuntu 26.04 (GCC 13.4, binutils 2.46) does **not** give the same
  bytes as a build on Ubuntu 24.04 (GCC 13.3, binutils 2.42). Build on the
  release's OS image, for example in a `ubuntu:<version>` container;
- the Conan profile, `conan.lock` and the Boost package revision;
- the flags of steps 4 and 5, and no extra `CFLAGS`/`CXXFLAGS`/`LDFLAGS`.

To check that the build is reproducible on your own machine, independent of
any published file, run the two-build check from the tree (it builds the
commit twice with different paths, Conan homes, time zones and umasks and
compares the hashes; exit 0 means identical):

```sh
cd ~/c2pool
export PATH="$HOME/c2pool-tools/bin:$PATH"
REPRO_JOBS=4 scripts/xmr-release-repro-check.sh HEAD
```

It uses the plain recipe without `-static-libgcc`, so its hashes differ from
the ones of step 6. Both are reproducible.

## Common errors and fixes

| Symptom | Cause and fix |
|---|---|
| `Could not get lock /var/lib/dpkg/lock-frontend ... held by ... unattended-upgr` | The system is updating itself. Wait until that process exits, then rerun step 1. |
| `error: externally-managed-environment` from `pip` | You ran the system `pip`. Use the venv of step 2 (`~/c2pool-tools/bin/pip`). |
| `git clone` stops making progress (network stall) | Press Ctrl-C, `rm -rf ~/c2pool`, and rerun step 3. |
| `conan: command not found` | New shell. Run `export PATH="$HOME/c2pool-tools/bin:$PATH"`. |
| `conan install` hangs or fails downloading `bzip2` from sourceware.org | Upstream mirror trouble. See [doc/build-unix.md](../../doc/build-unix.md#conan-install-hangs--fails-downloading-from-sourcewareorg-bzip2) for the mirror fix, then rerun step 4. |
| `conan install` builds Boost from source for a long time | No prebuilt binary matched (for example a different compiler). It works, it only takes longer (20+ minutes). Check that you used `-pr:a=ci/conan/linux-gcc13.profile`. |
| `Could NOT find secp256k1` at configure | `libsecp256k1-dev` is missing. Rerun step 1. |
| `Could not find toolchain file: build/conan_toolchain.cmake` | Step 4 did not finish, or it wrote to another `--output-folder`. |
| `c++: fatal error: Killed signal terminated program cc1plus` | Out of memory. Set a lower `JOBS` (for example `JOBS=2`) and rerun the step. |
| CMake complains that the compiler or generator changed | A stale `build/` from another setup. `rm -rf build` and redo steps 4 and 5. |
| `--version` shows `-dirty` or an unexpected string | The tree is modified, the clone is shallow, or tags are missing. Use a fresh full clone (step 3). |
| sha256 differs from a published release | See [step 9](#9-compare-with-a-published-release). Most often: a different OS image, compiler or binutils. |
| `install.sh` stops on the RAM or disk check | The machine is below the minimum in RUN-A-NODE.md. `--force` skips the check. |

## Resources

Measured in a clean `ubuntu:24.04` container on a 28-thread x86_64 host with
`JOBS=6`, a warm network and an empty Conan cache:

| Step | Time | Notes |
|---|---|---|
| 1. apt packages | about 5 min | depends on the mirror |
| 3. clone | about 30 s | full clone, about 120 MB |
| 4. `conan install` (empty cache) | 2 min 18 s | Boost prebuilt from Conan Center; gtest, ZeroMQ built |
| 5. build `c2pool-v37-xmr` | 2 min 6 s | `JOBS=6` |
| 7. XMR tests (`make` variant, targets built one after another) | 17 min 51 s, of which ctest 205 s | 125 of 125 tests passed |
| whole run (steps 1 to 8) | 28 min (1687 s) | |

Peak memory of the whole container (cgroup `memory.peak`, page cache
included): 4.8 GB with `JOBS=6`. Plan 8 GB RAM and 15 GB of free disk.

Proof status: the run above used the same steps except step 7, which then
built the test targets in `build/` with `make`; the Ninja form shown in step 7
has not yet completed a clean run. The stripped binary of commit
`09b85f856ad31a471c2128506ed346eb19bac9db` had sha256
`095e625b90d050f17ad1f867f8e13e852bca01b392e48a5029370acc10f967c1`
(unstripped `cd65ae1556e044b91acfbbf2eaa4bc50159371c4b23ea234199bba88d62d12e0`),
and the packaged binary of step 8 had the same hash. A second clean run for a
two-build comparison is still owed.
