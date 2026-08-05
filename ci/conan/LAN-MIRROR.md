# LAN Conan mirror — what it is, and how to refresh it

`ci/conan/lan-remote.sh` runs in every Linux CI job right after `Install Conan 2`.
It is a pure optimisation with a fail-open contract: every probe has a short
timeout, `conancenter` is never removed, and a runner that cannot route to the
LAN (any GitHub-hosted fork runner) behaves exactly as it did before.

## Why it exists

Each self-hosted runner has its own `CONAN_HOME` (`$HOME/.conan2-ci/$RUNNER_NAME`
— deliberate, it avoids conan sqlite contention between concurrent jobs). A
newly registered runner therefore pays a full cold bootstrap on its first
compiling job. Measured on the `c2pool-heavy` host from an empty `CONAN_HOME`,
2026-08-05:

| lane | before | after (LAN) |
|---|---|---|
| `ci/conan/linux-gcc13.profile` | 117 s | **2.3 s** |
| host-default `conan profile detect` (ASan / BCH / DGB) | 1554 s | **2.2 s** |
| fully offline (binary remote down, seed archive only) | — | **17.9 s** idle host / **77 s** under full CI load |

The "after" column is an idle host. Re-measured on the same host while it was
running four concurrent CI jobs the same two resolves cost 8.4 s and 5.6 s —
still three orders of magnitude off the cold bootstrap, but quote the range,
not the best case.

The 1554 s row is the one that matters: conancenter ships prebuilt binaries for
gcc-13 but **not** for gcc-15, so on a gcc-15 host conan fell back to fetching
170.7 MB of `boost_1_90_0.tar.bz2` over the WAN (~90% of the wall time) and
building Boost from source. That is the "new runner looks hung and isn't" case.

## The two pieces

| piece | host | URL | contents |
|---|---|---|---|
| binary remote (`conan_server`, v2 API) | VM905 `c2pool-build` | `http://192.168.86.178:9300` | full dependency closure, **both** profiles |
| static archive | VM104 `git-mirror` | `http://192.168.86.181:9301` | `sources/<sha256>` boost tarball + `seed/c2pool-deps-*.tgz` |

Both are `systemd` units and survive reboot. On VM104 the unit is
`conan-lan-http.service` (root-owned, `/srv/conan-lan`, runs as `nobody`,
`ProtectSystem=strict`) — it is a read-only file server and cannot touch the
gitea data on that box. On VM905 the unit is the user-level
`conan-server.service` with linger enabled.

Read access to both is anonymous; the upload account exists only on VM905 and
its credential is not in this repo.

## Coverage

Exported from a warm CI cache, so it tracks `conanfile.txt` + `conan.lock`:

- `boost/1.90.0`, `zeromq/4.3.5`, `leveldb/1.23`, `yaml-cpp/0.8.0`,
  `nlohmann_json/3.12.0`, `gtest/1.14.0` and their transitives
  (`b2`, `bzip2`, `crc32c`, `libbacktrace`, `snappy`, `zlib`)
- two `package_id` sets per recipe: **gcc-13** (the committed profile) and
  **gcc-15** (the host-default detect as it was before oplex7020 was pinned to
  gcc-13). Keeping both means a host flipping its default compiler is a cache
  hit either way.

## Refresh — when, who, how

**It goes stale when `conanfile.txt` or `conan.lock` changes, or when a build
host's default compiler changes** (a new `compiler.version` is a new
`package_id`, which the mirror does not have).

**Symptom of staleness:** a job logs `Building from source` or downloads from
`conancenter` for a package the mirror was supposed to serve. That is a
degraded-but-correct state — nothing breaks, it is just slow again.

**Trigger:** whoever lands a dependency bump (the PR that edits `conanfile.txt`
or regenerates `conan.lock`) refreshes the mirror in the same change. There is
deliberately no cron: a silent auto-refresh would republish whatever a random
runner happened to have, which is how a mirror turns into a mystery artifact.

**Procedure** — from any host with a warm, correct cache (a CI runner that has
just built the new dependency set green):

```bash
# 1. export the whole dependency set from that warm cache
export CONAN_HOME=$HOME/.conan2-ci/<runner-name>       # must NOT be mid-job
conan cache save "*:*" --file=/tmp/c2pool-deps-$(date +%Y%m%d).tgz

# 2. push the binaries into the LAN remote (restore into a scratch home first
#    so the runner's own cache and remotes are never touched)
export CONAN_HOME=/tmp/upload-home && rm -rf "$CONAN_HOME"
conan cache restore /tmp/c2pool-deps-$(date +%Y%m%d).tgz
conan remote add lan http://192.168.86.178:9300 --index 0 --force
conan remote login lan ciupload          # credential: VM905 ~/.conan_server/server.conf
conan upload "*" -r=lan --confirm

# 3. publish the seed archive + any new upstream source tarball on VM104
#    (/srv/conan-lan is served read-only; sources are named by their sha256,
#    which must match the recipe's conandata.yml `sources:` entry)
#    then bump SEED_URL's default in ci/conan/lan-remote.sh in the same PR.
```

**Safety rules for step 1 and 2:** never `conan cache save` a `CONAN_HOME` whose
runner is mid-job — check `gh api repos/frstrtr/c2pool/actions/runners` for
`busy=false` *and* that no `Runner.Worker` pid exists for that runner. Restore
is additive and never deletes, but a concurrent writer can still tear the
sqlite index.

**Rollback:** `systemctl stop conan-lan-http` on VM104 and
`systemctl --user stop conan-server` on VM905. Every probe in
`lan-remote.sh` then fails and CI reverts to conancenter with no workflow
change. Nothing else on either box is involved.
