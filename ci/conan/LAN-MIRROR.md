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

| lane | before | after — VM104 primary | after — VM905 fallback |
|---|---|---|---|
| `ci/conan/linux-gcc13.profile` | 117 s | **2.6 s** | 2.3 s idle / 8.4 s loaded |
| host-default `conan profile detect` (ASan / BCH / DGB) | 1554 s | **2.2 s** | 2.2 s idle / 5.6 s loaded |
| fully offline (both remotes down, seed archive only) | — | **17.9 s** idle host / **77 s** under full CI load | — |

Every "after" number was taken from a purged `CONAN_HOME` with **conancenter
removed entirely**, so the resolve provably came off the LAN and not from a warm
remote cache. The VM905 column shows idle and loaded figures because that box
also runs eight CI slots; quote the range, not the best case.

The 1554 s row is the one that matters: conancenter ships prebuilt binaries for
gcc-13 but **not** for gcc-15, so on a gcc-15 host conan fell back to fetching
170.7 MB of `boost_1_90_0.tar.bz2` over the WAN (~90% of the wall time) and
building Boost from source. That is the "new runner looks hung and isn't" case.

## The pieces

| role | host | URL | contents |
|---|---|---|---|
| binary remote `lan` — **PRIMARY** | VM104 `git-mirror` | `http://192.168.86.181:9300` | full dependency closure, **both** profiles |
| binary remote `lan905` — **FALLBACK** | VM905 `c2pool-build` | `http://192.168.86.178:9300` | identical closure |
| static archive | VM104 `git-mirror` | `http://192.168.86.181:9301` | `sources/<sha256>` boost tarball + `seed/c2pool-deps-*.tgz` |

`lan-remote.sh` probes them in that order and inserts each ahead of
`conancenter`, so the search order is `lan` → `lan905` → `conancenter`. If the
primary is down the fallback is promoted to the front; if both are down and the
cache is cold, the seed archive is restored instead.

**VM104 lives on Proxmox node `pve`, not `pve1`.** Fleet notes said `pve1`;
that is wrong and `qm` commands against `pve1` fail with
`Configuration file 'nodes/pve1/qemu-server/104.conf' does not exist`.

All three are `systemd` units and survive reboot:

| unit | host | notes |
|---|---|---|
| `conan-server.service` | VM104 | **root/system** unit, runs as `ubuntu`, `ProtectSystem=strict`, `ProtectHome=read-only`, writes only to its own storage dir |
| `conan-lan-http.service` | VM104 | root/system unit, runs as `nobody`, read-only file server over `/srv/conan-lan` |
| `conan-server.service` | VM905 | user unit with linger enabled |

Nothing on VM104 touches the gitea container, which keeps `:3000` to itself;
gitea was verified answering 200 after every step of the install.

**Footprint on VM104:** 427 MB static archive (`/srv/conan-lan`) + 54 MB package
store (`/home/ubuntu/conan-server-data`) + ~90 MB of venvs ≈ **0.6 GB** on a
58 G disk with 26 G free. The 242 git mirrors remain the dominant consumer.

Read access to every endpoint is anonymous; upload accounts exist only on the
two server boxes and no credential is in this repo.

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

# 2. publish it as the new seed archive on VM104 and, if a recipe pulled a new
#    upstream tarball, drop that in sources/ named by the sha256 from the
#    recipe's conandata.yml `sources:` entry (the name IS the integrity check)
scp /tmp/c2pool-deps-$(date +%Y%m%d).tgz \
    ubuntu@192.168.86.181:/srv/conan-lan/seed/

# 3. push the binaries into BOTH binary remotes, primary first. Run this ON the
#    server box: /home/ubuntu/vm104_upload.sh reads the upload credential out of
#    that host's own server.conf, restores the seed into a scratch CONAN_HOME and
#    uploads, so no credential ever crosses a shell you are typing into.
ssh ubuntu@192.168.86.181 bash /home/ubuntu/vm104_upload.sh
#    then the same for the VM905 fallback.

# 4. bump SEED_URL's default in ci/conan/lan-remote.sh in the same PR.
```

**Safety rules:** never `conan cache save` a `CONAN_HOME` whose runner is
mid-job — check `gh api repos/frstrtr/c2pool/actions/runners` for `busy=false`
*and* that no `Runner.Worker` pid exists for that runner. Restore is additive
and never deletes, but a concurrent writer can still tear the sqlite index.
Always restore into a scratch `CONAN_HOME` before uploading, so a runner's own
cache and remote list are never touched.

**Rollback:** stop `conan-server` and/or `conan-lan-http` on VM104 and
`conan-server` (user unit) on VM905. Every probe in `lan-remote.sh` then fails
and CI reverts to conancenter with no workflow change. Nothing else on either
box is involved.
