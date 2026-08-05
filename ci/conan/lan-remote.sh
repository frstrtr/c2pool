#!/usr/bin/env bash
# Point Conan at the LAN mirror when it is reachable. Runbook: ci/conan/LAN-MIRROR.md
#
# WHY ──────────────────────────────────────────────────────────────────────────
# Every self-hosted runner gets its OWN CONAN_HOME ($HOME/.conan2-ci/$RUNNER_NAME
# — deliberate: it avoids conan sqlite contention between concurrent jobs), so a
# NEWLY registered runner's first compiling job pays a full cold bootstrap over
# the WAN. Measured on the c2pool-heavy host (oplex7020) from an empty
# CONAN_HOME, 2026-08-05:
#
#   committed gcc-13 profile   117 s   conancenter ships matching prebuilts
#   host-default gcc-15 lane  1554 s   conancenter ships NO gcc-15 prebuilt, so
#                                      conan fetched 170.7 MB of
#                                      boost_1_90_0.tar.bz2 over the WAN (~90%
#                                      of the wall time) and built Boost
#
# Against the LAN mirror the same empty CONAN_HOME resolves in ~2 s, and even
# the fully offline seed path (no internet reachable at all) costs 18-77 s
# (18 s on an idle host, 77 s on VM905 under full CI load).
#
# FAIL-OPEN ───────────────────────────────────────────────────────────────────
# The mirror is an optimisation, never a dependency. Every probe has a short
# timeout and every failure degrades to today's behaviour. conancenter is kept
# as the fallback remote and is never removed or disabled. GitHub-hosted fork
# runners cannot route to the LAN, fail all three probes, and are unaffected.
set -uo pipefail

# Binary remote: conan_server v2 API. Serves prebuilt binaries for BOTH profiles
# in use — ci/conan/linux-gcc13.profile and the host-default `conan profile
# detect`. Read access is anonymous, so no credentials live in this repo.
PKG_URL="${C2POOL_CONAN_LAN_URL:-http://192.168.86.178:9300}"
# Source + seed archive host (VM104, the box that already holds the git mirror).
ARCHIVE="${C2POOL_CONAN_ARCHIVE_URL:-http://192.168.86.181:9301}"
SRC_URL="${C2POOL_CONAN_SRC_URL:-${ARCHIVE}/sources/}"
SEED_URL="${C2POOL_CONAN_SEED_URL:-${ARCHIVE}/seed/c2pool-deps-20260805.tgz}"

if ! command -v conan >/dev/null 2>&1; then
  echo "conan not on PATH — skipping LAN mirror setup"
  exit 0
fi

# ── 1. binary remote, searched BEFORE conancenter ────────────────────────────
lan_up=0
if curl -fsS -m 3 -o /dev/null "${PKG_URL}/v2/ping" 2>/dev/null; then
  conan remote add lan "${PKG_URL}" --index 0 --force
  lan_up=1
  echo "conan: LAN binary remote ENABLED (${PKG_URL}) — preferred over conancenter"
else
  conan remote remove lan >/dev/null 2>&1 || true
  echo "conan: LAN binary remote unreachable — conancenter only"
fi

# ── 2. backup-sources mirror ─────────────────────────────────────────────────
# Only consulted when a recipe genuinely needs the upstream tarball, i.e. a
# package_id with no prebuilt binary on any remote. "origin" keeps the recipe's
# own URLs as fallback, so a missing or stale mirror degrades to today's
# behaviour. core.* conf can ONLY live in global.conf — `conan install -c
# core.sources:...` is rejected by design, which is why this is a script.
GLOBAL_CONF="$(conan config home)/global.conf"
touch "${GLOBAL_CONF}"
sed -i '/^core\.sources:download_urls/d' "${GLOBAL_CONF}"
if curl -fsS -m 3 -o /dev/null "${SRC_URL}" 2>/dev/null; then
  printf 'core.sources:download_urls=["%s", "origin"]\n' "${SRC_URL}" >> "${GLOBAL_CONF}"
  echo "conan: LAN source mirror ENABLED (${SRC_URL})"
else
  echo "conan: LAN source mirror unreachable — sources come from origin"
fi

# ── 3. offline seed, only when the binary remote is down AND the cache is cold ─
# This is the "no internet at all" path: one LAN transfer of the whole exported
# dependency set, then `conan cache restore`. Measured 17.9 s end-to-end on the
# heavy host (2.4 s transfer of 276 MB + 14.8 s restore + 0.8 s resolve) and
# 77 s on VM905 while it was running eight concurrent CI jobs. Deliberately NOT
# taken when the binary remote answers — the remote only moves what the graph
# needs and is ~8x faster.
# NB: match an indented `boost/...` line specifically. A bare `grep ':'` false-
# positives on conan's own "WARN: There are no matching recipe references".
if [ "${lan_up}" -eq 0 ] && ! conan list "boost/*:*" 2>/dev/null | grep -qE '^[[:space:]]+boost/'; then
  if curl -fsS -m 5 -o /dev/null -I "${SEED_URL}" 2>/dev/null; then
    tmp="$(mktemp -t c2pool-conan-seed.XXXXXX.tgz)"
    if curl -fsS -m 300 -o "${tmp}" "${SEED_URL}" && conan cache restore "${tmp}"; then
      echo "conan: cold cache seeded from LAN archive (${SEED_URL})"
    else
      echo "conan: LAN seed restore failed — falling through to conancenter"
    fi
    rm -f "${tmp}"
  fi
fi

conan remote list
