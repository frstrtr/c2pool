#!/usr/bin/env bash
# Point Conan at the LAN package/source mirror when it is reachable.
#
# WHY ──────────────────────────────────────────────────────────────────────────
# Every self-hosted runner gets its OWN CONAN_HOME ($HOME/.conan2-ci/$RUNNER_NAME
# — deliberate: it avoids conan sqlite contention between concurrent jobs), so a
# NEWLY registered runner's first compiling job pays a full cold bootstrap.
# Measured on the c2pool-heavy host (oplex7020) from an empty CONAN_HOME:
#
#   committed gcc-13 profile   117 s   conancenter has matching prebuilt binaries
#   host-default gcc-15 lane  1554 s   no prebuilt -> 170.7 MB boost_1_90_0.tar.bz2
#                                      dragged over the WAN (~90% of the wall
#                                      time) + a from-source Boost build
#
# Against the LAN remote both lanes resolve in ~2 s from an empty CONAN_HOME.
#
# FAIL-OPEN ───────────────────────────────────────────────────────────────────
# The mirror is an optimisation, never a dependency. If it does not answer the
# probe this script REMOVES the remote and the job proceeds against conancenter
# exactly as before. conancenter is kept as the fallback remote and is never
# removed or disabled. GitHub-hosted runners (forks) simply fail the probe.
set -uo pipefail

LAN_HOST="${C2POOL_CONAN_LAN_HOST:-192.168.86.178}"
PKG_URL="${C2POOL_CONAN_LAN_URL:-http://${LAN_HOST}:9300}"
SRC_URL="${C2POOL_CONAN_SRC_URL:-http://${LAN_HOST}:9301/}"

if ! command -v conan >/dev/null 2>&1; then
  echo "conan not on PATH — skipping LAN remote setup"
  exit 0
fi

# --index 0 => searched BEFORE conancenter. Read access on the mirror is
# anonymous, so no credentials are needed (and none are stored in the repo).
if curl -fsS -m 3 -o /dev/null "${PKG_URL}/v2/ping" 2>/dev/null; then
  conan remote add lan "${PKG_URL}" --index 0 --force
  echo "conan: LAN binary remote ENABLED (${PKG_URL}) — preferred over conancenter"
else
  conan remote remove lan >/dev/null 2>&1 || true
  echo "conan: LAN binary remote unreachable — conancenter only"
fi

# Backup-sources mirror. Only consulted when a recipe actually needs the upstream
# tarball, i.e. a package_id with no prebuilt binary on any remote. "origin"
# keeps the recipe's own URLs as the fallback, so a missing/incomplete mirror
# degrades to today's behaviour. core.* conf can ONLY be set in global.conf —
# `conan install -c core.sources:...` is rejected by design.
GLOBAL_CONF="$(conan config home)/global.conf"
touch "${GLOBAL_CONF}"
sed -i '/^core\.sources:download_urls/d' "${GLOBAL_CONF}"
if curl -fsS -m 3 -o /dev/null "${SRC_URL}" 2>/dev/null; then
  printf 'core.sources:download_urls=["%s", "origin"]\n' "${SRC_URL}" >> "${GLOBAL_CONF}"
  echo "conan: LAN source mirror ENABLED (${SRC_URL})"
else
  echo "conan: LAN source mirror unreachable — sources come from origin"
fi

conan remote list
