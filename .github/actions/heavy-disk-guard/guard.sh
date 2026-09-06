#!/usr/bin/env bash
# Pre-build disk-headroom guard + bounded prune for the heavy sanitizer legs.
#
# Why: a sanitizer build tree measures ~44G (build_asan + checkout, measured on
# c2pool-heavy runner heavy-2, 280G volume: 89%/31G-free with ONE leg present).
# Two co-resident heavy legs on one physical oplex7020 box put ~88G of trees on
# ~88G of free space; the final sanitizer link then ENOSPCs mid-`ld` and
# surfaces as a CODE-SHAPED red on an unrelated diff (run 34006115987, PR #1506).
# This guard (a) reclaims orphaned space and (b) fails FAST with an explicit
# infra error if the floor is still not met -- so the red is unambiguously
# infra, not the diff. Same spirit as the per-host heavy-leg lock's
# "blocked by live long holders, not this diff".
#
# NOT set -e: exits are controlled deliberately (prune failures must not abort
# the guard; only an unreachable floor is fatal).
set -uo pipefail

FLOOR_GB="${HEAVY_DISK_FLOOR_GB:-50}"
CCACHE_MAX="${HEAVY_DISK_CCACHE_MAX:-15G}"
STALE_HOURS="${HEAVY_DISK_STALE_HOURS:-6}"
BUILD_VOLUME="${HEAVY_DISK_BUILD_VOLUME:-${GITHUB_WORKSPACE:-$PWD}}"
# Runner-home roots to sweep for orphaned build trees. Default: every
# actions-runner* home of the current user -- the co-resident heavy runners
# share one physical disk, so a reaped sibling's 44G tree is ours to reclaim.
SWEEP_ROOTS="${HEAVY_DISK_SWEEP_ROOTS:-$HOME/actions-runner*}"
RUNNER="${RUNNER_NAME:-$(hostname 2>/dev/null || echo unknown)}"

avail_gb () { df -BG --output=avail "$1" 2>/dev/null | tail -1 | tr -dc '0-9' || true; }

echo "::group::heavy-disk-guard: bounded prune on ${RUNNER}"

# (1) Cap the shared ccache. It grows unbounded across runs; capping + evicting
#     overflow reclaims real space and never costs more than the cap's worth of
#     warm hits on the next build.
if command -v ccache >/dev/null 2>&1; then
  ccache -M "$CCACHE_MAX" >/dev/null 2>&1 || true
  ccache -c              >/dev/null 2>&1 || true
  echo "ccache capped at ${CCACHE_MAX} and evicted to fit"
else
  echo "ccache not on PATH -- skipping cap"
fi

# (2) Reap ORPHANED build trees. A heavy build+test finishes in ~25 min, so any
#     build tree untouched for >${STALE_HOURS}h was left by a host-reaped job
#     whose post-job prune never ran. mtime is the safety interlock: a LIVE
#     co-resident build has a fresh mtime and is NEVER swept, so we cannot turn
#     a sibling job's green into a red. The name+path patterns keep rm strictly
#     on build trees under an actions-runner _work dir -- never $HOME itself.
reaped=0
for root in $SWEEP_ROOTS; do
  [ -d "$root" ] || continue
  while IFS= read -r -d '' d; do
    case "$d" in
      */_work/*/*/build|*/_work/*/*/build_*|*/_work/*/*/build-*)
        echo "  reaping orphaned build tree (idle >${STALE_HOURS}h): $d"
        rm -rf -- "$d" && reaped=$((reaped+1)) || true ;;
      *) : ;;
    esac
  done < <(find "$root" -maxdepth 4 -type d \
             \( -name build -o -name 'build_*' -o -name 'build-*' \) \
             -mmin "+$((STALE_HOURS*60))" -print0 2>/dev/null)
done
echo "reaped ${reaped} orphaned build tree(s)"
echo "::endgroup::"

FREE="$(avail_gb "$BUILD_VOLUME")"
: "${FREE:=0}"
MOUNT="$(df -P "$BUILD_VOLUME" 2>/dev/null | awk 'NR==2{print $6}')"
echo "heavy-disk-guard: ${RUNNER} has ${FREE}G free on ${MOUNT:-?} (floor ${FLOOR_GB}G)"

if [ "${FREE:-0}" -lt "$FLOOR_GB" ]; then
  echo "::group::heavy-disk-guard: disk state on failure"
  df -h "$BUILD_VOLUME" 2>/dev/null || true
  du -xh -d1 "$(dirname "$BUILD_VOLUME")" 2>/dev/null | sort -rh | head -12 || true
  echo "::endgroup::"
  echo "::error::insufficient build disk on ${RUNNER}, ${FREE} GB free (floor ${FLOOR_GB} GB) -- transient infra: concurrent heavy legs filled the shared oplex7020 volume, NOT this diff. Re-run once a co-resident heavy leg drains."
  exit 1
fi

echo "heavy-disk-guard: OK -- ${FREE}G >= ${FLOOR_GB}G floor"
