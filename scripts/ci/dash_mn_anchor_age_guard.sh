#!/usr/bin/env bash
# DASH masternode-set anchor age guard (#1906).
#
# Usage: dash_mn_anchor_age_guard.sh [now_epoch]   (run from the repo root)
#
# A cold c2pool-dash with no dashd replays the MN set from the compiled anchor
# to the tip and refuses (fails closed) when that is more than
# kDefaultMaxBridgeBlocks. This estimates the anchor's age in blocks from the
# pinned anchor header time, so the release workflow can tell before tagging
# whether a fresh install still serves templates on default flags.
#
# The estimate uses the 150 s mainnet target spacing. Observed spacing is a
# little slower (~158 s around #1906), so the estimate runs a few percent high:
# the gate trips slightly early, which is the safe side for a release that
# users will cold-start for weeks after the tag.
#
# Exit 0, stale=0: within the default bridge limit.
# Exit 0, stale=1: over the default limit, within the 40000 workaround; the
#                  release notes must carry --embedded-mn-bridge-max 40000.
# Exit 1:          past the workaround, the anchor must be bumped.
# Exit 2:          the pins could not be parsed (fail closed).
set -euo pipefail

INC=src/impl/dash/coin/checkpoints/dash_mn_checkpoint_mainnet.inc
HDR=src/impl/dash/coin/header_chain.hpp
LANE=src/impl/dash/coin/mn_checkpoint_lane.hpp
SPACING=150
WORKAROUND_MAX=40000
NOW="${1:-$(date -u +%s)}"

inc_height="$(sed -n 's/^"height \([0-9]*\)\\n"$/\1/p' "$INC")"
# Mainnet params only: stop at the testnet factory so its pins are not read.
mainnet="$(sed -n '1,/make_dash_chain_params_testnet/p' "$HDR")"
hdr_height="$(sed -n 's/.*fast_start_checkpoint->height *= *\([0-9]*\);.*/\1/p' <<<"$mainnet" | tail -1)"
hdr_time="$(sed -n 's/.*fast_start_checkpoint->hdr_time *= *\([0-9]*\)u;.*/\1/p' <<<"$mainnet" | tail -1)"
limit="$(sed -n 's/.*kDefaultMaxBridgeBlocks *= *\([0-9]*\);.*/\1/p' "$LANE" | head -1)"

for v in inc_height hdr_height hdr_time limit; do
  if [ -z "${!v}" ]; then
    echo "::error::MN-ANCHOR FAIL: could not parse $v from the DASH anchor pins; the guard fails closed. See #1906."
    exit 2
  fi
done
if [ "$inc_height" != "$hdr_height" ]; then
  echo "::error::MN-ANCHOR FAIL: anchor height mismatch: $INC says $inc_height, $HDR says $hdr_height. See #1906."
  exit 2
fi

age=$(( (NOW - hdr_time) / SPACING ))
echo "DASH MN anchor h=$inc_height, header time $(date -u -d "@$hdr_time" +%FT%TZ), estimated age $age blocks (default bridge limit $limit, workaround $WORKAROUND_MAX)."

out() { [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1" >> "$GITHUB_OUTPUT" || true; }
out "age=$age"

if [ "$age" -le "$limit" ]; then
  out "stale=0"
  echo "ok: within the default bridge limit."
  exit 0
fi
if [ "$age" -le "$WORKAROUND_MAX" ]; then
  out "stale=1"
  echo "::warning::DASH MN anchor h=$inc_height is about $age blocks old, over the $limit-block default bridge limit. A fresh c2pool-dash with no dashd fails closed on default flags. Until #1906 bumps the anchor, the release notes must carry the workaround --embedded-mn-bridge-max $WORKAROUND_MAX."
  exit 0
fi
out "stale=1"
echo "::error::MN-ANCHOR FAIL: DASH MN anchor h=$inc_height is about $age blocks old, past even the --embedded-mn-bridge-max $WORKAROUND_MAX workaround. Bump the compiled anchor before releasing: see #1906."
exit 1
