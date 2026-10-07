#!/usr/bin/env bash
# Guard: apt-daily*.timer MUST stay masked on a CI host.
#
# The 09-22 masking stops apt-daily from bouncing a self-hosted runner
# mid-build: an unmasked apt-daily.timer fires apt-daily.service, whose
# package ops can restart the runner service and kill an in-flight leg
# (surfacing as a steps=0 drop / mid-build red). Masking is the fix; this
# guard fails CLOSED if the fix silently regresses (host re-image, an
# apt update re-enabling the unit, a hand-unmask).
#
# Scope is the two TIMERS only -- masking the timer stops the scheduled
# trigger; the .service units are left to their normal static state so the
# guard never false-reds a correctly-masked host.
#
# Usage:
#   apt_daily_masked_guard.sh            # check THIS host; exit 1 if any timer unmasked
#   apt_daily_masked_guard.sh --selftest # prove the guard goes red on an unmasked
#                                        # input (falsifiability); does not touch the host
set -uo pipefail

TIMERS="apt-daily.timer apt-daily-upgrade.timer"

# Evaluate "unit=state" pairs; emit ::error for any not masked; return 1 if any bad.
evaluate() {
  local bad=0 pair unit state
  for pair in "$@"; do
    unit="${pair%%=*}"; state="${pair#*=}"
    if [ "$state" = "masked" ]; then
      echo "ok: $unit is masked"
    else
      echo "::error title=apt-daily unmasked on CI host::$unit is '$state' (expected 'masked') on $(hostname) -- apt-daily can restart a runner mid-build; re-mask: sudo systemctl mask $unit"
      bad=1
    fi
  done
  return $bad
}

if [ "${1:-}" = "--selftest" ]; then
  echo "SELFTEST: feeding a synthetic unmasked timer; guard MUST return non-zero."
  if evaluate "apt-daily.timer=masked" "apt-daily-upgrade.timer=enabled" >/dev/null 2>&1; then
    echo "SELFTEST FAILED: guard stayed green on an unmasked timer (not falsifiable)"; exit 3
  fi
  echo "SELFTEST PASSED: guard goes red on an unmasked timer."
  exit 0
fi

pairs=()
for u in $TIMERS; do
  st=$(systemctl is-enabled "$u" 2>/dev/null || true)
  [ -n "$st" ] || st="unknown"
  pairs+=("$u=$st")
done
echo "Host $(hostname): asserting apt-daily timers are masked"
if evaluate "${pairs[@]}"; then
  echo "All apt-daily timers masked. CI host clean."
  exit 0
fi
exit 1
