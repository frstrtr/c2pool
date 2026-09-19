#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# #1671 — BEHAVIORAL honesty check for a c2pool-dash binary's BLS posture.
#
# The companion guard scripts/ci/dash_bls_linked_guard.sh inspects the ARTEFACT
# (rodata ciphersuite + symbols) and answers "does this binary link real BLS?".
# This script checks the two RUNTIME surfaces #1671 added, and cross-checks them
# against that same artefact ground truth:
#
#   1. SELF-REPORT — `--version` prints `... bls=<dashbls|stub>` as its last
#      token. It MUST agree with what the binary actually links. A --version
#      that says "dashbls" over a BLS-dark image is exactly the masquerade #1671
#      closes, and fails HERE.
#   2. REFUSE-TO-START — a bls=stub binary launched in a BLS-relying config
#      (here: --embedded-null-arm) MUST refuse (exit 2) with the named message,
#      and MUST flip to a loud "running BLS-dark by --allow-stub-bls" self-ID
#      when that override is passed. A real binary MUST NOT refuse.
#
# ANTI-VACUOUS (the whole point — a green that proved nothing is worse than a
# red). This script FAILS, never silently passes, when it has nothing to stand
# on: no binary, a --version with no `bls=` token, a binary that is neither
# provably real NOR observed to refuse, or a self-report that contradicts the
# artefact. Every "pass" is backed by at least one POSITIVE observation recorded
# in $proved; if $proved is empty at the end, that is a failure.
#
#   usage: scripts/ci/dash_bls_stub_honesty.sh <path-to-c2pool-dash>
set -euo pipefail

BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "dash_bls_stub_honesty: usage: $0 <path-to-executable-c2pool-dash>" >&2
    echo "  (missing or non-executable binary is a FAILURE, not a skip)" >&2
    exit 2
fi

echo "dash_bls_stub_honesty: target = $BIN"

fail=0
proved=""      # accumulates the positive observations that back each pass
note() { echo "  $*"; }
bad()  { echo "  FAIL $*"; fail=1; }

# ── Ground truth from the artefact (same marker as dash_bls_linked_guard) ─────
# Capture-then-test, never `grep -q` in a pipeline under `set -o pipefail` (that
# reports a real-BLS binary as dark — see the linked_guard header).
CIPHERSUITE_RE='BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_(NUL|AUG|POP)_'
cs_hits="$(strings -a "$BIN" | grep -E "$CIPHERSUITE_RE" || true)"
if [ -n "$cs_hits" ]; then
    truth="real"
else
    truth="stub"
fi
note "artefact ground truth: bls=$truth (dashbls ciphersuite $( [ -n "$cs_hits" ] && echo present || echo absent ))"

# ── 1. Self-report: parse the last token of `--version` ───────────────────────
ver_out="$("$BIN" --version 2>&1 || true)"
# Extract the value of the `bls=` token, wherever it sits on the line.
reported="$(printf '%s\n' "$ver_out" | sed -n 's/.*[[:space:]]bls=\([A-Za-z0-9_]*\).*/\1/p' | head -n1)"
if [ -z "$reported" ]; then
    bad "\`--version\` printed no \`bls=<backend>\` token — the self-report surface is gone or renamed."
    note "     got: $(printf '%s' "$ver_out" | head -n1)"
else
    note "self-report: --version says bls=$reported"
    case "$reported" in
        dashbls|stub) : ;;
        *) bad "self-report names an unrecognised backend '$reported' (expected dashbls|stub)";;
    esac
    if [ "$reported" = "$truth" ]; then
        note "ok   self-report AGREES with the artefact ($reported)"
        proved="${proved} self-report-agrees"
    else
        bad "self-report ('$reported') CONTRADICTS the artefact ('$truth') — a lying --version."
    fi
fi

# ── 2. Refuse-to-start behaviour ──────────────────────────────────────────────
REFUSE_MARK='[BLS-STUB] refusing to start'
ALLOW_MARK='[BLS-STUB] running BLS-dark by --allow-stub-bls'
# --embedded-null-arm is a BLS-relying arm, so it trips the gate independent of
# the daemonless-posture inference. timeout guards the real-binary / override
# paths, which proceed into run_node instead of exiting.
run_claim() { timeout 20s "$BIN" --embedded-mainnet --embedded-null-arm "$@" 2>&1 || true; }

if [ "$truth" = "stub" ]; then
    # 2a. Refuses without the override, naming itself and the exit command.
    out_refuse="$(run_claim)"
    rc_refuse=0
    timeout 20s "$BIN" --embedded-mainnet --embedded-null-arm >/dev/null 2>&1 || rc_refuse=$?
    case "$out_refuse" in
        *"$REFUSE_MARK"*)
            note "ok   stub binary refuses --embedded-null-arm (marker present)"
            proved="${proved} stub-refuses"
            case "$out_refuse" in
                *"--allow-stub-bls"*) note "ok   refusal text names the --allow-stub-bls escape hatch" ;;
                *) bad "refusal text does not name the --allow-stub-bls exit command" ;;
            esac
            [ "$rc_refuse" -eq 2 ] && note "ok   exit code 2" \
                || bad "refusal fired but exit code was $rc_refuse, expected 2"
            ;;
        *)
            bad "stub binary did NOT refuse a BLS-relying config — the refuse-to-start gate is inert."
            note "     (a stub that neither links BLS nor refuses is the #1671 defect; this is a hard fail, not a skip)"
            ;;
    esac
    # 2b. With the override it must NOT refuse — it runs BLS-dark, loudly.
    out_allow="$(run_claim --allow-stub-bls)"
    case "$out_allow" in
        *"$REFUSE_MARK"*) bad "--allow-stub-bls did not suppress the refusal" ;;
        *"$ALLOW_MARK"*)
            note "ok   --allow-stub-bls runs BLS-dark with the loud self-ID marker"
            proved="${proved} allow-stub-self-id" ;;
        *) bad "--allow-stub-bls produced neither the refusal nor the loud self-ID marker (surface changed?)" ;;
    esac
else
    # Real binary: the gate must be transparent (bls_backend_available()==true).
    out_real="$(run_claim)"
    case "$out_real" in
        *"$REFUSE_MARK"*) bad "real (dashbls-linked) binary REFUSED a BLS-relying config — the gate misfires on a capable build." ;;
        *) note "ok   real binary does not refuse --embedded-null-arm"
           proved="${proved} real-does-not-refuse" ;;
    esac
fi

# ── Anti-vacuous backstop: at least one positive observation must have carried ─
if [ -z "$proved" ]; then
    echo "::error::dash_bls_stub_honesty proved NOTHING about $BIN — no self-report" \
         "agreement and no refusal/transparency observed. Treating as failure so a" \
         "check that could not exercise the binary can never read as green."
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "::error::$BIN failed the #1671 BLS honesty check."
    exit 1
fi

echo "dash_bls_stub_honesty: PASS (backed by:${proved} )"
