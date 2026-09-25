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

# The self-report token domain is {dashbls,stub}; the artefact label domain is
# {real,stub}. Map the artefact ground truth to the EXPECTED self-report token so
# the two vocabularies are compared through a bijection (real<->dashbls,
# stub<->stub) — never token-against-label, which would brand every honest real
# binary a liar (real != dashbls). The binary's own token stays 'dashbls': it
# names the linked library, and the GTEST SelfReportIsTruthful, --help, the
# param catalog row and the [init] banner all use it. So the SCRIPT maps the two
# domains, not the binary.
if [ "$truth" = "real" ]; then
    expect_report="dashbls"
else
    expect_report="stub"
fi

# ── 1. Self-report: parse the last token of `--version` ───────────────────────
# `--version` is a pure query on this binary (prints and returns before any
# network), but wrap it in `timeout` regardless: an old or regressed binary that
# opens the network on `--version` instead of returning would otherwise hang
# this whole CI step (observed live on a pre-#1671 build). A timeout kill leaves
# ver_out empty, which the missing-token branch below reports as a hard fail —
# fast, not a hung job.
ver_out="$(timeout 20s "$BIN" --version 2>&1 || true)"
# Extract the value of the `bls=` token, wherever it sits on the line.
reported="$(printf '%s\n' "$ver_out" | sed -n 's/.*[[:space:]]bls=\([A-Za-z0-9_]*\).*/\1/p' | head -n1)"
if [ -z "$reported" ]; then
    bad "\`--version\` printed no \`bls=<backend>\` token — the self-report surface is gone or renamed, or --version did not return within 20s."
    note "     got: $(printf '%s' "$ver_out" | head -n1)"
else
    note "self-report: --version says bls=$reported"
    case "$reported" in
        dashbls|stub) : ;;
        *) bad "self-report names an unrecognised backend '$reported' (expected dashbls|stub)";;
    esac
    if [ "$reported" = "$expect_report" ]; then
        note "ok   self-report AGREES with the artefact (bls=$truth => '$expect_report')"
        proved="${proved} self-report-agrees"
    else
        bad "self-report ('$reported') CONTRADICTS the artefact (bls=$truth => expected '$expect_report') — a lying --version."
    fi
fi

# ── 2. Refuse-to-start behaviour ──────────────────────────────────────────────
REFUSE_MARK='[BLS-STUB] refusing to start'
ALLOW_MARK='[BLS-STUB] running BLS-dark by --allow-stub-bls'
GOODCITIZEN_MARK='[run] good-citizen default (daemonless posture)'
SELFTEST_MARK='[selftest]'
# The refuse-to-start gate AND the loud --allow-stub-bls self-ID both live on the
# --run dispatch path (main_dash.cpp): they are evaluated after the good-citizen
# resolver arms the daemonless levers and immediately before run_node opens any
# store. So the invocation MUST pass --run — without it, main falls through to
# run_selftest() and the gate is never evaluated (the exact defect that let this
# check read green on a stub that never refused). --embedded-null-arm is one of
# the BLS-relying arms the gate keys on, and with no --coin-rpc the posture is
# also daemonless, so BOTH terms of bls_claim_config are true. A private
# --data-dir keeps the 20 s run_node window (real binary, and stub under
# --allow-stub-bls, both proceed past the gate into run_node) off ~/.c2pool on
# the runner; the markers are printed BEFORE run_node, so a later bind/port
# failure inside run_node cannot mask them.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
run_claim() { timeout 20s "$BIN" --run --data-dir "$WORK" --embedded-mainnet --embedded-null-arm "$@" 2>&1; }

# Fall-through detector, applied to EVERY captured output. A binary that never
# enters the --run dispatch prints the run_selftest banner ('[selftest] ...',
# main_dash.cpp). Seeing it means the gate site was never reached, so any pass
# here would be vacuous — a hard FAIL on every branch. This turns the defect that
# hid here (never entering the run path) into a caught error, and defends against
# a future gate relocation off the run path or a script that drops --run again.
check_ran_the_gate() {
    case "$1" in
        *"$SELFTEST_MARK"*)
            bad "binary took the selftest path: the --run dispatch (where the BLS gate lives) was never entered — this observation would prove nothing" ;;
    esac
}

if [ "$truth" = "stub" ]; then
    # 2a. Refuses without the override, naming itself and the exit command. The
    # rc MUST come from the SAME process whose output we judge, so capture both
    # from one invocation.
    set +e
    out_refuse="$(run_claim)"
    rc_refuse=$?
    set -e
    check_ran_the_gate "$out_refuse"
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
    # 2b. With the override it must NOT refuse — it runs BLS-dark, loudly. The
    # ALLOW_MARK is printed before run_node.
    set +e
    out_allow="$(run_claim --allow-stub-bls)"
    rc_allow=$?
    set -e
    check_ran_the_gate "$out_allow"
    case "$out_allow" in
        *"$REFUSE_MARK"*) bad "--allow-stub-bls did not suppress the refusal" ;;
        *"$ALLOW_MARK"*)
            note "ok   --allow-stub-bls runs BLS-dark with the loud self-ID marker"
            proved="${proved} allow-stub-self-id" ;;
        *) bad "--allow-stub-bls produced neither the refusal nor the loud self-ID marker (surface changed?)" ;;
    esac
else
    # Real binary: the gate must be transparent (bls_backend_available()==true) —
    # it must NOT refuse, AND it must demonstrably reach the gate site. Absence of
    # the refusal marker ALONE is no longer a pass: a binary that exits early (the
    # selftest path, or a crash before the gate) would falsely read as 'does not
    # refuse'. Require positive evidence the run path was entered — either timeout
    # killed a live run_node (rc==124), or the pre-gate good-citizen line printed.
    set +e
    out_real="$(run_claim)"
    rc_real=$?
    set -e
    check_ran_the_gate "$out_real"
    reached_gate=0
    [ "$rc_real" -eq 124 ] && reached_gate=1
    case "$out_real" in *"$GOODCITIZEN_MARK"*) reached_gate=1 ;; esac
    case "$out_real" in
        *"$REFUSE_MARK"*)
            bad "real (dashbls-linked) binary REFUSED a BLS-relying config — the gate misfires on a capable build." ;;
        *)
            if [ "$reached_gate" -eq 1 ]; then
                note "ok   real binary reached the gate and did NOT refuse --embedded-null-arm"
                proved="${proved} real-does-not-refuse"
            else
                bad "real binary did not refuse, but produced no evidence it reached the gate (neither a timeout-killed run nor the pre-gate good-citizen line) — a vacuous non-observation, not a pass."
            fi ;;
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
