#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Attribution gate. Fails when any of these carries a marker listed in
# ci/attribution-patterns.txt (case-insensitive extended regular expressions):
#   * a commit message in GATE_RANGE (a git revision range, e.g. base..head);
#   * the pull request title or body (PR_TITLE, PR_BODY), the branch name (BRANCH);
#   * a line added to a tracked file by the change GATE_DIFF ("<from> <to>",
#     two commits; ci/attribution-patterns.txt itself is not scanned). Only
#     added lines are scanned, so content already on master is not re-judged.
# Used by .github/workflows/attribution-gate.yml and by the local hooks in
# scripts/ci/hooks/. Exit 0 clean, 1 marker found, 2 setup error.
set -uo pipefail
export LC_ALL=C.UTF-8

root=$(git rev-parse --show-toplevel) || exit 2
pat_rel=ci/attribution-patterns.txt
pat_file=${GATE_PATTERNS:-$root/$pat_rel}
if [ ! -s "$pat_file" ]; then
    echo "::error::attribution gate: pattern file $pat_file is missing or empty"
    exit 2
fi
pattern=$(grep -v -E '^[[:space:]]*(#|$)' "$pat_file" | paste -sd'|')
if [ -z "$pattern" ]; then
    echo "::error::attribution gate: no patterns in $pat_file"
    exit 2
fi

fail=0
report() { echo "::error::attribution marker found in $1"; fail=1; }

if [ -n "${GATE_RANGE:-}" ]; then
    # shellcheck disable=SC2086  # a range may be "a..b" or "x --not --remotes"
    echo "-- commit messages in $GATE_RANGE: $(git rev-list --count $GATE_RANGE 2>/dev/null || echo '?') commit(s)"
    # shellcheck disable=SC2086
    if ! msgs=$(git log --format='commit %H%n%B' $GATE_RANGE 2>/dev/null); then
        echo "::error::attribution gate: cannot read the commit range $GATE_RANGE"
        exit 2
    fi
    if printf '%s\n' "$msgs" | grep -n -i -E -- "$pattern"; then
        report "a commit message ($GATE_RANGE)"
    fi
fi

for var in PR_TITLE PR_BODY BRANCH; do
    val=${!var:-}
    [ -z "$val" ] && continue
    if printf '%s\n' "$val" | grep -n -i -E -- "$pattern"; then
        report "$var"
    fi
done

if [ -n "${GATE_DIFF:-}" ]; then
    read -r d_from d_to <<<"$GATE_DIFF"
    echo "-- lines added to tracked files, $d_from..$d_to (except $pat_rel)"
    if ! added=$(git -C "$root" diff --no-renames --no-color -U0 "$d_from" "$d_to" -- . ":(exclude)$pat_rel"); then
        echo "::error::attribution gate: cannot diff $d_from $d_to"
        exit 2
    fi
    # Keep the file headers so a hit names its file; scan only the added lines.
    if printf '%s\n' "$added" | awk '/^\+\+\+ /{f=substr($0,5); next} /^\+/{print f ": " substr($0,2)}' \
            | grep -n -i -E -- "$pattern"; then
        report "a line added to a tracked file ($d_from..$d_to)"
    fi
fi

if [ "$fail" -ne 0 ]; then
    echo "attribution gate: FAILED. This repository carries no AI or tool attribution: remove the marker from the commit message, the pull request title or body, the branch name or the file."
    exit 1
fi
echo "attribution gate: clean"
exit 0
