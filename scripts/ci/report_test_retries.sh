#!/bin/sh
# Report the lines cmake/RetryTest.cmake writes (a failed attempt, a retry, a
# late pass) from a CTest log, as GitHub warning annotations and in the job
# summary. Informational: always exits 0.
#
#   scripts/ci/report_test_retries.sh <build>/Testing/Temporary/LastTest.log [label]
set -u
LOG=${1:?usage: report_test_retries.sh <LastTest.log> [label]}
LABEL=${2:-ctest}
if [ ! -f "$LOG" ]; then
    echo "report_test_retries: $LABEL: no log at $LOG"
    exit 0
fi
PAT='^(attempt [0-9]+/[0-9]+ FAILED rc=|RETRY [0-9]+/[0-9]+ |RETRY passed on attempt [0-9]+/[0-9]+ )'
N=$(grep -cE "$PAT" "$LOG" || true)
echo "report_test_retries: $LABEL: ${N:-0} retry line(s) in $LOG"
grep -E "$PAT" "$LOG" | while IFS= read -r line; do
    echo "::warning title=ctest retry ($LABEL)::$line"
done
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ "${N:-0}" -gt 0 ]; then
    {
        echo "### ctest retries ($LABEL)"
        echo '```'
        grep -E "$PAT" "$LOG"
        echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
fi
exit 0
