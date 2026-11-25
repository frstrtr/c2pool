#!/bin/bash
# Offline self-test of the two L1 gate expressions in ltc_g3b_vm220_harness.sh.
# Usage: scripts/g3b_l1_gate_selftest.sh scripts/ltc_g3b_vm220_harness.sh
H=$1
REJ_RE=$(grep -m1 '^REJ_RE=' "$H" | sed 's/^REJ_RE="//; s/"$//')
POP=$(grep -o 'grep -Eq "(^| )populated=\[1-9\]"' "$H" | head -1)
[ -n "$REJ_RE" ] && [ -n "$POP" ] || { echo "SELFTEST could not extract gates"; exit 2; }
fail=0
chk(){ if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3 (got $1 want $2)"; fail=1; fi; }
n(){ printf '%s\n' "$1" | grep -Eci "$REJ_RE"; }
chk "$(n '2026-11-24 [error] submit_block_hex result: "high-hash"')" 1 "LTC daemon reject counted"
chk "$(n 'Block submittal result: 0("bad-txnmrklroot") Expected: 1')" 1 "LTC submit_block reject counted"
chk "$(n '[MM:DOGE] submitblock REJECTED by daemon: bad-cb-amount')" 1 "DOGE reject counted"
chk "$(n '[MM:DOGE] submitblock failed: connection refused')" 1 "DOGE exception counted"
chk "$(n 'submit_block_hex accepted')" 0 "LTC accept not counted"
chk "$(n 'submit_block_hex accepted ("duplicate")')" 0 "LTC duplicate-accept not counted"
chk "$(n '[MM:DOGE] submitblock ACCEPTED')" 0 "DOGE accept not counted"
chk "$(n '[MM:DOGE] submitblock duplicate/inconclusive (duplicate) -- treated as accepted')" 0 "DOGE dup not counted"
p(){ echo "$1" | grep -Eq "(^| )populated=[1-9]" && echo 1 || echo 0; }
chk "$(p 'L1SUM ltc_blocks=9 populated=0 auxcommit=9 pays_both=9 doge_blocks=9 doge_auxpow=9 doge_populated=234')" 0 "LTC populated=0 not masked by doge_populated"
chk "$(p 'L1SUM ltc_blocks=9 populated=7 auxcommit=9 pays_both=9 doge_blocks=9 doge_auxpow=9 doge_populated=0')" 1 "LTC populated=7 passes"
exit $fail
