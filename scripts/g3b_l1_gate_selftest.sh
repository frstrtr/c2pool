#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Offline self-test of the G3b gate expressions: L1 reject regex, L1SUM gate,
# L2 tip compare (ltc_g3b_vm220_harness.sh) and the L3 scorer's input checks
# (g3b_l3_score.sh, same dir as the harness).
#
# Usage: scripts/g3b_l1_gate_selftest.sh scripts/ltc_g3b_vm220_harness.sh [c2pool src root]
#
# Every log sample is the verbatim line the source emits, with the real core
# prefix "[HH:MM:SS.ffffff][sev] " (src/core/log.cpp format "[%1%][%2%] %3%").
# With a src root, each sample's literal is also looked up in the named source
# file, so a sample the code cannot emit fails the test.
H=$1; SRC=${2:-}
L3S="$(cd "$(dirname "$H")" && pwd)/g3b_l3_score.sh"
eval "$(grep -m1 '^REJ_RE=' "$H")"
eval "$(grep -m1 '^l1sum_ok()' "$H")"
eval "$(grep -m1 '^tipnorm()' "$H")"
eval "$(grep -m1 '^hex64()' "$H")"
[ -n "${REJ_RE:-}" ] && declare -F l1sum_ok tipnorm hex64 >/dev/null && [ -x "$L3S" ] \
  || { echo "SELFTEST could not extract gates"; exit 2; }
fail=0
chk(){ if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3 (got $1 want $2)"; fail=1; fi; }
# src FILE LITERAL: the sample's fixed text must appear in that source file
src(){ [ -z "$SRC" ] && return; grep -qF -- "$2" "$SRC/$1" && echo "ok   src $1 has $2" || { echo "FAIL src $1 lacks $2"; fail=1; }; }
n(){ printf '%s\n' "$1" | grep -Ec "$REJ_RE"; }
MM=src/c2pool/merged/merged_mining.cpp; LR=src/impl/ltc/coin/rpc.cpp; WS=src/core/web_server.cpp

# DOGE aux submit verdicts (merged_mining.cpp 858-876)
chk "$(n '[08:15:08.662939][info] [MM:DOGE] submitblock ACCEPTED')" 0 "DOGE accepted (858) not counted"
src $MM '"] submitblock ACCEPTED"'
chk "$(n '[08:54:04.680109][info] [MM:DOGE] submitblock: duplicate (the daemon already has this block, valid)')" 0 "DOGE duplicate (861) not counted"
src $MM '"] submitblock: duplicate (the daemon already has this block, valid)"'
chk "$(n "[09:01:12.104233][warning] [MM:DOGE] submitblock INCONCLUSIVE (inconclusive): stored, not on the daemon's best chain")" 0 "DOGE INCONCLUSIVE (864) not counted (deliberate)"
src $MM '"] submitblock INCONCLUSIVE ("'; src $MM "\"): stored, not on the daemon's best chain\""
chk "$(n '[09:01:12.104233][error] [MM:DOGE] submitblock REJECTED by daemon: bad-cb-amount')" 1 "DOGE BIP22 reject (868) counted"
src $MM '"] submitblock REJECTED by daemon: "'
chk "$(n '[09:01:12.104233][error] [MM:DOGE] submitblock refused: -22: Block decode failed')" 1 "DOGE -22 decode failed (871) counted"
src $MM '"] submitblock refused: "'; src $MM 'code == -22 ? K::error'
chk "$(n '[09:01:12.104233][warning] [MM:DOGE] submitblock: no answer (no answer within 30000 ms): the chain decides (P2P relay sent it too)')" 1 "DOGE no answer (874) counted (deliberate)"
src $MM '"] submitblock: no answer ("'; src $MM '"): the chain decides (P2P relay sent it too)"'
# DOGE merged-block build/refuse paths
chk "$(n '[09:01:12.104233][warning] [MM:DOGE] Merged block refused: leaf mismatch — committed root 7068263050cb28c1, not submitted')" 1 "DOGE commit refuse (1897) counted"
src $MM '"] Merged block refused: "'
chk "$(n '[09:01:12.104233][error] [MM:DOGE] Merged block REFUSED: stripped size 1100000 > 1000000 (1200000 bytes; auxpow 300 B, coinbase 200 B, 12 txs) — not submitted, not relayed')" 1 "DOGE oversize REFUSED (2079) counted"
src $MM '"] Merged block REFUSED: "'
chk "$(n '[09:01:12.104233][error] [MM:DOGE] Merged block assembly failed: bad coinbase — not submitted')" 1 "DOGE assembly failed (2141) counted"
src $MM '"] Merged block assembly failed: "'
chk "$(n '[09:01:12.104233][error] [MM:DOGE] submit threw: connect: Connection refused')" 1 "DOGE submit threw (2170) counted"
src $MM '"] submit threw: "'
chk "$(n '[09:01:12.104233][error] [MM:DOGE] submit threw an unknown exception')" 1 "DOGE submit threw unknown (2173) counted"
src $MM '"] submit threw an unknown exception"'
chk "$(n '[08:15:08.660652][info] [MM:DOGE] Merged block submitted (742 bytes, snapshot hash=7068263050cb28c1)')" 0 "DOGE submitted (2089) not counted"
src $MM '"] Merged block submitted ("'
# LTC parent submit (ltc/coin/rpc.cpp 470, 481, 483)
chk "$(n '[09:01:12.104233][error] Block submittal result: 0("bad-txnmrklroot") Expected: 1')" 1 "LTC submit_block reject (470) counted"
src $LR '"Block submittal result: "'
chk "$(n '[09:01:12.104233][error] submit_block_hex result: "high-hash"')" 1 "LTC submit_block_hex reject (481) counted"
src $LR '"submit_block_hex result: "'
chk "$(n '[09:01:12.104233][info] submit_block_hex accepted')" 0 "LTC accepted (483) not counted"
chk "$(n '[09:01:12.104233][info] submit_block_hex accepted ("duplicate")')" 0 "LTC accepted duplicate (483) not counted"
chk "$(n '[09:32:58.259821][info] submit_block_hex accepted ("inconclusive")')" 0 "LTC accepted inconclusive (483) not counted"
src $LR '"submit_block_hex accepted"'
# core stratum submit path (web_server.cpp)
chk "$(n '[09:01:12.104233][warning] submitblock: coin daemon rejected the block (or already had it)')" 1 "stratum daemon reject counted"
src $WS '"submitblock: coin daemon rejected the block (or already had it)"'
chk "$(n '[09:01:12.104233][error] submitblock failed: Connection refused')" 1 "stratum submit transport failure counted"
src $WS '"submitblock failed: "'

# L1SUM gate: each claimed counter must be >=1; populated= must not be satisfied by doge_populated=
G(){ l1sum_ok "$1" && echo 1 || echo 0; }
chk "$(G 'L1SUM ltc_blocks=9 populated=7 auxcommit=9 pays_both=9 doge_blocks=9 doge_auxpow=9 doge_populated=3')" 1 "L1SUM all >=1 passes"
chk "$(G 'L1SUM ltc_blocks=9 populated=0 auxcommit=9 pays_both=9 doge_blocks=9 doge_auxpow=9 doge_populated=234')" 0 "LTC populated=0 not masked by doge_populated"
chk "$(G 'L1SUM ltc_blocks=9 populated=7 auxcommit=0 pays_both=9 doge_blocks=9 doge_auxpow=9 doge_populated=3')" 0 "auxcommit=0 fails"
chk "$(G 'L1SUM ltc_blocks=9 populated=7 auxcommit=9 pays_both=0 doge_blocks=9 doge_auxpow=9 doge_populated=3')" 0 "pays_both=0 fails"
chk "$(G 'L1SUM ltc_blocks=9 populated=7 auxcommit=9 pays_both=9 doge_blocks=9 doge_auxpow=9 doge_populated=0')" 0 "doge_populated=0 fails"

# L2 tip compare: JSON-string tips compare; error bodies and zero hashes never do
T=5ca172a7c813cb3f5ca172a7c813cb3f5ca172a7c813cb3f5ca172a7c813cb3f
tip_eq(){ local a b; a=$(printf '%s' "$1" | tipnorm); b=$(printf '%s' "$2" | tipnorm)
  hex64 "$a" && hex64 "$b" && [ "$a" = "$b" ] && echo 1 || echo 0; }
chk "$(tip_eq "\"$T\"" "\"$T\"")" 1 "equal JSON-string tips compare equal"
chk "$(tip_eq '{"error":"Internal error"}' '{"error":"Internal error"}')" 0 "two error bodies are not a tip match"
chk "$(tip_eq '' '')" 0 "two empty replies are not a tip match"
chk "$(tip_eq '"0000000000000000000000000000000000000000000000000000000000000000"' '"0000000000000000000000000000000000000000000000000000000000000000"')" 0 "zero hash is not a tip"
chk "$(tip_eq "\"$T\"" "\"${T%?}0\"")" 0 "different tips differ"

# L3 scorer input checks: a missing log or a malformed l3.lines gives resub=NA, never PASS
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
PH=34b3f1ec4fc0037ddc85f4eeb7c4370d0c853e51f8425dbf80b20d77ab700088
DH=65545c59b535eb5ca5c2f73e119378fb58727f200e30fb7e48aa7bb5ee246d15
mk(){ rm -rf "$W/e"; mkdir -p "$W/e"
  printf '%s\n' "[10:24:40.000000][info] old line" > "$W/e/nodeA.log"
  printf '%s\n' "[10:25:00.000000][warning] Block ${PH:0:16}... ORPHANED (confirmations=-1)" \
    "[10:25:00.000000][warning] BLOCK ORPHANED — DOGE" "  Block hash: $DH" >> "$W/e/nodeA.log"
  printf '%s\n' "[10:24:40.000000][info] old line" > "$W/e/nodeB.log"
  echo '[]' > "$W/e/recent_blocks.after.json"; }
L3(){ "$L3S" "$W/e" "$PH" "$DH" -1 | awk '{print $1" "$2}'; }
mk; echo "1 1" > "$W/e/l3.lines"; chk "$(L3)" "L3 PASS" "L3 well-formed evidence passes"
mk; echo "1" > "$W/e/l3.lines"; chk "$(L3)" "L3 FAIL" "L3 one-field l3.lines -> NA, not PASS"
mk; echo "1 x" > "$W/e/l3.lines"; chk "$(L3)" "L3 FAIL" "L3 non-integer l3.lines -> NA, not PASS"
mk; echo "1 1" > "$W/e/l3.lines"; rm "$W/e/nodeB.log"; chk "$(L3)" "L3 FAIL" "L3 missing nodeB.log -> NA, not PASS"
mk; echo "1 1" > "$W/e/l3.lines"; rm "$W/e/nodeA.log"; chk "$(L3)" "L3 FAIL" "L3 missing nodeA.log -> NA, not PASS"
mk; echo "1 1" > "$W/e/l3.lines"
echo "[10:26:00.000000][info] [MM:DOGE] Merged block submitted (742 bytes, snapshot hash=${DH:0:16})" >> "$W/e/nodeB.log"
chk "$(L3)" "L3 FAIL" "L3 resubmit of D after the orphan step fails"
exit $fail
