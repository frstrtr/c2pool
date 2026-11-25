#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Offline self-test of the G3b gate expressions: L1 reject and DOGE-dropped regexes,
# L1SUM gate, L2 tip compare (ltc_g3b_vm220_harness.sh) and the L3 scorer's input
# checks (g3b_l3_score.sh, same dir as the harness).
#
# Usage: scripts/g3b_l1_gate_selftest.sh scripts/ltc_g3b_vm220_harness.sh [c2pool src root]
#
# Every log sample is the verbatim line the source emits, with the real core
# prefix "[HH:MM:SS.ffffff][sev] " (src/core/log.cpp format "[%1%][%2%] %3%").
# Each quoted literal must appear in the sample itself, and with a src root it is
# also looked up in the named source file, so a sample the code cannot emit fails.
H=$1; SRC=${2:-}
L3S="$(cd "$(dirname "$H")" && pwd)/g3b_l3_score.sh"
eval "$(grep -m1 '^REJ_RE=' "$H")"
eval "$(grep -m1 '^DROP_RE=' "$H")"
eval "$(grep -m1 '^l1sum_ok()' "$H")"
eval "$(grep -m1 '^tipnorm()' "$H")"
eval "$(grep -m1 '^hex64()' "$H")"
[ -n "${REJ_RE:-}" ] && [ -n "${DROP_RE:-}" ] && declare -F l1sum_ok tipnorm hex64 >/dev/null && [ -x "$L3S" ] \
  || { echo "SELFTEST could not extract gates"; exit 2; }
fail=0
chk(){ if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3 (got $1 want $2)"; fail=1; fi; }
# src FILE LITERAL: the literal must appear in that source file
src(){ [ -z "$SRC" ] && return; grep -qF -- "$2" "$SRC/$1" && echo "ok   src $1 has $2" || { echo "FAIL src $1 lacks $2"; fail=1; }; }
n(){ printf '%s\n' "$1" | grep -Ec "$REJ_RE"; }
d(){ printf '%s\n' "$1" | grep -Ec "$DROP_RE"; }
# c REJ DROP DESC SAMPLE [FILE LITERAL]...: the sample must count REJ times on REJ_RE and
# DROP times on DROP_RE. A literal in double quotes is a C++ string literal: without its
# quotes it must be a substring of the sample, and (with a src root) it must be in FILE.
# A literal not in quotes is a code fragment and is only looked up in FILE.
c(){ local r=$1 dr=$2 desc=$3 s=$4 f l in; shift 4
  chk "$(n "$s")" "$r" "$desc (reject)"; chk "$(d "$s")" "$dr" "$desc (dropped)"
  while [ $# -ge 2 ]; do f=$1; l=$2; shift 2
    if [ "${l:0:1}" = '"' ] && [ "${l: -1}" = '"' ]; then in=${l:1:${#l}-2}
      case $s in *"$in"*) echo "ok   sample has $in";; *) echo "FAIL sample for '$desc' lacks $in"; fail=1;; esac; fi
    src "$f" "$l"; done; }
MM=src/c2pool/merged/merged_mining.cpp; LR=src/impl/ltc/coin/rpc.cpp; WS=src/core/web_server.cpp

# DOGE aux submit verdicts (merged_mining.cpp 858-876, 949)
c 0 0 "DOGE accepted (858) not counted" '[08:15:08.662939][info] [MM:DOGE] submitblock ACCEPTED' \
  $MM '"] submitblock ACCEPTED"'
c 0 0 "DOGE duplicate (861) not counted" '[08:54:04.680109][info] [MM:DOGE] submitblock: duplicate (the daemon already has this block, valid)' \
  $MM '"] submitblock: duplicate (the daemon already has this block, valid)"'
c 0 0 "DOGE INCONCLUSIVE (864) not counted (deliberate)" "[09:01:12.104233][warning] [MM:DOGE] submitblock INCONCLUSIVE (inconclusive): stored, not on the daemon's best chain" \
  $MM '"] submitblock INCONCLUSIVE ("' $MM "\"): stored, not on the daemon's best chain\""
c 1 0 "DOGE BIP22 reject (868) counted" '[09:01:12.104233][error] [MM:DOGE] submitblock REJECTED by daemon: bad-cb-amount' \
  $MM '"] submitblock REJECTED by daemon: "'
c 1 0 "DOGE -22 decode failed (871) counted" '[09:01:12.104233][error] [MM:DOGE] submitblock refused: -22: Block decode failed' \
  $MM '"] submitblock refused: "' $MM 'code == -22 ? K::error'
c 1 0 "DOGE no answer (874) counted (deliberate)" '[09:01:12.104233][warning] [MM:DOGE] submitblock: no answer (no answer within 30000 ms): the chain decides (P2P relay sent it too)' \
  $MM '"] submitblock: no answer ("' $MM '"): the chain decides (P2P relay sent it too)"'
c 1 0 "DOGE submitauxblock fallback failure (949) counted" '[09:01:12.104233][warning] [MM:DOGE] submitauxblock failed: Connection refused' \
  $MM '"] submitauxblock failed: "'
# DOGE merged-block build/refuse paths
c 1 0 "DOGE commit refuse (1897) counted" '[09:01:12.104233][warning] [MM:DOGE] Merged block refused: this chain has no block in that commitment — committed root 7068263050cb28c1, not submitted' \
  $MM '"] Merged block refused: "' $MM '"this chain has no block in that commitment"' $MM '" — committed root "' $MM '", not submitted"'
c 1 0 "DOGE oversize REFUSED (2079) counted" '[09:01:12.104233][error] [MM:DOGE] Merged block REFUSED: stripped size 1100000 > 1000000 (1200000 bytes; auxpow 300 B, coinbase 200 B, 12 txs) — not submitted, not relayed' \
  $MM '"] Merged block REFUSED: "' $MM '" txs) — not submitted, not relayed"'
c 1 0 "DOGE assembly failed (2141) counted" '[09:01:12.104233][error] [MM:DOGE] Merged block assembly failed: bad coinbase — not submitted' \
  $MM '"] Merged block assembly failed: "' $MM '" — not submitted"'
c 1 0 "DOGE submit threw (2170) counted" '[09:01:12.104233][error] [MM:DOGE] submit threw: connect: Connection refused' \
  $MM '"] submit threw: "'
c 1 0 "DOGE submit threw unknown (2173) counted" '[09:01:12.104233][error] [MM:DOGE] submit threw an unknown exception' \
  $MM '"] submit threw an unknown exception"'
c 0 0 "DOGE submitted (2089) not counted" '[08:15:08.660652][info] [MM:DOGE] Merged block submitted (742 bytes, snapshot hash=7068263050cb28c1)' \
  $MM '"] Merged block submitted ("' $MM '", snapshot hash="'
# DOGE blocks found but dropped before any submit: doge_dropped, never a reject
c 0 1 "DOGE no_snapshot (1967) dropped" '[09:01:12.104233][warning] [MM:DOGE] No matching snapshot for committed hash 7068263050cb28c1 — history_size=8, skipping submission to avoid ban' \
  $MM '"] No matching snapshot for committed hash "' $MM '" — history_size="' $MM '", skipping submission to avoid ban"'
c 0 1 "DOGE root_mismatch (1980) dropped" '[09:01:12.104233][error] [MM:DOGE] BUG: recomputed chain merkle root 1a2b3c4d5e6f7a8b != committed 7068263050cb28c1 — skipping to avoid ban' \
  $MM '"] BUG: recomputed chain merkle root "' $MM '" != committed "' $MM '" — skipping to avoid ban"'
c 0 1 "DOGE snapshot bits (2022) dropped" "[09:01:12.104233][warning] [MM:DOGE] Parent PoW 00ffe1c2d3b4a596 does not meet the snapshot's bits 207fffff (block 7068263050cb28c1 on 3c2b1a0f9e8d7c6b) — not submitted" \
  $MM '"] Parent PoW "' $MM "\" does not meet the snapshot's bits \"" $MM '" (block "' $MM '" on "' $MM '") — not submitted"'
c 0 1 "DOGE rebuilt header hash (2042) dropped" '[09:01:12.104233][error] [MM:DOGE] BUG: rebuilt header hash 9f8e7d6c5b4a3928 != committed 7068263050cb28c1 — skipping to avoid ban' \
  $MM '"] BUG: rebuilt header hash "' $MM '" != committed "' $MM '" — skipping to avoid ban"'
c 0 1 "DOGE no fabe6d6d (1860) dropped" '[09:01:12.104233][warning] [MM:DOGE] fabe6d6d NOT FOUND in parent coinbase — cannot submit' \
  $MM '"] fabe6d6d NOT FOUND in parent coinbase — cannot submit"'
c 0 1 "DOGE short fabe6d6d (1867) dropped" '[09:01:12.104233][warning] [MM:DOGE] fabe6d6d found but insufficient bytes after magic' \
  $MM '"] fabe6d6d found but insufficient bytes after magic"'
c 0 0 "DOGE NULL target (1819) is not a found block" '[09:01:12.104233][warning] [MM:DOGE] Check #5 — target is NULL, no merged blocks can be found! (chain synced? work height=0)' \
  $MM '" — target is NULL, no merged blocks can be found!"'
c 0 0 "DOGE found banner (1837) not counted" '###  MERGED BLOCK FOUND! DOGE                                    ###' \
  $MM '"###  MERGED BLOCK FOUND! "'
# the harness must gate L1 PASS on doge_dropped == 0, not only compute it
grep -q '\[ "\$DROP" -eq 0 \]' "$H" && echo "ok   L1 PASS requires doge_dropped=0" || { echo "FAIL L1 PASS does not gate on DROP"; fail=1; }
# LTC parent submit (ltc/coin/rpc.cpp 470, 481, 483)
c 1 0 "LTC submit_block reject (470) counted" '[09:01:12.104233][error] Block submittal result: 0("bad-txnmrklroot") Expected: 1' \
  $LR '"Block submittal result: "'
c 1 0 "LTC submit_block_hex reject (481) counted" '[09:01:12.104233][error] submit_block_hex result: "high-hash"' \
  $LR '"submit_block_hex result: "'
c 0 0 "LTC accepted (483) not counted" '[09:01:12.104233][info] submit_block_hex accepted' \
  $LR '"submit_block_hex accepted"'
c 0 0 "LTC accepted duplicate (483) not counted" '[09:01:12.104233][info] submit_block_hex accepted ("duplicate")' \
  $LR '"submit_block_hex accepted"'
c 0 0 "LTC accepted inconclusive (483) not counted" '[09:32:58.259821][info] submit_block_hex accepted ("inconclusive")' \
  $LR '"submit_block_hex accepted"'
# core stratum submit path (web_server.cpp)
c 1 0 "stratum daemon reject counted" '[09:01:12.104233][warning] submitblock: coin daemon rejected the block (or already had it)' \
  $WS '"submitblock: coin daemon rejected the block (or already had it)"'
c 1 0 "stratum submit transport failure counted" '[09:01:12.104233][error] submitblock failed: Connection refused' \
  $WS '"submitblock failed: "'

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
