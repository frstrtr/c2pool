#!/bin/bash
# GAP-2 rig analyzer: owed_digest convergence through SETTLED blocks, receipts over the relay only.
R=~/gap2-rig; cd $R/logs || exit 1
echo "===================== GAP-2 RIG ANALYSIS $(date -Is) ====================="
for n in A B C; do
  [ -f node$n.log ] || continue
  cat $(ls node$n.run*.log 2>/dev/null) node$n.log > node$n.all.log
  grep -a -oE "owed_digest=[0-9a-f]+" node$n.all.log | uniq > $n.digseq
  grep -a -oE "ledger_seq=[0-9]+ owed_digest=[0-9a-f]+" node$n.all.log | sort -u -t= -k2,2n > $n.seqdig
  grep -a -oE "FINALIZED [0-9a-f]+" node$n.all.log | sort -u > $n.fin
done
eq() { diff -q $1 $2 >/dev/null 2>&1 && echo EQUAL || echo DIFF; }
echo "== distinct owed_digest SEQUENCE =="
echo "A=$(wc -l < A.digseq) B=$(wc -l < B.digseq) C=$(wc -l < C.digseq) | A==B:$(eq A.digseq B.digseq) A==C:$(eq A.digseq C.digseq)"
echo "== owed_digest per ledger_seq (every seq present on >1 node must agree) =="
cat A.seqdig B.seqdig C.seqdig | sort -u | awk -F'[ =]' '{s=$2; d=$4; if (s in m && m[s]!=d) {bad++; print "  MISMATCH seq="s" "m[s]" vs "d} m[s]=d} END {print "  distinct seqs=" length(m) " mismatches=" bad+0}'
echo "== FINALIZED bid sets =="
echo "A=$(wc -l < A.fin) B=$(wc -l < B.fin) C=$(wc -l < C.fin) | A==B:$(eq A.fin B.fin) A==C:$(eq A.fin C.fin)"
echo "== per node =="
for n in A B C; do [ -f node$n.log ] || continue
  echo "$n: SETTLED=$(grep -a -c 'FINALIZED .* SETTLED' node$n.all.log) ab-credit=$(grep -a -c '^ab-credit:' node$n.log) [src chain=$(grep '^ab-credit:' node$n.log | grep -a -c 'src=chain ') wire=$(grep '^ab-credit:' node$n.log | grep -a -c 'src=wire')] cba-book=$(grep -a -c '^cba-book:' node$n.log) relay-repair=$(grep -a -c '^relay-repair:' node$n.log) cut-repair(own)=$(grep -a -c '^cut-repair:' node$n.log) REFUSED=$(grep -a -c 'REFUSED' node$n.log) ALARM=$(grep -a -c 'cba-ALARM' node$n.log) MISMATCH=$(grep -a -ci 'mismatch:' node$n.log) wire-tx=$(grep -a -c '^ab-wire-tx:.*FB_BLOCK_WON' node$n.log) wire-rx=$(grep -a -c '^ab-wire-rx:' node$n.log)"
  echo "   $(grep -a -E '^  relay: conns' node$n.log | tail -1 | cut -c1-400)"
  echo "   $(grep -a -E '^  relay-ingest:' node$n.log | tail -1 | cut -c1-400)"
  echo "   $(grep -a -oE '^status: hw=[0-9]+ cursor=[0-9]+ tip=[0-9]+' node$n.log | tail -1) last=$(tail -1 $n.digseq | cut -c1-30)"
done
echo "== credit feed / wire stand-ins must be absent =="
for n in A B C; do echo "$n: $(grep -a -m1 '^ab: on-chain credit cut ARMED' node$n.log | cut -c1-140)"; done
