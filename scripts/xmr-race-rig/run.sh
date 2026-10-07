#!/bin/bash
# run.sh : ONE race-heavy 3-node regtest run (REGTEST ONLY). Three native p2p-first nodes A,B,C (BIN or
# BIN_A/BIN_B/BIN_C), D_conf DCONF (10), each with a paced stratum miner (burst.py: one nonce every LO..HI s;
# at regtest difficulty 1 every nonce is a block, so three miners at 2-4 s produce same-height races and
# depth-1/2 native reorgs all the time). Mining stops at FOUND_WANT lane blocks (or DUR_CAP s), then BURY
# plain blocks bury the tail past D_conf, then race_classify.py writes runs-<LABEL>/CLASSIFY.txt.
# env: LABEL BIN(_A/_B/_C) FOUND_WANT(45) DUR_CAP(300) LO(2) HI(4) BURY(14) BURY_PACE(4) TAIL_S(40) SHAREDIFF DCONF
source "$(dirname "$0")/common.sh"; mkdir -p $RIG; cd $RIG || exit 1
LABEL=${LABEL:-run}
[ -d tmpl/mdata1 ] || { echo "REFUSED: no chain template (run gen_chain.sh)"; exit 1; }
if ports_busy; then echo "REFUSED: rig ports busy"; exit 1; fi
a=$(free -g | awk '/Mem:/{print $7}'); [ "$a" -lt 6 ] && { echo "REFUSED: avail ${a}G"; exit 1; }
rm -rf logs mdata1 mdata2 mdata3 settleA settleB settleC; mkdir -p logs; : > logs/pids
for i in 1 2 3; do cp -a tmpl/mdata1 mdata$i; done
say "GO $LABEL A=$(sha256sum ${BIN_A:-$BIN} | cut -c1-12) B=$(sha256sum ${BIN_B:-$BIN} | cut -c1-12) C=$(sha256sum ${BIN_C:-$BIN} | cut -c1-12) D_conf=${DCONF:-10} LO=${LO:-2} HI=${HI:-4}"
for i in 1 2 3; do $HERE/monerod.sh $i >> logs/monerod$i.out 2>&1 < /dev/null; sleep 2; done
for k in $(seq 1 60); do [ -n "$(H 1)" ] && [ -n "$(H 2)" ] && [ -n "$(H 3)" ] && break; sleep 2; done
GEN=$(H 1); echo $GEN > logs/gen_height; say "monerods up GEN=$GEN"
for i in 1 2 3; do nohup python3 $HERE/rpcproxy.py $(prx_of $i) http://127.0.0.1:$(rpc_of $i) $RIG/logs/rpcproxy$i.log > logs/proxy$i.out 2>&1 < /dev/null & echo "PROXY$i=$!" >> logs/pids; done; sleep 1
for n in A B C; do mkdir -p settle$n; nohup $HERE/node.sh $n >> logs/node$n.log 2>&1 < /dev/null & echo "$n=$!" >> logs/pids; sleep 4; done
ok=0; for n in A B C; do for k in $(seq 1 300); do grep -q "stratum: listening" logs/node$n.log 2>/dev/null && { ok=$((ok+1)); break; }; sleep 2; done; done
say "ready=$ok"; sleep 10
for n in A B C; do case $n in A) p=$(str_of 1);; B) p=$(str_of 2);; C) p=$(str_of 3);; esac
  nohup python3 $HERE/burst.py $p "$(addr_of $n).rig$n" ${LO:-2} ${HI:-4} >> logs/miner$n.log 2>&1 < /dev/null & echo "MINER$n=$!" >> logs/pids; done
t0=$(date +%s)
while :; do f=$(found_total); el=$(( $(date +%s) - t0 ))
  [ "$f" -ge ${FOUND_WANT:-45} ] && break
  [ $el -ge ${DUR_CAP:-300} ] && { say "cap reached"; break; }
  sleep 5; done
say "MINING_DONE found=$(found_total)"
for n in A B C; do p=$(pidof_ MINER$n); [ -n "$p" ] && kill $p 2>/dev/null; done
sleep 15
for k in $(seq 1 ${BURY:-14}); do mrpc 1 generateblocks "{\"amount_of_blocks\":1,\"wallet_address\":\"$WADDR\"}" > /dev/null; sleep ${BURY_PACE:-4}; done
sleep ${TAIL_S:-40}
say "DONE found=$(found_total)"
python3 $HERE/dump_coinbases.py $(rpc_of 1) $GEN > logs/coinbases.txt 2>&1
python3 $HERE/race_classify.py logs --label $LABEL --d-conf ${DCONF:-10} --json logs/classify.json > logs/CLASSIFY.txt 2>&1; say "CLASSIFY rc=$?"
$HERE/stop.sh >> logs/phase.log 2>&1
rm -rf runs-$LABEL; mv logs runs-$LABEL; rm -rf mdata1 mdata2 mdata3 settleA settleB settleC; touch runs-$LABEL/run.done
