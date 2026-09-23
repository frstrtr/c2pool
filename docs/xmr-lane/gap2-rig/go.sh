#!/bin/bash
# GAP-2 rig: 3 regtest monerods (P2P line), 3 c2pool-v37-xmr nodes on separate data dirs exchanging receipts ONLY over the
# TCP relay (full mesh), 1 xmrig per node with a distinct payee wallet, tx generator (good-citizen). NO --credit-feed, NO --wire-*.
if ss -ltn | grep -qE ":(4500[0-2]|4490[01]) "; then echo "REFUSED: a GAP-2 rig is already up"; exit 1; fi
R=~/gap2-rig; cd $R || exit 1; source common.sh
[ -d logs ] && mv logs archive-$(date +%s)
rm -rf mdata1 mdata2 mdata3 settleA settleB settleC wallets addrA addrB addrC
mkdir -p mdata1 mdata2 mdata3 logs settleA settleB settleC wallets; : > logs/pids
echo "GO $(date -Is) BIN=$BIN" | tee -a logs/phase.log
for i in 1 2 3; do DIFF=${DIFF:-50000} bash ./monerod.sh $i >/dev/null 2>&1; sleep 3; done
sleep 6; echo "daemons d1=$(H 44901) d2=$(H 44911) d3=$(H 44921)" | tee -a logs/phase.log
nohup ./wallet.sh > logs/wallet-rpc.out 2>&1 < /dev/null & echo "WALLETRPC=$!" >> logs/pids
sleep 8
python3 walletctl.py setup 2>&1 | tee -a logs/phase.log
[ "${PREMINE:-0}" -gt 0 ] && { waitpast 44901 $PREMINE; waitpast 44911 $PREMINE; waitpast 44921 $PREMINE; }
echo "premined d1=$(H 44901) d2=$(H 44911) d3=$(H 44921)" | tee -a logs/phase.log
nohup ./node.sh A > logs/nodeA.log 2>&1 < /dev/null & echo "A=$!" >> logs/pids
sleep 6
nohup ./node.sh B > logs/nodeB.log 2>&1 < /dev/null & echo "B=$!" >> logs/pids
sleep 3
nohup ./node.sh C > logs/nodeC.log 2>&1 < /dev/null & echo "C=$!" >> logs/pids
for i in $(seq 1 90); do c=0; for n in A B C; do grep -q "stratum: listening" logs/node$n.log 2>/dev/null && c=$((c+1)); done; [ $c -eq 3 ] && break; sleep 2; done
echo "listening A=$(grep -c 'stratum: listening' logs/nodeA.log) B=$(grep -c 'stratum: listening' logs/nodeB.log) C=$(grep -c 'stratum: listening' logs/nodeC.log)" | tee -a logs/phase.log
nohup ./xmrig.sh 5790 "$(cat addrA)" rigA ${TA:-4} > logs/xmrigA.log 2>&1 < /dev/null & echo "MINERA=$!" >> logs/pids
nohup ./xmrig.sh 5791 "$(cat addrB)" rigB ${TB:-3} > logs/xmrigB.log 2>&1 < /dev/null & echo "MINERB=$!" >> logs/pids
nohup ./xmrig.sh 5792 "$(cat addrC)" rigC ${TC:-3} > logs/xmrigC.log 2>&1 < /dev/null & echo "MINERC=$!" >> logs/pids
[ "${PREMINE:-0}" -gt 0 ] && nohup python3 walletctl.py gen > logs/txgen.log 2>&1 < /dev/null & echo "TXGEN=$!" >> logs/pids
echo "GO_DONE $(date -Is)" | tee -a logs/phase.log
