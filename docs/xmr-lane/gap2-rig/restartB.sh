#!/bin/bash
# Kill node B right after a new block lands, restart it after DOWN seconds (default 8) -- short enough that
# (usually) no block is found meanwhile, so the pre-existing finalize-restart window is not hit.
R=~/gap2-rig; cd $R; source common.sh
h0=$(H 44901); until [ "$(H 44901)" -gt "$h0" ]; do sleep 1; done
BP=$(grep "^B=" logs/pids | tail -1 | cut -d= -f2)
kill -INT $BP; echo "KILL_B pid=$BP $(date -Is) h=$(H 44901)" | tee -a logs/phase.log
while kill -0 $BP 2>/dev/null; do sleep 0.5; done
sleep ${DOWN:-8}
n=$(ls logs/nodeB.run*.log 2>/dev/null | wc -l); mv logs/nodeB.log logs/nodeB.run$((n+1)).log
nohup ./node.sh B > logs/nodeB.log 2>&1 < /dev/null & echo "B=$!" >> logs/pids
echo "RESTART_B $(date -Is) h=$(H 44901)" | tee -a logs/phase.log
