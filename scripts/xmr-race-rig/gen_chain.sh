#!/bin/bash
# gen_chain.sh : build the regtest chain template ONCE ($RIG/tmpl/mdata1): monerod 1 (+ a peer so it counts
# as synchronized) mines GEN blocks at fixed difficulty 1. Every run copies it into three fresh data dirs.
source "$(dirname "$0")/common.sh"; mkdir -p $RIG; cd $RIG || exit 1
GEN=${GEN:-120}
if ports_busy; then echo "REFUSED: rig ports busy"; exit 1; fi
rm -rf tmpl; mkdir -p tmpl/mdata1 tmpl/mdata2 tmpl/logs logs
DATADIR=$RIG/tmpl/mdata1 LOGD=$RIG/tmpl/logs $HERE/monerod.sh 1 < /dev/null || exit 1
DATADIR=$RIG/tmpl/mdata2 LOGD=$RIG/tmpl/logs $HERE/monerod.sh 2 < /dev/null || exit 1
for k in $(seq 1 60); do [ -n "$(H 1)" ] && [ -n "$(H 2)" ] && break; sleep 1; done
for k in $(seq 1 90); do mrpc 1 get_info "{}" | grep -q "\"synchronized\": true" && break; sleep 2; done
for i in $(seq 1 $GEN); do mrpc 1 generateblocks "{\"amount_of_blocks\":1,\"wallet_address\":\"$WADDR\"}" > /dev/null; done
echo "generated: h=$(H 1)"
for i in 1 2; do kill $(cat $RIG/monerod$i.pid); done; sleep 8
for i in 1 2; do kill -9 $(cat $RIG/monerod$i.pid) 2>/dev/null; rm -f $RIG/monerod$i.pid; done
rm -rf tmpl/mdata2; echo GEN_DONE
