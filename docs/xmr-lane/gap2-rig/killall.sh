#!/bin/bash
# hard teardown of every GAP-2 rig process (own ports/dirs only)
pkill -INT -f "wt-gap2/build/src/c2pool/c2pool-v37-xmr" ; sleep 5
pkill -9 -f "wt-gap2/build/src/c2pool/c2pool-v37-xmr"
pkill -f "xmrig -o 127.0.0.1:579[0-2]"
pkill -f "gap2-rig/walletctl.py"; pkill -f "monero-wallet-rpc .*44950"
pkill -f "monerod .*gap2-rig/mdata"; sleep 4; pkill -9 -f "monerod .*gap2-rig/mdata"; pkill -9 -f "xmrig -o 127.0.0.1:579[0-2]"
rm -f ~/gap2-rig/monerod*.pid
sleep 1
ps aux | grep -E "gap2-rig|wt-gap2/build|127.0.0.1:579[0-2]" | grep -v grep | grep -v killall | wc -l
