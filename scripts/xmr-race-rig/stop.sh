#!/bin/bash
# stop.sh : stop THIS rig's processes only (by recorded PID, then by patterns containing $RIG).
source "$(dirname "$0")/common.sh"
for k in MINERA MINERB MINERC; do p=$(pidof_ $k); [ -n "$p" ] && kill $p 2>/dev/null; done
for k in A B C; do p=$(pidof_ $k); [ -n "$p" ] && kill -INT $p 2>/dev/null; done
sleep 12
for k in A B C; do p=$(pidof_ $k); [ -n "$p" ] && kill -9 $p 2>/dev/null; done
for k in PROXY1 PROXY2 PROXY3; do p=$(pidof_ $k); [ -n "$p" ] && kill $p 2>/dev/null; done
for i in 1 2 3; do [ -f $RIG/monerod$i.pid ] && kill $(cat $RIG/monerod$i.pid) 2>/dev/null; done
sleep 8
for i in 1 2 3; do [ -f $RIG/monerod$i.pid ] && kill -9 $(cat $RIG/monerod$i.pid) 2>/dev/null; rm -f $RIG/monerod$i.pid; done
pkill -9 -f -- "[-]-data-dir $RIG/" 2>/dev/null
pkill -9 -f -- "[r]pcproxy.py [0-9]* http://127.0.0.1:[0-9]* $RIG/logs/" 2>/dev/null
echo "stopped; left: $(pgrep -fc -- "[-]-data-dir $RIG/") (node+monerod) proxies=$(pgrep -fc -- "[r]pcproxy.py [0-9]* http://127.0.0.1:[0-9]* $RIG/logs/")"
