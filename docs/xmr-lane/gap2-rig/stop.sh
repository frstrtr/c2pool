#!/bin/bash
R=~/gap2-rig; cd $R
for f in logs/pids; do [ -f $f ] && while IFS='=' read -r k p; do [ -n "$p" ] && kill -INT $p 2>/dev/null; done < $f; done
sleep 6
for f in logs/pids; do [ -f $f ] && while IFS='=' read -r k p; do [ -n "$p" ] && kill -9 $p 2>/dev/null; done < $f; done
for i in 1 2 3; do [ -f monerod$i.pid ] && kill $(cat monerod$i.pid) 2>/dev/null; done
sleep 4
for i in 1 2 3; do [ -f monerod$i.pid ] && kill -9 $(cat monerod$i.pid) 2>/dev/null; rm -f monerod$i.pid; done
echo stopped
