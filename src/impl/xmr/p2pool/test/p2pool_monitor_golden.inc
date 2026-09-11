// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/test/p2pool_monitor_golden.inc
//
// THE GOLDEN FRAME: exactly what the monitor's fixture renders at 100 columns,
// one C string per line, included inside an array initialiser in
// p2pool_monitor_kat.cpp.
//
// It is kept in its own file rather than inline because it is meant to be READ
// as a picture. A reviewer can open this and see the dashboard -- the labels,
// the units, the cadence bar, the pulse ramp, the emitted-id footer -- without
// building anything, and a diff on this file is a diff of what an operator will
// be looking at.
//
// Regenerate deliberately, never casually:
//
//     xmr_p2pool_monitor_kat --emit-golden > p2pool_monitor_golden.inc
//
// (then put this header back). If a change to the renderer was not intended to
// change what is on screen, this file changing is the bug report.
// ---------------------------------------------------------------------------
" p2pool monitor  READ-ONLY  chains 3/3  up 00:03:05  peers 9/99  blocks 17  races 1  11.2 KiB out",
"----------------------------------------------------------------------------------------------------",
" MAIN  port 37889  LIVE  target 10s ----------------------------------------------------------------",
"   tip      15200104 2b323940  diff 4.36 G  hash 436.00 MH/s  cum 4.36 T",
"   cadence  9.33 s / 10 s  [#######-:-------]  over 4 live heights above 15200100",
"   pulse    ---  gaps, newest right (3)",
"   races    contested 1  uncles named 1 resolved 1  monero tpl 3512003 over 5 heights",
"   net      4 up / 4 sock / 57 known / 48 gossip / 12 queued  blocks 8 (dup 0, bad 0, bc 1)",
"   out      chal 6  sol 6  block_req 141  peer_req 6  = 4.9 KiB sent",
"   feed     15200104 2b323940  2s 122sh u1   15200103 d0d7dee5* 10s 120sh",
"",
" MINI  port 37888  LIVE  target 10s ----------------------------------------------------------------",
"   tip      14757144 686f767d  diff 218.00 M  hash 21.80 MH/s  cum 218.00 G",
"   cadence  11.17 s / 10 s  [########:-------]  over 4 live heights above 14757140",
"   pulse    .*-  gaps, newest right (3)",
"   races    contested 0  uncles named 0 resolved 0  monero tpl 3512003 over 4 heights",
"   net      3 up / 3 sock / 31 known / 22 gossip / 7 queued  blocks 6 (dup 0, bad 1, bc 0)",
"   out      chal 5  sol 5  block_req 118  peer_req 5  = 4.1 KiB sent",
"   feed     14757144 686f767d  0s 46sh   14757143 575e656c  9s 46sh",
"",
" NANO  port 37890  WARM  target 30s ----------------------------------------------------------------",
"   tip      2301885 72798087  diff 9.40 M  hash 313.33 kH/s  cum 9.40 G",
"   cadence  warming -- 1 live height(s) above frontier 2301884; two are needed to time the chain",
"   pulse    (no live gaps yet)",
"   races    contested 0  uncles named 0 resolved 0  monero tpl 3512003 over 3 heights",
"   net      2 up / 2 sock / 11 known / 6 gossip / 3 queued  blocks 3 (dup 0, bad 0, bc 0)",
"   out      chal 3  sol 3  block_req 64  peer_req 3  = 2.2 KiB sent",
"   feed     2301885 72798087  4s 10sh   2301883 50575e65  34s 9sh   2301884 61686f76  35s 9sh",
"",
"----------------------------------------------------------------------------------------------------",
" emitted ids {0,1,3,6}  CHALLENGE  SOLUTION  BLOCK_REQUEST  PEER_LIST_REQUEST",
" never emitted: LISTEN_PORT, BLOCK_RESPONSE, BLOCK_BROADCAST, BLOCK_NOTIFY -- no encoder exists",
