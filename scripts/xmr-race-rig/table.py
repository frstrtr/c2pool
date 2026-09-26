#!/usr/bin/env python3
# table.py RUNDIR... : one row per run from runs-*/classify.json (race_classify.py --json) + the totals.
import json, sys, os
rows, tot = [], dict(div=0, runs=0, found=0, lane=0, orph=0, cur=0, mm=0, fin=0, a=0, b=0, fa=0, fb=0, fired=0, late=0, fbr=0)
print(f"{'run':<16} {'found':>5} {'lane':>5} {'orph':>5} {'maxdepth A/B/C (native)':>24} {'cursors':>7} {'dig_mm':>6} {'fin_neq':>7} {'a':>3} {'b(root)':>6} {'a:D2|late/a':>7} {'rebook':>7}")
for d in sys.argv[1:]:
    p = os.path.join(d, "classify.json")
    if not os.path.exists(p): print(f"{os.path.basename(d):<16} (no classify.json)"); continue
    s = json.load(open(p))["summary"]
    md = "/".join(str(s["max_depth"].get(n, "-")) for n in "ABC")
    rb = "/".join(str(s["stale_pending_rebooked"].get(n, "-")) for n in "ABC")
    print(f"{os.path.basename(d):<16} {s['found']:>5} {str(s['lane_canonical']):>5} {str(s['orphans']):>5} {md:>24} {s['shared_cursors']:>7} "
          f"{s['digest_mismatches']:>6} {s['fin_unequal']:>7} {s['fin_a']:>3} {str(s['fin_b'])+'('+str(s.get('fin_b_root','?'))+')':>6} {str(s['fin_a_alarm_fired'])+'|'+str(s.get('fin_a_late_unbooked_fired',0))+'/'+str(s['fin_a']):>7} {rb:>7}")
    tot["div"] += 1 if (s["digest_mismatches"] or s["fin_unequal"]) else 0
    tot["runs"] += 1; tot["found"] += s["found"]; tot["lane"] += s["lane_canonical"] or 0; tot["orph"] += s["orphans"] or 0
    tot["cur"] += s["shared_cursors"]; tot["mm"] += s["digest_mismatches"]; tot["fin"] += s["fin_unequal"]
    tot["a"] += s["a"]; tot["b"] += s["b"]; tot["fa"] += s["fin_a"]; tot["fb"] += s["fin_b"]; tot["fbr"] += s.get("fin_b_root", 0); tot["fired"] += s["fin_a_alarm_fired"]; tot["late"] += s.get("fin_a_late_unbooked_fired", 0)
print(f"TOTAL runs={tot['runs']} found={tot['found']} lane={tot['lane']} orphans={tot['orph']} shared_cursors={tot['cur']} "
      f"digest_mismatches={tot['mm']} (a={tot['a']} b={tot['b']}) finalized_unequal_heights={tot['fin']} (a={tot['fa']} D2_alarm_fired={tot['fired']}/{tot['fa']} late_unbooked_alarm={tot['late']}/{tot['fa']} b={tot['fb']} of which root={tot['fbr']}) runs_with_divergence={tot['div']}/{tot['runs']}")
