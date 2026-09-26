#!/usr/bin/env python3
# race_classify.py -- per-mismatch classification of settlement divergence between honest v37 XMR nodes.
#
# Reads the stdout logs of N c2pool-v37-xmr nodes (and, optionally, their monerods' logs) and prints:
#   * per node: lane-block bookings, ORPHANED dispositions, re-deliveries, reorg depths (native view, from
#     the node log; monerod view, from "REORGANIZE on height" lines when a monerod log is given), the
#     FINALIZED set, the owed_digest per finalize cursor, and every D2 / cba alarm it raised;
#   * every shared cursor whose owed_digest differs, and every height whose FINALIZED block differs, each
#     labelled:
#       (a) EXPECTED  -- some node saw a reorg covering that height at depth >= D_conf (finality boundary
#                        crossed); then "alarm fired" = that node raised MINORITY-SUSPECT/DETECTED or a
#                        CONVERGING/DIVERGED state (the D2-C alarm, alarm-only by ruling D-1 = C);
#       (b) BUG       -- every node's reorg covering that height was shallower than D_conf, yet they
#                        finalized different blocks (or the digests differ with equal finalized sets);
#     with the evidence lines (node, log line number, text) around each divergent height.
# Exit status: 0 = no class-(b) divergence, 2 = at least one class-(b), 1 = usage/parse error.
#
# Usage:
#   race_classify.py LOGDIR [--d-conf 10] [--label X] [--json out.json]
#       LOGDIR holds node<N>.log (+ optional monerod<i>.log; node letter A,B,C.. maps to monerod1,2,3..)
#   race_classify.py --node A=/path/a.log --node B=/path/b.log [--monerod A=/path/m.log ...] [--d-conf 10]
#       explicit files (capstone: one log per host); --coinbases FILE = dump_coinbases.py output (optional)
import argparse, collections, json, os, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("logdir", nargs="?")
ap.add_argument("--node", action="append", default=[])
ap.add_argument("--monerod", action="append", default=[])
ap.add_argument("--coinbases")
ap.add_argument("--d-conf", type=int, default=None)
ap.add_argument("--label", default="")
ap.add_argument("--json")
ap.add_argument("--quiet", action="store_true", help="summary only, no evidence lines")
a = ap.parse_args()

nodes, mons = {}, {}
if a.logdir:
    for f in sorted(os.listdir(a.logdir)):
        m = re.fullmatch(r"node([A-Za-z0-9_-]+)\.log", f)
        if m: nodes[m.group(1)] = os.path.join(a.logdir, f)
    for i, n in enumerate(sorted(nodes), 1):
        p = os.path.join(a.logdir, f"monerod{i}.log")
        if os.path.exists(p): mons[n] = p
    cb = os.path.join(a.logdir, "coinbases.txt")
    if not a.coinbases and os.path.exists(cb): a.coinbases = cb
for kv in a.node: k, v = kv.split("=", 1); nodes[k] = v
for kv in a.monerod: k, v = kv.split("=", 1); mons[k] = v
if len(nodes) < 2: print("need >= 2 node logs", file=sys.stderr); sys.exit(1)
N = sorted(nodes)

RX = {
    "fin":     re.compile(r"FINALIZED ([0-9a-f]{12})\S* h=(\d+) SETTLED"),
    "orph":    re.compile(r"ORPHANED ([0-9a-f]{12})\S* h=(\d+) left the pending set(.*)"),
    "book":    re.compile(r"cba: CHAIN FOUND booked ([0-9a-f]{12})\S* h=(\d+)"),
    "again":   re.compile(r"cba: chain block ([0-9a-f]{12})\S* h=(\d+) is canonical AGAIN"),
    "reorgin": re.compile(r"reorg-in: delivered (\d+) re-applied height\(s\) \[(\d+)\.\.(\d+)\] below the Reorg tip h=(\d+) \(depth (\d+)\)"),
    "digest":  re.compile(r"cba-digest: cursor=(\d+) .*owed_digest=([0-9a-f]{64})"),
    "tmpl":    re.compile(r"(?:^|\s)template: id=\d+ height=(\d+)"),
    "found":   re.compile(r"\[submit\] FOUND h=(\d+) bid=([0-9a-f]{12})"),
    "dconf":   re.compile(r"D_conf=(\d+)"),
    "alarm":   re.compile(r"cba-ALARM (\S+(?: \S+)?)"),
    "minst":   re.compile(r"minority: mode=(\S+) state=(\S+) .*alarms=(\d+) suspect=(\d+) .*detected=(\d+) converged=(\d+) diverged=(\d+)"),
    "tipfeed": re.compile(r"native tip feed: events=(\d+) \(extend=(\d+) reorg=(\d+) orphan=(\d+)\)"),
    "rcvote":  re.compile(r"r-c: .*vote=(\S+)"),
    "rootref": re.compile(r"lane-root-refused: chain lane block ([0-9a-f]{12})\S* h=(\d+)"),
}
MON_REORG = re.compile(r"REORGANIZE on height: (\d+) of (\d+)")
MON_ALT = re.compile(r"BLOCK ADDED AS ALTERNATIVE ON HEIGHT (\d+)")

class NodeLog:
    def __init__(s, name, path):
        s.name, s.path = name, path
        s.fin = {}                       # h -> (bid12, line)
        s.digest = {}                    # cursor -> (digest, line)
        s.ev = collections.defaultdict(list)   # h -> [(line, text)]
        s.depth = collections.defaultdict(int) # h -> max reorg depth (native view) covering h
        s.depth_src = {}
        s.reorgs = []                    # (line, lo, hi, tip, depth)
        s.orph = []                      # (line, bid, h, est_depth)
        s.found = []
        s.alarms = collections.Counter(); s.alarm_lines = []
        s.minority = None; s.tipfeed = None; s.rcvote = None
        s.dconf = None; s.stale_rebooked = 0; s.rootref = {}
        tip = 0; last_reorg = None
        for ln, line in enumerate(open(path, errors="replace"), 1):
            if "D_conf=" in line and s.dconf is None:
                m = RX["dconf"].search(line)
                if m: s.dconf = int(m.group(1))
            m = RX["tmpl"].search(line)
            if m: tip = int(m.group(1)) - 1; continue
            m = RX["reorgin"].search(line)
            if m:
                n_, lo, hi, H, d = map(int, m.groups())
                last_reorg = (ln, lo, H, d); s.reorgs.append((ln, lo, hi, H, d))
                for h in range(lo, H):
                    s.ev[h].append((ln, line.strip()))
                    if d > s.depth[h]: s.depth[h] = d; s.depth_src[h] = ln
                continue
            m = RX["orph"].search(line)
            if m:
                bid, h, tail = m.group(1), int(m.group(2)), m.group(3)
                if "retired at its re-delivery" in tail: s.stale_rebooked += 1
                # depth estimate: a reorg-in covering h delivered shortly before -> its depth; else the
                # current tip - h + 1 (an upper bound: the tip may already include the new branch)
                if last_reorg and last_reorg[1] <= h <= last_reorg[2] and ln - last_reorg[0] < 80: d = last_reorg[3]
                else: d = max(1, tip - h + 1)
                s.orph.append((ln, bid, h, d)); s.ev[h].append((ln, line.strip()))
                if d > s.depth[h]: s.depth[h] = d; s.depth_src[h] = ln
                continue
            m = RX["fin"].search(line)
            if m: s.fin[int(m.group(2))] = (m.group(1), ln); s.ev[int(m.group(2))].append((ln, line.strip())); continue
            m = RX["book"].search(line) or RX["again"].search(line)
            if m: s.ev[int(m.group(2))].append((ln, line.strip())); continue
            m = RX["digest"].search(line)
            if m: s.digest[int(m.group(1))] = (m.group(2), ln); continue
            m = RX["found"].search(line)
            if m: s.found.append((int(m.group(1)), m.group(2))); continue
            m = RX["rootref"].search(line)
            if m: s.rootref[int(m.group(2))] = m.group(1); s.ev[int(m.group(2))].append((ln, line.strip()))
            m = RX["alarm"].search(line)
            if m:
                k = m.group(1).rstrip(":"); s.alarms[k] += 1
                if "MINORITY" in k or "DIVERGED" in k: s.alarm_lines.append((ln, line.strip()[:240]))
                continue
            m = RX["minst"].search(line)
            if m: s.minority = dict(zip(("mode", "state", "alarms", "suspect", "detected", "converged", "diverged"), m.groups())); continue
            m = RX["tipfeed"].search(line)
            if m: s.tipfeed = dict(zip(("events", "extend", "reorg", "orphan"), map(int, m.groups()))); continue
            m = RX["rcvote"].search(line)
            if m: s.rcvote = m.group(1)
    def d2_fired(s):
        mi = s.minority or {}
        return bool(s.alarm_lines) or any(int(mi.get(k, 0)) > 0 for k in ("alarms", "suspect", "detected", "diverged")) \
            or mi.get("state") in ("CONVERGING", "DIVERGED")
    def max_depth(s): return max(s.depth.values(), default=0)

L = {n: NodeLog(n, nodes[n]) for n in N}
D = a.d_conf or next((L[n].dconf for n in N if L[n].dconf), None) or 10
mon = {}
for n, p in mons.items():
    depths, alts, cover = [], 0, collections.defaultdict(int)
    for line in open(p, errors="replace"):
        m = MON_REORG.search(line)   # "REORGANIZE on height: <split> of <old top>": blocks split..top disconnected
        if m:
            x, y = int(m.group(1)), int(m.group(2)); d = y - x + 1; depths.append(d)
            for h in range(x, y + 1): cover[h] = max(cover[h], d)
        if MON_ALT.search(line): alts += 1
    mon[n] = {"reorgs": len(depths), "max_depth": max(depths, default=0), "alternatives": alts, "cover": cover}

# canonical chain (optional): dump_coinbases.py output "h bid reward outs nout extra blob"
canon = {}
if a.coinbases and os.path.exists(a.coinbases):
    for l in open(a.coinbases):
        f = l.split()
        if len(f) >= 2 and f[0].isdigit(): canon[int(f[0])] = f[1][:12]
found_bids = {}
for n in N:
    for h, b in L[n].found: found_bids[b] = (h, n)
lane_canon = sum(1 for b, (h, _) in found_bids.items() if canon.get(h) == b) if canon else None
orphans = (len(found_bids) - lane_canon) if canon else None

# shared cursors + owed_digest mismatches
shared = sorted(set.intersection(*[set(L[n].digest) for n in N]))
mm = [c for c in shared if len({L[n].digest[c][0] for n in N}) > 1]
# finalized-set comparison over the heights every node's cursor has passed
frontier = min(max(L[n].fin, default=0) for n in N)
lo_h = max(min(L[n].fin, default=0) for n in N)
fin_diff = [h for h in range(lo_h, frontier + 1) if len({L[n].fin.get(h, (None,))[0] for n in N}) > 1]

def classify_heights(hs):
    out = []
    for h in hs:
        dep = {n: max(L[n].depth.get(h, 0), mon[n]["cover"].get(h, 0) if n in mon else 0) for n in N}
        deep = [n for n in N if dep[n] >= D]
        if deep:
            fired = {n: L[n].d2_fired() for n in N}
            late = {n: any(k.startswith("late_unbooked") for k in L[n].alarms) for n in N}
            out.append({"h": h, "class": "a", "depths": dep, "deep_nodes": deep,
                        "alarm_fired": any(fired.values()), "fired": fired,
                        "late_unbooked_fired": any(late[n] for n in deep), "late": late})
        else:
            # mechanism hint (reference = the canonical block when known, else the majority): a node disposed it ORPHANED (the one-tick
            # flip-flop signature fixed by RACE-DIVERGE) or never booked it at all
            fins = collections.Counter(L[n].fin.get(h, (None,))[0] for n in N if h in L[n].fin)
            maj = canon.get(h) or (fins.most_common(1)[0][0] if fins else None)   # the reference block
            sig = {}
            for n in N:
                if L[n].fin.get(h, (None,))[0] == maj: continue
                orphaned = [x for x in L[n].orph if x[2] == h and x[1] == maj]
                sig[n] = ("reference block ORPHANED although canonical (one-tick flip-flop)" if orphaned
                          else "reference block REFUSED lane-root-unmatched (downstream of an earlier divergence)"
                          if L[n].rootref.get(h) == maj
                          else "reference block never booked" if not any(maj and maj in t for _, t in L[n].ev.get(h, []))
                          else "other")
            out.append({"h": h, "class": "b", "depths": dep, "signature": sig})
    return out

report = {"label": a.label, "d_conf": D, "nodes": N, "mismatches": [], "fin_diff": []}
fin_cls = classify_heights(fin_diff)
report["fin_diff"] = fin_cls
for c in mm:
    hs = [h for h in fin_diff if h <= c]
    if hs: cls = classify_heights(hs); k = "a" if any(x["class"] == "a" for x in cls) else "b"
    else: cls = []; k = "b"   # digests differ with equal finalized sets: credit/amount divergence, never expected
    report["mismatches"].append({"cursor": c, "class": k, "heights": cls,
                                 "digests": {n: L[n].digest[c][0][:16] for n in N}})

# ---- print ----
print(f"===== RACE-CLASSIFY {a.label} (D_conf={D}, nodes={','.join(N)}) =====")
if canon:
    print(f"lane blocks: FOUND={len(found_bids)} canonical(on monerod chain)={lane_canon} orphaned={orphans} "
          f"same-height multi-FOUND heights={sum(1 for v in collections.Counter(h for h, _ in found_bids.values()).values() if v >= 2)}")
else:
    print(f"lane blocks: FOUND={len(found_bids)} (no coinbases file: canonical/orphan split unknown)")
for n in N:
    s = L[n]; mi = s.minority or {}
    print(f"  {n}: FINALIZED={len(s.fin)} cursors={len(s.digest)} ORPHANED={len(s.orph)} reorg-in={len(s.reorgs)} "
          f"max_reorg_depth(native)={s.max_depth()} stale_pending_rebooked={s.stale_rebooked} "
          f"tipfeed={s.tipfeed} d2={mi.get('state','?')}(alarms={mi.get('alarms','?')} suspect={mi.get('suspect','?')} "
          f"detected={mi.get('detected','?')} diverged={mi.get('diverged','?')}) rc_vote={s.rcvote} "
          f"alarms={dict(s.alarms)}" + (f" | monerod reorgs={mon[n]['reorgs']} max_depth={mon[n]['max_depth']} alternatives={mon[n]['alternatives']}" if n in mon else ""))
print(f"OWED_DIGEST: shared cursors={len(shared)} range={shared[0] if shared else 0}..{shared[-1] if shared else 0} MISMATCHES={len(mm)} {mm[:12]}")
print(f"FINALIZED sets over heights {lo_h}..{frontier}: UNEQUAL heights={len(fin_diff)} {fin_diff[:12]}")
na = sum(1 for x in report["mismatches"] if x["class"] == "a"); nb = len(report["mismatches"]) - na
fa = sum(1 for x in fin_cls if x["class"] == "a"); fb = len(fin_cls) - fa
fired = sum(1 for x in fin_cls if x["class"] == "a" and x["alarm_fired"])
late_fired = sum(1 for x in fin_cls if x["class"] == "a" and x["late_unbooked_fired"])
fb_root = sum(1 for x in fin_cls if x["class"] == "b" and not all("downstream" in v for v in x.get("signature", {}).values()))
print(f"CLASSIFY: digest mismatches a={na} b={nb} | finalized-set unequal heights a={fa} (D2 alarm fired {fired}/{fa}, late_unbooked alarm {late_fired}/{fa}) b={fb} (root={fb_root}, downstream={fb - fb_root})")
for x in report["mismatches"]:
    print(f"  cursor {x['cursor']}: class ({x['class']}) digests={x['digests']} divergent heights={[y['h'] for y in x['heights']]}")
for y in fin_cls:
    dep = " ".join(f"{n}={y['depths'][n]}" for n in N)
    tag = (f"(a) EXPECTED: reorg >= D_conf on {y['deep_nodes']}, D2 alarm fired={y['alarm_fired']}, "
           f"cba-ALARM late_unbooked on the deep node={y['late_unbooked_fired']}" if y["class"] == "a"
           else f"(b) BUG: every covering reorg < D_conf={D} [{y.get('signature')}]")
    print(f"  h={y['h']}: {tag}; max reorg depth covering h per node (native|monerod): {dep}; FINALIZED: " +
          " ".join(f"{n}={L[n].fin.get(y['h'], ('-',))[0]}" for n in N) + (f" canonical={canon.get(y['h'])}" if canon else ""))
    if not a.quiet:
        for n in N:
            for ln, t in L[n].ev.get(y["h"], [])[:12]: print(f"      {n}:{ln}: {t[:200]}")
for n in N:
    for ln, t in L[n].alarm_lines[:5]: print(f"  D2 alarm {n}:{ln}: {t}")
report["summary"] = {"found": len(found_bids), "lane_canonical": lane_canon, "orphans": orphans,
                     "shared_cursors": len(shared), "digest_mismatches": len(mm), "fin_unequal": len(fin_diff),
                     "a": na, "b": nb, "fin_a": fa, "fin_b": fb, "fin_b_root": fb_root, "fin_a_alarm_fired": fired, "fin_a_late_unbooked_fired": late_fired,
                     "max_depth": {n: L[n].max_depth() for n in N},
                     "monerod_max_depth": {n: mon[n]["max_depth"] for n in mon},
                     "stale_pending_rebooked": {n: L[n].stale_rebooked for n in N}}
print("SUMMARY " + json.dumps(report["summary"], sort_keys=True))
if a.json: json.dump(report, open(a.json, "w"), indent=1, default=str)
sys.exit(2 if (nb or fb) else 0)
