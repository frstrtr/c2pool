#!/usr/bin/env python3
"""miner_notify_engine — D-MINER.5 (P1: evaluator + core + email adapter)

Transport-agnostic miner notification engine. Reads the presence DB written by
miner_presence_sampler (D-MINER.1), diffs successive per-worker samples into
typed events, applies per-worker subscription + throttle/dedupe + quiet-hours,
and delivers an abstract Message through a pluggable transport.

Built by dashboard-steward. Charter honesty rules apply end to end:
  * "online" == observed live hashrate > 0 (same source of truth as the
    dashboard); the engine never fabricates presence.
  * Every produced Message is recorded in `notifications` with an explicit
    status (delivered / undelivered / throttled / quiet). An alert that cannot
    be delivered is logged as undelivered, NEVER silently dropped.

Seams (per docs/design/d-miner-5-notify-engine.md):
  1. event source   -> evaluate() diffs samples -> typed events
  2. notification core (transport-agnostic) -> subscription/throttle/quiet
  3. transport adapter -> deliver(Message, route); P1 ships email + logonly.
     V36 P2P relay (P2) and Telegram (P3) plug in here later, no core change.

Modes:
  run       evaluate newest samples, route+deliver due notifications
  daily     emit per-worker daily-summary from the `daily` rollup table
  subscribe operator-seed/update a worker subscription (TOFU public is D-MINER.4)
  selftest  deterministic in-memory KAT of the evaluator + core (no network)
"""
import argparse
import json
import smtplib
import sqlite3
import sys
import time
from datetime import datetime, timezone
from email.message import EmailMessage

# event kinds
OFFLINE = "offline"
BACK_ONLINE = "back_online"
HASHRATE_DROP = "hashrate_drop"
DAILY_SUMMARY = "daily_summary"

SEVERITY = {OFFLINE: "warn", BACK_ONLINE: "info",
            HASHRATE_DROP: "warn", DAILY_SUMMARY: "info"}

# subscription defaults (operator can override per worker)
DEF_OFFLINE_MIN = 15      # emit offline alert after this many minutes dark
DEF_DROP_PCT = 50.0       # emit drop alert when hashrate falls >= this %
DEF_THROTTLE_SEC = 3600   # suppress repeat of same kind within this window


def now_ts():
    return int(time.time())


def connect(db_path):
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL")
    # engine-owned tables; the sampler owns samples/pool_samples/daily
    con.execute("""
        CREATE TABLE IF NOT EXISTS subscriptions (
            worker      TEXT PRIMARY KEY,
            channels    TEXT NOT NULL DEFAULT 'email',
            route       TEXT,                      -- e.g. email address
            quiet_hours TEXT,                      -- "HH-HH" UTC, e.g. "22-07"
            offline_min INTEGER NOT NULL DEFAULT %d,
            drop_pct    REAL    NOT NULL DEFAULT %f,
            throttle_s  INTEGER NOT NULL DEFAULT %d,
            enabled     INTEGER NOT NULL DEFAULT 1
        )""" % (DEF_OFFLINE_MIN, DEF_DROP_PCT, DEF_THROTTLE_SEC))
    # per-worker engine state carried across runs (stateless process otherwise)
    con.execute("""
        CREATE TABLE IF NOT EXISTS worker_state (
            worker        TEXT PRIMARY KEY,
            last_ts       INTEGER,
            last_online   INTEGER,
            last_hashrate REAL,
            offline_since INTEGER,    -- ts the worker first went dark (NULL if up)
            offline_fired INTEGER NOT NULL DEFAULT 0,
            peak_hashrate REAL NOT NULL DEFAULT 0
        )""")
    con.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       INTEGER NOT NULL,
            worker   TEXT NOT NULL,
            kind     TEXT NOT NULL,
            severity TEXT NOT NULL,
            route    TEXT,
            status   TEXT NOT NULL,   -- delivered|undelivered|throttled|quiet
            detail   TEXT
        )""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_notif ON notifications(worker, kind, ts)")
    con.commit()
    return con


# ---------------------------------------------------------------------------
# seam 1: event source — diff newest sample per worker against carried state
# ---------------------------------------------------------------------------
def latest_samples(con):
    """Return {worker: (ts, hashrate, online)} for the newest sample each."""
    cur = con.execute("""
        SELECT s.worker, s.ts, s.hashrate, s.online
        FROM samples s
        JOIN (SELECT worker, MAX(ts) AS mts FROM samples GROUP BY worker) m
          ON s.worker = m.worker AND s.ts = m.mts""")
    return {w: (ts, hr, online) for w, ts, hr, online in cur.fetchall()}


def evaluate(con, sub_for, at=None):
    """Diff newest samples vs carried worker_state -> list of typed events.

    Pure given the DB contents: emits {worker, kind, ts, detail} dicts and
    updates worker_state. `sub_for(worker)` returns the effective subscription
    (so thresholds are per worker). `at` overrides wall clock for testing.
    """
    at = at if at is not None else now_ts()
    events = []
    state = {w: row for w, row in (
        (r[0], r) for r in con.execute(
            "SELECT worker,last_ts,last_online,last_hashrate,offline_since,"
            "offline_fired,peak_hashrate FROM worker_state").fetchall())}
    for worker, (ts, hr, online) in latest_samples(con).items():
        sub = sub_for(worker)
        prev = state.get(worker)
        p_online = prev[2] if prev else None
        offline_since = prev[4] if prev else None
        offline_fired = prev[5] if prev else 0
        peak = prev[6] if prev else 0.0

        if online:
            # back-online edge: only after we actually reported the outage.
            # A sub-threshold blip never fires OFFLINE -> reporting a recovery
            # from an outage the miner was never told about is a false alert.
            if p_online == 0 and offline_fired:
                events.append({"worker": worker, "kind": BACK_ONLINE, "ts": ts,
                               "detail": f"hashrate {hr:.3g} (was offline)"})
            offline_since, offline_fired = None, 0
            # hashrate-drop vs observed peak (honest: only on real prior peak)
            if peak > 0 and hr < peak * (1.0 - sub["drop_pct"] / 100.0):
                events.append({"worker": worker, "kind": HASHRATE_DROP, "ts": ts,
                               "detail": f"hashrate {hr:.3g} < {sub['drop_pct']:.0f}%"
                                         f" of peak {peak:.3g}"})
            peak = max(peak, hr)
        else:
            if offline_since is None:
                offline_since = ts
            dark_min = (ts - offline_since) / 60.0
            if not offline_fired and dark_min >= sub["offline_min"]:
                events.append({"worker": worker, "kind": OFFLINE, "ts": ts,
                               "detail": f"dark {dark_min:.0f}m "
                                         f"(>= {sub['offline_min']}m)"})
                offline_fired = 1

        con.execute("""INSERT OR REPLACE INTO worker_state
            (worker,last_ts,last_online,last_hashrate,offline_since,
             offline_fired,peak_hashrate) VALUES(?,?,?,?,?,?,?)""",
            (worker, ts, online, hr, offline_since, offline_fired, peak))
    con.commit()
    return events


# ---------------------------------------------------------------------------
# seam 2: notification core — subscription / throttle / quiet-hours (no I/O)
# ---------------------------------------------------------------------------
def get_sub(con, worker):
    row = con.execute(
        "SELECT channels,route,quiet_hours,offline_min,drop_pct,throttle_s,"
        "enabled FROM subscriptions WHERE worker=?", (worker,)).fetchone()
    if not row:
        return {"channels": [], "route": None, "quiet_hours": None,
                "offline_min": DEF_OFFLINE_MIN, "drop_pct": DEF_DROP_PCT,
                "throttle_s": DEF_THROTTLE_SEC, "enabled": 0}
    ch, route, qh, omin, drop, thr, en = row
    return {"channels": [c for c in (ch or "").split(",") if c], "route": route,
            "quiet_hours": qh, "offline_min": omin, "drop_pct": drop,
            "throttle_s": thr, "enabled": en}


def in_quiet_hours(quiet_hours, ts):
    if not quiet_hours:
        return False
    try:
        lo, hi = (int(x) for x in quiet_hours.split("-"))
    except ValueError:
        return False
    h = datetime.fromtimestamp(ts, timezone.utc).hour
    return lo <= h < hi if lo <= hi else (h >= lo or h < hi)


def recently_sent(con, worker, kind, ts, window):
    row = con.execute(
        "SELECT MAX(ts) FROM notifications WHERE worker=? AND kind=? AND "
        "status='delivered'", (worker, kind)).fetchone()
    return row[0] is not None and (ts - row[0]) < window


def route_event(con, ev, sub):
    """Classify one event into a delivery decision (pure policy)."""
    if not sub["enabled"] or not sub["channels"]:
        return None  # no subscriber -> nothing to deliver (still loggable)
    kind, worker, ts = ev["kind"], ev["worker"], ev["ts"]
    sev = SEVERITY.get(kind, "info")
    if in_quiet_hours(sub["quiet_hours"], ts) and sev != "warn":
        return {"status": "quiet"}
    if recently_sent(con, worker, kind, ts, sub["throttle_s"]):
        return {"status": "throttled"}
    return {"status": "deliver", "severity": sev,
            "channels": sub["channels"], "route": sub["route"]}


# ---------------------------------------------------------------------------
# seam 3: transport adapters — deliver(Message, route) -> bool
# ---------------------------------------------------------------------------
def render(ev):
    return (f"[c2pool] worker {ev['worker']}: {ev['kind']} — {ev['detail']}")


def deliver_email(subject, body, route, smtp_host, smtp_port, sender):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = route
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
        s.send_message(msg)
    return True


def make_transport(args):
    """Return deliver(channel, subject, body, route) -> bool. logonly never
    raises; email raises on failure so the caller records 'undelivered'."""
    def deliver(channel, subject, body, route):
        if channel == "logonly" or args.dry_run:
            print(f"[logonly] -> {route}: {subject} | {body}", flush=True)
            return True
        if channel == "email":
            return deliver_email(subject, body, route,
                                 args.smtp_host, args.smtp_port, args.sender)
        raise ValueError(f"unknown channel '{channel}'")
    return deliver


def record(con, ev, status, route, severity):
    con.execute("""INSERT INTO notifications
        (ts,worker,kind,severity,route,status,detail)
        VALUES(?,?,?,?,?,?,?)""",
        (ev["ts"], ev["worker"], ev["kind"], severity, route, status,
         ev.get("detail")))
    con.commit()


def run(con, args):
    deliver = make_transport(args)
    events = evaluate(con, lambda w: get_sub(con, w))
    sent = held = 0
    for ev in events:
        sub = get_sub(con, ev["worker"])
        decision = route_event(con, ev, sub)
        if decision is None:
            record(con, ev, "undelivered", None, SEVERITY.get(ev["kind"], "info"))
            held += 1
            continue
        if decision["status"] != "deliver":
            record(con, ev, decision["status"], sub["route"],
                   SEVERITY.get(ev["kind"], "info"))
            held += 1
            continue
        subject = f"c2pool alert: {ev['worker']} {ev['kind']}"
        body = render(ev)
        ok = False
        for channel in decision["channels"]:
            try:
                ok = deliver(channel, subject, body, decision["route"])
                if ok:
                    break
            except Exception as e:  # honesty: a failed send is undelivered, logged
                print(f"deliver error ({channel}): {e}", file=sys.stderr, flush=True)
        record(con, ev, "delivered" if ok else "undelivered",
               decision["route"], decision["severity"])
        sent += 1 if ok else 0
        held += 0 if ok else 1
    print(f"events={len(events)} delivered={sent} held={held}")


def daily(con, args):
    """Emit a per-worker daily-summary for the most recent rolled-up day."""
    deliver = make_transport(args)
    row = con.execute(
        "SELECT MAX(day) FROM daily WHERE worker!='__pool__'").fetchone()
    if not row or not row[0]:
        print("no daily rollups yet")
        return
    day = row[0]
    cur = con.execute(
        "SELECT worker,hours_online,avg_hashrate,stale_pct FROM daily "
        "WHERE day=? AND worker!='__pool__'", (day,))
    n = 0
    for worker, hours, avg_hr, stale in cur.fetchall():
        sub = get_sub(con, worker)
        ev = {"worker": worker, "kind": DAILY_SUMMARY, "ts": now_ts(),
              "detail": f"{day}: online {hours:.1f}h, avg {avg_hr:.3g}, "
                        f"stale {stale:.1f}%"}
        if not sub["enabled"] or not sub["channels"]:
            record(con, ev, "undelivered", None, "info")
            continue
        subject = f"c2pool daily summary: {worker} {day}"
        ok = False
        for channel in sub["channels"]:
            try:
                ok = deliver(channel, subject, render(ev), sub["route"])
                if ok:
                    break
            except Exception as e:
                print(f"deliver error ({channel}): {e}", file=sys.stderr, flush=True)
        record(con, ev, "delivered" if ok else "undelivered", sub["route"], "info")
        n += 1
    print(f"daily summaries for {day}: {n} workers")


def subscribe(con, args):
    con.execute("""INSERT INTO subscriptions
        (worker,channels,route,quiet_hours,offline_min,drop_pct,throttle_s,enabled)
        VALUES(?,?,?,?,?,?,?,1)
        ON CONFLICT(worker) DO UPDATE SET channels=excluded.channels,
            route=excluded.route, quiet_hours=excluded.quiet_hours,
            offline_min=excluded.offline_min, drop_pct=excluded.drop_pct,
            throttle_s=excluded.throttle_s, enabled=1""",
        (args.worker, args.channels, args.route, args.quiet_hours,
         args.offline_min, args.drop_pct, args.throttle_s))
    con.commit()
    print(f"subscribed {args.worker} -> {args.channels} ({args.route})")


# ---------------------------------------------------------------------------
# deterministic KAT — exercises evaluator + core with no network/clock deps
# ---------------------------------------------------------------------------
def selftest(_args=None):
    con = connect(":memory:")
    # the sampler normally owns `samples`; create it here for the KAT
    con.execute("""CREATE TABLE IF NOT EXISTS samples (
        ts INTEGER NOT NULL, worker TEXT NOT NULL, hashrate REAL NOT NULL,
        dead_hashrate REAL NOT NULL, online INTEGER NOT NULL)""")
    con.commit()
    sub = {"channels": ["logonly"], "route": "x", "quiet_hours": None,
           "offline_min": 15, "drop_pct": 50.0, "throttle_s": 3600, "enabled": 1}
    sub_for = lambda w: sub
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    def put(ts, worker, hr):
        con.execute("INSERT INTO samples(ts,worker,hashrate,dead_hashrate,online)"
                    " VALUES(?,?,?,?,?)", (ts, worker, hr, 0.0, 1 if hr > 0 else 0))
        con.commit()

    t0 = 1_700_000_000
    # 1) first time online -> NO event (no prior state, no false back-online)
    put(t0, "w1", 100.0)
    e = evaluate(con, sub_for, at=t0)
    check(e == [], f"first-online should be silent, got {e}")

    # 2) goes dark but < offline_min -> no offline yet (no premature alarm)
    put(t0 + 60, "w1", 0.0)
    e = evaluate(con, sub_for, at=t0 + 60)
    check(e == [], f"brief dark < threshold should be silent, got {e}")

    # 3) still dark past offline_min -> exactly one offline event
    put(t0 + 16 * 60, "w1", 0.0)
    e = evaluate(con, sub_for, at=t0 + 16 * 60)
    check([x["kind"] for x in e] == [OFFLINE], f"expected one offline, got {e}")

    # 4) still dark again -> NOT re-fired (offline_fired latch)
    put(t0 + 30 * 60, "w1", 0.0)
    e = evaluate(con, sub_for, at=t0 + 30 * 60)
    check(e == [], f"offline must not re-fire while still dark, got {e}")

    # 5) comes back -> back_online event
    put(t0 + 40 * 60, "w1", 120.0)
    e = evaluate(con, sub_for, at=t0 + 40 * 60)
    check([x["kind"] for x in e] == [BACK_ONLINE], f"expected back_online, got {e}")

    # 6) hashrate halves vs peak (120) -> hashrate_drop
    put(t0 + 41 * 60, "w1", 40.0)
    e = evaluate(con, sub_for, at=t0 + 41 * 60)
    check([x["kind"] for x in e] == [HASHRATE_DROP], f"expected drop, got {e}")

    # 6b) sub-threshold blip (dark < offline_min so OFFLINE never fired) then
    #     recovery must stay silent: no false back_online for an unreported outage
    put(t0 + 50 * 60, "w3", 90.0)
    evaluate(con, sub_for, at=t0 + 50 * 60)             # w3 first-online: silent
    put(t0 + 51 * 60, "w3", 0.0)
    e = evaluate(con, sub_for, at=t0 + 51 * 60)         # 1m dark < 15m threshold
    check([x for x in e if x["worker"] == "w3"] == [],
          f"sub-threshold blip should be silent, got {e}")
    put(t0 + 52 * 60, "w3", 90.0)
    e = evaluate(con, sub_for, at=t0 + 52 * 60)         # recovered, never alerted
    check([x for x in e if x["worker"] == "w3"] == [],
          f"recovery without a prior offline alert must be silent, got {e}")

    # 6c) hashrate_drop honesty: a brand-new worker (no observed prior peak)
    #     must NEVER emit a drop on its first sample -- a drop without real
    #     history is a fabricated alert (mirrors the back_online gate of #558).
    put(t0 + 60 * 60, "w4", 30.0)
    e = evaluate(con, sub_for, at=t0 + 60 * 60)
    check([x for x in e if x["worker"] == "w4"] == [],
          f"first-online must never fire hashrate_drop, got {e}")

    # 6d) only AFTER a real peak is observed does a halving fire exactly one drop
    put(t0 + 61 * 60, "w4", 12.0)                       # 12 < 50% of peak 30
    e = evaluate(con, sub_for, at=t0 + 61 * 60)
    check([x["kind"] for x in e if x["worker"] == "w4"] == [HASHRATE_DROP],
          f"expected one drop vs observed peak, got {e}")

    # 6e) a drop is never evaluated while the worker is dark (online branch only):
    #     going to 0 is an OFFLINE concern, not a fabricated -100% drop alert.
    put(t0 + 62 * 60, "w4", 0.0)
    e = evaluate(con, sub_for, at=t0 + 62 * 60)
    check([x["kind"] for x in e if x["worker"] == "w4"] == [],
          f"dark sample must not fire hashrate_drop, got {e}")

    # 7) quiet-hours suppresses info (back_online) but NOT warn (offline)
    check(in_quiet_hours("22-07", t0) is not None, "quiet parse")
    info_ev = {"worker": "w1", "kind": BACK_ONLINE, "ts": t0, "detail": "d"}
    warn_ev = {"worker": "w1", "kind": OFFLINE, "ts": t0, "detail": "d"}
    qsub = dict(sub, quiet_hours="00-23")  # t0 hour is inside this window
    d_info = route_event(con, info_ev, qsub)
    d_warn = route_event(con, warn_ev, qsub)
    check(d_info and d_info["status"] == "quiet", f"info should be quiet, got {d_info}")
    check(d_warn and d_warn["status"] == "deliver", f"warn should bypass quiet, got {d_warn}")

    # 8) throttle: a just-delivered kind is suppressed within window
    con.execute("INSERT INTO notifications(ts,worker,kind,severity,route,status)"
                " VALUES(?,?,?,?,?,?)",
                (t0, "w2", OFFLINE, "warn", "x", "delivered"))
    con.commit()
    thr = route_event(con, {"worker": "w2", "kind": OFFLINE, "ts": t0 + 10,
                            "detail": "d"}, sub)
    check(thr and thr["status"] == "throttled", f"expected throttled, got {thr}")

    # 9) no subscription -> route_event returns None (logged undelivered, not dropped)
    nosub = dict(sub, enabled=0, channels=[])
    check(route_event(con, info_ev, nosub) is None, "unsub should route to None")

    con.close()
    if fails:
        print("SELFTEST FAILED:")
        for f in fails:
            print("  -", f)
        return 1
    print("SELFTEST OK (13/13)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="c2pool miner notification engine (D-MINER.5 P1)")
    sp = ap.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default="miner_presence.db")
    common.add_argument("--dry-run", action="store_true", help="force logonly transport")
    common.add_argument("--smtp-host", default="127.0.0.1")
    common.add_argument("--smtp-port", type=int, default=25)
    common.add_argument("--sender", default="dashboard-steward@morisguide.com")

    sp.add_parser("run", parents=[common])
    sp.add_parser("daily", parents=[common])

    s = sp.add_parser("subscribe", parents=[common])
    s.add_argument("--worker", required=True)
    s.add_argument("--channels", default="email")
    s.add_argument("--route", required=True, help="delivery address for the channel")
    s.add_argument("--quiet-hours", default=None, help="UTC HH-HH, e.g. 22-07")
    s.add_argument("--offline-min", type=int, default=DEF_OFFLINE_MIN)
    s.add_argument("--drop-pct", type=float, default=DEF_DROP_PCT)
    s.add_argument("--throttle-s", type=int, default=DEF_THROTTLE_SEC)

    sp.add_parser("selftest")

    args = ap.parse_args()
    if args.mode == "selftest":
        sys.exit(selftest(args))
    con = connect(args.db)
    try:
        {"run": run, "daily": daily, "subscribe": subscribe}[args.mode](con, args)
    finally:
        con.close()


if __name__ == "__main__":
    main()
