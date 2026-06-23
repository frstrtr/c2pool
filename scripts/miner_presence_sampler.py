#!/usr/bin/env python3
"""miner_presence_sampler — D-MINER.1

Polls the c2pool dashboard JSON API (/local_stats) and records per-worker
presence into a local sqlite DB, then rolls raw samples up into per-worker/day
summaries. Built by dashboard-steward: every recorded metric is sourced from
the same internal state the dashboard surfaces — no stubs, no fabrication.

Two modes:
  sample   poll /local_stats every --interval seconds, append raw rows
  rollup   aggregate raw rows into daily per-worker summaries, prune raw >90d

Source fields (see core/web_server.cpp rest_local_stats):
  miner_hash_rates        {worker_address: hashrate}        live hashrate
  miner_dead_hash_rates   {worker_address: dead_hashrate}   DOA/dead hashrate
  shares                  {total, orphan, dead}             pool-level (global)

Presence rule: a worker is "online" for a sample when its live hashrate > 0.

Retention: raw samples kept 90 days; daily rollups kept forever.

Known gap (future D-MINER.x): /local_stats exposes shares only pool-wide, not
per-worker, so the daily `shares`/`stale_pct` columns are recorded at pool
scope (worker='__pool__'). Per-worker stale% is derived honestly from each
worker's dead/(live+dead) hashrate, which IS per-worker.
"""
import argparse
import json
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timezone

DEFAULT_URL = "http://127.0.0.1:8080/local_stats"
RAW_RETENTION_DAYS = 90


def now_ts():
    return int(time.time())


def connect(db_path):
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS samples (
            ts            INTEGER NOT NULL,
            worker        TEXT    NOT NULL,
            hashrate      REAL    NOT NULL,
            dead_hashrate REAL    NOT NULL,
            online        INTEGER NOT NULL
        )""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_samples_ts ON samples(ts)")
    con.execute("CREATE INDEX IF NOT EXISTS ix_samples_worker ON samples(worker, ts)")
    # pool-level shares snapshot (global; not attributable per worker via this API)
    con.execute("""
        CREATE TABLE IF NOT EXISTS pool_samples (
            ts            INTEGER NOT NULL PRIMARY KEY,
            shares_total  INTEGER NOT NULL,
            shares_orphan INTEGER NOT NULL,
            shares_dead   INTEGER NOT NULL
        )""")
    con.execute("""
        CREATE TABLE IF NOT EXISTS daily (
            day          TEXT NOT NULL,
            worker       TEXT NOT NULL,
            hours_online REAL NOT NULL,
            avg_hashrate REAL NOT NULL,
            samples      INTEGER NOT NULL,
            shares       INTEGER NOT NULL,
            stale_pct    REAL NOT NULL,
            PRIMARY KEY (day, worker)
        )""")
    con.commit()
    return con


def fetch(url, timeout=10):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def record_sample(con, stats):
    ts = now_ts()
    live = stats.get("miner_hash_rates", {}) or {}
    dead = stats.get("miner_dead_hash_rates", {}) or {}
    rows = []
    for worker in set(live) | set(dead):
        hr = float(live.get(worker, 0.0))
        dr = float(dead.get(worker, 0.0))
        rows.append((ts, worker, hr, dr, 1 if hr > 0 else 0))
    if rows:
        con.executemany(
            "INSERT INTO samples(ts,worker,hashrate,dead_hashrate,online) VALUES(?,?,?,?,?)",
            rows)
    sh = stats.get("shares", {}) or {}
    con.execute(
        "INSERT OR REPLACE INTO pool_samples(ts,shares_total,shares_orphan,shares_dead) VALUES(?,?,?,?)",
        (ts, int(sh.get("total", 0)), int(sh.get("orphan", 0)), int(sh.get("dead", 0))))
    con.commit()
    return len(rows)


def sample_loop(con, url, interval, once=False):
    while True:
        try:
            stats = fetch(url)
            n = record_sample(con, stats)
            print(f"[{datetime.now(timezone.utc).isoformat()}] sampled {n} workers", flush=True)
        except Exception as e:  # never let a transient fetch error kill the sampler
            print(f"[{datetime.now(timezone.utc).isoformat()}] sample error: {e}", file=sys.stderr, flush=True)
        if once:
            return
        time.sleep(interval)


def rollup(con, interval):
    """Aggregate raw samples into per-worker/day rows. Idempotent (REPLACE)."""
    cur = con.execute("SELECT MIN(ts), MAX(ts) FROM samples")
    lo, hi = cur.fetchone()
    if lo is None:
        print("no samples to roll up")
        return
    hours_per_sample = interval / 3600.0
    cur = con.execute("""
        SELECT date(ts,'unixepoch') AS day, worker,
               SUM(online)                                   AS online_samples,
               COUNT(*)                                      AS n,
               AVG(CASE WHEN online=1 THEN hashrate END)     AS avg_hr,
               SUM(hashrate)                                 AS sum_live,
               SUM(dead_hashrate)                            AS sum_dead
        FROM samples GROUP BY day, worker""")
    n_rows = 0
    for day, worker, online_samples, n, avg_hr, sum_live, sum_dead in cur.fetchall():
        hours_online = (online_samples or 0) * hours_per_sample
        avg_hashrate = avg_hr or 0.0
        denom = (sum_live or 0.0) + (sum_dead or 0.0)
        stale_pct = (100.0 * (sum_dead or 0.0) / denom) if denom > 0 else 0.0
        con.execute("""INSERT OR REPLACE INTO daily
            (day,worker,hours_online,avg_hashrate,samples,shares,stale_pct)
            VALUES(?,?,?,?,?,?,?)""",
            (day, worker, hours_online, avg_hashrate, n, 0, stale_pct))
        n_rows += 1
    # pool-level daily shares delta (max-min over the day) under worker='__pool__'
    cur = con.execute("""
        SELECT date(ts,'unixepoch') AS day,
               MAX(shares_total)-MIN(shares_total) AS d_total,
               MAX(shares_dead)-MIN(shares_dead)   AS d_dead
        FROM pool_samples GROUP BY day""")
    for day, d_total, d_dead in cur.fetchall():
        d_total = max(0, d_total or 0)
        d_dead = max(0, d_dead or 0)
        stale = (100.0 * d_dead / d_total) if d_total > 0 else 0.0
        con.execute("""INSERT OR REPLACE INTO daily
            (day,worker,hours_online,avg_hashrate,samples,shares,stale_pct)
            VALUES(?,?,?,?,?,?,?)""",
            (day, "__pool__", 0.0, 0.0, 0, d_total, stale))
        n_rows += 1
    # prune raw beyond retention; daily kept forever
    cutoff = now_ts() - RAW_RETENTION_DAYS * 86400
    con.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
    con.execute("DELETE FROM pool_samples WHERE ts < ?", (cutoff,))
    con.commit()
    print(f"rolled up {n_rows} per-worker/day rows; pruned raw < {RAW_RETENTION_DAYS}d")


def main():
    ap = argparse.ArgumentParser(description="c2pool miner presence sampler + rollup (D-MINER.1)")
    ap.add_argument("mode", choices=["sample", "rollup"])
    ap.add_argument("--db", default="miner_presence.db")
    ap.add_argument("--url", default=DEFAULT_URL, help="dashboard /local_stats URL")
    ap.add_argument("--interval", type=int, default=60, help="sample interval seconds")
    ap.add_argument("--once", action="store_true", help="sample: take one sample and exit")
    args = ap.parse_args()
    con = connect(args.db)
    try:
        if args.mode == "sample":
            sample_loop(con, args.url, args.interval, once=args.once)
        else:
            rollup(con, args.interval)
    finally:
        con.close()


if __name__ == "__main__":
    main()
