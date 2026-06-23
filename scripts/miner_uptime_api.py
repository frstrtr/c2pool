#!/usr/bin/env python3
"""miner_uptime_api — D-MINER.2

Read-only public HTTP API over the miner_presence.db written by
miner_presence_sampler (D-MINER.1). Serves per-worker uptime — the
electricity-billing document a miner can self-serve — plus a miner roster.

Endpoints:
  GET /api/miners
        -> {"miners": [{worker, first_day, last_day, days, online, last_seen_ts,
                        last_hashrate}], "generated_ts": <int>}
  GET /api/miner/<worker>/uptime?from=YYYY-MM-DD&to=YYYY-MM-DD
        -> {"worker", "from", "to",
            "days": [{day, hours_online, avg_hashrate, samples, stale_pct,
                      partial}],
            "totals": {hours_online, days_present, avg_hashrate}}
  GET /api/miner/<worker>/uptime.csv?from=&to=
        -> text/csv: day,hours_online,avg_hashrate_hs,samples,stale_pct,partial

Design notes (dashboard-steward charter — never lie, never fabricate):
  * Daily rows come from the `daily` table (nightly rollup). The current,
    not-yet-rolled-up day is computed live from raw `samples` so today is
    never silently empty; such rows are flagged "partial": true.
  * The DB is opened strictly read-only (sqlite ?mode=ro) — this service can
    never mutate sampler state.
  * stdlib only, matching the sampler. Bind localhost; front with the same
    reverse proxy that exposes the dashboard.
"""
import argparse
import csv
import io
import json
import re
import sqlite3
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# stratum usernames are payout addresses, optionally .worker — keep it liberal
# but bounded so the path component can't smuggle SQL or traversal.
WORKER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAMPLE_INTERVAL_SECONDS = 60  # must match the sampler --interval for hour math


def day_str(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


def valid_day(s):
    if not s:
        return None
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return s
    except ValueError:
        return None


class Store:
    def __init__(self, db_path, interval):
        self.uri = "file:%s?mode=ro" % db_path
        self.interval = interval

    def _con(self):
        # read-only; one short-lived connection per request keeps it thread-safe
        return sqlite3.connect(self.uri, uri=True)

    def _today(self):
        return day_str(int(time.time()))

    def _live_day(self, con, worker, day):
        """Compute a single day's stats from raw samples (for the current,
        un-rolled-up day). Mirrors the rollup math in the sampler."""
        row = con.execute(
            """SELECT SUM(online), COUNT(*),
                      AVG(CASE WHEN online=1 THEN hashrate END),
                      SUM(hashrate), SUM(dead_hashrate)
                 FROM samples
                WHERE worker=? AND date(ts,'unixepoch')=?""",
            (worker, day)).fetchone()
        online_samples, n, avg_hr, sum_live, sum_dead = row
        if not n:
            return None
        hours = (online_samples or 0) * (self.interval / 3600.0)
        denom = (sum_live or 0.0) + (sum_dead or 0.0)
        stale = (100.0 * (sum_dead or 0.0) / denom) if denom > 0 else 0.0
        return {
            "day": day,
            "hours_online": round(hours, 4),
            "avg_hashrate": round(avg_hr or 0.0, 4),
            "samples": n,
            "stale_pct": round(stale, 4),
            "partial": True,
        }

    def uptime(self, worker, dfrom, dto):
        today = self._today()
        with self._con() as con:
            q = "SELECT day,hours_online,avg_hashrate,samples,stale_pct FROM daily WHERE worker=?"
            params = [worker]
            if dfrom:
                q += " AND day>=?"
                params.append(dfrom)
            if dto:
                q += " AND day<=?"
                params.append(dto)
            q += " ORDER BY day"
            days = []
            seen = set()
            for day, hrs, avg, n, stale in con.execute(q, params).fetchall():
                seen.add(day)
                days.append({
                    "day": day,
                    "hours_online": round(hrs, 4),
                    "avg_hashrate": round(avg, 4),
                    "samples": n,
                    "stale_pct": round(stale, 4),
                    "partial": False,
                })
            # splice in the current day live if it's in range and not rolled up yet
            in_range = (not dfrom or today >= dfrom) and (not dto or today <= dto)
            if in_range and today not in seen:
                live = self._live_day(con, worker, today)
                if live:
                    days.append(live)
            days.sort(key=lambda d: d["day"])
        total_hours = round(sum(d["hours_online"] for d in days), 4)
        present = [d for d in days if d["samples"] > 0]
        avg_hr = round(
            sum(d["avg_hashrate"] for d in present) / len(present), 4) if present else 0.0
        return {
            "worker": worker,
            "from": dfrom,
            "to": dto,
            "days": days,
            "totals": {
                "hours_online": total_hours,
                "days_present": len(present),
                "avg_hashrate": avg_hr,
            },
        }

    def miners(self):
        today = self._today()
        with self._con() as con:
            rows = con.execute(
                """SELECT worker, MIN(day), MAX(day), COUNT(*)
                     FROM daily WHERE worker != '__pool__'
                 GROUP BY worker""").fetchall()
            roster = {}
            for worker, first, last, days in rows:
                roster[worker] = {
                    "worker": worker, "first_day": first, "last_day": last,
                    "days": days, "online": False,
                    "last_seen_ts": None, "last_hashrate": 0.0,
                }
            # latest raw sample per worker -> live online flag (truth, not stale rollup)
            live = con.execute(
                """SELECT s.worker, s.ts, s.hashrate, s.online
                     FROM samples s
                     JOIN (SELECT worker, MAX(ts) ts FROM samples GROUP BY worker) m
                       ON s.worker=m.worker AND s.ts=m.ts""").fetchall()
            for worker, ts, hr, online in live:
                if worker == "__pool__":
                    continue
                r = roster.setdefault(worker, {
                    "worker": worker, "first_day": None, "last_day": None,
                    "days": 0, "online": False,
                    "last_seen_ts": None, "last_hashrate": 0.0,
                })
                r["last_seen_ts"] = ts
                r["last_hashrate"] = round(hr, 4)
                r["online"] = bool(online)
        return {
            "miners": sorted(roster.values(), key=lambda r: r["worker"]),
            "generated_ts": int(time.time()),
            "today": today,
        }


class Handler(BaseHTTPRequestHandler):
    store = None  # set in main

    def log_message(self, fmt, *args):  # quiet; journald captures stderr anyway
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def _err(self, code, msg):
        self._json(code, {"error": msg})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        parts = [p for p in u.path.split("/") if p]
        qs = parse_qs(u.query)
        dfrom = valid_day(qs.get("from", [None])[0])
        dto = valid_day(qs.get("to", [None])[0])

        try:
            if parts == ["api", "miners"]:
                return self._json(200, self.store.miners())

            # /api/miner/<worker>/uptime[.csv]
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "miner" \
                    and parts[3] in ("uptime", "uptime.csv"):
                worker = parts[2]
                if not WORKER_RE.match(worker):
                    return self._err(400, "invalid worker")
                data = self.store.uptime(worker, dfrom, dto)
                if parts[3] == "uptime.csv":
                    return self._send(200, self._csv(data), "text/csv")
                return self._json(200, data)

            return self._err(404, "not found")
        except Exception as e:  # never leak a stack to the public endpoint
            return self._err(500, "internal error: %s" % type(e).__name__)

    @staticmethod
    def _csv(data):
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["# c2pool miner uptime", "worker", data["worker"]])
        w.writerow(["# range", data.get("from") or "", data.get("to") or ""])
        w.writerow(["day", "hours_online", "avg_hashrate_hs", "samples",
                    "stale_pct", "partial"])
        for d in data["days"]:
            w.writerow([d["day"], d["hours_online"], d["avg_hashrate"],
                        d["samples"], d["stale_pct"], int(d["partial"])])
        t = data["totals"]
        w.writerow(["TOTAL", t["hours_online"], t["avg_hashrate"],
                    "", "", ""])
        return buf.getvalue()


def main():
    ap = argparse.ArgumentParser(description="c2pool miner uptime API (D-MINER.2)")
    ap.add_argument("--db", default="miner_presence.db")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--interval", type=int, default=SAMPLE_INTERVAL_SECONDS,
                    help="sampler interval seconds (for live-day hour math)")
    args = ap.parse_args()
    Handler.store = Store(args.db, args.interval)
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print("miner_uptime_api serving on http://%s:%d (db=%s, ro)" %
          (args.host, args.port, args.db), flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
