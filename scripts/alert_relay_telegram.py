#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""alert_relay_telegram.py -- Telegram sidecar for the c2pool-dash alert relay (D-MINER.7).

Runs next to a c2pool-dash node started with --alert-relay-telegram. The node
appends every alert it accepts (signed + sealed by an allowlisted origin node,
e.g. a DPI-bound hotel node, carried over the sharechain p2p) to

    <state-dir>/outbox.jsonl      (one JSON object per line, 0600)

This sidecar sends each row to Telegram (sendMessage, plain text -- no
parse_mode, so origin-supplied strings are never interpreted as markup) and,
ONLY after Telegram answered HTTP 200 {"ok": true} for every configured chat,
appends {"id": ...} to

    <state-dir>/delivered.jsonl

which the node polls and turns into a signed "delivered" ack back to the
origin. Anything else (network error, 5xx, 429, ok:false) is retried with
exponential backoff (5 s -> 5 min; 429 honours retry_after) and never marked.

A row whose event is older than --max-age (default 6 h, the origin's own
give-up age) is NOT sent -- a page saying "rig OFFLINE at <two days ago>" helps
nobody. It is logged once and recorded in <state-dir>/expired.jsonl (never in
delivered.jsonl, so the node never acks it as delivered; the origin reports it
as expired_at_relay).

Secrets: the bot token comes from $TELEGRAM_BOT_TOKEN or --token-file (0600).
It is never logged: every log line passes through a redactor, and request
URLs are never logged.

stdlib only. `--selftest` runs an in-process fake Telegram server (no network).
"""

import argparse
import http.server
import io
import json
import logging
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone

LOG = logging.getLogger("alert-relay-telegram")

KIND_TEXT = {
    "offline": "OFFLINE",
    "back_online": "back ONLINE",
    "digest": "DIGEST",
    "test": "TEST",
}


class Redactor(logging.Filter):
    """Scrub the bot token (and anything after '/bot') from every record."""

    def __init__(self, secrets):
        super().__init__()
        self.secrets = [s for s in secrets if s]

    def scrub(self, text):
        for s in self.secrets:
            text = text.replace(s, "<redacted>")
        i = text.find("/bot")
        while i != -1:
            j = i + 4
            while j < len(text) and text[j] not in " /'\")\n":
                j += 1
            text = text[: i + 4] + "<redacted>" + text[j:]
            i = text.find("/bot", i + 4 + len("<redacted>"))
        return text

    def filter(self, record):
        record.msg = self.scrub(record.getMessage())
        record.args = ()
        return True


def format_text(row):
    label = (row.get("label") or "").strip() or "c2pool"
    kind = row.get("kind", "")
    worker = row.get("worker", "")
    detail = row.get("detail", "")
    ts = row.get("event_ts") or row.get("sent_ts") or 0
    when = datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if kind in ("offline", "back_online"):
        text = "[c2pool] %s: worker %s %s (%s) at %s" % (label, worker, KIND_TEXT[kind], detail, when)
    else:
        text = "[c2pool] %s: %s %s at %s" % (label, KIND_TEXT.get(kind, kind.upper()), detail, when)
    return text[:4000]


class Sidecar:
    def __init__(self, state_dir, token, chat_ids, api_base="https://api.telegram.org",
                 max_per_min=20, backoff_min=5.0, backoff_max=300.0, timeout=15.0,
                 clock=time.monotonic, max_age=6 * 3600, wall=time.time):
        self.state_dir = state_dir
        self.outbox = os.path.join(state_dir, "outbox.jsonl")
        self.delivered_path = os.path.join(state_dir, "delivered.jsonl")
        self.expired_path = os.path.join(state_dir, "expired.jsonl")
        self.max_age = max_age       # seconds; <= 0 disables the age cut
        self.wall = wall             # wall clock (event_ts is unix time)
        self.token = token
        self.chat_ids = list(chat_ids)
        self.api_base = api_base.rstrip("/")
        self.max_per_min = max_per_min
        self.backoff_min = backoff_min
        self.backoff_max = backoff_max
        self.timeout = timeout
        self.clock = clock
        self.delivered = set()
        self.expired = set()
        self.outbox_offset = 0
        self.pending = {}            # id -> row
        self.order = []              # ids in arrival order
        self.done_chats = {}         # id -> set(chat) already ok (this process)
        self.next_try = {}           # id -> clock time
        self.backoff = {}            # id -> current backoff seconds
        self.sent_window = deque()   # clock times of sendMessage calls
        self.stats = {"sent": 0, "delivered": 0, "failed": 0, "rate_limited": 0, "expired": 0}
        self.delivered = self._load_ids(self.delivered_path)
        self.expired = self._load_ids(self.expired_path)

    @staticmethod
    def _load_ids(path):
        ids = set()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(obj, dict) and isinstance(obj.get("id"), str):
                        ids.add(obj["id"])
        except FileNotFoundError:
            pass
        return ids

    def read_outbox(self):
        try:
            size = os.path.getsize(self.outbox)
        except OSError:
            return
        if size < self.outbox_offset:
            self.outbox_offset = 0
        with open(self.outbox, "rb") as fh:
            fh.seek(self.outbox_offset)
            data = fh.read()
        consumed = 0
        for raw in data.split(b"\n")[:-1]:     # a partial last line waits for the next poll
            consumed += len(raw) + 1
            try:
                row = json.loads(raw.decode("utf-8"))
            except ValueError:
                LOG.warning("skipping unparsable outbox line")
                continue
            rid = row.get("id") if isinstance(row, dict) else None
            if not isinstance(rid, str) or rid in self.delivered or rid in self.expired or rid in self.pending:
                continue
            self.pending[rid] = row
            self.order.append(rid)
        self.outbox_offset += consumed

    @staticmethod
    def _append(path, obj):
        line = json.dumps(obj) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def _mark_delivered(self, rid):
        self._append(self.delivered_path, {"id": rid, "ts": int(time.time())})
        self.delivered.add(rid)

    def _event_age(self, row):
        ts = row.get("event_ts") or row.get("sent_ts") or 0
        try:
            ts = int(ts)
        except (TypeError, ValueError):
            return None
        return self.wall() - ts if ts > 0 else None

    def _expire(self, rid, row, age):
        self._append(self.expired_path, {"id": rid, "event_ts": row.get("event_ts"), "ts": int(self.wall())})
        self.expired.add(rid)
        self.stats["expired"] += 1
        LOG.warning("not sending %s (%s %s): event is %.0fs old (> --max-age %ds); recorded in expired.jsonl",
                    rid[:16] + rid[rid.rfind(":"):], row.get("kind"), row.get("worker", ""), age, self.max_age)
        self._forget(rid)

    def _forget(self, rid):
        self.pending.pop(rid, None)
        if rid in self.order:
            self.order.remove(rid)
        self.done_chats.pop(rid, None)
        self.next_try.pop(rid, None)
        self.backoff.pop(rid, None)

    def _throttled(self, now):
        while self.sent_window and self.sent_window[0] + 60.0 <= now:
            self.sent_window.popleft()
        return len(self.sent_window) >= self.max_per_min

    def send_one(self, chat_id, text):
        """Return (ok, retry_after_seconds_or_None, description)."""
        url = "%s/bot%s/sendMessage" % (self.api_base, self.token)
        body = json.dumps({"chat_id": chat_id, "text": text, "disable_web_page_preview": True}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                payload = resp.read()
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                payload = e.read()
            except Exception:  # noqa: BLE001 - body is best effort
                payload = b""
        except (urllib.error.URLError, OSError) as e:
            return False, None, "network error: %s" % type(e).__name__
        try:
            obj = json.loads(payload.decode("utf-8") or "{}")
        except ValueError:
            obj = {}
        if status == 200 and obj.get("ok") is True:
            return True, None, "ok"
        retry_after = None
        if status == 429:
            retry_after = (obj.get("parameters") or {}).get("retry_after")
            try:
                retry_after = float(retry_after)
            except (TypeError, ValueError):
                retry_after = None
        return False, retry_after, "HTTP %d %s" % (status, str(obj.get("description", ""))[:120])

    def step(self):
        """One pass: pick up new outbox rows, send whatever is due."""
        self.read_outbox()
        for rid in list(self.order):
            if rid not in self.pending:
                continue
            now = self.clock()
            if self.next_try.get(rid, 0) > now:
                continue
            row = self.pending[rid]
            age = self._event_age(row)
            if self.max_age > 0 and age is not None and age > self.max_age:
                self._expire(rid, row, age)
                continue
            text = format_text(row)
            done = self.done_chats.setdefault(rid, set())
            failed = False
            for chat in self.chat_ids:
                if chat in done:
                    continue
                if self._throttled(self.clock()):
                    LOG.info("throttled (%d msgs/min); deferring", self.max_per_min)
                    return
                self.sent_window.append(self.clock())
                self.stats["sent"] += 1
                ok, retry_after, why = self.send_one(chat, text)
                if ok:
                    done.add(chat)
                    continue
                failed = True
                if retry_after is not None:
                    self.stats["rate_limited"] += 1
                    wait = max(1.0, retry_after)
                else:
                    self.stats["failed"] += 1
                    wait = self.backoff.get(rid, self.backoff_min)
                    self.backoff[rid] = min(self.backoff_max, wait * 2)
                self.next_try[rid] = self.clock() + wait
                LOG.warning("send failed for %s (%s); retry in %.0fs", rid[:16], why, wait)
                break
            if not failed and all(c in done for c in self.chat_ids):
                self._mark_delivered(rid)
                self.stats["delivered"] += 1
                LOG.info("delivered %s (%s %s)", rid[:16] + rid[rid.rfind(":"):], row.get("kind"), row.get("worker", ""))
                self._forget(rid)


def read_token(args):
    tok = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not tok and args.token_file:
        st = os.stat(args.token_file)
        if st.st_mode & 0o077:
            LOG.warning("token file %s is group/other accessible; chmod 600 it", args.token_file)
        with open(args.token_file, "r", encoding="utf-8") as fh:
            tok = fh.read().strip()
    return tok


def read_chat_ids(args):
    ids = list(args.chat_id or [])
    if args.chat_id_file:
        with open(args.chat_id_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    ids.append(line)
    return ids


# ── selftest ────────────────────────────────────────────────────────────────
class _FakeTelegram(http.server.BaseHTTPRequestHandler):
    script = []      # list of (status, json) consumed in order; then 200 ok
    calls = []

    def do_POST(self):  # noqa: N802 - http.server API
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n) or b"{}")
        type(self).calls.append({"path": self.path, "body": body})
        status, obj = (type(self).script.pop(0) if type(self).script else (200, {"ok": True, "result": {}}))
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # silence
        pass


def selftest():
    token = "123456:SELFTEST-SECRET-TOKEN-abcdef"
    log_buf = io.StringIO()
    handler = logging.StreamHandler(log_buf)
    handler.addFilter(Redactor([token]))
    LOG.addHandler(handler)
    LOG.setLevel(logging.DEBUG)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeTelegram)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    fails = 0

    def check(cond, msg):
        nonlocal fails
        print(("ok:   " if cond else "FAIL: ") + msg)
        if not cond:
            fails += 1

    with tempfile.TemporaryDirectory() as d:
        clock = [1000.0]
        wall = lambda: 1790000000 + 600 + (clock[0] - 1000.0)   # rows below are ~10 min old
        sc = Sidecar(d, token, ["42"], api_base=base, backoff_min=5, clock=lambda: clock[0], wall=wall)
        row = {"id": "02ab:1", "kind": "offline", "label": "hotel", "worker": "XaddrABC.rig1",
               "detail": "disconnected; down 5m", "event_ts": 1790000000}
        with open(os.path.join(d, "outbox.jsonl"), "w") as fh:
            fh.write(json.dumps(row) + "\n")
            fh.write('{"id": "partial')          # partial trailing line must be ignored
        # (a) 200 ok -> delivered exactly once
        _FakeTelegram.script = [(200, {"ok": True, "result": {}})]
        sc.step()
        check(len(_FakeTelegram.calls) == 1, "one sendMessage for one outbox row")
        call = _FakeTelegram.calls[0]
        check(call["path"] == "/bot%s/sendMessage" % token, "Bot API path shape")
        check("rig1" in call["body"]["text"] and "OFFLINE" in call["body"]["text"], "text carries worker + OFFLINE")
        check("parse_mode" not in call["body"], "plain text, no parse_mode")
        check(call["body"]["chat_id"] == "42", "chat id forwarded")
        sc.step()
        check(len(_FakeTelegram.calls) == 1, "no second send after delivery")
        with open(os.path.join(d, "delivered.jsonl")) as fh:
            dl = [json.loads(l)["id"] for l in fh if l.strip()]
        check(dl == ["02ab:1"], "delivered.jsonl holds the id once")

        # (b) 429 -> honours retry_after, not marked meanwhile
        row2 = dict(row, id="02ab:2", kind="back_online", detail="back online after 7m down")
        with open(os.path.join(d, "outbox.jsonl"), "a") as fh:
            fh.write('garbage\n')                 # completes the partial line into unparsable junk
            fh.write(json.dumps(row2) + "\n")
        _FakeTelegram.script = [(429, {"ok": False, "description": "Too Many Requests",
                                       "parameters": {"retry_after": 7}})]
        sc.step()
        check(len(_FakeTelegram.calls) == 2, "429 attempt made")
        check("02ab:2" not in sc.delivered, "429 -> not marked delivered")
        clock[0] += 5
        sc.step()
        check(len(_FakeTelegram.calls) == 2, "waits for retry_after (7 s)")
        clock[0] += 3
        sc.step()
        check(len(_FakeTelegram.calls) == 3 and "02ab:2" in sc.delivered, "delivered after retry_after")
        check("back ONLINE" in _FakeTelegram.calls[-1]["body"]["text"], "back-online text")

        # (c) 500 and ok:false -> retried with backoff, never marked early
        row3 = dict(row, id="02ab:3")
        with open(os.path.join(d, "outbox.jsonl"), "a") as fh:
            fh.write(json.dumps(row3) + "\n")
        _FakeTelegram.script = [(500, {"ok": False, "description": "boom"}),
                                (200, {"ok": False, "description": "chat not found"})]
        sc.step()
        check("02ab:3" not in sc.delivered, "500 -> not marked")
        clock[0] += 5
        sc.step()
        check("02ab:3" not in sc.delivered, "200 ok:false -> not marked")
        clock[0] += 10
        sc.step()
        check("02ab:3" in sc.delivered, "backoff (5 s, 10 s) then delivered")
        check(len(_FakeTelegram.calls) == 6, "exactly 6 HTTP calls in total")

        # (d) restart: a fresh sidecar re-reads delivered.jsonl and sends nothing
        sc2 = Sidecar(d, token, ["42"], api_base=base, clock=lambda: clock[0], wall=wall)
        sc2.step()
        check(len(_FakeTelegram.calls) == 6, "restart does not resend delivered rows")

        # (e) network error -> retried, not marked
        sc3 = Sidecar(d, token, ["42"], api_base="http://127.0.0.1:1", clock=lambda: clock[0], wall=wall)
        with open(os.path.join(d, "outbox.jsonl"), "a") as fh:
            fh.write(json.dumps(dict(row, id="02ab:4")) + "\n")
        sc3.step()
        check("02ab:4" not in sc3.delivered, "connection refused -> not marked")

        # (f) a row older than --max-age is never sent, recorded as expired, not delivered
        sc4 = Sidecar(d, token, ["42"], api_base=base, clock=lambda: clock[0], wall=wall)
        sc4.read_outbox()
        sc4.pending.clear(); sc4.order.clear()        # only the new row below matters here
        old = dict(row, id="02ab:5", event_ts=int(wall()) - 7 * 3600)
        with open(os.path.join(d, "outbox.jsonl"), "a") as fh:
            fh.write(json.dumps(old) + "\n")
        n0 = len(_FakeTelegram.calls)
        sc4.step()
        check(len(_FakeTelegram.calls) == n0, "stale row (7 h > 6 h) -> no sendMessage")
        with open(os.path.join(d, "expired.jsonl")) as fh:
            ex = [json.loads(l)["id"] for l in fh if l.strip()]
        with open(os.path.join(d, "delivered.jsonl")) as fh:
            dl = [json.loads(l)["id"] for l in fh if l.strip()]
        check(ex == ["02ab:5"] and "02ab:5" not in dl, "stale row -> expired.jsonl, never delivered.jsonl")
        sc5 = Sidecar(d, token, ["42"], api_base=base, clock=lambda: clock[0], wall=wall)
        sc5.read_outbox()
        check("02ab:5" not in sc5.pending, "restart does not pick an expired row up again")

        # (g) a row that ages out while it is being retried is dropped, not paged late
        sc6 = Sidecar(d, token, ["42"], api_base=base, backoff_min=5, clock=lambda: clock[0], wall=wall,
                      max_age=100)
        sc6.read_outbox()
        sc6.pending.clear(); sc6.order.clear()
        fresh = dict(row, id="02ab:6", event_ts=int(wall()) - 50)
        with open(os.path.join(d, "outbox.jsonl"), "a") as fh:
            fh.write(json.dumps(fresh) + "\n")
        _FakeTelegram.script = [(500, {"ok": False, "description": "boom"})]
        n0 = len(_FakeTelegram.calls)
        sc6.step()
        check(len(_FakeTelegram.calls) == n0 + 1 and "02ab:6" not in sc6.delivered, "fresh row tried, failed")
        clock[0] += 60                                  # now 110 s old, past max_age=100
        sc6.step()
        check(len(_FakeTelegram.calls) == n0 + 1 and "02ab:6" in sc6.expired, "aged out during retry -> expired, no late page")

    srv.shutdown()
    logs = log_buf.getvalue()
    check(token not in logs and "SELFTEST-SECRET" not in logs, "token never appears in log output")
    check(Redactor([token]).scrub("POST %s/bot%s/sendMessage" % (base, token)).count("<redacted>") >= 1,
          "redactor scrubs /bot<token> URLs")
    print("selftest %s (%d failure%s)" % ("PASSED" if fails == 0 else "FAILED", fails, "" if fails == 1 else "s"))
    return 0 if fails == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--state-dir", help="the node's alert_relay state dir (holds outbox.jsonl)")
    ap.add_argument("--token-file", help="file holding the bot token (else $TELEGRAM_BOT_TOKEN)")
    ap.add_argument("--chat-id", action="append", help="Telegram chat id (repeatable)")
    ap.add_argument("--chat-id-file", help="file with one chat id per line")
    ap.add_argument("--telegram-api-base", default="https://api.telegram.org",
                    help="Bot API base URL (override for a local fake endpoint in tests)")
    ap.add_argument("--poll", type=float, default=5.0, help="seconds between outbox polls")
    ap.add_argument("--max-per-min", type=int, default=20)
    ap.add_argument("--max-age", type=int, default=6 * 3600,
                    help="never send an alert whose event is older than this many seconds (0 = no limit)")
    ap.add_argument("--once", action="store_true", help="one pass, then exit")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    # urllib3/requests are not used; still, never let a library log the URL.
    if not args.state_dir:
        ap.error("--state-dir is required")
    token = read_token(args)
    for h in logging.getLogger().handlers:
        h.addFilter(Redactor([token]))
    if not token:
        LOG.error("no bot token: set TELEGRAM_BOT_TOKEN or --token-file")
        return 2
    chats = read_chat_ids(args)
    if not chats:
        LOG.error("no chat id: pass --chat-id or --chat-id-file")
        return 2
    sc = Sidecar(args.state_dir, token, chats, api_base=args.telegram_api_base,
                 max_per_min=args.max_per_min, max_age=args.max_age)
    LOG.info("alert-relay telegram sidecar: state=%s chats=%d api=%s", args.state_dir, len(chats),
             args.telegram_api_base)
    while True:
        try:
            sc.step()
        except Exception as e:  # noqa: BLE001 - keep the sidecar alive, log without the token
            LOG.error("step failed: %s", e)
        if args.once:
            return 0
        time.sleep(args.poll)


if __name__ == "__main__":
    sys.exit(main())
