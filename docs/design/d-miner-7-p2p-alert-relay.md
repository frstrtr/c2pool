# D-MINER.7 — miner-offline alerts relayed over the sharechain p2p (c2pool-dash)

Status: implemented, default OFF. Lane: DASH only (the first deployment target is a
private deployment behind restrictive egress).

## Why

An operator wants a Telegram message when one of their miners goes offline (and
when it comes back). Some c2pool nodes sit behind an ISP DPI box (TSPU class):
outbound flows to foreign hosts are latched after roughly 13–16 KB of
unclassified payload and Telegram is unreachable. Those nodes do, however, keep
an established sharechain peer socket to our public nodes.

So the DPI-bound node (the **origin**) does not talk to Telegram at all. It
sends a small signed, sealed `alert` frame over its existing sharechain peer
sockets; a node with clean connectivity (the **relay**, e.g. the public
bootstrap node) queues it, a sidecar posts it to Telegram, and the relay answers
with a signed `alertack`. Nodes in between may **forward** it.

There was no Telegram code in the tree before this change. The D-MINER.6
`v36relay` spool stub in `scripts/miner_notify_engine.py` is left untouched;
wiring it to this transport is a follow-up.

## Consensus / money safety

- Two new pool-protocol commands, `alert` and `alertack`, dash lane only
  (`src/impl/dash/messages.hpp`). No change to shares, share hashes, the
  sharechain, block templates, coinbase, PPLNS or payouts.
- Default OFF. With no `--alert-relay-*` flag, `run_node` never constructs the
  service: nothing is sent, inbound `alert`/`alertack` are ignored at the first
  branch of the handler (never a disconnect), no state dir is created, and the
  `/api/alert-relay/status` route does not exist.
- Old peers: a master c2pool peer's `MessageHandler::parse` throws
  `out_of_range` for an unknown command; `Legacy/Actual::handle_message` logs
  `Failed to parse message 'alert'` and drops it — no disconnect, no ban.
  Python p2pool skips a command it has no `message_<cmd>` type for
  (`p2pool/util/p2protocol.py`, `type_ is None → continue`). Both are exercised
  by the tests (handler-list KAT + a master-built peer in the e2e rig).
- `/p2p_stats` gains `alert` and `alertack` counters (additive, all lanes; 0 when unused).

## Roles and flags

| Flag | Role | Default |
|---|---|---|
| `--alert-relay-origin` | watch this node's stratum workers, emit alerts | off |
| `--alert-relay-to PUBHEX` (repeatable) | origin: relay key(s) to seal for (required with origin) | — |
| `--alert-relay-label STR` | origin: label shown in the message (≤ 32) | empty |
| `--alert-relay-telegram` | relay: accept alerts addressed to this node | off |
| `--alert-relay-accept PUBHEX` / `--alert-relay-accept-file F` | relay: allowlisted origin keys | empty ⇒ refuse all |
| `--alert-relay-forward` | forward alerts not addressed to this node (implied by the two roles) | off |
| `--alert-relay-key-file F` | secp256k1 key (created 0600 on first use) | `<data-dir>/<net>/alert_relay/alert.key` |
| `--alert-relay-show-key` | print this node's alert pubkey (creating the key) and exit | — |
| `--alert-relay-test` | origin: one test alert ~30 s after start | off |
| `--alert-relay-offline-after S` | down this long ⇒ OFFLINE | 300 |
| `--alert-relay-online-after S` | back this long ⇒ BACK_ONLINE | 60 |
| `--alert-relay-min-interval S` | min gap between OFFLINE alerts per worker | 600 |
| `--alert-relay-startup-grace S` | no OFFLINE right after start | 600 |
| `--alert-relay-stall-after S` | connected but no accepted share this long ⇒ down (0 = off) | 900 |
| `--alert-relay-retry-every S` | retransmit an unacked alert | 60 |
| `--alert-relay-retry-max N` | total transmissions before "undelivered" | 60 |

## Presence detection (origin)

Every 5 s the node samples the same per-session stratum registry that feeds
`/local_stats` (`DASHWorkSource::get_stratum_workers()`), keyed `ADDRESS.worker`.
A worker is **up** while at least one session maps to its key and (if the stall
check is on) it produced live evidence — a new session or an advancing accepted
counter — within `stall-after`. Hashrate is not used as evidence: it is a 1000 s
sliding average that keeps a dead rig "alive" for ~17 minutes.

- OFFLINE fires after `offline-after` continuous seconds down, never inside the
  startup grace, and at most once per `min-interval` per worker.
- BACK_ONLINE fires only after an emitted OFFLINE, once the worker has been up
  for `online-after`.
- A worker never seen up never alerts. Known workers (and whether an OFFLINE is
  outstanding) persist in `state.json`, so a restart neither forgets a rig that
  never reconnects nor re-pages one already reported.
- Global cap: 30 events per rolling hour; the first refused event produces one
  digest message and refused events stay pending (they fire when the window frees).

## Wire format

`alert`: `u32 version(=1) | u8 hops_left | u32 timestamp | u64 nonce |
var origin_pubkey(33) | var to_key_id(8) | var body(sealed, ≤ 400) | var signature(DER ≤ 72)`
— about 300 bytes on the wire.

`alertack`: `u32 version | var origin_pubkey(33) | u64 nonce | u8 status |
var relay_pubkey(33) | var signature` — status 1 delivered (Telegram ok:true),
2 refused (origin not allowlisted), 3 refused (stale timestamp / undecryptable /
malformed body), 4 queued at the relay (sidecar has not delivered yet), 5 expired
at the relay (the sidecar will not page it: too old).

Body plaintext: `kind(1: offline, 2: back_online, 3: digest, 4: test) |
event_ts u32 | label | worker | detail` (length-prefixed, clipped to 32/64/128
bytes). The strings are UTF-8: the origin replaces malformed bytes with `?` and
clips on a code-point boundary (Cyrillic worker names and labels are common),
and the relay refuses a body whose strings are not well-formed UTF-8
(status 3; such a frame is never cached in the seen set). Every JSON dump on
the node (outbox row, state, ledger, status) also uses nlohmann's `replace`
error handler as a backstop, so a malformed byte can never throw on a hot path.

## Security model

- **Authenticity:** each alert is ECDSA-signed (libsecp256k1, RFC 6979 nonces) by
  the origin's own alert key over
  `SHA256d("c2pool-alert-v1" | version | ts | nonce | origin_pubkey | to_key_id | body)`.
  `hops_left` is outside the signature (forwarders decrement it) and range-checked.
  The relay delivers only alerts from allowlisted origin keys.
- **Confidentiality:** the body is sealed for exactly one relay:
  `shared = SHA256(compressed(relay_pub · origin_sec))`, a fresh 16-byte random
  nonce keys a counter-mode SHA256 stream and an encrypt-then-MAC HMAC-SHA256
  tag (the `share_messages.hpp` primitives, with a domain-separation label).
  Forwarders see ciphertext; worker names and payout addresses do not leak to
  the mesh.
- **Acks** are signed by the relay key. An origin accepts an ack only from the
  relay it addressed, and a forwarder caches/forwards only a verified ack whose
  key id matches the alert, so an intermediate cannot silence retransmits or
  fake a delivery.
- **Replay:** ±900 s timestamp window, a node-level seen set, and the relay
  persists the ids it accepted, so a restart never pages twice for one frame.
- **DoS:** per-peer windows (30 alerts + 30 acks per minute), shape checks
  before any crypto, signatures verified only for first-seen frames (a forged
  frame never enters the seen set), bounded seen set (4096, FIFO), bounded
  origin queue (1000, oldest dropped and recorded), bounded relay outbox (16 MiB).
  Anyone can mint keys and sign valid junk, and forwarders pass on anything with
  a valid signature, so frames that claim a key the node already trusts get a
  separate per-peer window (120/min): on a relay, alerts from allowlisted
  origins; on an origin, acks for itself from a configured relay. Junk under
  fresh keys fills only the shared window. A peer that forges a trusted key
  uses up the trusted window of its own link only, because forwarders drop bad
  signatures before forwarding. The "not allowlisted" warning uses one global
  hourly throttle, with the rest counted in `refused_log_suppressed`. It is not
  a per-key table, which would grow without bound on a public relay.
- **Randomness:** `getrandom(2)` with a `/dev/urandom` fallback; no seeded PRNG.
- **Keys:** created with `O_EXCL`, mode 0600; a group/other-readable key file is
  flagged; the secret is never printed or logged. The bot token lives only with
  the sidecar (env or 0600 file) and is redacted from every log line.

## Delivery semantics

- The origin retransmits the same signed frame every `retry-every` seconds until
  acked. A DPI-latched flow errors out within ~30 s (TCP_USER_TIMEOUT) and is
  redialled; the next retransmit rides the fresh flow.
- Before a frame would leave the relay's replay window it is re-issued with a
  fresh timestamp and nonce, so an alert survives a long outage (bounded by
  `retry-max` and a 6 h maximum event age). If the relay had received the earlier
  frame but every ack was lost, this can page twice — a duplicate page is
  preferred to a lost one.
- Forwarders dedupe by (origin key, nonce). A duplicate is re-forwarded at most
  every 20 s (so a retransmit can cross a hop whose earlier forward was lost), and
  a cached ack is sent straight back (a lost ack is repaired without reaching the
  relay again).
- Pending origin events (with their exact signed frame) persist in `state.json`:
  an origin restart re-sends the same nonce, which the relay dedupes.
- A `queued_at_relay` event is re-probed with the same frame every 600 s. The
  relay answers an id it has accepted with that id's current status, at any
  age, including outside the replay window, because an accepted id can never be
  appended twice. A forwarder that holds only the cached "queued" ack answers
  and also passes the frame on. So a lost "delivered" ack is recovered, for
  example one broadcast after a relay restart emptied its seen set. The relay
  keeps final statuses for 8 h, longer than the origin's 6 h maximum event age.
  If an event is still unconfirmed at the maximum age, the ledger records
  `expired_at_relay`. If the relay no longer knows the id (lost or pruned
  state), it records `lost_at_relay`. Neither case is silent.
- A forwarder also passes on a validly signed frame that is outside the replay
  window (hops permitting), exactly like a fresh one: it may be a re-probe, which
  outlives the window, and only the relay can judge it (an accepted id is
  answered at any age; an unknown one is refused, never paged). The frame enters
  the forwarder's seen set, so the relay's answer is routed back and repeats are
  throttled to one re-forward per 20 s. The frame is charged to the sender's
  per-peer window as usual. This is what recovers a lost "delivered" ack across
  a forwarder that restarted, and so lost its seen set, between two re-probes.
- A final refusal (status 2, 3 or 5) ends an event only when its nonce is the one
  the origin is currently sending. A late refusal of a superseded nonce (for
  example, the first frame reached the relay stale while its re-issue is still in
  flight) is counted in `outbox.stale_refusal` and ignored. "delivered" and
  "queued" are honoured for any nonce of the event.
- The origin ledger (`ledger.jsonl`) records every final state: `delivered`
  (relay-signed "Telegram said ok"), `queued_at_relay` (relay holds it, sidecar not
  done), `expired_at_relay`, `lost_at_relay`, `refused_*`, `undelivered`,
  `dropped_cap`. Nothing is recorded as delivered on a guess.
- The origin and forwarders broadcast to every sharechain peer, because nothing
  on the wire says a peer understands `alert`. A master-built peer logs one
  WARNING `Failed to parse message 'alert'` per frame it gets, then drops the
  frame and stays connected. While the relay is unreachable, that is one frame
  per pending event per `retry-every` (60 s) from the origin, plus at most one
  re-forward per 20 s from each forwarder. This is log noise only. Point the
  origin at the relay with `--connect` to keep it off unrelated fleet nodes.

## Disk I/O and the node IO thread

The node IO thread also runs the StratumServer and the sharechain p2p, so the
alert service does no `write`/`fsync`/`rename` there. All durable writes
(`state.json`, `outbox.jsonl`, `ledger.jsonl`) go to one writer thread
(`src/impl/dash/alert_io.hpp`). Jobs run in order, and a state save that has
not started yet is replaced by a newer one (coalesced). Results come back on
the IO thread at the top of every handler and tick. There are no callbacks
across threads and no posts into the io_context.

- An idle node writes nothing. An origin that tracks workers refreshes their
  `last_seen` every 300 s. One event costs one state write. One accepted alert
  on the relay costs one job: the outbox row, then the state that records it.
- The relay sends the "queued" ack only after the outbox row is on disk.
- Nonces are reserved in blocks of 65536. A restart resumes above the persisted
  reservation, so issuing a nonce needs no write. The next block is reserved
  asynchronously when half of the current one is used.
- The only blocking write is the startup `init()`, before any peer or miner is
  served.
- The writer queue is bounded (256 jobs). Accepting an alert is the only job
  that inbound traffic can create at will. When the queue is full (the disk
  stalled under a burst), the relay answers "not now": it sends no ack, forgets
  the id, counts it in `relay.deferred_io` / `io.deferred`, and the origin's
  retransmit is processed afresh later. The node's own bounded work (state
  saves, which coalesce, and at most one ledger row per event) is never
  refused. A state save folds into the queued job whose trailing op writes the
  same file, including the state write that ends an "append the outbox row,
  then the state" job.
- The 5 s tick is wrapped (`run_tick`): an exception from sampling or from the
  tick is logged, counted in `tick.errors` (with `tick.last_error`) and the
  timer re-arms. `core::Timer` does not re-arm after a throwing handler, so an
  unguarded throw would stop the alert timer without a trace.

## Relay side: node ↔ Telegram sidecar

The node never speaks HTTPS (there is no TLS client in the node). It appends
accepted alerts to `<state>/outbox.jsonl` (0600).
`scripts/alert_relay_telegram.py` sends each row with `sendMessage` (plain text,
no `parse_mode`, so origin-supplied strings are never markup) and, only after
HTTP 200 `{"ok": true}` for every chat, appends `{"id": ...}` to
`<state>/delivered.jsonl`; the node polls that file and sends the status-1 ack.
Retries: 5 s → 5 min exponential backoff, 429 `retry_after` honoured, 20
messages/min throttle. The sidecar does not send a row whose event is older
than `--max-age` (default 6 h, the origin's own limit), because a page saying
"OFFLINE at <two days ago>" helps nobody. It logs the row once and records it
in `<state>/expired.jsonl`. It never writes that row to `delivered.jsonl`. The
node polls `expired.jsonl` as well and answers the origin at once with a signed
status-5 ("expired") ack, so the origin records `expired_at_relay` immediately
instead of re-probing until its own maximum age. The relay keeps that status
and answers later re-probes with it.

The handoff is file-based rather than an HTTP endpoint: it is loopback by
construction (filesystem permissions), durable across restarts of either
process, and needs no new write route on a web server that is public on the
bootstrap node.

Example message: `[c2pool] farm-1: worker XaddrABC.rig1 OFFLINE (disconnected; down 5m) at 2026-09-27 12:00:00 UTC`

## Telegram group

Alerts go to ONE designated Telegram group (or channel). The destination is
configuration only: `--chat-id <id>` or `--chat-id-file <file>` on the sidecar
(`TELEGRAM_CHAT_ID` in the systemd env file). Nothing is hard-coded, there is no
default, and the sidecar refuses to start without an id. Group ids are
negative: a supergroup looks like `-1001234567890`, a basic group like
`-987654321`. A public channel can be given as `@channelname`. A positive id is
a private chat with one user and is refused unless `--allow-direct-chat` is
passed explicitly. Numeric ids are sent to the Bot API as JSON integers,
exactly as configured, and `@channelname` as a string. Both are forms that
`sendMessage` accepts for `chat_id`.

Setting it up:

1. Create the bot: in Telegram, talk to `@BotFather`, send `/newbot`, and keep
   the token it prints. Put it only in the 0600 env file or a 0600
   `--token-file`, never on a command line.
2. Create the alert group (or pick an existing one) and add the bot as a member:
   group → Add members → search the bot's `@username`. Posting needs no admin
   rights. In a channel the bot must be an administrator with "Post messages".
3. Get the group id. In the group, send `/start@<bot_username>` (a command
   addressed to the bot reaches it even with privacy mode on). Then, on a
   trusted machine:

       read -rs TOKEN   # paste the token; it stays out of the shell history
       curl -s "https://api.telegram.org/bot${TOKEN}/getUpdates" | python3 -m json.tool | grep -A3 '"chat"'

   The `"id"` under `"chat"`, with `"type": "group"` or `"supergroup"`, is the
   group id, a negative number. Take the `-100...` form when the type is
   `supergroup`. If `getUpdates` returns nothing, send the command again, and
   make sure no webhook is set for the bot (`getWebhookInfo`).
4. Configure it: set `TELEGRAM_CHAT_ID=-100...` in
   `~/.config/c2pool/alert-relay.env` (or put the id in a file for
   `--chat-id-file`; `#` comments are allowed) and restart the sidecar. The
   startup log line reads `chats=1`. A `--alert-relay-test` alert from the
   origin should then show up in the group.
5. If a basic group is later upgraded to a supergroup, its id changes. Telegram
   then answers `sendMessage` with `migrate_to_chat_id`. The sidecar logs the
   new id as an error and keeps retrying, but never switches destination on its
   own. Update the configuration and restart it.

## Status

`GET /api/alert-relay/status` (present only when a role is armed; no secrets):
roles, this node's pubkey, relay key ids, detector state (origin), outbox
counters (pending / awaiting_ack / queued_at_relay / delivered / undelivered /
refused / dropped / expired_at_relay / lost_at_relay / retransmits / reprobes /
reissued), relay counters (accepted / refused / duplicates / forwarded /
pending_sidecar / delivered_telegram / expired_sidecar / deferred_io /
stale_forwarded / outbox_bytes), writer counters (backlog / jobs / coalesced /
deferred / max_jobs / errors), tick counters (errors / last_error), and p2p
counters. The origin's outbox block also carries `stale_refusal`.

## Runbook

1. On the relay (bootstrap) node: `c2pool-dash <usual flags> --alert-relay-show-key`
   prints its alert pubkey `R`. On the origin node (the one behind restrictive
   egress): same command prints `H`.
2. Relay: add `--alert-relay-telegram --alert-relay-accept H` and restart. Install
   the sidecar: copy `deploy/systemd/c2pool-alert-relay.env.example` to
   `~/.config/c2pool/alert-relay.env` (chmod 600), fill in the token and the
   designated group id (see "Telegram group"),
   copy `c2pool-alert-relay-telegram.service` to `~/.config/systemd/user/`,
   `systemctl --user enable --now c2pool-alert-relay-telegram`.
3. Origin: add `--alert-relay-origin --alert-relay-to R --alert-relay-label farm-1`
   (optionally `--alert-relay-test` once) and restart. It must already peer with the
   relay (directly or through at most two forwarders).
4. Verify: `curl -s 127.0.0.1:<web>/api/alert-relay/status` on both; the test alert
   shows `outbox.delivered: 1` on the origin node and one message in the group.

## Tests

- `test/test_dash_alert_relay.cpp` (target `test_dash_alert_relay`): wire codec
  round-trip through `dash::Handler`, signatures, ECDH seal/open, body codec,
  shape checks, allowlist, replay window, duplicate + restart safety, forged
  frames, per-peer rate limit, forwarding / hops / no echo, end-to-end queued →
  delivered across a forwarder, fake acks, lossy link + lost ack repair,
  retry-max / re-issue, nonce persistence, pending persistence, master handler
  list tolerance, detector rules (threshold, dwell, grace, restore, never-seen,
  flaps, stall, hourly cap, real outage length after a restart), bounded memory,
  key file, status contents. Also: global refused-log throttle, seen-set erase
  that leaves no ghost FIFO slot, outbox write failure deferred and recovered,
  idle ticks write nothing, a stalled disk never blocks a handler or tick,
  re-probe recovering a lost delivered ack (through a forwarder, and after a
  relay restart outside the window), `expired_at_relay` / `lost_at_relay`, and
  junk from fresh keys unable to starve an allowlisted origin. Also: a late
  refusal of a superseded nonce leaving the event pending; UTF-8 clip / sanitize
  / validate, a Cyrillic worker name longer than the clip and a Cyrillic label
  delivered exactly once, malformed miner-supplied bytes never breaking a dump,
  an invalid-UTF-8 body refused without entering the seen set; a throwing tick
  caught and counted while later ticks run (including a real `core::Timer`,
  which stops re-arming on an unguarded throw); a stale re-probe crossing a
  restarted forwarder to recover a lost delivered ack; the writer queue cap and
  trailing-Replace coalescing, and the relay deferring alerts when the queue is
  full; the sidecar's `expired.jsonl` acked "expired" at once.
- `scripts/alert_relay_telegram.py --selftest`: fake in-process Bot API (200,
  429 retry_after, 500, ok:false, connection refused, restart, token redaction,
  `--max-age` for new rows and for rows that age out while being retried, the
  `expired.jsonl` contract the node reads, and the destination group: a negative
  `-100...` id is carried unchanged as a JSON integer, and the CLI refuses to
  start with no id or with a private-chat id).
- `scripts/alert_relay_e2e.sh`: two nodes + fake Telegram + stratum simulator on
  loopback with a private network id, plus a master-built peer and a flag-off
  parity phase.

## Follow-ups (not in this change)

- On master, a dash node never re-dials a `--connect`/`--addnode` peer whose
  dial was refused: `dash::NodeImpl` has no `connect_failed()` override, so the
  address stays in `m_pending_outbound`. For an origin behind restrictive
  egress, a relay outage at reconnect time cuts the sharechain link, and alert
  delivery with it, until a restart. That fix changes behaviour with every alert
  flag off, so it needs its own PR, and it blocks the first deployment.
- `scripts/miner_notify_engine.py` `v36relay` channel → hand off to the origin
  node (keeping its RAISE-on-failure contract).
- Other lanes (LTC/BTC/DGB/BCH) once the dash lane has soaked.
- Outbox/delivered file compaction on the relay (today bounded at 16 MiB).
