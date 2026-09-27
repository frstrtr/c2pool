# D-MINER.7 — miner-offline alerts relayed over the sharechain p2p (c2pool-dash)

Status: implemented, default OFF. Lane: DASH only (the hotel deployment target).

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
2 refused (origin not allowlisted), 3 refused (stale timestamp / undecryptable),
4 queued at the relay (sidecar has not delivered yet).

Body plaintext: `kind(1: offline, 2: back_online, 3: digest, 4: test) |
event_ts u32 | label | worker | detail` (length-prefixed, clipped to 32/64/128).

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
- The origin ledger (`ledger.jsonl`) records every final state: `delivered`
  (relay-signed "Telegram said ok"), `queued_at_relay` (relay holds it, sidecar not
  done), `refused_*`, `undelivered`, `dropped_cap`. Nothing is recorded as
  delivered on a guess.

## Relay side: node ↔ Telegram sidecar

The node never speaks HTTPS (there is no TLS client in the node). It appends
accepted alerts to `<state>/outbox.jsonl` (0600).
`scripts/alert_relay_telegram.py` sends each row with `sendMessage` (plain text,
no `parse_mode`, so origin-supplied strings are never markup) and, only after
HTTP 200 `{"ok": true}` for every chat, appends `{"id": ...}` to
`<state>/delivered.jsonl`; the node polls that file and sends the status-1 ack.
Retries: 5 s → 5 min exponential backoff, 429 `retry_after` honoured, 20
messages/min throttle.

The handoff is file-based rather than an HTTP endpoint: it is loopback by
construction (filesystem permissions), durable across restarts of either
process, and needs no new write route on a web server that is public on the
bootstrap node.

Example message: `[c2pool] hotel: worker XaddrABC.rig1 OFFLINE (disconnected; down 5m) at 2026-09-27 12:00:00 UTC`

## Status

`GET /api/alert-relay/status` (present only when a role is armed; no secrets):
roles, this node's pubkey, relay key ids, detector state (origin), outbox
counters (pending / awaiting_ack / queued_at_relay / delivered / undelivered /
refused / dropped / retransmits / reissued), relay counters (accepted / refused /
duplicates / forwarded / pending_sidecar / delivered_telegram) and p2p counters.

## Runbook

1. On the relay (bootstrap) node: `c2pool-dash <usual flags> --alert-relay-show-key`
   prints its alert pubkey `R`. On the hotel node: same command prints `H`.
2. Relay: add `--alert-relay-telegram --alert-relay-accept H` and restart. Install
   the sidecar: copy `deploy/systemd/c2pool-alert-relay.env.example` to
   `~/.config/c2pool/alert-relay.env` (chmod 600), fill in the token and chat id,
   copy `c2pool-alert-relay-telegram.service` to `~/.config/systemd/user/`,
   `systemctl --user enable --now c2pool-alert-relay-telegram`.
3. Hotel: add `--alert-relay-origin --alert-relay-to R --alert-relay-label hotel`
   (optionally `--alert-relay-test` once) and restart. It must already peer with the
   relay (directly or through at most two forwarders).
4. Verify: `curl -s 127.0.0.1:<web>/api/alert-relay/status` on both; the test alert
   shows `outbox.delivered: 1` on the hotel node and one Telegram message.

## Tests

- `test/test_dash_alert_relay.cpp` (target `test_dash_alert_relay`): wire codec
  round-trip through `dash::Handler`, signatures, ECDH seal/open, body codec,
  shape checks, allowlist, replay window, duplicate + restart safety, forged
  frames, per-peer rate limit, forwarding / hops / no echo, end-to-end queued →
  delivered across a forwarder, fake acks, lossy link + lost ack repair,
  retry-max / re-issue, nonce persistence, pending persistence, master handler
  list tolerance, detector rules (threshold, dwell, grace, restore, never-seen,
  flaps, stall, hourly cap), bounded memory, key file, status contents.
- `scripts/alert_relay_telegram.py --selftest`: fake in-process Bot API (200,
  429 retry_after, 500, ok:false, connection refused, restart, token redaction).
- `scripts/alert_relay_e2e.sh`: two nodes + fake Telegram + stratum simulator on
  loopback with a private network id, plus a master-built peer and a flag-off
  parity phase.

## Follow-ups (not in this change)

- `scripts/miner_notify_engine.py` `v36relay` channel → hand off to the origin
  node (keeping its RAISE-on-failure contract).
- Other lanes (LTC/BTC/DGB/BCH) once the dash lane has soaked.
- Outbox/delivered file compaction on the relay (today bounded at 16 MiB).
