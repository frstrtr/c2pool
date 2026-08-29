# D-MINER.5 — Miner Notification Engine (design)

Status: DESIGN (pre-implementation). Owner: dashboard-steward.
Reframed 2026-06-24 (operator): NOT Telegram-only. Must be robust,
transport-agnostic, and geo-resilient (Telegram is geo-blocked in many
miner locations, so a TG-only bot is structurally insufficient).

## Goal
Notify a pool miner about events on THEIR worker(s): offline > N min,
back-online, hashrate-drop, daily-summary. Per-worker routing. Block/payout
events are a stretch. Universal: serves any miner on any coin/stratum worker,
keyed by the same per-worker identity D-MINER.1/.2/.3 already use.

## Why transport-agnostic
A single channel (Telegram) fails closed for geo-blocked miners. The engine
must treat delivery as pluggable and pick whatever transport can actually
reach a given miner. Telegram becomes ONE optional channel, never the spine.

## Architecture (three seams)

1. Event source (already exists): miner_presence.db rollups (D-MINER.1) +
   live /local_stats miner_hash_rates. An evaluator diffs successive samples
   per worker -> emits typed events {worker, kind, ts, detail}.

2. Notification core (NEW, transport-agnostic): takes typed events, applies
   per-worker subscription + throttle/dedupe + quiet-hours, produces an
   abstract Message {worker, kind, body, severity}. NO transport knowledge.

3. Transport adapters (pluggable): each implements deliver(Message, route).
   Candidates, in resilience order:
   - email: works everywhere; AgenticMail relay already on this VM.
   - V36 P2P MESSAGING RELAY (explore): route the alert through the pool
     node mesh; each node forwards via whatever transport it can reach the
     miner with (local/email/other). Leverages share-peer connectivity that
     is, by definition, reachable from the miner's own node.
   - Telegram: optional, release-gated on operator BotFather token.

## V36 P2P relay note (cross-steward)
Using the V36 messaging layer as a notification relay is a CONSENSUS/transport
concern, not a web-layer change. This doc proposes the seam; the V36/transport
stewards own whether the P2P message type carries operator-alert payloads and
the addressing model. Web layer owns only the event source + notification core
+ the email adapter.

## Routing / subscription
Per-worker subscription record {worker, channels[], quiet_hours, thresholds}.
TOFU public /subscribe (D-MINER.4) populates it. Until then: operator-seeded.

## Throttle / honesty
- Dedupe identical events within a window; coalesce flapping into one digest.
- Never fabricate "online": online == observed hashrate>0, same source of
  truth as the dashboard. An undelivered alert is logged as undelivered,
  never silently dropped (charter: the system must not lie about delivery).

## Phasing
P1 event evaluator + notification core + email adapter (shippable solo, web-owned).
P2 V36 P2P relay adapter (cross-steward with transport/consensus stewards).
P3 Telegram adapter (release-gated on operator token).
