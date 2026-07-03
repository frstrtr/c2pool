# D-MINER.6 — V36 P2P Relay Notification Adapter (design)

Status: DESIGN (pre-implementation). Owner: dashboard-steward (web half).
Builds on D-MINER.5 (notify engine, shipped) — see d-miner-5-notify-engine.md.
Realizes D-MINER.5 phasing item "P2 V36 P2P relay adapter (cross-steward)".

## Why
Email (D-MINER.5 P1) reaches any miner with a mailbox; Telegram is geo-blocked
in many miner locations. The V36 P2P messaging layer offers a THIRD path that
is, by construction, reachable: the miner's alert rides the pool's own
share-peer mesh, and each hop forwards via whatever transport can reach the
next node — including the miner's own node, which the miner already connects to.
This is the geo-resilient spine the operator asked for (2026-06-24 reframe).

## Boundary (who owns what)
This is a two-steward seam. To keep it shippable in independent halves:

- WEB layer (dashboard-steward) owns: the transport-adapter CONTRACT the
  notify engine already exposes — deliver(channel, subject, body, route)->bool
  (scripts/miner_notify_engine.py:234) — plus the new channel name, the route
  format, and the delivery-honesty invariant. No consensus code.
- V36 / transport / consensus stewards own: whether the P2P message type
  carries an operator-alert payload, the addressing/forwarding model across
  the mesh, and the security/authorization of relayed payloads. Consensus-
  adjacent; NOT a web change.

This doc fixes the web half so the P2P half is a drop-in against a frozen
contract, not a negotiation.

## Web-owned contract
1. Channel name: "v36relay". Subscribers opt in via sub["channels"] exactly
   as they do for "email"/"logonly"; no new dispatch shape.
2. Route format: opaque string owned by the P2P steward's addressing model
   (candidate: a miner-node identity / share-peer handle). The notify core
   treats route as a passthrough token — it never parses it. This lets the
   addressing model evolve without a web change.
3. deliver("v36relay", subject, body, route) MUST raise on any failure to
   hand off to the P2P layer, exactly like deliver_email. The engine records
   RAISED -> "undelivered"; RETURNED-True -> "sent". Handoff-to-mesh counts
   as sent ONLY if the local enqueue is durably accepted (see honesty below).

## Delivery honesty (charter)
The founding charter forbids the system lying about state — here, about
delivery. Relay adds hops the engine cannot observe, so:
- "sent" means the message was durably ACCEPTED by the local V36 relay
  enqueue — NOT that it reached the miner. It is a handoff receipt, not a
  read receipt.
- If the P2P layer later exposes per-message ack, add a "delivered" status
  distinct from "sent"; until then the notifications row stays "sent" and
  MUST NOT be upgraded to imply end-to-end receipt.
- No fabricated success: a relay with no reachable next hop RAISES ->
  "undelivered", never a silent True.

## Phasing
P1 (web, solo): freeze this contract; add a "v36relay" branch to make_transport
   that enqueues to a local relay-handoff stub and raises when the stub is
   absent (fails closed, honest). KAT: unknown-route raises -> undelivered.
P2 (cross-steward): P2P steward implements the real enqueue + addressing.
P3: per-message ack -> "delivered" status, if/when the mesh exposes it.
