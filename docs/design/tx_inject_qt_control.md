# QT tx-inject control plane — design + read-only status slice (#157)

Status: DESIGN + read-only slice. The two gated slices below are **design only**;
they change the money path and/or arm a feature, so they are **not implemented**
in this PR and require an explicit operator tap on wake. This PR ships slice (0)
only — a read-only status surface.

## Update (2026-09) — what has since landed on master

The sequencing below has largely happened; this section is the authoritative
current state, the design that follows is retained for rationale:

- **M3 (#1606) is MERGED and INLINE.** The rate limiter + bounded-work sandbox
  live directly inside `NodeCoinState::submit_inject` (`inject_rate_limiter.hpp`
  + `inject_sandbox.hpp`). submit_inject now carries an `InjectOrigin{Local,Peer}`
  parameter that selects a SPLIT rate budget: a peer flood exhausts only the peer
  budget and can never starve the operator's own local inject.
- **Slice A (#1616) is MERGED.** `POST /api/config/apply` is the live, fail-closed,
  money-gated write path (loopback control token + two-phase money nonce bound to
  the exact diff + M0 tripwire). Dormant until an operator registers a token.
- **Slice B is RE-LANDED onto master (this PR)**, M3-origin-correct:
  - `embedded.tx_inject` is reclassified `RESTART -> MONEY_LIVE`, so arming it
    runs the full two-phase money-nonce gate through the SAME apply path.
  - The runtime arm setter flips BOTH the M1 submit gate AND the p2p tx_inject
    sink together; the peer sink installs with `InjectOrigin::Peer` (M3 split
    preserved); disarm clears the sink.
  - `POST /api/tx-inject/submit` (loopback-only) hands a raw consensus tx to
    `submit_inject` with `InjectOrigin::Local` (the operator's own reserved
    budget). It is installed through `thread_safe_wrap`, so it runs on the node
    io_context strand, never the web thread; a wedged strand degrades to a 5xx.
  - **`control_token` is now REQUIRED on the submit body** (checked via the same
    `check_control_token()`; 403 on miss), so once armed no other local process
    can spend the operator's inject rate-budget. `raw_tx` must be even-length hex.
  - The apply path now **REFUSES RESTART-class keys** by a named cause
    (`restart_unsupported`) until a restart-aware applier exists — closing a
    mirror-vs-runtime hole (a RESTART key had been partitioned but never consulted).


## Background — what exists today

Node-side tx-inject runtime (DASH only, flag `--embedded-tx-inject`, **default
OFF** everywhere):
- **M1** (#1499): flag + `NodeCoinState::submit_inject` gate (cheapest-checks-first:
  feature-enabled -> DoS caps via `TxInjectPool` -> mempool admission). Registered
  in `src/core/param_catalog.inc` (`embedded.tx_inject`, `embedded.tx_inject_hex`).
- **M2** (#1505): p2p `tx_inject` message subtype + first-see fan-out; wire
  counters live in `core::obs::p2p_stats()` (`messages["tx_inject"].{in,out}`) and
  are already served by the public `/p2p_stats` endpoint.
- **M3** (draft #1606): `inject_rate_limiter.hpp` + `inject_sandbox.hpp` with
  named counters (`inject-rate-limited-count/-bytes`, `peer-rate-limited-*`,
  `inject-sandbox-*`). NOT on master; slots into the status endpoint when merged.

QT control-plane:
- **M0** (#1423): declarative param catalog + settings-file loader + money gate +
  tripwire.
- **M1** (#1429): read-only `GET /api/config` + `GET /api/config/schema`
  (loopback-gated). `POST /api/config/apply` is **INERT** — an unconditional 503
  (`{"armed":false,...}`), pinned by a KAT. The `--embedded-tx-inject` flag is
  therefore already VISIBLE in `/api/config/schema`; apply/write is dormant and
  money-gated.

The write path (`config_endpoint.hpp` apply-batch validator) is present but
DORMANT: not wired to any route, guarded by the 503 KAT.

## Slice 0 (THIS PR — safe, non-money-path, read-only)

`GET /api/tx-inject-status` (loopback-only, same posture as `/api/config`). Pure
reader over `core::obs::inject_status()` (a new process-global snapshot the armed
`NodeCoinState` mirrors into) plus the M2 `tx_inject` wire counters from
`core::obs::p2p_stats()`. Response:

```json
{
  "wired": false,            // updated_at != 0 (lane has published at least once)
  "enabled": false,          // --embedded-tx-inject armed?
  "updated_at": 0,
  "pool": { "entries": 0, "bytes": 0,
            "max_entries": 1024, "max_total_bytes": 400000, "max_tx_bytes": 100000 },
  "wire": { "tx_inject_in": 0, "tx_inject_out": 0 },   // M2
  "rate_limit": null,        // M3 (#1606) — null until wired
  "sandbox": null            // M3 (#1606) — null until wired
}
```

Money-safety: adds a read-only mirror + endpoint. It never arms the flag,
submits a tx, or writes config. Same lock-free obs-global pattern as `/p2p_stats`
(one pool node per process => process-global == per-node scope, no node->web
plumbing). This is the panel's "SHOW tx-inject state" surface.

## Slice A (DESIGN ONLY — control-plane apply, dormant -> live)

Goal: turn the DORMANT `POST /api/config/apply` into a live write path for
**non-money** params, with money-path params held behind an explicit confirm +
tripwire.

Shape:
1. **Control token.** Apply requires a per-process control token (generated at
   launch, surfaced only on loopback, e.g. printed to the operator console or a
   0600 file). No token => keep the current 503. This is what the M1 comment
   ("until the control-token lands with the write path") already anticipates.
2. **Two-tier param classification** (already in the M0 catalog's money gate):
   - *non-money* params: apply after schema validation (type/range/enum) + token.
   - *money-path* params (fee/address/donation/reward, and **`--embedded-tx-inject`
     itself** — it changes what can land in a block): require a **two-phase money
     nonce** (server issues a nonce bound to the exact requested diff; client
     echoes it in a confirm call) AND must pass the server-side `AddressValidator`
     / reward-safe checks. The **tripwire** (M0) fires on any attempt to write a
     money-path key without a valid confirmed nonce.
3. **Flip the 503 KAT** deliberately (reviewed change): the endpoint stays 503
   until the token+nonce path is armed; arming is the reviewed diff, never a
   silent default.

Money-safety gates: control token (loopback) + schema validation for every write;
**money-path writes additionally require the two-phase nonce + AddressValidator +
tripwire**. Reward path is untouched for non-money writes by construction (they
cannot name a money key).

Owed: operator tap (money path), independent review, and a KAT that pins "money
key without confirmed nonce => tripwire + refuse".

## Slice B (DESIGN ONLY — QT tx-inject control: arm/disarm + submit-raw-tx)

Goal: from the panel, (i) arm/disarm `--embedded-tx-inject` and (ii) submit a raw
tx for injection.

Shape:
1. **Arm/disarm** = a money-path config write of `embedded.tx_inject` through
   Slice A (two-phase nonce + tripwire + token). Arming changes what can land in
   a block, so it is money-path by definition. Runtime effect calls
   `NodeCoinState::set_tx_inject_enabled()` on the ARMED instance
   (`main_dash.cpp`'s standalone `node_coin_state`, NOT `NodeImpl::m_coin_state`
   — see node.hpp: a call on the wrong instance fails closed forever). The status
   mirror (Slice 0) already reflects the flip so the panel confirms visually.
2. **Submit raw tx** = `POST /api/tx-inject/submit` (loopback + control token),
   payload = raw tx hex. Server path routes through the SAME M1 gate
   (`submit_inject`: type-0 only, DoS caps, mempool admission with the consensus
   script check) — no bypass. Refusals return the named cause (DEF3: no silent
   drops). REWARD-SAFE by the M1 invariant (an inject is an ordinary body tx; a
   0-fee inject adds 0 to `total_fees`, coinbase/subsidy/PPLNS/payee byte-
   unchanged) — but a submitted tx spends real funds, so the submit endpoint is
   money-path: it requires the control token, refuses unless the flag is armed,
   and is rate-limited (M3 #1606). Consider a per-submit confirm for large-value
   txs.

Money-safety gates: arm/disarm and submit are BOTH money-path — control token +
(for arm) two-phase nonce + tripwire; submit re-uses the M1 consensus gate and
the M3 rate-limiter, refuses when disarmed, returns named refusals.

Owed: operator tap, independent review, dependence on M3 #1606 (rate-limiter) for
the submit endpoint's DoS posture.

## Sequencing

Slice 0 (this PR, read-only) -> M3 #1606 merges (wires `rate_limit`/`sandbox` in
the status JSON) -> Slice A (control token + apply for non-money, money-gated) ->
Slice B (arm/disarm + submit). Each of A and B is a separate money-path PR with
its own operator tap and KAT.
