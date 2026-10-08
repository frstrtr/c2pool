# D4 milestone m1 — the ISSUED embedded template, captured

Closing m1 by observation rather than by inference. The earlier reading was
`arm=would-serve`, which is the node saying it *would* serve; this is the
template it actually served, taken off `/embedded_template` and corroborated on
the miner's wire.

## Why this needed a new run

The m2 run (`fa758340-m2-fixed`, port 8095) cannot produce a template at all,
and the endpoint says so rather than failing:

    GET http://127.0.0.1:8095/embedded_template
    {"note":"embedded-template endpoint not wired on this node","state":"unavailable"}

That is structural, not transient. In `src/c2pool/main_dash.cpp` the call to
`mi->set_embedded_template_fn(...)` at :4406 sits **inside** the branch taken
only when `--stratum` was passed and the bind succeeded; the `else` at :4417
prints `[run] stratum disabled (no --stratum flag)`. And a template is sourced
only from `StratumSession::send_notify_work` (`src/core/stratum_server.cpp:1568`)
→ `get_current_work_template()` → `cached_work()`, i.e. from inside a miner
session. The D4 recipe deliberately omitted `--stratum`, so that node never
builds a template and never mounts the endpoint. No amount of polling it would
have produced one.

## The run that closes m1

Same binary as the m2 run — built from `f4daaa775`, sha256
`30e8b7e0b08a0ebc1824321b34d94adac8c69b22794630e591e70815c622b47c`,
`[init] DASH BLS backend: REAL` — same isolation, a fresh data directory, plus
stratum on loopback:

    c2pool-dash --run --data-dir /home/ubuntu/fa758340-m1-stratum \
      --embedded-mainnet --coin-p2p-discover --connect 127.0.0.1:1 \
      --web-host 127.0.0.1 --web-port 8097 --stratum 127.0.0.1:3345

Host `dev-host`, PID 312752. The endpoint's answer changed to
`{"state":"no_template_served_yet"}` the moment stratum was bound — a clean
discriminator between "not wired" and "wired, nothing served yet".

A subscribe-only probe client (`miner_probe.py`, no submits, zero hashrate) held
a session open so work would be pushed.

## Timing chain, from a cold empty data directory

| moment | UTC | from T0 |
|---|---|---|
| T0 — process start | 2026-09-10T09:27:02Z | 0 |
| `[MN-CKPT] bridge COMPLETE` as-of h=2536439, 13935 blocks replayed | 09:43:09Z | 16 min 07 s |
| `[Stratum] send_notify_work: height=2536440` — **first issuance** | 09:43:12.721Z | **16 min 10 s** |
| `mining.notify` received by the subscribed client | 09:43:12.741Z | 16 min 10 s |
| `/embedded_template` returns `state:ok` (frozen, capture #1) | 09:43:28Z | 16 min 26 s |

Milestone budget was 60 minutes.

## Captured artifacts

    embedded_template.2026-09-10T09:43:28Z.json  sha256 79359c8fce06cbee5f178974bab28db934fbe8ba04fa97cd8d4a0ca6b7a7b45e
    embedded_template.2026-09-10T09:44:28Z.json  sha256 c6c58bbdecf54d7110bac2887949525945672968733ac97fc16c10d5b1169d6a
    embedded_template.2026-09-10T09:45:28Z.json  sha256 793f642dbae6ecc75181818b8da3038380fcf25bb022a11b6d44eeb0938b3c73

Capture #1, the first served template:

    state                    ok
    height                   2536440              (tip+1)
    previousblockhash        00000000000000110f1d12ea82b7b0c7fb02bbfd5c72c9b63f2b651b56cef90d
    version                  536870912
    nbits                    19388f50
    curtime                  1789033392
    coinbasevalue_duffs      164400509
    total_fees_duffs         22468
    txs                      5   (mempool_tx_first_index=0, mempool_tx_count=5)
    merkle_branch            3 levels
    cbtx                     version 3, height 2536440,
                             merkleRootMNList  45d3a5bceaa7dd2cfc76156d50f24d494a425a9ec8ba98b955d9a30de178fa85
                             merkleRootQuorums 6cc3ea26babb99e4aceac49384c041242cd7963ee5f7081d0420d0ea2bd2b777
                             bestCLHeightDiff 0, bestCLSig present,
                             creditPoolBalance 3198755699080
    superblock               {"active": false, "payouts": []}
    template_age_sec         15

The snapshot and the wire agree: `template_age_sec=15` places the sourcing at
09:43:13Z, and the `mining.notify` prevhash
`56cef90d3f2b651b5c72c9b6fb02bbfd82b7b0c70f1d12ea0000001100000000` is the
stratum chunk-reversed form of the `previousblockhash` above. The template also
carries `coinbase_hex`, `coinbase_payload_hex` (the raw DIP-4 CbTx) and
`coinbase_txid`.

## What this run also confirms, incidentally

It is a second cold data directory exercising PR #1553. It walked through
`h=2529626` — where the pre-fix build fail-closed — and finished with
`BAN-STATE PROBE: 24/147 used`, `grep -c "PROBE CAP IS EXHAUSTED"` = 0.

Live sources on `dev-host`:
`/home/ubuntu/fa758340-m1-stratum/{m1.log, miner_probe.log, poll.log, captures/}`
