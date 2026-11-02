# c2wallet-qt

A standalone, **air-gapped** Qt desktop signer and transaction constructor for
the frstrtr/c2pool ecosystem — the offline, key-holding successor to
`tools/c2wallet/c2wallet.py`. Full design: **PR #1621**,
[`docs/design/c2wallet-qt.md`](../../docs/design/c2wallet-qt.md).

## The air-gap model

c2wallet-qt is the **offline** half of a two-machine model:

```
   OFFLINE — c2wallet-qt-signer (holds keys)      ONLINE — c2pool node + companion (no keys)
   ──────────────────────────────────────         ──────────────────────────────────────────
                              ◀── unsigned/constructed artifact ── built from live UTXO/chain view
   import keys, derive, DISPLAY summary,
   operator CONFIRMS, sign, SELF-VERIFY
              signed artifact ──▶                 re-validate (gate), then inject / broadcast
```

- **Keys live only inside the offline `c2wallet-qt-signer` build.** The seed and
  private keys never touch a networked or agent-controlled host, and never
  persist in plaintext.
- **c2pool is verify-only by construction** — it holds no keys and never signs.
  It re-validates every artifact regardless of origin.
- **Two public artifacts cross the gap** (unsigned in, signed out), by file or
  QR — never over a live socket from the signer.

## The security property this tree guarantees

The signing binary is compiled **network-incapable** — defense in depth,
layer 1 (design §5.2):

> `c2wallet-qt-signer` links **`Qt6::Core` + `Qt6::Gui` + `Qt6::Widgets` ONLY** —
> no Qt Network, no QtWebEngine, no QtWebChannel, no libcurl, no OpenSSL, no
> boost::asio. A socket call is a **link error**, not a runtime check.

This is why c2wallet-qt is a **separate binary** from `ui/c2pool-qt/`, which
hard-requires QtWebEngine (Chromium + a full network stack): you cannot embed
Chromium and honestly claim to be network-incapable. c2wallet-qt reuses only
c2pool-qt's Widgets shell *pattern*, never its networked dependencies.

The property is proved mechanically by
[`ci/check_no_network.sh`](ci/check_no_network.sh), which inspects the built
binary's `NEEDED` libraries and imported dynamic symbols and fails if any
networking library or network C-ABI symbol (`connect`, `socket`, `bind`,
`listen`, `getaddrinfo`, `gethostbyname`, `SSL_*`, `curl_*`, `res_*`, ...) is
present. It is registered as a `ctest` (`no_network_link_guard`) and is wired
to run in CI on every PR that touches this tree — see
[`ci/CI_WIRING.md`](ci/CI_WIRING.md) and
[`ci/ci-wiring.build-yml.patch`](ci/ci-wiring.build-yml.patch) for the CI job.

The later layers of the model (not in this phase): an optional **online
companion** binary (key-free, does QR/file marshalling and talks to c2pool) is
a later phase, and a **runtime seccomp belt** that kills the process on
`socket(2)`/`connect(2)` lands in **M5**.

## Phase status — M0

M0 is the foundation phase and is deliberately **non-money**: no keys, no
signing, no crypto. It delivers:

- the `ui/c2wallet-qt/` tree and a **Widgets-only CMake** target
  `c2wallet-qt-signer`;
- a minimal Bitcoin-Core-like **MainWindow + sidebar shell** (Wallets /
  Construct / Sign / Convert / Settings) — an empty, runnable skeleton;
- the **network-incapable link-guard** (`ci/check_no_network.sh`) and its CI
  wiring.

Key import, address derivation, transaction construction and signing arrive in
later phases (M1–M6); see the phase table in the design doc §6.

## Build

Requires Qt6 (Core/Gui/Widgets) development packages — on Debian/Ubuntu:

```sh
sudo apt install qt6-base-dev cmake g++
```

Then, from the repo root:

```sh
cmake -S ui/c2wallet-qt -B build-c2wallet -DC2WALLET_QT_BUILD_TESTS=ON
cmake --build build-c2wallet --target c2wallet-qt-signer
# prove the network-incapable property on the produced binary:
ui/c2wallet-qt/ci/check_no_network.sh build-c2wallet/c2wallet-qt-signer
#   ... or via ctest:
( cd build-c2wallet && ctest --output-on-failure )
```

The online companion (built by default) also needs `nlohmann-json3-dev` for
its inject scheduler. A signer-only build needs neither it nor Qt Network:
add `-DC2WALLET_QT_BUILD_COMPANION=OFF`.

## DASH inject / collateral (slice 2)

The **DASH Inject / Collateral** screen consolidates the mature UTXOs of one
DASH P2PKH address (zero fee for a c2pool node's pin / inject lane, or a
fee-paying tx for `dash-cli sendrawtransaction`) or builds a governance
collateral, and signs it offline. All of its rules live in the Qt-free
`DashInjectModel` (`src/family/bitcoin/dash/`), KAT'd by `c2wallet-dash-test`.

Produce its input on the online host, next to a dashd with `addressindex=1`:

```sh
python3 ui/c2wallet-qt/tools/export_utxos.py <ADDRESS> utxos.json
# DASH_CLI="dash-cli -conf=/path/dash.conf" to point at a specific node
```

Carry `utxos.json` to the signer; carry back `<name>.hex` (one raw tx per line,
the c2pool loader format) and `<name>.manifest.json` (txids, sizes, inputs,
maturity, node requirements, the file's sha256 / sha256d; no secrets).

**Before `dash-cli sendrawtransaction` (the relay lane), check every input's
amount on the online host.** Legacy sighash commits no input amounts, so the
amounts in the export are the trust root: on the relay lane an understated one
is paid as extra fee (the zero-fee pin / inject lanes refuse such a tx instead).
Every manifest input must still be unspent with exactly its `value` and
`script_hex`, and each tx's inputs must sum to its `value_out + fee`:

```sh
python3 - name.manifest.json <<'PY'
import json, subprocess, sys
m = json.load(open(sys.argv[1]))
for t in m["txs"]:
    for i in t["inputs"]:
        o = json.loads(subprocess.check_output(["dash-cli", "gettxout", i["txid"], str(i["vout"]), "true"]) or b"null")
        assert o and round(o["value"] * 1e8) == i["value"] and o["scriptPubKey"]["hex"] == i["script_hex"], i
    assert sum(i["value"] for i in t["inputs"]) == t["value_out"] + t["fee"], t["txid"]
print("preflight OK: every input is unspent with the manifest's amount")
PY
```

## Companion Scan & Plan (slices S-A, S-B, S-C)

The companion scans the UTXOs of up to 16 P2PKH addresses from dashd
(`getaddressutxos`, else `scantxoutset`; `gettxout` per row) and/or the c2pool
node's `GET /api/utxo/scan` (node slice N1), cross-checks both at one tip,
classifies every output at a target landing height and plans with the signer's
own code: `c2wallet-dash-plan`, the key-free half of the DASH library
(`src/family/bitcoin/dash/DashPlan.cmake`). It writes `<name>.utxos.json`
(`c2wallet-utxo-export/1`, byte-identical to `tools/export_utxos.py`),
`<name>.scanplan.json` (`c2wallet-scan-plan/1`, advisory: the signer re-plans
and compares digests), a report with the `c2wallet-qt-schedd add` lines and,
optionally, C2WU containers. The core is `src/companion/scan/` (Qt-free, inside
`c2wallet-companion`, covered by `ci/check_key_free.sh`; the daemon and the GUI
that link it are guarded too). Nothing here signs, arms or submits: the
offline signer signs, and the scheduler submits only what `add` queued under
its own arm policy.

```sh
S="c2wallet-qt-schedd --queue $Q --node-url http://127.0.0.1:8080 --token-file /path/control.token"
# scan (dashd + node cross-checked); credentials only from a 0600 file, never argv
$S scan --address XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u --source both \
        --dashd-url http://127.0.0.1:9998 --dashd-auth-file ~/.dash-rpc.auth \
        --key-encoding compressed --out xdgf-2565514
# ... sign xdgf-2565514.utxos.json (+ .scanplan.json) offline -> xdgf-2565514.hex + .manifest.json
$S preflight --hex xdgf-2565514.hex --utxos xdgf-2565514.utxos.json \
        --scanplan xdgf-2565514.scanplan.json --source dashd \
        --dashd-url http://127.0.0.1:9998 --dashd-auth-file ~/.dash-rpc.auth
$S add --hex xdgf-2565514.hex --preflight --utxos xdgf-2565514.utxos.json \
        --scanplan xdgf-2565514.scanplan.json --source c2pool
# a two-stage collateral: after signing stage 1, write the stage-2 intake
$S plan --stage2 --utxos gov.utxos.json --scanplan gov.scanplan.json --stage1-hex gov.hex --out gov-s2
$S watch --address XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u --source c2pool   # every 50 blocks; one alert per batch
```

`preflight` (also `add --preflight`) checks, right before a pair is queued: the
structure and the hex/manifest binding; every manifest input is an export row
and each signed tx is the planned one (its unsigned sha256d = the sidecar's);
every input is still unspent on the chosen source(s); and the node's dry run
`POST /api/tx-inject/validate` (node slice N3) when the node offers it (404,
503 or a reply without `dry_run` is a notice, the other checks stand). `--force
"<reason>"` turns a dry-run cause or a plan-digest mismatch into a warning and
is journaled on the queued items; a spent input is never forceable. Ctrl-C (or
the GUI's Cancel) aborts a running `scantxoutset` with `scantxoutset "abort"`
and drops a node scan request. A stage-2 intake (two-stage collateral) dates
the unmined stage-1 outputs at a projected height (`tip_hash
"projected:<h>"`, marked in the sidecar and the report); `add` refuses its
manifest unless every parent is an `--after-parent`. The companion GUI's
"Scan & Plan" tab runs the same commands in a worker thread.

KATs: `companion_scan_kats` (K1-K21), `companion_scan_cli_kats` (C1-C9: the
commands through `sched::cli::run` with fakes), `scan_qt_kats` (the Qt
transports against local fake servers, the daemon end to end),
`companion_scan_export_parity`, `scan_signer_roundtrip` (through
`DashInjectModel`). A companion-only configure builds the plan library on a
leaf helper target and needs no libsecp256k1 / zlib dev package.

Not done yet: the MN-collateral helper (DESIGN §3.4, §6 #8) and a relay
governance collateral are not planned by the companion (the signer plans the
latter; the companion answers `scan-unsupported`).

## Companion inject scheduler (core)

The online, key-free companion carries an **inject scheduler**: it queues the
signed `<name>.hex` + `<name>.manifest.json` pair and submits each tx to a c2pool
node's loopback `POST /api/tx-inject/submit` when its triggers hold. This tree
holds the Qt-free core (`src/companion/sched/`, inside the key-free
`c2wallet-companion` library, so `ci/check_key_free.sh` covers it), the Qt
Network transport and the headless `c2wallet-qt-schedd` runner (below); the
GUI queue tab is a later slice.

- **Queue file** `queue.json` (`c2wallet-inject-queue/1`): public data only —
  the raw signed txs, txids, provenance digests, triggers, node observations,
  attempts and a journal. Deterministic JSON, atomic writes (mode 0600). Two
  `flock`s: `queue.json.runner.lock` held by the one runner for its lifetime,
  `queue.json.lock` held for each short read-modify-write (operator edits and
  every runner persist; edits bump the item's `rev`, the runner never
  overwrites a higher one). Never the control token, a money nonce or a key.
- **Enqueue** verifies the hex file's sha256 against the manifest, each line's
  txid, the manifest's maturity claim against its own inputs, and the node caps
  (100000 B, 1000 inputs, 1000 outputs, a signed shape). An input txid that is
  already queued pre-fills `after_parent`.
- **Triggers** (all-of): maturity `tip >= safe_from_height - 1` (a coinbase
  created at `h0` is spendable in block `h0 + 100`, the next template is
  `tip + 1`; the rule is shared with the signer in
  `src/family/bitcoin/dash/InjectMaturity.hpp`), `not_before_height`,
  `not_before_time` (UTC, trailing `Z` required) and `after_parent`. A parent
  must be **final**, not merely mined: N confirmations (default 1), its block
  still on the node's chain, and ChainLocked (`bestchainlock.height >=` the
  parent's height in `getblockchaininfo`, on the node's own chain:
  `known_block` true or the hash checked by `getblockhash`). A node that knows
  the field but has not adopted a ChainLock yet (`unavailable.bestchainlock`,
  e.g. right after a restart) makes children wait; only a node with neither
  form (an older build) gets at least 2 confirmations instead ("ChainLock not
  exposed by node"). A parent only in the node mempool never fires a child
  unless the item sets `allow_unconfirmed_parent` (default false). Unknown
  input heights never auto-fire: set `not_before_height` or record an
  explicit override.
- **State machine**: waiting → ready → submitting → admitted → is_hold (the
  node's 600 s InstantSend hold for a zero-fee inject) → riding → mined →
  confirmed, with blocked_not_armed / blocked_token / blocked_node,
  submitted_unknown (504), dropped (bounded resubmits), expired (optional
  renew) and refused. Re-submits are safe: the node answers
  `inject-already-known` / `inject-already-confirmed`.
- **Arming**: the normal posture is the node's unit flag
  (`--embedded-tx-inject`). The scheduler arms the node itself only with a
  recorded consent (`arm_policy.auto_arm` + `consented_at`), through the
  two-phase `POST /api/config/apply`, at most once per 10 minutes, and never
  again after a `money_gate` refusal. A disarm is classified by the node's
  `GET /uptime`: a restart (uptime went back, or is shorter than the time since
  the node was last seen armed) may be re-armed under consent; a disarm while
  the node kept running, or with no usable `/uptime`, is the operator's:
  auto-arm is suspended (alert `operator_disarm`, `status` exit 1) until
  `arm-policy --auto-arm yes --consent "..."` records consent again.
- **Token**: read at use from a 0600 file (the node's own loader rules), held in
  a zeroizing buffer, placed only into the POST body; there is no
  `--token VALUE` option. The node URL must be loopback (use `ssh -L` for a
  remote node).

KATs: `c2wallet-companion-sched-test` (ctest `companion_sched_kats`) drives the
core, the runner merge and every daemon subcommand against a scripted fake
node and a fake clock (K1-K39).

### Headless runner `c2wallet-qt-schedd`

`c2wallet-qt-schedd` runs the loop next to the node (Qt6::Core + Qt6::Network
only; `ci/check_no_gui_link.sh` and `ci/check_key_free.sh` run over the binary).
The transport (`sched/QtNodeApi`, library `c2wallet-companion-qtnet`) talks to a
loopback URL only, with no proxy, no redirects, no HTTP/2, no cookies and a
15 s timeout per request. Operator commands (all accept `--queue PATH`,
`--node-url URL`, `--token-file PATH`; there is no `--token`):

```sh
Q=/home/c2pool/.local/share/c2wallet-qt/companion/queue.json
S="sudo -u c2pool c2wallet-qt-schedd --queue $Q"
$S --node-url http://127.0.0.1:8080 --token-file /home/c2pool/c2pool/control.token init
$S add --hex sweep.hex                       # sweep.manifest.json beside it gives the maturity
$S add --hex collateral.hex --manifest collateral.manifest.json \
       --after-parent 539aa4b7aeceeb17c302cd51f402f3371f527ef73178466b5e3c2f80b9b40a28:1
$S add --hex tx.hex --h0 2565145 --not-before-time 2026-11-05T10:00:00Z   # bare hex, explicit h0
$S arm-policy --auto-arm yes --consent "operator G, hotel queue, 2026-11-02"   # recorded, timestamped
$S list                  # state, why it waits, live IS-hold / retry ETA
$S show q-20261102-002   # one item: triggers, node record, attempts, journal
$S pause ID | resume ID | rm ID | requeue ID | retry ID | set-max-fee ID DUFFS
$S status                # exit 1 when blocked / disarmed / alert pending / runner down
$S ack-alerts
$S run                   # the loop (the systemd unit runs this); run --once for one tick
```

`tools/c2wallet-qt-schedd.service` is the unit for the node host (a system
unit with `User=c2pool`, sandboxed to loopback HTTP and the queue directory;
its header lists the install steps). Exit codes: 0 ok, 1 refused/attention,
2 usage/config, 3 queue unreadable, 4 another runner holds the queue. Qt KATs:
`c2wallet-qt-schedd-test` (ctest `schedd_qt_kats`: the transport against a
local `QTcpServer` fake node, and the daemon binary end to end).
