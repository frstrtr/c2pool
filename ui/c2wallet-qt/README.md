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

## Companion inject scheduler (core)

The online, key-free companion carries an **inject scheduler**: it queues the
signed `<name>.hex` + `<name>.manifest.json` pair and submits each tx to a c2pool
node's loopback `POST /api/tx-inject/submit` when its triggers hold. This tree
holds the Qt-free core (`src/companion/sched/`, inside the key-free
`c2wallet-companion` library, so `ci/check_key_free.sh` covers it); the Qt
transport, the headless `c2wallet-qt-schedd` runner and the GUI queue tab are
later slices.

- **Queue file** `queue.json` (`c2wallet-inject-queue/1`): public data only —
  the raw signed txs, txids, provenance digests, triggers, node observations,
  attempts and a journal. Deterministic JSON, atomic writes, `flock` on
  `queue.json.lock`. Never the control token, a money nonce or a key.
- **Enqueue** verifies the hex file's sha256 against the manifest, each line's
  txid, the manifest's maturity claim against its own inputs, and the node caps
  (100000 B, 1000 inputs, 1000 outputs, a signed shape). An input txid that is
  already queued pre-fills `after_parent`.
- **Triggers** (all-of): maturity `tip >= safe_from_height - 1` (a coinbase
  created at `h0` is spendable in block `h0 + 100`, the next template is
  `tip + 1`; the rule is shared with the signer in
  `src/family/bitcoin/dash/InjectMaturity.hpp`), `not_before_height`,
  `not_before_time` (UTC, trailing `Z` required) and `after_parent` (N
  confirmations, default 1). Unknown input heights never auto-fire: set
  `not_before_height` or record an explicit override.
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
  again after a `money_gate` refusal.
- **Token**: read at use from a 0600 file (the node's own loader rules), held in
  a zeroizing buffer, placed only into the POST body; there is no
  `--token VALUE` option. The node URL must be loopback (use `ssh -L` for a
  remote node).

KATs: `c2wallet-companion-sched-test` (ctest `companion_sched_kats`) drives the
core against a scripted fake node and a fake clock (K1-K27).
