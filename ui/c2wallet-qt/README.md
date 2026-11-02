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
core against a scripted fake node and a fake clock (K1-K27).

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

## Sign / verify message

The **Sign / Verify Message** screen signs an exact message with the key of a
DASH P2PKH address, in the Dash Core `signmessage` format, and verifies other
people's signatures. All of its rules live in the Qt-free `MessageModel` /
`DashMessage` (`src/family/bitcoin/dash/`), KAT'd by `c2wallet-dash-test`
against signatures produced by Dash Core v23.1.7 `signmessagewithprivkey`:
ours must equal Core's byte for byte, for compressed and uncompressed keys.

Example: a DashCentral proposal-ownership claim.

1. **Target**: coin `DASH`, the address that paid the proposal collateral.
   The card shows its version byte and hash160.
2. **Message**: type exactly what the site asks for, e.g.
   `dashcentral-proposal-1556`. Nothing is trimmed: the live counter shows the
   byte count and the sha256, and warns about a trailing newline,
   leading/trailing whitespace, a CR, an empty message or the long form
   (>= 253 bytes). Typed text is signed as UTF-8 with LF line breaks; for
   arbitrary bytes, load them from a file.
3. **Key**: mnemonic (with passphrase and scan range), WIF, BIP38, descriptor
   or JSON keystore. The key is bound on both the address and hash160(pubkey);
   an uncompressed key (a WIF without the `01` suffix, old p2pool-era keys)
   signs with Core's uncompressed header.
4. **Sign**: tick the review box and type `SIGN`. The signer signs, verifies
   the emitted signature, wipes the key, and shows:

```
address:   Xn9KtWHuvMBuSbpzPFTzYG2bC9Wp2ZZJJG
message:   dashcentral-proposal-1556
signature: IPFklzhS3xSUKSIxB5IBWLS/r9Jbc9whftHCjweVVx1aCYwaeRLIO56GvYR6P6ITr4A13dWc20JgSBX/4oK0e6w=
```

(that is a public test key's signature, from the KATs). These three lines are
exactly what the python stopgap `c2wallet.py sign-message` prints for the same
key and message, so switching tools changes nothing for the site. "Copy
signature" puts only the base64 on the clipboard; "Save signature.txt" writes
the three lines; "Verify this in the Verify tab" runs the independent check.

The **Verify** tab takes an address, the exact message and a base64 signature
and answers `VALID` (with the recovered address, key encoding and recovery id)
or `INVALID` with the reason, like `dash-cli verifymessage`. It has no key
field.

Two typed confirmation words exist and mean different things:

- `SPEND` (DASH Inject / Collateral): signs a transaction that moves money.
- `SIGN` (Sign / Verify Message): signs a message. It moves no money, and the
  coin's message magic in the signed digest means a message signature can
  never be replayed as a transaction signature.

Only DASH is enabled. BTC, LTC, DGB and DOGE are listed but refused until a
vector from that coin's own node is committed to
`src/family/bitcoin/dash/tests/msg_vectors.hpp`.

core, the runner merge and every daemon subcommand against a scripted fake
node and a fake clock (K1-K39).
