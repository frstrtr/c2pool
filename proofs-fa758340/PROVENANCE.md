# proofs-fa758340 — provenance

Dated evidence for campaign **fa758340**: bringing the c2pool-dash *embedded
daemonless* path (no attached `dashd`) to consensus parity with Dash Core on
mainnet. The campaign is organised as deliverables D1–D6; this directory holds
the artifacts for the D2, D3 and D4 legs that were closed by observation, plus
the cold-start analysis written for an external node operator.

These files are **captures, not source**. Nothing here is built, imported or
executed by the build; the directory is retained so that each claim made in the
campaign can be re-checked against the artifact that produced it, long after the
run logs are gone. Capture date for every artifact is **2026-09-10**, from
commit `d7b4aed33` (an ancestor of `master`).

## What each file is

### D2 — DIP4 CbTx byte-parity

| file | what it is |
|---|---|
| `d2_issue_cbtx.md` | The D2 write-up: scope of the CbTx consensus fields checked, the method, the result, and the reproduction recipe. Also records that the *superblock*-coinbase leg of D2 is blocked on an external precondition (the network held no funded governance trigger for the next superblock height), not on the assembler. |
| `cbtx_byte_parity_20260910T014709Z.txt` | The raw gtest run behind that write-up: 8 tests, 2 suites (`DashEmbeddedCbtxByteParity`, `DashMnlistdiffRootParity`), 8 passed / 0 failed, with the capture timestamp and git head in the header. |

**How to verify:** rebuild and re-run the same target — the assertions are in the
repo and in the CI "Build tests" set, so this is not a one-machine claim:

```
cmake --build build --target test_dash_embedded_gbt
DASH_FIXTURE_DIR=<repo>/test/fixtures ./build/test/test_dash_embedded_gbt \
  --gtest_filter='DashEmbeddedCbtxByteParity.*:DashMnlistdiffRootParity.*'
# expect: 8 passed, 0 failed
```

### D3 — old-coin fee class (the fee half)

| file | what it is |
|---|---|
| `d3fee.py` | The scanner. One `getblock <hash> 3` per block over mainnet heights 2535178..2536177; classifies a fee-bearing tx as **old-coin** if any input spends a prevout below `h-288`, i.e. outside the `--embedded-utxo` 288-block sliding window, which therefore cannot price it. |
| `d3fee.out` | The run log of that scanner, ending in the machine-readable `RESULT` line. |
| `d3_fee_oldcoin_summary.txt` | The reading of that run: 1000 blocks, 19420 fee-bearing txs, 39.3% of fee value (and 23.2% of fee-bearing txs) falls in the class the sliding window drops. Includes the cross-check against an independently captured ground-truth total (0.012% apart), which is what makes this a measurement rather than an estimate. |

**How to verify:** the range is historical mainnet, so the scan is replayable.
Point `dash-cli` at any mainnet node with `txindex=1` and re-run
`python3 d3fee.py`; the `RESULT` line must match `d3fee.out`. The accuracy half
of D3 — whether the replay fold prices these old-coin txs *correctly* — is not
in this directory; it remained build-gated at capture time.

### D4 m1 — the issued embedded template

| file | what it is |
|---|---|
| `d4-m1-template/MANIFEST.md` | The m1 closure write-up: why a new run was needed (the earlier node never mounted `/embedded_template` because the D4 recipe omitted `--stratum`, so no miner session ever sourced a template), the exact launch line, and the timing chain from a cold empty datadir to first issuance — 16 min 10 s against a 60 min budget. |
| `d4-m1-template/INDEX.txt` | The three capture timestamps with their offsets from process start T0. |
| `d4-m1-template/embedded_template.*.json` | The three frozen `/embedded_template` snapshots, 60 s apart. Capture #1 is the **first template the node actually served** at height 2536440 — not a "would-serve" reading. |

**How to verify:**

1. The three JSON sha256 sums below are also recorded inside `MANIFEST.md`,
   written at capture time; they match, so neither side has drifted.
2. The snapshot is self-consistent with the miner's wire: the `mining.notify`
   prevhash quoted in `MANIFEST.md` is the stratum chunk-reversed form of
   `previousblockhash` in capture #1, and `template_age_sec=15` places the
   sourcing at the `send_notify_work` timestamp in the same table.
3. Everything in the JSON (prevhash, nbits, the CbTx roots, mempool txs) is
   mainnet block data at 2536440 and can be checked against any mainnet node.

Note on the coinbase: `coinbase_hex` is the *canonical* template coinbase — zero
extranonce, no per-session miner payout. The two P2PKH outputs in it are chain
data (the deterministic masternode payee and a reward output), and both hash160s
already appear in files committed elsewhere in this repository
(`src/impl/dash/coin/checkpoints/dash_mn_checkpoint_mainnet.inc`,
`test/test_dash_coinbase_parity.cpp`). No operator or pool payout address is
recorded here.

### Cold-start analysis

| file | what it is |
|---|---|
| `external_operator_node_spec.md` | Why a *fresh* deployment could not reach a served masternode set on the cold path at that time — the checkpoint bridge replays from the compiled-in anchor (height 2522504) and, on an empty datadir, exhausts its flat ban-state probe budget before the replay completes, fails closed, and never arms `have_mn`. Sets out three options (ship a post-divergence cursor + diff store; ship a binary with the budget scaled or the anchor re-pinned; or run the full genesis-to-tip replay fold) with the trade-offs of each, and recommends the binary fix as the durable answer. |

**How to verify:** this one is analysis, not a capture — it is reasoning about
code paths that are in the tree and about a window size that moves with the
chain. Treat it as dated: it is a snapshot of the cold-start situation on
2026-09-10, and the anchor has since been re-pinned under separate work, which
is exactly the Option B it recommends.

## Redactions

Two edits were made before committing, because this repository is public:

- `d3_fee_oldcoin_summary.txt` — the measuring node's internal hostname and
  LAN address were replaced with "internal mainnet full node". The node's
  software version, network and `txindex` setting are kept, since those are what
  bear on the result.
- `external_operator_node_spec.md` — the document was written for a named
  third-party node operator. The operator's handle was removed from the filename
  and from the body (now "the external operator"); no technical content was
  changed.

Nothing else was altered. The artifacts are otherwise byte-for-byte as captured,
which is why the one-line gtest header and the absolute paths in the logs were
left alone.

## sha256

```
847a07503c4a1dab598b36d295d389cd5f6d13f6195e3731b33d1b0b134cee5e  cbtx_byte_parity_20260910T014709Z.txt
31ea6d82480c0c621f7ae3907b42eacf197f42cc2cf9debf5c293674ee82cac6  d2_issue_cbtx.md
b41c8742a9f38a0301e44982c5fa2dd2aa38ab8fa861db7689aaede74e846d79  d3_fee_oldcoin_summary.txt
3849ae65f118572add356d195fc86bb53e23ea3ce7d3436077a61dc7f8bc0f3b  d3fee.out
95bcd9a9fb8ad5fa4d39f1dc476bdf83bf8d4faf550fac6ff39bace6bc5dd642  d3fee.py
fbcdae8ef0c08dbe54774fed9919566ef0d7e51133b2665c6b96d3e3ec6b3252  d4-m1-template/INDEX.txt
df4700894b9e4f721aca294acff1cbdb2ce5539ee8c38d704ad1d63a5948a5e1  d4-m1-template/MANIFEST.md
79359c8fce06cbee5f178974bab28db934fbe8ba04fa97cd8d4a0ca6b7a7b45e  d4-m1-template/embedded_template.2026-09-10T09:43:28Z.json
c6c58bbdecf54d7110bac2887949525945672968733ac97fc16c10d5b1169d6a  d4-m1-template/embedded_template.2026-09-10T09:44:28Z.json
793f642dbae6ecc75181818b8da3038380fcf25bb022a11b6d44eeb0938b3c73  d4-m1-template/embedded_template.2026-09-10T09:45:28Z.json
ae3218b336b43e07e64f8761b0685e8cc8c3eb115622a40d723ae073e39b4179  external_operator_node_spec.md
```

Verify with `sha256sum -c` after stripping this block to a plain checksum file,
or `cd proofs-fa758340 && find . -type f ! -name PROVENANCE.md | sort | xargs sha256sum`.
