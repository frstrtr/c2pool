# T15 — real-share-format build cost (residual local M4 item, CLOSED)

T1–T14 used synthetic 32B leaves. The open question the README flagged: does the **real
V37 share-format preimage size** change the O(W) bootstrap verdict, or is it a constant
factor on the hashing leg only?

## Setup
Real sizes from `docs/c2pool-v37-share-format.md`:
- receipt envelope = header 80B + ref_hash 32B + link ~100B + info_digest 32B = **244B**
- full carrier share = receipt fields + PayoutDescriptor v1 (~96B) + R_MAX(4)×256B receipt
  budget = **1364B**

Three build paths over the real Utreexo forest @W=300K (`harness/t15_real_share_format.py`):
- `snapshot_path` — ships 32B leaf HASHES (`add_hash`), the T6/T7/T14 cold-start path
- `raw_ingest[*]` — serialize + `leaf_hash(preimage)` + add, the cold raw-off-the-wire path

## Numbers (W=300K, process_time)
Headline ratio is **x_snap** = build vs the snapshot cold-start floor (~0.7s, low-variance).
`x_synth` (vs the 32B raw-ingest baseline) is *not* headlined: that baseline is small
(~1.3–2.0s) and forest-add-dominated, so its jitter swings the ratio (~7.5–13x for
full_share across runs — an earlier draft cited the 7.5x low end, which is a baseline
artifact, not a real bound). The **absolute** full_share build is stable at ~15–16s.

| path | leaf preimage | build_s (stable) | x_snap | raw egress |
|---|---|---|---|---|
| snapshot_path | 32B (hash) | 0.71 | — | 9.6 MB |
| raw_ingest synthetic32 | 32B | ~1.3 | ~1.8 | 9.6 MB |
| raw_ingest receipt_min | 244B | ~3.9 | ~5.3 | 73.2 MB |
| raw_ingest full_share | 1364B | ~15.6 | ~21 | 409.2 MB |

All paths yield the same **8 roots** (popcount(300000)) — forest structure and 32B-leaf
storage are invariant to preimage size.

## Verdict
1. **O(W) bootstrap stands.** Real preimage size inflates only the cold raw-ingest hashing
   leg by a bounded constant factor — full_share ~15–16s @300K absolute, ~21x the snapshot
   floor — never the O(W) asymptote. Storage stays O(W) 32B leaves; roots are size-invariant.
2. **The snapshot/checkpoint path sidesteps it entirely** (0.72s, 9.6MB): a checkpoint-
   anchored cold-start (T14) ships 32B leaf hashes, paying zero preimage-hashing cost.
3. **Raw-share egress is the real lever, and it confirms the T9/T12/T14 design call:**
   serving full raw shares is 409MB vs 9.6MB for a 32B-leaf snapshot — **43x**. The
   sticky-shard snapshot serving layer (T12) must ship leaf-hash snapshots, never raw
   shares, for cold-start. Raw shares are only needed by a node that wants to *re-verify
   PoW from preimages* — an opt-in audit, not the default bootstrap.

Net: no residual asymptotic risk in M4 from real share format. The only place real share
bytes matter is an audit-mode node re-hashing preimages, ~15–16s @300K (~21x the snapshot
floor) — still seconds-scale and a bounded constant factor, not asymptotic. **M4 local feasibility track is now complete; remaining real-share
build cost over genuine serialized shares is an M5 testbed item, not a local blocker.**
