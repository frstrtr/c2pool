# XMR lane — real sharechain relay (GAP-2): stage-1 design

Status: DESIGN (read-only inventory + specification). Branch `v37/xmr-gap2-relay`
(worktree on origin/master `f91242945`). Nothing here changes a consensus byte;
every place where it would is marked **SEAM** and handed over.

## 0. The gap, precisely

`main_v37_xmr.cpp` (the `c2pool-v37-xmr` daemon) has no c2pool-to-c2pool share
exchange. What exists instead:

| stand-in | where | what it is |
|---|---|---|
| `--credit-feed FILE` | `main_v37_xmr.cpp:148,1292-1333` (`feed_push_line`, `feed_pump`) | a SHARED append-only file, one receipt per line, every node folds the same lines in file order (`submit_tracked(...).get()` per line so every prefix is published) |
| `--credit-feed-lag-ms` | `:149,1325-1331` | receiver-behind simulator |
| `--wire-out DIR` / `--wire-in DIR` | `:150,1233-1290` (`on_own_win_deferred`, `wire_pump`) | directory drop of REAL S-1c v0x02 `CarrierWire` frames carrying the block-winner `CutDescriptor` (fast path A) |
| `feed_log` + `replay_view` | `:1060-1136` | R3 replay-to-prefix from the node's own ingest log; comment at `:1103-1105` already says: "When the real S-1 carrier relay lands, swap the source to FrameVaultChainReader + replay_to_cut (carrier_repair.hpp) — same gate, same fold." |
| `--mint-receipts` (PR c2pool#1710, fee-port, UNMERGED) | `pr-1710:main_v37_xmr.cpp` mint hook | writes `"R1 <kind> <payload128hex> <w> <d>\n"` per accepted stratum share into the feed; `d` = give-author u16, payee = owner-fee-substituted ref. `xmr_fee_model.hpp:277-333`. NOT PoW-bound: a feed writer forges payee/`d` at will. |

The daemon's own accepted shares reach the lane ONLY through that file: there is
no `LaneRecord::push` in the daemon except `feed_push_line` and the replay
(`grep LaneRecord::push main_v37_xmr.cpp` -> `:1119, :1298`).

Convergence today rests on two things: the on-chain credit cut
`(P, spine_digest)` in the coinbase 0x02 tail (`xmr_credit_cut.hpp`, authority B)
and the assumption "every node ingested the same records in the same order"
(feed). Stage 1 must replace the second assumption with a protocol.

## 1. Inventory — what already exists (file:line) and the reuse verdict

### 1.1 Family-B (RandomX) receipt stack — `src/impl/xmr/` — REUSE AS-IS

* `receipt/xmr_receipt.hpp` — `MoneroReceipt` = `HashingBlob` (~77 B, the exact
  RandomX input) + `SeedRef` (0/32 B) + `CoinbaseOpening` (200-B Keccak midstate +
  prefix tail + tx_extra in the clear, `:144-160`) + `TreeBranch` (`:167-185`) +
  `info_digest` (`:236-266`); `ReceiptSideData{t_origin, payout_identity,
  chain_id, prev_own_share}` (`:211-216`); byte budget `budget::PER_RECEIPT_BUDGET
  = 768`, `R_MAX_XMR = 2` (`:268-289`).
* `receipt/xmr_receipt_verify.hpp/.cpp` — `parse_hashing_blob`, `parse_tx_extra`
  (0x01/0x02/0x03), `side_data_digest` (`.cpp:139-148`), `mm_commitment_leaf`,
  `build_coinbase_opening`, `resume_prefix_hash`, `verify_crypto_opening`
  (midstate -> H(prefix) -> coinbase tx hash -> tree branch -> root == blob's
  tree_root; proven byte-identical on mainnet block 3000000), `open_and_bind_impl`,
  `build_v37_receipt(BuildInputs)`, `verify_receipt(...)` (the full 5-stage order),
  `cheap_receipt_id = keccak256(hashing_blob)`.
* `receipt/xmr_admission.hpp` — the ratified INVERTED admission order for
  `keyed_heavy`: `1 dedup -> 2 expiry -> 3 structural+binding -> 4 R-1 target ->
  5 RandomX LAST` (`:40-70`), `LaneKeyedHeavy{r_max=2, per_receipt_budget=768,
  n_ctx=2, seed_ref_policy, index_retention_blocks=2112}` (`:83-101`),
  `admit_receipt_keyed_heavy` (`:200`), stage reporting so griefing is priced.
* `wire/xmr_carrier_wire.hpp` — TOTAL, BOUNDED codec: `encode_receipt/decode_receipt`
  (`:201,:225`), `CarrierMessage{chain_id, carrier, receipts}` +
  `encode_carrier/decode_carrier` (`:301-341`), caps (`cap::MSG_MAX = 2311`).
* `wire/xmr_carrier_dos_budget.hpp` — `CarrierDosBudget`: per-peer token bucket on
  RANDOMX EVALUATIONS (refund on valid, spend on invalid, ban on confirmed
  invalid PoW; defaults refill 1/s cap 20 per peer, global 16/s cap 256 ~ <=25% of
  one core), `confirm_invalid` re-verify (p2pool "UNSTABLE HARDWARE" idiom).
* `wire/xmr_carrier_relay.hpp` — `LaneEnv` (injected cheap oracles + `rx_verify`),
  `admit_one` (`:114`), `handle_xmr_carrier` (`:227`) = the token seam: the budget
  grant is injected into the stage-5 `seed_for_bin` hook so `rx_check` runs IFF a
  token was granted. Has NO transport binding ("the reception slice ... out of
  scope here").
* `wire/messages.hpp` — `message_xmr_carrier` for the v36 `pool::` p2p stack. NOT
  used: the v37 XMR daemon stands up no v36 `pool::Node` (same finding as
  `carrier_net.hpp:9-17` for btc-dash).
* `pow/randomx_verify.hpp` — `LightVerifier`: two-cache (current/next) 256 MiB
  light manager, `seed_height/seed_heights` (2048-epoch, 64 lag), `prefetch_epoch`,
  `meets_difficulty_64/128`; invariants I1 (RandomX LAST), I2 (never init a cache
  on the hot path), I3 (light only). `pow/randomx_init_lock.hpp` — process-wide
  init serialisation (the 09-17 SIGFPE). NOT thread-safe: one instance per thread.
* `test/randomx-light-measurement.txt` — MEASURED: Argon2d cache init 702 ms per
  epoch; per hash 20.6/24.5/26.2 ms (min/med/max, warm, light mode); RSS +256 MiB
  per cache, ~2 MiB per VM.

### 1.2 Family-A S-1 carrier/relay/supply/repair — `src/c2pool/v37/` — REUSE THE TRANSPORT + SUPPLY + VAULT; SIBLING FOR THE TYPED PARTS

* `carrier_net.hpp` — `CarrierPeerNode : ICarrierTransport` (`:122`): POSIX TCP,
  framing `[u32 LE len][frame]`, `kMaxCarrierFrame = 1 MiB` (`:110`), FIRST-BYTE
  NAMESPACE `0x01..0x7f` = carrier-body versions -> `InboundFn`, `0x80..0xff` =
  control opcodes -> `ControlFn` (`:114-119, :408-440 reader_loop demux`),
  `PeerId` fresh per connection (`:137`), `PeerConnectFn`/`PeerEventFn`
  (`:126-150`), `send_to(pid, frame)` (`:190`), `peer_ids()` (`:218`),
  `listen(host, port)` (`:229`), `add_peer(host, port)` (`:255`, dial; a failed dial
  is a no-op the caller may retry -> the redial timer is ours), `broadcast`
  (`:290`), SO_SNDTIMEO + hard drop of slow peers (`:59-72, :321`). Duplex, one
  reader thread per peer. **REUSE VERBATIM** — it is byte-agnostic; our frames
  take an unused first byte in `0x01..0x7f`.
* `carrier_supply.hpp` — the repair channel: `GETORDER 0x80 / ORDER 0x81 /
  GETFRAMES 0x82 / FRAMES 0x83` (`:53-79, :179-184`), `CtrlWire` (`:294`),
  `SupplyService(vault, send_ctl)` serve side with per-peer token bucket, LRU peer
  table, reply ceiling derived from the transport (`:512-787`), `SupplyRequester`
  fetch side: one outstanding request per peer, continuation cursor, fail-closed
  whole-response rejection (`:789-1237`). Ids are `bytes32`, frames are bytes.
  **REUSE**, with ONE generalisation: the requester's byte-to-id check is
  Family-A typed — `:1016 CarrierWire::decode(bytes)` / `:1024 dr.carrier.carrier.hash()
  == id`. Stage 1 adds an injectable `IdOfFrameFn` (default = today's CarrierWire
  path, DASH unchanged) so Family-B frames verify as `cheap_receipt_id(blob)`.
* `frame_vault.hpp` — `FrameVault` (`:161`): one bounded store (max_entries 16384,
  max_bytes 32 MiB, horizon 8640 positions), indexed by position AND by hash,
  `Entry{hash, chain, pos_first, n_pushes, frame, at}` (`:171-178`),
  `serve_frames` (`:348`). Byte-agnostic. **REUSE VERBATIM.**
* `carrier_repair.hpp` — Stage-2 APPLY: `replay_to_cut(RepairInput, index)`
  (`:383`) = fetch winner's ORDER over [0,P) + FRAMES, replay through a SCRATCH
  `V37Engine`, accept ONLY if digest at P == winner's `cut_spine_digest`;
  `RepairDriver` (`:611`). The digest gate and the "repair changes WHICH
  SettlementView fold_eb reads, never the fold" argument (`:20-63`) carry over
  1:1. The BODY is Family-A typed (`FrameVaultChainReader : persist::ISharechainReader`
  over `WorkEvent`, `ReceiptAdmitter`, w6 `ReplayDriver`) -> **SIBLING** for
  Family-B (`xmr_relay_repair.hpp`), same gate, same fold.
* `w3_relay.hpp` — `CarrierWire` v0x01/v0x02 (frozen goldens), `CutDescriptor`
  (`:170`), `RelaySeenSet` (`:526`), `CarrierBloatStats`, `ICarrierTransport`
  (`:610`), `CarrierRelay` (`:728`, `handle_inbound :904`, `handle_local :949`,
  `append_block_winner :979`, RE-OFFER sweep `note_peer_connected :822` /
  `reoffer_tick :827`, `vault() :812`). Typed on `WorkEvent` (synthetic sha256d
  RDWR envelope, `w2_receipt.hpp:206-234`); `put_cutdesc/get_cutdesc` are
  `private` (`:361, :406, :418`). **NOT reused for receipts** (wrong envelope);
  the CutDescriptor FIELD LIST (`:62-70`) is reused as the block-won message body.
* `w2_admission.hpp` / `w2_receipt.hpp` — Family-A admission (`ReceiptAdmitter`,
  `DedupWindow`, `EmittedPush`, push sequence `:22-32`). The XMR arm has its own
  admission (`xmr_admission.hpp`); the PUSH SEQUENCE rule ("carrier push then
  receipt pushes, in wire order, one lane position each") is kept.
* `carrier_ingest.hpp` — `CarrierIngest::fn()` (`:97-115`): admit + `engine.submit(
  LaneRecord::push(...))` as ONE locked step; the threading argument (`:20-33`) is
  reused for the Family-B ingest.
* `carrier_index.hpp` — `LiveMainchainIndex` horizon/tri-state design (`:19-48`);
  XMR binds its own `MainchainIndex::by_hash` (`impl/xmr/node/mainchain_index.hpp:278`)
  / native chain (`xmr_native_chain_source.hpp:60`).
* `main_v37_btc_dash.cpp:406-600` — the production wiring pattern of all of the
  above (`--peer`, `CarrierPeerNode`, `SupplyService/Requester`, `RepairDriver`).
  **COPY THE SHAPE.**
* KAT templates: `test/v37_a2_multinode_test.cpp` (394 lines; 2 in-process nodes
  over real loopback sockets), `test/v37_convergence_supply_kat.cpp`,
  `test/v37_carrier_relay_robustness_kat.cpp`, `test/v37_xmr_credit_cut_kat.cpp`.

### 1.3 XMR native levin transport — `src/impl/xmr/native/p2p/` — NOT REUSED FOR THIS

`levin_codec.hpp`, `levin_socket.hpp`, `xmr_levin_link.hpp`, `xmr_peer_pool.hpp`,
`xmr_p2p_dos.hpp`, `xmr_peer_store.hpp` speak the MONERO network (handshake with
network_id, 1001/1002/2006/2008...). c2pool-to-c2pool receipt exchange is a
separate overlay: a custom levin command would be dropped by monerod peers and
would couple the receipt relay to the native arm's peer set (which the daemon arm
does not have). Verdict: receipts ride `CarrierPeerNode`; blocks keep riding
levin (`xmr_p2p_block_publisher.hpp`, C5 `xmr_block_relay.hpp`) — unchanged.
Later stage: a c2pool-only levin command is an option once the native arm is
the only stack.

### 1.4 Where the mint inputs live (own shares)

* `impl/xmr/stratum/xmr_stratum.cpp:347-426 handle_submit` — re-hashes every
  submit (`m_verifier.randomx_hash`), `AcceptedShare{template_id, extra_nonce,
  nonce, pow_hash, achieved_target, height, is_network_block, worker, address}`
  (`xmr_stratum.hpp:133-143`) -> `IShareSink::on_accepted_share`.
* `xmr_live_submit.hpp:158-183 BlockCandidate{full_blob, hashing_blob,
  nonce_offset, prev_id, height, ...}`; the daemon's candidate ring lookup
  `own_candidate_lookup(tid, en, c)` (`main_v37_xmr.cpp:1029, :1558`).
* Template: `impl/xmr/template/xmr_block_template.hpp:165-178`
  (`commitment_leaf(extra_nonce)`, `extra_nonce_tail()`), `.cpp:313-345`
  (per-extra_nonce midstate patch: extra_nonce 4 B in the 0x02 field, then the
  0x03 MM root); `xmr_o2_settlement_source.hpp:405-409` — the 0x03 leaf is
  `keccak(MM_LEAF_DOMAIN || chain_id || lane_commitment)`, extra_nonce-INDEPENDENT
  by design. The 0x02 payload today = `nonce(4) | pad | "V37C" u64 P b32 spine`
  (`xmr_credit_cut.hpp:8-20`).
* Fee model (PR c2pool#1710): `xmr_fee_model.hpp` `MintedReceipt`, `mint_receipt`
  (owner roll at mint), `receipt_pushes(r)` -> `{payee, w_miner}` +
  `{donation, w_donation}` (`:329-333`), `give_author_u16`.

## 2. The two facts that shape the protocol

**F1 — the payee MUST be inside the PoW-hashed bytes, or nodes fork.** Dedup keys
on `receipt_id = keccak(hashing_blob)` (admission (D), `xmr_admission.hpp:55-60`).
If the payee/`d` travel outside the blob (as in the R1 feed line), the same blob
can arrive at node A with payee X and at node B with payee Y; each admits the
first it sees; the lane record streams differ; `owed_digest` forks with no
detectable fault. So binding is a CONVERGENCE requirement, not only anti-forgery.
The existing receipt design already binds `info_digest` via the coinbase — but
via the 0x03 MM leaf (`open_and_bind_impl`: `tx_extra 0x03 == mm_leaf(chain_id,
info_digest)`), and in the v37 settlement coinbase that leaf is the OWED
commitment (`lane_commitment`), extra_nonce-independent, and read by the
coinbase authority decoder (`xmr_coinbase_authority.hpp`). It cannot also be a
per-worker receipt commitment without changing block-decode consensus. Hence:

**Binding site for stage 1 = the per-worker 0x02 extra-nonce region.** Today
`[extra_nonce(4)]`; stage 1 makes it `[extra_nonce(4) | rbind(32)]` where
`rbind = keccak256("c2pool-v37-xmr-rbind-v1" || chain_id_le32 || side_data_v2)`.
It is per-worker (the template already patches per-extra_nonce bytes there via
the cached midstate, `.cpp:313-345`, so the O(1) fast path holds), it is under
the tree_root and therefore under RandomX, the credit-cut tail stays at the END
of the payload (`parse_tail` reads from the end, unchanged), and the 0x03 leaf,
deterministic `r`, K_fair outputs and coinbase-authority decode are untouched.
Miner_tx weight grows by a CONSTANT 32 B. -> **SEAM-1** (coinbase bytes; see §8).

**F2 — order is node-local (Ruling A, 09-12), the winner's cut is the authority.**
With gossip, arrival order differs per node; the landed answer (btc-dash Stage
1+2, `carrier_repair.hpp`) is: fold at the WINNER's `(P, spine)` from our own ring
when we published it, else fetch the winner's ORDER over [0,P) + missing FRAMES
and replay in a scratch engine, accept only on digest equality. Stage 1 adopts
this verbatim for XMR (the file's own comment at `main_v37_xmr.cpp:1103` asks
for exactly that), and ADDS a local scheduling policy that makes orders coincide
in the common case (§4.4) so repair is the exception, not the per-block rule.

## 3. Stage-1 protocol

Transport: `CarrierPeerNode` framing `[u32 LE len][frame]`, one TCP connection per
peer pair, duplex. First byte of every frame selects the codec:

| frame[0] | owner | meaning |
|---|---|---|
| `0x01`, `0x02` (`0x03` planned) | Family-A `CarrierWire` | an XMR node counts and ignores (never drops the peer) |
| `0x40` | **FB_HELLO** | first frame on every connection, both directions |
| `0x41` | **FB_RECEIPTS** | 1..8 Family-B receipts (flood or backfill delivery) |
| `0x42` | **FB_BLOCK_WON** | block-winner cut descriptor (replaces `--wire-out/--wire-in`) |
| `0x80..0x83` | `carrier_supply.hpp` control | GETORDER/ORDER/GETFRAMES/FRAMES — reused unchanged |

`0x40..0x4f` is claimed for Family-B and pinned by a KAT against
`w3_wire_freeze::kAcceptedVersions` and `kCtrlOpcodeBase` (no collision, ever).
All integers little-endian, fixed order, no varints except inside the reused
receipt codec. Every decoder is total and bounded (`WireError` -> count, drop the
FRAME, keep the socket, unless the length prefix itself is over the ceiling).

### 3.1 FB_HELLO (0x40) — the pool/consensus-id gate

```
u8  0x40 ; u8 ver=1 ; u32 magic 'C2XR'
u8  network (0 mainnet 1 testnet 2 stagenet 3 regtest)
u32 chain_id
b32 lane_params_digest      keccak256(canonical LaneParams fields || share_diff || keyed_heavy fields)
u64 share_diff              cfg.stratum_share_diff (the R-1 pin every node must share)
u64 node_nonce              random per process (self-connect detection)
u16 listen_port             0 = dial-only
u64 lane_next_pos           our lane tip (diagnostic + backfill hint)
b32 lane_digest             our LaneSnapshot digest at that tip (diagnostic)
```
Rules: must be the first frame; any mismatch of `magic/ver/network/chain_id/
lane_params_digest/share_diff` -> log the reason and drop the peer (this closes
the memory-recorded GAP "mismatched-LaneParams nodes must reject explicitly, not
diverge silently"). Until HELLO is accepted no other frame is processed from
that peer. A peer that never sends HELLO within 10 s is dropped.

### 3.2 FB_RECEIPTS (0x41)

```
u8 0x41 ; u8 ver=1 ; u32 chain_id ; u8 n (1..8)
n x fb_receipt
fb_receipt :=
  u16 len ; len bytes = xmr_carrier_wire::encode_receipt(MoneroReceipt)   (<= per_receipt_budget)
  side_data_v2 :=  u64 t_origin.lo ; u64 t_origin.hi ; b32 payout_identity ; u32 chain_id ; u16 give_author ; u16 reserved=0
  ref payee   :=  u8 kind (0x10 XMR_STD | 0x11 XMR_SUB) ; u8 len=64 ; 64 bytes
```
Receiver processing (per receipt, in the injected `LaneEnv` shape of
`xmr_carrier_relay.hpp:69-104`, RandomX LAST):

1. **bounds** — frame <= `kFbMaxFrame` (8 x 1024 + header); `len <= per_receipt_budget`.
2. **dedup** — `receipt_id = cheap_receipt_id(blob)` in the seen-set (bounded,
   retention = index horizon) -> drop silently, count.
3. **expiry/context** — `bin = height(parse_hashing_blob(blob).prev_id)` via the
   mainchain index (daemon arm `MainchainIndex::by_hash`, native arm the chain
   source); unresolvable or older than `--relay-index-horizon` (default 64 bins,
   ~2 h) -> drop (peer not penalised: our index may lag; counted).
4. **structural + binding (v2)** — `verify_crypto_opening` (midstate -> H(prefix)
   -> tx hash -> branch -> tree_root == blob root); `parse_tx_extra`; the 0x02
   payload bytes `[4..36) == rbind(chain_id, side_data_v2)`; `identity ==
   xmr_identity_key(payee)`; `side_data.chain_id == lane`; `give_author` any.
   Failure -> `DroppedCheap`, soft score bump (microseconds).
5. **R-1** — opened `t_origin == share_diff` (the lane's consensus share
   difficulty; equal on all nodes by HELLO).
6. **RandomX** — token from `CarrierDosBudget::grant_randomx(peer)`; none -> DEFER
   (queue up to a small bound, retry on refill; never a penalty). With token:
   `LightVerifier::hash(blob, seed_for_bin)`; `meets_difficulty_64(hash,
   t_origin)`. Valid -> refund token, ACCEPT. Invalid -> `confirm_invalid` re-hash
   (unstable-hardware guard) then BAN the peer (spent token stays spent).
7. **accept** -> ingest (§4), vault (§4.2), verified-cache insert, FLOOD to every
   peer except the source (`send_to` loop over `peer_ids()`), stats.

Own shares take the fast path: the stratum listener already re-hashed the
share (`handle_submit :392`), so the mint marks `receipt_id` verified with
`pow_hash` and skips stage 6 (still runs 1-5 against itself: a template bug must
not mint an unverifiable receipt).

### 3.3 FB_BLOCK_WON (0x42)

Same field list as the frozen v0x02 `CutDescriptor` (`w3_relay.hpp:62-70`),
flat: `u8 0x42 ; u8 ver=1 ; u32 chain_id ; b32 bid ; u64 h_b ; u64 cut_next_pos ;
b32 cut_spine_digest ; u64 reward ; u8 payout_emitted ; b32 owed_digest_at_win`.
Receiver = today's `wire_pump` body (`main_v37_xmr.cpp:1266-1290`): cache by
`bid`, pre-fold at the carried cut when we hold it, and REMEMBER `(bid ->
PeerId)` so the repair asks the right peer first. Verified only against the
chain (the chain path stays the authority, exactly as now).

### 3.4 Backfill after (re)connect

On `PeerEventFn(pid, connected=true)` + HELLO accepted:
* **re-offer (sender side)**: re-send our last `--relay-reoffer-seconds` (60 s) of
  admitted receipts to the new peer (a shallow sub-view over the vault, like
  `w3_relay.hpp §RE-OFFER`); the receiver dedups.
* **catch-up (receiver side)**: `SupplyRequester::request_order(pid, chain, a =
  max(0, peer.lane_next_pos - N), p = peer.lane_next_pos, spine = 0, max_ids)`
  with `N = --relay-backfill-positions` (default 2048); from the ORDER answer,
  fetch the ids NOT in our seen-set with `request_frames` (<= 64 per fetch,
  continuation cursor as designed), verify each `id == cheap_receipt_id(blob)`
  (the `IdOfFrameFn` seam), then run §3.2 steps 1-7 on each (RandomX metered by
  a separate, larger "solicited" bucket: we asked for these bytes).
* Positions in GETORDER are the SERVING peer's positions (node-local under
  Ruling A); we use them only to enumerate ids, never to place our own pushes.

### 3.5 Settlement fold — what replaces `feed_log`

`book_from_chain` (`main_v37_xmr.cpp:1158-1231`) and `fold_at_cut` (`:1137-1156`)
are unchanged. Only `replay_view` (`:1097-1136`) changes its SOURCE:

1. try our own vault by position: if our order over [0,P) exists and our recorded
   `(P -> lane digest)` equals `spine` -> replay our own frames (no fetch).
2. else `GETORDER(chain, 0, P, spine)` to the block-won sender first, then every
   peer; a peer whose `have_spine=1 && spine_digest == spine` serves; others are
   skipped (`SupplyService::set_spine_probe` answers from the ingest's
   `pos -> digest` record, §4.2).
3. `GETFRAMES` for ids we lack; for every id derive the pushes: verified-cache
   hit -> `{payee, w, d}` with no hashing; miss -> full §3.2 admission (RandomX).
4. scratch `V37Engine`: `add_lane(cfg.lane_chain, cfg.lane_params)`, then the
   pushes in the SERVED order; `settlement_view_by_cut(chain, P, spine)`; a
   reachable-but-different digest is `cut_mismatch` (fail-closed), a short serve is
   `cut_pending` (retry) — the same three outcomes the code has today.
5. bound: only while position 0 is inside the server's vault horizon (8640
   positions, `frame_vault.hpp:41-49`); past it the repair REFUSES (as btc-dash).
   Stated, not hidden; see §9 stage 4.

## 4. Node internals (new files, all under `src/c2pool/v37/xmr/relay/`)

### 4.1 Threads and the RandomX instance

* `CarrierPeerNode` reader threads (one per peer): decode header, HELLO gate,
  control frames -> `SupplyService/SupplyRequester::on_control` directly (as
  designed); receipt frames -> bounded per-peer inbound queue (drop-oldest,
  counted) -> ONE **relay-verify worker** thread.
* The relay-verify worker owns its OWN `LightVerifier` (+256 MiB RSS, +256 MiB
  transiently at epoch rollover; `randomx_init_lock` already serialises inits
  against the stratum verifier and the `--mine` miner). Seeds: prefetch on every
  new template (`seed_hash`, `next_seed_hash` are in `TemplateJob`), plus
  `seed_for_bin(bin)` via `MainchainIndex::seed_hash_for_height` (`:222`) for
  backfilled receipts of an older epoch. Rationale for a second instance: a
  receipt flood must never delay a miner's submit on the listener thread. Cost:
  ~24.5 ms per foreign receipt (measured), i.e. ~40 hashes/s/core ceiling;
  honest 3-node load is well under 1/s.
* Ingest (§4.2) runs on the verify worker under one mutex (admit -> pushes ->
  `submit_tracked(...).get()` -> record digest -> vault -> flood), preserving the
  `carrier_ingest.hpp:20-33` invariant (no interleaving of one receipt's pushes
  with another's).
* Main thread keeps the fold path, template refresh, block-won handling, and a
  1-s tick: redial of `--relay-peer` targets with backoff (1 s .. 60 s), reoffer
  sweep, `SupplyRequester::tick`.

### 4.2 `xmr_receipt_ingest.hpp`

* `admit(receipt, side_v2, payee, from_peer) -> Outcome` (the §3.2 order via
  `LaneEnv`), then `receipt_pushes` (PR #1710 split: miner `w_miner`, donation
  `w_donation`; `d = 0` -> one push) -> `LaneRecord::push(chain, PayoutDescriptor{
  payee}, w, L0F_RECEIPT?)` — flags exactly as the feed path uses today (`0`), to
  keep the record stream byte-identical to the stand-in for a given order.
* after each tracked submit: `snapshot(chain)->{next_pos, digest}` appended to a
  bounded `pos -> digest` map (the spine probe and step 1 of §3.5).
* `FrameVault::admit(chain, receipt_id, pos_first, n_pushes, frame_bytes)` where
  `frame_bytes` = the single `fb_receipt` encoding (so GETFRAMES serves exactly
  what §3.4 verifies).
* verified cache: `receipt_id -> {payee, t_origin, d, bin}` bounded to the vault
  horizon; durable append-only file `<data-dir>/lane<chain>.receipts` (one
  `fb_receipt` per record) replaces `lane<chain>.pushes`; reloaded at boot into
  the vault + cache WITHOUT re-hashing (we verified them before) and re-pushed in
  file order (our own historical order).

### 4.3 `xmr_receipt_mint.hpp`

From `AcceptedShare` + `BlockCandidate`: `full_blob` -> `parse_block` (native
consensus parser gives `miner_tx_offset/size`) -> tx-prefix bytes and the
`extra_start` offset (walk `version, unlock, vin, vout` with the existing
prefix parser in `native/consensus/xmr_tx_weight.hpp:278-370`) ->
`build_coinbase_opening`; `other_leaves` = the tx hashes in `full_blob`'s tail;
header fields from `hashing_blob`; `side_data_v2 = {t_origin = share_diff,
identity(payee), chain_id, d}` with the payee = `mint_receipt(...)` (owner roll
at mint, PR #1710 semantics, unchanged) -> `build_v37_receipt`-equivalent with
the v2 binding -> `fb_receipt`. The template must have written `rbind` for that
extra_nonce (§5); the mint asserts it by running its own structural check.

### 4.4 Local ordering policy (`--relay-order canonical|arrival`, default canonical)

Not a consensus rule: each node still pushes in its OWN order and the winner's
cut stays the authority. Policy: hold admitted receipts of bin `b` in a per-bin
pending set; when our index tip reaches `b + L` (`--relay-bin-lag L`, default 1,
i.e. the next Monero block), push bin `b` sorted by `receipt_id`. Two nodes
holding the same SET for bin `b` then publish the same prefix digest, so
`fold_at_cut` hits their own ring and no repair runs. Late arrivals for an
already-pushed bin are pushed at the tail (arrival) and are the residual case
the §3.5 repair covers. `arrival` = today's semantics (push on admit). Trade:
one block (~2 min regtest-tunable) of crediting latency for near-zero repair
traffic. **Ruling owed (OQ-1): default policy + L.**

## 5. Template / mint side (SEAM-1 in detail — hand over, do not edit)

* `IXmrSettlementSource` gains `virtual std::array<u8,32> worker_binding(uint32_t
  extra_nonce) const { return {}; }` (default zeros = today's bytes for every
  implementer that does not override — same pattern as `extra_nonce_tail()`).
* `XmrBlockTemplate`: the per-worker mutable region in the 0x02 payload widens
  from 4 to 36 B (`m_extraNonceSize`), patched in-place per extra_nonce next to
  the nonce (`.cpp:313-345`). Weight +32 constant; the credit-cut tail stays
  last; `merkle_root_offset` shifts by 32.
* `xmr_coinbase.cpp:277 assemble_tx_extra`, `canonical_coinbase_matches`, the
  shape gate (`xmr_settlement_coinbase_shape.hpp` property 2 CANONICAL) and the
  coinbase goldens (`xmr_coinbase_kat`, `xmr_goldens_kat`, `v37_xmr_credit_cut_kat`,
  `xmr_e2e_kat`) move together — this is the W3 every-node ACCEPT check on
  blocks, i.e. block-level consensus for the lane. Operator's hand.
* The settlement provider registers `extra_nonce -> rbind` from the stratum
  login table (login address -> payee ref, node give-author `d`) at job issue
  (`xmr_o2_settlement_provider.hpp:358-372 fill_job`).

## 6. Flags (all networks except where noted; mainnet keeps the existing fence for the stand-ins)

```
--relay-listen HOST:PORT       bind the receipt relay (default: off)
--relay-peer HOST:PORT         dial a peer (repeatable; redial with backoff)
--relay-max-peers N            inbound+outbound cap (default 8)
--relay-index-horizon N        oldest admissible receipt bin, in blocks behind tip (default 64)
--relay-rx-budget P,C,G,GC     per-peer refill/s, cap, global refill/s, cap (default 1,20,16,256)
--relay-solicited-credits N    extra RandomX tokens for frames WE fetched (default 256)
--relay-backfill-positions N   GETORDER depth on connect (default 2048)
--relay-reoffer-seconds S      sender-side re-offer window (default 60)
--relay-order canonical|arrival, --relay-bin-lag L          (§4.4)
--relay-vault-entries N / --relay-vault-bytes N / --relay-vault-horizon N   (FrameVault bounds)
--no-relay-serve               do not answer GETORDER/GETFRAMES (dial-only observers)
```
`--relay-*` and `--credit-feed/--wire-*` are mutually exclusive (REFUSED at
start). The stand-ins stay for the existing KATs/rigs.

## 7. KATs (new; names follow the tree's `v37_xmr_*_kat` / `xmr_*_kat` idiom)

1. `xmr_relay_wire_kat` (`src/impl/xmr/test/`, RandomX-free): goldens for
   0x40/0x41/0x42; total/bounded decode under truncation, oversize `n`, oversize
   `len`; first-byte non-collision with `kAcceptedVersions` and `>= 0x80`.
2. `xmr_receipt_bind_v2_kat`: `side_data_v2` digest golden; a regtest coinbase
   built by `XmrBlockTemplate` with `worker_binding` set -> mint -> accept;
   tamper payee / `d` / `t_origin` / extra_nonce -> reject at Structural BEFORE
   RandomX (`spent_randomx == false`); RandomX stage CI-gated
   (`SkippedCIGated`) and REAL under `XMR_BUILD_RANDOMX`.
3. `v37_xmr_relay_3node_kat`: three in-process nodes over loopback
   `CarrierPeerNode` (shape of `v37_a2_multinode_test`), synthetic `rx_verify`
   fake: HELLO gate (mismatched share_diff is dropped with the reason), flood +
   dedup (each receipt admitted once per node, relayed to exactly n-1 peers),
   disconnect B, mint on A and C, reconnect -> re-offer + GETORDER/GETFRAMES
   backfill -> identical receipt SETS on all three; under `canonical` identical
   lane digests at every bin boundary.
4. `v37_xmr_relay_repair_kat`: under `arrival` order with a forced permutation,
   a block-won cut from A at P; C misses one receipt; C's `replay_view` repairs
   via A's ORDER + FRAMES and produces `fold_eb` byte-equal to A's credit map;
   a peer serving a tampered frame -> whole response rejected, `cut_pending`,
   never a wrong fold.
5. `v37_xmr_relay_dos_kat`: structurally valid below-target receipts from one
   peer -> at most `cap` RandomX spends, then BAN; oversize frame -> socket
   drop; unknown `0x4f` -> counted, socket kept; old peer sending `0x02` ->
   counted, socket kept.
6. Rig (not CI; the #1697 cluster-soak shape): one `monerod --regtest`
   (44900..), three `c2pool-v37-xmr --network regtest --coinbase v37-settlement
   --relay-listen/--relay-peer --mine` on separate `--data-dir`s, stratum
   5790-5792, relay 45000-45002; generate blocks; assert equal `owed_digest`
   lines after each SETTLED height, kill/restart one node mid-run, assert
   re-convergence. Binary-identical to today's soak assertions.

## 8. Consensus-canon seams (STOP points; hand the operator the seam)

| # | seam | why it is consensus | what stage 1 does |
|---|---|---|---|
| SEAM-1 | coinbase 0x02 region `[nonce 4 | rbind 32]` (§5) | block bytes; every node's CANONICAL accept check + goldens | specify + KAT harness; the template/coinbase edits are handed over |
| SEAM-2 | `side_data_v2` digest domain + XMR lane `per_receipt_budget 768 -> 1024` | `LaneKeyedHeavy` is documented digest-committed-by-intent (`xmr_admission.hpp:63-72`); with the rbind + credit-cut tail a max receipt is ~835 B > 768 | new header, new domain string; v1 untouched; ratification owed |
| SEAM-3 | pushes per receipt `{miner, donation}` and the `d` u16 in the PoW-bound side data | lane record stream = `owed_digest` input; this IS PR #1710's S3 | consumes #1710's `receipt_pushes`; stage 1 rebases onto #1710 |
| SEAM-4 | `LaneParams` equality via `lane_params_digest` in HELLO | no canon edit (reads `cfg.lane_params`), but it decides who may talk | new code; the canonical field serialisation is ours, pinned by KAT |
| SEAM-5 | `replay_view` source swap (`feed_log` -> vault/ORDER) in `main_v37_xmr.cpp:1097-1136` | not `src/sharechain/v37`, but it is the W4 fold's input; `fold_eb` call byte-identical | the one existing-file edit in the daemon besides flags/wiring |
| OQ-1 | local ordering policy default + bin lag (§4.4) | not consensus (Ruling A stands); operational default | ruling owed |
| OQ-2 | seed policy for backfilled receipts of an older epoch (`DerivedFromBin`, 0 B) | admission param | default kept; needs `seed_hash_for_height` on both arms |

`src/sharechain/v37/*` is not touched anywhere in this design.

## 9. Staged plan

* **Stage 1 (now)** — files: `xmr/relay/xmr_relay_wire.hpp`, `xmr_receipt_side_v2.hpp`,
  `xmr_receipt_mint.hpp`, `xmr_receipt_ingest.hpp`, `xmr_relay_node.hpp`,
  `xmr_relay_repair.hpp`, `carrier_supply.hpp` `IdOfFrameFn` seam (default
  unchanged), `main_v37_xmr.cpp` flags + wiring (relay replaces feed/wire when
  `--relay-*`), KATs 1-5, rig 6; SEAM-1/2/3 handed over with the harness green
  under a test `IXmrSettlementSource` that overrides `worker_binding`.
* **Stage 2 — DoS hardening**: persistent ban list keyed by IP with decay
  (`xmr_peer_store.hpp` idioms), per-IP connection cap and inbound accept
  budget, HELLO proof-of-work or pre-shared cookie for inbound on public
  listeners, inbound queue fairness (per-peer round-robin into the verify
  worker), receipt-rate ceiling per peer derived from share_diff and the
  peer's advertised hashrate, `/relay_stats`.
* **Stage 3 — peer discovery**: HELLO carries a bounded peer list (addr, port,
  last_seen) + white/gray/anchor tiers (reuse `xmr_peer_store.hpp` shape), DNS
  seeds per network, `--relay-seed`, netgroup cap (`xmr_dial_plan.hpp` logic).
* **Stage 4 — roundabout partitioning**: per-roundabout lanes/chains with a
  windowed digest so the [0,P) replay bound becomes O(window) and the vault
  horizon stops being a liveness cliff (ties to the dynamic-window design of
  record); FB_HELLO advertises served roundabouts; GETORDER per roundabout.

## 10. Honest bounds

* RandomX: 24.5 ms median per foreign receipt (light mode, measured); one
  extra 256 MiB cache per relay verifier; epoch rollover costs ~0.7 s of init on
  the verify thread (never the listener).
* Repair is a whole-prefix replay, bounded by the serving node's vault horizon
  (8640 positions) — same bound as btc-dash today; stage 4 lifts it.
* Backfill admits receipts up to `--relay-index-horizon` blocks old (~2 h at
  64); an outage longer than that leaves a set difference that only the repair
  path (winner order) can reconcile at fold time.
* The stand-in (`--credit-feed`) gave a global total order for free; the relay
  gives node-local order + winner authority. Convergence of `owed_digest` is
  preserved by the fold-at-cut + repair gate, exactly as Ruling A states; the
  LIVE lane digests may differ across nodes and that is by design.

## 11. Stage-1 implementation notes (as built on this branch)

Files: `src/c2pool/v37/xmr/relay/{xmr_relay_wire,xmr_receipt_mint,xmr_relay_node,xmr_receipt_ingest,xmr_address}.hpp`;
additive seams in `carrier_net.hpp` (pid-tagged inbound, `add_peer_id`, `disconnect`), `carrier_supply.hpp`
(`IdOfFrameFn`), `impl/xmr/stratum/xmr_stratum.hpp` + `xmr_stratum_listener.hpp` (`seed_extra_nonce`), and the
daemon wiring in `main_v37_xmr.cpp` (flags, mint hook, FB_BLOCK_WON, `relay_view` = SEAM-5). Rig scripts:
`docs/xmr-lane/gap2-rig/`.

Deviations from §3-§6, each found by the rig:

* **Per-node extra_nonce base.** Three nodes with the same tip, the same owed ledger and a stratum
  extra_nonce counter that starts at 0 hand their miners byte-identical blobs; the miners duplicate work and
  the same receipt id gets minted with different payees on different nodes -- F1's silent fork, observed
  (run 1: `repair-rejected` climbing, cursor stalled). Stage 1 seeds each node's counter from a random base in
  `[2^24, 2^31)` (not consensus: the pool chooses those 4 bytes). SEAM-1 (`rbind`) removes the cause for good.
* **Receipt context by RPC, once per tip.** A restarted or lagging node must resolve peers' receipts on blocks
  its in-memory index never held; the daemon arm now notes the last 128 headers
  (`get_block_headers_range`) + the cached RandomX seed block into the relay ChainView on every new tip.
* **`--relay-bind none` is the only mode today's template can serve.** Receipts are PoW-verified (opening ->
  tree_root -> RandomX >= share_diff) and dedup-keyed on the blob; the payee/give-author are carried, not
  PoW-bound. The relay is therefore REFUSED on mainnet until SEAM-1. `rbind` verification is implemented and
  KAT-pinned against a SEAM-1-layout coinbase.
* **`--relay-test-partition-seconds S`** (rig only): SIGUSR1 drops every relay link for S seconds while the
  node keeps mining; the reconnect exercises re-offer, GETORDER/GETFRAMES backfill and the winner-order repair.

Finding outside GAP-2 (in code this branch does not touch; it runs at boot before the relay starts; NOT yet
reproduced on a stand-in build): restarting a node after the chain advanced past its persisted
`hw_height` boots with `UNRECOVERABLE PENDING` (the finalize cursor steps past sidecar-pending FOUNDs before
`reseed_after_bring_up` runs), after which the node stays `lane-root-unknown` for every later lane block.
Reproduced twice with the relay (runs 2 and 3); the relay itself reloaded the durable log, backfilled and
repaired. Owner: the finalize-connect boot order, not this branch.
