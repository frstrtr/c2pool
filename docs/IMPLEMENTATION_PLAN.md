# c2pool → frstrtr/p2pool-merged-v36 Compatibility Implementation Plan

## Goal
Make c2pool (C++20/Boost ASIO, `service-update` branch) fully interoperable with
`frstrtr/p2pool-merged-v36` on the Litecoin p2pool network.

## Reference: p2pool-merged-v36 LTC network constants
```
SHARE_PERIOD         = 15 seconds
CHAIN_LENGTH         = 8640 shares  (24*60*60 // 10)
REAL_CHAIN_LENGTH    = 8640 shares
TARGET_LOOKBEHIND    = 200 shares
SPREAD               = 3 blocks
IDENTIFIER           = e037d5b8c6923410   (8 bytes, big-endian)
PREFIX               = 7208c1a53ef629b0   (8 bytes, big-endian, framing)
P2P_PORT             = 9338
MIN_TARGET           = 0
MAX_TARGET           = 2**256//2**20 - 1
MINIMUM_PROTOCOL_VERSION = 3301
SEGWIT_ACTIVATION_VERSION = 17
BLOCK_MAX_SIZE       = 1000000
BLOCK_MAX_WEIGHT     = 4000000
SOFTFORKS_REQUIRED   = {bip65, csv, segwit, taproot, mweb}
BOOTSTRAP_ADDRS      = [ml.toom.im, usa.p2p-spb.xyz, 102.160.209.121,
                         5.188.104.245, 20.127.82.115, 31.25.241.224,
                         20.113.157.65, 20.106.76.227, 15.218.180.55,
                         173.79.139.224, 174.60.78.162]
```

---

## Phase 1 — Protocol Correctness  (**START HERE**)

### Step 1.1 — Fix `handle_version` in `src/impl/ltc/node.cpp`
**Problem:** After receiving a peer's version message we never send our own version
back, so the remote peer's handshake never completes.
**Fix:**  
- After storing `peer->m_nonce`, construct and send `message_version::make_raw(…)`
  back to `peer`.
- Send `message_getaddrs::make_raw(8)` to bootstrap our addr table.
- If `msg->m_best_share` is non-null, call `processing_shares` via a download
  request so we sync from that peer's head.
- Detect protocol version ≥ 3301 and set `PeerConnectionType::legacy` vs `::actual`
  (all frstrtr nodes speak `legacy` protocol; `actual` is only c2pool-to-c2pool).

### Step 1.2 — Wire `ReplyMatcher` for `sharereq`/`sharereply` in `src/impl/ltc/`
**Problem:** `HANDLER(sharereply)` receives shares but never resolves the async
caller — DownloadShareManager calls to `request_shares()` hang forever.
**Fix:**
- Add to `NodeImpl`:
  ```cpp
  using share_getter_t = ReplyMatcher::ID<uint256>
      ::RESPONSE<std::vector<ltc::ShareType>>
      ::REQUEST<uint256, peer_ptr, std::vector<uint256>,
                uint64_t, std::vector<uint256>>;
  share_getter_t m_share_getter;
  ```
- `NodeImpl(ctx, config)` ctor: initialise `m_share_getter` with a lambda that
  builds and writes `message_sharereq::make_raw(id, hashes, parents, stops)`.
- Add public method `request_shares(id, peer, hashes, parents, stops, callback)`.
- In `HANDLER(sharereply)`: call `m_share_getter.got_response(msg->m_id, result)`.

### Step 1.3 — Implement `HANDLER(bestblock)` in `src/impl/ltc/protocol_legacy.cpp`
**Problem:** Empty body — new block notifications don't trigger work refresh.
**Fix:** Store new best block on coin node; signal miner work refresh.

### Step 1.4 — Add LTC network constants to `src/impl/ltc/config_pool.hpp`
**Problem:** All constants are commented-out TODOs — node can't bootstrap.
**Fix:**
- Add static constexpr constants (SHARE_PERIOD, CHAIN_LENGTH, PREFIX, IDENTIFIER,
  P2P_PORT, MAX_TARGET, SOFTFORKS_REQUIRED, BOOTSTRAP_ADDRS).
- Update `get_default()` to write the correct LTC prefix (`7208c1a53ef629b0`)
  and bootstrap addresses into the default YAML.
- Add `m_bootstrap_addrs` runtime field; populate from YAML with fallback to static
  list; call `m_addrs.load(bootstrap_addrs)` inside `BaseNode` ctor / `init()`.

---

## Phase 2 — Work Generation

### Step 2.1 — Poll `getblocktemplate` in `src/impl/ltc/coin/rpc.hpp`
- Add a periodic timer (every ~1 s) that calls `getblocktemplate`.
- Store result in `CoinNode`; expose `current_template()`.

### Step 2.2 — Implement `getwork` / `mining_subscribe` in `src/core/web_server.cpp`
- Replace placeholder `uint256::ZERO` / hardcoded target with real template data.
- For Stratum: implement `mining.subscribe`, `mining.authorize`, `mining.notify`
  using the block template from Step 2.1.

### Step 2.3 — Implement `submitblock` in `src/core/web_server.cpp`
- Reconstruct block from miner's submitted work.
- Call coin RPC `submitblock` or `getblocktemplate` with `modeval=submit`.
- On success, broadcast `message_bestblock` to all connected p2pool peers.

---

## Phase 3 — PPLNS Sharechain Payouts

### Step 3.1 — Wire `SharechainStorage` into `NodeImpl::processing_shares`
- `processing_shares` currently only adds to in-memory `m_chain`.
- After `m_chain->add(share)`, also call `m_storage->add(share)`.
- On startup, call `m_storage->load_recent(CHAIN_LENGTH)` to restore shares.

### Step 3.2 — Implement PPLNS coinbase construction in `PayoutManager`
- Walk the share chain back `REAL_CHAIN_LENGTH` shares from head.
- Compute miner weights using `prefsum_weights.hpp`.
- Build the coinbase transaction with proportional outputs.
- Integrate with `getblocktemplate` result (coinbase value, fees).

### Step 3.3 — Dev fee integration
- PayoutManager already has dev fee configuration.
- Wire dev fee address into coinbase outputs after PPLNS weights.

---

## Phase 4 — DownloadShareManager Bootstrap

### Step 4.1 — Implement `DownloadShareManager`
- On `handle_version` when peer announces `best_share`:
  - If hash is unknown: send `message_sharereq` for that hash + N parents.
  - Use `m_share_getter.request(...)` from Step 1.2.
  - In the response callback: call `processing_shares`; recurse if there are
    more unknown parents up to `CHAIN_LENGTH`.
- Stop recursion when: `m_chain->get_height()` ≥ `CHAIN_LENGTH` OR all parents
  are already known.

---

## Phase 5 — Build + Integration Test

### Step 5.1 — Fix build
- Ensure all new code compiles: `cd build && cmake .. && make -j$(nproc)`.
- Address any missing includes / CMakeLists.txt entries.

### Step 5.2 — Testnet connectivity test
- Run c2pool with `--sharechain` on LTC testnet.
- Confirm TCP connections to bootstrap nodes succeed (tcpdump / logs).
- Confirm version message exchange happens (check logs for "stable connection").
- Confirm shares are received and added to chain.

---

## Current Status

| Phase | Step | Status |
|-------|------|--------|
| 1 | 1.4 LTC network constants | ⬜ TODO |
| 1 | 1.2 ReplyMatcher wiring    | ⬜ TODO |
| 1 | 1.1 handle_version fix     | ⬜ TODO |
| 1 | 1.3 bestblock handler      | ⬜ TODO |
| 2 | 2.1 getblocktemplate poll  | ⬜ TODO |
| 2 | 2.2 mining_subscribe       | ⬜ TODO |
| 2 | 2.3 submitblock            | ⬜ TODO |
| 3 | 3.1 SharechainStorage wire | ⬜ TODO |
| 3 | 3.2 PPLNS coinbase         | ⬜ TODO |
| 3 | 3.3 Dev fee coinbase       | ⬜ TODO |
| 4 | 4.1 DownloadShareManager   | ⬜ TODO |
| 5 | 5.1 Build fix              | ⬜ TODO |
| 5 | 5.2 Testnet test           | ⬜ TODO |
