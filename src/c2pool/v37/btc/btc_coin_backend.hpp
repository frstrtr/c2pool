// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/btc_coin_backend.hpp  (Track A2 / Milestone A-BTC — v36 seam)
//
// ICoinBackend — the SEAM between the v37 BTC-family node lifecycle and the
// MATURE v36 coin plumbing. It names EXACTLY the four v36 operations the v37
// node consumes, and NOTHING ELSE. We WIRE the v36 adapter; we do not rewrite
// it (HARD SAFETY 5). Each pure-virtual documents the concrete v36 symbol its
// production binding delegates to.
//
// THE FOUR OPERATIONS (and their v36 bindings) ------------------------------
//   best_tip()      — the coin mainchain view: (height, block-hash) of the
//                     best chain. DASH: dash::coin::chain_rpc getbestblockhash
//                     + HeaderChain::tip()->{height,hash} (embedded-SPV,
//                     daemonless, src/impl/dash/coin/chain_rpc.hpp +
//                     header_chain.hpp). LTC testnet4: getbestblockhash /
//                     getblockchaininfo RPC.
//   is_canonical()  — the reorg predicate the F1 driver asks at maturity:
//                     does the best chain still carry `bid` at `height`? DASH:
//                     dash::coin::chain_rpc getblockhash <h> == bid
//                     (HeaderChain::get_header_by_height). LTC: getblockhash RPC.
//   block_reward()  — the subsidy at a height, for the W5 native coinbase's
//                     block_reward argument. DASH: dash::coin::subsidy (the
//                     creditPool-aware subsidy, src/impl/dash/coin/subsidy.hpp).
//                     LTC: GetBlockSubsidy halving schedule.
//   submit_block()  — hand an assembled full-block hex to the coin network.
//                     DASH: the daemonless critical path is ARM A
//                     CoinClient::submit_block_p2p_raw (embedded coin-P2P
//                     relay) with ARM B NodeRPC::submit_block_hex (submitblock
//                     RPC backup) — see dash::coin::won_block_dispatch
//                     (won_block_dispatch.hpp) fed by
//                     dash::coin::reconstruct_won_block. LTC: submitblock RPC.
//
// The STRATUM front-end is a SEPARATE v36 seam (core::stratum::IWorkSource +
// core::StratumServer, src/core/stratum_work_source.hpp): the BTC-family node
// hands the v36 BTCWorkSource / DASHWorkSource straight to a core::StratumServer
// and lets IWorkSource::mining_submit classify PoW ≤ block target → submit. The
// node's role is only to feed that work source the current template and to bind
// its block-found callback to build the W5 coinbase + call submit_block() here.
// So the WORK/TEMPLATE half is NOT in ICoinBackend — it lives in the v36 work
// source; ICoinBackend carries the mainchain-view + subsidy + submit half the
// F1 driver and the coinbase path need.
//
// Header-only, STL-only. The MockCoinBackend below is the LOCAL smoke backend
// (HARD SAFETY 6: heavy/full DASH+LTC builds are CI-only; locally we smoke
// against this mock). DashCoinBackend / LtcCoinBackend are the production
// bindings — declared here as GAP stubs with their exact delegation cited, to
// be filled in the follow-on that links the heavy v36 coin libraries under CI.
// ===========================================================================
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <sharechain/v37/v37_roundabout.hpp>   // ::v37::bytes32, ::v37::ChainId

namespace c2pool::v37n::btc {

// The coin mainchain view at one instant: best-chain height + block hash.
struct CoinTip {
    std::uint64_t  height = 0;
    std::string    hash;      // display-hex block hash (the F1 driver's bid space)
    ::v37::bytes32 id{};      // the 32-byte hash, for SettleHW::advance(best_id)
};

// The disposition of a submit_block(): whether the coin network accepted it.
struct SubmitResult {
    bool        accepted = false;   // accepted OR duplicate == success
    bool        armed    = false;   // a submit sink was actually wired (fired)
    std::string reason;             // loud cause on neither-accept (telemetry #987)
};

class ICoinBackend {
public:
    virtual ~ICoinBackend() = default;

    // (1) mainchain view — best chain tip. Polled by the node's height-watch
    //     loop; every advance feeds BtcFinalizeDriver::advance_to_tip().
    virtual CoinTip best_tip() = 0;

    // (2) reorg predicate — is `bid` still the canonical block at `height`?
    //     Bound into BtcFinalizeDriver's CanonicalFn.
    virtual bool is_canonical(std::uint64_t height, const std::string& bid) = 0;

    // (3) subsidy — the block reward at `height`, for the W5 coinbase.
    virtual std::uint64_t block_reward(std::uint64_t height) = 0;

    // (4) submit — hand a full-block hex to the coin network (ARM A + ARM B).
    virtual SubmitResult submit_block(const std::string& block_hex) = 0;

    // Human tag for logs.
    virtual const char* name() const = 0;
};

// ---------------------------------------------------------------------------
// MockCoinBackend — the LOCAL smoke backend. A scripted, reorg-injectable coin
// mainchain: append_block() extends the chain, reorg_to() rolls it back and
// re-forges from a fork point (the controlled falsifier's reorg drill). No coin
// daemon, no PoW, no network — everything the DASH-regtest demo needs to prove
// the v37 lifecycle end to end without linking the heavy v36 coin libs.
// ---------------------------------------------------------------------------
class MockCoinBackend final : public ICoinBackend {
public:
    explicit MockCoinBackend(std::uint64_t fixed_reward = 5000000000ULL /*50.00*/)
        : m_reward(fixed_reward) {}

    // Extend the best chain by one block with the given hash. Returns its height.
    std::uint64_t append_block(const std::string& hash) {
        std::uint64_t h = m_chain.size();      // genesis at height 0 implied
        m_chain.push_back(hash);
        m_by_hash[hash] = h;
        return h;
    }

    // Reorg: drop every block above `fork_height`, then append `new_tail` on top
    // of the survivor. Blocks dropped here fail is_canonical() at their old
    // height → the F1 driver orphans any found block among them.
    void reorg_to(std::uint64_t fork_height, const std::vector<std::string>& new_tail) {
        while (m_chain.size() > fork_height + 1) {
            m_by_hash.erase(m_chain.back());
            m_chain.pop_back();
        }
        for (const auto& h : new_tail) append_block(h);
    }

    CoinTip best_tip() override {
        CoinTip t;
        if (m_chain.empty()) return t;
        t.height = m_chain.size() - 1;
        t.hash   = m_chain.back();
        t.id     = hash_to_id(t.hash);
        return t;
    }

    bool is_canonical(std::uint64_t height, const std::string& bid) override {
        if (height >= m_chain.size()) return false;
        return m_chain[height] == bid;
    }

    std::uint64_t block_reward(std::uint64_t /*height*/) override { return m_reward; }

    SubmitResult submit_block(const std::string& block_hex) override {
        SubmitResult r;
        r.armed = true;
        r.accepted = !block_hex.empty();       // mock: any non-empty block "accepted"
        m_submitted.push_back(block_hex);
        if (!r.accepted) r.reason = "mock: empty block hex";
        return r;
    }

    const char* name() const override { return "mock"; }

    // smoke introspection
    const std::vector<std::string>& submitted() const { return m_submitted; }

private:
    // A stable 32-byte id from the hash string (smoke only — the real backend
    // carries the true block hash bytes).
    static ::v37::bytes32 hash_to_id(const std::string& s) {
        ::v37::bytes32 b{};
        for (std::size_t i = 0; i < s.size() && i < 32; ++i)
            b[i] = static_cast<std::uint8_t>(s[i]);
        return b;
    }
    std::uint64_t            m_reward;
    std::vector<std::string> m_chain;      // index == height
    std::map<std::string, std::uint64_t> m_by_hash;
    std::vector<std::string> m_submitted;
};

// ---------------------------------------------------------------------------
// DashCoinBackend / LtcCoinBackend — PRODUCTION bindings (GAP: CI-only, links
// the heavy v36 coin libs). Declared here with their exact delegation so the
// follow-on is a fill-in, not a design. Kept out of the local smoke TU per HARD
// SAFETY 6 (host OOM); see build.yml note — these compile on the CI leg that
// already links src/impl/dash and src/impl/ltc.
//
//   class DashCoinBackend final : public ICoinBackend {
//     // best_tip()     -> dash::coin::HeaderChain::tip() (embedded-SPV) with a
//     //                   dash::coin::chain_rpc getbestblockhash cross-check.
//     // is_canonical() -> dash::coin::HeaderChain::get_header_by_height(h)==bid
//     //                   (chain_rpc getblockhash <h>).
//     // block_reward() -> dash::coin::subsidy (creditPool-aware).
//     // submit_block() -> dash::coin::won_block_dispatch: ARM A
//     //                   CoinClient::submit_block_p2p_raw + ARM B
//     //                   NodeRPC::submit_block_hex (submitblock backup).
//     // (the full block hex comes from dash::coin::reconstruct_won_block fed the
//     //  W5 coinbase this node built — see btc_node.hpp on_block_won.)
//   };
//   class LtcCoinBackend final : public ICoinBackend {
//     // best_tip()/is_canonical()/block_reward() -> ltc daemon getblockchaininfo
//     //   / getblockhash / GetBlockSubsidy; submit_block() -> submitblock RPC.
//   };
// ---------------------------------------------------------------------------

} // namespace c2pool::v37n::btc
