// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH embedded live-feed bridge (E2a, #738) — translation-layer KATs.
///
/// live_feed.hpp turns the RAW dash::interfaces::Node wire events the E1 coin-
/// P2P client fires into the DERIVED events the ingest legs consume, using a
/// HeaderChain as the tip/height authority:
///   * tip_advance_from_chain()   — pure: builds the TipAdvance the embedded
///     template needs (prev height/hash, DGW next-work bits, MTP, addr versions)
///     off the header-chain tip; nullopt when the chain has no tip / can't
///     retarget yet, so the caller keeps the dashd fallback.
///   * wire_full_block_ingest()   — full_block -> (X11 hash -> header-chain
///     height) -> Node::block_connected, driving leg 3 (apply_block) + E2b UTXO.
///   * wire_header_ingest()       — new_headers -> HeaderChain::add_headers.
///
/// The header->tip->maintainer arm at scale is proven by the live smoke against
/// a testnet dashd (see PR); these KATs pin the pure/lookup translation logic
/// without a fully PoW-synced chain (set_dynamic_checkpoint registers a
/// hash->height entry the full_block lookup resolves against).
///
/// Compiles into the allowlisted test_dash_node_reception_wire target (second
/// TU; no new target, no workflow edit).

#include <gtest/gtest.h>

#include <impl/dash/coin/live_feed.hpp>
#include <impl/dash/coin/header_chain.hpp>
#include <impl/dash/coin/node_interface.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>   // compute_merkle_root (E2 finding A body↔header bind)
#include <impl/dash/coin/utxo_adapter.hpp>     // dash_txid

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <impl/dash/crypto/hash_x11.hpp>

#include <vector>

using dash::coin::HeaderChain;
using dash::coin::BlockType;
using dash::coin::BlockHeaderType;
using dash::coin::make_dash_chain_params_testnet;
using dash::coin::tip_advance_from_chain;
using dash::coin::wire_full_block_ingest;
using dash::coin::wire_header_ingest;

namespace {

// Dash testnet address versions (params.hpp) — the payee-encoding bytes the
// TipAdvance carries.
constexpr uint8_t DASH_TESTNET_PUBKEY_VER = 140;
constexpr uint8_t DASH_TESTNET_P2SH_VER   = 19;

BlockType make_block(uint8_t seed) {
    BlockType b;
    b.m_version        = 0x20000000u | seed;
    b.m_previous_block.SetHex("00");
    b.m_timestamp      = 1'700'000'000u + seed;
    b.m_bits           = 0x1e0ffff0u;
    b.m_nonce          = 0x12340000u + seed;
    // A minimal coinbase so the body binds to the header (E2 finding A: the
    // bridge now verifies the tx set folds to the committed merkle root before
    // firing block_connected). A real P2P block always carries a coinbase.
    dash::coin::MutableTransaction cb;
    cb.version = 1; cb.type = 0; cb.locktime = seed;
    ::bitcoin_family::coin::TxIn in;
    in.prevout.hash = uint256::ZERO; in.prevout.index = 0xffffffffu;
    in.sequence = 0xffffffffu;
    cb.vin.push_back(in);
    b.m_txs.push_back(cb);
    std::vector<uint256> ids;
    for (const auto& tx : b.m_txs) ids.push_back(dash::coin::dash_txid(tx));
    b.m_merkle_root = dash::coin::compute_merkle_root(ids);
    return b;
}

uint256 x11_of(const BlockType& b) {
    auto packed = ::pack(static_cast<const BlockHeaderType&>(b));
    return ::dash::crypto::hash_x11(packed.get_span());
}

// ── tip_advance_from_chain: nullopt gates ─────────────────────────────────

TEST(DashLiveFeedBridge, TipAdvanceNulloptOnEmptyChain) {
    HeaderChain chain(make_dash_chain_params_testnet());
    chain.init();
    // Only the genesis stub is seeded (height 0) — next_work_required needs
    // >= 24 headers, so it returns 0 and tip_advance_from_chain declines,
    // keeping the caller on the dashd fallback.
    auto ta = tip_advance_from_chain(chain, DASH_TESTNET_PUBKEY_VER,
                                     DASH_TESTNET_P2SH_VER);
    EXPECT_FALSE(ta.has_value());
}

// ── wire_full_block_ingest: header present -> block_connected(block, height) ─

TEST(DashLiveFeedBridge, FullBlockFiresBlockConnectedWithChainHeight) {
    HeaderChain chain(make_dash_chain_params_testnet());
    chain.init();

    auto block = make_block(7);
    const uint256 hash = x11_of(block);
    // Register the block's identity at a known height WITHOUT PoW (the bridge
    // only needs the height lookup; a real chain gets it from add_headers).
    chain.set_dynamic_checkpoint(1000, hash);

    ::dash::interfaces::Node node;

    int fired = 0;
    uint32_t got_height = 0;
    uint256  got_prev;
    auto sub_probe = node.block_connected.subscribe(
        [&](const ::dash::interfaces::BlockConnected& bc) {
            ++fired;
            got_height = bc.height;
            got_prev   = bc.block.m_previous_block;
        });

    auto sub_bridge = wire_full_block_ingest(node, chain);

    node.full_block.happened(block);

    EXPECT_EQ(fired, 1);
    EXPECT_EQ(got_height, 1000u);
    EXPECT_EQ(got_prev, block.m_previous_block);
}

// ── wire_full_block_ingest: header ABSENT -> no block_connected (deferred) ───

TEST(DashLiveFeedBridge, FullBlockUnknownHeaderIsDeferred) {
    HeaderChain chain(make_dash_chain_params_testnet());
    chain.init();

    auto block = make_block(9);   // never registered in the chain

    ::dash::interfaces::Node node;
    int fired = 0;
    auto sub_probe = node.block_connected.subscribe(
        [&](const ::dash::interfaces::BlockConnected&) { ++fired; });
    auto sub_bridge = wire_full_block_ingest(node, chain);

    node.full_block.happened(block);

    // A block whose header is not yet in the chain is skipped — apply_block /
    // UTXO need the chain-position height; a later headers batch closes the gap.
    EXPECT_EQ(fired, 0);
}

// ── wire_header_ingest: empty batch is a no-op (never touches the chain) ─────

TEST(DashLiveFeedBridge, HeaderIngestEmptyBatchNoOp) {
    HeaderChain chain(make_dash_chain_params_testnet());
    chain.init();
    const uint32_t h0 = chain.height();

    ::dash::interfaces::Node node;
    auto sub = wire_header_ingest(node, chain);

    node.new_headers.happened(std::vector<BlockHeaderType>{});
    EXPECT_EQ(chain.height(), h0);
}

} // namespace
