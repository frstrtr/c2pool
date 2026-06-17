#pragma once
// BCH block-template builder. Mirrors src/impl/btc/coin/template_builder.hpp,
// diverging where BCH consensus requires (M1 §4):
//   * No SegWit / witness commitment  -- txs serialize as a single canonical
//     form; txid == "hash" (no wtxid distinction). `rules` carries no segwit.
//   * CTOR (CHIP-2018-11)             -- block body txs are re-sorted into
//     canonical (ascending txid) order AFTER fee selection, coinbase excluded.
//   * ASERT (aserti3-2d, CHIP-2020-05)-- next-block bits come from the ASERT
//     DAA (asert.hpp), not BTC's 2016-block retarget.
//   * CashTokens (May 2023)           -- token-prefixed outputs are carried
//     transparently: they live in the tx bytes and round-trip unchanged.
//   * HogEx                           -- NOT applicable (SmartBCH; struck §4.2).
//
// Coinbase: like the BTC builder, this body does NOT assemble the coinbase tx
// itself -- it emits `coinbasevalue` + `height` and downstream share/work code
// builds the coinbase. The BCH coinbase scriptSig commitment (BIP34 height +
// "/c2pool/" + 32B state_root) is produced by bch::consensus (see
// ../coinbase_commitment.hpp, M3 s19); binding it into the coinbase builder is
// the next M4 slice in the work-source path, NOT here.
//
// PIN / VERIFY (vs VM300 bchn-bch + p2pool-merged-v36 python ref, staged next):
//   * block-size budget is sourced via abla.hpp (CHIP-2023-01): a caller-
//     supplied per-tip ABLA State (abla::replay over full-block sizes) raises
//     it dynamically, else the safe activation/floor limit (32 MB). The size
//     feed is a full-block/daemon-layer concern (M5+) -- the headers-only SPV
//     chain does not carry block sizes.
//   * `rules` array contents -- confirm against BCHN getblocktemplate output.

#include "header_chain.hpp"
#include "mempool.hpp"
#include "transaction.hpp"
#include "block.hpp"
#include "rpc_data.hpp"
#include "../coinbase_commitment.hpp"   // s19 seam (commitment built downstream)
#include "abla.hpp"                       // s2: ABLA block-size limit (CHIP-2023-01)
#include "abla_tracker.hpp"               // sC: live full-block size feed -> ABLA state

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>

#include <btclibs/util/strencodings.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace bch
{

namespace coin
{

// CoinNodeInterface -- ported from src/impl/btc/coin/template_builder.hpp.
//
// Abstract interface for obtaining work and submitting blocks. Allows swapping
// between RPC (legacy), embedded, or hybrid implementations without changing
// downstream code (share creation, Stratum, etc.). BCH carries the same shape
// as BTC: getwork() returns the coin-agnostic WorkData, submit_block() takes a
// BlockType (no MWEB extension on BCH).
class CoinNodeInterface {
public:
    virtual ~CoinNodeInterface() = default;

    /// Return a block template as WorkData.
    /// Throws std::runtime_error if no template can be produced.
    virtual rpc::WorkData getwork() = 0;

    /// Submit a found block.
    virtual void submit_block(BlockType& block) = 0;

    /// Return chain info (analogous to getblockchaininfo RPC).
    virtual nlohmann::json getblockchaininfo() = 0;

    /// True when the embedded chain is up to date with the network
    /// AND has enough UTXO depth for coinbase maturity validation.
    virtual bool is_synced() const { return false; }
};

// ─── BCH Subsidy ─────────────────────────────────────────────────────────────

/// BCH block subsidy in satoshis at a given height. BCH inherited Bitcoin's
/// emission verbatim: 50 BCH initial, halving every 210,000 blocks. Identical
/// to the BTC schedule (BCH forked at height 478,558 with the same curve).
/// Reference: BCHN src/validation.cpp GetBlockSubsidy().
inline uint64_t get_block_subsidy(uint32_t height) {
    static constexpr uint64_t COIN             = 100'000'000ULL;  // satoshis per BCH
    static constexpr uint64_t INITIAL_SUBSIDY  = 50ULL * COIN;    // 50 BCH
    static constexpr uint32_t HALVING_INTERVAL = 210'000u;

    int halvings = static_cast<int>(height / HALVING_INTERVAL);
    if (halvings >= 64) return 0;
    return INITIAL_SUBSIDY >> halvings;
}

// ─── Merkle Tree (SHA256d, BCH == BTC) ───────────────────────────────────────

inline uint256 merkle_hash_pair(const uint256& left, const uint256& right) {
    auto sl = std::span<const uint8_t>(left.data(),  32);
    auto sr = std::span<const uint8_t>(right.data(), 32);
    return Hash(sl, sr);
}

/// Merkle root over txids (SHA256d pairwise, last element duplicated for odd
/// counts). Identical algorithm to BTC -- BCH did not change the merkle rule.
inline uint256 compute_merkle_root(std::vector<uint256> hashes) {
    if (hashes.empty()) return uint256::ZERO;
    while (hashes.size() > 1) {
        if (hashes.size() & 1u)
            hashes.push_back(hashes.back());
        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i < hashes.size(); i += 2)
            next.push_back(merkle_hash_pair(hashes[i], hashes[i + 1]));
        hashes = std::move(next);
    }
    return hashes[0];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Compact bits as 8-char lowercase hex, matching bchn getblocktemplate.
inline std::string bits_to_hex(uint32_t bits) {
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", bits);
    return std::string(buf);
}

// ─── TemplateBuilder ─────────────────────────────────────────────────────────

/// Builds a BCH block template (WorkData) from a validated HeaderChain and
/// Mempool. WorkData stays layout-compatible with the GBT JSON downstream code
/// (share creation, Stratum) consumes, so p2pool-merged-v36 interop is held.
class TemplateBuilder {
public:
    // BCH has no SegWit weight accounting -- the budget is a flat byte size,
    // sourced per-network from abla.hpp (see build_template / file head).
    static constexpr uint32_t COINBASE_RESERVE = 1'000u;  // bytes for coinbase

    static std::optional<rpc::WorkData> build_template(
        const HeaderChain& chain,
        const Mempool&     pool,
        bool               is_testnet = false,
        const abla::State* tip_state  = nullptr)
    {
        auto t0 = std::chrono::steady_clock::now();

        // Block-size byte budget. ABLA (CHIP-2023-01) makes the consensus
        // limit dynamic. When the caller supplies a per-tip ABLA State
        // (replayed via abla::replay from a BCHN-pinned anchor over full-block
        // sizes -- a full-block/daemon-layer feed, NOT the headers-only SPV
        // chain) we build to that dynamic limit; otherwise we fall back to the
        // activation/floor limit, which ABLA only ever raises -- always a safe
        // LOCAL build cap (see abla.hpp head). Either way this is a build-time
        // byte budget only: zero p2pool-merged-v36 surface.
        const uint64_t max_block_bytes = tip_state
            ? tip_state->GetBlockSizeLimit()
            : abla::floor_block_size_limit(is_testnet);

        auto tip_opt = chain.tip();
        if (!tip_opt)
            return std::nullopt;  // chain has no genesis yet

        const IndexEntry& tip    = *tip_opt;
        uint32_t          next_h  = tip.height + 1;
        uint32_t          now_ts  = static_cast<uint32_t>(std::time(nullptr));

        // ── Next difficulty via ASERT (aserti3-2d) ─────────────────────────
        const BCHChainParams& params = chain.params();
        uint32_t next_bits;
        if (static_cast<int64_t>(tip.height) >= params.asert.anchor.height) {
            next_bits = get_next_work_required_asert(
                tip.height,
                static_cast<int64_t>(tip.header.m_timestamp),
                static_cast<int64_t>(now_ts),
                params.asert);
        } else {
            // Chain shorter than the ASERT anchor (post-checkpoint cold start):
            // fall back to the tip's bits, else pow_limit.
            next_bits = (tip.header.m_bits != 0)
                            ? tip.header.m_bits
                            : params.pow_limit.GetCompact();
            LOG_INFO << "[EMB-BCH] TemplateBuilder: bits fallback to 0x"
                     << std::hex << next_bits << std::dec
                     << " (tip below ASERT anchor)";
        }

        // ── Block version ──────────────────────────────────────────────────
        // BCH blocks use version 4 (no BIP9 version-bit signaling -- BCH does
        // not soft-fork via version bits). Mirror the tip; floor at 4.
        uint32_t block_version = static_cast<uint32_t>(tip.header.m_version);
        if (block_version < 4u) block_version = 4u;

        // ── Subsidy ────────────────────────────────────────────────────────
        uint64_t subsidy = get_block_subsidy(next_h);

        // ── Mempool selection (fee-sorted) ─────────────────────────────────
        auto [selected_txs, total_fees] =
            pool.get_sorted_txs_with_fees(max_block_bytes - COINBASE_RESERVE);

        // ── CTOR re-sort (CHIP-2018-11) ────────────────────────────────────
        // After fee selection, the block body must be in canonical order:
        // ascending txid, coinbase excluded (it is prepended downstream). This
        // is consensus-critical on BCH -- a non-CTOR body is rejected.
        std::sort(selected_txs.begin(), selected_txs.end(),
                  [](const Mempool::SelectedTx& a, const Mempool::SelectedTx& b) {
                      return compute_txid(a.tx) < compute_txid(b.tx);
                  });

        uint64_t coinbasevalue = subsidy + total_fees;

        nlohmann::json           tx_array = nlohmann::json::array();
        std::vector<Transaction> tx_objects;
        std::vector<uint256>     tx_hashes;

        for (const auto& stx : selected_txs) {
            uint256     txid     = compute_txid(stx.tx);
            auto        packed   = pack(stx.tx);          // single canonical form
            std::string hex_data = HexStr(packed.get_span());

            nlohmann::json entry;
            entry["data"] = hex_data;
            entry["txid"] = txid.GetHex();
            entry["hash"] = txid.GetHex();   // BCH: no wtxid; hash == txid
            // Per-tx fee -- p2pool adjusts subsidy when txs are excluded from a
            // share (helper.py / data.py). null => python uses base subsidy.
            if (stx.fee_known)
                entry["fee"] = static_cast<int64_t>(stx.fee);
            else
                entry["fee"] = nullptr;
            tx_array.push_back(std::move(entry));

            tx_objects.push_back(Transaction(stx.tx));
            tx_hashes.push_back(txid);
        }

        // ── GBT-compatible JSON ────────────────────────────────────────────
        nlohmann::json data;
        data["version"]           = static_cast<int>(block_version);
        data["previousblockhash"] = tip.block_hash.GetHex();
        data["bits"]              = bits_to_hex(next_bits);
        data["height"]            = static_cast<int>(next_h);
        data["curtime"]           = static_cast<int64_t>(now_ts);
        data["coinbasevalue"]     = static_cast<int64_t>(coinbasevalue);
        data["transactions"]      = std::move(tx_array);
        // BCH: no segwit. ABLA/active-fork rules to be confirmed vs BCHN GBT.
        data["rules"]             = nlohmann::json::array();
        data["coinbaseflags"]     = "";
        data["sizelimit"]         = static_cast<int64_t>(max_block_bytes);
        data["mintime"]           = static_cast<int64_t>(tip.header.m_timestamp + 1);

        LOG_INFO << "[EMB-BCH] TemplateBuilder: height=" << next_h
                 << " version=" << block_version
                 << " prev=" << tip.block_hash.GetHex().substr(0, 16) << "..."
                 << " bits=" << bits_to_hex(next_bits)
                 << " subsidy=" << subsidy << " fees=" << total_fees
                 << " coinbasevalue=" << coinbasevalue << " sat"
                 << " txs=" << data["transactions"].size()
                 << " (CTOR-sorted) tip_ts=" << tip.header.m_timestamp
                 << " now=" << now_ts << " synced=" << chain.is_synced();

        auto t1 = std::chrono::steady_clock::now();
        auto latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        return rpc::WorkData{std::move(data), std::move(tx_objects), std::move(tx_hashes), latency_ms};
    }
};

// ─── EmbeddedCoinNode ─────────────────────────────────────────────────────────

/// Concrete CoinNodeInterface backed by a HeaderChain and Mempool.
class EmbeddedCoinNode : public CoinNodeInterface {
public:
    EmbeddedCoinNode(HeaderChain& chain, Mempool& pool, bool testnet = false)
        : m_chain(chain), m_pool(pool), m_testnet(testnet) {}

    rpc::WorkData getwork() override {
        LOG_DEBUG_COIND << "[EMB-BCH] EmbeddedCoinNode::getwork()"
                  << " chain_height=" << m_chain.height()
                  << " mempool_size=" << m_pool.size()
                  << " synced=" << m_chain.is_synced();
        if (!m_chain.is_synced()) {
            LOG_INFO << "[EMB-BCH] getwork() blocked: chain not synced (height="
                     << m_chain.height() << ")";
            throw std::runtime_error("EmbeddedCoinNode::getwork: chain not synced — waiting for header sync");
        }
        // Dynamic ABLA budget: when an AblaTracker is wired (the full-block /
        // daemon layer feeding live per-block sizes) and its running state sits
        // exactly at our tip, hand build_template that per-tip State so the
        // budget tracks the live consensus limit. Otherwise pass nullptr and
        // build_template falls back to the 32 MB activation/floor -- the hard,
        // never-undercut fallback for an absent or stale (gapped) feed.
        const abla::State* tip_state = nullptr;
        if (m_abla) {
            auto tip = m_chain.tip();
            if (tip)
                tip_state = m_abla->state_for_tip(tip->height);
        }
        auto result = TemplateBuilder::build_template(m_chain, m_pool, m_testnet, tip_state);
        if (!result) {
            LOG_WARNING << "[EMB-BCH] getwork() FAILED: no tip (chain empty)";
            throw std::runtime_error("EmbeddedCoinNode::getwork: chain has no tip (not yet synced to genesis)");
        }
        return *result;
    }

    /// Block relay in embedded mode is handled by CoinBroadcaster, not here.
    void submit_block(BlockType& /*block*/) override { }

    nlohmann::json getblockchaininfo() override {
        nlohmann::json info;
        info["chain"]   = m_testnet ? "test" : "main";
        info["blocks"]  = static_cast<int>(m_chain.height());
        info["headers"] = static_cast<int>(m_chain.height());
        info["synced"]  = m_chain.is_synced();

        auto tip = m_chain.tip();
        if (tip) {
            info["bestblockhash"] = tip->block_hash.GetHex();
            info["bits"]          = bits_to_hex(tip->header.m_bits);
        } else {
            info["bestblockhash"] = std::string(64, '0');
            info["bits"]          = "00000000";
        }
        return info;
    }

    /// UTXO-readiness gate (coinbase maturity = 100 blocks on BCH).
    void set_utxo_ready_fn(std::function<bool()> fn) { m_utxo_ready = std::move(fn); }

    /// Wire the live ABLA size feed (full-block/daemon layer). Optional: when
    /// unset the template builder uses the 32 MB floor budget. The tracker is
    /// owned by the daemon layer and must outlive this node.
    void set_abla_tracker(AblaTracker* abla) { m_abla = abla; }

    bool is_synced() const override {
        if (!m_chain.is_synced()) return false;
        if (m_utxo_ready && !m_utxo_ready()) return false;
        return true;
    }

private:
    HeaderChain&          m_chain;
    Mempool&              m_pool;
    std::function<bool()> m_utxo_ready;
    bool                  m_testnet;
    AblaTracker*          m_abla = nullptr;   // sC: live size feed (daemon-owned, optional)
};

} // namespace coin
} // namespace bch
