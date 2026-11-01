// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase 5.3: DOGE Template Builder
///
/// Builds block templates for Dogecoin from HeaderChain + Mempool.
/// Reuses LTC's CoinNodeInterface, Merkle tree, and TemplateBuilder logic.
/// Only the subsidy schedule and difficulty calculation differ.

#include <functional>
#include "header_chain.hpp"    // DOGE HeaderChain (uses DOGEChainParams)
#include "chain_params.hpp"    // get_doge_block_subsidy(), calculate_doge_next_work()

#include <core/log.hpp>
#include <core/coin/mweb_shape.hpp>

// Reuse LTC's generic components (Mempool, block format, RPC data, merkle)
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/rpc_data.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/template_builder.hpp>  // CoinNodeInterface, compute_merkle_root, bits_to_hex

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <ctime>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace doge {
namespace coin {

// Reuse LTC types directly — same Bitcoin wire format
using ltc::coin::BlockType;
using ltc::coin::BlockHeaderType;
using ltc::coin::Transaction;
using ltc::coin::MutableTransaction;
using ltc::coin::Mempool;
using ltc::coin::CoinNodeInterface;
using ltc::coin::compute_merkle_root;
using ltc::coin::compute_txid;
using ltc::coin::bits_to_hex;
using ltc::coin::TX_WITH_WITNESS;

/// The degraded code of a template built while the set the pool prices
/// against cannot show every input unspent (core::coin::kTemplateDegradedKey).
inline constexpr const char* kUtxoIncomplete = "utxo-incomplete";

/// Can the pool's view price a DOGE template on the tip `tip_hash` at
/// `tip_height`?
///   - no view: no;
///   - a set with a sync state (the full set): only when complete(), i.e.
///     built from genesis and its best block is the tip (a sibling at the
///     tip's height is not);
///   - a legacy accrual view (no sync state): yes, as before (the dual-DB
///     transition prices against it until the full set completes).
inline bool utxo_view_prices(const core::coin::UTXOViewCache* view, uint32_t tip_height, const uint256& tip_hash)
{
    if (!view)
        return false;
    if (!view->sync_state().tracked())
        return true;
    return view->complete(tip_height, tip_hash);
}

/// The DOGE mining gate (EmbeddedCoinNode::is_synced), on the set the pool
/// prices against:
///   - no view: closed;
///   - the full set (a sync state): built from genesis and its best has
///     reached the header chain's tip once (synced). Behind the tip later
///     (a restart, a block in flight, a rebuild) the gate stays open and the
///     templates are coinbase-only (utxo-incomplete): a closed gate gives the
///     merged-mining poll empty work, which keeps the old tip's work until
///     the next tip change (MergedMiningManager::refresh_aux_work);
///   - a legacy accrual view: blocks_connected() >= DOGE_MINING_GATE_DEPTH,
///     the predicate before the full set.
inline bool utxo_mining_gate(const core::coin::UTXOViewCache* view)
{
    if (!view)
        return false;
    const auto s = view->sync_state();
    if (s.tracked())
        return s.anchor_height == 0 && s.synced != 0;
    return view->blocks_connected() >= core::coin::DOGE_MINING_GATE_DEPTH;
}

// ─── DOGE TemplateBuilder ────────────────────────────────────────────────────

class TemplateBuilder {
public:
    // Block version derived from chain tip in build_template(), not hardcoded.
    // DOGE uses (chain_id << 16) | base_version, e.g. 0x00620004 for BIP65.
    static constexpr uint32_t MAX_BLOCK_WEIGHT  = 4'000'000u;
    static constexpr uint32_t COINBASE_RESERVE  = 2'000u;
    // dogecoind CheckBlock: the serialized block, AuxPoW in the header
    // included, at most MAX_BLOCK_BASE_SIZE bytes (validation.cpp:2972,
    // consensus/consensus.h:17; primitives/block.h serializes the auxpow with
    // the header). DOGE has no witness: a tx's weight is 4 x its size.
    static constexpr uint32_t MAX_BLOCK_BASE_SIZE = 1'000'000u;

    /// The weight the mempool selection may use when `reserve_bytes` of the
    /// block go to the header, the AuxPoW and the coinbase.
    static uint32_t tx_weight_budget(uint32_t reserve_bytes)
    {
        const uint64_t reserve_wu = std::max<uint64_t>(uint64_t{reserve_bytes} * 4, COINBASE_RESERVE);
        return reserve_wu >= MAX_BLOCK_WEIGHT ? 0 : static_cast<uint32_t>(MAX_BLOCK_WEIGHT - reserve_wu);
    }

    /// dogecoind's CBlockIndex::GetMedianTimePast (chain.h:286-298): the median
    /// of the timestamps of `tip` and up to 10 of its ancestors.
    static int64_t median_time_past(const HeaderChain& chain, const IndexEntry& tip)
    {
        std::vector<int64_t> times;
        times.reserve(11);
        std::optional<IndexEntry> cur = tip;
        for (int i = 0; i < 11 && cur; ++i) {
            times.push_back(static_cast<int64_t>(cur->header.m_timestamp));
            if (cur->prev_hash.IsNull())
                break;
            cur = chain.get_header(cur->prev_hash);
        }
        std::sort(times.begin(), times.end());
        return times[times.size() / 2];
    }

    // ── Underfill guard (v36 cutover deploy path) ──────────────────────
    // Mirror of the LTC parent guard. DOGE runs its OWN embedded GBT path and
    // selects its OWN transactions, so it can go near-empty on a non-empty DOGE
    // mempool independently: merged-mining makes the aux inherit the parent PoW,
    // NOT the tx-fill. The guard therefore lives here directly rather than being
    // inherited from LTC. Thresholds are a v36-native shared structure (bucket-2,
    // standardize cross-coin) pinned to the legacy p2pool near-empty floor
    // (~50 kB); reviewable by btc-heap-opt.
    static constexpr uint64_t UNDERFILL_MIN_FILL_BYTES = 50'000ull; // < this = near-empty block
    static constexpr uint64_t UNDERFILL_BACKLOG_SLACK  = 50'000ull; // unselected fee-paying material that should have filled it

    /// The underfill guard's predicate: a near-empty template while the pool
    /// holds fee-paying backlog that should have filled it. `priced_bytes` is
    /// the pool's priced txs (Mempool::priced_bytes): an unpriced tx enters
    /// no template, so it is no backlog.
    static bool underfill(uint64_t selected_bytes, uint64_t priced_bytes, uint64_t mempool_fees)
    {
        const bool near_empty  = selected_bytes < UNDERFILL_MIN_FILL_BYTES;
        const bool has_backlog = mempool_fees > 0
                              && priced_bytes > selected_bytes + UNDERFILL_BACKLOG_SLACK;
        return near_empty && has_backlog;
    }

    /// max_weight bounds the mempool selection: tx_weight_budget(reserve)
    /// with the bytes the header, AuxPoW and coinbase take (MergedMiningManager
    /// passes them through AuxChainEmbedded).
    static std::optional<ltc::coin::rpc::WorkData> build_template(
        const HeaderChain& chain,
        const Mempool&     pool,
        const DOGEChainParams& params,
        uint32_t           max_weight = MAX_BLOCK_WEIGHT - COINBASE_RESERVE)
    {
        auto tip_opt = chain.tip();
        if (!tip_opt) return std::nullopt;

        const auto& tip    = *tip_opt;
        uint32_t    next_h = tip.height + 1;
        // dogecoind refuses a block at or below the median time past
        // (time-too-old, validation.cpp:3103); its own template time is
        // max(MTP + 1, now) (miner.cpp:65 UpdateTime).
        const int64_t mtp = median_time_past(chain, tip);
        uint32_t    now_ts = static_cast<uint32_t>(
            std::max<int64_t>(static_cast<int64_t>(std::time(nullptr)), mtp + 1));

        // ── Next difficulty (DigiShield v3) ───────────────────────────────
        uint32_t next_bits;
        if (params.is_digishield(next_h)) {
            // DigiShield: use prev block's data for 1-block retarget
            int64_t first_time = tip.header.m_timestamp - DOGEChainParams::TARGET_SPACING;
            // Use grandparent timestamp if available
            if (tip.prev_hash != uint256::ZERO) {
                auto gp = chain.get_header(tip.prev_hash);
                if (gp.has_value())
                    first_time = gp->header.m_timestamp;
            }
            next_bits = calculate_doge_next_work(
                tip.header.m_bits, tip.header.m_timestamp,
                first_time, next_h, params);
        } else {
            // Pre-DigiShield: use tip bits (only retargets every 240 blocks)
            next_bits = tip.header.m_bits;
        }

        // ── Subsidy ──────────────────────────────────────────────────────
        // Use prevHash-based random subsidy (exact match with Dogecoin Core)
        uint64_t subsidy = get_doge_block_subsidy(next_h, params, tip.block_hash);

        // ── Mempool cleaned for this tip ──────────────────────────────────
        // The txs the tip confirmed leave the pool only when the tip's body
        // runs through remove_for_block; until then any selection can carry
        // them (bad-txns-inputs-missingorspent). The DOGE list is fetched once
        // per tip change, usually before the body, and kept for the whole
        // interval. A coinbase-only block on the new tip is valid and pays the
        // subsidy (DOGE fees are a few hundredths of a percent of it); a held
        // template would be on the old tip. So: no txs, marked degraded, and
        // the merged-mining poll fetches again until the pool is cleaned.
        const bool pool_cleaned = pool.size() == 0 || pool.cleaned_for(tip.block_hash);

        // ── The set the pool prices against ───────────────────────────────
        // A tx may enter only when every input is shown unspent: the full
        // set must be complete at the tip (a rebuild, a restart behind the
        // tip, the tip's body still in flight), and there must be a view at
        // all. Otherwise coinbase-only, marked degraded, fetched again by the
        // merged-mining poll until it prices.
        const bool view_prices = pool.size() == 0 || utxo_view_prices(pool.utxo(), tip.height, tip.block_hash);
        const char* degraded = !pool_cleaned ? "mempool-not-cleaned-for-tip"
                             : !view_prices ? kUtxoIncomplete
                             : nullptr;

        // ── Transactions from mempool: priced txs only (fee-sorted) ──────
        auto [selected_txs, total_fees] = degraded == nullptr
            ? pool.get_sorted_txs_with_fees(max_weight)
            : std::pair<std::vector<ltc::coin::Mempool::SelectedTx>, uint64_t>{};

        // coinbasevalue = block reward + included transaction fees
        uint64_t coinbasevalue = subsidy + total_fees;

        nlohmann::json tx_array = nlohmann::json::array();
        std::vector<Transaction> tx_objects;
        std::vector<uint256>     tx_hashes;

        uint64_t selected_bytes = 0;  // wire bytes packed into this template (underfill guard)
        for (const auto& stx : selected_txs) {
            uint256     txid     = compute_txid(stx.tx);
            auto        packed   = pack(TX_WITH_WITNESS(stx.tx));
            selected_bytes += packed.get_span().size();
            std::string hex_data = HexStr(packed.get_span());

            nlohmann::json entry;
            entry["data"] = hex_data;
            entry["txid"] = txid.GetHex();
            if (stx.fee_known)
                entry["fee"] = static_cast<int64_t>(stx.fee);
            else
                entry["fee"] = nullptr;
            tx_array.push_back(std::move(entry));

            tx_objects.push_back(Transaction(stx.tx));
            tx_hashes.push_back(txid);
        }

        // ── Underfill guard ───────────────────────────────────────
        // Do not silently treat a near-empty DOGE template as healthy when the
        // DOGE mempool held fee-paying backlog that should have filled it. We
        // cannot fabricate transactions, so surface loudly (WARNING) for
        // contabo-prod-watch / the operator. Genuinely empty mempools never trip.
        // A degraded template is not a fill: the clean-tip gate or an
        // incomplete set chose coinbase-only, it is marked degraded and fetched
        // again, so the guard skips it (144 of 150 warnings in an hour were
        // those, VERIFY9 S1). The backlog is the priced txs only.
        if (degraded == nullptr) {
            const uint64_t priced_bytes = pool.priced_bytes();
            const uint64_t mempool_fees = pool.total_fees();
            if (underfill(selected_bytes, priced_bytes, mempool_fees)) {
                LOG_WARNING << "[EMB-DOGE] TemplateBuilder UNDERFILL: selected "
                            << selected_txs.size() << " tx / " << selected_bytes
                            << "B into template while mempool holds " << pool.size()
                            << " tx / " << pool.byte_size() << "B (" << priced_bytes
                            << "B priced, " << mempool_fees
                            << " sat fees) — near-empty block on a non-empty "
                            << "mempool; template-fill regression, gates cutover.";
            }
        }

        // ── Build GBT-compatible JSON ────────────────────────────────────
        nlohmann::json data;
        // Derive version from chain tip (preserves chain_id + BIP signaling bits)
        // Strip the AuxPoW bit (0x100) — it's added later during block construction.
        int32_t tip_version = tip.header.m_version;
        int block_version = tip_version & ~0x100;  // strip auxpow bit from tip
        if (block_version == 0) block_version = (DOGEChainParams::AUXPOW_CHAIN_ID << 16) | 4;
        data["version"]           = block_version;
        data["previousblockhash"] = tip.block_hash.GetHex();
        data["bits"]              = bits_to_hex(next_bits);
        data["height"]            = static_cast<int>(next_h);
        data["curtime"]           = static_cast<int64_t>(now_ts);
        data["coinbasevalue"]     = static_cast<int64_t>(coinbasevalue);
        data["transactions"]      = std::move(tx_array);
        data["rules"]             = nlohmann::json::array(); // DOGE: no segwit
        data["coinbaseflags"]     = "";
        data["sigoplimit"]        = 80000;
        data["sizelimit"]         = 1'000'000;
        data["weightlimit"]       = 4'000'000;
        data["mintime"]           = static_cast<int64_t>(mtp + 1);
        if (degraded)
            data[core::coin::kTemplateDegradedKey] = degraded;

        LOG_INFO << "[EMB-DOGE] TemplateBuilder: height=" << next_h
                 << " version=0x" << std::hex << block_version << std::dec
                 << " prev=" << tip.block_hash.GetHex().substr(0, 16) << "..."
                 << " bits=" << bits_to_hex(next_bits)
                 << " subsidy=" << subsidy
                 << " fees=" << total_fees
                 << " coinbasevalue=" << coinbasevalue << " sat"
                 << " txs=" << selected_txs.size()
                 << (degraded ? std::string(" degraded=") + degraded : std::string())
                 << " max_weight=" << max_weight
                 << " tip_ts=" << tip.header.m_timestamp
                 << " mtp=" << mtp
                 << " now=" << now_ts
                 << " synced=" << (chain.is_synced() ? "true" : "false");

        return ltc::coin::rpc::WorkData{std::move(data), std::move(tx_objects), std::move(tx_hashes), 0};
    }
};

// ─── EmbeddedCoinNode<DOGE> ──────────────────────────────────────────────────

class EmbeddedCoinNode : public CoinNodeInterface {
public:
    EmbeddedCoinNode(HeaderChain& chain, Mempool& pool, const DOGEChainParams& params)
        : m_chain(chain), m_pool(pool), m_params(params) {}

    ltc::coin::rpc::WorkData getwork() override {
        if (!m_chain.is_synced())
            throw std::runtime_error("DOGE EmbeddedCoinNode: header chain not synced (height="
                + std::to_string(m_chain.height()) + ")");
        auto result = TemplateBuilder::build_template(
            m_chain, m_pool, m_params,
            TemplateBuilder::tx_weight_budget(m_reserve_bytes.load(std::memory_order_relaxed)));
        if (!result)
            throw std::runtime_error("DOGE EmbeddedCoinNode: chain has no tip");
        return *result;
    }

    void submit_block(BlockType& /*block*/) override {
        // Block relay handled by CoinBroadcaster
    }

    nlohmann::json getblockchaininfo() override {
        nlohmann::json info;
        info["chain"]  = "doge";
        info["blocks"] = static_cast<int>(m_chain.height());
        info["headers"] = static_cast<int>(m_chain.height());
        info["synced"] = m_chain.is_synced();
        auto tip = m_chain.tip();
        if (tip) {
            info["bestblockhash"] = tip->block_hash.GetHex();
            info["bits"]          = bits_to_hex(tip->header.m_bits);
        }
        return info;
    }

    /// Set UTXO readiness callback — blocks getwork() until UTXO has
    /// enough depth for coinbase maturity validation (240 blocks for DOGE).
    void set_utxo_ready_fn(std::function<bool()> fn) { m_utxo_ready = std::move(fn); }

    /// The readiness callback main_ltc installs: utxo_mining_gate on the set
    /// the pool prices against at the time of the call (it changes when the
    /// full set completes).
    void gate_on_pool_view()
    {
        auto closed = std::make_shared<std::atomic<uint64_t>>(0);
        m_utxo_ready = [this, closed]() {
            const core::coin::UTXOViewCache* view = m_pool.utxo();
            const bool ready = utxo_mining_gate(view);
            if (!ready && closed->fetch_add(1, std::memory_order_relaxed) % 20 == 0) {
                if (!view) {
                    LOG_INFO << "[EMB-DOGE] UTXO mining gate closed: no UTXO set";
                } else if (const auto s = view->sync_state(); s.tracked()) {
                    LOG_INFO << "[EMB-DOGE] UTXO mining gate closed: full set anchor=" << s.anchor_height
                             << " best=" << view->get_best_height() << " synced=" << int(s.synced);
                } else {
                    LOG_INFO << "[EMB-DOGE] UTXO maturity gate: blocks_connected=" << view->blocks_connected()
                             << " need>=" << core::coin::DOGE_MINING_GATE_DEPTH;
                }
            }
            return ready;
        };
    }

    /// Bytes of the block the next templates leave to the header, the AuxPoW
    /// and the coinbase (0: COINBASE_RESERVE weight only).
    void set_block_size_reserve(uint32_t bytes) { m_reserve_bytes.store(bytes, std::memory_order_relaxed); }

    bool is_synced() const override {
        if (!m_chain.is_synced()) return false;
        if (m_utxo_ready && !m_utxo_ready()) return false;
        return true;
    }

    // Expose header lookup for block verification
    std::optional<IndexEntry> get_header_by_hash(const std::string& hash_hex) const {
        uint256 h;
        h.SetHex(hash_hex);
        return m_chain.get_header(h);
    }

private:
    HeaderChain&         m_chain;
    Mempool&             m_pool;
    const DOGEChainParams& m_params;
    std::function<bool()> m_utxo_ready;  // coinbase maturity gate
    std::atomic<uint32_t> m_reserve_bytes{0};
};

} // namespace coin
} // namespace doge