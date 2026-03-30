#pragma once

/// Phase 5.3: DOGE Template Builder
///
/// Builds block templates for Dogecoin from HeaderChain + Mempool.
/// Reuses LTC's CoinNodeInterface, Merkle tree, and TemplateBuilder logic.
/// Only the subsidy schedule and difficulty calculation differ.

#include "header_chain.hpp"    // DOGE HeaderChain (uses DOGEChainParams)
#include "chain_params.hpp"    // get_doge_block_subsidy(), calculate_doge_next_work()

// Reuse LTC's generic components (Mempool, block format, RPC data, merkle)
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/rpc_data.hpp>
#include <impl/ltc/coin/transaction.hpp>
#include <impl/ltc/coin/block.hpp>
#include <impl/ltc/coin/template_builder.hpp>  // CoinNodeInterface, compute_merkle_root, bits_to_hex

#include <nlohmann/json.hpp>

#include <ctime>
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

// ─── DOGE TemplateBuilder ────────────────────────────────────────────────────

class TemplateBuilder {
public:
    // Block version derived from chain tip in build_template(), not hardcoded.
    // DOGE uses (chain_id << 16) | base_version, e.g. 0x00620004 for BIP65.
    static constexpr uint32_t MAX_BLOCK_WEIGHT  = 4'000'000u;
    static constexpr uint32_t COINBASE_RESERVE  = 2'000u;

    static std::optional<ltc::coin::rpc::WorkData> build_template(
        const HeaderChain& chain,
        const Mempool&     pool,
        const DOGEChainParams& params)
    {
        auto tip_opt = chain.tip();
        if (!tip_opt) return std::nullopt;

        const auto& tip    = *tip_opt;
        uint32_t    next_h = tip.height + 1;
        uint32_t    now_ts = static_cast<uint32_t>(std::time(nullptr));

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

        // ── Transactions from mempool (fee-sorted when UTXO available) ──
        auto [selected_txs, total_fees] =
            pool.get_sorted_txs_with_fees(MAX_BLOCK_WEIGHT - COINBASE_RESERVE);

        // coinbasevalue = block reward + included transaction fees
        uint64_t coinbasevalue = subsidy + total_fees;

        nlohmann::json tx_array = nlohmann::json::array();
        std::vector<Transaction> tx_objects;
        std::vector<uint256>     tx_hashes;

        for (const auto& stx : selected_txs) {
            uint256     txid     = compute_txid(stx.tx);
            auto        packed   = pack(TX_WITH_WITNESS(stx.tx));
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
        data["mintime"]           = static_cast<int64_t>(tip.header.m_timestamp + 1);

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
        auto result = TemplateBuilder::build_template(m_chain, m_pool, m_params);
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

    bool is_synced() const override { return m_chain.is_synced(); }

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
};

} // namespace coin
} // namespace doge
