#pragma once

/// Phase 3: LTC Template Builder
///
/// Builds block templates (WorkData) natively from HeaderChain + Mempool,
/// removing the getblocktemplate RPC dependency for LTC.
///
/// Provides:
///   get_block_subsidy()   — BTC halving schedule (50 BTC, per-network halving interval)
///   compute_merkle_root() — SHA256d-based Merkle tree (Bitcoin/Litecoin compatible)
///   TemplateBuilder       — static build_template() → WorkData
///   CoinNodeInterface     — abstract interface (getwork / submit_block / getblockchaininfo)
///   EmbeddedCoinNode      — concrete implementation backed by HeaderChain + Mempool

#include <functional>
#include "header_chain.hpp"
#include "mempool.hpp"
#include "rpc_data.hpp"
#include "transaction.hpp"
#include "block.hpp"

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>

#include <btclibs/util/strencodings.h>

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <ctime>
#include <cstdio>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace btc {
namespace coin {

// ─── BTC Subsidy ─────────────────────────────────────────────────────────────

/// BTC block subsidy (miner reward) in satoshis at a given block height.
/// Initial subsidy: 50 BTC = 5,000,000,000 satoshis.
/// Halving: every halving_interval blocks (210,000 mainnet/testnet, 150 regtest).
/// Subsidy drops to 0 after 64 halvings (never in practice — block ~13.4 M).
/// Reference: ref/bitcoin/src/validation.cpp GetBlockSubsidy().
inline uint64_t get_block_subsidy(uint32_t height,
                                  uint32_t halving_interval = 210'000u) {
    static constexpr uint64_t COIN            = 100'000'000ULL;   // satoshis per BTC
    static constexpr uint64_t INITIAL_SUBSIDY = 50ULL * COIN;     // 50 BTC
    // halving_interval is per-network (Bitcoin Core consensus.nSubsidyHalvingInterval):
    // mainnet/testnet 210,000, regtest 150. Default keeps single-arg callers on mainnet.
    if (halving_interval == 0) return INITIAL_SUBSIDY;  // guard div-by-zero

    int halvings = static_cast<int>(height / halving_interval);
    if (halvings >= 64) return 0;
    return INITIAL_SUBSIDY >> halvings;
}

// ─── Merkle Tree ─────────────────────────────────────────────────────────────

/// Hash two adjacent Merkle nodes together (SHA256d of concatenation).
inline uint256 merkle_hash_pair(const uint256& left, const uint256& right) {
    auto sl = std::span<const uint8_t>(left.data(),  32);
    auto sr = std::span<const uint8_t>(right.data(), 32);
    return Hash(sl, sr);
}

/// Compute the Merkle root of a list of txids.
/// Implements Bitcoin/Litecoin Core's ComputeMerkleRoot() algorithm
/// (SHA256d pairwise, duplicating the last element if count is odd).
/// Returns uint256::ZERO for an empty list.
inline uint256 compute_merkle_root(std::vector<uint256> hashes) {
    if (hashes.empty()) return uint256::ZERO;

    while (hashes.size() > 1) {
        if (hashes.size() & 1u)
            hashes.push_back(hashes.back());  // duplicate last for odd count

        std::vector<uint256> next;
        next.reserve(hashes.size() / 2);
        for (size_t i = 0; i < hashes.size(); i += 2)
            next.push_back(merkle_hash_pair(hashes[i], hashes[i + 1]));
        hashes = std::move(next);
    }
    return hashes[0];
}

/// Stratum coinbase merkle branch siblings for a populated template.
///
/// PRODUCER/CONSUMER CONTRACT: `tx_hashes` is the pure tx-hash list
/// [tx1..txN] with NO coinbase slot (template_builder / GBT transactions[]).
/// The stratum merkle tree has the coinbase as leaf 0, so we prepend a
/// placeholder leaf before folding. At each level we emit the SIBLING of the
/// left-most (coinbase-descended) node -- exactly the branch list a miner
/// folds against its own coinbase txid to rebuild the header merkle root:
///     acc = coinbase_txid
///     for b in siblings: acc = merkle_hash_pair(acc, b)
///     acc == compute_merkle_root([coinbase_txid, tx1..txN])
///
/// SSOT for both BTCWorkSource::get_stratum_merkle_branches() (which hex-
/// encodes these for the wire) and the merkle self-check in mining_submit.
/// Without the leaf-0 prepend, tx1 is dropped and the folded root diverges
/// from the serialized body -> bad-txnmrklroot on any populated won block.
/// Returns {} for an empty (coinbase-only) template.
inline std::vector<uint256> stratum_merkle_siblings(const std::vector<uint256>& tx_hashes) {
    if (tx_hashes.empty()) return {};

    std::vector<uint256> level;
    level.reserve(tx_hashes.size() + 1);
    level.push_back(uint256::ZERO);  // coinbase placeholder leaf (leaf 0)
    level.insert(level.end(), tx_hashes.begin(), tx_hashes.end());

    std::vector<uint256> siblings;
    while (level.size() > 1) {
        siblings.push_back(level[1]);  // right-sibling of the coinbase node

        std::vector<uint256> next;
        next.reserve((level.size() + 2) / 2);
        next.push_back(uint256::ZERO);  // placeholder for combo of (cb, level[1])
        for (size_t i = 2; i < level.size(); i += 2) {
            const uint256& l = level[i];
            const uint256& r = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(merkle_hash_pair(l, r));
        }
        level = std::move(next);
    }
    return siblings;
}

/// Compute the BIP141 segwit witness-commitment merkle root.
///
/// The coinbase transaction's own wtxid is DEFINED as 32 zero bytes and MUST
/// occupy leaf 0 of the witness merkle tree; the remaining leaves are the
/// other transactions' wtxids IN BLOCK ORDER. This helper is the single source
/// of truth for that leaf-0 placeholder contract -- the witness-tree analogue
/// of the txid-merkle coinbase leaf-0 fix (PR #570). Keeping it in one place
/// means a populated segwit block cannot silently drop the first tx's wtxid
/// (which bitcoind rejects as bad-witness-merkle-match).
///
/// other_wtxids: wtxids of every tx EXCEPT the coinbase, in block order.
inline uint256 witness_merkle_root(const std::vector<uint256>& other_wtxids) {
    std::vector<uint256> leaves;
    leaves.reserve(1 + other_wtxids.size());
    leaves.push_back(uint256::ZERO);  // coinbase wtxid placeholder (BIP141)
    leaves.insert(leaves.end(), other_wtxids.begin(), other_wtxids.end());
    return compute_merkle_root(std::move(leaves));
}

// ─── CoinNodeInterface ────────────────────────────────────────────────────────

/// Abstract interface for obtaining work and submitting blocks.
/// Allows swapping between RPC (legacy), embedded, or hybrid implementations
/// without changing downstream code (share creation, Stratum, etc.).
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Format a compact bits value as an 8-character lowercase hex string,
/// matching the format litecoind returns in getblocktemplate.
inline std::string bits_to_hex(uint32_t bits) {
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", bits);
    return std::string(buf);
}

// ─── TemplateBuilder ─────────────────────────────────────────────────────────

/// Builds an LTC block template from a validated HeaderChain and Mempool.
///
/// The resulting WorkData is layout-compatible with the GBT JSON that
/// NodeRPC::getwork() returns, so all downstream code (web_server, share
/// creation, Stratum) works without modification.
///
/// JSON fields produced:
///   version           — derived from chain tip (BIP9 base 0x20000000 + signaling bits)
///   previousblockhash — SHA256d hex of tip header (big-endian display)
///   bits              — compact target for next block as 8-char hex
///   height            — next block height
///   curtime           — current wall-clock timestamp
///   coinbasevalue     — miner subsidy in satoshis (no fees — no UTXO set)
///   transactions      — array with "data" (hex) and "txid" per tx
///   rules             — ["segwit"]
///   coinbaseflags     — "" (empty)
///   sigoplimit        — 80000
///   sizelimit         — 4000000
///   weightlimit       — 4000000
///   mintime           — tip.timestamp + 1
class TemplateBuilder {
public:
    // BIP9 base version — all modern blocks use 0x20000000 as the base with
    // optional version-bit signaling.  We derive the actual version from the
    // chain tip so we automatically mirror whatever signaling bits the network
    // is using (e.g. Taproot, future soft-forks).
    static constexpr uint32_t BIP9_BASE_VERSION = 0x20000000u;
    static constexpr uint32_t MAX_BLOCK_WEIGHT  = 4'000'000u;
    static constexpr uint32_t COINBASE_RESERVE  = 2'000u;   // weight reserved for coinbase tx

    /// Build a WorkData template from the current chain tip + mempool.
    /// Returns std::nullopt if the chain has no tip yet (not synced to genesis).
    static std::optional<rpc::WorkData> build_template(
        const HeaderChain& chain,
        const Mempool&     pool,
        bool               is_testnet = false)
    {
        (void)is_testnet;  // reserved for future per-network rules
        auto t0 = std::chrono::steady_clock::now();

        auto tip_opt = chain.tip();
        if (!tip_opt)
            return std::nullopt;  // chain has no genesis yet

        const IndexEntry& tip       = *tip_opt;
        uint32_t          next_h    = tip.height + 1;
        uint32_t          now_ts    = static_cast<uint32_t>(std::time(nullptr));

        // ── Next difficulty ────────────────────────────────────────────────
        auto get_ancestor = [&](uint32_t h) -> std::optional<IndexEntry> {
            return chain.get_header_by_height(h);
        };
        uint32_t next_bits = get_next_work_required(
            get_ancestor,
            tip.height,
            tip.header.m_bits,
            tip.header.m_timestamp,
            now_ts,
            chain.params());
        // After a checkpoint, the chain may lack enough headers for difficulty
        // calculation (need 2016+ ancestors). Fall back to tip's bits or
        // pow_limit if bits came back as 0.
        if (next_bits == 0) {
            if (tip.header.m_bits != 0)
                next_bits = tip.header.m_bits;
            else
                next_bits = chain.params().pow_limit.GetCompact();
            LOG_INFO << "[EMB-BTC] TemplateBuilder: bits fallback to 0x"
                     << std::hex << next_bits << std::dec
                     << " (chain too short for retarget)";
        }

        // ── Block version ──────────────────────────────────────────────────
        uint32_t block_version = static_cast<uint32_t>(tip.header.m_version);
        if (block_version < BIP9_BASE_VERSION)
            block_version = BIP9_BASE_VERSION;

        // ── Subsidy ────────────────────────────────────────────────────────
        uint64_t subsidy = get_block_subsidy(next_h, chain.params().subsidy_halving_interval);

        // ── Transactions from mempool (fee-sorted when UTXO available) ────
        auto [selected_txs, total_fees] =
            pool.get_sorted_txs_with_fees(MAX_BLOCK_WEIGHT - COINBASE_RESERVE);

        // coinbasevalue = block reward + included transaction fees
        // Matches litecoind's getblocktemplate coinbasevalue field.
        uint64_t coinbasevalue = subsidy + total_fees;

        nlohmann::json         tx_array = nlohmann::json::array();
        std::vector<Transaction> tx_objects;
        std::vector<uint256>     tx_hashes;

        for (const auto& stx : selected_txs) {
            uint256     txid     = compute_txid(stx.tx);
            auto        packed   = pack(TX_WITH_WITNESS(stx.tx));
            std::string hex_data = HexStr(packed.get_span());
            // wtxid = SHA256d of witness serialization (for witness merkle tree)
            uint256     wtxid    = Hash(packed.get_span());

            nlohmann::json entry;
            entry["data"] = hex_data;
            entry["txid"] = txid.GetHex();
            entry["hash"] = wtxid.GetHex();  // wtxid for witness commitment
            // Per-tx fee field — p2pool reads this in helper.py:123
            // and uses it in data.py:876-884 to adjust subsidy when
            // transactions are excluded from shares.
            if (stx.fee_known)
                entry["fee"] = static_cast<int64_t>(stx.fee);
            else
                entry["fee"] = nullptr;  // JSON null → p2pool uses base_subsidy fallback
            tx_array.push_back(std::move(entry));

            tx_objects.push_back(Transaction(stx.tx));
            tx_hashes.push_back(txid);
        }

        // ── Build GBT-compatible JSON ──────────────────────────────────────
        nlohmann::json data;
        data["version"]           = static_cast<int>(block_version);
        data["previousblockhash"] = tip.block_hash.GetHex();
        data["bits"]              = bits_to_hex(next_bits);
        data["height"]            = static_cast<int>(next_h);
        data["curtime"]           = static_cast<int64_t>(now_ts);
        data["coinbasevalue"]     = static_cast<int64_t>(coinbasevalue);
        data["transactions"]      = std::move(tx_array);
        // Bitcoin rules: BTC has only segwit (no MWEB).
        data["rules"]             = nlohmann::json::array({"segwit"});
        data["coinbaseflags"]     = "";
        data["sigoplimit"]        = 80000;
        data["sizelimit"]         = 4'000'000;
        data["weightlimit"]       = 4'000'000;
        data["mintime"]           = static_cast<int64_t>(tip.header.m_timestamp + 1);

        LOG_INFO << "[EMB-BTC] TemplateBuilder: height=" << next_h
                 << " version=0x" << std::hex << block_version << std::dec
                 << " prev=" << tip.block_hash.GetHex().substr(0, 16) << "..."
                 << " bits=" << bits_to_hex(next_bits)
                 << " subsidy=" << subsidy << " fees=" << total_fees
                 << " coinbasevalue=" << coinbasevalue << " sat"
                 << " txs=" << data["transactions"].size()
                 << " tip_ts=" << tip.header.m_timestamp
                 << " now=" << now_ts
                 << " synced=" << chain.is_synced();
        auto t1 = std::chrono::steady_clock::now();
        auto latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        return rpc::WorkData{std::move(data), std::move(tx_objects), std::move(tx_hashes), latency_ms};
    }

};

// ─── EmbeddedCoinNode ─────────────────────────────────────────────────────────

/// Concrete CoinNodeInterface backed by a HeaderChain and Mempool.
/// Calls TemplateBuilder::build_template() for getwork().
class EmbeddedCoinNode : public CoinNodeInterface {
public:
    EmbeddedCoinNode(HeaderChain& chain, Mempool& pool, bool testnet = false)
        : m_chain(chain)
        , m_pool(pool)
        , m_testnet(testnet)
    {}

    /// Build a template from the current chain tip + mempool.
    /// Throws std::runtime_error if the chain has no genesis yet or not synced.
    rpc::WorkData getwork() override {
        LOG_DEBUG_COIND << "[EMB-BTC] EmbeddedCoinNode::getwork() called"
                  << " chain_height=" << m_chain.height()
                  << " mempool_size=" << m_pool.size()
                  << " synced=" << m_chain.is_synced();
        if (!m_chain.is_synced()) {
            LOG_INFO << "[EMB-BTC] getwork() blocked: chain not synced (height="
                     << m_chain.height() << ")";
            throw std::runtime_error("EmbeddedCoinNode::getwork: chain not synced — waiting for header sync");
        }
        auto result = TemplateBuilder::build_template(m_chain, m_pool, m_testnet);
        if (!result) {
            LOG_WARNING << "[EMB-BTC] EmbeddedCoinNode::getwork() FAILED: no tip (chain empty)";
            throw std::runtime_error("EmbeddedCoinNode::getwork: chain has no tip (not yet synced to genesis)");
        }
        return *result;
    }

    /// Block relay in embedded mode is handled by CoinBroadcaster via
    /// MiningInterface::on_block_relay, not through this interface.
    /// This override is intentionally empty — the RPC-based NodeRPC path
    /// uses its own submit_block_hex() directly.
    void submit_block(BlockType& /*block*/) override { }

    /// Return basic chain state info (analogous to getblockchaininfo RPC).
    nlohmann::json getblockchaininfo() override {
        nlohmann::json info;
        info["chain"]    = m_testnet ? "test" : "main";
        info["blocks"]   = static_cast<int>(m_chain.height());
        info["headers"]  = static_cast<int>(m_chain.height());
        info["synced"]   = m_chain.is_synced();

        auto tip = m_chain.tip();
        if (tip) {
            info["bestblockhash"] = tip->block_hash.GetHex();
            info["bits"]          = bits_to_hex(tip->header.m_bits);
        } else {
            info["bestblockhash"] = std::string(64, '0');
            info["bits"]          = "00000000";
        }
        LOG_DEBUG_COIND << "[EMB-BTC] getblockchaininfo: height=" << info["blocks"].get<int>()
                  << " synced=" << info["synced"].get<bool>()
                  << " best=" << info["bestblockhash"].get<std::string>().substr(0, 16);
        return info;
    }

    /// Set UTXO readiness callback — blocks getwork() until UTXO has
    /// enough depth for coinbase maturity validation (100 blocks for LTC).
    void set_utxo_ready_fn(std::function<bool()> fn) { m_utxo_ready = std::move(fn); }

    bool is_synced() const override {
        if (!m_chain.is_synced()) return false;
        if (m_utxo_ready && !m_utxo_ready()) return false;
        return true;
    }

private:
    HeaderChain& m_chain;
    Mempool&     m_pool;
    std::function<bool()> m_utxo_ready;  // coinbase maturity gate
    bool         m_testnet;
};

} // namespace coin
} // namespace btc
