#pragma once

/// P1 PD: Embedded NMC (Namecoin) backend for merge-mining under a BTC parent.
///
/// Re-homed analog of src/impl/doge/coin/aux_chain_embedded.hpp (DOGE-under-LTC),
/// adapted to the NMC coin tree (BTC parent, SHA256d). Implements
/// c2pool::merged::IAuxChainBackend over the embedded NMC HeaderChain +
/// TemplateBuilder, so the merged-mining manager can pull NMC aux-work and run
/// the DUAL-TARGET check (share-target for PPLNS, aux-network-target for a real
/// Namecoin block) WITHOUT a namecoind RPC dependency.
///
/// Build-side responsibilities (PD), the complement of the header_chain verify
/// side (P1c/P1d/P1f):
///   get_work_template()  -> EmbeddedCoinNode::getwork() -> TemplateBuilder
///       Surfaces:
///         * block_hash  - the NMC block hash to COMMIT in the parent BTC
///                         coinbase (the aux-merkle leaf the verifier later
///                         walks via aux_merkle_root());
///         * target      - the NMC PoW target (dual-target: a found share is a
///                         real NMC block only if parent-PoW <= this target);
///         * chain_id    - NMCChainParams::aux_chain_id (consensus source, the
///                         SAME field the verify side pins).
///   submit_block()      -> P2P broadcast via CoinBroadcaster (embedded mode);
///   submit_aux_block()  -> fallback (submitauxblock) path - logged only,
///                          embedded mode has no daemon to RPC.
///
/// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY. No
/// core/ or btc/ header is modified. The merged_mining IAuxChainBackend contract
/// is a shared src/c2pool seam consumed READ-ONLY (same one doge implements).

#include "header_chain.hpp"
#include "template_builder.hpp"
#include "mempool.hpp"

#include <c2pool/merged/merged_mining.hpp>

#include <core/log.hpp>

#include <algorithm>
#include <string>

namespace nmc {
namespace coin {

class AuxChainEmbedded : public c2pool::merged::IAuxChainBackend
{
public:
    AuxChainEmbedded(
        HeaderChain& chain,
        Mempool& pool,
        const NMCChainParams& params,
        const c2pool::merged::AuxChainConfig& config,
        bool testnet = false)
        : m_chain(chain)
        , m_pool(pool)
        , m_params(params)
        , m_config(config)
        , m_embedded(chain, pool, testnet)
    {}

    bool connect() override {
        // Embedded backend is always "connected" - no namecoind socket.
        LOG_INFO << "[MM:" << m_config.symbol << "] Embedded NMC backend ready (no daemon needed)";
        return true;
    }

    c2pool::merged::AuxWork get_work_template() override {
        // Sync gate: no aux-work until the NMC header chain is caught up AND any
        // UTXO/coinbase-maturity gate wired on the embedded node is satisfied.
        if (!m_embedded.is_synced()) {
            LOG_DEBUG_COIND << "[MM:" << m_config.symbol << "] Embedded: not synced"
                           << " (height=" << m_chain.height() << "), returning empty work";
            return {};
        }

        rpc::WorkData wd;
        try {
            wd = m_embedded.getwork();
        } catch (const std::exception& e) {
            LOG_DEBUG_COIND << "[MM:" << m_config.symbol << "] Embedded: getwork threw ("
                           << e.what() << "), returning empty work";
            return {};
        }

        c2pool::merged::AuxWork work;
        work.height         = wd.m_data.value("height", 0);
        work.coinbase_value = wd.m_data.value("coinbasevalue", uint64_t(0));
        // chain_id: the consensus source is the params field the VERIFY side
        // pins (header_chain aux_chain_id), NOT the transport-layer config copy.
        // Unpinned (-1 sentinel) never reaches here: is_synced() is false under
        // placeholder genesis, so {} is returned above.
        work.chain_id       = static_cast<uint32_t>(m_params.aux_chain_id);
        work.block_template = wd.m_data;

        if (wd.m_data.contains("previousblockhash"))
            work.prev_block_hash = wd.m_data["previousblockhash"].get<std::string>();

        // Dual-target: aux PoW target derived from the template bits. A found
        // share is a REAL NMC block only when the parent-chain PoW satisfies it.
        if (wd.m_data.contains("bits")) {
            uint32_t bits = static_cast<uint32_t>(
                std::stoul(wd.m_data["bits"].get<std::string>(), nullptr, 16));
            work.target.SetCompact(bits);
        }

        // Aux block hash committed in the parent BTC coinbase (the merge-mining
        // leaf the verifier later proves via aux_merkle_root()).
        auto tip = m_chain.tip();
        if (tip.has_value())
            work.block_hash = tip->block_hash;

        return work;
    }

    c2pool::merged::AuxWork create_aux_block(const std::string& /*address*/) override {
        // Embedded mode is always multiaddress (GBT-shaped) - createauxblock and
        // getblocktemplate collapse to the same embedded template path.
        return get_work_template();
    }

    bool submit_block(const std::string& block_hex) override {
        // Embedded mode: P2P relay handled by CoinBroadcaster. Cache for
        // get_block_hex() retrieval and log the 80-byte header prefix.
        LOG_INFO << "[MM:" << m_config.symbol << "] Embedded: block submitted ("
                 << block_hex.size() / 2 << " bytes)"
                 << " header=" << block_hex.substr(0, std::min(size_t(160), block_hex.size()));
        m_last_block_hex = block_hex;
        return true;
    }

    bool submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex) override {
        // Fallback (submitauxblock) path: embedded mode has no daemon to RPC,
        // the frozen-block submit_block() + P2P relay is the primary route.
        LOG_WARNING << "[MM:" << m_config.symbol << "] Embedded: submit_aux_block called"
                    << " (fallback path) hash=" << block_hash.GetHex().substr(0, 16) << "..."
                    << " auxpow=" << auxpow_hex.size() / 2 << " bytes"
                    << " - no daemon to submit to, relying on P2P relay";
        return true;
    }

    std::string get_block_hex(const std::string& /*block_hash*/) override {
        if (!m_last_block_hex.empty())
            return m_last_block_hex;
        return {};
    }

    std::string get_best_block_hash() override {
        auto tip = m_chain.tip();
        return tip.has_value() ? tip->block_hash.GetHex() : "";
    }

    std::vector<NetService> getpeerinfo() override {
        // No daemon peers - the P2P broadcaster owns its own peer discovery.
        return {};
    }

    const c2pool::merged::AuxChainConfig& config() const override { return m_config; }

    /// Expose embedded node for UTXO maturity gate wiring.
    EmbeddedCoinNode& embedded_node() { return m_embedded; }

private:
    HeaderChain&                       m_chain;
    Mempool&                           m_pool;
    NMCChainParams                     m_params;
    c2pool::merged::AuxChainConfig     m_config;
    EmbeddedCoinNode                   m_embedded;
    std::string                        m_last_block_hex;  // cached for get_block_hex() after submit
};

} // namespace coin
} // namespace nmc
