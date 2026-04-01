#pragma once

/// Phase 5.5: Embedded DOGE backend for merged mining
///
/// Implements IAuxChainBackend using the embedded DOGE HeaderChain +
/// TemplateBuilder, replacing AuxChainRPC for daemonless operation.
///
/// Work flow:
///   get_work_template() / create_aux_block() → TemplateBuilder::build_template()
///   submit_block()     → P2P broadcast via CoinBroadcaster
///   get_best_block_hash() → HeaderChain::tip()
///   get_block_hex()    → not supported (no full block storage in SPV mode)

#include "header_chain.hpp"
#include "template_builder.hpp"
#include "chain_params.hpp"

#include <c2pool/merged/merged_mining.hpp>

#include <core/log.hpp>

namespace doge {
namespace coin {

class AuxChainEmbedded : public c2pool::merged::IAuxChainBackend
{
public:
    AuxChainEmbedded(
        HeaderChain& chain,
        ltc::coin::Mempool& pool,
        const DOGEChainParams& params,
        const c2pool::merged::AuxChainConfig& config)
        : m_chain(chain)
        , m_pool(pool)
        , m_params(params)
        , m_config(config)
        , m_embedded(chain, pool, params)
    {}

    bool connect() override {
        // No RPC connection needed — embedded node is always "connected"
        LOG_INFO << "[MM:" << m_config.symbol << "] Embedded backend ready (no daemon needed)";
        return true;
    }

    c2pool::merged::AuxWork get_work_template() override {
        // Sync gate: don't return work until header chain is caught up AND
        // UTXO has coinbase maturity depth (240 blocks for DOGE).
        // Reference: dogecoin/src/chainparams.cpp digishieldConsensus.nCoinbaseMaturity = 240
        if (!m_embedded.is_synced()) {
            LOG_DEBUG_COIND << "[MM:" << m_config.symbol << "] Embedded: not synced"
                           << " (height=" << m_chain.height() << "), returning empty work";
            return {};
        }

        auto wd = m_embedded.getwork();

        c2pool::merged::AuxWork work;
        work.height = wd.m_data.value("height", 0);
        work.coinbase_value = wd.m_data.value("coinbasevalue", uint64_t(0));
        work.chain_id = DOGEChainParams::AUXPOW_CHAIN_ID;
        work.block_template = wd.m_data;

        if (wd.m_data.contains("previousblockhash")) {
            work.prev_block_hash = wd.m_data["previousblockhash"].get<std::string>();
        }

        // Target from bits
        if (wd.m_data.contains("bits")) {
            uint32_t bits = static_cast<uint32_t>(
                std::stoul(wd.m_data["bits"].get<std::string>(), nullptr, 16));
            work.target.SetCompact(bits);
        }

        // Block hash for AuxPoW commitment — use the hash of the block we're building
        auto tip = m_chain.tip();
        if (tip.has_value())
            work.block_hash = tip->block_hash;

        return work;
    }

    c2pool::merged::AuxWork create_aux_block(const std::string& /*address*/) override {
        return get_work_template();
    }

    bool submit_block(const std::string& block_hex) override {
        // Embedded mode: P2P relay handled by CoinBroadcaster via set_block_relay_fn.
        // Log block hex prefix for diagnostics (first 160 hex chars = 80-byte header).
        LOG_INFO << "[MM:" << m_config.symbol << "] Embedded: block submitted ("
                 << block_hex.size() / 2 << " bytes)"
                 << " header=" << block_hex.substr(0, std::min(size_t(160), block_hex.size()));
        // Cache last block hex for get_block_hex() retrieval
        m_last_block_hex = block_hex;
        return true;
    }

    bool submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex) override {
        // Fallback path: submit_aux_block without a fully assembled block.
        // Embedded mode can't do RPC submitauxblock — log for diagnostics.
        // The frozen block path (submit_block) is the primary submission method.
        LOG_WARNING << "[MM:" << m_config.symbol << "] Embedded: submit_aux_block called"
                    << " (fallback path) hash=" << block_hash.GetHex().substr(0, 16) << "..."
                    << " auxpow=" << auxpow_hex.size() / 2 << " bytes"
                    << " — no daemon to submit to, relying on P2P relay";
        return true;
    }

    std::string get_block_hex(const std::string& /*block_hash*/) override {
        // Return last submitted block hex if available (for P2P relay after submission)
        if (!m_last_block_hex.empty())
            return m_last_block_hex;
        return {};
    }

    std::string get_best_block_hash() override {
        auto tip = m_chain.tip();
        return tip.has_value() ? tip->block_hash.GetHex() : "";
    }

    std::vector<NetService> getpeerinfo() override {
        // No daemon peers — P2P broadcaster handles its own peer discovery
        return {};
    }

    const c2pool::merged::AuxChainConfig& config() const override { return m_config; }

    /// Expose embedded node for UTXO maturity gate wiring.
    EmbeddedCoinNode& embedded_node() { return m_embedded; }

private:
    HeaderChain&                       m_chain;
    ltc::coin::Mempool&                m_pool;
    const DOGEChainParams&             m_params;
    c2pool::merged::AuxChainConfig     m_config;
    EmbeddedCoinNode                   m_embedded;
    std::string                        m_last_block_hex;  // cached for get_block_hex() after submit
};

} // namespace coin
} // namespace doge
