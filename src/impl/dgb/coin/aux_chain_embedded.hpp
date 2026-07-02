#pragma once
// ===========================================================================
// dgb::coin::AuxChainEmbedded -- DGB's OWN embedded merged-mining backend.
//
// Registers against the shared c2pool::merged::IAuxChainBackend (the DC
// merged-mining seam, src/c2pool/merged/merged_mining.hpp), giving DGB a
// daemonless aux-chain work source built ENTIRELY from in-process embedded
// chain state: the DGB HeaderChain (coin/header_chain.hpp) + EmbeddedCoinNode
// (coin/embedded_coin_node.hpp), with NO external digibyted RPC.
//
// This is the DGB analogue of doge::coin::AuxChainEmbedded and
// nmc::coin::AuxChainEmbedded -- PATTERN-mirrored from the DOGE class, but every
// consensus/identity value is DGB-native: chain_id is dgb::AUXPOW_CHAIN_ID
// (0x1AFE, NEVER DOGE's 0x0062), and the work template flows through the DGB
// build_work_template SSOT via EmbeddedCoinNode::getwork().
//
// Work / submit contract (identical to the DOGE mirror):
//   get_work_template() / create_aux_block() -> EmbeddedCoinNode::getwork(),
//     GATED on is_synced() -- returns {} (empty AuxWork) until the embedded
//     header-download ingest reports synced. DGB EmbeddedCoinNode::is_synced()
//     is currently a truthful `false`, so this correctly returns not-ready
//     work today (the empty-work contract, not a bug).
//   submit_block()      -> the REAL submit path: P2P relay is wired by the
//     manager's set_block_relay_fn / a registration-site relay lambda
//     (CoinBroadcaster). This method logs + caches the block hex for
//     get_block_hex() retrieval; it does NOT itself touch the network.
//   submit_aux_block()  -> LOG-ONLY diagnostic fallback (no daemon to submit
//     to). Mirrors the DOGE class exactly: log, return true.
//
// -DAUX_DOGE=ON only: this backend is part of the merged-mining seam that is
// compiled solely under the AUX_DOGE stretch flag (mirrors coin/node.hpp).
// ===========================================================================

#ifdef AUX_DOGE

#include <ctime>
#include <cstdint>
#include <string>
#include <vector>

#include <core/coin_params.hpp>   // core::SubsidyFunc
#include <core/log.hpp>

#include "header_chain.hpp"            // c2pool::dgb::HeaderChain
#include "embedded_coin_node.hpp"      // dgb::coin::EmbeddedCoinNode
#include "hash_format.hpp"            // dgb::coin::u256_be_display_hex SSOT
#include "mempool.hpp"                // dgb::coin::Mempool

#include <impl/dgb/params.hpp>         // dgb::AUXPOW_CHAIN_ID (bucket-1 SSOT)

#include <c2pool/merged/merged_mining.hpp>

namespace dgb {
namespace coin {

class AuxChainEmbedded : public c2pool::merged::IAuxChainBackend
{
public:
    // Mirror of doge::coin::AuxChainEmbedded, adapted to the DGB EmbeddedCoinNode
    // ctor shape (HeaderChain& + SubsidyFunc + optional tx_source). The Mempool&
    // is held for parity/future embedded fee wiring; fee-selected txs reach the
    // node via an injected EmbeddedTxSource at the registration site, not here.
    AuxChainEmbedded(
        c2pool::dgb::HeaderChain& chain,
        dgb::coin::Mempool& pool,
        core::SubsidyFunc subsidy_func,
        const c2pool::merged::AuxChainConfig& config,
        dgb::coin::EmbeddedTxSource tx_source = {})
        : m_chain(chain)
        , m_pool(pool)
        , m_config(config)
        , m_embedded(chain, std::move(subsidy_func), std::move(tx_source))
    {}

    bool connect() override {
        // No RPC connection needed -- the embedded node is always "connected".
        LOG_INFO << "[MM:" << m_config.symbol << "] Embedded backend ready (no daemon needed)";
        return true;
    }

    c2pool::merged::AuxWork get_work_template() override {
        // Empty-work contract: no work until the embedded header chain is synced.
        // DGB EmbeddedCoinNode::is_synced() is a truthful `false` until the
        // header-download ingest is wired, so this returns {} today -- correct.
        if (!m_embedded.is_synced()) {
            LOG_DEBUG_COIND << "[MM:" << m_config.symbol << "] Embedded: not synced"
                           << " (height=" << m_chain.tip_height().value_or(0)
                           << "), returning empty work";
            return {};
        }

        auto wd = m_embedded.getwork();

        c2pool::merged::AuxWork work;
        work.height         = wd.m_data.value("height", 0);
        work.coinbase_value = wd.m_data.value("coinbasevalue", uint64_t(0));
        work.chain_id       = dgb::AUXPOW_CHAIN_ID;   // DGB-native; never DOGE's 98
        work.block_template = wd.m_data;

        if (wd.m_data.contains("previousblockhash"))
            work.prev_block_hash = wd.m_data["previousblockhash"].get<std::string>();

        // Target from bits. The DGB embedded template HOLDS BACK `bits`
        // (Scrypt-only slice: a single-algo walk cannot emit the 5-algo
        // MultiShield difficulty), so this branch is inert until an external
        // bits source is plumbed. Left in place to mirror the DOGE seam exactly.
        if (wd.m_data.contains("bits")) {
            uint32_t bits = static_cast<uint32_t>(
                std::stoul(wd.m_data["bits"].get<std::string>(), nullptr, 16));
            work.target.SetCompact(bits);
        }

        // Aux block hash for the AuxPoW commitment -- the DGB tip's block id
        // (sha256d over the 80-byte header), rendered via the DGB display-hex
        // SSOT. tip_hash() is nullopt until the header ingest fills block_hash,
        // so this stays a truthful absence rather than a fabricated hash.
        if (auto th = m_chain.tip_hash())
            work.block_hash = uint256S(u256_be_display_hex(*th));

        return work;
    }

    c2pool::merged::AuxWork create_aux_block(const std::string& /*address*/) override {
        return get_work_template();
    }

    bool submit_block(const std::string& block_hex) override {
        // Embedded mode: the REAL submit path. P2P relay is performed by the
        // CoinBroadcaster via the registration-site relay lambda / the manager's
        // set_block_relay_fn -- this method logs + caches the block hex so
        // get_block_hex() can hand it to the relay after submission.
        LOG_INFO << "[MM:" << m_config.symbol << "] Embedded: block submitted ("
                 << block_hex.size() / 2 << " bytes)"
                 << " header=" << block_hex.substr(0, std::min(size_t(160), block_hex.size()));
        m_last_block_hex = block_hex;
        return true;
    }

    bool submit_aux_block(const uint256& block_hash, const std::string& auxpow_hex) override {
        // Log-only diagnostic fallback (mirror of the DOGE class). Embedded mode
        // has no daemon to RPC submitauxblock -- the frozen-block path
        // (submit_block + P2P relay) is the primary submission route.
        LOG_WARNING << "[MM:" << m_config.symbol << "] Embedded: submit_aux_block called"
                    << " (fallback path) hash=" << block_hash.GetHex().substr(0, 16) << "..."
                    << " auxpow=" << auxpow_hex.size() / 2 << " bytes"
                    << " -- no daemon to submit to, relying on P2P relay";
        return true;
    }

    std::string get_block_hex(const std::string& /*block_hash*/) override {
        // Return the last submitted block hex (for P2P relay after submission).
        if (!m_last_block_hex.empty())
            return m_last_block_hex;
        return {};
    }

    std::string get_best_block_hash() override {
        if (auto th = m_chain.tip_hash())
            return u256_be_display_hex(*th);
        return "";
    }

    std::vector<NetService> getpeerinfo() override {
        // No daemon peers -- the P2P broadcaster handles its own peer discovery.
        return {};
    }

    const c2pool::merged::AuxChainConfig& config() const override { return m_config; }

    /// Expose the embedded node for sync-gate / tx-source wiring at registration.
    EmbeddedCoinNode& embedded_node() { return m_embedded; }

private:
    c2pool::dgb::HeaderChain&          m_chain;
    dgb::coin::Mempool&                m_pool;
    c2pool::merged::AuxChainConfig     m_config;
    EmbeddedCoinNode                   m_embedded;
    std::string                        m_last_block_hex;  // cached for get_block_hex() after submit
};

} // namespace coin
} // namespace dgb

#endif // AUX_DOGE
