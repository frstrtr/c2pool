#pragma once
// DGB block-template builder. Mirrors src/impl/btc/coin/template_builder.hpp.
// Must emit p2pool-merged-v36-compatible templates (V36 master compat).
//
// >>> SCRYPT GBT FILTER POINT (M1 section 3) <<<
// DGB multi-algo: getblocktemplate is requested with rules=["scrypt"] so the
// embedded daemon only returns Scrypt-eligible templates. The builder assembles
// and submits Scrypt blocks only in V36. (config_coin.hpp CoinParams::GBT_ALGO.)
//
// Share/PoW format is identical to LTC Scrypt; share assembly reuses the shared
// Scrypt-family path (do NOT fork LTC share logic -- per-coin isolation).
// TODO(M3): TemplateBuilder + EmbeddedCoinNode emitting p2pool-merged-v36-parity
// Scrypt templates (mirror of btc's HeaderChain+Mempool-backed EmbeddedCoinNode).
//
// Namespace note: seam-facing DGB types live in dgb::coin / dgb::interfaces,
// matching config_coin.hpp (namespace dgb) and the btc::coin / ltc::coin
// pattern the family-1 seam binds against.

#include <stdexcept>

#include <nlohmann/json.hpp>

#include "rpc_data.hpp"

namespace dgb
{

namespace coin
{

// --- CoinNodeInterface ------------------------------------------------------
// Abstract interface for obtaining work and submitting blocks; lets the
// concrete CoinNode swap between RPC (legacy), embedded, or hybrid sources
// without changing downstream code. TRIMMED mirror of btc's CoinNodeInterface
// (src/impl/btc/coin/template_builder.hpp:93): submit_block(BlockType&) is
// deferred to M3 with the coin/block.hpp port -- BlockType does not exist for
// dgb yet, and the family-1 seam submits via NodeRPC::submit_block_hex, so
// nothing binds the trimmed slot today.
class CoinNodeInterface {
public:
    virtual ~CoinNodeInterface() = default;

    /// Return a block template as WorkData.
    /// Throws std::runtime_error if no template can be produced.
    virtual rpc::WorkData getwork() = 0;

    /// Return chain info (analogous to getblockchaininfo RPC).
    virtual nlohmann::json getblockchaininfo() = 0;

    /// True when the embedded chain is up to date with the network
    /// AND has enough UTXO depth for coinbase maturity validation.
    virtual bool is_synced() const { return false; }

    // TODO(M3): virtual void submit_block(BlockType& block) = 0; -- restored
    // verbatim from btc once coin/block.hpp is ported.
};

} // namespace coin

} // namespace dgb
