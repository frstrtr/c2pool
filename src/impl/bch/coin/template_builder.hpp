#pragma once
// BCH block-template builder. Mirrors src/impl/btc/coin/template_builder.hpp.
//
// >>> CTOR INSERTION POINT (M1 4.3) <<<
// BCH requires CTOR: canonical (lexicographic txid) ordering of mempool txs
// in the block body, coinbase first. Net-new c2pool code (second BCH slice).
// TODO(M3/M4): CTOR re-sort pass over selected txs before template assembly.
//
// CashTokens (May 2023) awareness: token-bearing outputs must round-trip
// intact through template assembly. TODO(M3/M4): preserve token prefix bytes.
// HogEx: NOT applicable (see config_coin.hpp scope note).
//
// M3 slice 3: CoinNodeInterface (the abstract work-source/submit seam) is
// ported here -- mirroring the BTC source, which co-locates it with the
// builder. It is independent of TemplateBuilder (depends only on rpc::WorkData
// + BlockType) and is the base inherited by bch::coin::CoinNode. The concrete
// TemplateBuilder body (merkle helpers + GBT assembly + CTOR re-sort) remains
// the M4 deliverable below.

#include "block.hpp"
#include "rpc_data.hpp"

#include <nlohmann/json.hpp>

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

// TODO(M4): class TemplateBuilder -- GBT assembly from HeaderChain + Mempool
// with CTOR re-sort and CashTokens-transparent tx carry. (was: namespace
// c2pool::bch TemplateBuilder stub)

} // namespace coin

} // namespace bch
