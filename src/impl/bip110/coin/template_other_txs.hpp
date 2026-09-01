// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// bip110::coin::template_other_txs -- the producer bridge between the captured GBT
// work template's transactions[] (TemplateCapture, reconstructor slice 3 / #837)
// and the won-block reconstructor's template_other_txs_fn seam
// (reconstruct_won_block.hpp, make_reconstruct_closure -- slice 5 / #839).
//
// The reconstructor frames the broadcast block as [gentx] ++ other_txs, where
// other_txs is the captured template's non-coinbase set in template order
// (block tx order after the coinbase). The captured template carries each tx as
// a conformant GBT entry {data,txid,hash,fee} (exactly bitcoind's
// getblocktemplate shape); the reconstructor consumes them as already-
// deserialized bip110::coin::MutableTransaction. This header is the missing decode
// step: the GBT `data` (with-witness) hex -> MutableTransaction, in template
// order. It is the literal wire between TemplateCapture (the template's tx
// SOURCE) and the reconstruct closure (the broadcast tx SINK).
//
// A won BTC share commits to the template it was mined against, so the
// broadcast block's non-coinbase set MUST be that template's transactions[] --
// NOT the live mempool selection, and NOT the share's transaction_hash_refs
// (v34+ SegwitMining/PaddingBugfix/MergedMining shares carry no m_tx_info, so
// the share never carried the block tx set for ANY current version). That is
// why the reconstructor is template-sourced.
//
// SSOT split:
//   * deserialize_template_tx(data_hex)        -- pure: one GBT `data` -> tx.
//   * deserialize_template_other_txs(json)     -- pure: transactions[] -> txs[],
//     in template order. An empty / absent array yields an empty vector (a
//     valid coinbase-only block, the reconstructor's documented empty contract).
//     Throws on a malformed `data` entry (bad hex / trailing bytes) so the
//     closure's broad catch fails the whole won block CLOSED rather than
//     broadcasting a half-decoded tx set (mirrors unpack_gentx_coinbase).
//   * make_template_other_txs_fn(captured_template_txs_fn) -- adapts the per-
//     share captured-transactions[] provider (TemplateCapture::provider(), #837)
//     into the template_other_txs_fn signature make_reconstruct_closure
//     installs. Any decode error propagates so the reconstruct closure fails
//     the won block CLOSED. Wiring the concrete provider is the main_btc run-loop
//     integration (slice 7); this header owns ONLY the decode wire.
//
// Per-coin isolation: src/impl/btc/ only. p2pool-merged-v36 surface: NONE -- the
// transactions[] form is already the conformant GBT shape; this only decodes it
// back into the in-memory tx the block carries. BTC is a standalone SHA256d
// parent (no merged-coinbase leg).
// ---------------------------------------------------------------------------

#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // ParseHex

#include "transaction.hpp"   // MutableTransaction, UnserializeTransaction, TX_WITH_WITNESS, PackStream

namespace bip110
{
namespace coin
{

// Decode one GBT `data` (with-witness) hex string into a MutableTransaction.
// The captured template's `data` is the full serialized transaction WITH
// witness (bitcoind getblocktemplate), so decode symmetrically with
// TX_WITH_WITNESS. Throws std::out_of_range if the hex carries trailing bytes
// past a complete transaction (a malformed template entry), matching
// unpack_gentx_coinbase's fail-closed contract for the gentx.
inline MutableTransaction
deserialize_template_tx(const std::string& data_hex)
{
    PackStream ps(ParseHex(data_hex));
    MutableTransaction tx;
    UnserializeTransaction(tx, ps, TX_WITH_WITNESS);
    if (!ps.empty())
        throw std::out_of_range(
            "deserialize_template_tx: trailing bytes after tx -- "
            "malformed GBT template `data` entry");
    return tx;
}

// Decode the captured GBT template's transactions[] into the won-block other-tx
// vector, in template order (block tx order after the coinbase). Each entry's
// `data` field is the with-witness bytes the template carried. An empty /
// absent array yields an empty vector (a valid coinbase-only block).
inline std::vector<MutableTransaction>
deserialize_template_other_txs(const nlohmann::json& transactions)
{
    std::vector<MutableTransaction> out;
    if (transactions.is_array())
    {
        out.reserve(transactions.size());
        for (const auto& entry : transactions)
            out.push_back(deserialize_template_tx(entry.at("data").get<std::string>()));
    }
    return out;
}

// Adapt a per-share captured-transactions[] provider into the run-loop's
// template_other_txs_fn (the third argument of make_reconstruct_closure).
// captured_template_txs_fn(share_hash) MUST return the transactions[] of the
// template the won share was mined against (per-job capture, #837); decoded here
// through the deserialize SSOT. Any decode error propagates so the reconstruct
// closure fails the won block CLOSED.
inline std::function<std::vector<MutableTransaction>(const uint256&)>
make_template_other_txs_fn(
    std::function<nlohmann::json(const uint256&)> captured_template_txs_fn)
{
    return [captured_template_txs_fn = std::move(captured_template_txs_fn)](
               const uint256& share_hash) -> std::vector<MutableTransaction> {
        return deserialize_template_other_txs(captured_template_txs_fn(share_hash));
    };
}

} // namespace coin
} // namespace bip110
