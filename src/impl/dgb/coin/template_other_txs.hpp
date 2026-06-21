// ---------------------------------------------------------------------------
// template_other_txs.hpp -- the producer bridge between the embedded work
// template's transactions[] (make_mempool_tx_source / embedded_tx_select.cpp)
// and the won-block reconstructor's template_other_txs_fn seam
// (reconstruct_closure.hpp, make_reconstruct_closure_from_template).
//
// The reconstructor frames the broadcast block as [gentx] ++ other_txs, where
// other_txs is the captured-GBT template's non-coinbase set in template order
// (#271). The template carries each tx as a GBT entry {data,txid,hash,fee}; the
// reconstructor consumes them as already-deserialized dgb::coin::Mutable-
// Transaction. This header is the missing deserialize step: the GBT `data`
// (with-witness) hex -> MutableTransaction, in template order. It is the literal
// wire between make_mempool_tx_source (the template's tx SOURCE) and the
// reconstructor (the broadcast tx SINK).
//
// SSOT split:
//   * deserialize_template_other_txs(json)  -- pure: transactions[] -> txs[].
//     Throws on a malformed `data` entry (bad hex / trailing bytes) so the
//     closure's broad catch fails the whole won block CLOSED rather than
//     broadcasting a half-decoded tx set (mirrors unpack_gentx_coinbase).
//   * make_template_other_txs_fn(captured_template_txs_fn) -- adapts a per-share
//     captured-transactions[] provider into the template_other_txs_fn signature
//     make_reconstruct_closure_from_template installs. The provider MUST return
//     the transactions[] of the GBT TEMPLATE the won share was handed at job
//     hand-out (the per-job capture seam, #271), NOT the live mempool selection:
//     a won share commits to the template it was mined against, which may differ
//     from the current mempool. Wiring that per-job capture provider is the
//     run-loop integration; this header owns ONLY the deserialize wire.
//
// Per-coin isolation: src/impl/dgb/ only. p2pool-merged-v36 surface: NONE -- the
// transactions[] form is already the conformant GBT shape make_mempool_tx_source
// emits; this only decodes it back into the in-memory tx the block carries.
// ---------------------------------------------------------------------------
#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // ParseHex

#include "transaction.hpp"   // MutableTransaction, UnserializeTransaction, TX_WITH_WITNESS

namespace dgb
{
namespace coin
{

// Decode one GBT `data` (with-witness) hex string into a MutableTransaction.
// Throws std::out_of_range if the hex carries trailing bytes past a complete
// transaction (a malformed template entry), matching unpack_gentx_coinbase's
// fail-closed contract for the gentx.
inline MutableTransaction
deserialize_template_tx(const std::string& data_hex)
{
    PackStream ps(ParseHex(data_hex));
    MutableTransaction tx;
    // With-witness parse: make_mempool_tx_source emits `data` as the with-
    // witness submit bytes (pack(TX_WITH_WITNESS(tx))), so decode symmetrically.
    UnserializeTransaction(tx, ps, TX_WITH_WITNESS);
    if (!ps.empty())
        throw std::out_of_range(
            "deserialize_template_tx: trailing bytes after tx -- "
            "malformed GBT template `data` entry");
    return tx;
}

// Decode the captured GBT template's transactions[] into the won-block other-tx
// vector, in template order (block tx order after the coinbase). Each entry's
// `data` field is the with-witness bytes make_mempool_tx_source emitted. An
// empty / absent array yields an empty vector (a valid coinbase-only block).
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
// template_other_txs_fn (the third argument of make_reconstruct_closure_from_
// template). captured_template_txs_fn(share_hash) MUST return the transactions[]
// of the template the won share was mined against (per-job capture, #271);
// decoded here through the deserialize SSOT. Any decode error propagates so the
// reconstruct closure fails the won block CLOSED.
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
} // namespace dgb
