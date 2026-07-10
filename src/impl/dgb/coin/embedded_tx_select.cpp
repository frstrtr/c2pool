// SPDX-License-Identifier: AGPL-3.0-or-later
// ===========================================================================
// embedded_tx_select.cpp -- out-of-line shaper for the embedded tx source.
//
// The tx/UTXO serialization codec (TX_WITH_WITNESS pack + Hash + HexStr) lives
// here, NOT in any header, so embedded_coin_node.hpp stays codec-free and the
// #143 btclibs SCC trap stays shut. Compiled into dgb_coin (which already links
// the full btclibs serialization), so the codec resolves at link time.
//
// Mirrors the per-tx GBT entry shape src/impl/btc/coin/template_builder.hpp
// emits, so c2pool-dgb and the p2pool-dgb-scrypt reference consume an identical
// transactions[] form (p2pool reads `fee` in helper.py:123 and adjusts subsidy
// in data.py:876-884 when a tx is excluded from the share).
// ===========================================================================

#include "embedded_tx_select.hpp"

#include "transaction.hpp"            // TX_WITH_WITNESS, compute_txid is in mempool.hpp

#include <core/pack.hpp>             // pack
#include <core/hash.hpp>            // Hash (sha256d)
#include <btclibs/util/strencodings.h>  // HexStr

#include <string>
#include <utility>

namespace dgb::coin
{

EmbeddedTxSource make_mempool_tx_source(Mempool& pool, uint32_t max_weight)
{
    return [&pool, max_weight]() -> EmbeddedTxSelection {
        auto [selected, total_fees] = pool.get_sorted_txs_with_fees(max_weight);

        EmbeddedTxSelection out;
        out.total_fees = total_fees;

        nlohmann::json tx_array = nlohmann::json::array();
        for (const auto& stx : selected)
        {
            // data  = with-witness serialization hex (what a daemon submits)
            // txid  = legacy (non-witness) sha256d
            // hash  = wtxid (with-witness sha256d) for the witness merkle tree
            const uint256     txid     = compute_txid(stx.tx);
            auto              packed   = pack(TX_WITH_WITNESS(stx.tx));
            const std::string hex_data = HexStr(packed.get_span());
            const uint256     wtxid    = Hash(packed.get_span());

            nlohmann::json entry;
            entry["data"] = hex_data;
            entry["txid"] = txid.GetHex();
            entry["hash"] = wtxid.GetHex();
            if (stx.fee_known)
                entry["fee"] = static_cast<int64_t>(stx.fee);
            else
                entry["fee"] = nullptr;   // JSON null -> p2pool base_subsidy fallback
            tx_array.push_back(std::move(entry));
        }

        out.transactions = std::move(tx_array);
        return out;
    };
}

} // namespace dgb::coin