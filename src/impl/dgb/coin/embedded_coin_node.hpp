// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ===========================================================================
// dgb::coin::EmbeddedCoinNode -- embedded (no external digibyted) work source.
//
// Implements CoinNodeInterface::getwork() (coin/template_builder.hpp) by
// assembling a GBT-compatible work template ENTIRELY from in-process embedded
// chain state -- the HeaderChain (coin/header_chain.hpp) plus the coin's
// subsidy schedule -- with NO external RPC. This is the SECOND caller of
// dgb::coin::build_work_template(): the stratum work source
// (DGBWorkSource::get_current_work_template, stratum/work_source.cpp) is the
// first. Routing BOTH the miner-facing stratum path and the embedded
// CoinNodeInterface path through the one build_work_template SSOT is what makes
// the "the two paths cannot emit a divergent template" guarantee CONCRETE
// rather than theoretical (integrator directive, 2026-06-19).
//
// CONSENSUS DISCIPLINE (identical to build_work_template + the stratum caller):
//   * coinbasevalue is resolved through the #207 resolve_coinbase_value SSOT.
//     On the embedded path there is no external GBT figure, so it is derived
//     as subsidy_func(height) + total_fees via embedded_coinbase_value.hpp.
//     The external-daemon GBT fallback (NodeRPC::getwork) is a SEPARATE path
//     and is untouched -- this node is the no-external-daemon source only.
//   * version pins the Scrypt lane (build_work_template, DGB_BLOCK_VERSION_SCRYPT).
//   * transactions[] + the fee total come from an injected EmbeddedTxSource
//     (default empty -> empty transactions[], 0 fees, byte-identical to the
//     pre-tx-select call site). The production source (embedded_tx_select.cpp,
//     make_mempool_tx_source) selects fee-sorted mempool txs; their fee total
//     is folded into coinbasevalue via resolve_coinbase_value (#207), never
//     fabricated, and transactions[] is passed through build_work_template
//     verbatim.
//   * previousblockhash is emitted ONLY when HeaderChain::tip_hash() carries a
//     real tip id, rendered through the coin/hash_format.hpp SSOT so it is
//     byte-identical to the stratum caller's previousblockhash.
//   * bits is HELD BACK (MultiShield V4 next-target is a 5-algo global window
//     == V37; a Scrypt-only walk would emit a known-wrong difficulty). It
//     becomes a GBT pass-through once an external-daemon bits source is plumbed.
//
// Header-only + pure w.r.t. its inputs: make_inputs(curtime) is split out so
// the assembly is deterministically unit-testable without a wall clock or a
// running node; getwork() supplies std::time(nullptr) in production exactly as
// the stratum caller does.
// ===========================================================================

#include <ctime>
#include <cstdint>
#include <optional>
#include <functional>
#include <utility>

#include <core/pow.hpp>   // core::SubsidyFunc

#include "header_chain.hpp"            // c2pool::dgb::HeaderChain
#include "hash_format.hpp"            // u256_be_display_hex SSOT
#include "embedded_coinbase_value.hpp"  // resolve_coinbase_value SSOT (#207)
#include "template_builder.hpp"       // build_work_template SSOT + CoinNodeInterface
#include "rpc_data.hpp"               // rpc::WorkData

namespace dgb::coin
{

// Caller-supplied embedded transaction selection. Decouples EmbeddedCoinNode
// from the heavy tx/UTXO codec (mempool.hpp -> transaction.hpp pulls the
// btclibs serialization templates -- the #143 SCC trap): the node consumes
// only the ALREADY-SHAPED GBT transactions[] array + the fee total, both plain
// JSON/integer, so this header stays codec-free and a guard-weight TU that
// reaches it never compiles the serialization templates. The production shaper
// lives out-of-line in embedded_tx_select.cpp (make_mempool_tx_source).
struct EmbeddedTxSelection
{
    // GBT transactions[] array, per-tx {data,txid,hash,fee} -- build_work_template
    // passes it through verbatim. Empty array = no txs selected.
    nlohmann::json transactions = nlohmann::json::array();
    // Sum of the known fees across the selected txs, folded into coinbasevalue
    // via the #207 resolve_coinbase_value SSOT (NOT added to the template here).
    uint64_t total_fees = 0;
};

// Injected transaction source. An empty std::function (the default) means NO
// transaction source is wired: the node emits an empty transactions[] and 0
// fees -- byte-identical to the pre-tx-select #237 call site. The production
// wiring injects make_mempool_tx_source(mempool, max_weight).
using EmbeddedTxSource = std::function<EmbeddedTxSelection()>;

class EmbeddedCoinNode : public CoinNodeInterface
{
public:
    EmbeddedCoinNode(c2pool::dgb::HeaderChain& chain,
                     core::SubsidyFunc        subsidy_func,
                     EmbeddedTxSource         tx_source = {})
        : m_chain(chain), m_subsidy_func(std::move(subsidy_func)),
          m_tx_source(std::move(tx_source))
    {
    }

    // Assemble the build_work_template inputs from the live embedded chain
    // state. Split from getwork() so the curtime is injectable for
    // deterministic tests (the stratum caller does the same with std::time).
    WorkTemplateInputs make_inputs(int64_t curtime) const
    {
        const uint32_t height = m_chain.next_block_height();

        // Pull the caller-supplied transaction selection (empty when no source
        // is wired -> byte-identical to the pre-tx-select template). The heavy
        // codec that shapes these lives out-of-line (embedded_tx_select.cpp);
        // this node only folds the fee total into coinbasevalue and passes the
        // transactions[] array through build_work_template.
        EmbeddedTxSelection sel;
        if (m_tx_source)
            sel = m_tx_source();

        WorkTemplateInputs in;
        in.next_height      = height;
        // Embedded path: no external GBT value -> derive subsidy(height)+fees
        // via the #207 SSOT. total_fees comes from the selected txs (0 when no
        // source is wired).
        in.coinbasevalue    = resolve_coinbase_value(m_subsidy_func, height,
                                                      /*total_fees=*/sel.total_fees,
                                                      /*gbt_coinbasevalue=*/std::nullopt);
        in.median_time_past = m_chain.median_time_past();
        in.curtime          = curtime;
        in.transactions     = std::move(sel.transactions);
        if (auto th = m_chain.tip_hash())
            in.previousblockhash = u256_be_display_hex(*th);
        return in;
    }

    // CoinNodeInterface: produce a WorkData carrying the embedded template.
    // m_hashes stays empty (transactions[] is empty), m_latency 0 (no RPC).
    rpc::WorkData getwork() override
    {
        rpc::WorkData wd;
        wd.m_data = build_work_template(make_inputs(std::time(nullptr)));
        return wd;
    }

    // Minimal chain-info shaped like getblockchaininfo's relevant fields. The
    // embedded chain reports its absolute tip height (0 on an empty chain).
    nlohmann::json getblockchaininfo() override
    {
        nlohmann::json info = nlohmann::json::object();
        info["blocks"] = m_chain.tip_height().value_or(0);
        return info;
    }

    // Not synced until the embedded P2P header-download ingest is wired (it is
    // what populates HeaderSample.block_hash and gives real UTXO depth). A
    // truthful false, never an optimistic claim of readiness.
    bool is_synced() const override { return false; }

private:
    c2pool::dgb::HeaderChain& m_chain;
    core::SubsidyFunc         m_subsidy_func;
    EmbeddedTxSource          m_tx_source;
};

} // namespace dgb::coin