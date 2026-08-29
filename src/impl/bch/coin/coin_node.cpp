// SPDX-License-Identifier: AGPL-3.0-or-later
#include "coin_node.hpp"

#include <stdexcept>
#include <utility>

namespace bch
{

namespace coin
{

core::coin::WorkView CoinNode::get_work_view()
{
    // No work source configured at all -> empty view (1:1 with the btc/ltc reference).
    if (!m_embedded && !m_rpc)
        return {};

    // Embedded preferred, external RPC fallback. getwork() throws
    // std::runtime_error when no template can be produced -- propagated to the
    // caller (web_server), matching the ICoinNode contract.
    rpc::WorkData wd = m_embedded ? m_embedded->getwork() : m_rpc->getwork();

    // Retain the FULL WorkData (incl. m_txs) coin-side. Variable::set takes its
    // argument BY VALUE, so this copies wd; sequenced BEFORE the std::move()s
    // below so the copy completes first -- never move out of wd beforehand.
    work.set(wd);

    core::coin::WorkView v;
    v.m_data    = std::move(wd.m_data);
    v.m_hashes  = std::move(wd.m_hashes);
    v.m_latency = wd.m_latency;
    return v;
}

bool CoinNode::submit_block_hex(const std::string& block_hex, bool ignore_failure)
{
    // Guard sits ahead of the submit: in embedded-preferred mode m_rpc can be
    // null. Returning false is the correct "no RPC sink" result.
    if (!m_rpc)
        return false;

    // BCH's NodeRPC::submit_block_hex is the agnostic 2-arg/no-mweb form (MWEB
    // is LTC-specific and absent here), so we forward directly -- no 3-arg
    // mweb="" coin-side overload exists or is needed for BCH.
    return m_rpc->submit_block_hex(block_hex, ignore_failure);
}

} // namespace coin

} // namespace bch