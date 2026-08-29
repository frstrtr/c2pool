// SPDX-License-Identifier: AGPL-3.0-or-later
#include "coin_node.hpp"

#include <stdexcept>
#include <utility>

namespace ltc
{

namespace coin
{

core::coin::WorkView CoinNode::get_work_view()
{
    // No work source configured at all -> empty view.
    if (!m_embedded && !m_rpc)
        return {};

    // Embedded preferred, external RPC fallback. getwork() throws
    // std::runtime_error when no template can be produced -- propagated to the
    // caller (web_server), matching the ICoinNode contract. Folds the old
    // web_server.cpp:2167-2168 embedded-vs-rpc decision coin-side.
    rpc::WorkData wd = m_embedded ? m_embedded->getwork() : m_rpc->getwork();

    // Retain the FULL WorkData (incl. m_txs) coin-side. Variable::set takes its
    // argument BY VALUE, so this copies wd; sequenced BEFORE the std::move()s
    // below so the copy completes first -- never move out of wd beforehand.
    // (Pre-seam this was web_server.cpp:2171-2172 m_coin_node->work.set(wd),
    // which only ran in rpc mode; keeping it unconditional here is strictly
    // safe -- the agnostic slice still leaves, the payload still stays.)
    work.set(wd);

    core::coin::WorkView v;
    v.m_data    = std::move(wd.m_data);
    v.m_hashes  = std::move(wd.m_hashes);
    v.m_latency = wd.m_latency;
    return v;
}

bool CoinNode::submit_block_hex(const std::string& block_hex, bool ignore_failure)
{
    // Guard sits ahead of the submit: in embedded-only mode m_rpc can be null.
    // Returning false is the correct "no RPC sink" result (mirrors the old
    // web_server.cpp:2728 `if (m_coin_rpc)` guard).
    if (!m_rpc)
        return false;

    // MWEB arity bridge: ltc NodeRPC::submit_block_hex is the 3-arg
    // (block_hex, mweb, ignore_failure) form. The ICoinNode contract is the
    // 2-arg coin-agnostic form, so we supply mweb="" here. The sole pre-seam
    // caller (web_server.cpp:2730) already passed "" for mweb, so this is
    // behaviour-preserving. FLAG (per integrator, for review): when MWEB
    // submit grows a non-empty extension-block path, mweb must NOT be hard-""
    // -- it would need a coin-side source (e.g. the retained WorkData) rather
    // than a new arg on the shared seam, since mweb is LTC-specific.
    return m_rpc->submit_block_hex(block_hex, "", ignore_failure);
}

} // namespace coin

} // namespace ltc