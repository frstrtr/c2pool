// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <vector>

#include <core/uint256.hpp>

namespace dgb
{

// SSOT: the new-transaction hashes a share references for peer tx-relay.
//
// DGB shares carry these INSIDE m_tx_info (dgb::ShareTxInfo), and only on the
// pre-segwit variants Share (v17) and NewShare (v33). v34/v35/v36 declare no
// m_tx_info member, so the `requires { obj->m_tx_info; }` probe compiles the
// body out for them: correct-by-construction, never silently dead.
//
// This replaces the defective `requires { obj->m_new_transaction_hashes; }`
// probe in send_shares(), which named a TOP-LEVEL member NO dgb share type
// declares (the field is nested in m_tx_info). That probe was ALWAYS false, so
// the remember_tx/forget_tx relay block never forwarded a single tx hash to a
// peer for ANY share version. Faithful port of the btc fix behind #880
// (src/impl/btc/node.cpp: guard on obj->m_tx_info, iterate the nested member).
template <typename ShareT>
inline void append_share_tx_refs(const ShareT* obj, std::vector<uint256>& out)
{
    if constexpr (requires { obj->m_tx_info; })
        for (const auto& th : obj->m_tx_info.m_new_transaction_hashes)
            out.push_back(th);
}

} // namespace dgb
