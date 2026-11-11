// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The SML leaf of a masternode state: Dash Core v24.0.0
/// CDeterministicMN::to_sml_entry (src/evo/deterministicmns.cpp:45-52), for
/// every state type that carries the v24 state members (MNState of the payee
/// projection, ReplayMNState of the root-checked replay fold).
///
/// One definition, used by the replay fold (ReplayMNState::to_sml_entry) and
/// by the template-side v24 fold (sml_special_fold.hpp), so the leaf a served
/// template commits for a masternode a provider tx changed is derived exactly
/// as the root-checked fold derives it for a mined block.

#include <impl/dash/coin/v24_state.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>     // opkey_for_leaf
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

namespace dash {
namespace coin {
namespace v24 {

/// The fields a masternode state contributes to its SML leaf: everything but
/// proRegTxHash, confirmedHash and isValid, which the caller owns (the replay
/// fold has its own confirmedHash and ban state; the template fold takes them
/// from the projected leaf and the transitions it applied).
///
/// The store keeps the operator key canonical basic; the leaf carries it in
/// the scheme the entry nVersion dictates (legacy iff nVersion < BasicBLS). A
/// v3 leaf carries the ExtNetInfo and no legacy service (and no
/// platformHTTPPort: the leaf codec skips it at v3).
template <typename S>
void write_sml_leaf_fields(const S& st, vendor::CSimplifiedMNListEntry& e)
{
    e.nVersion = st.nVersion;
    // An empty MnNetInfo is hashed as CService{}: 16 zero bytes, port 0.
    e.netAddress = st.netInfo.canonical().ip;
    e.netPort = st.netInfo.canonical().port_be;
    e.extNetInfo = vendor::ExtNetInfo{};
    if (state_has_ext(st.nVersion)) {
        e.netAddress = {};
        e.netPort = 0;
        e.extNetInfo = st.v24.extNetInfo;
    }
    e.pubKeyOperator = vendor::opkey_for_leaf(st.pubKeyOperator, st.nVersion < vendor::ProTxVersion::BASIC_BLS);
    e.keyIDVoting = st.keyIDVoting;
    e.nType = st.nType;
    e.platformHTTPPort = st.platformHTTPPort;
    e.platformNodeID = st.platformNodeID;
}

} // namespace v24
} // namespace coin
} // namespace dash
