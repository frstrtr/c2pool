// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH specialization of the coin-agnostic enhanced-node template.
//
// Mirrors src/c2pool/node/enhanced_node.hpp (the LTC backward-compat alias),
// which explicitly directs other coins here: "For Dash (or other coins),
// include impl/<coin>/enhanced_node.hpp instead".
//
// The alias exists so main_dash.cpp can hand a `std::shared_ptr<core::
// IMiningNode>` to core::WebServer — the same ctor arg main_ltc.cpp passes —
// without dragging LTC types into the DASH binary. Header-only; no consensus
// code lives here and none is edited by adding it.
//
// dash::ShareType is declared in impl/dash/share_chain.hpp (not share.hpp as
// on the LTC side: LTC keeps the ShareVariants alias in share.hpp, DASH keeps
// it next to its ShareIndex/ShareChain). share_chain.hpp includes share.hpp.

#include <c2pool/node/enhanced_node_impl.hpp>

#include <impl/dash/config.hpp>
#include <impl/dash/peer.hpp>
#include <impl/dash/share_chain.hpp>   // dash::ShareType, dash::ShareChain

namespace dash {

using EnhancedDashNode =
    c2pool::node::EnhancedC2PoolNodeT<dash::Config, dash::ShareChain,
                                      dash::Peer, dash::ShareType>;

} // namespace dash
