#pragma once

// Dash-specialized alias for the enhanced c2pool node template.
// Mirrors impl/ltc/... pattern by pinning the template params to Dash types.

#include <c2pool/node/enhanced_node_impl.hpp>
#include "config.hpp"
#include "share_chain.hpp"
#include "peer.hpp"

namespace dash {

using EnhancedNode = ::c2pool::node::EnhancedC2PoolNodeT<Config, ShareChain, Peer, ShareType>;

} // namespace dash
