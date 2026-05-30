#pragma once

// Backward-compat header: resolves c2pool::node::EnhancedC2PoolNode to the
// LTC-specialized instance of the template in enhanced_node_impl.hpp.
// For Dash (or other coins), include impl/<coin>/enhanced_node.hpp instead.

#include <c2pool/node/enhanced_node_impl.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/peer.hpp>
#include <impl/ltc/share.hpp>

namespace c2pool {
namespace node {

using EnhancedC2PoolNode = EnhancedC2PoolNodeT<ltc::Config, ltc::ShareChain, ltc::Peer, ltc::ShareType>;

} // namespace node
} // namespace c2pool
