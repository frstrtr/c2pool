// BCH legacy-protocol dispatch router (broadcaster-gate / pool p2p ingress).
//
// Mirror of btc::Legacy::handle_message with the namespace swapped to bch.
// Conformance anchor: p2poolBCH @6603b79 + btc oracle protocol_legacy.cpp.
// Routing contract (matches oracle exactly, the thing reviewers diff):
//   parse RawMessage via m_handler -> std::visit-dispatch to the typed
//   handle(msg, peer) HANDLER overload for the command. Unknown/over-old
//   peers are gated upstream by NodeBridge via handle_version (require-version
//   before any command routes here). Parse and handler faults are logged and
//   swallowed per-message — never tear down the peer loop on one bad frame.
//
// HANDLER bodies (addrs/shares/sharereq/...) land in follow-up slices; this
// slice is the router skeleton only.
#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/random.hpp>
#include <core/common.hpp>

namespace bch
{

void Legacy::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    bch::Handler::result_t result;
    try
    {
        result = m_handler.parse(rmsg);
    } catch (const std::exception& ec)
    {
        LOG_WARNING << "Failed to parse message '" << rmsg->m_command << "' from "
                    << peer->addr().to_string() << ": " << ec.what();
        return;
    }

    try
    {
        std::visit([&](auto& msg){ handle(std::move(msg), peer); }, result);
    }
    catch (const std::exception& ec)
    {
        LOG_WARNING << "Handler error for '" << rmsg->m_command << "' from "
                    << peer->addr().to_string() << ": " << ec.what();
        return;
    }
}

} // namespace bch
