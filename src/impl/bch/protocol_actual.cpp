// BCH actual-protocol dispatch router (broadcaster-gate / pool p2p ingress).
//
// Mirror of btc::Actual::handle_message with the namespace swapped to bch.
// Conformance anchor: p2poolBCH @6603b79 + btc oracle protocol_actual.cpp.
// Identical routing contract to Legacy: parse RawMessage via m_handler ->
// std::visit-dispatch to the typed handle(msg, peer) overload. The Legacy vs
// Actual split is the wire-protocol generation, not the dispatch shape, so the
// router body is byte-for-byte the same (only the class qualifier differs).
//
// HANDLER bodies land in follow-up slices; this slice is the router skeleton.
#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/random.hpp>
#include <core/common.hpp>

#include <cstring>

namespace bch
{

void Actual::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
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
