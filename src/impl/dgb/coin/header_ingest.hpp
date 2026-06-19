#pragma once
// ===========================================================================
// c2pool::dgb::wire_header_ingest -- connect the embedded P2P header-download
// feed to the HeaderChain so validate_and_append runs on LIVE headers.
//
// The embedded coin P2P layer (coin/p2p_node.hpp, ADD_P2P_HANDLER(headers))
// parses each received `headers` batch into BlockHeaderType records and fires
// dgb::interfaces::Node::new_headers (coin/node_interface.hpp). Until this
// slice nothing consumed that event for the HeaderChain, so validate_and_append
// never ran on live headers: the chain stayed empty and EmbeddedCoinNode
// reported is_synced()==false / tip_hash()==nullopt regardless of P2P traffic.
//
// wire_header_ingest subscribes the chain to that feed. Every announced header
// is converted through the make_header_sample SSOT (coin/header_sample_build.hpp
// -- the SAME pure builder the ingest scaffold pins: block_hash =
// sha256d(80-byte header), target = SetCompact(nBits), pow_hash left 0 for the
// daemon-port scrypt boundary) and handed to HeaderChain::validate_and_append.
//
// CONSENSUS DISCIPLINE: this connector adds NO policy of its own. Disposition
// (VALIDATED_SCRYPT / ACCEPTED_CONTINUITY / REJECTED), the Scrypt-only PoW gate
// and the work-neutral continuity accounting all live inside
// validate_and_append -- the single validation SSOT. Routing the live path
// through it is what makes "the live header feed cannot bypass the Scrypt-only
// gate" concrete rather than theoretical. The batch is ingested in arrival
// order, exactly as the wire delivered it.
//
// LIFETIME: the handler captures `chain` by reference, so `chain` MUST outlive
// `node`. The returned EventDisposable lets a caller tear the subscription down
// explicitly; while it (and the node) live, every new_headers batch is ingested.
// ===========================================================================

#include <memory>
#include <vector>

#include <core/events.hpp>

#include "node_interface.hpp"        // dgb::interfaces::Node (new_headers feed)
#include "header_chain.hpp"          // c2pool::dgb::HeaderChain / HeaderSample
#include "header_sample_build.hpp"   // c2pool::dgb::make_header_sample SSOT

namespace c2pool::dgb
{

// Subscribe `chain` to `node.new_headers`. Returns the subscription handle so
// the caller controls teardown; the subscription persists for the node's life
// if the handle is dropped (EventDisposable does not auto-dispose on destruction).
inline std::shared_ptr<EventDisposable>
wire_header_ingest(::dgb::interfaces::Node& node, HeaderChain& chain)
{
    return node.new_headers.subscribe(
        [&chain](const std::vector<::dgb::coin::BlockHeaderType>& headers)
        {
            for (const auto& h : headers)
                chain.validate_and_append(make_header_sample(h));
        });
}

} // namespace c2pool::dgb
