// SPDX-License-Identifier: AGPL-3.0-or-later
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
// LINKAGE (ingest_linked): a header is appended only onto its parent; known
// headers are skipped, a header onto an earlier retained header cuts the chain
// back to it (the peer's branch), an unconnected one is dropped.
//
// CONSENSUS DISCIPLINE: beyond the linkage this connector adds NO policy. Disposition
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
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include "node_interface.hpp"        // dgb::interfaces::Node (new_headers feed)
#include "header_chain.hpp"          // c2pool::dgb::HeaderChain / HeaderSample
#include "header_sample_build.hpp"   // c2pool::dgb::make_header_sample SSOT

namespace c2pool::dgb
{

// Subscribe `chain` to `node.new_headers`. Returns the subscription handle so
// the caller controls teardown; the subscription persists for the node's life
// if the handle is dropped (EventDisposable does not auto-dispose on destruction).
// What ingest_linked did with one header.
enum class LinkResult {
    APPENDED,      // onto the tip (or the first header of an empty chain)
    KNOWN,         // already in the retained window: skipped
    REORGED,       // onto an earlier retained header: the chain was cut back to it
    UNCONNECTED,   // its parent is not retained: dropped
    REJECTED,      // validate_and_append refused it
};

// One header, linked: appended only onto its parent. Before, every header
// was appended in arrival order whatever its parent, so a peer answering a
// locator it did not know (from genesis) or a stale block left the chain
// wedged: old headers fail the MTP gate, and a stale tip made every
// getheaders answer start from genesis again (dgb.voidbind, 2026-11-27:
// 161k blocks behind, re-downloading batches). A header whose parent is a
// retained header below the tip is the peer's branch: the chain is cut back
// to that parent (truncate_after) and follows it, as a header-following node
// follows its peer's best chain. Validation is validate_and_append's.
inline LinkResult ingest_linked(HeaderChain& chain, const HeaderSample& s)
{
    const auto tip = chain.tip_hash();
    if (!tip || s.prev_hash.is_zero() || s.prev_hash == *tip)
        return chain.validate_and_append(s) == IngestResult::REJECTED ? LinkResult::REJECTED : LinkResult::APPENDED;
    if (chain.find_index(s.block_hash))
        return LinkResult::KNOWN;
    const auto parent = chain.find_index(s.prev_hash);
    if (!parent)
        return LinkResult::UNCONNECTED;
    chain.truncate_after(*parent);
    return chain.validate_and_append(s) == IngestResult::REJECTED ? LinkResult::REJECTED : LinkResult::REORGED;
}

// The wire uint256 of a u256 block id (from_le_bytes inverted).
inline uint256 wire_hash(const u256& v)
{
    std::vector<unsigned char> b(32);
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 8; ++j)
            b[i * 8 + j] = static_cast<unsigned char>((v.limb[i] >> (8 * j)) & 0xffu);
    return uint256(b);
}

// The getheaders locator for `chain` (HeaderChain::locator: the tip, 10 below
// it, then doubling steps), ending with `genesis` when given; [genesis] for
// an empty chain.
inline std::vector<uint256> getheaders_locator(const HeaderChain& chain, const uint256& genesis)
{
    std::vector<uint256> out;
    for (const auto& h : chain.locator())
        out.push_back(wire_hash(h));
    if (!genesis.IsNull() && (out.empty() || out.back() != genesis))
        out.push_back(genesis);
    return out;
}

inline std::shared_ptr<EventDisposable>
wire_header_ingest(::dgb::interfaces::Node& node, HeaderChain& chain)
{
    return node.new_headers.subscribe(
        [&chain](const std::vector<::dgb::coin::BlockHeaderType>& headers)
        {
            std::size_t reorged = 0, unconnected = 0;
            for (const auto& h : headers) {
                // The cheap linkage first (sha256d, no scrypt): a known or an
                // unconnected header is decided without building its sample.
                auto packed = pack(h);
                uint256 id = Hash(packed.get_span());
                const u256 block_hash = u256::from_le_bytes(reinterpret_cast<const unsigned char*>(id.begin()));
                uint256 prev_id = h.m_previous_block;
                const u256 prev = u256::from_le_bytes(reinterpret_cast<const unsigned char*>(prev_id.begin()));
                const auto tip = chain.tip_hash();
                if (tip && !prev.is_zero() && !(prev == *tip)) {
                    if (chain.find_index(block_hash))
                        continue;
                    if (!chain.find_index(prev)) {
                        ++unconnected;
                        continue;
                    }
                }
                switch (ingest_linked(chain, make_header_sample(h))) {
                case LinkResult::REORGED: ++reorged; break;
                case LinkResult::UNCONNECTED: ++unconnected; break;
                default: break;
                }
            }
            if (reorged)
                LOG_WARNING << "[DGB-HEADERS] followed the peer's branch: chain cut back to a retained header ("
                            << reorged << " header(s) of the batch reorged)";
            if (unconnected && unconnected == headers.size())
                LOG_INFO << "[DGB-HEADERS] a batch of " << unconnected
                         << " header(s) does not connect to the retained chain: dropped";
        });
}

} // namespace c2pool::dgb