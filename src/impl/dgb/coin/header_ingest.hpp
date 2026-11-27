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
// headers are skipped; a fork branch from a retained header at most
// kMaxReorgDepth below the tip switches the tip only once it is longer, with
// the chain restored on a rejection; a zero or unretained parent is dropped.
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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
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

// What ingest_linked did with one header.
enum class LinkResult {
    APPENDED,      // onto the tip (or the first header of an empty chain)
    KNOWN,         // already in the retained window: skipped
    BUFFERED,      // a fork header kept aside: its branch is not longer yet
    REORGED,       // its branch became longer: the tip switched to it
    UNCONNECTED,   // its parent is not retained, too deep, or zero: dropped
    REJECTED,      // validate_and_append refused it (the chain is unchanged)
};

// A fork branch below the tip is kept here until it is longer than the
// branch above its fork point (first seen keeps the tip).
inline constexpr std::size_t kMaxReorgDepth = 32;
struct ForkBuffer {
    u256 parent = 0;
    std::vector<HeaderSample> headers;
};

// One header, linked: appended only onto its parent. Rules:
//   - the tip's child is appended (validate_and_append);
//   - a zero parent on a non-empty chain is refused (UNCONNECTED);
//   - a header onto a retained header at most kMaxReorgDepth below the tip
//     starts or extends a fork branch, kept aside until that branch is
//     strictly longer than the branch above the fork point; then the tip
//     switches to it, every header validated in the fork's own context, and
//     on any rejection the chain is restored exactly;
//   - anything else is dropped.
// The first header of an empty chain onto `genesis` sits at height 1.
// `cut_depth`, when given, receives the depth of a switch.
inline LinkResult ingest_linked(HeaderChain& chain, ForkBuffer& fork, const HeaderSample& s,
                                const u256& genesis = 0, std::size_t* cut_depth = nullptr)
{
    const auto tip = chain.tip_hash();
    if (!tip) {
        if (chain.size() == 0 && !genesis.is_zero() && s.prev_hash == genesis && chain.base_height() == 0)
            chain.set_base_height(1);
        return chain.validate_and_append(s) == IngestResult::REJECTED ? LinkResult::REJECTED : LinkResult::APPENDED;
    }
    if (s.prev_hash.is_zero())
        return LinkResult::UNCONNECTED;
    if (s.prev_hash == *tip)
        return chain.validate_and_append(s) == IngestResult::REJECTED ? LinkResult::REJECTED : LinkResult::APPENDED;
    if (chain.find_index(s.block_hash))
        return LinkResult::KNOWN;
    if (!fork.headers.empty() && s.prev_hash == fork.headers.back().block_hash) {
        fork.headers.push_back(s);
    } else if (const auto p = chain.find_index(s.prev_hash)) {
        if (chain.size() - 1 - *p > kMaxReorgDepth)
            return LinkResult::UNCONNECTED;
        fork.parent = s.prev_hash;
        fork.headers.assign(1, s);
    } else {
        return LinkResult::UNCONNECTED;
    }
    const auto p = chain.find_index(fork.parent);
    if (!p || chain.size() - 1 - *p > kMaxReorgDepth) {
        fork.headers.clear();
        return LinkResult::UNCONNECTED;
    }
    const std::size_t above = chain.size() - 1 - *p;
    if (fork.headers.size() <= above)
        return LinkResult::BUFFERED;
    // Switch: the fork onto its parent, validated there; restored on reject.
    // The parent is tracked by height (an append may evict the window front).
    const uint64_t parent_height = chain.base_height() + *p;
    const std::vector<HeaderSample> tail = chain.tail_after(*p);
    chain.truncate_after(*p);
    for (const auto& h : fork.headers) {
        if (chain.validate_and_append(h) == IngestResult::REJECTED) {
            chain.truncate_after(static_cast<std::size_t>(parent_height - chain.base_height()));
            chain.restore_tail(tail);
            fork.headers.clear();
            return LinkResult::REJECTED;
        }
    }
    fork.headers.clear();
    if (cut_depth)
        *cut_depth = above;
    return LinkResult::REORGED;
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

// The live ingest's options (main_dgb): the genesis the first header sits
// on, a getheaders request with the chain's locator (an unconnected or a
// buffered fork header: the peer is asked from the fork point, as Core does),
// the tip height published after each batch (for other threads), and the
// depth of a tip switch.
struct HeaderIngestOptions {
    u256 genesis = 0;
    std::function<void()> request_headers;
    std::function<void(uint32_t)> on_tip;
    std::function<void(std::size_t)> on_reorg;
};

// Subscribe `chain` to `node.new_headers`. Returns the subscription handle so
// the caller controls teardown; the subscription persists for the node's life
// if the handle is dropped (EventDisposable does not auto-dispose on destruction).
inline std::shared_ptr<EventDisposable>
wire_header_ingest(::dgb::interfaces::Node& node, HeaderChain& chain, HeaderIngestOptions opts = {})
{
    auto fork = std::make_shared<ForkBuffer>();
    return node.new_headers.subscribe(
        [&chain, fork, opts](const std::vector<::dgb::coin::BlockHeaderType>& headers)
        {
            std::size_t reorged = 0, unconnected = 0, buffered = 0, deepest = 0;
            for (const auto& h : headers) {
                // The cheap linkage first (sha256d, no scrypt): a known or an
                // unconnected header is decided without building its sample.
                auto packed = pack(h);
                uint256 id = Hash(packed.get_span());
                const u256 block_hash = u256::from_le_bytes(reinterpret_cast<const unsigned char*>(id.begin()));
                uint256 prev_id = h.m_previous_block;
                const u256 prev = u256::from_le_bytes(reinterpret_cast<const unsigned char*>(prev_id.begin()));
                const auto tip = chain.tip_hash();
                if (tip && !(prev == *tip)) {
                    if (prev.is_zero()) {
                        ++unconnected;
                        continue;
                    }
                    if (chain.find_index(block_hash))
                        continue;
                    const bool extends_fork = !fork->headers.empty() && prev == fork->headers.back().block_hash;
                    if (!extends_fork && !chain.find_index(prev)) {
                        ++unconnected;
                        continue;
                    }
                }
                std::size_t depth = 0;
                switch (ingest_linked(chain, *fork, make_header_sample(h), opts.genesis, &depth)) {
                case LinkResult::REORGED: ++reorged; deepest = std::max(deepest, depth); break;
                case LinkResult::BUFFERED: ++buffered; break;
                case LinkResult::UNCONNECTED: ++unconnected; break;
                default: break;
                }
            }
            if (reorged) {
                LOG_WARNING << "[DGB-HEADERS] the tip switched to a longer branch (cut " << deepest
                            << " header(s) deep)";
                if (opts.on_reorg)
                    opts.on_reorg(deepest);
            }
            if (unconnected && unconnected == headers.size())
                LOG_INFO << "[DGB-HEADERS] a batch of " << unconnected
                         << " header(s) does not connect to the retained chain: dropped";
            if ((unconnected || buffered) && opts.request_headers)
                opts.request_headers();
            if (opts.on_tip)
                opts.on_tip(chain.tip_height().value_or(0));
        });
}

} // namespace c2pool::dgb