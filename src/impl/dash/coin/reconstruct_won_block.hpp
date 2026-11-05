// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// dash::coin::reconstruct_won_block -- turn a VERIFIED won share into the full
// serialized DASH parent block, ready for broadcast_won_block's dual path.
//
// This is the DASH analogue of dgb::coin::reconstruct_won_block
// (src/impl/dgb/coin/reconstruct_won_block.hpp) and the C++ of p2pool-dash
// data.py Share.as_block(tracker, known_txs):
//
//     gentx     = self.check(tracker, known_txs)                 # coinbase tx
//     other_txs = [known_txs[h]
//                  for h in self.get_other_tx_hashes(tracker)]   # ref-walk
//     return dict(header=self.header, txs=[gentx]+other_txs)
//
// THE DASH-SPECIFIC BIT -- the coinbase is a DIP3/DIP4 special CbTx (version|type
// = 3|(5<<16), extra_payload appended). We do NOT re-implement that assembly:
// generate_share_transaction (share_check.hpp) ALREADY regenerates the exact
// coinbase the share committed to (it is the accept-path payout-commitment
// keystone, KAT-proven by test_dash_payout_commitment / test_dash_share_producer),
// and now exposes the coinbase BYTES + txid via its out_gentx param. We reuse
// that ONE byte path. So the reconstructed coinbase is, by construction, the
// very coinbase whose txid equals the gentx_hash the share's hash_link committed
// to -- the same value share_init_verify folded into the block's merkle_root.
//
// FAIL-LOUD (reward-safety, mirrors p2pool "GOT INCOMPLETE BLOCK" + dgb "NOT
// broadcast"): every unrecoverable condition returns std::nullopt so the caller
// broadcasts NOTHING -- never a partial/malformed block:
//   * the winning share's parent is not yet in-chain (no PPLNS window to rebuild
//     the coinbase from) -> nullopt;
//   * generate_share_transaction throws / yields empty coinbase bytes -> nullopt;
//   * the share references other (non-coinbase) txs whose bodies are not in the
//     known-tx set -> nullopt (an incomplete block would hash to the committed
//     merkle_root's tree but omit a body -> daemon-rejected; never emit it).
// A partial/wrong reconstruction hashes to the wrong merkle_root and is rejected
// by every peer/daemon, so failing loudly here is strictly safer than emitting.
//
// COINBASE-ONLY is the DAEMONLESS NORM (transactions==[]): the share carries no
// transaction_hash_refs, other_tx_hashes is empty, the block is [gentx] alone,
// and merkle_root == gentx_txid (an empty merkle_link is identity). On the v16
// share the ref-walk + known-tx bodies fill in automatically as embedded mempool
// tx-selection lands, with no change here.
//
// THE DASH v36 NETWORK commits the template's transactions differently: a v36
// share carries no tx refs, only the coinbase merkle_link (the branch from the
// coinbase to the header merkle root), which is all a peer needs to verify the
// PoW. The tx BODIES exist only on the node that served the template -- the
// finder -- frozen with the producer job (FrozenMintJob::tx_data_hex). A v36
// share whose link is non-empty is therefore rebuilt ONLY from the finder's
// frozen job (FinderBodiesLookup), and only when those bodies hash to the
// share's committed merkle root; every other node refuses it (fail-loud, never
// an incomplete block) -- the finder's stratum arm already carried the block.
//
// Reward/consensus-NEUTRAL: it READS already-validated share_info + the on-chain
// PPLNS window (the SAME reads the accept path already did under the same tracker
// lock) and already-relayed tx bodies; it WRITES no consensus, PPLNS, payout, or
// target state. Per-coin isolation: src/impl/dash/ only.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // HexStr

#include "gentx_coinbase.hpp"
#include "won_block_dispatch.hpp"       // dash::coin::ReconstructedWonBlock
#include "../share.hpp"
#include "../share_check.hpp"            // generate_share_transaction, check_merkle_link

namespace dash
{
namespace coin
{

// Look up a known non-coinbase tx BODY (non-witness bytes) by txid, or nullptr
// if absent. The run-loop binds this to the node's remember_tx / m_known_txs
// cache; an empty function means "no known-tx source" -> any share that
// references other txs fails loud (coinbase-only still reconstructs).
using KnownTxLookup =
    std::function<const std::vector<unsigned char>*(const uint256&)>;

// ── v36 finder bodies ───────────────────────────────────────────────────────
// The template a v36 producer job was built over, as the finder froze it: the
// tx hashes in template order (FrozenMintJob::desired_tx_hashes) and the
// parallel hex bodies (FrozenMintJob::tx_data_hex). Looked up by the share's
// ref_hash (the FrozenJobRegistry key); nullopt when this node holds no such
// job (not the finder, or the job was evicted).
struct FinderTemplateBodies
{
    std::vector<uint256> tx_hashes;
    std::shared_ptr<const std::vector<std::string>> tx_data_hex;
};
using FinderBodiesLookup =
    std::function<std::optional<FinderTemplateBodies>(const uint256& ref_hash)>;

// v36_finder_block_bodies (pure): the non-coinbase bodies of a v36 won block, in
// template order, or nullopt (with the cause in *why) unless ALL of:
//   * one body per tx hash, at least one;
//   * sha256d(body[i]) == tx_hashes[i] (the body IS the committed tx);
//   * the merkle root over [gentx_txid] ++ tx_hashes (dashcore's fold: duplicate
//     the last node of an odd layer; a CVE-2012-2459 duplicate-pair mutation is
//     refused) equals check_merkle_link(gentx_txid, share.m_merkle_link) -- the
//     root the share's header commits and peers verified the PoW over.
// So the block framed from these bodies passes dashd's merkle-root check by
// construction, or nothing is framed.
inline std::optional<std::vector<std::vector<unsigned char>>>
v36_finder_block_bodies(const DashV36Share& share,
                        const uint256& gentx_txid,
                        const FinderTemplateBodies& fb,
                        std::string* why = nullptr)
{
    auto fail = [&](std::string cause)
        -> std::optional<std::vector<std::vector<unsigned char>>> {
        if (why) *why = std::move(cause);
        return std::nullopt;
    };
    if (!fb.tx_data_hex)
        return fail("no template tx bodies frozen with the job");
    if (fb.tx_hashes.empty())
        return fail("the frozen job carries no transactions");
    if (fb.tx_data_hex->size() != fb.tx_hashes.size())
        return fail(std::to_string(fb.tx_hashes.size()) + " tx hashes but " +
                    std::to_string(fb.tx_data_hex->size()) + " bodies");

    std::vector<std::vector<unsigned char>> bodies;
    bodies.reserve(fb.tx_hashes.size());
    for (size_t i = 0; i < fb.tx_hashes.size(); ++i) {
        std::vector<unsigned char> body = ParseHex((*fb.tx_data_hex)[i]);
        if (body.empty() || body.size() * 2 != (*fb.tx_data_hex)[i].size())
            return fail("tx " + std::to_string(i) + " body is not valid hex");
        const uint256 txid = Hash(std::span<const unsigned char>(body.data(), body.size()));
        if (txid != fb.tx_hashes[i])
            return fail("tx " + std::to_string(i) + " body hashes to " +
                        txid.GetHex().substr(0, 16) + ", template lists " +
                        fb.tx_hashes[i].GetHex().substr(0, 16));
        bodies.push_back(std::move(body));
    }

    std::vector<uint256> layer;
    layer.reserve(1 + fb.tx_hashes.size());
    layer.push_back(gentx_txid);
    layer.insert(layer.end(), fb.tx_hashes.begin(), fb.tx_hashes.end());
    while (layer.size() > 1) {
        for (size_t pos = 0; pos + 1 < layer.size(); pos += 2)
            if (layer[pos] == layer[pos + 1])
                return fail("duplicate txid pair in the template (mutated merkle tree)");
        if (layer.size() & 1) layer.push_back(layer.back());
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) {
            unsigned char buf[64];
            std::memcpy(buf,      layer[i].data(),     32);
            std::memcpy(buf + 32, layer[i + 1].data(), 32);
            next.push_back(Hash(std::span<const unsigned char>(buf, 64)));
        }
        layer.swap(next);
    }
    const uint256 committed = check_merkle_link(gentx_txid, share.m_merkle_link);
    if (layer[0] != committed)
        return fail("template merkle root " + layer[0].GetHex().substr(0, 16) +
                    " != the share's committed root " + committed.GetHex().substr(0, 16));
    if (why) why->clear();
    return bodies;
}

// ── resolve_other_tx_hashes (DASH) ──────────────────────────────────────────
// Resolve a share's transaction_hash_refs to the ordered other_tx hash list,
// the DASH port of dgb::coin::resolve_other_tx_hashes. DASH stores refs FLAT as
// [share_count, tx_count] pairs (share.hpp: std::vector<uint64_t>), so we walk
// them two-at-a-time. Throws std::out_of_range on a ref that walks off the known
// sharechain or indexes past an ancestor's new_transaction_hashes -- both are
// malformed-share conditions the caller turns into a fail-loud nullopt.
//
//   nth_parent_fn    : (start, n) -> hash of the n-th parent (n==0 -> start),
//                      IsNull() when the walk runs off the known sharechain
//   new_tx_hashes_fn : share_hash -> that share's new_transaction_hashes (copy)
inline std::vector<uint256>
resolve_other_tx_hashes(
    const uint256& won_share_hash,
    const std::vector<uint64_t>& refs,
    const std::function<uint256(const uint256&, uint64_t)>& nth_parent_fn,
    const std::function<std::vector<uint256>(const uint256&)>& new_tx_hashes_fn)
{
    std::vector<uint256> out;
    out.reserve(refs.size() / 2);

    for (std::size_t i = 0; i + 1 < refs.size(); i += 2)
    {
        const uint64_t share_count = refs[i];
        const uint64_t tx_count    = refs[i + 1];

        const uint256 ancestor = nth_parent_fn(won_share_hash, share_count);
        if (ancestor.IsNull())
            throw std::out_of_range(
                "dash resolve_other_tx_hashes: transaction_hash_ref share_count "
                "walks past the known sharechain");

        const std::vector<uint256> nths = new_tx_hashes_fn(ancestor);
        if (tx_count >= nths.size())
            throw std::out_of_range(
                "dash resolve_other_tx_hashes: transaction_hash_ref tx_count "
                "out of range for ancestor new_transaction_hashes");

        out.push_back(nths[tx_count]);
    }

    return out;
}

// ── frame_won_block (pure) ──────────────────────────────────────────────────
// Frame the final block bytes from its parts. Pure + injectable (no tracker):
//   header = version|prev|merkle_root|time|bits|nonce   (80 bytes, DASH block)
//   merkle_root = check_merkle_link(gentx.txid, merkle_link)   (== gentx.txid
//                 for an empty coinbase-only link)
//   body   = varint(1 + other.size()) ++ gentx.bytes ++ other_tx_bodies...
// The header build MIRRORS share_check.hpp share_init_verify byte-for-byte, so
// X11(header) of the reconstructed block equals the share hash the tracker fired
// on -- i.e. the reconstructed block IS the block the winning share solved.
// MerkleLinkT: dash::MerkleLink (v16) or dash::v36::MerkleLink (v36); both fold
// through the same templated check_merkle_link.
template <typename MerkleLinkT>
inline ReconstructedWonBlock
frame_won_block(const bitcoin_family::coin::SmallBlockHeaderType& min_header,
                const MerkleLinkT& merkle_link,
                const GentxCoinbase& gentx,
                const std::vector<std::vector<unsigned char>>& other_tx_bodies)
{
    const uint256 merkle_root = check_merkle_link(gentx.txid, merkle_link);

    // 80-byte block header (identical field order to share_init_verify).
    PackStream header;
    {
        uint32_t hdr_version = static_cast<uint32_t>(min_header.m_version);
        header << hdr_version;
    }
    header << min_header.m_previous_block;
    header << merkle_root;
    header << min_header.m_timestamp;
    header << min_header.m_bits;
    header << min_header.m_nonce;

    std::vector<unsigned char> block(
        reinterpret_cast<const unsigned char*>(header.data()),
        reinterpret_cast<const unsigned char*>(header.data()) + header.size());

    // tx count (CompactSize) then [gentx] ++ other bodies.
    const std::size_t n_txs = 1 + other_tx_bodies.size();
    if (n_txs < 253) {
        block.push_back(static_cast<unsigned char>(n_txs));
    } else {
        block.push_back(0xfd);
        block.push_back(static_cast<unsigned char>(n_txs & 0xff));
        block.push_back(static_cast<unsigned char>((n_txs >> 8) & 0xff));
    }

    block.insert(block.end(), gentx.bytes.begin(), gentx.bytes.end());
    for (const auto& body : other_tx_bodies)
        block.insert(block.end(), body.begin(), body.end());

    ReconstructedWonBlock out;
    out.hex = HexStr(block);
    out.bytes = std::move(block);
    return out;
}

// ── reconstruct_won_block (tracker-bound) ───────────────────────────────────
// Full reconstruction for the run-loop. MUST be called on the compute thread
// with the tracker lock held (the m_on_block_found contract): it reads the
// on-chain PPLNS window via generate_share_transaction and walks the sharechain
// via tracker.chain -- exactly the reads the accept path already performed under
// this same lock. Returns std::nullopt (never throws) on any unrecoverable
// condition so the caller broadcasts NOTHING.
// Both live share types; generate_share_transaction overload-resolves to the
// v36 coinbase. A v36 share (the DASH v36 network) carries no tx refs: with an
// empty merkle_link its block is the coinbase-only [gentx]; with a non-empty
// link the template's bodies come from `finder` (this node's frozen producer
// job for the share's ref_hash) and must hash to the committed merkle root,
// else nothing is built. `finder` is ignored for the v16 DashShare, whose other
// txs resolve through the ref-walk + `known_txs` exactly as before.
template <typename ShareT, typename TrackerT>
    requires is_live_share<ShareT>
inline std::optional<ReconstructedWonBlock>
reconstruct_won_block(const uint256& share_hash,
                      const ShareT& share,
                      TrackerT& tracker,
                      const core::CoinParams& params,
                      const KnownTxLookup& known_txs = {},
                      const FinderBodiesLookup& finder = {})
{
    // Guard: the coinbase recompute needs the parent's PPLNS window in-chain.
    if (share.m_prev_hash.IsNull() || !tracker.chain.contains(share.m_prev_hash)) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " parent not in-chain -- cannot rebuild coinbase; NOT broadcast.";
        return std::nullopt;
    }

    // 1. Regenerate the DIP3/DIP4 coinbase (bytes + txid) via the SSOT accept
    //    path. Any throw -> fail loud.
    GentxCoinbase gentx;
    try {
        (void)generate_share_transaction(share, tracker, params, &gentx);
    } catch (const std::exception& e) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " coinbase regen threw (" << e.what() << ") -- NOT broadcast.";
        return std::nullopt;
    }
    if (gentx.bytes.empty()) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " coinbase regen empty -- NOT broadcast.";
        return std::nullopt;
    }

    // 2 (v36). The DASH v36 network: the share commits the template's txs
    //    through its merkle_link; only the finder holds the bodies.
    if constexpr (std::is_same_v<ShareT, DashV36Share>) {
        (void)known_txs;
        if (share.m_merkle_link.m_branch.empty())
            return frame_won_block(share.m_min_header, share.m_merkle_link, gentx, {});

        const uint256 ref_hash = compute_v36_ref_hash(params, share);
        std::optional<FinderTemplateBodies> fb;
        if (finder) fb = finder(ref_hash);
        if (!fb) {
            LOG_WARNING << "[EMB-DASH] v36 won-block " << share_hash.GetHex().substr(0, 16)
                      << " commits a " << share.m_merkle_link.m_branch.size()
                      << "-branch merkle link but this node holds no template bodies for ref="
                      << ref_hash.GetHex().substr(0, 16)
                      << " (not the finder / frozen job evicted) -- NOT rebuilt; the "
                         "finder's stratum arm carries the full block";
            return std::nullopt;
        }
        std::string why;
        auto bodies = v36_finder_block_bodies(share, gentx.txid, *fb, &why);
        if (!bodies) {
            LOG_ERROR << "[EMB-DASH] v36 won-block " << share_hash.GetHex().substr(0, 16)
                      << " frozen template does not match the share's merkle link ("
                      << why << ") -- INCOMPLETE, NOT broadcast.";
            return std::nullopt;
        }
        return frame_won_block(share.m_min_header, share.m_merkle_link, gentx, *bodies);
    }
    (void)finder;   // v16: other txs resolve through the ref-walk below

    // 2. Resolve any other (non-coinbase) tx bodies. Empty for the coinbase-only
    //    daemonless norm. Missing body / malformed ref -> fail loud.
    std::vector<std::vector<unsigned char>> other_bodies;
    try {
        const std::vector<uint256> other_hashes = resolve_other_tx_hashes(
            share_hash, share.m_transaction_hash_refs,
            [&tracker](const uint256& h, uint64_t n) {
                return tracker.chain.get_nth_parent_via_skip(h, n);
            },
            [&tracker](const uint256& h) {
                std::vector<uint256> nths;
                tracker.chain.get_share(h).invoke([&](auto* obj) {
                    if (obj) nths = obj->m_new_transaction_hashes;
                });
                return nths;
            });

        other_bodies.reserve(other_hashes.size());
        for (const auto& h : other_hashes) {
            const std::vector<unsigned char>* body = known_txs ? known_txs(h) : nullptr;
            if (!body) {
                LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                            << " references unknown tx " << h.GetHex().substr(0, 16)
                            << " -- INCOMPLETE, NOT broadcast.";
                return std::nullopt;
            }
            other_bodies.push_back(*body);
        }
    } catch (const std::exception& e) {
        LOG_WARNING << "[EMB-DASH] won-block " << share_hash.GetHex().substr(0, 16)
                    << " other-tx resolve threw (" << e.what() << ") -- NOT broadcast.";
        return std::nullopt;
    }

    // 3. Frame [gentx] ++ other bodies under the share's committed header.
    return frame_won_block(share.m_min_header, share.m_merkle_link, gentx, other_bodies);
}

} // namespace coin
} // namespace dash
