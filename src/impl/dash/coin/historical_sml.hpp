// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DIP-4 client verification of a HISTORICAL Simplified Masternode List
/// snapshot, shared by every consumer that sources an SML at a height other
/// than the tip.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHY THIS IS A SHARED FUNCTION AND NOT A METHOD
/// ─────────────────────────────────────────────────────────────────────────
/// There are now two consumers of `getmnlistd(ZERO, <historical block>)`:
///
///   • quorum_member_source.hpp — the ordered operator-key set as of a
///     quorum's WORK block (#814 R3);
///   • mn_checkpoint_lane.hpp — the PoSe-validity view as of a REPLAYED
///     block, so the daemonless bridge can fold removals at the exact height
///     they apply to.
///
/// Both are on the reward path and both are trusting a peer-supplied list, so
/// both need the identical authentication. Two copies of that check would be
/// two places for it to rot; this is the one implementation.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT IS PROVEN (and why a snapshot may be believed at all)
/// ─────────────────────────────────────────────────────────────────────────
/// A lying peer can serve any list it likes. What it cannot forge is the
/// PoW-validated header chain we already hold. So:
///
///   (a) the reply's embedded cbTx is a coinbase special-tx (type-5 CCbTx),
///       parses, and its nHeight equals the height we asked about — a peer
///       cannot satisfy the request with a different, even genuine, block;
///   (b) `cbTxMerkleTree` proves that cbTx's hash into the block header's
///       hashMerkleRoot at tx index 0 (the coinbase position) — and that
///       header is PoW-verified by our own HeaderChain;
///   (c) the SML rebuilt from the snapshot hashes to `cbTx.merkleRootMNList`.
///
/// Chained, that means: the returned list IS the deterministic masternode
/// list that consensus committed to in the coinbase of that exact block. It
/// is not "a list a peer sent"; it is dated, committed and header-anchored.
///
/// ANY failure returns std::nullopt. There is no partial acceptance — a
/// half-authenticated masternode set projects a wrong payee, and a wrong
/// payee is a coinbase the network rejects.

#include <impl/dash/coin/utxo_adapter.hpp>            // dash_txid
#include <impl/dash/coin/vendor/cbtx.hpp>             // CCbTx, parse_cbtx
#include <impl/dash/coin/vendor/simplifiedmns.hpp>    // CSimplifiedMNList
#include <impl/dash/coin/vendor/smldiff.hpp>          // CSimplifiedMNListDiff, apply_diff

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// The PoW-verified header's hashMerkleRoot for a held block hash, or nullopt
/// when the header is not held. This is the trust anchor for step (b).
using MerkleRootOfHashFn =
    std::function<std::optional<uint256>(const uint256&)>;

/// Authenticate a historical full snapshot (base == ZERO) and return the SML
/// it commits to.
///
/// `expected_height` is the height the CALLER asked about; binding it here is
/// what stops a peer answering with some other block's genuine snapshot.
/// `tag` only names the consumer in the log line.
inline std::optional<vendor::CSimplifiedMNList>
authenticate_historical_snapshot(const vendor::CSimplifiedMNListDiff& diff,
                                 uint32_t expected_height,
                                 const MerkleRootOfHashFn& merkle_root_of_hash,
                                 vendor::CCbTx& cbtx_out,
                                 const char* tag)
{
    auto fail = [&](const char* why) -> std::optional<vendor::CSimplifiedMNList> {
        LOG_WARNING << "[" << tag << "] historical snapshot AUTH FAILED ("
                    << why << ") for block "
                    << diff.blockHash.GetHex().substr(0, 16)
                    << " at expected h=" << expected_height
                    << " — fail closed";
        return std::nullopt;
    };

    // (a) cbTx: coinbase, special-tx type 5, parseable, height bound to the
    // request.
    if (diff.cbTx.type != 5 || diff.cbTx.extra_payload.empty())
        return fail("cbTx not a type-5 CbTx");
    if (!vendor::parse_cbtx(diff.cbTx.extra_payload, cbtx_out))
        return fail("cbTx payload unparseable");
    if (expected_height == 0 || cbtx_out.nHeight < 0
        || static_cast<uint32_t>(cbtx_out.nHeight) != expected_height)
        return fail("cbTx height != expected height");

    // (b) merkle proof against the PoW-verified header.
    auto header_root = merkle_root_of_hash(diff.blockHash);
    if (!header_root || header_root->IsNull())
        return fail("block header not held");
    std::vector<uint256>      matches;
    std::vector<unsigned int> match_idx;
    const uint256 proof_root = diff.cbTxMerkleTree.ExtractMatches(matches, match_idx);
    if (proof_root.IsNull() || proof_root != *header_root)
        return fail("cbTxMerkleTree root != header merkle root");
    const uint256 cbtx_hash = dash_txid(diff.cbTx);
    if (matches.size() != 1 || match_idx.size() != 1 || match_idx[0] != 0
        || matches[0] != cbtx_hash)
        return fail("cbTx not proven at coinbase position");

    // (c) SML root commitment.
    vendor::CSimplifiedMNList sml;
    vendor::apply_diff(sml, diff);   // base == ZERO: apply onto empty
    if (sml.CalcMerkleRoot() != cbtx_out.merkleRootMNList)
        return fail("SML root != cbTx.merkleRootMNList");

    return sml;
}

/// ─────────────────────────────────────────────────────────────────────────
/// THE DEMUX (reward-critical)
/// ─────────────────────────────────────────────────────────────────────────
/// There is exactly ONE mnlistdiff message type on the wire, and it carries
/// two utterly different things depending on who asked for it:
///
///   • a TIP-sync diff, which the CoinStateMaintainer applies to the LIVE SML
///     the block template is validated against;
///   • a HISTORICAL full snapshot (base == ZERO at an old block), which some
///     consumer asked for in order to read the past.
///
/// The maintainer treats ANY base==ZERO diff as a full snapshot and adopts it
/// wholesale. So a historical reply reaching it REWRITES THE LIVE TIP SML TO A
/// PAST STATE — silently, on the money path. That is the corruption this class
/// exists to prevent, and it is why consumption is decided BEFORE the tip feed
/// is ever called.
///
/// There is now more than one historical consumer (QuorumMemberSource and the
/// MnCheckpointLane), so this is a CHAIN rather than a single slot — and it is
/// deliberately NOT short-circuiting. Two consumers may legitimately await the
/// SAME block hash (a bridge fold point can coincide with a quorum work
/// block); the reply is immutable, so both may take it. Short-circuiting would
/// leave whichever filter sits later in the chain waiting forever on a reply
/// that had already arrived and been swallowed.
///
/// Consumption is decided by ANY filter claiming the reply. A claim is a claim
/// even when that consumer then REFUSES the content (authentication failure):
/// the reply was still an answer to a historical request, and still must not
/// reach the tip.
class HistoricalMnListDiffDemux {
public:
    /// Returns true iff the diff answered THIS consumer's outstanding request.
    using Filter = std::function<bool(const vendor::CSimplifiedMNListDiff&)>;
    /// Hand a tip-sync diff on to the live SML maintainer.
    using TipFeed = std::function<void(const vendor::CSimplifiedMNListDiff&)>;

    void add_filter(Filter f)
    {
        if (f) m_filters.push_back(std::move(f));
    }
    size_t filter_count() const { return m_filters.size(); }

    /// Route one reply. Returns true when it was consumed as HISTORICAL, in
    /// which case `tip_feed` was NOT called.
    bool dispatch(const vendor::CSimplifiedMNListDiff& diff,
                  const TipFeed& tip_feed) const
    {
        bool consumed = false;
        // NOT short-circuiting, on purpose — see the class comment. Every
        // filter is offered every reply.
        for (const auto& f : m_filters) {
            if (f(diff)) consumed = true;
        }
        if (consumed) return true;
        if (tip_feed) tip_feed(diff);
        return false;
    }

private:
    std::vector<Filter> m_filters;
};

} // namespace coin
} // namespace dash
