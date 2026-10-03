// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Cheap pre-checks on incoming DASH shares (#1828): everything here runs
// BEFORE any hashing (no ref stream, no hash_link, no merkle, no X11).
//
// Two layers:
//
//   1. precheck_raw_shares(): per-message caps on the raw 'shares' /
//      'sharereply' payload, applied in the node receive path before a single
//      share is parsed (node.cpp NodeImpl::precheck_raw_shares, called first
//      thing by the four HANDLER(shares) / HANDLER(sharereply) bodies). Pure,
//      no parsing, no hashing. A message over a cap is dropped and counted;
//      no ban and no disconnect here (graded bans are #1829).
//
//   2. check_v16_structure() / check_v36_structure(): field checks that need
//      no hashing, called by share_init_verify right after the target check
//      and before the ref stream, so every verify path (node receive, tracker
//      attempt_verify, persisted reload, producer self-check) applies them.
//
// Oracle = p2pool-dash (p2pool/p2p.py, p2pool/data.py, p2pool/util/
// p2protocol.py). The public network (no --network-id) applies ONLY limits the
// oracle also enforces, so an honest p2pool-dash peer is never refused. The
// DASH v36 network (custom --network-id, share type 36) applies the full set;
// its per-message numbers live in SharechainConfig::ShareProfile.

#include "config_pool.hpp"
#include "share.hpp"
#include "share_messages.hpp"

#include <core/pack.hpp>
#include <sharechain/share.hpp>

#include <cstddef>
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace dash
{

// Largest message_data blob an honest producer can emit: the encryption header
// (49) plus the MAX_TOTAL_MESSAGE_BYTES inner cap that create_message_data
// enforces. Anything larger is rejected before any HMAC / ECDSA work (and, via
// check_v36_structure, before any hashing).
inline constexpr size_t MAX_MESSAGE_DATA_WIRE_BYTES =
    ENCRYPTION_HEADER_SIZE + MAX_TOTAL_MESSAGE_BYTES;

namespace precheck
{

// ── Oracle limits ────────────────────────────────────────────────────────────

// Per-message payload cap, both networks. p2pool/p2p.py:33
//     p2protocol.Protocol.__init__(self, node.net.PREFIX, 3145728, ...)
// Receive: util/p2protocol.py:38-40 skips a frame whose length exceeds it
// ("length too large"; frame dropped, connection kept). Send: :93-94 raises
// TooLong, so no oracle peer ever emits a larger 'shares' / 'sharereply'.
inline constexpr std::size_t MAX_P2P_PAYLOAD_BYTES = 3145728;

// Smallest wire size of a v16 RawShare that can pass share_init_verify:
// [VarInt type=16][VarStr contents], contents = the data.py:73-122 share_type
// with a 2-byte coinbase (data.py:315-316, the smallest admitted), a 1-byte VarInt
// header version and every list / VarStr / PossiblyNone field empty:
//   min_header 45 + share_data 81 + rest of share_info 66
//   + ref_merkle_link 1 + last_txout_nonce 8 + hash_link 34 + merkle_link 1
//   + coinbase_payload 1  = 237 contents bytes, + 1 type + 1 length = 239.
// Pinned by DashSharePrecheck.MinimalV16RawShareSize.
inline constexpr std::size_t MIN_V16_RAW_SHARE_WIRE_BYTES = 239;

// data.py:318-319: len(merkle_link['branch']) > 16 -> "merkle branch too long!"
inline constexpr std::size_t MAX_MERKLE_BRANCH_LEN = 16;

// data.py:335-340: every transaction_hash_refs share_count < 110.
inline constexpr uint64_t MAX_TX_REF_SHARE_COUNT = 110;

// Public per-message share-count cap: the most admissible shares that fit in
// one oracle payload, [VarInt n (3 bytes for 253..65535)] + n * 239 <=
// 3145728, i.e. 13162. The oracle's own receive rule re-expressed as a
// count, so a message it would process is never refused on a count.
inline constexpr uint32_t PUBLIC_MAX_SHARES_PER_MSG =
    static_cast<uint32_t>((MAX_P2P_PAYLOAD_BYTES - 3) / MIN_V16_RAW_SHARE_WIRE_BYTES);

// DASH v36 network caps (no oracle; conservative bounds over honest traffic):
//   'shares': a node broadcasts at most 5 shares per message (oracle
//     node.py:86-95, c2pool node.hpp send_shares batching); 64 leaves >10x.
//   'sharereply': a request carries 1 hash (node.cpp download_shares) and the
//     serve side clamps parents to 1000 // len(hashes) (oracle node.py:69,
//     node.cpp handle_get_share), so an honest reply holds at most 1001.
//   per-share: an honest v36 share is ~27 KB at worst (two 10000-byte DIP4
//     CbTx payloads, 561-byte message_data, two 16-deep merkle links, ~60
//     address payees); 64 KiB leaves >2x.
inline constexpr uint32_t V36_MAX_SHARES_PER_SHARES_MSG = 64;
inline constexpr uint32_t V36_MAX_SHARES_PER_SHAREREPLY = 1001;
inline constexpr uint32_t V36_MAX_SHARE_WIRE_BYTES      = 65536;

// The per-network profile carries these numbers (config_pool.hpp cannot
// include this header); keep the two in lock-step.
static_assert(SharechainConfig::PUBLIC_PROFILE.max_shares_per_shares_msg == PUBLIC_MAX_SHARES_PER_MSG);
static_assert(SharechainConfig::PUBLIC_PROFILE.max_shares_per_sharereply == PUBLIC_MAX_SHARES_PER_MSG);
static_assert(SharechainConfig::PUBLIC_PROFILE.max_share_wire_bytes == MAX_P2P_PAYLOAD_BYTES);
static_assert(SharechainConfig::ISOLATED_V36_PROFILE.max_shares_per_shares_msg == V36_MAX_SHARES_PER_SHARES_MSG);
static_assert(SharechainConfig::ISOLATED_V36_PROFILE.max_shares_per_sharereply == V36_MAX_SHARES_PER_SHAREREPLY);
static_assert(SharechainConfig::ISOLATED_V36_PROFILE.max_share_wire_bytes == V36_MAX_SHARE_WIRE_BYTES);

// ── Layer 1: raw per-message caps ────────────────────────────────────────────

enum class Kind { shares, sharereply };

inline const char* kind_name(Kind k) { return k == Kind::shares ? "shares" : "sharereply"; }

inline std::size_t compact_size_len(uint64_t n)
{
    if (n < 253) return 1;
    if (n <= 0xffff) return 3;
    if (n <= 0xffffffffull) return 5;
    return 9;
}

inline std::size_t raw_share_wire_bytes(const chain::RawShare& r)
{
    const std::size_t len = r.contents.m_data.size();
    return compact_size_len(r.type) + compact_size_len(len) + len;
}

// Exact serialized payload size of a 'shares' ([list]) or 'sharereply'
// ([id 32][result VarInt 1][list]) message carrying `shares`.
inline std::size_t payload_bytes(const std::vector<chain::RawShare>& shares, Kind kind)
{
    std::size_t n = (kind == Kind::sharereply ? 32 + 1 : 0) + compact_size_len(shares.size());
    for (const auto& r : shares)
        n += raw_share_wire_bytes(r);
    return n;
}

struct RawPrecheck
{
    bool        message_dropped{false};
    std::size_t shares_dropped{0};
    const char* reason{nullptr};
};

inline uint32_t max_shares(Kind kind, const SharechainConfig::ShareProfile& p)
{
    return kind == Kind::shares ? p.max_shares_per_shares_msg : p.max_shares_per_sharereply;
}

// Applies, in order: (1) the per-message share-count cap, (2) the oracle
// payload cap, both dropping the WHOLE message; (3) the per-share contents
// cap, erasing each oversize item. No parsing, no hashing.
inline RawPrecheck precheck_raw_shares(std::vector<chain::RawShare>& shares, Kind kind,
                                       const SharechainConfig::ShareProfile& p)
{
    RawPrecheck r;
    if (shares.size() > max_shares(kind, p))
    {
        r.message_dropped = true;
        r.shares_dropped = shares.size();
        r.reason = "too many shares in one message";
        return r;
    }
    if (payload_bytes(shares, kind) > MAX_P2P_PAYLOAD_BYTES)
    {
        r.message_dropped = true;
        r.shares_dropped = shares.size();
        r.reason = "payload exceeds 3145728 bytes";
        return r;
    }
    const std::size_t before = shares.size();
    std::erase_if(shares, [&](const chain::RawShare& s) {
        return s.contents.m_data.size() > p.max_share_wire_bytes;
    });
    r.shares_dropped = before - shares.size();
    if (r.shares_dropped)
        r.reason = "share exceeds the per-share size cap";
    return r;
}

// Sender side: true when a 'sharereply' carrying `shares` fits the oracle
// payload cap (p2pool/p2p.py:399-404 handle_sharereq sends result='too long' when
// send_sharereply raises p2protocol.TooLong, util/p2protocol.py:93-94).
inline bool sharereply_fits(const std::vector<chain::RawShare>& shares)
{
    return payload_bytes(shares, Kind::sharereply) <= MAX_P2P_PAYLOAD_BYTES;
}

// ── Layer 2: field checks with no hashing ────────────────────────────────────

inline void check_merkle_branch_len(std::size_t n)
{
    if (n > MAX_MERKLE_BRANCH_LEN)
        throw std::invalid_argument("merkle branch too long");
}

// data.py:335-340:
//     for share_count, tx_count in self.iter_transaction_hash_refs():
//         assert share_count < 110
//         if share_count == 0: n.add(tx_count)
//     assert n == set(xrange(len(self.share_info['new_transaction_hashes'])))
inline void check_tx_hash_refs(const std::vector<uint64_t>& refs, std::size_t new_tx_count)
{
    if (refs.size() % 2 != 0)
        throw std::invalid_argument("bad transaction_hash_refs");
    std::vector<bool> seen(new_tx_count, false);
    std::size_t distinct = 0;
    for (std::size_t i = 0; i + 1 < refs.size(); i += 2)
    {
        const uint64_t share_count = refs[i];
        const uint64_t tx_count = refs[i + 1];
        if (share_count >= MAX_TX_REF_SHARE_COUNT)
            throw std::invalid_argument("bad transaction_hash_refs");
        if (share_count != 0)
            continue;
        if (tx_count >= new_tx_count)
            throw std::invalid_argument("bad transaction_hash_refs");
        if (!seen[tx_count])
        {
            seen[tx_count] = true;
            ++distinct;
        }
    }
    if (distinct != new_tx_count)
        throw std::invalid_argument("bad transaction_hash_refs");
}

// v16 (both networks): the data.py Share.__init__ checks c2pool did not have.
// Coinbase size and target validity already run in share_init_verify.
inline void check_v16_structure(const DashShare& share)
{
    check_merkle_branch_len(share.m_merkle_link.m_branch.size());
    check_tx_hash_refs(share.m_transaction_hash_refs, share.m_new_transaction_hashes.size());
}

// v36 (the DASH v36 network only; the type does not load elsewhere).
inline void check_v36_structure(const DashV36Share& share)
{
    check_merkle_branch_len(share.m_merkle_link.m_branch.size());
    check_merkle_branch_len(share.m_ref_merkle_link.m_branch.size());
    // Same text as check_v36_message_data, which keeps its own check.
    if (share.m_message_data.m_data.size() > MAX_MESSAGE_DATA_WIRE_BYTES)
        throw std::invalid_argument("share message_data exceeds MAX_TOTAL_MESSAGE_BYTES");
    // DASH pays P2PKH only and has no merged-mining child (share.hpp): the
    // producer always emits pubkey_type 0 and the merged fields empty.
    if (share.m_pubkey_type != 0)
        throw std::invalid_argument("share pubkey_type must be 0 (P2PKH)");
    if (!share.m_merged_addresses.empty() || !share.m_merged_coinbase_info.empty()
        || !share.m_merged_payout_hash.IsNull())
        throw std::invalid_argument("share merged-mining fields must be empty");
}

} // namespace precheck
} // namespace dash
