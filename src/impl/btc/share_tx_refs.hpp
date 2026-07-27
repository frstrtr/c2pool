// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Uniform access to a share's "new transaction hashes" list across the BTC
// share variants.
//
// WHY THIS EXISTS. The BTC share variants do NOT all spell this list the same
// way, and they do not all HAVE it:
//
//   btc::Share              (v17) -> obj->m_tx_info.m_new_transaction_hashes
//   btc::NewShare           (v33) -> obj->m_tx_info.m_new_transaction_hashes
//   btc::SegwitMiningShare  (v34) -> none (carries types::DataSegwitShare, no
//   btc::PaddingBugfixShare (v35)    m_tx_info member -- share_check leaves the
//   btc::MergedMiningShare  (v36)    tx list empty for version >= 34)
//
// node.cpp's send_shares() F3 broadcast gate (partition_backable) probed
// `requires { obj->m_new_transaction_hashes; }` directly on the share object.
// That expression is FALSE for every one of the five variants -- v17/v33 nest
// the list inside m_tx_info, v34+ have no list -- so the gate collected an empty
// ref list for every share, every share was vacuously backable, and the gate
// no-op'd for ALL versions (#880): a v17/v33 share referencing a tx the peer
// lacked was broadcast anyway, tripping the canonical "referenced unknown
// transaction" disconnect. The per_share_refs relay block below the gate already
// spells the nested list correctly (#871), which is why relay worked and only
// the gate probe was dead.
//
// Probing through one accessor removes the class of bug: a new share variant
// either exposes the list in one of the two known spellings and is handled, or
// exposes none and is reported as "no list" (nothing to gate on) -- never
// silently dead because of a member-name mismatch. Mirrors bch::new_tx_hashes
// (src/impl/bch/share_tx_refs.hpp, #913) and ltc::new_tx_hashes
// (src/impl/ltc/share_tx_refs.hpp, #873); BTC's variant topology is identical.

#pragma once

#include <vector>

#include <core/uint256.hpp>

namespace btc {

// Pointer to the share's new-transaction-hash list, or nullptr when this share
// variant carries none. A pointer (not a copy) so the broadcast hot path does no
// per-share allocation. Lifetime is the share object's.
template <typename ShareObj>
inline auto new_tx_hashes(ShareObj* obj)
{
    if constexpr (requires { obj->m_tx_info.m_new_transaction_hashes; })
        return &obj->m_tx_info.m_new_transaction_hashes;
    else if constexpr (requires { obj->m_new_transaction_hashes; })
        return &obj->m_new_transaction_hashes;
    else
        return static_cast<const std::vector<uint256>*>(nullptr);
}

// Compile-time pin of the fact above: true iff the share variant exposes the
// list under the FLAT spelling that the old probe assumed. Held false by the KAT
// for every BTC variant -- if this ever becomes true, the flat branch of
// new_tx_hashes() is what handles it, not a silent skip.
template <typename ShareObj>
inline constexpr bool has_flat_new_tx_hashes =
    requires(ShareObj* o) { o->m_new_transaction_hashes; };

// True iff the share variant nests the list inside m_tx_info (v17 / v33).
template <typename ShareObj>
inline constexpr bool has_nested_new_tx_hashes =
    requires(ShareObj* o) { o->m_tx_info.m_new_transaction_hashes; };

} // namespace btc
