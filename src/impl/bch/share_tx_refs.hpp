// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Uniform access to a share's "new transaction hashes" list across the BCH
// share variants.
//
// WHY THIS EXISTS. The BCH share variants do NOT all spell this list the same
// way, and they do not all HAVE it:
//
//   bch::Share              (v17) -> obj->m_tx_info.m_new_transaction_hashes
//   bch::NewShare           (v33) -> obj->m_tx_info.m_new_transaction_hashes
//   bch::SegwitMiningShare  (v34) -> none (carries types::DataSegwitShare, no
//   bch::PaddingBugfixShare (v35)    m_tx_info member -- BCH has no SegWit so
//   bch::MergedMiningShare  (v36)    v34+ never populate a new-tx list at all)
//
// node.cpp's tx-forwarding SEND path (send_shares) probed
// `requires { obj->m_new_transaction_hashes; }` directly on the share object.
// That expression is FALSE for every one of the five variants -- v17/v33 nest
// the list inside m_tx_info, v34+ have no list -- so the whole needed_txs /
// remember_tx forwarding block was unreachable: BCH never forwarded a single tx
// byte, and a relayed v17/v33 share referencing a tx the peer lacked was exactly
// the canonical "referenced unknown transaction" disconnect (#905). The RECEIVE
// side (protocol_actual.cpp:167 / protocol_legacy.cpp:173 / node.hpp:291) spells
// the nested list correctly, which is why receive worked and only send was dead.
//
// Probing through one accessor removes the class of bug: a new share variant
// either exposes the list in one of the two known spellings and is handled, or
// exposes none and is reported as "no list" (nothing to forward) -- never
// silently skipped because of a member-name mismatch. Mirrors ltc::new_tx_hashes
// (src/impl/ltc/share_tx_refs.hpp, #873); BCH's variant topology is identical.

#pragma once

#include <vector>

#include <core/uint256.hpp>

namespace bch {

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
// for every BCH variant -- if this ever becomes true, the flat branch of
// new_tx_hashes() is what handles it, not a silent skip.
template <typename ShareObj>
inline constexpr bool has_flat_new_tx_hashes =
    requires(ShareObj* o) { o->m_new_transaction_hashes; };

// True iff the share variant nests the list inside m_tx_info (v17 / v33).
template <typename ShareObj>
inline constexpr bool has_nested_new_tx_hashes =
    requires(ShareObj* o) { o->m_tx_info.m_new_transaction_hashes; };

} // namespace bch
