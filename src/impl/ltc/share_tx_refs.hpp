// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Uniform access to a share's "new transaction hashes" list across the LTC/DOGE
// share variants.
//
// WHY THIS EXISTS. The LTC share variants do NOT all spell this list the same
// way, and they do not all HAVE it:
//
//   ltc::Share              (v17) -> obj->m_tx_info.m_new_transaction_hashes
//   ltc::NewShare           (v33) -> obj->m_tx_info.m_new_transaction_hashes
//   ltc::SegwitMiningShare  (v34) -> none (Formatter serialises m_tx_info only
//   ltc::PaddingBugfixShare (v35)    for version < 34, and the v34+ structs
//   ltc::MergedMiningShare  (v36)    carry no m_tx_info member at all)
//
// node.cpp's tx-forwarding path used to probe `requires { obj->m_new_transaction_hashes; }`
// directly on the share object. That expression is FALSE for every one of the
// five variants — v17/v33 nest the list inside m_tx_info, v34+ have no list —
// so the whole remember_tx / forget_tx forwarding block was unreachable: LTC
// never forwarded a single tx byte, and a relayed v17/v33 share referencing a tx
// the peer lacked was exactly the canonical "referenced unknown transaction"
// disconnect. protocol_actual.cpp:123 / protocol_legacy.cpp:118 spell the same
// list correctly, which is why the RECEIVE side worked and only the SEND side
// was dead.
//
// Probing through one accessor removes the class of bug: a new share variant
// either exposes the list in one of the two known spellings and is handled, or
// exposes none and is reported as "no list" (trivially backable, nothing to
// forward) — never silently skipped because of a member-name mismatch.

#pragma once

#include <vector>

#include <core/uint256.hpp>

namespace ltc {

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
// list under the FLAT spelling that the old probe assumed. Used by the tests to
// hold the regression down — if this ever becomes true for a variant, the flat
// branch of new_tx_hashes() is what handles it, not a silent skip.
template <typename ShareObj>
inline constexpr bool has_flat_new_tx_hashes =
    requires(ShareObj* o) { o->m_new_transaction_hashes; };

// True iff the share variant nests the list inside m_tx_info (v17 / v33).
template <typename ShareObj>
inline constexpr bool has_nested_new_tx_hashes =
    requires(ShareObj* o) { o->m_tx_info.m_new_transaction_hashes; };

} // namespace ltc
