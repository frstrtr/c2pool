// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_miner_tx.hpp
// Path B, slice S3b-2: the hf-16 Monero miner tx of a receipt (D2.2, D2.7;
// S2.3 #12; C37, C25).
//
//   r      = sc_reduce32(keccak256("c2pool-v37-xmr-txkey-v3" || pool_id || tip
//            || prev_id || varint(h))); h = height(P_r) + 1, prev_id = P_r,
//            pool_id = side_data_v3.pool_id; the domain is its ASCII bytes
//            without a terminator
//   R_tx   = r G
//   key i  = D_i = 8 r A_i; P_i = H_s(D_i || varint(i)) G + B_i;
//            vt_i = keccak256("view_tag" || D_i || varint(i))[0]
//            (B_i, A_i) = spend, view key of payee i
//   extra  = PBX1 hf 16: 01 R_tx | 02 04 extra_nonce | 03 21 00 mm_root (74 B)
//   prefix = varint(2) | varint(h + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW)
//            | varint(1) | 0xff | varint(h) | varint(n)
//            | n x (varint(q_i) | 0x03 | P_i | vt_i) | varint(len extra) | extra
//   tx     = keccak256(keccak256(prefix) || keccak256(0x00) || 32 zero bytes)
//
// The key derivation, the prefix head and the tx hash are the coin layer's
// (impl/xmr/coin/xmr_derivation, xmr_blob); the extra is encode_pbx1.
//
// KeyCache (policy P-36): output keys per (tip, P_r) for a window with payees,
// per (tip, P_r, payee) for the finder-only coinbase.
//
// hf >= 17 (format only): miner outputs by Ko strictly ascending (memcmp); two
// equal Ko have no order.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"           // write_coinbase_prefix_head, tx_prefix_hash, coinbase_tx_hash
#include "impl/xmr/coin/xmr_derivation.hpp"     // generate_key_derivation, derive_public_key, derive_view_tag
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"  // ::xmr::coin::keccak256

#include "pathb_emission.hpp"  // kHf16
#include "pathb_params.hpp"
#include "pathb_pbx1.hpp"
#include "pathb_wire_v3.hpp"   // XmrKeyRef, kExtraNonceBytes, detail::put_*

namespace c2pool::xmr::pathb {

static_assert(::xmr::coin::MINER_REWARD_UNLOCK_TIME == CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
              "coinbase unlock = h + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW");

inline constexpr std::string_view kTxKeyDomain = "c2pool-v37-xmr-txkey-v3";

namespace detail_mtx {

template <class T>
inline T to_coin(const Hash32& h) {
    T out;
    std::memcpy(out.data(), h.data(), kHashBytes);
    return out;
}

inline Hash32 from_coin(const ::xmr::coin::Bytes32& b) {
    Hash32 out{};
    std::memcpy(out.data(), b.data(), kHashBytes);
    return out;
}

inline Hash32 keccak(const std::uint8_t* p, std::size_t n) { return from_coin(::xmr::coin::keccak256(p, n)); }

}  // namespace detail_mtx

// ---------------------------------------------------------------------------
// r and R_tx (D2.2)
// ---------------------------------------------------------------------------
inline Hash32 derive_r_v3(const Hash32& pool_id, const Hash32& tip, const Hash32& prev_id, std::uint64_t h) {
    std::vector<std::uint8_t> pre;
    pre.reserve(kTxKeyDomain.size() + 3 * kHashBytes + varint_len(h));
    pre.insert(pre.end(), kTxKeyDomain.begin(), kTxKeyDomain.end());
    detail::put_hash(pre, pool_id);
    detail::put_hash(pre, tip);
    detail::put_hash(pre, prev_id);
    detail::put_varint(pre, h);
    ::xmr::coin::EcScalar s;
    ::xmr::coin::hash_to_scalar(pre.data(), pre.size(), s);  // keccak256, sc_reduce32
    return detail_mtx::from_coin(s);
}

// R_tx = r G; nullopt when r is not a reduced scalar.
inline std::optional<Hash32> tx_public_key(const Hash32& r) {
    ::xmr::coin::PublicKey pub;
    if (!::xmr::coin::secret_key_to_public_key(detail_mtx::to_coin<::xmr::coin::SecretKey>(r), pub))
        return std::nullopt;
    return detail_mtx::from_coin(pub);
}

// ---------------------------------------------------------------------------
// One output's one-time key and view tag (D:683-690)
// ---------------------------------------------------------------------------
struct OutKey {
    Hash32 key{};
    std::uint8_t view_tag = 0;

    friend bool operator==(const OutKey&, const OutKey&) = default;
};

// r must be reduced (tx_public_key(r) has a value). nullopt when the payee's
// spend or view key is not a point.
inline std::optional<OutKey> derive_out_key(const Hash32& r, const XmrKeyRef& ref, std::size_t index) {
    ::xmr::coin::KeyDerivation d;
    if (!::xmr::coin::generate_key_derivation(detail_mtx::to_coin<::xmr::coin::PublicKey>(ref.view),
                                              detail_mtx::to_coin<::xmr::coin::SecretKey>(r), d))
        return std::nullopt;
    ::xmr::coin::PublicKey p;
    if (!::xmr::coin::derive_public_key(d, index, detail_mtx::to_coin<::xmr::coin::PublicKey>(ref.spend), p))
        return std::nullopt;
    ::xmr::coin::ViewTag vt;
    ::xmr::coin::derive_view_tag(d, index, vt);
    return OutKey{detail_mtx::from_coin(p), vt.tag};
}

// The output keys of one canonical miner tx: r, R_tx and (P_i, vt_i) in vout order.
struct OutputKeys {
    Hash32 r{};
    Hash32 r_tx{};
    std::vector<OutKey> keys;
};

// nullopt when r is not reduced or a payee key is not a point.
inline std::optional<OutputKeys> derive_output_keys_with_r(const Hash32& r, std::span<const XmrKeyRef> refs) {
    const std::optional<Hash32> r_tx = tx_public_key(r);
    if (!r_tx) return std::nullopt;
    OutputKeys k;
    k.r = r;
    k.r_tx = *r_tx;
    k.keys.reserve(refs.size());
    for (std::size_t i = 0; i < refs.size(); ++i) {
        const std::optional<OutKey> o = derive_out_key(r, refs[i], i);
        if (!o) return std::nullopt;
        k.keys.push_back(*o);
    }
    return k;
}

inline std::optional<OutputKeys> derive_output_keys(const Hash32& pool_id, const Hash32& tip, const Hash32& p_r,
                                                    std::uint64_t h, std::span<const XmrKeyRef> refs) {
    return derive_output_keys_with_r(derive_r_v3(pool_id, tip, p_r, h), refs);
}

// ---------------------------------------------------------------------------
// The miner tx bytes
// ---------------------------------------------------------------------------
struct MinerOut {
    std::uint64_t amount = 0;
    Hash32 key{};
    std::uint8_t view_tag = 0;

    friend bool operator==(const MinerOut&, const MinerOut&) = default;
};

// The miner tx prefix for height h, outputs in vout order and the tx_extra bytes.
inline std::vector<std::uint8_t> serialize_miner_tx_prefix(std::uint64_t h, std::span<const MinerOut> outs,
                                                           std::span<const std::uint8_t> extra) {
    std::vector<std::uint64_t> amounts(outs.size());
    std::vector<::xmr::coin::PublicKey> keys(outs.size());
    std::vector<::xmr::coin::ViewTag> tags(outs.size());
    for (std::size_t i = 0; i < outs.size(); ++i) {
        amounts[i] = outs[i].amount;
        keys[i] = detail_mtx::to_coin<::xmr::coin::PublicKey>(outs[i].key);
        tags[i].tag = outs[i].view_tag;
    }
    const std::vector<unsigned char> head =
            ::xmr::coin::write_coinbase_prefix_head(h, amounts.data(), keys.data(), tags.data(), outs.size());
    std::vector<std::uint8_t> prefix(head.begin(), head.end());
    detail::put_varint(prefix, extra.size());
    prefix.insert(prefix.end(), extra.begin(), extra.end());
    return prefix;
}

inline Hash32 miner_tx_prefix_hash(std::span<const std::uint8_t> prefix) {
    return detail_mtx::from_coin(::xmr::coin::tx_prefix_hash(std::vector<unsigned char>(prefix.begin(), prefix.end())));
}

// The tx hash of a v2 RCTTypeNull miner tx (tree leaf 0).
inline Hash32 miner_tx_hash(const Hash32& prefix_hash) {
    return detail_mtx::from_coin(
            ::xmr::coin::coinbase_tx_hash(detail_mtx::to_coin<::xmr::coin::Hash256>(prefix_hash)));
}

// hf-16 PBX1 tx_extra: 01 R_tx[32] 02 04 nonce[4] 03 21 00 mm_root[32] (74 B).
inline std::vector<std::uint8_t> canonical_tx_extra_hf16(const Hash32& r_tx,
                                                         const std::array<std::uint8_t, kExtraNonceBytes>& nonce,
                                                         const Hash32& mm_root) {
    Pbx1 x;
    x.keys.push_back(r_tx);
    x.extra_nonce = nonce;
    x.mm_root = mm_root;
    std::vector<std::uint8_t> out;
    encode_pbx1(kHf16, x, out);
    return out;
}

struct MinerTx {
    Hash32 r{};
    Hash32 r_tx{};
    std::vector<std::uint8_t> extra;
    std::vector<MinerOut> outs;
    std::vector<std::uint8_t> prefix;
    Hash32 prefix_hash{};
    Hash32 tx_hash{};
};

// The hf-16 miner tx from its keys and the amounts in vout order. nullopt when
// the counts differ or there is no output.
inline std::optional<MinerTx> assemble_miner_tx_hf16(std::uint64_t h, const OutputKeys& k,
                                                     std::span<const std::uint64_t> amounts,
                                                     const std::array<std::uint8_t, kExtraNonceBytes>& extra_nonce,
                                                     const Hash32& mm_root) {
    if (amounts.empty() || amounts.size() != k.keys.size()) return std::nullopt;
    MinerTx tx;
    tx.r = k.r;
    tx.r_tx = k.r_tx;
    tx.extra = canonical_tx_extra_hf16(k.r_tx, extra_nonce, mm_root);
    tx.outs.reserve(amounts.size());
    for (std::size_t i = 0; i < amounts.size(); ++i)
        tx.outs.push_back(MinerOut{amounts[i], k.keys[i].key, k.keys[i].view_tag});
    tx.prefix = serialize_miner_tx_prefix(h, tx.outs, tx.extra);
    tx.prefix_hash = miner_tx_prefix_hash(tx.prefix);
    tx.tx_hash = miner_tx_hash(tx.prefix_hash);
    return tx;
}

// One payee of the miner tx, in vout order.
struct MinerPayee {
    XmrKeyRef ref;
    std::uint64_t amount = 0;
};

// build_miner_tx_hf16: r from (pool_id, tip, P_r, h), the keys of the payees in
// vout order, PBX1 extra with mm_root. nullopt when a key does not derive.
inline std::optional<MinerTx> build_miner_tx_hf16(const Hash32& pool_id, const Hash32& tip, const Hash32& p_r,
                                                  std::uint64_t h, std::span<const MinerPayee> payees,
                                                  const std::array<std::uint8_t, kExtraNonceBytes>& extra_nonce,
                                                  const Hash32& mm_root) {
    std::vector<XmrKeyRef> refs;
    std::vector<std::uint64_t> amounts;
    refs.reserve(payees.size());
    amounts.reserve(payees.size());
    for (const MinerPayee& p : payees) {
        refs.push_back(p.ref);
        amounts.push_back(p.amount);
    }
    const std::optional<OutputKeys> k = derive_output_keys(pool_id, tip, p_r, h, refs);
    if (!k) return std::nullopt;
    return assemble_miner_tx_hf16(h, *k, amounts, extra_nonce, mm_root);
}

// ---------------------------------------------------------------------------
// KeyCache (S:40-42, S:401-406; R-9): output keys per (tip, P_r) for a window
// with payees; per (tip, P_r, payee) for the finder-only coinbase. On a hit the
// stored pool_id, h and ordered payee digest are compared with the request; a
// difference recomputes. LRU by bytes.
//
// Policy P-36 (ruling 23): budget default 64 MB, flag --pathb-key-cache-mb; a
// miss recomputes, the outcome does not depend on the budget.
// ---------------------------------------------------------------------------
inline constexpr std::size_t kKeyCacheBytesDefault = std::size_t{64} << 20;
inline constexpr std::string_view kKeyCacheFlag = "--pathb-key-cache-mb";

enum class KeysStatus : std::uint8_t {
    Ok,
    MissingRef,   // a payee's key reference is not held
    Underivable,  // r not reduced or a payee key not a point
};

struct KeysResult {
    KeysStatus status = KeysStatus::Underivable;
    std::shared_ptr<const OutputKeys> keys;
};

// Payee i's key reference (vout order); nullopt when not held.
using RefAt = std::function<std::optional<XmrKeyRef>(std::size_t)>;

class KeyCache {
public:
    explicit KeyCache(std::size_t budget_bytes = kKeyCacheBytesDefault) : budget_(budget_bytes) {}

    // payees: identities in vout order. finder_only: the one-output coinbase of
    // the receipt's own payee (payees.size() == 1).
    KeysResult get(const Hash32& pool_id, const Hash32& tip, const Hash32& p_r, std::uint64_t h,
                   std::span<const Hash32> payees, bool finder_only, const RefAt& ref_at) {
        const Key key{tip, p_r, finder_only && !payees.empty() ? payees.front() : Hash32{}};
        const Hash32 digest = payee_digest(payees);
        if (auto it = map_.find(key); it != map_.end()) {
            Entry& e = it->second;
            if (e.pool_id == pool_id && e.h == h && e.digest == digest) {
                lru_.splice(lru_.begin(), lru_, e.lru);
                ++hits_;
                return KeysResult{KeysStatus::Ok, e.keys};
            }
            erase(it);
        }
        std::vector<XmrKeyRef> refs;
        refs.reserve(payees.size());
        for (std::size_t i = 0; i < payees.size(); ++i) {
            std::optional<XmrKeyRef> ref = ref_at(i);
            if (!ref) return KeysResult{KeysStatus::MissingRef, nullptr};
            refs.push_back(*ref);
        }
        ++computations_;
        std::optional<OutputKeys> k = derive_output_keys(pool_id, tip, p_r, h, refs);
        if (!k) return KeysResult{KeysStatus::Underivable, nullptr};
        auto keys = std::make_shared<const OutputKeys>(std::move(*k));
        insert(key, Entry{pool_id, h, digest, keys, entry_bytes(keys->keys.size()), {}});
        return KeysResult{KeysStatus::Ok, keys};
    }

    std::uint64_t computations() const noexcept { return computations_; }
    std::uint64_t hits() const noexcept { return hits_; }
    std::size_t bytes() const noexcept { return bytes_; }
    std::size_t entries() const noexcept { return map_.size(); }
    std::size_t budget() const noexcept { return budget_; }

    static std::size_t entry_bytes(std::size_t n_keys) noexcept {
        return sizeof(Entry) + sizeof(Key) + sizeof(OutputKeys) + n_keys * sizeof(OutKey);
    }

    static Hash32 payee_digest(std::span<const Hash32> payees) {
        std::vector<std::uint8_t> pre;
        pre.reserve(10 + payees.size() * kHashBytes);
        detail::put_varint(pre, payees.size());
        for (const Hash32& p : payees) detail::put_hash(pre, p);
        return detail_mtx::keccak(pre.data(), pre.size());
    }

private:
    struct Key {
        Hash32 tip{};
        Hash32 p_r{};
        Hash32 payee{};  // zero for a window with payees

        friend bool operator<(const Key& a, const Key& b) {
            return std::tie(a.tip, a.p_r, a.payee) < std::tie(b.tip, b.p_r, b.payee);
        }
    };
    struct Entry {
        Hash32 pool_id{};
        std::uint64_t h = 0;
        Hash32 digest{};
        std::shared_ptr<const OutputKeys> keys;
        std::size_t bytes = 0;
        std::list<Key>::iterator lru;
    };

    void erase(std::map<Key, Entry>::iterator it) {
        bytes_ -= it->second.bytes;
        lru_.erase(it->second.lru);
        map_.erase(it);
    }

    void insert(const Key& key, Entry e) {
        if (e.bytes > budget_) return;  // larger than the whole budget: not kept
        while (bytes_ + e.bytes > budget_ && !lru_.empty()) erase(map_.find(lru_.back()));
        lru_.push_front(key);
        e.lru = lru_.begin();
        bytes_ += e.bytes;
        map_.emplace(key, std::move(e));
    }

    std::size_t budget_;
    std::size_t bytes_ = 0;
    std::uint64_t computations_ = 0;
    std::uint64_t hits_ = 0;
    std::map<Key, Entry> map_;
    std::list<Key> lru_;  // most recent first
};

// ---------------------------------------------------------------------------
// hf >= 17 output order (format only; S:531, S:538-539, D:683-690): all miner
// outputs by Ko strictly ascending, Ko compared as Monero's crypto::public_key
// operator< (memcmp); the 0x04 D_e list in the same order. Two equal Ko: no order.
// ---------------------------------------------------------------------------
inline bool ko_less(const Hash32& a, const Hash32& b) noexcept {
    return std::memcmp(a.data(), b.data(), kHashBytes) < 0;
}

// Monero's miner-output check: Ko strictly ascending in vout order.
inline bool miner_outputs_strictly_sorted(std::span<const Hash32> ko) {
    for (std::size_t i = 1; i < ko.size(); ++i)
        if (!ko_less(ko[i - 1], ko[i])) return false;
    return true;
}

// The vout order of outputs given in any order: perm[j] = the input index at
// vout j. nullopt when two Ko are equal.
inline std::optional<std::vector<std::size_t>> carrot_output_order(std::span<const Hash32> ko) {
    std::vector<std::size_t> perm(ko.size());
    std::iota(perm.begin(), perm.end(), std::size_t{0});
    std::sort(perm.begin(), perm.end(), [&](std::size_t a, std::size_t b) { return ko_less(ko[a], ko[b]); });
    for (std::size_t j = 1; j < perm.size(); ++j)
        if (!ko_less(ko[perm[j - 1]], ko[perm[j]])) return std::nullopt;
    return perm;
}

// A per-output list (e.g. the D_e keys of 0x04) in the vout order of perm.
inline std::vector<Hash32> in_vout_order(std::span<const Hash32> v, const std::vector<std::size_t>& perm) {
    std::vector<Hash32> out;
    out.reserve(perm.size());
    for (std::size_t j : perm) out.push_back(v[j]);
    return out;
}

}  // namespace c2pool::xmr::pathb
