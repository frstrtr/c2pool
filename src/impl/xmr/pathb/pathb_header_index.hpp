// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_header_index.hpp
// Path B, slice S3b-4a: side headers and the bodies of placed carriers.
//
//   CarrierHeader   the FC_HEADERS header: u8 ver 3 | own receipt body |
//                   u8 n_carried | u128 cum_work_claim (LE); id =
//                   receipt_id(own); digest = sha256d(header bytes).
//   HeaderIndex     side-header variants keyed by (id, digest), each with its
//                   serving peers; no count cap (P-49: a structure, no
//                   number):
//                     a peer holds at most one unbound variant per id; its
//                       later variant of that id replaces its earlier one;
//                     bind(id, digest) drops every other variant of id; a
//                       later different variant of a bound id is dropped;
//                     a peer's unbound variants are released when it
//                       disconnects or is banned (release_peer);
//                     an unbound variant with h < the floor H(base_pos - J_0)
//                       is dropped (drop_below);
//                   body sets of walked carriers: one unbound set per
//                   (serving peer, carrier id), keyed by its digest, a peer's
//                   later set replacing its earlier one; dropped on placement
//                   of the carrier, with the peer, or with its header below
//                   the floor. Every drop is DROP: no verdict, no token.
//                   Variants and body sets enter only from replies to the
//                   node's own requests (the caller's rule).
//   CarrierBodies   the bodies of the carriers this node placed (own body and
//                   carried bodies), by id.
//   Serving (the node's own binding): FC_HEADERS only from carriers it has
//   placed (bound), the reply ending before the first header it has not
//   (n = 0 when none); FC_GETCARRIER only for a placed carrier; never an
//   unbound HeaderIndex variant or body set.
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/types.hpp"  // U128
#include "sharechain/v37/v37_hash.hpp"          // ::v37::sha256d

#include "pathb_params.hpp"
#include "pathb_receipt_admission.hpp"  // receipt_id
#include "pathb_wire_v3.hpp"            // ReceiptBodyV3, CarrierBodyV3, encoders

namespace c2pool::xmr::pathb {

// ---------------------------------------------------------------------------
// CarrierHeader
// ---------------------------------------------------------------------------
struct CarrierHeader {
    ReceiptBodyV3 own;
    std::uint8_t n_carried = 0;
    ::c2pool::xmr::native::U128 cum_work_claim{};

    friend bool operator==(const CarrierHeader&, const CarrierHeader&) = default;
};

// The header bytes: u8 ver | own body | u8 n_carried | LE128 cum_work_claim.
inline std::optional<std::vector<std::uint8_t>> header_bytes(const CarrierHeader& h) {
    std::vector<std::uint8_t> out;
    out.push_back(kCarrierBodyVersion);
    if (encode_receipt_body_v3(h.own, out) != WireError::None) return std::nullopt;
    out.push_back(h.n_carried);
    detail::put_le(out, h.cum_work_claim.lo);
    detail::put_le(out, h.cum_work_claim.hi);
    return out;
}

inline std::optional<Hash32> header_digest(const CarrierHeader& h) {
    const std::optional<std::vector<std::uint8_t>> b = header_bytes(h);
    if (!b) return std::nullopt;
    return ::v37::sha256d(*b);
}

// The header of a carrier body (the body without its carried bodies).
inline CarrierHeader header_of(const CarrierBodyV3& c, const ::c2pool::xmr::native::U128& cum_work_claim = {}) {
    CarrierHeader h;
    h.own = c.own;
    h.n_carried = static_cast<std::uint8_t>(c.carried.size());
    h.cum_work_claim = cum_work_claim;
    return h;
}

// The digest of a body set (the concatenated encodings of the carried bodies).
inline std::optional<Hash32> body_set_digest(const std::vector<ReceiptBodyV3>& bodies) {
    std::vector<std::uint8_t> out;
    detail::put_le(out, static_cast<std::uint64_t>(bodies.size()));
    for (const ReceiptBodyV3& b : bodies)
        if (encode_receipt_body_v3(b, out) != WireError::None) return std::nullopt;
    return ::v37::sha256d(out);
}

// ---------------------------------------------------------------------------
// HeaderIndex
// ---------------------------------------------------------------------------
struct HeaderVariant {
    CarrierHeader header;
    Hash32 id{};
    Hash32 digest{};
    std::set<std::uint64_t> peers;  // the peers that served it
    bool path_ok = true;            // its own reply's header path (t_origin == d, PoW at d) passed
    bool bound = false;             // its own S1.3 #9 matched at this node
    std::uint64_t height = 0;       // h(y) = height(P_r) + 1 (from the reply's Monero context)
};

struct BodySet {
    Hash32 carrier{};
    Hash32 digest{};
    std::vector<ReceiptBodyV3> bodies;
    std::uint64_t peer = 0;
    std::optional<Hash32> reply_header;  // the digest of the header served in the same FC_CARRIER reply
};

enum class IndexAdd : std::uint8_t {
    Added,         // a new variant / body set
    Replaced,      // the peer's earlier unbound variant / set of this id replaced
    Known,         // the same variant / set already held (peer recorded)
    BoundDropped,  // another variant of a bound id (or a set of a placed carrier): dropped
    Unencodable,   // no digest: dropped
};

class HeaderIndex {
public:
    // A variant from `peer`'s reply to the node's own FC_GETHEADERS. `height`:
    // h(y) from the Monero context of the reply; `path_ok`: its reply's header
    // path check.
    IndexAdd add(std::uint64_t peer, const CarrierHeader& h, std::uint64_t height, bool path_ok = true) {
        const std::optional<Hash32> dg = header_digest(h);
        if (!dg) return IndexAdd::Unencodable;
        const Hash32 id = receipt_id(h.own);
        if (const auto b = bound_.find(id); b != bound_.end()) {
            if (b->second != *dg) return IndexAdd::BoundDropped;
            variants_.at(Key{id, *dg}).peers.insert(peer);
            return IndexAdd::Known;
        }
        IndexAdd out = IndexAdd::Added;
        if (const auto pk = by_peer_.find(PeerKey{peer, id}); pk != by_peer_.end()) {
            if (pk->second == *dg) return IndexAdd::Known;
            unserve(peer, id, pk->second);
            out = IndexAdd::Replaced;
        }
        HeaderVariant& v = variants_[Key{id, *dg}];
        if (v.peers.empty() && !v.bound) {
            v.header = h;
            v.id = id;
            v.digest = *dg;
            v.height = height;
            v.path_ok = path_ok;
        }
        v.peers.insert(peer);
        by_peer_[PeerKey{peer, id}] = *dg;
        return out;
    }

    // The variant (id, digest) bound (its own S1.3 #9 matched): every other
    // variant of id is dropped.
    bool bind(const Hash32& id, const Hash32& digest) {
        const auto it = variants_.find(Key{id, digest});
        if (it == variants_.end()) return false;
        for (auto v = variants_.lower_bound(Key{id, Hash32{}}); v != variants_.end() && v->first.first == id;) {
            if (v->first.second == digest) {
                ++v;
                continue;
            }
            for (std::uint64_t p : v->second.peers) by_peer_.erase(PeerKey{p, id});
            v = variants_.erase(v);
        }
        it->second.bound = true;
        for (std::uint64_t p : it->second.peers) by_peer_.erase(PeerKey{p, id});
        bound_[id] = digest;
        return true;
    }

    // A variant refuted at its own #9 (computed Mismatch): dropped.
    void refute(const Hash32& id, const Hash32& digest) {
        const auto it = variants_.find(Key{id, digest});
        if (it == variants_.end() || it->second.bound) return;
        for (std::uint64_t p : it->second.peers) by_peer_.erase(PeerKey{p, id});
        variants_.erase(it);
    }

    // A disconnected or banned peer: its unbound variants and body sets are released.
    void release_peer(std::uint64_t peer) {
        for (auto it = by_peer_.lower_bound(PeerKey{peer, Hash32{}}); it != by_peer_.end() && it->first.first == peer;) {
            const Hash32 id = it->first.second;
            const Hash32 dg = it->second;
            it = by_peer_.erase(it);
            const auto v = variants_.find(Key{id, dg});
            if (v != variants_.end() && !v->second.bound) {
                v->second.peers.erase(peer);
                if (v->second.peers.empty()) variants_.erase(v);
            }
        }
        for (auto it = sets_.begin(); it != sets_.end();) {
            if (it->first.first == peer)
                it = sets_.erase(it);
            else
                ++it;
        }
    }

    // Unbound variants with h(y) < floor (H(base_pos - J_0) on the best chain) and their body sets.
    std::size_t drop_below(std::uint64_t floor) {
        std::size_t n = 0;
        for (auto it = variants_.begin(); it != variants_.end();) {
            if (!it->second.bound && it->second.height < floor) {
                for (std::uint64_t p : it->second.peers) by_peer_.erase(PeerKey{p, it->first.first});
                drop_sets_of(it->first.first);
                it = variants_.erase(it);
                ++n;
            } else {
                ++it;
            }
        }
        return n;
    }

    // Every held variant of id, the bound one first, then by digest.
    std::vector<const HeaderVariant*> variants(const Hash32& id) const {
        std::vector<const HeaderVariant*> out;
        for (auto v = variants_.lower_bound(Key{id, Hash32{}}); v != variants_.end() && v->first.first == id; ++v)
            out.push_back(&v->second);
        std::stable_sort(out.begin(), out.end(), [](const HeaderVariant* a, const HeaderVariant* b) {
            return a->bound && !b->bound;
        });
        return out;
    }

    const HeaderVariant* variant(const Hash32& id, const Hash32& digest) const {
        const auto it = variants_.find(Key{id, digest});
        return it == variants_.end() ? nullptr : &it->second;
    }

    std::optional<Hash32> bound_digest(const Hash32& id) const {
        const auto it = bound_.find(id);
        if (it == bound_.end()) return std::nullopt;
        return it->second;
    }

    // Unbound variants a peer holds (at most one per id).
    std::size_t held_by(std::uint64_t peer) const {
        std::size_t n = 0;
        for (auto it = by_peer_.lower_bound(PeerKey{peer, Hash32{}}); it != by_peer_.end() && it->first.first == peer; ++it)
            ++n;
        return n;
    }
    std::size_t size() const noexcept { return variants_.size(); }

    // ---- body sets (ClosureBodies) ----
    // A body set of carrier `carrier` from `peer`'s reply to the node's own
    // FC_GETCARRIER; reply_header: the header digest in the same reply.
    IndexAdd add_body_set(std::uint64_t peer, const Hash32& carrier, const std::vector<ReceiptBodyV3>& bodies,
                          std::optional<Hash32> reply_header = std::nullopt) {
        if (placed_.count(carrier) != 0) return IndexAdd::BoundDropped;
        const std::optional<Hash32> dg = body_set_digest(bodies);
        if (!dg) return IndexAdd::Unencodable;
        const SetKey k{peer, carrier};
        IndexAdd out = IndexAdd::Added;
        if (const auto it = sets_.find(k); it != sets_.end()) {
            if (it->second.digest == *dg) return IndexAdd::Known;
            out = IndexAdd::Replaced;
        }
        BodySet bs;
        bs.carrier = carrier;
        bs.digest = *dg;
        bs.bodies = bodies;
        bs.peer = peer;
        bs.reply_header = reply_header;
        sets_[k] = std::move(bs);
        return out;
    }

    // The body sets held for a carrier (one per serving peer), by peer.
    std::vector<const BodySet*> body_sets(const Hash32& carrier) const {
        std::vector<const BodySet*> out;
        for (const auto& [k, bs] : sets_)
            if (k.second == carrier) out.push_back(&bs);
        return out;
    }

    // A set refuted by a computed S1.3 #10 or a body's computed Mismatch: dropped.
    void drop_body_set(std::uint64_t peer, const Hash32& carrier) { sets_.erase(SetKey{peer, carrier}); }

    // The carrier placed: its unbound sets are dropped (the placed set is kept by CarrierBodies).
    void placed(const Hash32& carrier) {
        drop_sets_of(carrier);
        placed_.insert(carrier);
    }

private:
    using Key = std::pair<Hash32, Hash32>;              // (id, digest)
    using PeerKey = std::pair<std::uint64_t, Hash32>;   // (peer, id)
    using SetKey = std::pair<std::uint64_t, Hash32>;    // (peer, carrier id)

    void unserve(std::uint64_t peer, const Hash32& id, const Hash32& dg) {
        const auto v = variants_.find(Key{id, dg});
        if (v == variants_.end() || v->second.bound) return;
        v->second.peers.erase(peer);
        if (v->second.peers.empty()) variants_.erase(v);
    }

    void drop_sets_of(const Hash32& carrier) {
        for (auto it = sets_.begin(); it != sets_.end();) {
            if (it->first.second == carrier)
                it = sets_.erase(it);
            else
                ++it;
        }
    }

    std::map<Key, HeaderVariant> variants_;
    std::map<PeerKey, Hash32> by_peer_;  // a peer's unbound variant per id
    std::map<Hash32, Hash32> bound_;     // id -> bound digest
    std::map<SetKey, BodySet> sets_;
    std::set<Hash32> placed_;
};

// ---------------------------------------------------------------------------
// CarrierBodies: the bodies of the carriers this node placed (K-OWN).
// ---------------------------------------------------------------------------
class CarrierBodies {
public:
    void put(const Hash32& id, const CarrierBodyV3& body) { bodies_[id] = body; }
    const CarrierBodyV3* get(const Hash32& id) const {
        const auto it = bodies_.find(id);
        return it == bodies_.end() ? nullptr : &it->second;
    }
    std::size_t size() const noexcept { return bodies_.size(); }

private:
    std::map<Hash32, CarrierBodyV3> bodies_;
};

// FC_HEADERS: the headers after `from` up to `stop`, oldest first, at most
// `max`: placed carriers and, above them, variants this node has bound; the
// reply ends before the first header the node has not bound (empty when
// `stop` does not descend from `from` through bound headers).
template <class Tree>
inline std::vector<CarrierHeader> serve_headers(const Tree& tree, const CarrierBodies& bodies, const HeaderIndex& headers,
                                                const Hash32& from, const Hash32& stop, std::uint64_t max) {
    std::vector<CarrierHeader> above;  // bound, not placed: newest first
    Hash32 x = stop;
    for (std::size_t guard = 0; tree.find(x) == nullptr; ++guard) {
        const std::optional<Hash32> bd = headers.bound_digest(x);
        const HeaderVariant* v = bd ? headers.variant(x, *bd) : nullptr;
        if (v == nullptr || guard > headers.size()) {
            above.clear();  // the chain to `stop` holds a header this node has not bound
            x = Hash32{};
            break;
        }
        above.push_back(v->header);
        x = v->header.own.side.tip;
    }
    std::vector<CarrierHeader> out;
    const std::optional<std::vector<Hash32>> path = tree.find(x) ? tree.path(from, x) : std::nullopt;
    if (!path) return out;
    for (const Hash32& id : *path) {
        if (out.size() >= max) return out;
        const CarrierBodyV3* b = bodies.get(id);
        if (b == nullptr) return out;  // not held: the reply ends before it
        out.push_back(header_of(*b));
    }
    for (auto it = above.rbegin(); it != above.rend() && out.size() < max; ++it) out.push_back(*it);
    return out;
}

// FC_GETCARRIER: a placed carrier's body (with its carried bodies when asked).
template <class Tree>
inline std::optional<CarrierBodyV3> serve_carrier(const Tree& tree, const CarrierBodies& bodies, const Hash32& id,
                                                  bool want_bodies) {
    if (tree.find(id) == nullptr) return std::nullopt;
    const CarrierBodyV3* b = bodies.get(id);
    if (b == nullptr) return std::nullopt;
    CarrierBodyV3 out = *b;
    if (!want_bodies) out.carried.clear();
    return out;
}

}  // namespace c2pool::xmr::pathb
