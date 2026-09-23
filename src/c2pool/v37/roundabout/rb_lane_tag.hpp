#pragma once
// S1 — the v0x03 lane_tag: the roundabout/pool identity bound under PoW.
//
//   lane_tag = sha256d( 'V37RBT' || u32 chain_id || b32 geometry_digest ||
//                       u32 version || u32 authority || u64 map_epoch ||
//                       u32 rb_index || u16 stripe )                 (64 B)
//
//   geometry_digest = sha256d( 'V37RBG' || geometry_leaf(LaneParams) )
//   geometry_leaf   = 'V37H' || u64 window || u64 c0 || u64 rollup ||
//                     u64 half_life || u64 |level_caps| || u64 caps[i]...
//
// geometry_leaf is recomputed STANDALONE from the public LaneParams fields and
// is byte-for-byte the geometry prefix of the canon lane header leaf
// (v37_lane.hpp:2869-2875) — it never calls Lane internals, so it cannot drift
// the lane digest. `version` is the V37.x consensus version the lane runs
// (::v37::SHIPPED_CONSENSUS_VERSION / for_version(v)); `authority` is a u32
// slot reserved 0 (it deliberately does NOT depend on ::v37::LaneKind, which
// has no XMR member).
//
// POOL-ID GAP closure: both BTC and XMR node configs default lane_chain = 0
// (btc_node_config.hpp:128, xmr_node_config.hpp:156), so chain_id alone cannot
// tell two pools apart. A receipt carries its lane_tag inside the PoW preimage;
// a validator recomputes the tag from ITS OWN (chain_id, LaneParams geometry,
// version, authority) and the receipt's (map_epoch, rb_index, stripe). Any
// mismatch — different geometry, different version, different map epoch —
// is an EXPLICIT REJECT_ROUNDABOUT (rb_admission.hpp), never a silent
// divergence.
//
// WIRE / PREIMAGE: the tag is 32 bytes APPENDED after the v0x01/v0x02 112-byte
// WorkEvent preimage (w2_receipt.hpp:216-227). tagged_preimage() below is the
// standalone form; the v0x01 preimage is a strict prefix, so an OFF lane that
// never appends a tag hashes byte-identically to master. Wiring the tagged
// preimage into WorkEvent::hash() and the wire trailer is the S1 SEAM (README).

#include <cstdint>
#include <vector>

#include <c2pool/v37/w2_receipt.hpp>        // WorkEvent (read-only use)
#include <sharechain/v37/v37_lane.hpp>      // LaneParams (read-only use)

#include "rb_params.hpp"

namespace c2pool::v37n::rb {

// Byte-exact mirror of the geometry sub-tuple of the canon "V37H" header leaf.
inline std::vector<std::uint8_t> geometry_leaf(const ::v37::LaneParams& p) {
    std::vector<std::uint8_t> h;
    put_tag(h, "V37H");
    put_u64(h, p.window);
    put_u64(h, p.c0);
    put_u64(h, p.rollup);
    put_u64(h, p.half_life);
    put_u64(h, static_cast<u64>(p.level_caps.size()));
    for (u64 c : p.level_caps) put_u64(h, c);
    return h;
}

inline bytes32 geometry_digest(const ::v37::LaneParams& p) {
    std::vector<std::uint8_t> b;
    put_tag(b, TAG_GEOMETRY);
    const auto leaf = geometry_leaf(p);
    b.insert(b.end(), leaf.begin(), leaf.end());
    return hash_bytes(b);
}

// The node-side constant part of the tag (fixed for a lane incarnation).
struct LaneTagContext {
    ChainId       chain_id = 0;
    bytes32       geometry{};        // geometry_digest(LaneParams)
    std::uint32_t version = 0;       // V37.x consensus version
    std::uint32_t authority = 0;     // reserved 0

    static LaneTagContext of(ChainId chain, const ::v37::LaneParams& p,
                             std::uint32_t version, std::uint32_t authority = 0) {
        return LaneTagContext{chain, geometry_digest(p), version, authority};
    }
    bool operator==(const LaneTagContext&) const = default;
};

inline constexpr std::size_t LANE_TAG_PREIMAGE_BYTES = 6 + 4 + 32 + 4 + 4 + 8 + 4 + 2;  // 64

inline std::vector<std::uint8_t> lane_tag_preimage(const LaneTagContext& c, MapEpoch e,
                                                   RbIndex rb, Stripe s) {
    std::vector<std::uint8_t> b;
    b.reserve(LANE_TAG_PREIMAGE_BYTES);
    put_tag(b, TAG_LANE_TAG);
    put_u32(b, c.chain_id);
    put_b32(b, c.geometry);
    put_u32(b, c.version);
    put_u32(b, c.authority);
    put_u64(b, e);
    put_u32(b, rb);
    put_u16(b, s);
    return b;
}

inline bytes32 lane_tag(const LaneTagContext& c, MapEpoch e, RbIndex rb, Stripe s) {
    return hash_bytes(lane_tag_preimage(c, e, rb, s));
}

// What a v0x03 receipt/carrier carries in clear beside its PoW-bound tag.
struct RbCarriage {
    MapEpoch map_epoch = 0;
    RbIndex  rb_index = 0;
    Stripe   stripe = 0;
    bytes32  lane_tag{};
    bool operator==(const RbCarriage&) const = default;
};

inline constexpr std::size_t RB_CARRIAGE_BYTES = 8 + 4 + 2 + 32;  // 46

// Canonical 46-byte wire encoding (the proposed v0x03 trailer body).
inline std::vector<std::uint8_t> encode_carriage(const RbCarriage& c) {
    std::vector<std::uint8_t> b;
    b.reserve(RB_CARRIAGE_BYTES);
    put_u64(b, c.map_epoch);
    put_u32(b, c.rb_index);
    put_u16(b, c.stripe);
    put_b32(b, c.lane_tag);
    return b;
}

inline bool decode_carriage(const std::uint8_t* p, std::size_t n, RbCarriage& out) {
    if (n != RB_CARRIAGE_BYTES) return false;
    auto rd = [&](std::size_t off, int w) {
        u64 x = 0;
        for (int i = 0; i < w; ++i) x |= u64(p[off + i]) << (8 * i);
        return x;
    };
    out.map_epoch = rd(0, 8);
    out.rb_index = static_cast<RbIndex>(rd(8, 4));
    out.stripe = static_cast<Stripe>(rd(12, 2));
    for (int i = 0; i < 32; ++i) out.lane_tag[i] = p[14 + i];
    return true;
}

// v0x03 PoW preimage: the unchanged v0x01 112-byte preimage || lane_tag.
inline std::vector<std::uint8_t> tagged_preimage(const ::c2pool::v37n::WorkEvent& ev, const bytes32& tag) {
    std::vector<std::uint8_t> v = ev.preimage();
    put_b32(v, tag);
    return v;
}
inline bytes32 tagged_hash(const ::c2pool::v37n::WorkEvent& ev, const bytes32& tag) {
    return hash_bytes(tagged_preimage(ev, tag));
}

}  // namespace c2pool::v37n::rb
