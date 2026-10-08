#pragma once
// S4 — per-roundabout checkpoint summary + canonical serialization + the
// summary merkle, and the k-leg consistent-cut token.
//
// Summary_i = (rb_index, period, lane_digest_i, W_i, payout_map_i) is the
// PoW-backed weight checkpoint a roundabout publishes every ckpt_bins bins
// (D1: cross-roundabout traffic is these checkpoints only; no owed row moves).
// The map derivation (S3) reads W_i; settlement (rb_settle.hpp) reads
// Σ_i payout_map_i; the cut commits merkle(lane_digest_i).
//
// CutTokenK generalizes w4_settlement.hpp CutToken (:284-298) / read_cut()
// (:982-1014) from one lane leg to k roundabout legs WITHOUT modifying them:
// read every leg + the ledger leg, re-read all, any mismatch -> discard and
// retry, budget exhausted or any leg missing -> nullopt. No lock.

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#include "rb_params.hpp"

namespace c2pool::v37n::rb {

struct Summary {
    RbIndex  rb_index = 0;
    u64      period = 0;                 // checkpoint period index (ckpt_bins cadence)
    bytes32  lane_digest{};              // LaneSnapshot::digest of roundabout i's lane
    u128     W = 0;                      // PoW-backed finalized raw work over the period
    std::map<bytes32, U256> payout_map;  // canonical identity key -> decayed weight

    // Canonical bytes: 'V37RBS' || u32 rb || u64 period || b32 lane_digest ||
    // u128 W || u32 count || (b32 key || u256 weight)* in key ASC; zero-weight
    // rows are omitted (they carry no settlement value and must not make two
    // equal maps serialize differently).
    std::vector<std::uint8_t> canonical_bytes() const {
        std::vector<std::uint8_t> b;
        put_tag(b, TAG_SUMMARY);
        put_u32(b, rb_index);
        put_u64(b, period);
        put_b32(b, lane_digest);
        put_u128(b, W);
        std::uint32_t cnt = 0;
        for (const auto& kv : payout_map) if (!kv.second.is_zero()) ++cnt;
        put_u32(b, cnt);
        for (const auto& [k, w] : payout_map) {
            if (w.is_zero()) continue;
            put_b32(b, k);
            put_u256(b, w);
        }
        return b;
    }
    bytes32 hash() const { return hash_bytes(canonical_bytes()); }
};

// Parse canonical_bytes (round-trip + strictness: trailing bytes, non-ASC or
// duplicate keys, zero weights all reject).
inline std::optional<Summary> parse_summary(const std::vector<std::uint8_t>& b) {
    const std::size_t tl = 6;
    std::size_t o = 0;
    auto need = [&](std::size_t n) { return o + n <= b.size(); };
    auto rd = [&](int w) { u64 x = 0; for (int i = 0; i < w; ++i) x |= u64(b[o + i]) << (8 * i); o += w; return x; };
    if (!need(tl) || std::vector<std::uint8_t>(b.begin(), b.begin() + tl) !=
                         std::vector<std::uint8_t>(TAG_SUMMARY, TAG_SUMMARY + tl))
        return std::nullopt;
    o = tl;
    Summary s;
    if (!need(4 + 8 + 32 + 16 + 4)) return std::nullopt;
    s.rb_index = static_cast<RbIndex>(rd(4));
    s.period = rd(8);
    for (int i = 0; i < 32; ++i) s.lane_digest[i] = b[o + i];
    o += 32;
    const u64 lo = rd(8), hi = rd(8);
    s.W = (u128(hi) << 64) | lo;
    const u64 cnt = rd(4);
    bool first = true;
    bytes32 prev{};
    for (u64 i = 0; i < cnt; ++i) {
        if (!need(64)) return std::nullopt;
        bytes32 k;
        for (int j = 0; j < 32; ++j) k[j] = b[o + j];
        o += 32;
        U256 w;
        for (int l = 0; l < 4; ++l) w.v[l] = rd(8);
        if (w.is_zero()) return std::nullopt;
        if (!first && !(prev < k)) return std::nullopt;
        first = false;
        prev = k;
        s.payout_map[k] = w;
    }
    if (o != b.size()) return std::nullopt;
    return s;
}

// 2-ary sha256d merkle, domain-separated leaf/node, an odd node is PROMOTED
// (never duplicated — the duplicate-last rule is malleable, CVE-2012-2459).
// Empty -> all-zero root.
inline bytes32 merkle_root(const std::vector<bytes32>& leaves) {
    if (leaves.empty()) return bytes32{};
    std::vector<bytes32> lvl;
    lvl.reserve(leaves.size());
    for (const auto& l : leaves) {
        std::vector<std::uint8_t> b;
        put_tag(b, TAG_MERKLE_LF);
        put_b32(b, l);
        lvl.push_back(hash_bytes(b));
    }
    while (lvl.size() > 1) {
        std::vector<bytes32> nx;
        for (std::size_t i = 0; i < lvl.size(); i += 2) {
            if (i + 1 == lvl.size()) { nx.push_back(lvl[i]); break; }
            std::vector<std::uint8_t> b;
            put_tag(b, TAG_MERKLE_ND);
            put_b32(b, lvl[i]);
            put_b32(b, lvl[i + 1]);
            nx.push_back(hash_bytes(b));
        }
        lvl.swap(nx);
    }
    return lvl[0];
}

// merkle(lane_digest_i) over the summaries in rb_index order. The caller
// supplies one summary per roundabout; order is canonicalized here.
inline bytes32 summary_merkle(std::vector<Summary> s) {
    std::sort(s.begin(), s.end(),
              [](const Summary& a, const Summary& b) { return a.rb_index < b.rb_index; });
    std::vector<bytes32> leaves;
    leaves.reserve(s.size());
    for (const auto& x : s) leaves.push_back(x.lane_digest);
    return merkle_root(leaves);
}

// ── k-leg consistent cut ────────────────────────────────────────────────────
struct CutLeg {
    RbIndex rb_index = 0;
    u64 incarnation = 0;     // executor-minted, never reused (F2 ABA guard)
    u64 version = 0;         // lane version at the burial-gated prefix
    u64 next_pos = 0;
    bytes32 spine_digest{};  // roundabout i's LaneSnapshot::digest
    bool operator==(const CutLeg&) const = default;
};

struct LedgerLeg {
    u64 ledger_seq = 0;
    bytes32 owed_digest{};   // the ONE replicated ledger (D1)
    bool operator==(const LedgerLeg&) const = default;
};

struct CutTokenK {
    std::vector<CutLeg> legs;   // one per roundabout, rb_index ASC
    LedgerLeg ledger;
    bytes32 lanes_root{};       // merkle_root(legs[i].spine_digest)
    bool operator==(const CutTokenK&) const = default;
};

// read_leg(i) -> optional<CutLeg> (nullopt = ring miss => slow path, nullopt)
// read_ledger() -> LedgerLeg
template <class ReadLeg, class ReadLedger>
inline std::optional<CutTokenK> read_cut_k(RbIndex k, ReadLeg&& read_leg,
                                           ReadLedger&& read_ledger,
                                           unsigned retry_budget = 4,
                                           unsigned* attempts_used = nullptr) {
    for (unsigned attempt = 0; attempt < retry_budget; ++attempt) {
        if (attempts_used) *attempts_used = attempt + 1;
        std::vector<CutLeg> a;
        a.reserve(k);
        bool miss = false;
        for (RbIndex i = 0; i < k; ++i) {
            auto l = read_leg(i);
            if (!l) { miss = true; break; }
            a.push_back(*l);
        }
        if (miss) return std::nullopt;               // ring miss -> slow path
        const LedgerLeg L0 = read_ledger();
        // re-read every leg; any change means the cut did not hold
        bool held = true;
        for (RbIndex i = 0; i < k && held; ++i) {
            auto l = read_leg(i);
            if (!l || !(*l == a[i])) held = false;
        }
        if (!held) continue;
        if (!(read_ledger() == L0)) continue;
        CutTokenK t;
        t.legs = std::move(a);
        t.ledger = L0;
        std::vector<bytes32> d;
        for (const auto& l : t.legs) d.push_back(l.spine_digest);
        t.lanes_root = merkle_root(d);
        return t;
    }
    return std::nullopt;
}

}  // namespace c2pool::v37n::rb
