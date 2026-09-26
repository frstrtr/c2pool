// ===========================================================================
// LANE-EPOCH BOOTSTRAP -- the settlement CHECKPOINT a fresh node fetches from a
// peer when it joins a LIVE epoch whose history it does not hold.
//
// Trust: none in the peer. A checkpoint names the settled owed state at a
// cursor C (C = the height of the last finalized lane block of that state, the
// ReconRing "since") and carries its PREIMAGE (the rows). The joiner accepts it
// only when
//   V1 the rows hash to the claimed owed_digest ('V37Q' preimage, key ASC,
//      zero rows absent) and every row's key is the identity of its payee ref;
//   V2 mm_root_of(chain, owed_digest) is the 0x03 root of an Own lane block of
//      the checkpoint's epoch on the JOINER'S OWN canonical chain above C (the
//      structure itself committed that state);
//   V3 every hist digest (the RECON ring seed) is likewise committed on chain
//      above its since (or is the empty digest);
//   V5 the epoch header (seq, version, parent) equals the joiner's own epoch
//      view at the witness height.
// The pending set is never served: the joiner books (C, tip] itself from the
// chain (its owed_digest at every later cursor is derived, not copied).
// Any failure -> REFUSED, the peer is dropped, the next peer is asked.
//
// Wire: relay family-B FB_GETCKPT 0x45 / FB_CKPT 0x46 carry these bytes
// opaquely (xmr_relay_wire.hpp); a master peer counts them fb_unknown.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>
#include <sharechain/v37/v37_descriptor.hpp>
#include <sharechain/v37/v37_descriptor_xmr.hpp>
#include "xmr_lane_epoch.hpp"
#include "xmr_lane_epoch_chain.hpp"

namespace c2pool::v37n::xmr::epoch::ckpt {

inline constexpr std::uint8_t  kFmt       = 1;
inline constexpr std::uint32_t kMaxRows   = 1u << 16;
inline constexpr std::uint32_t kMaxHist   = 256;
inline constexpr std::size_t   kMaxRefLen = 128;

struct Row {
    bytes32          key{};
    long long        w = 0;          // finalW (never 0 on the wire)
    std::uint64_t    fe = 0;         // first_eligible (0 = unarmed)
    ::v37::ScriptRef ref;            // the payee (identity_key(ref) == key)
};
struct Hist { bytes32 digest{}; std::uint64_t since = 0; };

struct Checkpoint {
    std::uint8_t       fmt = kFmt;
    credit::EpochField ep{};         // the epoch the state belongs to
    std::uint64_t      cursor = 0;   // C
    bytes32            owed_digest{};
    std::vector<Row>   rows;         // key ASC
    std::vector<Hist>  hist;         // oldest first; the ring seed (the last == (owed_digest, C))
};

namespace detail {
inline void put8(std::vector<std::uint8_t>& b, std::uint8_t v) { b.push_back(v); }
inline void put32(std::vector<std::uint8_t>& b, std::uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back((v >> (8 * i)) & 0xff); }
inline void put64(std::vector<std::uint8_t>& b, std::uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back((v >> (8 * i)) & 0xff); }
inline void putb(std::vector<std::uint8_t>& b, const bytes32& v) { b.insert(b.end(), v.begin(), v.end()); }
struct Rd {
    const std::vector<std::uint8_t>& b; std::size_t o = 0; bool ok = true;
    bool need(std::size_t n) { if (!ok || b.size() - o < n || o > b.size()) ok = false; return ok; }
    std::uint8_t  u8()  { if (!need(1)) return 0; return b[o++]; }
    std::uint32_t u32() { if (!need(4)) return 0; std::uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= std::uint32_t(b[o + i]) << (8 * i); o += 4; return v; }
    std::uint64_t u64() { if (!need(8)) return 0; std::uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= std::uint64_t(b[o + i]) << (8 * i); o += 8; return v; }
    bytes32 b32() { bytes32 v{}; if (!need(32)) return v; std::copy(b.begin() + o, b.begin() + o + 32, v.begin()); o += 32; return v; }
};
} // namespace detail

// Canonical bytes ('V37CK' domain prefix).
inline std::vector<std::uint8_t> encode(const Checkpoint& c) {
    using namespace detail;
    std::vector<std::uint8_t> b = {'V', '3', '7', 'C', 'K'};
    put8(b, c.fmt);
    put32(b, c.ep.seq); put32(b, c.ep.version); putb(b, c.ep.parent);
    put64(b, c.cursor); putb(b, c.owed_digest);
    put32(b, static_cast<std::uint32_t>(c.rows.size()));
    for (const auto& r : c.rows) {
        putb(b, r.key); put64(b, static_cast<std::uint64_t>(r.w)); put64(b, r.fe);
        put8(b, static_cast<std::uint8_t>(r.ref.kind));
        put8(b, static_cast<std::uint8_t>(r.ref.payload.size()));
        b.insert(b.end(), r.ref.payload.begin(), r.ref.payload.end());
    }
    put32(b, static_cast<std::uint32_t>(c.hist.size()));
    for (const auto& h : c.hist) { putb(b, h.digest); put64(b, h.since); }
    return b;
}

inline bool decode(const std::vector<std::uint8_t>& b, Checkpoint& c, std::string* why = nullptr) {
    auto bad = [&](const char* m) { if (why) *why = m; return false; };
    if (b.size() < 5 || b[0] != 'V' || b[1] != '3' || b[2] != '7' || b[3] != 'C' || b[4] != 'K') return bad("ckpt: no V37CK tag");
    detail::Rd r{b, 5};
    c = Checkpoint{};
    c.fmt = r.u8();
    if (r.ok && c.fmt != kFmt) return bad("ckpt: unknown fmt");
    c.ep.seq = r.u32(); c.ep.version = r.u32(); c.ep.parent = r.b32();
    c.cursor = r.u64(); c.owed_digest = r.b32();
    const std::uint32_t nr = r.u32();
    if (!r.ok || nr > kMaxRows) return bad("ckpt: row count");
    c.rows.resize(nr);
    for (auto& row : c.rows) {
        row.key = r.b32(); row.w = static_cast<long long>(r.u64()); row.fe = r.u64();
        row.ref.kind = static_cast<::v37::ScriptKind>(r.u8());
        const std::size_t n = r.u8();
        if (!r.need(n)) return bad("ckpt: short ref");
        row.ref.payload.assign(b.begin() + r.o, b.begin() + r.o + n); r.o += n;
    }
    const std::uint32_t nh = r.u32();
    if (!r.ok || nh > kMaxHist) return bad("ckpt: hist count");
    c.hist.resize(nh);
    for (auto& h : c.hist) { h.digest = r.b32(); h.since = r.u64(); }
    if (!r.ok) return bad("ckpt: short");
    if (r.o != b.size()) return bad("ckpt: trailing bytes");
    return true;
}

// sha256d('V37Q' || key || i64 w || u64 fe ...) -- byte-for-byte the preimage
// OwedLedger::owed_digest() hashes (w == 0 rows carry no commitment weight).
inline bytes32 rows_digest(const std::vector<Row>& rows) {
    std::vector<std::uint8_t> pre = {'V', '3', '7', 'Q'};
    for (const auto& r : rows) {
        if (r.w == 0) continue;
        detail::putb(pre, r.key); detail::put64(pre, static_cast<std::uint64_t>(r.w)); detail::put64(pre, r.fe);
    }
    return ::v37::sha256d(pre);
}

enum class Refusal : std::uint8_t { None, Codec, Rows, Ref, NoWitness, Hist, Epoch, Behind };
inline const char* to_string(Refusal r) {
    switch (r) {
        case Refusal::None:      return "ok";
        case Refusal::Codec:     return "codec";
        case Refusal::Rows:      return "V1-rows-digest";
        case Refusal::Ref:       return "V1-payee-ref";
        case Refusal::NoWitness: return "V2-no-onchain-witness";
        case Refusal::Hist:      return "V3-hist-unwitnessed";
        case Refusal::Epoch:     return "V5-epoch-mismatch";
        case Refusal::Behind:    return "behind-joiner-cursor";
    }
    return "?";
}
struct Verified {
    Refusal       r = Refusal::Codec;
    std::string   why;
    std::uint64_t witness_h = 0;
    bool ok() const { return r == Refusal::None; }
};

// The joiner's chain, read-only: the Own facts of its epoch view.
using FactAt = std::function<const ChainFact*(std::uint64_t)>;

// Verify `c` against the joiner's canonical chain [lo, tip] (V1, V2, V3, V5).
// `state_at(h)` = the joiner's epoch-view fold strictly below h.
inline Verified verify(const Checkpoint& c, std::uint32_t chain_id, const FactAt& fact_at, std::uint64_t tip,
                       const std::function<State(std::uint64_t)>& state_at, std::uint64_t joiner_cursor) {
    Verified v;
    auto fail = [&](Refusal r, std::string w) { v.r = r; v.why = std::move(w); return v; };
    if (c.fmt != kFmt) return fail(Refusal::Codec, "unknown fmt");
    // V1: rows are the preimage of the digest; keys strictly ascending; every key names its payee
    for (std::size_t i = 0; i < c.rows.size(); ++i) {
        const Row& r = c.rows[i];
        if (r.w == 0) return fail(Refusal::Rows, "zero row on the wire");
        if (i && !(c.rows[i - 1].key < r.key)) return fail(Refusal::Rows, "rows not key-ascending");
        if (!::v37::xmr::xmr_ref_well_formed(r.ref) || ::v37::xmr::xmr_identity_key(r.ref) != r.key)
            return fail(Refusal::Ref, "row " + std::to_string(i) + ": key is not the identity of its payee ref");
    }
    if (rows_digest(c.rows) != c.owed_digest) return fail(Refusal::Rows, "rows do not hash to the claimed owed_digest");
    if (c.cursor < joiner_cursor) return fail(Refusal::Behind, "checkpoint cursor " + std::to_string(c.cursor) +
                                              " below the joiner's cursor " + std::to_string(joiner_cursor));
    // V2: the structure committed exactly this state (an Own block of the epoch above C)
    auto witness = [&](const bytes32& d, std::uint64_t above) -> std::uint64_t {
        const bytes32 root = mm_root_of(chain_id, d);
        for (std::uint64_t h = above + 1; h <= tip; ++h) {
            const ChainFact* f = fact_at(h);
            if (f && f->own && f->has_root && f->root == root) return h;
        }
        return 0;
    };
    v.witness_h = witness(c.owed_digest, c.cursor);
    if (!v.witness_h) return fail(Refusal::NoWitness, "owed_digest has no Own lane block committing it above C=" + std::to_string(c.cursor));
    // V3: every ring-seed digest was committed on chain (or is the empty ledger)
    const bytes32 empty = empty_owed_digest();
    for (const auto& h : c.hist) {
        if (h.since > c.cursor) return fail(Refusal::Hist, "hist entry newer than C");
        if (h.digest != empty && !witness(h.digest, h.since)) return fail(Refusal::Hist, "hist digest with no on-chain witness");
    }
    // V5: the epoch header is the joiner's own view of the epoch at the witness
    const State s = state_at(v.witness_h + 1);   // the fold INCLUDING the witness (an opener witness names its own epoch)
    const ChainFact* wf = fact_at(v.witness_h);
    const credit::EpochField wfe = wf ? effective_field(*wf) : credit::EpochField{};
    if (s.cur_seq != c.ep.seq || wfe.seq != c.ep.seq || s.cur_version != c.ep.version || s.cur_parent != c.ep.parent)
        return fail(Refusal::Epoch, "epoch header (seq " + std::to_string(c.ep.seq) + ") != the joiner's view (seq " +
                                    std::to_string(s.cur_seq) + ")");
    v.r = Refusal::None;
    return v;
}

// SERVING side: the checkpoint of the ledger's CURRENT settled state (call it
// at a ledger event; `cursor` = the state's since, the height of the last
// finalized lane block). `pay_of(key)` = the payee ref the node learned.
template <class Ledger, class PayOf>
inline Checkpoint snapshot(const Ledger& L, const PayOf& pay_of, const credit::EpochField& ep, std::uint64_t cursor,
                           std::vector<Hist> hist) {
    Checkpoint c;
    c.ep = ep; c.cursor = cursor; c.owed_digest = L.owed_digest();
    for (const auto& [k, w] : L.finalW()) {
        if (w == 0) continue;
        Row r; r.key = k; r.w = w; r.fe = L.first_eligible_of(k); r.ref = pay_of(k);
        c.rows.push_back(std::move(r));
    }
    if (hist.size() > kMaxHist) hist.erase(hist.begin(), hist.end() - kMaxHist);
    c.hist = std::move(hist);
    return c;
}

// JOINER side: adopt a VERIFIED checkpoint into a FRESH node (no settled row,
// nothing pending: XmrFinalizeDriver::bootstrap_fresh). The finalize cursor jumps to C, then the rows are written
// THROUGH the event log grouped by first_eligible (ascending), so the replayed
// ledger re-arms every key at exactly its served fe and its owed_digest is the
// checkpoint's (checked; a mismatch is a loud failure, never a silent state).
template <class Node>
inline bool adopt(Node& node, const Checkpoint& c, std::string* why) {
    auto bad = [&](std::string m) { if (why) *why = std::move(m); return false; };
    if (!node.finalize_driver().bootstrap_cursor(c.cursor))
        return bad("the node is not fresh (a settled row or a pending block exists) or C is below its cursor");
    std::map<std::uint64_t, std::map<bytes32, long long>> groups;   // fe -> rows (fe 0 = unarmed rows, first)
    for (const auto& r : c.rows) groups[r.fe][r.key] = r.w;
    static const char* hx = "0123456789abcdef";
    std::size_t i = 0;
    for (const auto& [fe, rows] : groups) {
        std::string id = "ckpt-" + std::to_string(c.ep.seq) + "-" + std::to_string(c.cursor) + "-" + std::to_string(i++) + "-";
        for (int j = 0; j < 4; ++j) { id += hx[c.owed_digest[j] >> 4]; id += hx[c.owed_digest[j] & 15]; }
        (void)node.seed_settled_owed(id, rows, fe ? fe : 1);
    }
    node.finalize_driver().set_digest_since(c.cursor);
    if (node.ledger().owed_digest() != c.owed_digest) return bad("adopted ledger digest != checkpoint digest (codec/ledger drift)");
    return true;
}

// FNV-free short hex for logs.
inline std::string short_hex(const bytes32& d) {
    static const char* hx = "0123456789abcdef";
    std::string s; for (int j = 0; j < 8; ++j) { s += hx[d[j] >> 4]; s += hx[d[j] & 15]; }
    return s;
}

} // namespace c2pool::v37n::xmr::epoch::ckpt
