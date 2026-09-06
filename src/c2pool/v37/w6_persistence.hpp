#pragma once
// ─────────────────────────────────────────────────────────────────────────
// Track A2 · Step W6 — the DURABLE side of the v37 RDWR engine: persistence,
// restart-recovery and the `>D` lane-rebuild slow path. CONSUMER-tree code
// (src/c2pool/v37/) that adds NOTHING to consensus: it only CALLS the fenced
// surfaces (SettleHW / OwedLedger / CutToken / V37Engine / SharechainStorage /
// core::LevelDBStore) and never edits them (spec §7.2).
//
// Binding spec: /home/ubuntu/v37-work/v37-a2-w6-persistence-spec.md
//   §1 state families A/B/C/D · §2.1-2.3 storage primitive + v37s: key schema +
//   every value layout · §2.4 event-log rationale · §3 crash consistency +
//   the single-batch rule + write ordering · §4 restart recovery (steps 1-9,
//   fail-closed rules) · §5 the >D rebuild + replay-to-prefix · §6.5 grep gates
//   · §9 red-team F1 (per-height monotone bin_height), F2 (fail-closed open over
//   the UNION of chains + lhead-vs-levt census), F4 (post-truncate the backward
//   walk at LANE genesis).
//
// This ONE header composes the five W6 fan-out legs onto a single fixed
// ISettleStore contract and a single §2.3 codec layer:
//   (a) the ISettleBatch/ISettleStore seam (spec §7.1);
//   (b) all §2.3 record codecs (u8 ver=1 ‖ u8 kind ‖ payload; ints LE; maps =
//       u32 n ‖ n×(bytes32 ‖ i64); strings = u16 len ‖ bytes) — fail-closed;
//   (c) census_open (F2);
//   (d) SettlementJournal (single writer of families A/B/C, §3.2 sequences);
//   (e) RecoveryDriver (§4.1 steps 1-9), ReplayDriver + PrefixResolver (§5).
// The concrete LevelDB binding (LevelDBSettleStore) is ISOLATED at the bottom
// behind `#ifdef W6_ENABLE_LEVELDB` so a stdlib test TU never pulls
// <core/leveldb_store.hpp> — it drives a FaultSettleStore double instead
// (spec §6, the guard-on/guard-off fault-double shape).
//
// Build modes for the W4 types (fenced; CALLED, never edited):
//   production                : includes the REAL <c2pool/v37/w4_settlement.hpp>
//   W6_PERSISTENCE_STDLIB_TEST : includes the byte-faithful stdlib shim so the
//                               self-check builds single-TU with plain g++ and
//                               the fault double drives every crash window
//                               in memory (no leveldb, no engine, no consensus
//                               tree — for the OOM host).
// The driver code below is written ONCE against the settle:: / ::v37 names and
// compiles unchanged in either mode.
// ─────────────────────────────────────────────────────────────────────────

#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#if defined(W6_PERSISTENCE_STDLIB_TEST)
#  include <c2pool/v37/test/w6_w4_shim.hpp>   // ::v37 + settle:: byte-faithful doubles
#else
#  include <c2pool/v37/w4_settlement.hpp>     // real SettleHW / OwedLedger / CutToken
#endif

namespace c2pool::v37n::persist {

using ::v37::bytes32;
using ::v37::ChainId;
using ::v37::u64;
using SettleHW   = ::c2pool::v37n::settle::SettleHW;
using OwedLedger = ::c2pool::v37n::settle::OwedLedger;
using CutToken   = ::c2pool::v37n::settle::CutToken;
using Amounts    = OwedLedger::Amounts;    // std::map<bytes32,long long>

// ═════════════════════════════════════════════════════════════════════════
// (0) The FIXED interface contract (spec §6/§7.1). The fault double and the
//     LevelDB binding both implement it. The seam exposes ONLY commit_sync()
//     (never commit()) — the §6.5 "every settlement batch ends commit_sync"
//     gate is structural here.
// ═════════════════════════════════════════════════════════════════════════
struct ISettleBatch {
    virtual void put(const std::string& k, const std::string& v) = 0;
    virtual void remove(const std::string& k) = 0;
    virtual bool commit_sync() = 0;                     // false == torn / IO error
    virtual ~ISettleBatch() = default;
};
struct ISettleStore {
    virtual std::unique_ptr<ISettleBatch> batch() = 0;
    virtual std::optional<std::string> get(const std::string& k) = 0;
    // fail-closed: MUST return false on iterator/IO error (never "empty").
    virtual bool for_each_prefix(
        const std::string& prefix,
        const std::function<bool(const std::string& k, const std::string& v)>& fn) = 0;
    virtual ~ISettleStore() = default;
};

// ═════════════════════════════════════════════════════════════════════════
// (1) Schema constants + kinds (spec §2.3). Kinds are 1-based (K_META=1 ..
//     K_TIP=9); a 0 kind byte never occurs, so a zeroed value fails the header
//     check → fail-closed.
// ═════════════════════════════════════════════════════════════════════════
constexpr std::uint8_t SCHEMA_VER = 1;    // reader accepts ver <= own
constexpr unsigned     R_MAX      = 4;    // receipts per carrier (accepted_mask)
constexpr std::size_t  HW_BLOB    = 56;   // SettleHW::serialize() fixed length

enum RecordKind : std::uint8_t {
    K_META = 1, K_HW = 2, K_LHEAD = 3, K_EVENT = 4, K_BLK = 5,
    K_INTENT = 6, K_CARRIER = 7, K_GENESIS = 8, K_TIP = 9,
};
enum EvKind : std::uint8_t { EV_FOUND = 1, EV_FINALIZE = 2, EV_ORPHAN = 3 };

constexpr const char* PREFIX = "v37s:";

// ── key builders (spec §2.3: <chain>=%010u, <seq>=%020u, hashes lower-hex) ──
namespace keys {
inline std::string chain_fmt(ChainId c) {
    char b[16]; std::snprintf(b, sizeof b, "%010u", static_cast<unsigned>(c)); return b;
}
inline std::string seq_fmt(u64 s) {
    char b[24]; std::snprintf(b, sizeof b, "%020llu", static_cast<unsigned long long>(s)); return b;
}
inline std::string hex_lower(const bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (std::uint8_t x : h) { s.push_back(d[x >> 4]); s.push_back(d[x & 0xf]); }
    return s;
}
inline std::string meta()                             { return "v37s:meta"; }
inline std::string hw(ChainId c)                      { return "v37s:hw:" + chain_fmt(c); }
inline std::string lhead(ChainId c)                   { return "v37s:lhead:" + chain_fmt(c); }
inline std::string levt(ChainId c, u64 seq)           { return "v37s:levt:" + chain_fmt(c) + ":" + seq_fmt(seq); }
inline std::string levt_prefix(ChainId c)             { return "v37s:levt:" + chain_fmt(c) + ":"; }
inline std::string blk(ChainId c, const std::string& bid)  { return "v37s:blk:" + chain_fmt(c) + ":" + bid; }
inline std::string blk_prefix(ChainId c)              { return "v37s:blk:" + chain_fmt(c) + ":"; }
inline std::string intent(ChainId c, const bytes32& sh)    { return "v37s:intent:" + chain_fmt(c) + ":" + hex_lower(sh); }
inline std::string intent_prefix(ChainId c)           { return "v37s:intent:" + chain_fmt(c) + ":"; }
inline std::string carrier(ChainId c, const bytes32& sh)   { return "v37s:carrier:" + chain_fmt(c) + ":" + hex_lower(sh); }
inline std::string carrier_prefix(ChainId c)          { return "v37s:carrier:" + chain_fmt(c) + ":"; }
inline std::string tip(ChainId c)                     { return "v37s:tip:" + chain_fmt(c); }
inline std::string genesis(ChainId c)                 { return "v37s:genesis:" + chain_fmt(c); }
} // namespace keys

// ═════════════════════════════════════════════════════════════════════════
// (2) Low-level LE writer / bounds-checked reader (spec §2.3). Every decode
//     fails-closed (nullopt) on underrun / unknown newer ver / wrong kind /
//     bad blob_len / trailing garbage — NEVER a partial default-construct
//     (§2.3 versioning rule / §4.4).
// ═════════════════════════════════════════════════════════════════════════
struct Writer {
    std::string s;
    void u8(std::uint8_t x)  { s.push_back(char(x)); }
    void u16(std::uint16_t x){ for (int i = 0; i < 2; ++i) s.push_back(char((x >> (8 * i)) & 0xff)); }
    void u32(std::uint32_t x){ for (int i = 0; i < 4; ++i) s.push_back(char((x >> (8 * i)) & 0xff)); }
    void u64v(u64 x)         { for (int i = 0; i < 8; ++i) s.push_back(char((x >> (8 * i)) & 0xff)); }
    void i64v(long long v)   { u64v(static_cast<u64>(v)); }
    void b32(const bytes32& b){ s.append(reinterpret_cast<const char*>(b.data()), b.size()); }
    void str(const std::string& v) {
        std::size_t n = v.size() > 0xffff ? 0xffff : v.size();
        u16(static_cast<std::uint16_t>(n)); s.append(v, 0, n);
    }
    void raw(const std::string& v) { s.append(v); }
    // map = u32 n ‖ n × (bytes32 key ‖ i64 amount), canonical std::map key order.
    void amap(const Amounts& m) {
        u32(static_cast<std::uint32_t>(m.size()));
        for (const auto& [k, v] : m) { b32(k); i64v(v); }
    }
    void hdr(std::uint8_t kind) { u8(SCHEMA_VER); u8(kind); }
};
struct Reader {
    const std::string& s; std::size_t o = 0; bool ok = true;
    explicit Reader(const std::string& src) : s(src) {}
    bool need(std::size_t n) { if (o + n > s.size()) { ok = false; return false; } return true; }
    std::uint8_t  u8()  { if (!need(1)) return 0; return std::uint8_t(s[o++]); }
    std::uint16_t u16() { if (!need(2)) return 0; std::uint16_t x = 0; for (int i = 0; i < 2; ++i) x |= std::uint16_t(std::uint8_t(s[o++])) << (8 * i); return x; }
    std::uint32_t u32() { if (!need(4)) return 0; std::uint32_t x = 0; for (int i = 0; i < 4; ++i) x |= std::uint32_t(std::uint8_t(s[o++])) << (8 * i); return x; }
    u64           u64v(){ if (!need(8)) return 0; u64 x = 0; for (int i = 0; i < 8; ++i) x |= u64(std::uint8_t(s[o++])) << (8 * i); return x; }
    long long     i64() { return static_cast<long long>(u64v()); }
    bytes32       b32() { bytes32 b{}; if (!need(32)) return b; for (int i = 0; i < 32; ++i) b[i] = std::uint8_t(s[o++]); return b; }
    std::string   str() { std::uint16_t n = u16(); if (!ok || !need(n)) { ok = false; return {}; } std::string v = s.substr(o, n); o += n; return v; }
    std::string   raw(std::size_t n) { if (!need(n)) return {}; std::string v = s.substr(o, n); o += n; return v; }
    bool amap(Amounts& m) {
        std::uint32_t n = u32(); if (!ok) return false;
        if (n > (s.size() - o) / 40) { ok = false; return false; }   // 40 = 32+8 per entry
        for (std::uint32_t i = 0; i < n; ++i) { bytes32 k = b32(); long long v = i64(); if (!ok) return false; m[k] = v; }
        return ok;
    }
    bool done() const { return ok && o == s.size(); }   // reject trailing garbage
};
// header helper: false (fail-closed) on underrun / unknown newer ver / wrong kind.
inline bool read_hdr(Reader& r, std::uint8_t want_kind) {
    std::uint8_t ver = r.u8(); std::uint8_t kind = r.u8();
    if (!r.ok) return false;
    if (ver > SCHEMA_VER) return false;      // unknown newer schema → fail-closed
    if (kind != want_kind) return false;
    return true;
}

// ═════════════════════════════════════════════════════════════════════════
// (3) Decoded record structs (the value; keys are formed separately, above).
// ═════════════════════════════════════════════════════════════════════════
struct LaneParamsRec {                       // v37_lane.hpp:30-39 layout
    u64 window = 8640, c0 = 4096, rollup = 8, half_life = 2160, journal_depth = 64;
    std::vector<u64> level_caps = {568};
    u64 epoch_len() const { return c0; }     // == E (§5.1)
    bool operator==(const LaneParamsRec&) const = default;
};
struct MetaRec    { std::uint32_t schema = 1; u64 boot_id = 0, created_ts = 0, last_open_ts = 0; };
struct HwRec      { ChainId chain = 0; u64 boot_id = 0; SettleHW hw; };
struct LheadRec   { u64 ledger_seq = 0; bytes32 owed_digest{}; u64 boot_id = 0; };
struct EventRec   { std::uint8_t evkind = EV_FOUND; u64 seq = 0; std::string bid; u64 bin_height = 0;
                    Amounts credit, payout, settled_payout; };
struct BlkRec     { bytes32 share_hash{}; std::string bid;   // bid lives in the KEY (not serialized)
                    u64 height = 0, reward = 0, found_seq = 0, boot_id = 0; CutToken token; };
struct IntentRec  { std::string bid; u64 height = 0, reward = 0, ts = 0; };
struct CarrierRec { u64 boot_id = 0, incarnation = 0, lane_version_after = 0, next_pos_after = 0;
                    bytes32 digest_after{}; std::uint8_t accepted_mask = 0; u64 w_raw_carrier = 0;
                    std::vector<u64> w_raw_receipt; };
struct GenesisRec { bytes32 first_share_hash{}; LaneParamsRec params; u64 ts = 0; };
struct TipRec     { bytes32 share_hash{}; u64 next_pos = 0; u64 boot_id = 0; };

// ═════════════════════════════════════════════════════════════════════════
// (4) §2.3 codecs. Canonical byte layout (the definitive schema): every value
//     = u8 ver=1 ‖ u8 kind ‖ payload; ints LE; maps = u32 n ‖ n×(bytes32‖i64);
//     strings = u16 len ‖ bytes.
// ═════════════════════════════════════════════════════════════════════════

// ── meta ──
inline std::string encode_meta(const MetaRec& m) {
    Writer w; w.hdr(K_META); w.u32(m.schema); w.u64v(m.boot_id); w.u64v(m.created_ts); w.u64v(m.last_open_ts);
    return w.s;
}
inline std::optional<MetaRec> decode_meta(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_META)) return std::nullopt;
    MetaRec m; m.schema = r.u32(); m.boot_id = r.u64v(); m.created_ts = r.u64v(); m.last_open_ts = r.u64v();
    if (!r.done()) return std::nullopt; return m;
}

// ── hw (family A): wraps SettleHW::serialize VERBATIM; blob_len==56 gate ──
inline std::string encode_hw(ChainId chain, u64 boot_id, const SettleHW& hw) {
    Writer w; w.hdr(K_HW); w.u32(static_cast<std::uint32_t>(chain)); w.u64v(boot_id);
    std::string blob = hw.serialize();              // W4 blob, verbatim (56 bytes)
    w.u8(static_cast<std::uint8_t>(blob.size())); w.raw(blob);
    return w.s;
}
inline std::string encode_hw(const HwRec& h) { return encode_hw(h.chain, h.boot_id, h.hw); }
inline std::optional<HwRec> decode_hw(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_HW)) return std::nullopt;
    HwRec h; h.chain = r.u32(); h.boot_id = r.u64v();
    std::uint8_t blen = r.u8(); if (!r.ok) return std::nullopt;
    if (blen != HW_BLOB || !r.need(HW_BLOB)) return std::nullopt;   // BEFORE deserialize
    std::string blob = v.substr(r.o, HW_BLOB); r.o += HW_BLOB;
    if (!r.done()) return std::nullopt;
    h.hw = SettleHW::deserialize(blob);             // safe: exactly 56 bytes present
    return h;
}

// ── lhead (family B consistency) ──
inline std::string encode_lhead(const LheadRec& l) {
    Writer w; w.hdr(K_LHEAD); w.u64v(l.ledger_seq); w.b32(l.owed_digest); w.u64v(l.boot_id);
    return w.s;
}
inline std::optional<LheadRec> decode_lhead(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_LHEAD)) return std::nullopt;
    LheadRec l; l.ledger_seq = r.u64v(); l.owed_digest = r.b32(); l.boot_id = r.u64v();
    if (!r.done()) return std::nullopt; return l;
}

// ── event (family B): the value arguments of the applied W4 mutator ──
inline std::string encode_event(const EventRec& e) {
    Writer w; w.hdr(K_EVENT); w.u8(e.evkind); w.u64v(e.seq); w.str(e.bid); w.u64v(e.bin_height);
    w.amap(e.credit); w.amap(e.payout); w.amap(e.settled_payout);
    return w.s;
}
inline std::optional<EventRec> decode_event(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_EVENT)) return std::nullopt;
    EventRec e; std::uint8_t ek = r.u8();
    if (!r.ok || ek < EV_FOUND || ek > EV_ORPHAN) return std::nullopt;   // evkind guard
    e.evkind = ek; e.seq = r.u64v(); e.bid = r.str(); e.bin_height = r.u64v();
    if (!r.amap(e.credit) || !r.amap(e.payout) || !r.amap(e.settled_payout)) return std::nullopt;
    if (!r.done()) return std::nullopt; return e;
}

// ── blk (family C2): the assembly CutToken for the pool's own block ──
inline void w_token(Writer& w, const CutToken& t) {
    w.u32(static_cast<std::uint32_t>(t.chain));
    w.u64v(t.incarnation); w.u64v(t.version); w.u64v(t.next_pos); w.b32(t.spine_digest);
    w.u64v(t.ledger_seq); w.b32(t.owed_digest); w.u64v(t.hw_height); w.b32(t.hw_tip);
}
inline CutToken r_token(Reader& r) {
    CutToken t;
    t.chain = r.u32(); t.incarnation = r.u64v(); t.version = r.u64v(); t.next_pos = r.u64v();
    t.spine_digest = r.b32(); t.ledger_seq = r.u64v(); t.owed_digest = r.b32();
    t.hw_height = r.u64v(); t.hw_tip = r.b32();
    return t;
}
inline std::string encode_blk(const BlkRec& b) {
    Writer w; w.hdr(K_BLK); w.b32(b.share_hash); w.u64v(b.height); w.u64v(b.reward);
    w.u64v(b.found_seq); w.u64v(b.boot_id); w_token(w, b.token);
    return w.s;
}
inline std::optional<BlkRec> decode_blk(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_BLK)) return std::nullopt;
    BlkRec b; b.share_hash = r.b32(); b.height = r.u64v(); b.reward = r.u64v();
    b.found_seq = r.u64v(); b.boot_id = r.u64v(); b.token = r_token(r);
    if (!r.done()) return std::nullopt; return b;
}

// ── intent (family C2 two-phase) ──
inline std::string encode_intent(const IntentRec& i) {
    Writer w; w.hdr(K_INTENT); w.str(i.bid); w.u64v(i.height); w.u64v(i.reward); w.u64v(i.ts);
    return w.s;
}
inline std::optional<IntentRec> decode_intent(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_INTENT)) return std::nullopt;
    IntentRec i; i.bid = r.str(); i.height = r.u64v(); i.reward = r.u64v(); i.ts = r.u64v();
    if (!r.done()) return std::nullopt; return i;
}

// ── carrier (family C1+C3): dispositions, accepted_mask R_MAX=4, popcount receipts ──
inline int popcount8(std::uint8_t m) { return std::popcount(static_cast<unsigned>(m)); }
inline std::string encode_carrier(const CarrierRec& c) {
    Writer w; w.hdr(K_CARRIER);
    w.u64v(c.boot_id); w.u64v(c.incarnation); w.u64v(c.lane_version_after); w.u64v(c.next_pos_after);
    w.b32(c.digest_after); w.u8(c.accepted_mask); w.u64v(c.w_raw_carrier);
    for (u64 v : c.w_raw_receipt) w.u64v(v);        // popcount(accepted_mask) entries
    return w.s;
}
inline std::optional<CarrierRec> decode_carrier(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_CARRIER)) return std::nullopt;
    CarrierRec c; c.boot_id = r.u64v(); c.incarnation = r.u64v();
    c.lane_version_after = r.u64v(); c.next_pos_after = r.u64v(); c.digest_after = r.b32();
    c.accepted_mask = r.u8(); if (!r.ok) return std::nullopt;
    if (c.accepted_mask >= (1u << R_MAX)) return std::nullopt;      // only R_MAX bits valid
    c.w_raw_carrier = r.u64v();
    int pc = popcount8(c.accepted_mask);
    for (int i = 0; i < pc; ++i) { u64 w = r.u64v(); if (!r.ok) return std::nullopt; c.w_raw_receipt.push_back(w); }
    if (!r.done()) return std::nullopt; return c;
}

// ── genesis (family D anchor): LaneParams layout ──
inline std::string encode_genesis(const GenesisRec& g) {
    Writer w; w.hdr(K_GENESIS); w.b32(g.first_share_hash);
    w.u64v(g.params.window); w.u64v(g.params.c0); w.u64v(g.params.rollup); w.u64v(g.params.half_life);
    w.u32(static_cast<std::uint32_t>(g.params.level_caps.size()));
    for (u64 cap : g.params.level_caps) w.u64v(cap);
    w.u64v(g.params.journal_depth); w.u64v(g.ts);
    return w.s;
}
inline std::optional<GenesisRec> decode_genesis(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_GENESIS)) return std::nullopt;
    GenesisRec g; g.first_share_hash = r.b32();
    g.params.window = r.u64v(); g.params.c0 = r.u64v(); g.params.rollup = r.u64v(); g.params.half_life = r.u64v();
    std::uint32_t n = r.u32(); if (!r.ok) return std::nullopt;
    if (n > 64 || n > (v.size() - r.o) / 8) return std::nullopt;    // sanity + underrun fence
    g.params.level_caps.clear();
    for (std::uint32_t i = 0; i < n; ++i) { u64 cap = r.u64v(); if (!r.ok) return std::nullopt; g.params.level_caps.push_back(cap); }
    g.params.journal_depth = r.u64v(); g.ts = r.u64v();
    if (!r.done()) return std::nullopt; return g;
}

// ── tip (family D anchor) ──
inline std::string encode_tip(const TipRec& t) {
    Writer w; w.hdr(K_TIP); w.b32(t.share_hash); w.u64v(t.next_pos); w.u64v(t.boot_id);
    return w.s;
}
inline std::optional<TipRec> decode_tip(const std::string& v) {
    Reader r(v); if (!read_hdr(r, K_TIP)) return std::nullopt;
    TipRec t; t.share_hash = r.b32(); t.next_pos = r.u64v(); t.boot_id = r.u64v();
    if (!r.done()) return std::nullopt; return t;
}

// ═════════════════════════════════════════════════════════════════════════
// (5) F2 — the fail-closed OPEN census (spec §9 F2). core::LevelDBStore::open()
//     runs leveldb::RepairDB, which silently DROPS checksum-failing records and
//     returns success; a naive hw-key-set scan then never visits a chain whose
//     hw was dropped (its ledger silently vanishes = MD-3 loss), and a dropped
//     CONTIGUOUS levt tail escapes a pure seq-gap check. So census_open:
//       (1) drives off the UNION of chains across ALL v37s: prefixes;
//       (2) FAIL-CLOSED on any chain in that union missing its hw;
//       (3) whole-store lhead-vs-levt census: count(levt) MUST == lhead.ledger_seq
//           (catches a dropped tail) AND hw.ledger_seq == lhead.ledger_seq AND the
//           seqs MUST be the contiguous run 1..L (catches gap / dup / middle drop);
//       (4) any record that fails to decode = a byte-flip → fail-closed, naming
//           the offending key.
//     Runs over the ISettleStore SEAM so the FaultSettleStore double drives every
//     arm without a filesystem trick. (RecoveryDriver, below, additionally re-runs
//     an equivalent census inline as steps 2-3 of §4.1; census_open is the fast
//     open-time gate + the standalone F2 unit surface.)
// ═════════════════════════════════════════════════════════════════════════
struct CensusResult {
    bool ok = true;
    std::vector<std::string> errors;    // named keys / tuples, per §4.4
    std::set<ChainId> chains;           // the union of chains seen
    void fail(const std::string& e) { ok = false; errors.push_back(e); }
};
// Parse the chain id from "v37s:<tag>:<chain>[:...]"; false for chain-less keys.
inline bool parse_chain(const std::string& key, ChainId& out) {
    std::size_t p1 = key.find(':');                 if (p1 == std::string::npos) return false;
    std::size_t p2 = key.find(':', p1 + 1);         if (p2 == std::string::npos) return false;
    std::size_t p3 = key.find(':', p2 + 1);
    std::string cs = key.substr(p2 + 1, (p3 == std::string::npos ? key.size() : p3) - (p2 + 1));
    if (cs.empty()) return false;
    unsigned long long val = 0;
    for (char ch : cs) { if (ch < '0' || ch > '9') return false; val = val * 10 + unsigned(ch - '0'); }
    out = static_cast<ChainId>(val); return true;
}
inline std::string tag_of(const std::string& key) {
    std::size_t p1 = key.find(':'); if (p1 == std::string::npos) return {};
    std::size_t p2 = key.find(':', p1 + 1);
    return key.substr(p1 + 1, (p2 == std::string::npos ? key.size() : p2) - (p1 + 1));
}
inline CensusResult census_open(ISettleStore& store) {
    CensusResult res;
    std::map<ChainId, u64>            hw_seq, lhead_seq;
    std::map<ChainId, bool>           has_hw, has_lhead;
    std::map<ChainId, std::set<u64>>  levt_seqs;
    std::map<ChainId, std::size_t>    levt_count;

    bool scan_ok = store.for_each_prefix(PREFIX, [&](const std::string& k, const std::string& v) -> bool {
        std::string tag = tag_of(k);
        ChainId c = 0; bool have_chain = parse_chain(k, c);
        if (have_chain) res.chains.insert(c);
        if (tag == "meta")          { if (!decode_meta(v))    res.fail("corrupt record (decode failed) at key " + k); }
        else if (tag == "hw")       { auto h = decode_hw(v);    if (!h) { res.fail("corrupt record (decode failed) at key " + k); return true; } if (have_chain) { has_hw[c] = true; hw_seq[c] = h->hw.ledger_seq; } }
        else if (tag == "lhead")    { auto l = decode_lhead(v); if (!l) { res.fail("corrupt record (decode failed) at key " + k); return true; } if (have_chain) { has_lhead[c] = true; lhead_seq[c] = l->ledger_seq; } }
        else if (tag == "levt")     { auto e = decode_event(v); if (!e) { res.fail("corrupt record (decode failed) at key " + k); return true; } if (have_chain) { levt_seqs[c].insert(e->seq); levt_count[c]++; } }
        else if (tag == "blk")      { if (!decode_blk(v))     res.fail("corrupt record (decode failed) at key " + k); }
        else if (tag == "intent")   { if (!decode_intent(v))  res.fail("corrupt record (decode failed) at key " + k); }
        else if (tag == "carrier")  { if (!decode_carrier(v)) res.fail("corrupt record (decode failed) at key " + k); }
        else if (tag == "tip")      { if (!decode_tip(v))     res.fail("corrupt record (decode failed) at key " + k); }
        else if (tag == "genesis")  { if (!decode_genesis(v)) res.fail("corrupt record (decode failed) at key " + k); }
        return true;
    });
    if (!scan_ok) { res.fail("for_each_prefix returned false (iterator/IO error) over prefix " + std::string(PREFIX)); return res; }

    for (ChainId c : res.chains) {                          // (2) every chain must have hw
        if (!has_hw.count(c))
            res.fail("chain " + keys::chain_fmt(c) + ": missing hw (key " + keys::hw(c) +
                     ") but other v37s: records present — RepairDB drop / MD-3 loss");
    }
    for (ChainId c : res.chains) {                          // (3) lhead-vs-levt census
        u64 L = has_lhead.count(c) ? lhead_seq[c] : 0;
        if (has_hw.count(c) && has_lhead.count(c) && hw_seq[c] != L)
            res.fail("chain " + keys::chain_fmt(c) + ": hw.ledger_seq=" + std::to_string(hw_seq[c]) +
                     " != lhead.ledger_seq=" + std::to_string(L));
        std::size_t cnt = levt_count.count(c) ? levt_count[c] : 0;
        if (has_lhead.count(c)) {
            if (cnt != static_cast<std::size_t>(L))
                res.fail("chain " + keys::chain_fmt(c) + ": levt count=" + std::to_string(cnt) +
                         " != lhead.ledger_seq=" + std::to_string(L) + " (dropped/missing levt record — RepairDB tail drop)");
            const auto& seqs = levt_seqs[c];
            for (u64 want = 1; want <= L; ++want)
                if (!seqs.count(want))
                    res.fail("chain " + keys::chain_fmt(c) + ": missing levt seq " + std::to_string(want) +
                             " (key " + keys::levt(c, want) + ")");
        } else if (cnt > 0) {
            res.fail("chain " + keys::chain_fmt(c) + ": " + std::to_string(cnt) +
                     " levt records but no lhead — RepairDB drop of lhead");
        }
    }
    return res;
}

// ═════════════════════════════════════════════════════════════════════════
// (6) SettlementJournal — the SINGLE writer of families A/B/C2 (spec §3). Each
//     entrypoint runs exactly one §3.2 sequence: CALL the W4 mutator, then
//     commit ONE commit_sync batch (the §3.1 single-batch rule). A levt is
//     logged ONLY if ledger_seq advanced across the call (§2.4). No settlement
//     key is written outside a batch; no batch spans two events.
// ═════════════════════════════════════════════════════════════════════════
enum class TipResult    { Advanced, RefusedShorter, Torn, Poisoned };
enum class FoundResult  { Found, Duplicate, CarrierRefused, TornIntent, TornFound, Poisoned };
enum class FinalResult  { Finalized, NoOpNotPending, RejectedNonMonotone, RejectedAboveHighWater, Torn, Poisoned };
enum class OrphanResult { Applied, NoOpUnknown, Torn, Poisoned };

class SettlementJournal {
public:
    SettlementJournal(ISettleStore& store, u64 boot_id) : m_store(store), m_boot_id(boot_id) {}

    // §3.2.1 — tip advance. admit gate → advance → batch{hw} commit_sync →
    // caller then evaluates FINALIZE candidates. No ledger event, so NO levt.
    TipResult on_tip_advanced(ChainId c, u64 h, const bytes32& tip,
                              SettleHW& hw, OwedLedger& ledger) {
        if (poisoned(c)) return TipResult::Poisoned;
        if (!hw.admit_candidate_height(h)) {
            hw.ledger_seq = ledger.ledger_seq();
            auto b = m_store.batch();
            b->put(keys::hw(c), encode_hw(c, m_boot_id, hw));
            if (!b->commit_sync()) { poison(c); return TipResult::Torn; }
            return TipResult::RefusedShorter;
        }
        hw.advance(h, tip);
        hw.ledger_seq = ledger.ledger_seq();
        auto b = m_store.batch();
        b->put(keys::hw(c), encode_hw(c, m_boot_id, hw));
        if (!b->commit_sync()) { poison(c); return TipResult::Torn; }
        return TipResult::Advanced;
    }

    // §3.2.2 a-e — own block found, two-phase (W3-G2 write-ahead). FOUND precedes
    // submit — the ONLY order in which a later coinbase cannot re-pay the same
    // owed (§3.3). Idempotent per bid (§2.4).
    FoundResult on_block_found_twophase(
            ChainId c, const std::string& bid, const bytes32& share_hash,
            u64 height, u64 reward, const Amounts& credit, const Amounts& payout,
            const CutToken& cut, SettleHW& hw, OwedLedger& ledger,
            const std::function<bool()>& carrier_append_fn,
            const std::function<void()>& submit_fn = {},
            const std::function<void()>& telemetry_fn = {}) {
        if (poisoned(c)) return FoundResult::Poisoned;
        if (ledger.is_pending(bid) || ledger.is_settled(bid)) return FoundResult::Duplicate;

        {   // (a) intent — its own sync batch, before the carrier append.
            IntentRec ir{bid, height, reward, /*ts*/0};
            auto b = m_store.batch();
            b->put(keys::intent(c, share_hash), encode_intent(ir));
            if (!b->commit_sync()) { poison(c); return FoundResult::TornIntent; }
        }
        // (b) carrier append — unconditional (W3-G1); on failure leave the intent
        // for the restart reconcile (§3.3 first bullet).
        if (carrier_append_fn && !carrier_append_fn()) return FoundResult::CarrierRefused;

        // (c) FOUND — call the W4 mutator, then ONE batch with everything.
        const u64 seq0 = ledger.ledger_seq();
        ledger.on_block_found(bid, credit, payout);
        const u64 seq1 = ledger.ledger_seq();
        auto b = m_store.batch();
        if (seq1 > seq0) {                               // §2.4: log only if advanced
            EventRec ev; ev.evkind = EV_FOUND; ev.seq = seq1; ev.bid = bid;
            ev.bin_height = height; ev.credit = credit; ev.payout = payout;
            b->put(keys::levt(c, seq1), encode_event(ev));
        }
        BlkRec blk; blk.share_hash = share_hash; blk.height = height; blk.reward = reward;
        blk.found_seq = seq1; blk.boot_id = m_boot_id; blk.token = cut;
        b->put(keys::blk(c, bid), encode_blk(blk));
        stage_head(*b, c, hw, ledger);                   // hw (with ledger_seq) + lhead
        b->remove(keys::intent(c, share_hash));          // two-phase completion
        if (!b->commit_sync()) { poison(c); return FoundResult::TornFound; }

        if (submit_fn) submit_fn();                      // (d) then (e), never before (c)
        if (telemetry_fn) telemetry_fn();
        return FoundResult::Found;
    }

    // §3.2.4 — FINALIZE. batch{levt FINALIZE, lhead, hw} commit_sync THEN publish.
    // F1 (spec §9, consensus): bin_height is an EXPLICIT per-step argument (the
    // coin high-water AT that step) — the journal NEVER reads a live tip — and
    // MUST be monotone-non-decreasing in order. A decreasing step, or one above
    // the persisted high-water (a jump-to-tip overshoot), is REJECTED with the
    // ledger and disk untouched.
    FinalResult on_block_finalized(ChainId c, const std::string& bid, u64 bin_height,
                                   SettleHW& hw, OwedLedger& ledger,
                                   const std::function<void()>& publish_fn = {}) {
        if (poisoned(c)) return FinalResult::Poisoned;
        auto lit = m_last_finalize_bin.find(c);
        if (lit != m_last_finalize_bin.end() && bin_height < lit->second)   // F1 (a) monotone
            return FinalResult::RejectedNonMonotone;
        if (bin_height > hw.hw_height)                                       // F1 (b) never above hw
            return FinalResult::RejectedAboveHighWater;

        const u64 seq0 = ledger.ledger_seq();
        ledger.on_block_finalized(bid, bin_height);
        const u64 seq1 = ledger.ledger_seq();
        if (seq1 == seq0) return FinalResult::NoOpNotPending;

        auto b = m_store.batch();
        EventRec ev; ev.evkind = EV_FINALIZE; ev.seq = seq1; ev.bid = bid; ev.bin_height = bin_height;
        b->put(keys::levt(c, seq1), encode_event(ev));
        stage_head(*b, c, hw, ledger);
        if (!b->commit_sync()) { poison(c); return FinalResult::Torn; }

        m_last_finalize_bin[c] = bin_height;             // record only after durable
        if (publish_fn) publish_fn();                    // publish AFTER the batch
        return FinalResult::Finalized;
    }

    // §3.2.3 — ORPHAN. Pre-SETTLED = pure pending removal; post-SETTLED = priced
    // residual, logged (both bump ledger_seq). Unknown bid = no-op (no bump, no
    // levt, no batch). batch{levt ORPHAN, lhead, hw} commit_sync.
    OrphanResult on_block_orphaned(ChainId c, const std::string& bid,
                                   const Amounts& settled_payout,
                                   SettleHW& hw, OwedLedger& ledger) {
        if (poisoned(c)) return OrphanResult::Poisoned;
        const u64 seq0 = ledger.ledger_seq();
        ledger.on_block_orphaned(bid, settled_payout);
        const u64 seq1 = ledger.ledger_seq();
        if (seq1 == seq0) return OrphanResult::NoOpUnknown;

        auto b = m_store.batch();
        EventRec ev; ev.evkind = EV_ORPHAN; ev.seq = seq1; ev.bid = bid; ev.settled_payout = settled_payout;
        b->put(keys::levt(c, seq1), encode_event(ev));
        stage_head(*b, c, hw, ledger);
        if (!b->commit_sync()) { poison(c); return OrphanResult::Torn; }
        return OrphanResult::Applied;
    }

    // Once-per-open meta bump (boot_id++), its own sync batch.
    bool write_meta(const MetaRec& m) {
        auto b = m_store.batch();
        b->put(keys::meta(), encode_meta(m));
        return b->commit_sync();
    }
    bool is_poisoned(ChainId c) const { return m_poison.count(c) != 0; }

private:
    void stage_head(ISettleBatch& b, ChainId c, SettleHW& hw, OwedLedger& ledger) {
        hw.ledger_seq = ledger.ledger_seq();             // §3.1: copy seq into hw first
        b.put(keys::hw(c), encode_hw(c, m_boot_id, hw));
        LheadRec lh; lh.ledger_seq = ledger.ledger_seq(); lh.owed_digest = ledger.owed_digest(); lh.boot_id = m_boot_id;
        b.put(keys::lhead(c), encode_lhead(lh));
    }
    bool poisoned(ChainId c) const { return m_poison.count(c) != 0; }
    void poison(ChainId c) { m_poison.insert(c); }

    ISettleStore& m_store;
    u64 m_boot_id;
    std::map<ChainId, u64> m_last_finalize_bin;          // F1 monotone tracker
    std::set<ChainId> m_poison;                          // torn-sync abort latch
};

// ═════════════════════════════════════════════════════════════════════════
// (7) The `>D` rebuild slow path (spec §5). ReplayDriver + PrefixResolver drive
//     a deterministic replay from LANE genesis (positions are absolute, §5.3)
//     against three SEAMS: the ISettleStore (durable C1/anchor records), an
//     ISharechainReader (the §5.2 backward prev_hash walk + share bytes), and an
//     IEngineSeam (V37Engine::{submit, snapshot}, or a scratch engine). In the
//     real build the seams are thin adapters over V37Engine / SharechainStorage;
//     binding them to a live engine with publication-suppressed contiguous
//     enqueue is OI-W6-3 (v37_engine.hpp submit_batch follow-on). Nothing here
//     names Lane / Roundabout / LaneExecutor (§6.5).
// ═════════════════════════════════════════════════════════════════════════
struct LaneRecord {                          // seam mirror of ::v37::LaneRecord
    enum class K : std::uint8_t { AddLane, Push, Rewind, RemoveLane };
    K kind = K::Push;
    ChainId chain = 0;
    LaneParamsRec params{};                   // AddLane
    u64 payout_id = 0;                        // Push: PayoutDescriptor identity (mirror)
    u64 w_raw = 0;                            // Push
    std::uint32_t flags = 0;                  // Push
    u64 depth = 0;                            // Rewind
    static LaneRecord AddLane(ChainId c, const LaneParamsRec& p) { LaneRecord r; r.kind = K::AddLane; r.chain = c; r.params = p; return r; }
    static LaneRecord Push(ChainId c, u64 pid, u64 w, std::uint32_t f) { LaneRecord r; r.kind = K::Push; r.chain = c; r.payout_id = pid; r.w_raw = w; r.flags = f; return r; }
    static LaneRecord Rewind(ChainId c, u64 d) { LaneRecord r; r.kind = K::Rewind; r.chain = c; r.depth = d; return r; }
    static LaneRecord RemoveLane(ChainId c) { LaneRecord r; r.kind = K::RemoveLane; r.chain = c; return r; }
};
struct LaneSnapshotView {                     // projection of V37Engine::snapshot
    u64 version = 0, incarnation = 0; ChainId chain = 0; u64 next_pos = 0; bytes32 digest{};
};
struct ISharechainReader {
    // forward=false => walk prev_hash back from `start`, at most `max` hashes,
    // toward the SHARECHAIN genesis (NOT the lane genesis). Element 0 == start.
    virtual std::vector<bytes32> get_chain_hashes(const bytes32& start, u64 max, bool forward) const = 0;
    virtual std::optional<std::string> load_share(const bytes32& h) const = 0;
    virtual ~ISharechainReader() = default;
};
struct IEngineSeam {
    virtual void submit(const LaneRecord& r) = 0;
    virtual std::shared_ptr<const LaneSnapshotView> snapshot(ChainId c) const = 0;
    virtual ~IEngineSeam() = default;
};

// Carrier share bytes the driver re-decodes for descriptors + embedded receipts
// (spec §4.3/§5.2). Mirror layout: u8 n_receipts ‖ u64 carrier_payout_id ‖
// n_receipts × u64 receipt_payout_id.
struct DecodedShare { u64 carrier_payout_id = 0; std::vector<u64> receipt_payout_ids; };
inline std::string encode_share(const DecodedShare& d) {
    Writer w; w.u8(static_cast<std::uint8_t>(d.receipt_payout_ids.size())); w.u64v(d.carrier_payout_id);
    for (u64 id : d.receipt_payout_ids) w.u64v(id);
    return w.s;
}
inline std::optional<DecodedShare> decode_share(const std::string& s) {
    Reader r(s); DecodedShare d; std::uint8_t n = r.u8(); if (!r.ok) return std::nullopt;
    if (n > R_MAX) return std::nullopt;
    d.carrier_payout_id = r.u64v();
    for (std::uint8_t i = 0; i < n; ++i) { u64 id = r.u64v(); if (!r.ok) return std::nullopt; d.receipt_payout_ids.push_back(id); }
    if (!r.done()) return std::nullopt; return d;
}

class ReplayDriver {
public:
    ReplayDriver(ISettleStore& store, ISharechainReader& chain) : m_store(store), m_chain(chain) {}

    // §9 F4: the backward prev_hash walk has NO stop-at-hash. Walk from `tip`
    // backward, POST-TRUNCATE at `lane_genesis` (≠ sharechain genesis) and reverse
    // to forward order [genesis..tip]. Fail-closed (nullopt) if genesis is never
    // reached within `max` (fork / undersized max). Anything BELOW lane genesis is
    // discarded — replaying it starts at the wrong absolute position → wrong digest.
    std::optional<std::vector<bytes32>>
    walk_lane_forward(const bytes32& tip, const bytes32& lane_genesis, u64 max) const {
        std::vector<bytes32> back = m_chain.get_chain_hashes(tip, max, /*forward=*/false);
        std::size_t stop = back.size();
        for (std::size_t i = 0; i < back.size(); ++i)
            if (back[i] == lane_genesis) { stop = i; break; }
        if (stop == back.size()) return std::nullopt;      // never reached lane genesis
        std::vector<bytes32> fwd; fwd.reserve(stop + 1);
        for (std::size_t i = stop + 1; i-- > 0;) fwd.push_back(back[i]);
        return fwd;                                        // fwd[0] == lane_genesis
    }

    // Decode one carrier into its fixed W2 §4.2 push order (carrier first, then
    // accepted receipts in embedded order). Descriptors from the stored share
    // bytes; w_raw / accepted_mask / flags from the pinned C3 record (§4.3 —
    // replay independent of the live mainchain index). nullopt = fail-closed.
    std::optional<std::vector<LaneRecord>>
    pushes_for_carrier(ChainId c, const bytes32& share_hash) const {
        auto sb = m_chain.load_share(share_hash);
        if (!sb) return std::nullopt;
        auto ds = decode_share(*sb);
        if (!ds) return std::nullopt;
        auto cv = m_store.get(keys::carrier(c, share_hash));
        if (!cv) return std::nullopt;
        auto cr = decode_carrier(*cv);
        if (!cr) return std::nullopt;

        std::vector<LaneRecord> out;
        out.push_back(LaneRecord::Push(c, ds->carrier_payout_id, cr->w_raw_carrier, 0));
        std::size_t wi = 0;
        for (int i = 0; i < int(R_MAX) && i < int(ds->receipt_payout_ids.size()); ++i) {
            if (!((cr->accepted_mask >> i) & 1)) continue;
            if (wi >= cr->w_raw_receipt.size()) return std::nullopt;
            out.push_back(LaneRecord::Push(c, ds->receipt_payout_ids[i], cr->w_raw_receipt[wi++], /*flags=*/0x04 /*L0F_RECEIPT*/));
        }
        return out;
    }

    // Full §5.3 rebuild into `engine`: RemoveLane -> AddLane -> replay 0..tip.
    // Returns the reached (digest, next_pos, carriers), or nullopt on any
    // fail-closed condition. The caller checks the digest against digest_after.
    struct RebuildOut { bytes32 digest{}; u64 next_pos = 0; u64 carriers = 0; };
    std::optional<RebuildOut> rebuild(ChainId c, IEngineSeam& engine, u64 walk_max = ~u64(0)) {
        auto gv = m_store.get(keys::genesis(c));
        auto tv = m_store.get(keys::tip(c));
        if (!gv || !tv) return std::nullopt;
        auto g = decode_genesis(*gv); auto t = decode_tip(*tv);
        if (!g || !t) return std::nullopt;
        auto fwd = walk_lane_forward(t->share_hash, g->first_share_hash, walk_max);
        if (!fwd) return std::nullopt;                     // F4: never reached genesis

        engine.submit(LaneRecord::RemoveLane(c));          // fresh incarnation (§5.3)
        engine.submit(LaneRecord::AddLane(c, g->params));
        u64 carriers = 0;
        for (const bytes32& h : *fwd) {
            auto ps = pushes_for_carrier(c, h);
            if (!ps) return std::nullopt;
            for (const LaneRecord& r : *ps) engine.submit(r);
            ++carriers;
        }
        auto snap = engine.snapshot(c);
        if (!snap) return std::nullopt;
        RebuildOut o; o.digest = snap->digest; o.next_pos = snap->next_pos; o.carriers = carriers;
        return o;
    }

    // Emit the full canonical [AddLane, pushes...] stream — the input the
    // PrefixResolver replays into a scratch engine. Touches no engine.
    std::optional<std::vector<LaneRecord>>
    canonical_records(ChainId c, u64 walk_max = ~u64(0)) {
        auto gv = m_store.get(keys::genesis(c));
        auto tv = m_store.get(keys::tip(c));
        if (!gv || !tv) return std::nullopt;
        auto g = decode_genesis(*gv); auto t = decode_tip(*tv);
        if (!g || !t) return std::nullopt;
        auto fwd = walk_lane_forward(t->share_hash, g->first_share_hash, walk_max);
        if (!fwd) return std::nullopt;
        std::vector<LaneRecord> rs;
        rs.push_back(LaneRecord::AddLane(c, g->params));
        for (const bytes32& h : *fwd) {
            auto ps = pushes_for_carrier(c, h);
            if (!ps) return std::nullopt;
            for (const LaneRecord& r : *ps) rs.push_back(r);
        }
        return rs;
    }

private:
    ISettleStore& m_store;
    ISharechainReader& m_chain;
};

// §5.5 — W4's slow path for ring misses and pre-boot tokens. Keyed by prefix
// identity (chain, next_pos, spine_digest). Builds a scratch engine, replays the
// canonical records up to next_pos == P_b, snapshots, returns the projection IFF
// the reached digest == the requested spine_digest — else nullopt (prefix
// rewritten; F-SPINE's broadcast_prefix_rewritten). A CutToken from an earlier
// boot_id/incarnation is not in any ring; this path resolves it BY DIGEST,
// incarnation being node-local (§1, W4 §6.3).
class PrefixResolver {
public:
    using ScratchFactory = std::function<std::unique_ptr<IEngineSeam>()>;
    explicit PrefixResolver(ScratchFactory make_scratch) : m_make(std::move(make_scratch)) {}

    std::optional<LaneSnapshotView>
    resolve(ChainId chain, u64 target_pos, const bytes32& spine_digest,
            const std::vector<LaneRecord>& records) {
        std::unique_ptr<IEngineSeam> eng = m_make();
        u64 pushes = 0;
        for (const LaneRecord& r : records) {
            if (r.kind == LaneRecord::K::AddLane) { eng->submit(r); continue; }
            if (r.kind != LaneRecord::K::Push) continue;
            if (pushes >= target_pos) break;
            eng->submit(r); ++pushes;
        }
        if (pushes != target_pos) return std::nullopt;
        auto snap = eng->snapshot(chain);
        if (!snap) return std::nullopt;
        if (snap->next_pos != target_pos) return std::nullopt;
        if (snap->digest != spine_digest) return std::nullopt;   // rewritten
        return *snap;
    }
    std::optional<LaneSnapshotView>
    resolve_token(const CutToken& tok, const std::vector<LaneRecord>& records) {
        return resolve(tok.chain, tok.next_pos, tok.spine_digest, records);
    }
private:
    ScratchFactory m_make;
};

}  // namespace c2pool::v37n::persist


// ═════════════════════════════════════════════════════════════════════════
// (8) RecoveryDriver — restart recovery, spec §4.1 steps 1-9. Runs before the
//     engine accepts live records: reads meta (boot_id++), drives off the UNION
//     of chains, loads family A (hw, never re-derived), replays family B (levt →
//     mutators) with the §4.4 seq/digest gate + the F2 dropped-tail census,
//     rebuilds family D through the ReplayDriver hook with the §4.1 step-5
//     digest check, own-block-reconciles against the coin oracle SHAPE, resolves
//     surviving intents (§3.3), and starts each chain only if every §4.4 gate
//     passed — never "starts empty" (the MD-3 composition loss).
// ═════════════════════════════════════════════════════════════════════════
namespace c2pool::v37n::recover {

using ::v37::bytes32;
using ::v37::u64;
using settle::CutToken;
using settle::OwedLedger;
using settle::SettleHW;
using persist::ISettleStore;
using persist::LaneParamsRec;
using persist::MetaRec;
using persist::LheadRec;
using persist::EventRec;
using persist::BlkRec;
using persist::IntentRec;
using persist::CarrierRec;
using persist::TipRec;
using persist::GenesisRec;

enum : std::uint8_t { EV_FOUND = 1, EV_FINALIZE = 2, EV_ORPHAN = 3 };

struct FailClosed {
    u64 chain = 0;
    std::string condition;   // §4.4 name, e.g. "hw_missing", "seq_disagreement", "levt_bad"
    std::string key;         // the offending v37s: key (named, per RS-4 / F2)
    std::string detail;      // the exact tuple (seqs/digests) that disagreed
};
struct ChainRecovery {
    u64 chain = 0;
    bool started = false;
    bool refused_until_catchup = false;                  // §4.1 step 2 / RS-2
    SettleHW hw{};
    LheadRec lhead{};
    std::unique_ptr<OwedLedger> ledger;                  // built only on success
    std::vector<FailClosed> fails;
    u64 levt_applied = 0;
    u64 new_incarnation = 0;
    std::map<std::string, OwedLedger::Amounts> found_payout;   // §4.1 step 6 residual source
};
struct RecoveryHooks {
    std::function<u64(u64 /*chain*/)> local_header_height = [](u64) { return ~u64(0); };
    std::function<std::optional<std::pair<bytes32, u64>>(
        u64, const GenesisRec&, const TipRec&, const std::vector<CarrierRec>&)> replay_lane;
    std::function<std::optional<bytes32>(u64 /*chain*/, u64 /*height*/)> winner_at;
    std::function<bool(const CutToken&)> preboot_token_resolves = [](const CutToken&) { return false; };
    struct FoundRederive { OwedLedger::Amounts credit, payout; u64 bin_height = 0; BlkRec blk; };
    std::function<std::optional<FoundRederive>(const IntentRec&)> try_rederive_intent =
        [](const IntentRec&) { return std::optional<FoundRederive>{}; };
    std::function<void(u64 /*chain*/, u64 /*incarnation*/)> rebuild_w2_window = [](u64, u64) {};
};

class RecoveryDriver {
public:
    RecoveryDriver(ISettleStore& store, RecoveryHooks hooks) : m_store(store), m_hooks(std::move(hooks)) {}

    struct Result {
        MetaRec meta;
        std::map<u64, ChainRecovery> chains;
        std::vector<FailClosed> store_fails;
        bool ok() const {
            for (const auto& [c, r] : chains) { (void)c; if (!r.started) return false; }
            return store_fails.empty();
        }
    };

    Result recover() {
        Result res;
        if (!open_meta(res)) return res;                 // step 1
        std::set<u64> chains = census_union_chains(res); // F2 union
        for (u64 c : chains) {
            ChainRecovery cr; cr.chain = c;
            if (!load_family_A(c, cr)) { res.chains[c] = std::move(cr); continue; }  // step 2
            u64 hh = m_hooks.local_header_height(c);
            if (hh < cr.hw.hw_height) {                   // RS-2: refuse-until-catch-up
                cr.refused_until_catchup = true;
                (void)cr.hw.admit_candidate_height(hh);
            }
            if (!load_family_B(c, cr)) { res.chains[c] = std::move(cr); continue; }  // step 3
            if (!rebuild_family_D(c, cr)) { res.chains[c] = std::move(cr); continue; } // steps 4-5
            if (!own_block_reconcile(c, cr)) { res.chains[c] = std::move(cr); continue; } // step 6
            if (!intent_reconcile(c, cr)) { res.chains[c] = std::move(cr); continue; } // step 7
            m_hooks.rebuild_w2_window(c, cr.new_incarnation);                          // step 8
            cr.started = true;                                                         // step 9
            res.chains[c] = std::move(cr);
        }
        return res;
    }
    u64 boot_id() const { return m_boot_id; }

private:
    static std::string ten(u64 x)  { std::ostringstream o; o.width(10); o.fill('0'); o << x; return o.str(); }
    static std::string twenty(u64 x){ std::ostringstream o; o.width(20); o.fill('0'); o << x; return o.str(); }
    static std::string p_hw(u64 c)      { return "v37s:hw:" + ten(c); }
    static std::string p_lhead(u64 c)   { return "v37s:lhead:" + ten(c); }
    static std::string p_levt(u64 c)    { return "v37s:levt:" + ten(c) + ":"; }
    static std::string p_blk(u64 c)     { return "v37s:blk:" + ten(c) + ":"; }
    static std::string p_intent(u64 c)  { return "v37s:intent:" + ten(c) + ":"; }
    static std::string p_carrier(u64 c) { return "v37s:carrier:" + ten(c) + ":"; }
    static std::string p_tip(u64 c)     { return "v37s:tip:" + ten(c); }
    static std::string p_genesis(u64 c) { return "v37s:genesis:" + ten(c); }
    static std::string hex(const bytes32& h) {
        static const char* d = "0123456789abcdef";
        std::string s; s.reserve(64);
        for (auto b : h) { s.push_back(d[(b >> 4) & 0xf]); s.push_back(d[b & 0xf]); }
        return s;
    }

    bool open_meta(Result& res) {
        auto v = m_store.get("v37s:meta");
        MetaRec m;
        if (v) {
            auto dec = persist::decode_meta(*v);
            if (!dec) { res.store_fails.push_back({0, "meta_decode", "v37s:meta", "unknown schema/kind"}); return false; }
            m = *dec;
        }
        m.boot_id += 1; m_boot_id = m.boot_id;
        auto b = m_store.batch();
        b->put("v37s:meta", persist::encode_meta(m));
        if (!b->commit_sync()) { res.store_fails.push_back({0, "meta_commit", "v37s:meta", "commit_sync failed"}); return false; }
        res.meta = m;
        return true;
    }

    std::set<u64> census_union_chains(Result& res) {
        std::set<u64> chains;
        bool ok = m_store.for_each_prefix("v37s:", [&](const std::string& k, const std::string&) {
            u64 c; if (parse_chain(k, c)) chains.insert(c); return true;
        });
        if (!ok) res.store_fails.push_back({0, "census_iter", "v37s:", "for_each_prefix returned false"});
        return chains;
    }
    static bool parse_chain(const std::string& k, u64& out) {
        std::size_t p1 = k.find(':'); if (p1 == std::string::npos) return false;
        std::size_t p2 = k.find(':', p1 + 1); if (p2 == std::string::npos) return false;
        std::size_t start = p2 + 1; if (start + 10 > k.size()) return false;
        u64 v = 0;
        for (std::size_t i = 0; i < 10; ++i) { char ch = k[start + i]; if (ch < '0' || ch > '9') return false; v = v * 10 + u64(ch - '0'); }
        out = v; return true;
    }

    bool load_family_A(u64 c, ChainRecovery& cr) {
        auto v = m_store.get(p_hw(c));
        if (!v) { cr.fails.push_back({c, "hw_missing", p_hw(c), "chain present in v37s: union but hw dropped (RepairDB) — refuse"}); return false; }
        auto dec = persist::decode_hw(*v);
        if (!dec) { cr.fails.push_back({c, "hw_decode", p_hw(c), "unknown ver / blob_len!=56 / byte-flip — never default-construct"}); return false; }
        cr.hw = dec->hw;
        return true;
    }

    bool load_family_B(u64 c, ChainRecovery& cr) {
        cr.ledger = std::make_unique<OwedLedger>(static_cast<::v37::ChainId>(c));
        auto lv = m_store.get(p_lhead(c));
        if (!lv) { cr.fails.push_back({c, "lhead_missing", p_lhead(c), "chain in union, lhead dropped (RepairDB) — refuse"}); return false; }
        auto ldec = persist::decode_lhead(*lv);
        if (!ldec) { cr.fails.push_back({c, "lhead_decode", p_lhead(c), "unknown ver/kind or byte-flip"}); return false; }
        cr.lhead = *ldec;

        u64 expected_seq = 0; bool bad = false; std::string bad_key, bad_detail;
        bool iter_ok = m_store.for_each_prefix(p_levt(c), [&](const std::string& k, const std::string& val) {
            auto ev = persist::decode_event(val);
            if (!ev) { bad = true; bad_key = k; bad_detail = "levt decode failed (unknown ver / byte-flip)"; return false; }
            ++expected_seq;
            if (ev->seq != expected_seq) { bad = true; bad_key = k; bad_detail = "levt seq " + std::to_string(ev->seq) + " != expected " + std::to_string(expected_seq); return false; }
            if (ev->evkind == EV_FOUND) cr.found_payout[ev->bid] = ev->payout;
            apply_event(*cr.ledger, *ev);
            return true;
        });
        if (!iter_ok && !bad) { cr.fails.push_back({c, "levt_iter", p_levt(c), "for_each_prefix returned false"}); return false; }
        if (bad) { cr.fails.push_back({c, "levt_bad", bad_key, bad_detail}); return false; }
        cr.levt_applied = expected_seq;

        u64 lseq = cr.ledger->ledger_seq();
        if (!(lseq == cr.hw.ledger_seq && lseq == cr.lhead.ledger_seq)) {
            cr.fails.push_back({c, "seq_disagreement", p_lhead(c),
                "ledger.seq=" + std::to_string(lseq) + " hw.seq=" + std::to_string(cr.hw.ledger_seq) +
                " lhead.seq=" + std::to_string(cr.lhead.ledger_seq) + " (dropped levt tail or torn state)"});
            return false;
        }
        if (cr.ledger->owed_digest() != cr.lhead.owed_digest) {
            cr.fails.push_back({c, "owed_digest_mismatch", p_lhead(c),
                "replayed=" + hex(cr.ledger->owed_digest()) + " lhead=" + hex(cr.lhead.owed_digest)});
            return false;
        }
        return true;
    }

    static void apply_event(OwedLedger& led, const EventRec& ev) {
        switch (ev.evkind) {
            case EV_FOUND:    led.on_block_found(ev.bid, ev.credit, ev.payout); break;
            case EV_FINALIZE: led.on_block_finalized(ev.bid, ev.bin_height); break;   // F1: persisted height
            case EV_ORPHAN:   led.on_block_orphaned(ev.bid, ev.settled_payout); break;
            default: break;
        }
    }

    bool rebuild_family_D(u64 c, ChainRecovery& cr) {
        auto gv = m_store.get(p_genesis(c));
        auto tv = m_store.get(p_tip(c));
        if (!gv || !tv) { cr.new_incarnation = 1; return true; }   // settlement-only chain, no lane
        auto gdec = persist::decode_genesis(*gv);
        auto tdec = persist::decode_tip(*tv);
        if (!gdec || !tdec) { cr.fails.push_back({c, "anchor_decode", gdec ? p_tip(c) : p_genesis(c), "genesis/tip decode failed"}); return false; }

        std::vector<CarrierRec> carriers; bytes32 tip_digest{}; bool have_tip_carrier = false;
        std::string bad_key, bad_detail; bool bad = false;
        bool iter_ok = m_store.for_each_prefix(p_carrier(c), [&](const std::string& k, const std::string& val) {
            auto cd = persist::decode_carrier(val);
            if (!cd) { bad = true; bad_key = k; bad_detail = "carrier decode failed"; return false; }
            if (cd->next_pos_after == tdec->next_pos && key_hash_matches(k, tdec->share_hash)) { tip_digest = cd->digest_after; have_tip_carrier = true; }
            carriers.push_back(*cd);
            return true;
        });
        if (!iter_ok && !bad) { cr.fails.push_back({c, "carrier_iter", p_carrier(c), "for_each_prefix returned false"}); return false; }
        if (bad) { cr.fails.push_back({c, "carrier_bad", bad_key, bad_detail}); return false; }

        cr.new_incarnation = 1;                          // §1: fresh process, m_next_incarnation -> 1
        if (!m_hooks.replay_lane) return true;           // no replay hook (families A/B only)
        auto reached = m_hooks.replay_lane(c, *gdec, *tdec, carriers);
        if (!reached) { cr.fails.push_back({c, "replay_failed", p_genesis(c), "ReplayDriver returned nullopt"}); return false; }
        if (reached->second != tdec->next_pos) {         // §4.1 step 5
            cr.fails.push_back({c, "replay_pos_mismatch", p_tip(c), "reached next_pos=" + std::to_string(reached->second) + " tip.next_pos=" + std::to_string(tdec->next_pos)});
            return false;
        }
        if (have_tip_carrier && reached->first != tip_digest) {
            cr.fails.push_back({c, "replay_digest_mismatch", p_tip(c), "reached=" + hex(reached->first) + " digest_after=" + hex(tip_digest)});
            return false;
        }
        return true;
    }
    static bool key_hash_matches(const std::string& carrier_key, const bytes32& h) {
        std::string want = persist::keys::hex_lower(h);
        return carrier_key.size() >= want.size() && carrier_key.compare(carrier_key.size() - want.size(), want.size(), want) == 0;
    }

    bool own_block_reconcile(u64 c, ChainRecovery& cr) {
        std::vector<std::pair<std::string, BlkRec>> blks;
        std::string bad_key, bad_detail; bool bad = false;
        const std::string blk_prefix = p_blk(c);
        bool iter_ok = m_store.for_each_prefix(blk_prefix, [&](const std::string& k, const std::string& val) {
            auto bd = persist::decode_blk(val);
            if (!bd) { bad = true; bad_key = k; bad_detail = "blk decode failed"; return false; }
            bd->bid = k.substr(blk_prefix.size());
            blks.emplace_back(k, *bd);
            return true;
        });
        if (!iter_ok && !bad) { cr.fails.push_back({c, "blk_iter", p_blk(c), "for_each_prefix returned false"}); return false; }
        if (bad) { cr.fails.push_back({c, "blk_bad", bad_key, bad_detail}); return false; }

        for (auto& [k, bd] : blks) {
            (void)k;
            if (bd.token.incarnation != 0 && bd.boot_id != m_boot_id) {     // §1 / RS-5 pre-boot
                if (!m_hooks.preboot_token_resolves(bd.token)) continue;    // refuse, never alias
            }
            bool pending = cr.ledger->is_pending(bd.bid);
            bool settled = cr.ledger->is_settled(bd.bid);
            if (!pending && !settled) continue;
            std::optional<bytes32> w = m_hooks.winner_at ? m_hooks.winner_at(c, bd.height) : std::nullopt;
            bool still_wins = w && (*w == bd.share_hash);
            if (still_wins) continue;
            if (pending) {
                cr.ledger->on_block_orphaned(bd.bid, {});
                log_reconcile_event(c, cr, EV_ORPHAN, bd.bid, {}, {});
            } else {
                OwedLedger::Amounts sp;
                auto fit = cr.found_payout.find(bd.bid);
                if (fit != cr.found_payout.end()) sp = fit->second;
                cr.ledger->on_block_orphaned(bd.bid, sp);
                log_reconcile_event(c, cr, EV_ORPHAN, bd.bid, {}, sp);
            }
        }
        return true;
    }

    void log_reconcile_event(u64 c, ChainRecovery& cr, std::uint8_t evkind, const std::string& bid,
                             const OwedLedger::Amounts& credit, const OwedLedger::Amounts& settled_payout) {
        u64 seq = cr.ledger->ledger_seq();
        if (seq == cr.lhead.ledger_seq) return;
        EventRec ev; ev.evkind = evkind; ev.seq = seq; ev.bid = bid;
        ev.bin_height = cr.hw.hw_height; ev.credit = credit; ev.settled_payout = settled_payout;
        cr.hw.ledger_seq = seq; cr.lhead.ledger_seq = seq; cr.lhead.owed_digest = cr.ledger->owed_digest();
        auto b = m_store.batch();
        b->put("v37s:levt:" + ten(c) + ":" + twenty(seq), persist::encode_event(ev));
        b->put(p_lhead(c), persist::encode_lhead(cr.lhead));
        b->put(p_hw(c), persist::encode_hw(static_cast<::v37::ChainId>(c), m_boot_id, cr.hw));
        b->commit_sync();
    }

    bool intent_reconcile(u64 c, ChainRecovery& cr) {
        std::vector<std::pair<std::string, IntentRec>> intents;
        std::string bad_key, bad_detail; bool bad = false;
        bool iter_ok = m_store.for_each_prefix(p_intent(c), [&](const std::string& k, const std::string& val) {
            auto id = persist::decode_intent(val);
            if (!id) { bad = true; bad_key = k; bad_detail = "intent decode failed"; return false; }
            intents.emplace_back(k, *id);
            return true;
        });
        if (!iter_ok && !bad) { cr.fails.push_back({c, "intent_iter", p_intent(c), "for_each_prefix returned false"}); return false; }
        if (bad) { cr.fails.push_back({c, "intent_bad", bad_key, bad_detail}); return false; }

        for (auto& [k, id] : intents) {
            if (cr.ledger->is_pending(id.bid) || cr.ledger->is_settled(id.bid)) { drop_intent(k); continue; }
            auto rd = m_hooks.try_rederive_intent(id);
            if (rd) {
                cr.ledger->on_block_found(rd->blk.bid, rd->credit, rd->payout);
                u64 seq = cr.ledger->ledger_seq();
                EventRec ev; ev.evkind = EV_FOUND; ev.seq = seq; ev.bid = rd->blk.bid;
                ev.bin_height = rd->bin_height; ev.credit = rd->credit; ev.payout = rd->payout;
                cr.hw.ledger_seq = seq; cr.lhead.ledger_seq = seq; cr.lhead.owed_digest = cr.ledger->owed_digest();
                rd->blk.boot_id = m_boot_id;
                auto b = m_store.batch();
                b->put("v37s:levt:" + ten(c) + ":" + twenty(seq), persist::encode_event(ev));
                b->put(p_lhead(c), persist::encode_lhead(cr.lhead));
                b->put(p_hw(c), persist::encode_hw(static_cast<::v37::ChainId>(c), m_boot_id, cr.hw));
                b->put(p_blk(c) + rd->blk.bid, persist::encode_blk(rd->blk));
                b->remove(k);
                b->commit_sync();
            } else {
                drop_intent(k);
            }
        }
        return true;
    }
    void drop_intent(const std::string& intent_key) {
        auto b = m_store.batch();
        b->remove(intent_key);                           // removes a v37s:intent key ONLY (§6.5)
        b->commit_sync();
    }

    ISettleStore& m_store;
    RecoveryHooks m_hooks;
    u64 m_boot_id = 0;
};

}  // namespace c2pool::v37n::recover


// ═════════════════════════════════════════════════════════════════════════
// (9) LevelDBSettleStore — the ONE concrete LevelDB binding of ISettleStore.
//     ISOLATED behind W6_ENABLE_LEVELDB: this is the only place that includes
//     <core/leveldb_store.hpp>, so a stdlib test TU never pulls leveldb in
//     (spec §2.2, §3.1, §6.5). Opens one core::LevelDBStore at
//     config_path()/<net>/v37_settle_db with sync_writes=true, paranoid_checks=
//     true, verify_checksums=true; every batch ends commit_sync(), never
//     commit(). Meta boot_id++ is bumped ONCE at open (RecoveryDriver, above,
//     does the §4.1 census/replay — this class does not double-bump).
// ═════════════════════════════════════════════════════════════════════════
#if defined(W6_ENABLE_LEVELDB)
#include <chrono>
#include <core/leveldb_store.hpp>

namespace c2pool::v37n::persist {

// core::LevelDBStore::BatchWriter is non-movable (it owns unique_ptr<WriteBatch>
// + a user dtor), so it can only live as a commit-time local (a guaranteed-
// elided prvalue from create_batch()). This batch buffers put/remove ops and
// materialises ONE BatchWriter at commit_sync() — one WriteBatch = one atomic
// settlement event (§3.1).
class LevelDBSettleBatch final : public ISettleBatch {
public:
    explicit LevelDBSettleBatch(core::LevelDBStore* store) : m_store(store) {}
    void put(const std::string& k, const std::string& v) override {
        m_ops.push_back(Op{false, k, std::vector<std::uint8_t>(v.begin(), v.end())});
    }
    void remove(const std::string& k) override { m_ops.push_back(Op{true, k, {}}); }
    bool commit_sync() override {                        // NEVER commit()
        auto w = m_store->create_batch();                // local (guaranteed-elided prvalue)
        for (const auto& op : m_ops) {
            if (op.is_remove) w.remove(op.key); else w.put(op.key, op.val);
        }
        return w.commit_sync();
    }
private:
    struct Op { bool is_remove; std::string key; std::vector<std::uint8_t> val; };
    core::LevelDBStore* m_store;
    std::vector<Op> m_ops;
};

class LevelDBSettleStore final : public ISettleStore {
public:
    LevelDBSettleStore(const std::string& config_path, const std::string& net)
        : m_path(config_path + "/" + net + "/v37_settle_db"),
          m_db(m_path, core::LevelDBOptions{
                            /*write_buffer_size*/ 4 * 1024 * 1024,
                            /*max_open_files*/ 1000,
                            /*block_size*/ 4 * 1024,
                            /*block_cache_size*/ 8 * 1024 * 1024,
                            /*bloom_filter_bits*/ 10,
                            /*use_compression*/ true,
                            /*sync_writes*/ true,        // §2.2
                            /*verify_checksums*/ true,   // §2.2
                            /*paranoid_checks*/ true}) {} // §2.2

    // Open the core store + bump/fsync the meta boot_id ONCE. Returns the boot_id
    // (0 on failure). RecoveryDriver then runs the §4.1 census/replay over this
    // store; it does NOT bump meta again (single-bump keeps RS-5 monotone-by-1).
    std::optional<u64> open() {
        if (!m_db.open()) return std::nullopt;
        MetaRec meta;
        if (auto v = get(keys::meta())) {
            auto m = decode_meta(*v);
            if (!m) return std::nullopt;                 // corrupt meta → fail-closed
            meta = *m;
        } else {
            meta.created_ts = now_s();
        }
        meta.boot_id += 1; meta.last_open_ts = now_s();
        auto b = batch();
        b->put(keys::meta(), encode_meta(meta));
        if (!b->commit_sync()) return std::nullopt;
        return meta.boot_id;
    }
    void close() { m_db.close(); }

    std::unique_ptr<ISettleBatch> batch() override { return std::make_unique<LevelDBSettleBatch>(&m_db); }
    std::optional<std::string> get(const std::string& k) override {
        std::vector<std::uint8_t> v;
        if (!m_db.get(k, v)) return std::nullopt;
        return std::string(v.begin(), v.end());
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        // core::LevelDBStore::for_each_prefix is itself fail-closed (false on
        // iterator/IO error); forward that contract unchanged.
        return m_db.for_each_prefix(prefix, [&](const std::string& k, const std::vector<std::uint8_t>& v) -> bool {
            return fn(k, std::string(v.begin(), v.end()));
        });
    }
    const std::string& path() const { return m_path; }

private:
    static std::uint64_t now_s() {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }
    std::string m_path;
    core::LevelDBStore m_db;
};

}  // namespace c2pool::v37n::persist
#endif  // W6_ENABLE_LEVELDB
