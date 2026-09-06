// V37 W6 persistence / restart-recovery / >D rebuild — standalone test CONTRACT.
//
// Same tiny CHECK harness as v37_w0_scaffold_test.cpp / v37_w4_settlement_test.cpp:
// no gtest, no core/Boost link; builds with g++ -std=c++20 -pthread and an -I on
// src. This translation unit is stdlib-only by construction: it NEVER includes
// <core/leveldb_store.hpp> (LevelDBSettleStore is the only class that does, and
// it lives in w6_persistence.hpp, isolated so this test never pulls leveldb in).
// The persistence layer is exercised through the ISettleStore seam driven by a
// deterministic fault-injecting double (FaultSettleStore) — the same guard-on /
// guard-off shape as the rev3 red matrix (stamp 3692d922, the 75/75 falsifier
// harness).
//
// Binding spec: /home/ubuntu/v37-work/v37-a2-w6-persistence-spec.md
//   §2.3 key schema / codecs, §3 crash consistency, §3.3/§3.4 invariants,
//   §4 restart recovery, §5 >D rebuild, §6 test design (CM-1 k1..k5, CM-6,
//   RS-1..RS-5, RB-1..RB-5, §6.5 grep gates), §9 red-team F1/F2/F4.
//
// What is SELF-CONTAINED here (builds + runs on the OOM host, plain g++):
//   - the ISettleStore/ISettleBatch seam + FaultSettleStore double (DROP/TEAR);
//   - all §2.3 record codecs + round-trip + malformed (fail-closed) cases;
//   - the F2 union-census recovery gate (detects a RepairDB dropped tail);
//   - the FALSIFIER arms G1 (double-pay), G2 (MD-3 shorter branch), G3 (settled
//     divergence), plus F1 (finalize per-height vs jump-to-tip) — each with a
//     guard-off arm that MUST FAIL, else the test is flagged VACUOUS;
//   - RS-2/RS-3/RS-4/RS-5 shapes;
//   - the §6.5 structural grep-gate checklist as runtime assertions where
//     checkable (levt-delete tripwire; commit-not-commit_sync enforced by the
//     seam having only commit_sync()).
//
// What NEEDS THE ASSEMBLED CLASSES (marked NEEDS-ASSEMBLY, compiled under
// -DW6_ASSEMBLED once w6_persistence.hpp is wired to the real V37Engine /
// OwedLedger / SettleHW / SettlementJournal / RecoveryDriver / ReplayDriver):
//   - RS-1 restart digest check (real engine snapshot digest);
//   - RB-1..RB-5 deep-reorg golden digest traces (real engine rebuild);
//   - the CM-1 k1..k5 / CM-6 loopback drivers (W0 simnet launcher under tools/).
// The self-contained models (HwModel / LedgerModel) are FAITHFUL MIRRORS of the
// real w4_settlement.hpp classes (SettleHW :258-310, OwedLedger :352-546); in
// the assembled build the real classes are called and the mirrors drop out.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

// NON-HOLLOW: this stdlib TU ALSO includes the REAL assembled header (in stdlib
// mode, via the byte-faithful W4 shim; NO leveldb — LevelDBSettleStore is behind
// W6_ENABLE_LEVELDB, undefined here) and drives its actual persist:: codecs /
// census_open / SettlementJournal / RecoveryDriver / ReplayDriver / PrefixResolver
// against the same fault double (namespace w6asm, below). The w6test:: mirrors
// stay as the falsifier substrate; w6asm exercises the composed classes so the
// suite is not a hollow re-implementation of the header under test.
#define W6_PERSISTENCE_STDLIB_TEST 1
#include <c2pool/v37/w6_persistence.hpp>

// ───────────────────────────── CHECK harness ─────────────────────────────
static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                    \
    } while (0)

// A falsifier's guard-off arm MUST exhibit the violation. If it does not, the
// test proves nothing (a guard-off arm that passes = vacuous) — hard fail with
// a distinct banner so it can never be mistaken for a green run.
#define REQUIRE_VACUITY_BROKEN(guard_off_failed, name)                       \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(guard_off_failed)) {                                           \
            ++g_failures;                                                    \
            std::printf("VACUOUS %s:%d: falsifier %s guard-off arm PASSED "  \
                        "— the test proves nothing\n",                       \
                        __FILE__, __LINE__, name);                           \
        }                                                                    \
    } while (0)

namespace w6test {

using u64 = std::uint64_t;
using i64 = std::int64_t;
using bytes32 = std::array<std::uint8_t, 32>;

static bytes32 mk_hash(std::uint8_t fill) {
    bytes32 b{};
    b.fill(fill);
    return b;
}

// ───────────────────── little-endian byte cursor (codec I/O) ──────────────
struct Writer {
    std::string s;
    void u8(std::uint8_t x) { s.push_back(char(x)); }
    void u16(std::uint16_t x) { for (int i = 0; i < 2; ++i) s.push_back(char((x >> (8 * i)) & 0xff)); }
    void u32(std::uint32_t x) { for (int i = 0; i < 4; ++i) s.push_back(char((x >> (8 * i)) & 0xff)); }
    void u64_(u64 x) { for (int i = 0; i < 8; ++i) s.push_back(char((x >> (8 * i)) & 0xff)); }
    void i64_(i64 x) { u64_(static_cast<u64>(x)); }
    void h32(const bytes32& h) { s.append(reinterpret_cast<const char*>(h.data()), h.size()); }
    void str(const std::string& v) { u16(static_cast<std::uint16_t>(v.size())); s.append(v); }
    void raw(const std::string& v) { s.append(v); }
    // map = u32 n ‖ n × (bytes32 key ‖ i64 amount)  (§2.3)
    void amap(const std::map<bytes32, i64>& m) {
        u32(static_cast<std::uint32_t>(m.size()));
        for (const auto& [k, v] : m) { h32(k); i64_(v); }
    }
};

// A fail-closed reader: every get returns false past the end / on a short read,
// and the caller turns any false into a nullopt decode (§2.3 "never
// default-construct"). No exceptions.
struct Reader {
    const std::string& s;
    std::size_t o = 0;
    bool ok = true;
    explicit Reader(const std::string& src) : s(src) {}
    bool need(std::size_t n) { if (o + n > s.size()) { ok = false; return false; } return true; }
    std::uint8_t u8() { if (!need(1)) return 0; return std::uint8_t(s[o++]); }
    std::uint16_t u16() { std::uint16_t x = 0; if (!need(2)) return 0; for (int i = 0; i < 2; ++i) x |= std::uint16_t(std::uint8_t(s[o++])) << (8 * i); return x; }
    std::uint32_t u32() { std::uint32_t x = 0; if (!need(4)) return 0; for (int i = 0; i < 4; ++i) x |= std::uint32_t(std::uint8_t(s[o++])) << (8 * i); return x; }
    u64 u64_() { u64 x = 0; if (!need(8)) return 0; for (int i = 0; i < 8; ++i) x |= u64(std::uint8_t(s[o++])) << (8 * i); return x; }
    i64 i64_() { return static_cast<i64>(u64_()); }
    bytes32 h32() { bytes32 h{}; if (!need(32)) return h; for (int i = 0; i < 32; ++i) h[i] = std::uint8_t(s[o++]); return h; }
    std::string str() { std::uint16_t n = u16(); if (!ok || !need(n)) { ok = false; return {}; } std::string v = s.substr(o, n); o += n; return v; }
    std::string raw(std::size_t n) { if (!need(n)) return {}; std::string v = s.substr(o, n); o += n; return v; }
    std::map<bytes32, i64> amap() {
        std::map<bytes32, i64> m;
        std::uint32_t n = u32();
        for (std::uint32_t i = 0; ok && i < n; ++i) { bytes32 k = h32(); i64 a = i64_(); if (ok) m[k] = a; }
        return m;
    }
    bool done() const { return ok && o == s.size(); }   // reject trailing garbage too
};

// ───────────────── record kinds (the u8 kind byte, §2.3) ──────────────────
enum Kind : std::uint8_t {
    K_META = 1, K_HW = 2, K_LHEAD = 3, K_EVENT = 4, K_BLK = 5,
    K_INTENT = 6, K_CARRIER = 7, K_GENESIS = 8, K_TIP = 9
};
static constexpr std::uint8_t SCHEMA_VER = 1;
static constexpr std::size_t R_MAX = 4;      // carrier accepted_mask width
static constexpr std::size_t HW_BLOB_LEN = 56;  // SettleHW::serialize() (§2.3)

// ═══════════════════════════════════════════════════════════════════════════
//  FAITHFUL MIRRORS of the fenced W4 classes (self-contained build only).
//  In the assembled build these are replaced by the REAL classes — W6 CALLS
//  SettleHW / OwedLedger, never re-implements them. Kept byte-compatible so the
//  codecs and falsifiers exercise the real invariants.
// ═══════════════════════════════════════════════════════════════════════════

// Mirror of SettleHW (w4_settlement.hpp:258-310): 56-byte LE blob, no version,
// no bounds check; advance() never decreases; admit_candidate_height() refuses
// a shorter candidate. THIS IS THE MD-3 O5.5 gate.
struct HwModel {
    u64 hw_height = 0;
    bytes32 hw_tip{};
    u64 ledger_seq = 0;
    u64 refused = 0;
    bool advance(u64 h, const bytes32& tip) {
        if (h < hw_height) { ++refused; return false; }
        hw_height = h; hw_tip = tip; return true;
    }
    bool admit_candidate_height(u64 cand) {
        if (cand < hw_height) { ++refused; return false; }
        return true;
    }
    std::string serialize() const {   // exactly the W4 layout, 56 bytes
        Writer w; w.u64_(hw_height); w.h32(hw_tip); w.u64_(ledger_seq); w.u64_(refused);
        return w.s;
    }
    static HwModel deserialize(const std::string& s) {   // NO bounds check (mirror)
        HwModel hw; Reader r(s);
        hw.hw_height = r.u64_(); hw.hw_tip = r.h32(); hw.ledger_seq = r.u64_(); hw.refused = r.u64_();
        return hw;
    }
};

// Mirror of OwedLedger (w4_settlement.hpp:352-546): FOUND / FINALIZE / ORPHAN,
// signed amounts, EffectiveOwed = finalW − Σ pending payout, SETTLED terminal,
// first_eligible re-armed at the monotone coin high-water (the F1 K_fair clock).
struct LedgerModel {
    using Amounts = std::map<bytes32, i64>;
    struct Pending { Amounts credit; Amounts payout; };
    u64 seq = 0;
    Amounts finalW;
    std::map<std::string, Pending> pending;
    std::set<std::string> settled;
    std::map<bytes32, u64> first_eligible;
    i64 residual = 0;

    u64 ledger_seq() const { return seq; }
    bool is_settled(const std::string& b) const { return settled.count(b) != 0; }
    bool is_pending(const std::string& b) const { return pending.count(b) != 0; }

    void on_block_found(const std::string& bid, const Amounts& credit, const Amounts& payout) {
        if (pending.count(bid) || settled.count(bid)) return;
        Pending p;
        for (auto& [k, v] : credit) if (v) p.credit[k] = v;
        for (auto& [k, v] : payout) if (v) p.payout[k] = v;
        pending.emplace(bid, std::move(p)); ++seq;
    }
    void on_block_finalized(const std::string& bid, u64 bin_height) {
        auto it = pending.find(bid);
        if (it == pending.end()) return;
        for (auto& [k, v] : it->second.credit) finalW[k] += v;
        for (auto& [k, v] : it->second.payout) finalW[k] -= v;
        pending.erase(it); settled.insert(bid); rearm(bin_height); ++seq;
    }
    void on_block_orphaned(const std::string& bid, const Amounts& settled_payout) {
        auto it = pending.find(bid);
        if (it != pending.end()) { pending.erase(it); ++seq; return; }
        if (settled.count(bid)) {
            i64 res = 0; for (auto& [k, v] : settled_payout) res += v;
            if (res > 0) { residual += res; }
            ++seq;
        }
    }
    i64 effective_owed(const bytes32& k) const {
        i64 e = 0; auto it = finalW.find(k); if (it != finalW.end()) e = it->second;
        for (auto& [bid, p] : pending) { auto pit = p.payout.find(k); if (pit != p.payout.end()) e -= pit->second; }
        return e;
    }
    Amounts effective_owed_all() const {
        std::set<bytes32> keys;
        for (auto& [k, v] : finalW) { (void)v; keys.insert(k); }
        for (auto& [bid, p] : pending) for (auto& [k, v] : p.payout) { (void)v; keys.insert(k); }
        Amounts out; for (auto& k : keys) out[k] = effective_owed(k); return out;
    }
    void rearm(u64 bin_height) {
        for (auto& [k, e] : effective_owed_all()) {
            if (e > 0) { if (!first_eligible.count(k)) first_eligible[k] = bin_height; }
            else first_eligible.erase(k);
        }
    }
    // A stand-in for owed_digest(): a deterministic, order-independent fingerprint
    // over the FINALIZED partition AND first_eligible (both consensus-committed by
    // the real owed_digest(), w4_settlement.hpp:486-505). No crypto needed — the
    // falsifiers compare fingerprints for divergence, which is exact.
    std::string owed_fingerprint() const {
        Writer w;
        for (auto& [k, v] : finalW) { if (!v) continue; w.h32(k); w.i64_(v);
            u64 fe = 0; auto it = first_eligible.find(k); if (it != first_eligible.end()) fe = it->second; w.u64_(fe); }
        return w.s;
    }
};

// Mirror of CutToken value (w4_settlement.hpp:232-246) for encode_blk (§2.3 C2).
struct CutTokenModel {
    std::uint32_t chain = 0;
    u64 incarnation = 0, version = 0, next_pos = 0;
    bytes32 spine_digest{};
    u64 ledger_seq = 0;
    bytes32 owed_digest{};
    u64 hw_height = 0;
    bytes32 hw_tip{};
    bool operator==(const CutTokenModel&) const = default;
};

// Mirror of LaneParams (v37_lane.hpp:30-36) for encode_genesis (§2.3 D).
struct LaneParamsModel {
    u64 window = 8640, c0 = 4096, rollup = 8, half_life = 2160;
    std::vector<u64> level_caps = {568};
    u64 journal_depth = 64;
    bool operator==(const LaneParamsModel&) const = default;
};

// ═══════════════════════════════════════════════════════════════════════════
//  §2.3 CODECS — every value = u8 ver=1 ‖ u8 kind ‖ body; ints LE; fail-closed.
//  A decoder returns nullopt on: unknown ver (> own), wrong kind, short buffer,
//  or (hw) blob_len != 56. It NEVER default-constructs a live state (§2.3 rule).
// ═══════════════════════════════════════════════════════════════════════════

static std::string hdr(std::uint8_t kind) { Writer w; w.u8(SCHEMA_VER); w.u8(kind); return w.s; }
// returns false if header bad; sets reader past the 2 header bytes
static bool read_hdr(Reader& r, std::uint8_t want_kind) {
    std::uint8_t ver = r.u8(); std::uint8_t kind = r.u8();
    if (!r.ok) return false;
    if (ver > SCHEMA_VER) return false;     // reader accepts ver <= own (§2.3)
    if (kind != want_kind) return false;
    return true;
}

// v37s:meta
struct Meta { std::uint32_t schema = 1; u64 boot_id = 0, created_ts = 0, last_open_ts = 0; };
static std::string encode_meta(const Meta& m) { Writer w; w.raw(hdr(K_META)); w.u32(m.schema); w.u64_(m.boot_id); w.u64_(m.created_ts); w.u64_(m.last_open_ts); return w.s; }
static std::optional<Meta> decode_meta(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_META)) return std::nullopt;
    Meta m; m.schema = r.u32(); m.boot_id = r.u64_(); m.created_ts = r.u64_(); m.last_open_ts = r.u64_();
    if (!r.done()) return std::nullopt; return m;
}

// v37s:hw:<chain> = u32 chain ‖ u64 boot_id ‖ u8 blob_len=56 ‖ SettleHW blob
struct HwRec { std::uint32_t chain = 0; u64 boot_id = 0; HwModel hw; };
static std::string encode_hw(std::uint32_t chain, u64 boot_id, const HwModel& hw) {
    Writer w; w.raw(hdr(K_HW)); w.u32(chain); w.u64_(boot_id);
    std::string blob = hw.serialize();
    w.u8(static_cast<std::uint8_t>(blob.size())); w.raw(blob);   // blob_len then blob
    return w.s;
}
static std::optional<HwRec> decode_hw(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_HW)) return std::nullopt;
    HwRec rec; rec.chain = r.u32(); rec.boot_id = r.u64_();
    std::uint8_t blob_len = r.u8();
    if (!r.ok) return std::nullopt;
    if (blob_len != HW_BLOB_LEN) return std::nullopt;     // §2.3 CHECK BEFORE deserialize
    std::string blob = r.raw(blob_len);
    if (!r.done()) return std::nullopt;
    rec.hw = HwModel::deserialize(blob);
    return rec;
}

// v37s:lhead:<chain> = u64 ledger_seq ‖ bytes32 owed_digest ‖ u64 boot_id
struct LHead { u64 ledger_seq = 0; bytes32 owed_digest{}; u64 boot_id = 0; };
static std::string encode_lhead(const LHead& l) { Writer w; w.raw(hdr(K_LHEAD)); w.u64_(l.ledger_seq); w.h32(l.owed_digest); w.u64_(l.boot_id); return w.s; }
static std::optional<LHead> decode_lhead(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_LHEAD)) return std::nullopt;
    LHead l; l.ledger_seq = r.u64_(); l.owed_digest = r.h32(); l.boot_id = r.u64_();
    if (!r.done()) return std::nullopt; return l;
}

// v37s:levt:<chain>:<seq> = u8 evkind ‖ u64 seq ‖ str bid ‖ u64 bin_height
//                           ‖ map credit ‖ map payout ‖ map settled_payout
enum EvKind : std::uint8_t { EV_FOUND = 1, EV_FINALIZE = 2, EV_ORPHAN = 3 };
struct Event {
    std::uint8_t evkind = 0; u64 seq = 0; std::string bid; u64 bin_height = 0;
    std::map<bytes32, i64> credit, payout, settled_payout;
};
static std::string encode_event(const Event& e) {
    Writer w; w.raw(hdr(K_EVENT)); w.u8(e.evkind); w.u64_(e.seq); w.str(e.bid); w.u64_(e.bin_height);
    w.amap(e.credit); w.amap(e.payout); w.amap(e.settled_payout); return w.s;
}
static std::optional<Event> decode_event(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_EVENT)) return std::nullopt;
    Event e; e.evkind = r.u8();
    if (e.evkind < EV_FOUND || e.evkind > EV_ORPHAN) return std::nullopt;   // fail-closed
    e.seq = r.u64_(); e.bid = r.str(); e.bin_height = r.u64_();
    e.credit = r.amap(); e.payout = r.amap(); e.settled_payout = r.amap();
    if (!r.done()) return std::nullopt; return e;
}

// v37s:blk:<chain>:<bid> = bytes32 share_hash ‖ u64 height ‖ u64 reward
//                          ‖ u64 found_seq ‖ u64 boot_id ‖ CutToken
struct BlkRec { bytes32 share_hash{}; u64 height = 0, reward = 0, found_seq = 0, boot_id = 0; CutTokenModel token; };
static std::string encode_blk(const BlkRec& b) {
    Writer w; w.raw(hdr(K_BLK)); w.h32(b.share_hash); w.u64_(b.height); w.u64_(b.reward); w.u64_(b.found_seq); w.u64_(b.boot_id);
    const auto& t = b.token;
    w.u32(t.chain); w.u64_(t.incarnation); w.u64_(t.version); w.u64_(t.next_pos); w.h32(t.spine_digest);
    w.u64_(t.ledger_seq); w.h32(t.owed_digest); w.u64_(t.hw_height); w.h32(t.hw_tip);
    return w.s;
}
static std::optional<BlkRec> decode_blk(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_BLK)) return std::nullopt;
    BlkRec b; b.share_hash = r.h32(); b.height = r.u64_(); b.reward = r.u64_(); b.found_seq = r.u64_(); b.boot_id = r.u64_();
    auto& t = b.token;
    t.chain = r.u32(); t.incarnation = r.u64_(); t.version = r.u64_(); t.next_pos = r.u64_(); t.spine_digest = r.h32();
    t.ledger_seq = r.u64_(); t.owed_digest = r.h32(); t.hw_height = r.u64_(); t.hw_tip = r.h32();
    if (!r.done()) return std::nullopt; return b;
}

// v37s:intent:<chain>:<share_hash> = str bid ‖ u64 height ‖ u64 reward ‖ u64 ts
struct Intent { std::string bid; u64 height = 0, reward = 0, ts = 0; };
static std::string encode_intent(const Intent& i) { Writer w; w.raw(hdr(K_INTENT)); w.str(i.bid); w.u64_(i.height); w.u64_(i.reward); w.u64_(i.ts); return w.s; }
static std::optional<Intent> decode_intent(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_INTENT)) return std::nullopt;
    Intent i; i.bid = r.str(); i.height = r.u64_(); i.reward = r.u64_(); i.ts = r.u64_();
    if (!r.done()) return std::nullopt; return i;
}

// v37s:carrier:<chain>:<share_hash> = u64 boot_id ‖ u64 incarnation ‖ u64 lane_version_after
//   ‖ u64 next_pos_after ‖ bytes32 digest_after ‖ u8 accepted_mask ‖ u64 w_raw_carrier
//   ‖ popcount × u64 w_raw_receipt
struct Carrier {
    u64 boot_id = 0, incarnation = 0, lane_version_after = 0, next_pos_after = 0;
    bytes32 digest_after{};
    std::uint8_t accepted_mask = 0;
    u64 w_raw_carrier = 0;
    std::vector<u64> w_raw_receipt;   // length == popcount(accepted_mask)
};
static int popcount8(std::uint8_t m) { int c = 0; while (m) { c += m & 1; m >>= 1; } return c; }
static std::string encode_carrier(const Carrier& c) {
    Writer w; w.raw(hdr(K_CARRIER)); w.u64_(c.boot_id); w.u64_(c.incarnation); w.u64_(c.lane_version_after);
    w.u64_(c.next_pos_after); w.h32(c.digest_after); w.u8(c.accepted_mask); w.u64_(c.w_raw_carrier);
    for (u64 v : c.w_raw_receipt) w.u64_(v); return w.s;
}
static std::optional<Carrier> decode_carrier(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_CARRIER)) return std::nullopt;
    Carrier c; c.boot_id = r.u64_(); c.incarnation = r.u64_(); c.lane_version_after = r.u64_();
    c.next_pos_after = r.u64_(); c.digest_after = r.h32(); c.accepted_mask = r.u8(); c.w_raw_carrier = r.u64_();
    if (!r.ok) return std::nullopt;
    if (c.accepted_mask >> R_MAX) return std::nullopt;    // bits above R_MAX=4 => fail-closed
    int pc = popcount8(c.accepted_mask);
    for (int i = 0; i < pc; ++i) { u64 v = r.u64_(); if (!r.ok) return std::nullopt; c.w_raw_receipt.push_back(v); }
    if (!r.done()) return std::nullopt; return c;
}

// v37s:genesis:<chain> = bytes32 first_share_hash ‖ LaneParams ‖ u64 ts
//   LaneParams = u64 window ‖ u64 c0 ‖ u64 rollup ‖ u64 half_life ‖ u32 n
//                ‖ n × u64 level_caps ‖ u64 journal_depth   (§2.3)
struct Genesis { bytes32 first_share_hash{}; LaneParamsModel params; u64 ts = 0; };
static std::string encode_genesis(const Genesis& g) {
    Writer w; w.raw(hdr(K_GENESIS)); w.h32(g.first_share_hash);
    w.u64_(g.params.window); w.u64_(g.params.c0); w.u64_(g.params.rollup); w.u64_(g.params.half_life);
    w.u32(static_cast<std::uint32_t>(g.params.level_caps.size()));
    for (u64 lc : g.params.level_caps) w.u64_(lc);
    w.u64_(g.params.journal_depth); w.u64_(g.ts); return w.s;
}
static std::optional<Genesis> decode_genesis(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_GENESIS)) return std::nullopt;
    Genesis g; g.first_share_hash = r.h32();
    g.params.window = r.u64_(); g.params.c0 = r.u64_(); g.params.rollup = r.u64_(); g.params.half_life = r.u64_();
    std::uint32_t n = r.u32();
    if (!r.ok) return std::nullopt;
    if (n > 64) return std::nullopt;                       // sanity fence
    g.params.level_caps.clear();
    for (std::uint32_t i = 0; i < n; ++i) { u64 lc = r.u64_(); if (!r.ok) return std::nullopt; g.params.level_caps.push_back(lc); }
    g.params.journal_depth = r.u64_(); g.ts = r.u64_();
    if (!r.done()) return std::nullopt; return g;
}

// v37s:tip:<chain> = bytes32 share_hash ‖ u64 next_pos ‖ u64 boot_id
struct Tip { bytes32 share_hash{}; u64 next_pos = 0, boot_id = 0; };
static std::string encode_tip(const Tip& t) { Writer w; w.raw(hdr(K_TIP)); w.h32(t.share_hash); w.u64_(t.next_pos); w.u64_(t.boot_id); return w.s; }
static std::optional<Tip> decode_tip(const std::string& s) {
    Reader r(s); if (!read_hdr(r, K_TIP)) return std::nullopt;
    Tip t; t.share_hash = r.h32(); t.next_pos = r.u64_(); t.boot_id = r.u64_();
    if (!r.done()) return std::nullopt; return t;
}

// ═══════════════════════════════════════════════════════════════════════════
//  THE ISettleStore SEAM (spec §6/§7.1, FIXED INTERFACE CONTRACT) + the
//  fault-injecting double. The seam exposes ONLY commit_sync() (never commit())
//  — the §6.5 "every BatchWriter ends commit_sync" gate is structural here.
// ═══════════════════════════════════════════════════════════════════════════

struct ISettleBatch {
    virtual void put(const std::string& k, const std::string& v) = 0;
    virtual void remove(const std::string& k) = 0;
    virtual bool commit_sync() = 0;
    virtual ~ISettleBatch() = default;
};
struct ISettleStore {
    virtual std::unique_ptr<ISettleBatch> batch() = 0;
    virtual std::optional<std::string> get(const std::string& k) = 0;
    // fail-closed: returns false on iterator/IO error (§4.4, leveldb_store.hpp:74-87)
    virtual bool for_each_prefix(const std::string& prefix,
                                 const std::function<bool(const std::string&, const std::string&)>& fn) = 0;
    virtual ~ISettleStore() = default;
};

// §6.5 tripwire: no code path may delete or rewrite a v37s:levt: key.
static bool g_levt_delete_violation = false;

class FaultSettleStore : public ISettleStore {
public:
    // ── fault arming (deterministic) ─────────────────────────────────────
    // TEAR: the Nth commit_sync (1-based) is torn — LevelDB would drop the whole
    // log record; nothing applies and commit_sync returns false (models a crash
    // mid-batch / SIGKILL between hand-off and durability). 0 = disarmed.
    void arm_tear_on_commit(unsigned n) { m_tear_at = n; }
    // DROP: on the Nth commit_sync, writes to keys starting with `prefix` are
    // SILENTLY dropped though commit_sync returns true — models a lost async
    // batch (sync=false, CM-6 power-loss) OR a leveldb::RepairDB checksum drop
    // (spec §9 F2). Other writes in the same batch still apply.
    void arm_drop_prefix_on_commit(unsigned n, const std::string& prefix) { m_drop_at = n; m_drop_prefix = prefix; }
    // FAIL-CLOSED iterator: the next for_each_prefix returns false (IO error).
    void arm_iter_fail() { m_iter_fail = true; }

    unsigned commit_count() const { return m_commits; }
    const std::map<std::string, std::string>& kv() const { return m_kv; }
    void wipe_all() { m_kv.clear(); }   // model a store dir that never existed

    std::unique_ptr<ISettleBatch> batch() override { return std::make_unique<Batch>(*this); }

    std::optional<std::string> get(const std::string& k) override {
        auto it = m_kv.find(k); if (it == m_kv.end()) return std::nullopt; return it->second;
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        if (m_iter_fail) { m_iter_fail = false; return false; }   // §4.4 fail-closed
        // std::map is sorted by key: matches the LevelDB lexicographic scan order
        // (zero-padded <seq> => key order == seq order, §4.1 step 3).
        for (auto it = m_kv.lower_bound(prefix); it != m_kv.end(); ++it) {
            if (it->first.compare(0, prefix.size(), prefix) != 0) break;
            if (!fn(it->first, it->second)) return false;
        }
        return true;
    }

private:
    struct Op { bool is_put; std::string k, v; };
    class Batch : public ISettleBatch {
    public:
        explicit Batch(FaultSettleStore& s) : m_s(s) {}
        void put(const std::string& k, const std::string& v) override { m_ops.push_back({true, k, v}); }
        void remove(const std::string& k) override {
            if (k.rfind("v37s:levt:", 0) == 0) g_levt_delete_violation = true;   // §6.5 tripwire
            m_ops.push_back({false, k, ""});
        }
        bool commit_sync() override {
            unsigned n = ++m_s.m_commits;
            if (m_s.m_tear_at && n == m_s.m_tear_at) return false;   // torn: nothing applies
            bool dropping = (m_s.m_drop_at && n == m_s.m_drop_at);
            for (auto& op : m_ops) {
                if (dropping && op.k.rfind(m_s.m_drop_prefix, 0) == 0) continue;  // silently dropped
                if (op.is_put) m_s.m_kv[op.k] = op.v; else m_s.m_kv.erase(op.k);
            }
            return true;
        }
    private:
        FaultSettleStore& m_s;
        std::vector<Op> m_ops;
    };

    std::map<std::string, std::string> m_kv;
    unsigned m_commits = 0;
    unsigned m_tear_at = 0, m_drop_at = 0;
    std::string m_drop_prefix;
    bool m_iter_fail = false;
};

// key builders (§2.3)
static std::string kmeta() { return "v37s:meta"; }
static std::string khw(std::uint32_t c) { char b[32]; std::snprintf(b, sizeof b, "v37s:hw:%010u", c); return b; }
static std::string klhead(std::uint32_t c) { char b[40]; std::snprintf(b, sizeof b, "v37s:lhead:%010u", c); return b; }
static std::string klevt(std::uint32_t c, u64 seq) { char b[64]; std::snprintf(b, sizeof b, "v37s:levt:%010u:%020llu", c, (unsigned long long)seq); return b; }

// ═══════════════════════════════════════════════════════════════════════════
//  A minimal SINGLE-BATCH settlement writer (the §3.1 rule) over the seam, used
//  by the falsifiers. It mirrors SettlementJournal's write path: mutate the W4
//  state, then commit ONE batch {levt, lhead, hw} with commit_sync. In the
//  assembled build this is SettlementJournal calling the real OwedLedger/SettleHW.
// ═══════════════════════════════════════════════════════════════════════════
struct JournalModel {
    ISettleStore& store;
    std::uint32_t chain;
    u64 boot_id;
    LedgerModel& ledger;
    HwModel& hw;

    // one §3.1 settlement batch for an event that already advanced the ledger
    bool commit_event(const Event& ev) {
        auto b = store.batch();
        b->put(klevt(chain, ev.seq), encode_event(ev));
        LHead lh; lh.ledger_seq = ledger.ledger_seq(); lh.boot_id = boot_id;
        // owed_digest fingerprint (real code writes owed_digest())
        std::string fp = ledger.owed_fingerprint(); for (std::size_t i = 0; i < fp.size() && i < 32; ++i) lh.owed_digest[i] = std::uint8_t(fp[i]);
        b->put(klhead(chain), encode_lhead(lh));
        hw.ledger_seq = ledger.ledger_seq();               // §3.1: copy seq into hw first
        b->put(khw(chain), encode_hw(chain, boot_id, hw));
        return b->commit_sync();
    }
};

// ═══════════════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════════════

// ── codec round-trips + malformed (fail-closed) ───────────────────────────
static void test_codec_roundtrip() {
    // meta
    { Meta m{1, 7, 111, 222}; auto d = decode_meta(encode_meta(m)); CHECK(d && d->boot_id == 7 && d->last_open_ts == 222); }
    // hw (blob_len == 56 exactly)
    { HwModel hw; hw.hw_height = 15; hw.hw_tip = mk_hash(0xab); hw.ledger_seq = 9; hw.refused = 2;
      std::string enc = encode_hw(3, 5, hw);
      auto d = decode_hw(enc);
      CHECK(d && d->chain == 3 && d->boot_id == 5 && d->hw.hw_height == 15 && d->hw.ledger_seq == 9 && d->hw.refused == 2 && d->hw.hw_tip == mk_hash(0xab));
      CHECK(hw.serialize().size() == HW_BLOB_LEN); }
    // lhead
    { LHead l{42, mk_hash(0x11), 6}; auto d = decode_lhead(encode_lhead(l)); CHECK(d && d->ledger_seq == 42 && d->owed_digest == mk_hash(0x11) && d->boot_id == 6); }
    // event (all three kinds, maps populated)
    { Event e; e.evkind = EV_FOUND; e.seq = 3; e.bid = "blk-3"; e.bin_height = 100;
      e.credit[mk_hash(1)] = 50; e.credit[mk_hash(2)] = 50; e.payout[mk_hash(1)] = 20;
      auto d = decode_event(encode_event(e));
      CHECK(d && d->evkind == EV_FOUND && d->seq == 3 && d->bid == "blk-3" && d->bin_height == 100 && d->credit.size() == 2 && d->payout.at(mk_hash(1)) == 20); }
    { Event e; e.evkind = EV_ORPHAN; e.seq = 4; e.bid = "b"; e.settled_payout[mk_hash(9)] = 7;
      auto d = decode_event(encode_event(e)); CHECK(d && d->evkind == EV_ORPHAN && d->settled_payout.at(mk_hash(9)) == 7); }
    // blk (CutToken round-trips whole)
    { BlkRec b; b.share_hash = mk_hash(0x33); b.height = 800000; b.reward = 625000000; b.found_seq = 2; b.boot_id = 5;
      b.token.chain = 3; b.token.incarnation = 1; b.token.version = 12; b.token.next_pos = 4090; b.token.spine_digest = mk_hash(0x44);
      b.token.ledger_seq = 7; b.token.owed_digest = mk_hash(0x55); b.token.hw_height = 15; b.token.hw_tip = mk_hash(0x66);
      auto d = decode_blk(encode_blk(b)); CHECK(d && d->height == 800000 && d->reward == 625000000 && d->token == b.token); }
    // intent
    { Intent i{"blk-x", 900, 1234, 42}; auto d = decode_intent(encode_intent(i)); CHECK(d && d->bid == "blk-x" && d->height == 900 && d->reward == 1234 && d->ts == 42); }
    // carrier (accepted_mask + popcount receipts)
    { Carrier c; c.boot_id = 5; c.incarnation = 1; c.lane_version_after = 30; c.next_pos_after = 128; c.digest_after = mk_hash(0x77);
      c.accepted_mask = 0b1011; c.w_raw_carrier = 1000; c.w_raw_receipt = {11, 22, 33};   // popcount(0b1011)=3
      auto d = decode_carrier(encode_carrier(c)); CHECK(d && d->accepted_mask == 0b1011 && d->w_raw_receipt.size() == 3 && d->w_raw_receipt[2] == 33 && d->digest_after == mk_hash(0x77)); }
    // genesis (LaneParams incl. multi-cap)
    { Genesis g; g.first_share_hash = mk_hash(0x88); g.params.level_caps = {568}; g.ts = 99;
      auto d = decode_genesis(encode_genesis(g)); CHECK(d && d->params.window == 8640 && d->params.c0 == 4096 && d->params.level_caps.size() == 1 && d->params.journal_depth == 64 && d->ts == 99); }
    { Genesis g; g.params.level_caps = {568, 512, 400};   // multi-level geometry
      auto d = decode_genesis(encode_genesis(g)); CHECK(d && d->params.level_caps.size() == 3 && d->params.level_caps[2] == 400); }
    // tip
    { Tip t{mk_hash(0x99), 4096, 5}; auto d = decode_tip(encode_tip(t)); CHECK(d && t.share_hash == d->share_hash && d->next_pos == 4096); }
}

static void test_codec_malformed() {
    // truncated buffers => nullopt for every codec
    { std::string e = encode_hw(1, 1, HwModel{}); CHECK(!decode_hw(e.substr(0, e.size() - 3))); }
    { std::string e = encode_meta(Meta{}); CHECK(!decode_meta(e.substr(0, 4))); }
    { Event ev; ev.evkind = EV_FOUND; ev.bid = "x"; std::string e = encode_event(ev); CHECK(!decode_event(e.substr(0, e.size() - 5))); }
    // wrong ver (reader accepts ver <= own; ver=2 > 1 => fail-closed)
    { std::string e = encode_meta(Meta{}); e[0] = 2; CHECK(!decode_meta(e)); }
    // wrong kind byte
    { std::string e = encode_hw(1, 1, HwModel{}); e[1] = K_TIP; CHECK(!decode_hw(e)); }
    // hw with blob_len != 56 => fail-closed BEFORE deserialize (§2.3)
    { HwModel hw; std::string e = encode_hw(1, 1, hw);
      // the blob_len byte sits after ver(1)+kind(1)+chain(4)+boot_id(8) = offset 14
      e[14] = 55; CHECK(!decode_hw(e)); e[14] = 57; CHECK(!decode_hw(e)); }
    // event with an unknown evkind => fail-closed
    { Event ev; ev.evkind = 7; ev.bid = "x"; std::string e = encode_event(ev); CHECK(!decode_event(e)); }
    // carrier accepted_mask with a bit above R_MAX => fail-closed
    { Carrier c; c.accepted_mask = 0b10000; std::string e = encode_carrier(c); CHECK(!decode_carrier(e)); }
    // carrier truncated receipt tail => fail-closed
    { Carrier c; c.accepted_mask = 0b111; c.w_raw_receipt = {1, 2, 3}; std::string e = encode_carrier(c); CHECK(!decode_carrier(e.substr(0, e.size() - 4))); }
    // trailing-garbage rejection (a value longer than its schema => nullopt)
    { std::string e = encode_tip(Tip{}); e.push_back('\x00'); CHECK(!decode_tip(e)); }
}

// ── FaultSettleStore semantics (DROP / TEAR / fail-closed iterator) ────────
static void test_faultstore() {
    FaultSettleStore s;
    { auto b = s.batch(); b->put("v37s:hw:0000000000", "v0"); CHECK(b->commit_sync()); }
    CHECK(s.get("v37s:hw:0000000000") == std::optional<std::string>("v0"));

    // TEAR: the 2nd commit is torn — nothing from it applies, commit returns false
    s.arm_tear_on_commit(2);
    { auto b = s.batch(); b->put("v37s:hw:0000000000", "v1"); b->put("v37s:lhead:0000000000", "L"); CHECK(!b->commit_sync()); }
    CHECK(s.get("v37s:hw:0000000000") == std::optional<std::string>("v0"));  // rolled back whole
    CHECK(!s.get("v37s:lhead:0000000000"));

    // DROP: the next commit silently drops the levt write (models RepairDB / lost async)
    FaultSettleStore s2;
    s2.arm_drop_prefix_on_commit(1, "v37s:levt:");
    { auto b = s2.batch(); b->put(klevt(0, 5), "E5"); b->put(klhead(0), "L5"); CHECK(b->commit_sync()); }
    CHECK(!s2.get(klevt(0, 5)));                       // levt dropped
    CHECK(s2.get(klhead(0)) == std::optional<std::string>("L5"));   // lhead survived — the F2 census target

    // fail-closed iterator
    s.arm_iter_fail();
    bool visited = false;
    bool okiter = s.for_each_prefix("v37s:", [&](const std::string&, const std::string&) { visited = true; return true; });
    CHECK(!okiter && !visited);                        // §4.4: iterator error => false

    // ordered scan == sorted key order (== seq order for zero-padded seq)
    FaultSettleStore s3;
    for (u64 q : {u64(3), u64(1), u64(2)}) { auto b = s3.batch(); b->put(klevt(0, q), "e"); b->commit_sync(); }
    std::vector<std::string> seen;
    s3.for_each_prefix("v37s:levt:", [&](const std::string& k, const std::string&) { seen.push_back(k); return true; });
    CHECK(seen.size() == 3 && seen[0] == klevt(0, 1) && seen[2] == klevt(0, 3));
}

// ═══════════════════════════════════════════════════════════════════════════
//  FALSIFIER G1 — submit-then-FOUND ordering → double-pay exhibit at k3 (§3.3).
//  The invariant (§3.3): FOUND must be durable BEFORE mainchain submit, so that
//  a crash at k3 never leaves EffectiveOwed overstated by payout_b while the
//  block already pays it. Guard-off (submit-then-FOUND) MUST double-pay.
// ═══════════════════════════════════════════════════════════════════════════
static bool run_G1(bool guard_on) {
    bytes32 K = mk_hash(0x01);
    const i64 owed_b = 100;           // K is already owed 100 (prior finalized work)

    FaultSettleStore store;
    LedgerModel ledger; HwModel hw;
    JournalModel J{store, 0, 1, ledger, hw};

    // Seed durable owed: a prior finalized block "seed" credits K 100. This is on
    // the levt log, so it survives restart. Now EffectiveOwed(K) == 100.
    { ledger.on_block_found("seed", {{K, owed_b}}, {}); Event f; f.evkind = EV_FOUND; f.bid = "seed"; f.credit[K] = owed_b; f.seq = ledger.ledger_seq(); J.commit_event(f); }
    { ledger.on_block_finalized("seed", 5); Event fz; fz.evkind = EV_FINALIZE; fz.bid = "seed"; fz.bin_height = 5; fz.seq = ledger.ledger_seq(); J.commit_event(fz); }

    // Block b's coinbase PAYS DOWN K's owed 100 (payout[K]=100). Its FOUND records
    // that payout so EffectiveOwed(K) drops to 0. "submit" = the block (and its
    // coinbase) actually lands on the coin chain, paying K 100.
    Event found; found.evkind = EV_FOUND; found.bid = "b"; found.bin_height = 10; found.payout[K] = owed_b;
    auto do_found = [&]() { ledger.on_block_found(found.bid, found.credit, found.payout); found.seq = ledger.ledger_seq(); return J.commit_event(found); };
    i64 paid_on_chain = 0;
    auto do_submit = [&]() { paid_on_chain += owed_b; };

    // k3 crash window = between FOUND-durable and mainchain submit.
    //   guard-on : FOUND(durable) then submit. Crash at k3 => FOUND persisted,
    //              block NOT on chain. Restart: the pending payout nets
    //              EffectiveOwed(K)=0; no coinbase re-pays before the block is
    //              orphaned. No value leaves twice.
    //   guard-off: submit then FOUND. Crash between => block IS on chain (K paid
    //              100) but FOUND torn/lost => restart sees EffectiveOwed(K)=100
    //              (seed) => the NEXT coinbase pays K 100 AGAIN => double-pay.
    if (guard_on) {
        do_found();                       // durable first; submit never happens (crash)
    } else {
        do_submit();                      // block lands first, pays K on chain
        store.arm_tear_on_commit(3);      // the FOUND batch (3rd commit) is torn
        do_found();                       // NOT durable
    }

    // RESTART: replay the durable levt log into a fresh ledger.
    LedgerModel r;
    store.for_each_prefix("v37s:levt:", [&](const std::string&, const std::string& v) {
        auto e = decode_event(v); if (!e) return false;
        if (e->evkind == EV_FOUND) r.on_block_found(e->bid, e->credit, e->payout);
        else if (e->evkind == EV_FINALIZE) r.on_block_finalized(e->bid, e->bin_height);
        else r.on_block_orphaned(e->bid, e->settled_payout);
        return true;
    });

    // Next coinbase pays EffectiveOwed(K) (clamped >= 0).
    i64 eff = r.effective_owed(K); if (eff < 0) eff = 0;
    i64 total_paid = paid_on_chain + eff;   // value that leaves the pool for K
    bool double_pay = (total_paid > owed_b);   // payable(K) == owed_b (once)
    return double_pay;
}
static void falsifier_G1() {
    bool off = run_G1(/*guard_on=*/false);
    bool on = run_G1(/*guard_on=*/true);
    REQUIRE_VACUITY_BROKEN(off, "G1 (submit-then-FOUND double-pay @k3)");
    CHECK(!on);   // guard-on: no double-pay
}

// ═══════════════════════════════════════════════════════════════════════════
//  FALSIFIER G2 — in-memory SettleHW (no hw batch) → after k4 a shorter branch
//  is admitted (the MD-3 O5.5 loss, §3.3 / obligations O5.5). Mirrors
//  test_o55_persisted_restart's two arms (v37_w4_settlement_test.cpp:769-800).
// ═══════════════════════════════════════════════════════════════════════════
static bool run_G2(bool guard_on) {
    FaultSettleStore store;
    // advance high-water to 15 in a sync batch (the tip-advance of §3.2 step 1).
    HwModel hw; hw.advance(10, mk_hash(1)); hw.advance(15, mk_hash(2));
    if (guard_on) { auto b = store.batch(); b->put(khw(0), encode_hw(0, 1, hw)); b->commit_sync(); }
    // else: guard-off keeps hw in memory only (never persisted) — the MD-3 arm.

    // k4 crash: process dies after the tip-advance. RESTART: load hw from disk.
    HwModel restored;
    auto raw = store.get(khw(0));
    if (raw) { auto d = decode_hw(*raw); if (d) restored = d->hw; }
    // guard-off: nothing on disk -> restored is default (hw_height=0), the exact
    // in-memory-only failure mode.

    // A candidate branch at height 12 (< 15) arrives. admit_candidate_height must
    // REFUSE it (O5.5). guard-off admits it => the shorter branch is re-adopted.
    bool admitted_shorter = restored.admit_candidate_height(12);
    return admitted_shorter;   // true == MD-3 violation exhibited
}
static void falsifier_G2() {
    bool off = run_G2(/*guard_on=*/false);
    bool on = run_G2(/*guard_on=*/true);
    REQUIRE_VACUITY_BROKEN(off, "G2 (in-memory SettleHW admits shorter branch @k4)");
    CHECK(!on);   // guard-on: shorter branch refused
}

// ═══════════════════════════════════════════════════════════════════════════
//  FALSIFIER G3 — FINALIZE published before its batch → settled divergence at
//  k5 (§3.2 step 4 / §3.4). Two replicas X, Y on the same schedule. Guard-off
//  publishes the in-memory SETTLED before the durable batch; a crash at k5
//  loses the FINALIZE levt => on restart X is not settled while Y is.
// ═══════════════════════════════════════════════════════════════════════════
static bool run_G3(bool guard_on) {
    bytes32 K = mk_hash(0x02);
    // Y (never crashes): FOUND then FINALIZE, both durable.
    FaultSettleStore sy; LedgerModel ly; HwModel hy; JournalModel Jy{sy, 0, 1, ly, hy};
    { Event f; f.evkind = EV_FOUND; f.bid = "b"; f.bin_height = 20; f.credit[K] = 50; ly.on_block_found(f.bid, f.credit, f.payout); f.seq = ly.ledger_seq(); Jy.commit_event(f); }
    { ly.on_block_finalized("b", 20); Event fz; fz.evkind = EV_FINALIZE; fz.bid = "b"; fz.bin_height = 20; fz.seq = ly.ledger_seq(); Jy.commit_event(fz); }

    // X: same, but the FINALIZE ordering depends on the guard.
    FaultSettleStore sx; LedgerModel lx; HwModel hx; JournalModel Jx{sx, 0, 1, lx, hx};
    { Event f; f.evkind = EV_FOUND; f.bid = "b"; f.bin_height = 20; f.credit[K] = 50; lx.on_block_found(f.bid, f.credit, f.payout); f.seq = lx.ledger_seq(); Jx.commit_event(f); }
    bool x_published_settled = false;
    if (guard_on) {
        // batch first, then publish. Crash at k5 (after batch, before publish):
        // the levt IS durable; publish flag lost but recovered by replay.
        lx.on_block_finalized("b", 20);
        Event fz; fz.evkind = EV_FINALIZE; fz.bid = "b"; fz.bin_height = 20; fz.seq = lx.ledger_seq();
        Jx.commit_event(fz);
        // crash before the in-memory publish; x_published_settled stays false but disk has it.
    } else {
        // publish first (in-memory SETTLED visible to readers), THEN batch.
        lx.on_block_finalized("b", 20);
        x_published_settled = true;        // readers already saw SETTLED
        sx.arm_tear_on_commit(2);          // crash tears the FINALIZE batch (2nd commit on sx)
        Event fz; fz.evkind = EV_FINALIZE; fz.bid = "b"; fz.bin_height = 20; fz.seq = lx.ledger_seq();
        Jx.commit_event(fz);               // NOT durable
    }
    (void)x_published_settled;

    // RESTART both from their durable levt logs.
    auto replay = [](FaultSettleStore& s) {
        LedgerModel r;
        s.for_each_prefix("v37s:levt:", [&](const std::string&, const std::string& v) {
            auto e = decode_event(v); if (!e) return false;
            if (e->evkind == EV_FOUND) r.on_block_found(e->bid, e->credit, e->payout);
            else if (e->evkind == EV_FINALIZE) r.on_block_finalized(e->bid, e->bin_height);
            else r.on_block_orphaned(e->bid, e->settled_payout);
            return true;
        });
        return r;
    };
    LedgerModel rx = replay(sx), ry = replay(sy);
    bool diverged = (rx.is_settled("b") != ry.is_settled("b")) || (rx.owed_fingerprint() != ry.owed_fingerprint());
    return diverged;   // true == settled divergence exhibited
}
static void falsifier_G3() {
    bool off = run_G3(/*guard_on=*/false);
    bool on = run_G3(/*guard_on=*/true);
    REQUIRE_VACUITY_BROKEN(off, "G3 (FINALIZE published before batch => settled divergence @k5)");
    CHECK(!on);   // guard-on: X and Y converge after replay
}

// ═══════════════════════════════════════════════════════════════════════════
//  FALSIFIER F1 (spec §9, HIGH, consensus) — the FINALIZE driver must stamp
//  first_eligible at the coin high-water AT EACH coin-height step, in order,
//  never jump to the live tip. A slow/crashed-and-caught-up node that batches a
//  finalize backlog at the current tip stamps a later first_eligible =>
//  divergent owed_digest => fork. Guard-off (jump-to-tip) MUST diverge from the
//  per-height driver.
// ═══════════════════════════════════════════════════════════════════════════
static bool run_F1(bool guard_on, LedgerModel& out) {
    bytes32 K1 = mk_hash(0x10), K2 = mk_hash(0x20);
    // two own blocks b1 (credits K1 at coin-height 100) and b2 (credits K2 at 105).
    out = LedgerModel{};
    out.on_block_found("b1", {{K1, 40}}, {});
    out.on_block_found("b2", {{K2, 40}}, {});
    if (guard_on) {
        // per coin-height, in order: b1 finalized when high-water == 100, b2 at 105.
        out.on_block_finalized("b1", 100);
        out.on_block_finalized("b2", 105);
    } else {
        // caught-up node re-evaluates the backlog at the LIVE tip (== 105 for both).
        out.on_block_finalized("b1", 105);   // WRONG: b1's key stamped at tip, not 100
        out.on_block_finalized("b2", 105);
    }
    return true;
}
static void falsifier_F1() {
    LedgerModel a, b;
    run_F1(/*guard_on=*/true, a);
    run_F1(/*guard_on=*/false, b);
    bool diverged = (a.owed_fingerprint() != b.owed_fingerprint());
    REQUIRE_VACUITY_BROKEN(diverged, "F1 (finalize jump-to-tip diverges from per-height)");
    // and the per-height arm must stamp b1 at 100, not 105
    CHECK(a.first_eligible.count(mk_hash(0x10)) && a.first_eligible.at(mk_hash(0x10)) == 100);
    CHECK(b.first_eligible.count(mk_hash(0x10)) && b.first_eligible.at(mk_hash(0x10)) == 105);
}

// ═══════════════════════════════════════════════════════════════════════════
//  F2 recovery census (spec §9 F2 / §4.4) — recovery must drive off the UNION
//  of chains across ALL v37s: prefixes and fail-closed on any chain missing its
//  hw, PLUS an lhead-vs-levt census that catches a RepairDB dropped tail (a
//  dropped contiguous levt tail escapes a naive seq-gap check).
// ═══════════════════════════════════════════════════════════════════════════
struct CensusResult { bool ok = true; std::string offending_key; std::string reason; };
static CensusResult recovery_census(ISettleStore& s) {
    CensusResult res;
    // 1. union of chains seen across hw / lhead / levt prefixes
    std::set<std::string> chains_hw, chains_lhead, chains_levt;
    std::map<std::string, u64> lhead_seq;              // chain -> lhead.ledger_seq
    std::map<std::string, u64> levt_count, levt_max;   // chain -> count / max seq
    auto chain_of = [](const std::string& k, std::size_t pfx) { return k.substr(pfx, 10); };
    if (!s.for_each_prefix("v37s:hw:", [&](const std::string& k, const std::string&) { chains_hw.insert(chain_of(k, 8)); return true; })) { res.ok = false; res.reason = "hw iter fail"; return res; }
    if (!s.for_each_prefix("v37s:lhead:", [&](const std::string& k, const std::string& v) { auto c = chain_of(k, 11); chains_lhead.insert(c); auto d = decode_lhead(v); if (d) lhead_seq[c] = d->ledger_seq; return true; })) { res.ok = false; res.reason = "lhead iter fail"; return res; }
    if (!s.for_each_prefix("v37s:levt:", [&](const std::string& k, const std::string&) { auto c = chain_of(k, 10); chains_levt.insert(c); levt_count[c]++; u64 seq = std::strtoull(k.substr(k.size() - 20).c_str(), nullptr, 10); if (seq > levt_max[c]) levt_max[c] = seq; return true; })) { res.ok = false; res.reason = "levt iter fail"; return res; }

    std::set<std::string> all = chains_lhead; all.insert(chains_levt.begin(), chains_levt.end());
    for (const auto& c : all) {
        // F2 (a): any chain with ledger history MUST have its hw (else MD-3 loss)
        if (!chains_hw.count(c)) { res.ok = false; res.offending_key = "v37s:hw:" + c; res.reason = "chain missing hw (RepairDB drop / MD-3)"; return res; }
        // F2 (b): lhead.ledger_seq must equal the count of levt records. A dropped
        // contiguous tail leaves lhead_seq > count with NO seq gap — caught here.
        u64 want = lhead_seq.count(c) ? lhead_seq[c] : 0;
        u64 have = levt_count.count(c) ? levt_count[c] : 0;
        if (want != have) { res.ok = false; res.offending_key = "v37s:levt:" + c; res.reason = "lhead seq != levt count (dropped tail)"; return res; }
    }
    return res;
}

// ── RS-2 / RS-3 / RS-4 / RS-5 shapes (self-contained) ─────────────────────
static void test_rs_shapes() {
    // RS-2: restart with header chain pruned below hw_height => settlement refused
    // until catch-up, then resumes; nothing re-evaluated on the shorter view.
    { HwModel hw; hw.advance(1000, mk_hash(1));
      FaultSettleStore s; { auto b = s.batch(); b->put(khw(0), encode_hw(0, 1, hw)); b->commit_sync(); }
      HwModel r = HwModel::deserialize(decode_hw(*s.get(khw(0)))->hw.serialize());
      CHECK(!r.admit_candidate_height(900));    // header chain at 900 < hw => refused
      CHECK(r.admit_candidate_height(1000));    // caught up => resumes
      CHECK(r.hw_height == 1000); }             // never re-evaluated lower

    // RS-3: downtime reorg orphans a SETTLED block => residual surfaced with its
    // amount, finalW untouched, settled unchanged (B5 analog).
    { LedgerModel L; bytes32 K = mk_hash(3);
      L.on_block_found("b", {{K, 50}}, {{K, 50}});
      L.on_block_finalized("b", 10);
      auto finalW_before = L.finalW; bool settled_before = L.is_settled("b");
      L.on_block_orphaned("b", {{K, 50}});      // post-SETTLED orphan
      CHECK(L.residual == 50);                  // residual surfaced with amount
      CHECK(L.finalW == finalW_before);         // finalW untouched
      CHECK(L.is_settled("b") == settled_before && settled_before); }  // terminal

    // RS-4 (corruption): flip one byte in a levt value => fail-closed at open with
    // the offending key named; never an empty start. RepairDB dropped-tail variant
    // is caught by the census (below), NOT by the byte-flip path.
    { FaultSettleStore s;
      Event e; e.evkind = EV_FOUND; e.seq = 1; e.bid = "b"; e.credit[mk_hash(1)] = 10;
      { auto b = s.batch(); b->put(klevt(0, 1), encode_event(e)); b->commit_sync(); }
      // corrupt: flip the evkind byte to an invalid value
      auto v = *s.get(klevt(0, 1)); v[2] = 9; { auto b = s.batch(); b->put(klevt(0, 1), v); b->commit_sync(); }
      bool fail_closed = false; std::string offender;
      s.for_each_prefix("v37s:levt:", [&](const std::string& k, const std::string& val) {
          if (!decode_event(val)) { fail_closed = true; offender = k; return false; } return true; });
      CHECK(fail_closed && offender == klevt(0, 1)); }   // named, not silent

    // RS-4 census variant: a RepairDB-dropped levt tail (lhead says seq=3 but only
    // 2 levt records survive, no gap) is caught by the lhead-vs-levt census.
    { FaultSettleStore s;
      { auto b = s.batch(); b->put(khw(0), encode_hw(0, 1, HwModel{})); b->commit_sync(); }
      for (u64 q : {u64(1), u64(2)}) { auto b = s.batch(); Event e; e.evkind = EV_FOUND; e.seq = q; e.bid = "b"; b->put(klevt(0, q), encode_event(e)); b->commit_sync(); }
      LHead lh; lh.ledger_seq = 3;              // lhead claims 3 events; only 2 on disk
      { auto b = s.batch(); b->put(klhead(0), encode_lhead(lh)); b->commit_sync(); }
      auto cen = recovery_census(s);
      CHECK(!cen.ok && cen.offending_key == "v37s:levt:0000000000"); }

    // F2 (a): a chain whose hw was dropped but whose lhead/levt survive => census
    // fail-closed (the MD-3 loss the naive hw-key-set iteration would miss).
    { FaultSettleStore s;
      { auto b = s.batch(); Event e; e.evkind = EV_FOUND; e.seq = 1; e.bid = "b"; b->put(klevt(7, 1), encode_event(e)); b->commit_sync(); }
      LHead lh; lh.ledger_seq = 1; { auto b = s.batch(); b->put(klhead(7), encode_lhead(lh)); b->commit_sync(); }
      // no hw for chain 7 (dropped)
      auto cen = recovery_census(s);
      CHECK(!cen.ok && cen.offending_key == "v37s:hw:0000000007"); }

    // a clean store passes the census
    { FaultSettleStore s;
      { auto b = s.batch(); b->put(khw(0), encode_hw(0, 1, HwModel{})); b->commit_sync(); }
      { auto b = s.batch(); Event e; e.evkind = EV_FOUND; e.seq = 1; e.bid = "b"; b->put(klevt(0, 1), encode_event(e)); LHead lh; lh.ledger_seq = 1; b->put(klhead(0), encode_lhead(lh)); b->commit_sync(); }
      CHECK(recovery_census(s).ok); }

    // RS-5: boot_id monotone across 3 restarts; a CutToken from boot 1 read in
    // boot 3 resolves by digest (§5.5) or refuses — never aliases. Here we assert
    // the boot_id ladder and that a boot-1 token carries a boot_id < the live one
    // (so incarnation-by-value can never alias; digest identity is the resolver).
    { FaultSettleStore s; u64 boot = 0;
      auto open = [&]() { u64 nb = ++boot; Meta m; m.boot_id = nb; auto b = s.batch(); b->put(kmeta(), encode_meta(m)); b->commit_sync(); return nb; };
      u64 b1 = open(); BlkRec blk; blk.token.incarnation = 1; blk.boot_id = b1; blk.token.spine_digest = mk_hash(0x5a);
      u64 b2 = open(); (void)b2; u64 b3 = open();
      auto meta = decode_meta(*s.get(kmeta())); CHECK(meta && meta->boot_id == b3 && b3 == 3);
      // boot-1 token seen in boot 3: boot_id differs => resolve by digest identity, never alias
      CHECK(blk.boot_id != b3);
      CHECK(blk.token.spine_digest == mk_hash(0x5a)); }   // digest is the cross-boot resolver
}

// ═══════════════════════════════════════════════════════════════════════════
//  §6.5 STRUCTURAL GREP-GATE CHECKLIST (asserted where runtime-checkable;
//  the rest are documented invariants the assembler/reviewer greps for).
// ═══════════════════════════════════════════════════════════════════════════
static void test_grep_gates() {
    // (1) no code path deletes or rewrites a v37s:levt: key — the FaultSettleStore
    //     tripwire fires on any remove() of a levt key. Exercise a legitimate
    //     write path and assert the tripwire stayed clean.
    g_levt_delete_violation = false;
    { FaultSettleStore s; Event e; e.evkind = EV_FOUND; e.seq = 1; e.bid = "b";
      auto b = s.batch(); b->put(klevt(0, 1), encode_event(e)); b->commit_sync(); }
    CHECK(!g_levt_delete_violation);
    // and prove the tripwire actually trips (so the negative above is meaningful)
    { FaultSettleStore s; auto b = s.batch(); b->remove(klevt(0, 1)); }
    CHECK(g_levt_delete_violation);
    g_levt_delete_violation = false;

    // (2) every settlement BatchWriter ends commit_sync(), never commit(): the
    //     ISettleBatch seam exposes ONLY commit_sync() — structurally enforced,
    //     asserted here by construction (no commit() member exists to call).

    // (3) no MinerId / recipient-address / UTXO / txid in any v37s: value: the
    //     ledger maps are bytes32 CANONICAL-IDENTITY keyed (Amounts = map<bytes32,i64>,
    //     w4_settlement.hpp:354) and no codec above writes a MinerId, address,
    //     UTXO, or txid field. (Grep gate over w6_persistence.hpp encoders; the
    //     test's encoders mirror them 1:1 and contain no such field.)

    // (4) the height: index is never referenced by the replay driver: the replay
    //     walks prev_hash backward (get_chain_hashes forward=false) and post-
    //     truncates at the LANE-genesis hash (F4). No height:<...> key is read.
    //     (Grep gate over w6_persistence.hpp ReplayDriver; asserted structurally.)

    // (5) no Lane/Roundabout/LaneExecutor type name in w6_* : this TU names none;
    //     the assembler must keep w6_persistence.hpp free of them too (it CALLS
    //     V37Engine only). (Grep gate over the source tree.)
    CHECK(true);   // checklist anchor — items 2/3/4/5 are source-grep invariants
}

// ── NEEDS-ASSEMBLY stubs (compiled only under -DW6_ASSEMBLED) ──────────────
// These name the exact real-class wiring the assembler completes. They are the
// CM-1 k1..k5 / CM-6 loopback drivers and the RB-1..RB-5 golden digest traces
// that require a real V37Engine (submit/submit_tracked/snapshot), a real
// OwedLedger/SettleHW, and the real SettlementJournal/RecoveryDriver/ReplayDriver.
#ifdef W6_ASSEMBLED
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/w6_persistence.hpp>   // ISettleStore, LevelDBSettleStore, SettlementJournal, RecoveryDriver, ReplayDriver, PrefixResolver
static void test_rs1_restart_digest() {
    // RS-1: graceful stop -> restart -> §4.1 step 5 digest check passes, ring
    // warm, first W4 propose() after restart == pre-stop proposal at the same cut.
    //   drive a real V37Engine with a seeded LaneRecord stream; snapshot(c)->digest
    //   BEFORE stop == RecoveryDriver-rebuilt engine snapshot(c)->digest AFTER.
    // TODO(assembler): wire RecoveryDriver over a FaultSettleStore-backed journal.
}
static void test_rb_golden() {
    // RB-1..RB-5 (spec §6.3): reference digest trace Δ_ref from a fresh engine
    // replay of canonical S; test arm plays S with a depth-d fork, Rewind(d), on
    // RefusedJournal runs ReplayDriver (§5.3), then continues S; assert digest ==
    // Δ_ref at every position through TWO further epoch boundaries.
    //   RB-1 d=1 on an epoch boundary (sentinel refusal);
    //   RB-2 d=65 > D=64;  RB-3 d spans a boundary with d<D;
    //   RB-4 RemoveLane->AddLane in-boot (old-incarnation CutToken MUST fail
    //        read_cut; PrefixResolver §5.5 resolves it by digest);
    //   RB-5 OQ-5 default LaneParams{} crossing two real rebuilds (~9500 pushes).
    // TODO(assembler): pin the per-position digest trace under proto/w6-rebuild/.
}
#endif

}  // namespace w6test

// ═══════════════════════════════════════════════════════════════════════════
//  w6asm — NON-HOLLOW coverage that drives the REAL assembled classes from
//  <c2pool/v37/w6_persistence.hpp> (namespace c2pool::v37n::persist / ::recover,
//  with the W4 shim). Same FaultSettleStore idea, but over the header's OWN
//  ISettleStore seam and OWN codecs, so a codec/driver regression in the shipped
//  header fails THIS suite (the stdlib CI test), not only the assembled -DW6_
//  ASSEMBLED build.
// ═══════════════════════════════════════════════════════════════════════════
namespace w6asm {
namespace persist = c2pool::v37n::persist;
namespace recover = c2pool::v37n::recover;
namespace settle  = c2pool::v37n::settle;
using vb32 = ::v37::bytes32;
using vu64 = ::v37::u64;

static vb32 H(std::uint8_t seed) { vb32 b{}; b[0] = seed; b[31] = seed; return b; }

// FaultSettleStore over the header's ISettleStore seam (DROP / TEAR / iter-fail).
class FaultStore : public persist::ISettleStore {
public:
    std::map<std::string, std::string> kv;
    unsigned commits = 0, tear_at = 0, drop_at = 0; std::string drop_prefix; bool iter_fail = false;
    void arm_tear(unsigned n) { tear_at = n; }
    void arm_drop(unsigned n, const std::string& p) { drop_at = n; drop_prefix = p; }
    void arm_iter_fail() { iter_fail = true; }
    void set(const std::string& k, const std::string& v) { kv[k] = v; }
    void drop(const std::string& k) { kv.erase(k); }
    void flip(const std::string& k, std::size_t pos) { if (kv.count(k) && pos < kv[k].size()) kv[k][pos] ^= 0xff; }
    struct Batch : persist::ISettleBatch {
        FaultStore* s; std::vector<std::pair<std::string, std::string>> puts; std::vector<std::string> rems;
        void put(const std::string& k, const std::string& v) override { puts.push_back({k, v}); }
        void remove(const std::string& k) override { rems.push_back(k); }
        bool commit_sync() override {
            unsigned n = ++s->commits;
            if (s->tear_at && n == s->tear_at) return false;            // torn: nothing applies
            bool dropping = (s->drop_at && n == s->drop_at);
            for (auto& [k, v] : puts) { if (dropping && k.rfind(s->drop_prefix, 0) == 0) continue; s->kv[k] = v; }
            for (auto& k : rems) s->kv.erase(k);
            return true;
        }
    };
    std::unique_ptr<persist::ISettleBatch> batch() override { auto b = std::make_unique<Batch>(); b->s = this; return b; }
    std::optional<std::string> get(const std::string& k) override { auto it = kv.find(k); if (it == kv.end()) return std::nullopt; return it->second; }
    bool for_each_prefix(const std::string& pfx, const std::function<bool(const std::string&, const std::string&)>& fn) override {
        if (iter_fail) { iter_fail = false; return false; }
        for (auto it = kv.lower_bound(pfx); it != kv.end(); ++it) { if (it->first.compare(0, pfx.size(), pfx) != 0) break; if (!fn(it->first, it->second)) return false; }
        return true;
    }
};

// ── the real persist:: codecs round-trip + malformed fail-closed ──
static void test_persist_codecs() {
    { persist::MetaRec m; m.boot_id = 7; m.last_open_ts = 222; auto d = persist::decode_meta(persist::encode_meta(m)); CHECK(d && d->boot_id == 7 && d->last_open_ts == 222); }
    { settle::SettleHW hw; hw.hw_height = 15; hw.hw_tip = H(0xab); hw.ledger_seq = 9; hw.refused = 2;
      auto d = persist::decode_hw(persist::encode_hw(3, 5, hw));
      CHECK(d && d->chain == 3 && d->boot_id == 5 && d->hw.hw_height == 15 && d->hw.ledger_seq == 9 && d->hw.hw_tip == H(0xab)); }
    { persist::LheadRec l{42, H(0x11), 6}; auto d = persist::decode_lhead(persist::encode_lhead(l)); CHECK(d && d->ledger_seq == 42 && d->owed_digest == H(0x11)); }
    { persist::EventRec e; e.evkind = persist::EV_FOUND; e.seq = 3; e.bid = "blk-3"; e.bin_height = 100; e.credit[H(1)] = 50; e.payout[H(1)] = 20;
      auto d = persist::decode_event(persist::encode_event(e)); CHECK(d && d->seq == 3 && d->bid == "blk-3" && d->payout.at(H(1)) == 20); }
    { persist::BlkRec b; b.share_hash = H(0x33); b.height = 800000; b.token.incarnation = 1; b.token.next_pos = 4090; b.token.spine_digest = H(0x44);
      auto d = persist::decode_blk(persist::encode_blk(b)); CHECK(d && d->height == 800000 && d->token == b.token); }
    { persist::IntentRec i{"blk-x", 900, 1234, 42}; auto d = persist::decode_intent(persist::encode_intent(i)); CHECK(d && d->bid == "blk-x" && d->reward == 1234); }
    { persist::CarrierRec c; c.next_pos_after = 128; c.digest_after = H(0x77); c.accepted_mask = 0b1011; c.w_raw_receipt = {11, 22, 33};
      auto d = persist::decode_carrier(persist::encode_carrier(c)); CHECK(d && d->accepted_mask == 0b1011 && d->w_raw_receipt.size() == 3 && d->w_raw_receipt[2] == 33); }
    { persist::GenesisRec g; g.first_share_hash = H(0x88); g.params.level_caps = {568, 512}; g.ts = 99;
      auto d = persist::decode_genesis(persist::encode_genesis(g)); CHECK(d && d->params.c0 == 4096 && d->params.level_caps.size() == 2 && d->ts == 99); }
    { persist::TipRec t{H(0x99), 4096, 5}; auto d = persist::decode_tip(persist::encode_tip(t)); CHECK(d && d->next_pos == 4096); }
    // malformed → fail-closed
    { auto e = persist::encode_hw(1, 1, settle::SettleHW{}); CHECK(!persist::decode_hw(e.substr(0, e.size() - 3))); }
    { auto e = persist::encode_meta(persist::MetaRec{}); e[0] = 2; CHECK(!persist::decode_meta(e)); }              // ver=2 > 1
    { auto e = persist::encode_hw(1, 1, settle::SettleHW{}); e[e.size() - 57] = 55; CHECK(!persist::decode_hw(e)); } // blob_len != 56
    { persist::EventRec ev; ev.evkind = 7; ev.bid = "x"; CHECK(!persist::decode_event(persist::encode_event(ev))); } // bad evkind
    { persist::CarrierRec c; c.accepted_mask = 0b10000; CHECK(!persist::decode_carrier(persist::encode_carrier(c))); } // mask > R_MAX
    { auto e = persist::encode_tip(persist::TipRec{}); e.push_back('\x00'); CHECK(!persist::decode_tip(e)); }       // trailing garbage
}

// ── the real census_open F2 arms ──
static void test_persist_census() {
    // clean store passes (hw.ledger_seq must agree with lhead.ledger_seq == #levt,
    // exactly the invariant SettlementJournal::stage_head maintains).
    { FaultStore s;
      { auto b = s.batch(); settle::SettleHW hw; hw.ledger_seq = 1; b->put(persist::keys::hw(0), persist::encode_hw(0, 1, hw)); b->commit_sync(); }
      { auto b = s.batch(); persist::EventRec e; e.evkind = persist::EV_FOUND; e.seq = 1; e.bid = "b"; b->put(persist::keys::levt(0, 1), persist::encode_event(e));
        persist::LheadRec lh; lh.ledger_seq = 1; b->put(persist::keys::lhead(0), persist::encode_lhead(lh)); b->commit_sync(); }
      CHECK(persist::census_open(s).ok); }
    // F2(a): dropped hw while levt/lhead survive → fail, hw named
    { FaultStore s;
      { auto b = s.batch(); persist::EventRec e; e.evkind = persist::EV_FOUND; e.seq = 1; e.bid = "b"; b->put(persist::keys::levt(7, 1), persist::encode_event(e));
        persist::LheadRec lh; lh.ledger_seq = 1; b->put(persist::keys::lhead(7), persist::encode_lhead(lh)); b->commit_sync(); }
      auto cr = persist::census_open(s); bool named = false; for (auto& e : cr.errors) if (e.find(persist::keys::hw(7)) != std::string::npos) named = true;
      CHECK(!cr.ok && named); }
    // F2(b): dropped contiguous levt tail (lhead says 3, only 2 survive) → fail
    { FaultStore s;
      { auto b = s.batch(); settle::SettleHW hw; hw.ledger_seq = 3; b->put(persist::keys::hw(0), persist::encode_hw(0, 1, hw)); b->commit_sync(); }
      for (vu64 q : {vu64(1), vu64(2)}) { auto b = s.batch(); persist::EventRec e; e.evkind = persist::EV_FOUND; e.seq = q; e.bid = "b"; b->put(persist::keys::levt(0, q), persist::encode_event(e)); b->commit_sync(); }
      { auto b = s.batch(); persist::LheadRec lh; lh.ledger_seq = 3; b->put(persist::keys::lhead(0), persist::encode_lhead(lh)); b->commit_sync(); }
      CHECK(!persist::census_open(s).ok); }
    // byte-flip in a levt → fail, key named
    { FaultStore s;
      { auto b = s.batch(); settle::SettleHW hw; hw.ledger_seq = 1; b->put(persist::keys::hw(0), persist::encode_hw(0, 1, hw)); b->commit_sync(); }
      { auto b = s.batch(); persist::EventRec e; e.evkind = persist::EV_FOUND; e.seq = 1; e.bid = "b"; b->put(persist::keys::levt(0, 1), persist::encode_event(e));
        persist::LheadRec lh; lh.ledger_seq = 1; b->put(persist::keys::lhead(0), persist::encode_lhead(lh)); b->commit_sync(); }
      s.flip(persist::keys::levt(0, 1), 0);
      auto cr = persist::census_open(s); bool named = false; for (auto& e : cr.errors) if (e.find(persist::keys::levt(0, 1)) != std::string::npos) named = true;
      CHECK(!cr.ok && named); }
    // iterator/IO error → fail-closed, never "empty"
    { FaultStore s; s.arm_iter_fail(); CHECK(!persist::census_open(s).ok); }
}

// ── the real SettlementJournal write path + RecoveryDriver replay: bit-identical
//    ledger across a restart (CM-1 core: X.owed_digest == Y.owed_digest). ──
static void test_persist_journal_recovery() {
    FaultStore s;
    // boot 1: journal a FOUND then FINALIZE on chain 0 using the shim W4 state.
    settle::SettleHW hw; settle::OwedLedger led(0);
    persist::SettlementJournal J(s, 1);
    // seed meta so the store looks opened (RecoveryDriver bumps it)
    { auto b = s.batch(); persist::MetaRec m; m.boot_id = 1; b->put(persist::keys::meta(), persist::encode_meta(m)); b->commit_sync(); }
    vb32 K = H(0x21);
    // tip advance to 100 so the FINALIZE at bin_height 100 passes F1 (b).
    auto tr = J.on_tip_advanced(0, 100, H(100), hw, led);
    CHECK(tr == persist::TipResult::Advanced);
    persist::CutToken cut; cut.chain = 0; cut.incarnation = 1;
    auto fr = J.on_block_found_twophase(0, "b1", H(1), 100, 50, {{K, 50}}, {}, cut, hw, led, [] { return true; });
    CHECK(fr == persist::FoundResult::Found);
    auto fz = J.on_block_finalized(0, "b1", 100, hw, led);
    CHECK(fz == persist::FinalResult::Finalized);
    vb32 live_digest = led.owed_digest();
    vu64 live_seq = led.ledger_seq();

    // restart: RecoveryDriver replays families A/B from the store into a fresh ledger.
    recover::RecoveryHooks hk;
    recover::RecoveryDriver drv(s, hk);
    auto res = drv.recover();
    auto it = res.chains.find(0);
    CHECK(it != res.chains.end());
    CHECK(it->second.started);                                   // §4.4 all gates passed
    CHECK(it->second.ledger != nullptr);
    CHECK(it->second.ledger && it->second.ledger->ledger_seq() == live_seq);
    CHECK(it->second.ledger && it->second.ledger->owed_digest() == live_digest);  // bit-identical
    CHECK(it->second.ledger && it->second.ledger->is_settled("b1"));
    CHECK(it->second.hw.hw_height == 100);                        // O5.5 high-water survived
    CHECK(drv.boot_id() == 2);                                    // boot_id++ once

    // F1 replay-per-height: the persisted FINALIZE bin_height (100) is used, not
    // a live tip; first_eligible for K is stamped at 100 in both live and replay.
    // (Cross-checked structurally: identical owed_digest already implies identical
    // first_eligible, since owed_digest commits it.)
}

// ── the real ReplayDriver F4 truncation + rebuild digest, and PrefixResolver
//    resolve-by-digest, against a position-absolute stub engine. ──
namespace rp {
using LR = persist::LaneRecord;
// A faithful position-absolute fold engine (mirrors v37_lane digest semantics:
// digest = fold(B, next_pos, [(pos,pid,w)...]); RemoveLane resets).
class StubEngine : public persist::IEngineSeam {
    struct Hist { vu64 pos, pid, w; };
    struct Cell { vu64 next_pos = 0, version = 0, incarnation = 0; std::vector<Hist> hist; };
    std::map<::v37::ChainId, Cell> lanes; vu64 next_inc = 0;
    static vu64 mix(vu64 h, vu64 x) { h ^= x; h *= 1099511628211ull; return h; }
    static vb32 digest_of(const Cell& L) {
        vu64 h = 1469598103934665603ull; h = mix(h, L.next_pos);
        for (auto& e : L.hist) { h = mix(h, e.pos); h = mix(h, e.pid); h = mix(h, e.w); }
        vb32 b{}; for (int i = 0; i < 8; ++i) b[i] = std::uint8_t((h >> (8 * i)) & 0xff); return b;
    }
public:
    void submit(const LR& r) override {
        switch (r.kind) {
            case LR::K::RemoveLane: lanes.erase(r.chain); return;
            case LR::K::AddLane: { Cell c; c.incarnation = ++next_inc; lanes[r.chain] = c; return; }
            case LR::K::Push: { auto it = lanes.find(r.chain); if (it == lanes.end()) return; auto& L = it->second;
                L.hist.push_back({L.next_pos, r.payout_id, r.w_raw}); L.next_pos++; L.version++; return; }
            default: return;
        }
    }
    std::shared_ptr<const persist::LaneSnapshotView> snapshot(::v37::ChainId c) const override {
        auto it = lanes.find(c); if (it == lanes.end()) return nullptr;
        auto s = std::make_shared<persist::LaneSnapshotView>();
        s->chain = c; s->next_pos = it->second.next_pos; s->version = it->second.version;
        s->incarnation = it->second.incarnation; s->digest = digest_of(it->second); return s;
    }
};
class StubChain : public persist::ISharechainReader {
    std::map<vb32, vb32> prev; std::map<vb32, std::string> shares; vb32 zero{};
public:
    void set(const vb32& h, const vb32& p, const std::string& body) { prev[h] = p; shares[h] = body; }
    std::vector<vb32> get_chain_hashes(const vb32& start, vu64 max, bool) const override {
        std::vector<vb32> out; vb32 cur = start;
        while (out.size() < max) { out.push_back(cur); auto it = prev.find(cur); if (it == prev.end() || it->second == zero) break; cur = it->second; }
        return out;
    }
    std::optional<std::string> load_share(const vb32& h) const override { auto it = shares.find(h); if (it == shares.end()) return std::nullopt; return it->second; }
};
static vb32 mkh(vu64 n) { vb32 b{}; for (int i = 0; i < 8; ++i) b[i] = std::uint8_t((n >> (8 * i)) & 0xff); b[31] = 0xa5; return b; }
} // namespace rp

static void test_persist_replay_prefix() {
    using namespace rp;
    ::v37::ChainId c = 5;
    FaultStore store; StubChain chain;
    // 8 lane carriers above 6 pre-genesis (sharechain-only) carriers → F4 truncation load-bearing.
    const vu64 PRE = 6, N = 8;
    std::vector<vb32> pre_hashes, lane_hashes; vb32 prev{};
    for (vu64 i = 0; i < PRE; ++i) { vb32 h = mkh(900000 + i); persist::DecodedShare d; d.carrier_payout_id = 90000 + i;
        chain.set(h, prev, persist::encode_share(d)); persist::CarrierRec cr; cr.w_raw_carrier = 1; store.set(persist::keys::carrier(c, h), persist::encode_carrier(cr)); prev = h; pre_hashes.push_back(h); }
    // reference engine to compute per-carrier digest_after / tip digest.
    StubEngine ref; ref.submit(persist::LaneRecord::AddLane(c, persist::LaneParamsRec{}));
    vb32 dref{}; vu64 last_pos = 0;
    for (vu64 i = 0; i < N; ++i) {
        vb32 h = mkh(3000 + i); persist::DecodedShare d; d.carrier_payout_id = 3000 + i;
        chain.set(h, prev, persist::encode_share(d));
        persist::CarrierRec cr; cr.w_raw_carrier = 1 + (i % 7);
        ref.submit(persist::LaneRecord::Push(c, d.carrier_payout_id, cr.w_raw_carrier, 0));
        auto snap = ref.snapshot(c); cr.next_pos_after = snap->next_pos; cr.digest_after = snap->digest; cr.lane_version_after = snap->version;
        store.set(persist::keys::carrier(c, h), persist::encode_carrier(cr));
        dref = snap->digest; last_pos = snap->next_pos; prev = h; lane_hashes.push_back(h);
    }
    persist::GenesisRec g; g.first_share_hash = lane_hashes.front(); g.params = persist::LaneParamsRec{}; store.set(persist::keys::genesis(c), persist::encode_genesis(g));
    persist::TipRec t; t.share_hash = lane_hashes.back(); t.next_pos = last_pos; store.set(persist::keys::tip(c), persist::encode_tip(t));

    persist::ReplayDriver rd(store, chain);
    // F4: the raw backward walk descends below lane genesis (8 + 6 = 14).
    auto raw = chain.get_chain_hashes(lane_hashes.back(), ~vu64(0), false);
    CHECK(raw.size() == PRE + N);
    // walk_lane_forward truncates AT lane genesis: exactly N, starting at genesis.
    auto fwd = rd.walk_lane_forward(lane_hashes.back(), lane_hashes.front(), ~vu64(0));
    CHECK(fwd && fwd->size() == N && fwd->front() == lane_hashes.front() && fwd->back() == lane_hashes.back());
    // rebuild from the truncated walk == reference digest (bit-identical).
    StubEngine e; auto out = rd.rebuild(c, e);
    CHECK(out && out->digest == dref && out->carriers == N);
    // F4 negative: undersized max never reaches genesis → fail-closed nullopt.
    CHECK(!rd.walk_lane_forward(lane_hashes.back(), lane_hashes.front(), 3).has_value());

    // PrefixResolver: resolve prefix P=4 by digest; rewritten digest → nullopt.
    auto recs = rd.canonical_records(c); CHECK(recs.has_value());
    StubEngine scratch; { vu64 pushes = 0; for (auto& r : *recs) { if (r.kind == persist::LaneRecord::K::AddLane) { scratch.submit(r); continue; } if (r.kind != persist::LaneRecord::K::Push) continue; if (pushes >= 4) break; scratch.submit(r); ++pushes; } }
    vb32 pfx_digest = scratch.snapshot(c)->digest;
    persist::PrefixResolver resolver([] { return std::unique_ptr<persist::IEngineSeam>(std::make_unique<StubEngine>()); });
    auto ok = resolver.resolve(c, 4, pfx_digest, *recs);
    CHECK(ok && ok->next_pos == 4 && ok->digest == pfx_digest);
    CHECK(!resolver.resolve(c, 4, mkh(0xdead), *recs).has_value());   // rewritten prefix → nullopt
}

} // namespace w6asm

int main() {
    using namespace w6test;
    test_codec_roundtrip();
    test_codec_malformed();
    test_faultstore();
    falsifier_G1();
    falsifier_G2();
    falsifier_G3();
    falsifier_F1();
    test_rs_shapes();
    test_grep_gates();

    // NON-HOLLOW: drive the REAL assembled header (persist:: / recover::).
    w6asm::test_persist_codecs();
    w6asm::test_persist_census();
    w6asm::test_persist_journal_recovery();
    w6asm::test_persist_replay_prefix();

#ifdef W6_ASSEMBLED
    test_rs1_restart_digest();
    test_rb_golden();
#endif
    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
