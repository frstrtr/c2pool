// v37_retention_tiers_kat.cpp
//
// RECORD/MESSAGE RETENTION TIERS — the ruled 2+1 model (WINDOW / PINNED /
// HASH), VIEW-LAYER and NON-CONSENSUS. Stdlib-only harness (no gtest, no
// core/Boost link), the same convention as its siblings in this directory;
// returns non-zero on the first non-zero failure count.
//
// WHAT IT PINS, in seven sections:
//
//   A  LOG         the SECOND record log: its own "V37R" domain tag (distinct
//                  from the owed-event "V37L"), the mirrored leaf rule against
//                  a hand-built digest and an absolute golden, domain
//                  separation from the owed-event log, inclusion + prefix
//                  proofs through the SHIPPED ::v37::Lane::mmr_verify, a root
//                  golden over a fixed promotion schedule, and the codec.
//   B  WINDOW      the ratified renewable TTL: the clamp law against the ruled
//                  constants (TTL_MIN = R = 8, TTL_MAX = C0 = 4096), expiry
//                  rounded UP to the R^fold_cap lattice, GC riding the fold's
//                  own sealed() predicate, the PURE ladder driving the decay,
//                  requires-NEVER-burns, renewal by re-inclusion, and
//                  MSG_LIVE_CAP = 3 oldest-expires determinism.
//   C  PINNED      the paid horizon H_pin = 4096 = C0 exactly, funded/unfunded
//                  behaviour, outliving the free window, and RENEWAL THAT
//                  RESETS RATHER THAN CHAINS.
//   D  HASH        paid permanence as a 32-byte leaf: the body is DROPPED, the
//                  hash survives every horizon, permanent cost is 32 bytes per
//                  leaf and nothing else, and a second purchase is a no-op.
//   E  PRICING     the linear-rent law c*ceil(bytes/1024)*H_tier with c = 2,
//                  the BYTE bound it buys (<= 1024/c = 512 byte-bins per MWU
//                  for EVERY tier), the proof that the longer tier is never
//                  cheaper per byte-bin, a NON-VACUOUS negative control (the
//                  rejected size-blind price FAILS the same bound), the
//                  no-fragmentation-discount property, and an end-to-end
//                  griefing simulation against a fixed budget.
//   F  PREREQS     TM-OQ1 (the exogenous difficulty anchor: withhold-to-
//                  depress reproduced against the OQ-M2 literal EMA rule and
//                  CLOSED by the anchor floor; fail-closed when unreadable) and
//                  TM-OQ2 (per-epoch randomness from a finalized block hash:
//                  future-epoch precompute refused, boundary tolerance,
//                  perishable credit).
//   G  NON-CONSENSUS   owed_digest and its empty anchor UNMOVED; the w5
//                  StateCommitment root and leaf count UNMOVED; the owed-event
//                  MMR's leaf_count == ledger_seq bijection UNMOVED and its
//                  root untouched; W2 admission byte-identical with and without
//                  the retention tee; a THROWING observer through the real
//                  CarrierIngest unable to change an admission or escape; and
//                  every IGNORED retention request leaving the share standing.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/carrier_ingest.hpp>
#include <c2pool/v37/owed_event_log.hpp>
#include <c2pool/v37/record_log.hpp>
#include <c2pool/v37/retention_log.hpp>
#include <c2pool/v37/retention_view.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w2_admission.hpp>
#include <c2pool/v37/w2_receipt.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/w5_coinbase.hpp>

#include "owed_event_mmr_golden_v1.hpp"
#include "retention_tiers_golden_v1.hpp"

using namespace c2pool::v37n;
namespace ret = ::c2pool::v37n::retention;
namespace nr  = ::v37::nr;
namespace dc  = ::v37::decay_canonical;
using ::c2pool::v37n::coinbase::StateCommitment;
using ::c2pool::v37n::owedevent::OwedEventLog;
using ::c2pool::v37n::recordlog::RecordLog;
using ::c2pool::v37n::settle::OwedLedger;
using ::v37::bytes32;
using ::v37::ChainId;
using ::v37::LaneParams;
using ::v37::LaneRecord;
using ::v37::PayoutDescriptor;
using ::v37::u128;
using ::v37::u64;

// ── harness ──────────────────────────────────────────────────────────────
static int g_checks = 0, g_fail = 0;
static void ok(bool cond, const std::string& what) {
    ++g_checks;
    if (!cond) { ++g_fail; std::printf("   FAIL  %s\n", what.c_str()); }
}
static std::string hx(const bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (unsigned char c : h) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}
static std::string hx(const std::vector<std::uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (unsigned char c : v) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}
static std::string dec(u128 x) {
    if (x == 0) return "0";
    std::string s;
    while (x) { s.push_back(char('0' + int(x % 10))); x /= 10; }
    std::reverse(s.begin(), s.end());
    return s;
}
static bool minted(const char* g) { return g && g[0] != '@'; }
static void pin(const std::string& got, const char* golden, const std::string& what) {
    if (!minted(golden)) {
        ++g_checks; ++g_fail;
        std::printf("   FAIL  %s: golden not minted (placeholder %s), got %s\n",
                    what.c_str(), golden, got.c_str());
        return;
    }
    ok(got == golden, what + ": got " + got + " want " + golden);
}

// ── fixtures ─────────────────────────────────────────────────────────────
static bytes32 b32_of(std::uint8_t fill, std::uint8_t tweak = 0) {
    bytes32 b{};
    for (std::size_t i = 0; i < b.size(); ++i) b[i] = std::uint8_t(fill + i);
    b[31] = tweak;
    return b;
}
static bytes32 mc_hash(u64 h) {
    std::vector<std::uint8_t> v = {'M', 'C'};
    for (int i = 0; i < 8; ++i) v.push_back(std::uint8_t((h >> (8 * i)) & 0xff));
    return ::v37::sha256d(v);
}

// TM-OQ1 seam: a synthetic COMMITTED mainchain difficulty. `work` is the
// mainchain work-per-block; `dark` models a node that cannot read it.
struct SynthAnchor final : ret::IExogenousDifficultyAnchor {
    u64 work = u64(1) << 28;     // >> RETENTION_UNIT_SHIFT(20) = 256 = one share
    bool dark = false;
    std::optional<u64> block_work_at(u64) const override {
        if (dark) return std::nullopt;
        return work;
    }
};
// TM-OQ2 seam: finalized mainchain hashes up to `tip`.
struct SynthHashes final : ret::IFinalizedHashSource {
    u64 tip = u64(1) << 40;
    u64 salt = 0;
    std::optional<bytes32> hash_at(u64 bin) const override {
        if (bin > tip) return std::nullopt;
        return mc_hash(bin ^ salt);
    }
};

static EmittedPush mk_push(const bytes32& id, u64 w_raw, u64 origin_bin, u64 carrier_bin) {
    EmittedPush p;
    p.identity = id;
    p.w_raw = w_raw;
    p.origin_bin = origin_bin;
    p.carrier_bin = carrier_bin;
    return p;
}
static ret::RetentionRequest mk_req(const bytes32& id, const bytes32& rh,
                                    std::uint32_t bytes, ret::Tier want, u64 bin,
                                    const std::string& body = std::string()) {
    ret::RetentionRequest r;
    r.identity = id; r.record_hash = rh; r.bytes = bytes; r.want = want;
    r.carrier_bin = bin;
    r.body = body.empty() ? std::string(bytes, 'x') : body;
    return r;
}
// Mint enough live credit for `mwu`, honestly (through the epoch-seed gate).
static bool fund(ret::RetentionView& v, const bytes32& id, u64 mwu) {
    const u64 e = v.epoch_of(v.t_now());
    const std::optional<bytes32> seed = v.epoch_seed(e);
    if (!seed.has_value()) return false;
    const u64 shares = (mwu + ret::MWU_PER_SACRIFICE_SHARE - 1) / ret::MWU_PER_SACRIFICE_SHARE;
    return v.credit_sacrifice(id, shares, e, *seed) == ret::CreditOutcome::Minted;
}

// W2 fixtures (G4/G5) ------------------------------------------------------
static const ChainId KCHAIN = 7;
static LaneParams small_params() {
    LaneParams p;
    p.window = 256; p.c0 = 128; p.rollup = 8;
    p.level_caps = {16}; p.half_life = 64; p.journal_depth = 16;
    return p;
}
static PayoutDescriptor mk_desc(std::uint8_t fill) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(fill);
    s.push_back(0x88); s.push_back(0xac);
    PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}
struct KatTracker final : IShareTracker {
    std::map<bytes32, std::set<bytes32>> chained;
    bool has_prev_own(const bytes32& id, const bytes32& prev) const override {
        if (prev == W2_GENESIS_PREV_OWN) return true;
        auto it = chained.find(id);
        return it != chained.end() && it->second.count(prev) != 0;
    }
    void record_share(const bytes32& id, const bytes32& h) override { chained[id].insert(h); }
};
static WorkEvent mine(const bytes32& identity, const PayoutDescriptor& desc,
                      u64 origin_bin, const bytes32& prev_own, unsigned lz,
                      const char* tag, u64 salt = 0) {
    WorkEvent ev;
    ev.chain_id = static_cast<std::uint32_t>(KCHAIN);
    ev.identity = identity;
    ev.descriptor = desc;
    ev.prev_block_hash = mc_hash(origin_bin);
    ev.prev_own_share = prev_own;
    ev.lz_bits = lz ? lz : consensus_lz(origin_bin);
    ev.tag = tag;
    for (u64 n = salt << 32; n < (salt << 32) + (u64(1) << 24); ++n) {
        ev.nonce = n;
        if (ev.meets_own_target()) return ev;
    }
    std::printf("FATAL mine: nonce space exhausted (%s)\n", tag);
    std::abort();
}
static std::string push_tuple_digest(const std::vector<EmittedPush>& ps) {
    std::vector<std::uint8_t> buf;
    for (const auto& p : ps) {
        buf.insert(buf.end(), p.identity.begin(), p.identity.end());
        for (int i = 0; i < 8; ++i) buf.push_back(std::uint8_t(p.w_raw >> (8 * i)));
        for (int i = 0; i < 4; ++i) buf.push_back(std::uint8_t(p.flags >> (8 * i)));
        for (int i = 0; i < 8; ++i) buf.push_back(std::uint8_t(p.pos >> (8 * i)));
        for (int i = 0; i < 8; ++i) buf.push_back(std::uint8_t(p.origin_bin >> (8 * i)));
        for (int i = 0; i < 8; ++i) buf.push_back(std::uint8_t(p.carrier_bin >> (8 * i)));
        buf.insert(buf.end(), p.tag.begin(), p.tag.end());
    }
    return hx(::v37::sha256d(buf));
}

// ═════════════════════════════════════════════════════════════════════════
int main() {
    const bytes32 ALICE = b32_of(0x11, 1);
    const bytes32 BOB   = b32_of(0x22, 2);
    const bytes32 RH1   = b32_of(0x31, 1);
    const bytes32 RH2   = b32_of(0x31, 2);
    const bytes32 RH3   = b32_of(0x31, 3);
    const bytes32 RH4   = b32_of(0x31, 4);
    const u64 R_FOLD = nr::pow_R(nr::for_version(1, ::v37::LaneKind::BTC).fold_cap);

    // ── A · THE SECOND RECORD LOG ────────────────────────────────────────
    std::printf("-- A: the retention record log (its own instance, its own tag) --\n");
    {
        ok(std::memcmp(ret::RET_LEAF_TAG, "V37R", 4) == 0, "A1a domain tag is V37R");
        ok(std::memcmp(ret::RET_LEAF_TAG, owedevent::LEAF_TAG, 4) != 0,
           "A1b retention tag is NOT the owed-event tag (domain separation)");

        const auto payload = ret::ret_leaf_payload(ret::RET_PIN, ALICE, RH1, 4096, 1024, 8192);
        std::vector<std::uint8_t> hand;
        hand.push_back(0x00);
        hand.insert(hand.end(), payload.begin(), payload.end());
        ok(RecordLog::leaf_hash(payload) == ::v37::sha256d(hand),
           "A2 leaf == sha256d(0x00||payload), the lane rule mirrored once");
        ok(payload.size() == 4 + 1 + 32 + 32 + 8 + 4 + 8, "A2b leaf payload is fixed width");
        std::printf("   pin_leaf_payload=%s\n", hx(payload).c_str());
        pin(hx(payload), rtg_v1::PIN_LEAF_PAYLOAD_HEX, "A3a absolute leaf ENCODING golden");
        pin(hx(RecordLog::leaf_hash(payload)), rtg_v1::PIN_LEAF_HASH, "A3b absolute leaf HASH golden");

        ret::RetentionLog empty;
        ok(hx(empty.root()) == std::string(oes_v1::EMPTY_LOG_ROOT),
           "A4a empty retention log bags to 32 zero bytes");
        ok(hx(empty.root()) != std::string(oes_v1::EMPTY_OWED_DIGEST_ANCHOR),
           "A4b empty retention root is NOT the empty owed anchor");
        ok(empty.leaf_count() == 0 && empty.consistent(), "A4c empty log is consistent");

        // A5 — DOMAIN SEPARATION: an owed-event log and a retention log with the
        // same leaf COUNT never share a root, because the tags differ.
        ret::RetentionLog rl;
        OwedEventLog oel;
        for (int i = 0; i < 5; ++i) {
            rl.append_pin(ALICE, b32_of(0x40, std::uint8_t(i)), 1000 + i, 1024, 8192);
            oel.append_finalize("blk" + std::to_string(i), 1000 + i);
        }
        ok(rl.leaf_count() == oel.leaf_count(), "A5a same leaf count");
        ok(rl.root() != oel.root(), "A5b different roots (tags separate the domains)");

        // A6 — proofs through the SHIPPED lane verifier.
        bytes32 leaf{};
        ::v37::Lane::MmrProof prf;
        ok(rl.log().prove(2, leaf, prf) && RecordLog::verify(rl.root(), leaf, prf),
           "A6a inclusion proof verifies under ::v37::Lane::mmr_verify");
        RecordLog::PrefixProof pp;
        const bytes32 root5 = rl.root();
        ret::RetentionLog rl3;
        for (int i = 0; i < 3; ++i)
            rl3.append_pin(ALICE, b32_of(0x40, std::uint8_t(i)), 1000 + i, 1024, 8192);
        ok(rl.log().prove_prefix(3, pp) &&
           RecordLog::verify_prefix(rl3.root(), 3, root5, 5, pp),
           "A6b prefix proof: the log at 5 extends the log at 3");

        // A7 — a root golden over a fixed promotion schedule.
        ret::RetentionLog sched;
        sched.append_pin(ALICE, RH1, 4096, 1024, 8192);
        sched.append_renew(ALICE, RH1, 4160, 1024, 8192);
        sched.append_hash(BOB, RH2, 4224, 60000, 24576);
        sched.append_pin(BOB, RH3, 4288, 2048, 16384);
        sched.append_hash(ALICE, RH4, 4352, 1, 24576);
        std::printf("   schedule_root=%s\n", hx(sched.root()).c_str());
        pin(hx(sched.root()), rtg_v1::SCHEDULE_ROOT, "A7 retention-log root over the fixed schedule");

        // A8 — the primitive's codec, unchanged, through this instance.
        const std::string ser = sched.log().serialize();
        const auto back = RecordLog::deserialize(ser);
        ok(back.has_value() && back->root() == sched.root() &&
           back->leaf_count() == sched.leaf_count(),
           "A8a serialize/deserialize round-trips the retention log");
        std::string bad = ser; bad.push_back('\0');
        ok(!RecordLog::deserialize(bad).has_value(), "A8b trailing garbage is fail-closed");
    }

    // ── B · WINDOW (free, renewable, requires-never-burns) ───────────────
    std::printf("-- B: WINDOW — the ratified renewable TTL --\n");
    {
        ok(ret::TTL_MIN_BINS == nr::ROLLUP && ret::TTL_MIN_BINS == 8,
           "B1a TTL_MIN == R == 8 (OQ-M2)");
        ok(ret::TTL_MAX_BINS == dc::CANON_EPOCH_LEN && ret::TTL_MAX_BINS == 4096,
           "B1b TTL_MAX == C0 == 4096 (OQ-M2)");
        ok(ret::MSG_LIVE_CAP == 3, "B1c MSG_LIVE_CAP == 3 (OQ-M2)");

        // B2 — the clamp law itself, as a pure function.
        const u64 U = 256;
        ok(ret::RetentionView::ttl_bins_of(0, U) == ret::TTL_MIN_BINS, "B2a zero standing -> TTL_MIN");
        ok(ret::RetentionView::ttl_bins_of(u128(U) * 7, U) == ret::TTL_MIN_BINS, "B2b below the floor -> TTL_MIN");
        ok(ret::RetentionView::ttl_bins_of(u128(U) * 100, U) == 100, "B2c in band -> floor(dw/unit)");
        ok(ret::RetentionView::ttl_bins_of(u128(U) * 100 + (U - 1), U) == 100, "B2d it FLOORS, never rounds up");
        ok(ret::RetentionView::ttl_bins_of(u128(U) * 4096, U) == ret::TTL_MAX_BINS, "B2e at the ceiling -> TTL_MAX");
        ok(ret::RetentionView::ttl_bins_of(u128(U) << 90, U) == ret::TTL_MAX_BINS, "B2f absurd standing still TTL_MAX");

        SynthAnchor anchor; SynthHashes hashes;
        // AnchorOnly isolates the TTL law from the EMA interaction, which has
        // its own section (F).
        ret::RetentionView v(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        const u64 B = 5000;
        v.on_push(mk_push(ALICE, 256 * 100, B, B));        // standing == 25600 at t == B
        ok(v.t_now() == B, "B3a the view's bin clock is the monotone max carrier bin");
        ok(v.standing(ALICE) == u128(25600), "B3b standing at age 0 is the raw work");
        ok(v.ttl_work_unit(B) == 256, "B3c unit == mainchain block work >> shift");
        ok(v.ttl_bins_for(ALICE) == 100, "B3d ttl == floor(standing / unit)");

        // B4 — the decay is the PURE ratified ladder, not a local rule.
        const u128 half = v.standing_at(ALICE, B + dc::CANON_HALF_LIFE);
        ok(half * 2 >= u128(25600) * 99 / 100 && half * 2 <= u128(25600) * 101 / 100,
           "B4 one half-life of ladder decay halves the standing (within 1%)");

        // B5 — expiry rounds UP onto the R^fold_cap lattice.
        bool lattice = true, upward = true, tight = true;
        for (u64 b = 4990; b < 5010; ++b)
            for (u64 t = 8; t <= 64; t += 7) {
                const u64 e = v.window_expiry_of(b, t);
                if ((e + 1) % R_FOLD != 0) lattice = false;
                if (e < b + t) upward = false;
                if (e >= b + t + R_FOLD) tight = false;
            }
        ok(lattice, "B5a expiry sits on an R^fold_cap lattice boundary");
        ok(upward, "B5b expiry is rounded UP, never down");
        ok(tight, "B5c the rounding never adds a whole extra lattice span");

        // B6 — admission, and REQUIRES-NEVER-BURNS.
        const u128 before = v.standing(ALICE);
        ok(v.submit(mk_req(ALICE, RH1, 512, ret::Tier::Window, B)) == ret::Outcome::AdmittedWindow,
           "B6a a free-tier request is admitted");
        ok(v.standing(ALICE) == before, "B6b WINDOW READS the standing and never debits it");
        ok(v.tier_of(RH1) == ret::Tier::Window, "B6c the derived tier is WINDOW");
        ok(v.log().leaf_count() == 0, "B6d the FREE tier mints NO promotion leaf");
        const u64 exp1 = v.records().at(RH1).window_expiry;
        ok(exp1 == v.window_expiry_of(B, 100), "B6e expiry == lattice(carrier_bin + ttl)");

        // B7 — renewal by RE-INCLUSION in a later share.
        v.on_push(mk_push(ALICE, 256 * 100, B + 40, B + 40));
        ok(v.submit(mk_req(ALICE, RH1, 512, ret::Tier::Window, B + 40)) == ret::Outcome::Renewed,
           "B7a re-inclusion renews");
        ok(v.records().at(RH1).window_expiry > exp1, "B7b renewal moves the expiry forward");
        ok(v.log().leaf_count() == 0, "B7c renewal in the free tier still mints no leaf");

        // B8 — GC rides the FOLD: alive until sealed(expiry, t, H_open).
        const u64 exp2 = v.records().at(RH1).window_expiry;
        const u64 H_open = v.dim().open_horizon_bins;
        v.on_tip(exp2);
        ok(v.tier_of(RH1) == ret::Tier::Window, "B8a alive AT its expiry bin (not yet sealed)");
        v.on_tip(exp2 + H_open - 1);
        ok(v.tier_of(RH1) == ret::Tier::Window, "B8b alive through the open horizon");
        v.on_tip(exp2 + H_open);
        ok(v.tier_of(RH1) == ret::Tier::None && v.records().count(RH1) == 0,
           "B8c dropped exactly when the fold seals the expiry bin");

        // B9 — MSG_LIVE_CAP: oldest expires, deterministically, on every node.
        auto run_cap = [&](ret::RetentionView& w) {
            const u64 t0 = w.t_now();
            for (int i = 0; i < 5; ++i) {
                w.on_push(mk_push(BOB, 256 * (10 + u64(i) * 10), t0 + u64(i), t0 + u64(i)));
                w.submit(mk_req(BOB, b32_of(0x50, std::uint8_t(i)), 100,
                                ret::Tier::Window, t0 + u64(i)));
            }
            std::vector<std::string> live;
            for (const auto& [rh, r] : w.records())
                if (r.identity == BOB) live.push_back(hx(rh));
            std::sort(live.begin(), live.end());
            return live;
        };
        ret::RetentionView v1(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        ret::RetentionView v2(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        v1.on_tip(6000); v2.on_tip(6000);
        const auto l1 = run_cap(v1), l2 = run_cap(v2);
        ok(l1.size() == ret::MSG_LIVE_CAP, "B9a a sender never holds more than MSG_LIVE_CAP free records");
        ok(l1 == l2, "B9b which ones survive is identical on two independent views");

        // B10 — a sender with NO standing still gets the TTL_MIN floor.
        ret::RetentionView v3(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        v3.on_tip(7000);
        ok(v3.submit(mk_req(BOB, RH2, 64, ret::Tier::Window, 7000)) == ret::Outcome::AdmittedWindow,
           "B10a dust hashrate is still admitted");
        ok(v3.records().at(RH2).window_expiry == v3.window_expiry_of(7000, ret::TTL_MIN_BINS),
           "B10b ...at exactly the TTL_MIN floor");
    }

    // ── C · PINNED (paid, fixed horizon, renewable, never chained) ───────
    std::printf("-- C: PINNED — the paid beyond-window horizon --\n");
    {
        ok(ret::H_PIN_BINS == dc::CANON_EPOCH_LEN && ret::H_PIN_BINS == 4096,
           "C1a H_pin == C0 == 4096 bins (ruling)");
        ok(ret::H_PIN_BINS <= ret::TTL_MAX_BINS, "C1b H_pin sits inside the ruled TTL_MAX");
        ok(ret::price_mwu(ret::Tier::Pinned, 1024) == 2 * 1 * 4096, "C1c price(1 KiB) == c*1*H_pin");

        SynthAnchor anchor; SynthHashes hashes;
        ret::RetentionView v(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        const u64 T1 = 9000;
        v.on_push(mk_push(ALICE, 256 * 20, T1, T1));
        v.submit(mk_req(ALICE, RH1, 1024, ret::Tier::Window, T1));
        ok(v.tier_of(RH1) == ret::Tier::Window, "C2a starts in the free window");

        // C2 — UNFUNDED is an IGNORE: no leaf, no tier change, nothing burned.
        const bytes32 root_before = v.log_root();
        ok(v.submit(mk_req(ALICE, RH1, 1024, ret::Tier::Pinned, T1)) == ret::Outcome::IgnoredUnfunded,
           "C2b an unfunded promotion is IGNORED");
        ok(v.log().leaf_count() == 0 && v.log_root() == root_before,
           "C2c ...and mints no leaf and moves no root");
        ok(v.tier_of(RH1) == ret::Tier::Window, "C2d ...and leaves the tier alone");

        // C3 — funded promotion.
        ok(fund(v, ALICE, ret::price_mwu(ret::Tier::Pinned, 1024)), "C3a credit minted honestly");
        const u128 standing_before = v.standing(ALICE);
        ok(v.submit(mk_req(ALICE, RH1, 1024, ret::Tier::Pinned, T1)) == ret::Outcome::Promoted,
           "C3b a funded promotion is granted");
        ok(v.standing(ALICE) == standing_before,
           "C3c payment debits the MWU credit, NEVER the payout accumulator");
        ok(v.credit_balance(ALICE) == 0, "C3d the credit WAS debited (this is what bounds bytes)");
        ok(v.log().leaf_count() == 1, "C3e exactly one promotion leaf");
        ok(v.tier_of(RH1) == ret::Tier::Pinned, "C3f the derived tier is PINNED");
        ok(v.records().at(RH1).pin_anchor == T1, "C3g the anchor is the payment bin");

        // C4 — the horizon is EXACTLY H_pin, and it outlives the free window.
        v.on_tip(T1 + 4095);
        ok(v.tier_of(RH1) == ret::Tier::Pinned, "C4a pinned at anchor + H_pin - 1");
        ok(v.records().count(RH1) == 1, "C4b ...and still held, long past the free expiry");
        v.on_tip(T1 + 4096);
        ok(v.tier_of(RH1) == ret::Tier::None, "C4c NOT pinned at anchor + H_pin");
        ok(v.records().count(RH1) == 0, "C4d ...and GC has reclaimed the body");

        // C5 — RENEWAL RESETS THE ANCHOR; it does NOT chain.
        ret::RetentionView w(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        const u64 P1 = 9000, P2 = 9500;
        w.on_push(mk_push(ALICE, 256 * 20, P1, P1));
        ok(fund(w, ALICE, ret::price_mwu(ret::Tier::Pinned, 1024)), "C5a fund the first payment");
        ok(w.submit(mk_req(ALICE, RH1, 1024, ret::Tier::Pinned, P1)) == ret::Outcome::Promoted, "C5b first payment");
        w.on_tip(P2);
        ok(fund(w, ALICE, ret::price_mwu(ret::Tier::Pinned, 1024)), "C5c fund the second payment");
        ok(w.submit(mk_req(ALICE, RH1, 1024, ret::Tier::Pinned, P2)) == ret::Outcome::Renewed, "C5d second payment RENEWS");
        ok(w.records().at(RH1).pin_anchor == P2, "C5e the anchor is RESET to the new payment");
        ok(w.log().leaf_count() == 2, "C5f the renewal is its own leaf (kind RENEW)");
        w.on_tip(P2 + 4095);
        ok(w.tier_of(RH1) == ret::Tier::Pinned, "C5g pinned to P2 + H_pin - 1");
        w.on_tip(P2 + 4096);
        ok(w.tier_of(RH1) == ret::Tier::None,
           "C5h NOT pinned past P2 + H_pin: two payments buy H_pin, never 2*H_pin");
    }

    // ── D · HASH (paid, permanent, 32 bytes, body dropped) ───────────────
    std::printf("-- D: HASH — paid permanence as a 32-byte leaf --\n");
    {
        ok(ret::H_HASH_BINS == nr::ladder_domain_bins() && ret::H_HASH_BINS == 12288,
           "D1a the permanence horizon is the ladder domain, 3*C0");
        ok(ret::price_mwu(ret::Tier::Hash, 1) == ret::price_mwu(ret::Tier::Hash, 65536),
           "D1b the HASH price is SIZE-BLIND — it buys 32 bytes, not the body");
        ok(ret::price_mwu(ret::Tier::Hash, 1024) == 2 * 1 * 12288, "D1c price == c*1*H_hash == 24576");

        SynthAnchor anchor; SynthHashes hashes;
        ret::RetentionView v(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        const u64 T = 12000;
        v.on_push(mk_push(ALICE, 256 * 20, T, T));
        const std::string big(60000, 'z');
        v.submit(mk_req(ALICE, RH2, 60000, ret::Tier::Window, T, big));
        ok(v.retained_body_bytes() == 60000, "D2a the body is held while it is in the window");

        ok(fund(v, ALICE, ret::price_mwu(ret::Tier::Hash, 60000)), "D2b fund the HASH promotion");
        ok(v.submit(mk_req(ALICE, RH2, 60000, ret::Tier::Hash, T, big)) == ret::Outcome::Promoted,
           "D2c the HASH promotion is granted");
        ok(v.records().count(RH2) == 0 && v.retained_body_bytes() == 0,
           "D2d THE BODY IS DROPPED — only the hash survives");
        ok(v.hashed().count(RH2) == 1 && v.log().leaf_count() == 1, "D2e one permanent leaf");
        ok(v.permanent_bytes() == 32, "D2f the permanent cost is 32 bytes, not 60000");

        // D3 — permanence: past every horizon in the system.
        v.on_tip(T + ret::H_HASH_BINS * 1000);
        v.gc();
        ok(v.tier_of(RH2) == ret::Tier::Hash, "D3a still HASH far past the ladder domain");
        ok(v.permanent_bytes() == 32, "D3b ...at the same 32-byte cost");

        // D4 — a second purchase is a no-op, not a second charge.
        ok(fund(v, ALICE, ret::price_mwu(ret::Tier::Hash, 1)), "D4a fund a second attempt");
        const u128 bal = v.credit_balance(ALICE);
        ok(v.submit(mk_req(ALICE, RH2, 60000, ret::Tier::Hash, v.t_now())) ==
               ret::Outcome::IgnoredAlreadyHashed,
           "D4b a second HASH purchase of the same record is IGNORED");
        ok(v.credit_balance(ALICE) == bal, "D4c ...and nothing is debited for it");
        ok(v.log().leaf_count() == 1, "D4d ...and no second leaf is minted");

        // D5 — the permanent leaf is provable through the SHIPPED verifier at
        // any later leaf count: keep buying promotions and re-prove leaf 0.
        for (int i = 0; i < 6; ++i) {
            const bytes32 rh = b32_of(0x60, std::uint8_t(i));
            ok(fund(v, BOB, ret::price_mwu(ret::Tier::Pinned, 1024)), "D5a fund a later promotion");
            ok(v.submit(mk_req(BOB, rh, 1024, ret::Tier::Pinned, v.t_now())) == ret::Outcome::Promoted,
               "D5b ...and buy it");
        }
        ok(v.log().leaf_count() == 7, "D5c the log grew past the permanent leaf");
        bytes32 leaf{};
        ::v37::Lane::MmrProof prf;
        ok(v.log().log().prove(0, leaf, prf) && RecordLog::verify(v.log_root(), leaf, prf),
           "D5d the permanent leaf stays provable as the log grows");
    }

    // ── E · LINEAR RENT — the BYTE bound, and the griefer who cannot beat it ──
    std::printf("-- E: linear rent — bounding BYTES, not only time --\n");
    {
        ok(ret::RENT_C_MWU_PER_KIB_BIN == 2, "E1a c == 2 MWU per KiB-bin (ruling)");
        ok(ret::billed_kib(0) == 1 && ret::billed_kib(1) == 1 && ret::billed_kib(1024) == 1 &&
           ret::billed_kib(1025) == 2 && ret::billed_kib(2048) == 2,
           "E1b ceil(bytes/1024) with a one-KiB minimum charge");
        bool law = true;
        for (u64 n = 1; n <= 65536; n = n * 2 + 1)
            if (ret::price_mwu(ret::Tier::Pinned, n) !=
                ret::RENT_C_MWU_PER_KIB_BIN * ret::billed_kib(n) * ret::H_PIN_BINS) law = false;
        ok(law, "E1c price == c * ceil(bytes/1024) * H_tier over a size sweep");

        // E2 — THE BOUND: no tier hands out more than 1024/c byte-bins per MWU.
        const u64 CAP = ret::RENT_KIB_BYTES / ret::RENT_C_MWU_PER_KIB_BIN;   // 512
        u64 best = 0;
        bool bound = true;
        ret::Tier best_tier = ret::Tier::None;
        for (ret::Tier t : {ret::Tier::Pinned, ret::Tier::Hash})
            for (u64 n = 1; n <= 65536; ++n) {
                if (!ret::rent_bound_holds(t, n)) bound = false;
                const u64 bb = ret::tier_retained_bytes(t, n) * ret::tier_horizon_bins(t, 0) /
                               ret::price_mwu(t, n);
                if (bb > best) { best = bb; best_tier = t; }
            }
        ok(bound, "E2a rent_bound_holds for EVERY paid tier at EVERY size (65536 x 2 points)");
        ok(best == CAP, "E2b the best achievable rate is exactly 1024/c == 512 byte-bins per MWU");
        ok(best_tier == ret::Tier::Pinned, "E2c ...and it is PINNED that achieves it (the rent law)");

        // E3 — the LONGER tier is strictly WORSE per byte-bin. This is the
        // property the ruling asked to be proved: a griefer cannot buy a
        // cheaper per-byte-bin rate by buying a longer horizon.
        const u64 hash_rate = ret::tier_retained_bytes(ret::Tier::Hash, 60000) *
                              ret::tier_horizon_bins(ret::Tier::Hash, 0) /
                              ret::price_mwu(ret::Tier::Hash, 60000);
        ok(hash_rate == 16, "E3a HASH yields 16 byte-bins per MWU");
        ok(hash_rate * 32 == CAP, "E3b ...32x WORSE than the rent law, not better");

        // E4 — NEGATIVE CONTROL: the rejected size-blind price FAILS the bound,
        // so E2 is not vacuously true of every pricing function.
        const u64 flat = ret::flat_price_mwu_REJECTED(ret::Tier::Pinned, 65536);
        const u64 flat_rate = 65536 * ret::H_PIN_BINS / flat;
        ok(flat_rate > CAP, "E4a the rejected size-blind price busts the bound at 64 KiB");
        ok(flat_rate == CAP * (65536 / ret::RENT_KIB_BYTES),
           "E4b ...by EXACTLY the size ratio, so it grows without limit as the body grows");
        ok(ret::flat_price_mwu_REJECTED(ret::Tier::Pinned, 1) ==
               ret::flat_price_mwu_REJECTED(ret::Tier::Pinned, 65536),
           "E4c ...because the rejected price is blind to size, which is the whole defect");

        // E5 — fragmentation is never a discount (the one-KiB minimum charge).
        bool frag = true;
        for (u64 n = 1; n <= 64; ++n)
            for (u64 piece = 1; piece <= 4096; piece *= 2) {
                const u64 whole = ret::price_mwu(ret::Tier::Pinned, n * piece);
                const u64 split = n * ret::price_mwu(ret::Tier::Pinned, piece);
                if (split < whole) frag = false;
            }
        ok(frag, "E5 splitting a body into n records never costs less than keeping it whole");

        // E6 — END-TO-END GRIEF SIM: a fixed budget, every tier and size tried
        // for real through submit(), measured against the bound.
        SynthAnchor anchor; SynthHashes hashes;
        const u64 BUDGET = 8192 * 64;         // 64 minimum-size PINNED promotions
        u64 worst_byte_bins = 0;
        for (u64 sz : {u64(1), u64(512), u64(1024), u64(1025), u64(4096), u64(60000)})
            for (ret::Tier t : {ret::Tier::Pinned, ret::Tier::Hash}) {
                ret::RetentionView g(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
                g.on_tip(20000);
                fund(g, BOB, BUDGET);
                u64 spent = 0, got = 0;
                for (u64 i = 0; i < 4096; ++i) {
                    const u64 p = ret::price_mwu(t, sz);
                    if (spent + p > BUDGET) break;
                    const bytes32 rh = ::v37::sha256d(std::vector<std::uint8_t>{
                        std::uint8_t(i), std::uint8_t(i >> 8), std::uint8_t(sz), std::uint8_t(t)});
                    if (ret::outcome_is_ignore(g.submit(mk_req(BOB, rh, std::uint32_t(sz), t, 20000))))
                        break;
                    spent += p;
                    got += ret::tier_retained_bytes(t, sz) * ret::tier_horizon_bins(t, 0);
                }
                if (spent) worst_byte_bins = std::max(worst_byte_bins, got * BUDGET / spent);
            }
        std::printf("   grief sim: worst byte-bins for %s MWU = %s (cap %s)\n",
                    dec(BUDGET).c_str(), dec(worst_byte_bins).c_str(), dec(BUDGET * CAP).c_str());
        ok(worst_byte_bins <= BUDGET * CAP,
           "E6 a griefer spending the whole budget, any tier, any size, stays inside the rent bound");
    }

    // ── F · THE TWO PREREQUISITES ────────────────────────────────────────
    std::printf("-- F: TM-OQ1 exogenous anchor + TM-OQ2 per-epoch randomness --\n");
    {
        // F1/F2 — WITHHOLD-TO-DEPRESS, reproduced and then closed.
        // A sender parks standing, then the pool goes quiet. Under OQ-M2's
        // LITERAL rule (an EMA of in-window share work) the unit collapses and
        // the sender is handed the 4096-bin maximum. Under the shipped
        // anchor-floored rule the unit cannot fall below the mainchain anchor.
        auto withhold = [&](ret::UnitMode mode) {
            SynthAnchor anchor; SynthHashes hashes;
            ret::RetentionView v(::v37::LaneKind::BTC, anchor, hashes, mode);
            v.on_push(mk_push(ALICE, 256 * 256, 30000, 30000));      // real standing
            for (int i = 0; i < 200; ++i)                            // then withhold:
                v.on_push(mk_push(BOB, 1, 30000 + u64(i), 30000 + u64(i)));  // dust only
            return v.ttl_bins_for(ALICE);
        };
        const u64 ema_ttl = withhold(ret::UnitMode::WindowEmaOnly);
        const u64 anc_ttl = withhold(ret::UnitMode::AnchorFloored);
        std::printf("   withhold-to-depress: EMA-only ttl=%llu, anchor-floored ttl=%llu\n",
                    (unsigned long long)ema_ttl, (unsigned long long)anc_ttl);
        ok(ema_ttl == ret::TTL_MAX_BINS,
           "F1 OQ-M2's LITERAL EMA rule IS withhold-to-depress-gameable: the attacker is "
           "handed the 4096-bin CEILING (attack reproduced)");
        ok(anc_ttl < ret::TTL_MAX_BINS && ema_ttl >= 10 * anc_ttl,
           "F2 the exogenous anchor floor CLOSES it: the SAME withholding leaves the sender "
           "on the retention its real work bought, an order of magnitude below the ceiling");

        // F3 — an unreadable anchor FAILS CLOSED (TTL_MIN), never open.
        {
            SynthAnchor dark; dark.dark = true;
            SynthHashes hashes;
            ret::RetentionView v(::v37::LaneKind::BTC, dark, hashes, ret::UnitMode::AnchorFloored);
            v.on_push(mk_push(ALICE, u64(1) << 40, 30000, 30000));
            ok(v.ttl_work_unit(30000) == UINT64_MAX, "F3a unreadable anchor -> the largest unit");
            ok(v.ttl_bins_for(ALICE) == ret::TTL_MIN_BINS,
               "F3b ...so an enormous standing still yields TTL_MIN, never TTL_MAX");
        }

        // F4 — the unit is a pure function of the EXOGENOUS number only.
        {
            SynthAnchor a1; SynthHashes hashes;
            SynthAnchor a2; a2.work = a1.work * 2;
            ret::RetentionView v1(::v37::LaneKind::BTC, a1, hashes, ret::UnitMode::AnchorOnly);
            ret::RetentionView v2(::v37::LaneKind::BTC, a2, hashes, ret::UnitMode::AnchorOnly);
            ok(v2.ttl_work_unit(1) == 2 * v1.ttl_work_unit(1),
               "F4a doubling mainchain difficulty doubles the retention unit");
            ret::RetentionView v3(::v37::LaneKind::BTC, a1, hashes, ret::UnitMode::AnchorFloored);
            const u64 u0 = v3.ttl_work_unit(30000);
            for (int i = 0; i < 500; ++i) v3.on_push(mk_push(BOB, 1, 30000, 30000));
            ok(v3.ttl_work_unit(30000) >= u0,
               "F4b no volume a participant emits can push the unit BELOW the anchor");
        }

        // F5..F8 — per-epoch randomness.
        SynthAnchor anchor; SynthHashes hashes;
        ret::RetentionView v(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        const u64 T = 40000;
        v.on_tip(T);
        const u64 E = v.epoch_of(T);
        ok(v.epoch_bins() == 64 && v.epoch_bins() == v.dim().ckpt_bins,
           "F5a the epoch is the ratified checkpoint cadence, R^2 = 64 bins");
        const auto seed = v.epoch_seed(E);
        ok(seed.has_value(), "F5b the epoch seed resolves from the finalized hash");
        {
            SynthHashes other; other.salt = 99;
            ret::RetentionView vo(::v37::LaneKind::BTC, anchor, other, ret::UnitMode::AnchorOnly);
            vo.on_tip(T);
            ok(vo.epoch_seed(E).has_value() && *vo.epoch_seed(E) != *seed,
               "F5c the seed is a function of the FINALIZED BLOCK HASH (change it, it moves)");
        }
        // F6 — FUTURE-EPOCH PRECOMPUTE: the next epoch's seed does not exist
        // yet, so work ground against a guess cannot be minted.
        {
            SynthHashes limited; limited.tip = T;      // nothing after the current tip
            ret::RetentionView vf(::v37::LaneKind::BTC, anchor, limited, ret::UnitMode::AnchorOnly);
            vf.on_tip(T);
            ok(!vf.epoch_seed(E + 1).has_value(),
               "F6a the NEXT epoch's seed is unknowable before the epoch begins");
            ok(vf.credit_sacrifice(ALICE, 100, E + 1, bytes32{}) == ret::CreditOutcome::RefusedStaleEpoch,
               "F6b ...so a credit claiming a future epoch is refused outright");
        }
        // F7 — the mint gate: wrong seed refused, right seed minted, previous
        // epoch tolerated (the §11a boundary fix), stale epoch refused.
        ok(v.credit_sacrifice(ALICE, 1, E, bytes32{}) == ret::CreditOutcome::RefusedSeed,
           "F7a a wrong seed commitment is refused");
        ok(v.credit_sacrifice(ALICE, 1, E, *seed) == ret::CreditOutcome::Minted, "F7b the right seed mints");
        ok(v.credit_sacrifice(ALICE, 1, E - 1, *v.epoch_seed(E - 1)) == ret::CreditOutcome::Minted,
           "F7c the immediately preceding epoch is tolerated (honest boundary senders)");
        ok(v.credit_sacrifice(ALICE, 1, E - 2, *v.epoch_seed(E - 2)) == ret::CreditOutcome::RefusedStaleEpoch,
           "F7d an older epoch is refused (credit is PERISHABLE)");
        // F8 — perishability actually evaporates a balance.
        {
            ret::RetentionView vp(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
            vp.on_tip(T);
            const u64 e = vp.epoch_of(T);
            vp.credit_sacrifice(ALICE, 10, e, *vp.epoch_seed(e));
            ok(vp.credit_balance(ALICE) == u128(10 * ret::MWU_PER_SACRIFICE_SHARE), "F8a credit is live");
            vp.on_tip(T + 64);
            ok(vp.credit_balance(ALICE) > 0, "F8b ...still live one epoch later");
            vp.on_tip(T + 128);
            ok(vp.credit_balance(ALICE) == 0, "F8c ...and evaporated after CREDIT_TTL_EPOCHS");
        }
        // F9 — no readable exogenous clock -> paid promotions FAIL CLOSED, and
        // the share still stands (the request is ignored, nothing else).
        {
            SynthHashes none; none.tip = 0;
            ret::RetentionView vn(::v37::LaneKind::BTC, anchor, none, ret::UnitMode::AnchorOnly);
            vn.on_tip(T);
            ok(vn.submit(mk_req(ALICE, RH1, 1024, ret::Tier::Pinned, T)) ==
                   ret::Outcome::IgnoredNoEpochSeed,
               "F9a a promotion with no readable epoch seed is IGNORED, not honoured");
            ok(vn.log().leaf_count() == 0, "F9b ...and mints nothing");
            ok(vn.submit(mk_req(ALICE, RH1, 1024, ret::Tier::Window, T)) ==
                   ret::Outcome::AdmittedWindow,
               "F9c ...while the FREE tier, which needs no seed, still works");
        }
    }

    // ── G · NON-CONSENSUS: the wall ──────────────────────────────────────
    std::printf("-- G: NON-CONSENSUS — retention cannot move a committed byte --\n");
    {
        // G1 — owed_digest, the w5 StateCommitment, and the owed-event MMR are
        // untouched by an arbitrary retention workload.
        OwedLedger led(static_cast<ChainId>(KCHAIN));
        OwedEventLog oel;
        OwedLedger::Amounts credit, payout;
        credit[b32_of(0x71, 1)] = 500;
        payout[b32_of(0x72, 1)] = 900;
        led.on_block_found("blk-a", credit, payout);
        oel.append_found("blk-a", credit, payout);
        led.on_block_finalized("blk-a", 1234);
        oel.append_finalize("blk-a", 1234);

        const bytes32 owed_before = led.owed_digest();
        const u64 seq_before = led.ledger_seq();
        const bytes32 oel_before = oel.root();
        StateCommitment sc_before(led, KCHAIN, /*commit_owed_event_mmr*/ false);
        const bytes32 sc_root_before = sc_before.root();
        const std::size_t sc_leaves_before = sc_before.leaf_count();

        {
            OwedLedger fresh(static_cast<ChainId>(KCHAIN));
            ok(hx(fresh.owed_digest()) == std::string(oes_v1::EMPTY_OWED_DIGEST_ANCHOR),
               "G1a the empty owed_digest anchor is UNMOVED by this change");
        }

        SynthAnchor anchor; SynthHashes hashes;
        ret::RetentionView v(::v37::LaneKind::BTC, anchor, hashes);
        v.on_tip(50000);
        for (int i = 0; i < 40; ++i) {
            const bytes32 rh = b32_of(0x80, std::uint8_t(i));
            v.on_push(mk_push(ALICE, 256 * 8, 50000 + u64(i), 50000 + u64(i)));
            v.submit(mk_req(ALICE, rh, 1024 + std::uint32_t(i), ret::Tier::Window, 50000 + u64(i)));
            if (i % 3 == 0) {
                fund(v, ALICE, ret::price_mwu(ret::Tier::Pinned, 1024 + u64(i)));
                v.submit(mk_req(ALICE, rh, 1024 + std::uint32_t(i), ret::Tier::Pinned, 50000 + u64(i)));
            }
            if (i % 7 == 0) {
                fund(v, ALICE, ret::price_mwu(ret::Tier::Hash, 1));
                v.submit(mk_req(ALICE, rh, 1024 + std::uint32_t(i), ret::Tier::Hash, 50000 + u64(i)));
            }
        }
        ok(v.log().leaf_count() > 0, "G1b the workload really did mint retention leaves");
        StateCommitment sc_after(led, KCHAIN, /*commit_owed_event_mmr*/ false);
        ok(led.owed_digest() == owed_before, "G1c owed_digest UNCHANGED across the workload");
        ok(led.ledger_seq() == seq_before, "G1d ledger_seq UNCHANGED");
        ok(oel.root() == oel_before, "G1e the owed-event MMR root UNCHANGED");
        ok(oel.leaf_count() == led.ledger_seq(),
           "G1f the leaf_count == ledger_seq bijection still holds (retention is a SEPARATE log)");
        ok(sc_after.root() == sc_root_before, "G1g the w5 StateCommitment root UNCHANGED");
        ok(sc_after.leaf_count() == sc_leaves_before, "G1h ...and its leaf count UNCHANGED");
        ok(v.log_root() != oel.root() && v.log_root() != sc_root_before,
           "G1i the retention root is its own thing, committed nowhere");

        // G2 — W2 ADMISSION IS BYTE-IDENTICAL with and without the retention
        // tee. This is the "share validity never touched" proof at the exact
        // place a share is judged.
        auto chain = std::make_shared<std::map<bytes32, u64>>();
        for (u64 h = 190; h <= 210; ++h) (*chain)[mc_hash(h)] = h;
        CallbackMainchainIndex index([chain](const bytes32& p) -> std::optional<u64> {
            auto it = chain->find(p);
            return it == chain->end() ? std::nullopt : std::optional<u64>(it->second);
        });
        const PayoutDescriptor DESC = mk_desc(0x11);
        const WorkEvent carrier = mine(ALICE, DESC, 200, W2_GENESIS_PREV_OWN,
                                       consensus_lz(200), "c", 1);
        const WorkEvent good = mine(ALICE, DESC, 199, W2_GENESIS_PREV_OWN,
                                    consensus_lz(199), "r-ok", 2);
        WorkEvent badpow = mine(ALICE, DESC, 199, W2_GENESIS_PREV_OWN,
                                consensus_lz(199), "r-bad", 3);
        badpow.nonce += 1;                                  // PoW no longer holds
        const WorkEvent wrongid = mine(BOB, DESC, 199, W2_GENESIS_PREV_OWN,
                                       consensus_lz(199), "r-id", 4);
        const std::vector<WorkEvent> receipts = {good, badpow, wrongid};

        auto run_admit = [&](ret::RetentionView* tee) {
            KatTracker tracker;
            ReceiptAdmitter adm(static_cast<std::uint32_t>(KCHAIN), index, tracker, 1);
            RecordSink sink;
            if (tee) sink = tee->sink();
            return adm.admit(carrier, receipts, sink);
        };
        const auto plain = run_admit(nullptr);
        SynthAnchor a2; SynthHashes h2;
        ret::RetentionView tee(::v37::LaneKind::BTC, a2, h2);
        const auto teed = run_admit(&tee);
        ok(plain.carrier_status == teed.carrier_status, "G2a carrier status identical");
        ok(plain.receipts == teed.receipts, "G2b every receipt disposition identical");
        ok(plain.pushes.size() == teed.pushes.size(), "G2c push count identical");
        ok(push_tuple_digest(plain.pushes) == push_tuple_digest(teed.pushes),
           "G2d the whole ORDERED push tuple sequence is byte-identical");
        ok(tee.pushes_seen() == teed.pushes.size(), "G2e the tee really did observe every push");

        // G3 — a THROWING observer through the REAL CarrierIngest cannot change
        // an admission, cannot change the forwarded push count, and cannot
        // escape into the admission path.
        {
            V37Engine eng;
            eng.start();
            eng.submit_tracked(LaneRecord::add_lane(KCHAIN, small_params())).get();
            auto s0 = eng.snapshot(KCHAIN);
            const u64 inc = s0 ? s0->incarnation : 1;
            KatTracker tracker;
            CarrierIngest ingest(eng, KCHAIN, index, tracker, inc);
            bool threw_out = false;
            ReceiptAdmitter::Result r1{}, r2{};
            try {
                r1 = ingest.fn()(carrier, receipts);
            } catch (...) { threw_out = true; }
            const std::uint64_t fwd1 = ingest.pushes_forwarded();

            KatTracker tracker2;
            CarrierIngest ingest2(eng, KCHAIN, index, tracker2, inc);
            ingest2.set_observer([](const EmittedPush&) { throw std::runtime_error("view blew up"); });
            try {
                r2 = ingest2.fn()(carrier, receipts);
            } catch (...) { threw_out = true; }
            const std::uint64_t fwd2 = ingest2.pushes_forwarded();
            eng.stop();

            ok(!threw_out, "G3a a throwing observer never unwinds through admit()");
            ok(r1.carrier_status == r2.carrier_status && r1.receipts == r2.receipts,
               "G3b ...and changes no admission decision");
            ok(push_tuple_digest(r1.pushes) == push_tuple_digest(r2.pushes),
               "G3c ...and no emitted push");
            ok(fwd1 == fwd2 && fwd1 == r1.pushes.size(),
               "G3d ...and every push still reached the engine");
        }

        // G4 — every IGNORE path really is an ignore: malformed, over-quota,
        // unfunded and already-hashed all leave the view's committed surface
        // and the ledger exactly where they were.
        {
            ret::RetentionView g(::v37::LaneKind::BTC, anchor, hashes);
            g.on_tip(60000);
            const bytes32 root0 = g.log_root();
            const u64 leaves0 = g.log().leaf_count();
            ok(g.submit(mk_req(ALICE, RH1, 0, ret::Tier::Window, 60000)) == ret::Outcome::IgnoredMalformed,
               "G4a zero-length is ignored");
            ok(g.submit(mk_req(ALICE, RH1, ret::RET_MAX_RECORD_BYTES + 1, ret::Tier::Window, 60000)) ==
                   ret::Outcome::IgnoredMalformed, "G4b oversize is ignored");
            ok(g.submit(mk_req(ALICE, RH1, 64, ret::Tier::Window, 60001)) == ret::Outcome::IgnoredMalformed,
               "G4c a carrier bin ahead of the clock is ignored");
            ok(g.submit(mk_req(ALICE, RH1, 64, ret::Tier::Pinned, 60000)) == ret::Outcome::IgnoredUnfunded,
               "G4d unfunded is ignored");
            ok(g.log_root() == root0 && g.log().leaf_count() == leaves0,
               "G4e no ignored request moved the retention root");
            ok(led.owed_digest() == owed_before && led.ledger_seq() == seq_before,
               "G4f ...and none of them touched the ledger");
        }
    }

    // ── H · VIEW-LAYER PERSISTENCE ───────────────────────────────────────
    std::printf("-- H: the retention root is persisted (and restored) view-layer --\n");
    {
        struct MemRetStore final : ret::IRetentionStore {
            std::map<std::string, std::string> kv;
            void put(const std::string& k, const std::string& v) override { kv[k] = v; }
            std::optional<std::string> get(const std::string& k) override {
                auto it = kv.find(k);
                return it == kv.end() ? std::nullopt : std::optional<std::string>(it->second);
            }
        };

        SynthAnchor anchor; SynthHashes hashes;
        ret::RetentionView v(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        v.on_tip(70000);
        const bytes32 PA = b32_of(0x91, 1), PB = b32_of(0x91, 2), HA = b32_of(0x91, 3);
        ok(fund(v, ALICE, ret::price_mwu(ret::Tier::Pinned, 2048) * 2 +
                          ret::price_mwu(ret::Tier::Hash, 1)), "H1a fund the schedule");
        v.submit(mk_req(ALICE, PA, 2048, ret::Tier::Pinned, 70000));
        v.submit(mk_req(ALICE, PB, 2048, ret::Tier::Pinned, 70000));
        v.submit(mk_req(ALICE, HA, 4096, ret::Tier::Hash, 70000));
        ok(v.log().leaf_count() == 3 && v.promotions().size() == 3, "H1b three promotions");
        const bytes32 root = v.log_root();
        const ret::Tier tPA = v.tier_of(PA), tHA = v.tier_of(HA);

        MemRetStore store;
        v.save(store, KCHAIN);
        ok(store.kv.count(ret::RetentionLog::store_key(KCHAIN)) == 1,
           "H2a the journal lands under the view-layer key");
        ok(ret::RetentionLog::store_key(KCHAIN).rfind("v37v:", 0) == 0,
           "H2b ...which is a VIEW key, not a settlement key");

        ret::RetentionView back(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
        back.on_tip(70000);
        ok(back.load(store, KCHAIN), "H3a a restore from the store succeeds");
        ok(back.log_root() == root && back.log().leaf_count() == 3,
           "H3b replaying the journal reproduces the SAME root by construction");
        ok(back.tier_of(PA) == tPA && back.tier_of(PA) == ret::Tier::Pinned,
           "H3c the PINNED tier is restored");
        ok(back.tier_of(HA) == tHA && back.tier_of(HA) == ret::Tier::Hash,
           "H3d the permanent HASH leaf is restored");
        ok(back.records().at(PA).pin_anchor == 70000, "H3e ...with its anchor intact");

        // H4 — fail-closed, and never fatal: absent, truncated and corrupt all
        // return false and leave an EMPTY view, so a settlement recovery can
        // never be failed by a view artefact.
        {
            MemRetStore empty;
            ret::RetentionView e(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
            ok(!e.load(empty, KCHAIN) && e.log().leaf_count() == 0,
               "H4a an ABSENT record is not an error, just an empty view");
            MemRetStore trunc;
            std::string s = store.kv[ret::RetentionLog::store_key(KCHAIN)];
            trunc.kv[ret::RetentionLog::store_key(KCHAIN)] = s.substr(0, s.size() - 3);
            ret::RetentionView t(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
            ok(!t.load(trunc, KCHAIN) && t.log().leaf_count() == 0, "H4b truncation is fail-closed");
            MemRetStore corrupt;
            std::string c = s;
            c[9] = 'X';                                  // break the domain tag of leaf 0
            corrupt.kv[ret::RetentionLog::store_key(KCHAIN)] = c;
            ret::RetentionView k(::v37::LaneKind::BTC, anchor, hashes, ret::UnitMode::AnchorOnly);
            ok(!k.load(corrupt, KCHAIN) && k.log().leaf_count() == 0,
               "H4c a corrupt leaf is fail-closed (the view starts empty, nothing aborts)");
        }

        // H5 — the leaf accessors the restore relies on are the inverse of the
        // encoder, over every field.
        const auto p = ret::ret_leaf_payload(ret::RET_RENEW, BOB, PB, 123456, 9999, 777777);
        ok(ret::ret_leaf_valid(p) && p.size() == ret::RET_LEAF_BYTES, "H5a a well-formed leaf validates");
        ok(ret::ret_leaf_kind(p) == ret::RET_RENEW && ret::ret_leaf_sender(p) == BOB &&
           ret::ret_leaf_record_hash(p) == PB && ret::ret_leaf_anchor_bin(p) == 123456 &&
           ret::ret_leaf_bytes(p) == 9999 && ret::ret_leaf_price(p) == 777777,
           "H5b every field decodes back to what was encoded");
    }

    std::printf("\n== v37_retention_tiers_kat: %d checks, %d failures -> %s\n",
                g_checks, g_fail, g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
