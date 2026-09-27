// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 generation-transaction KATs (verifier + producer) for the
// private/isolated DASH v36 sharechain.
//
// CONSENSUS-BEARING. No external oracle mints a DASH v36 share, so the v36
// coinbase is pinned by:
//   * HAND-DERIVED INTEGER GOLDENS: the decay constants, per-script decayed
//     weights and every output amount below were computed offline with Python
//     big integers directly from the published formulas (decay_per =
//     2^40 - 2^40*693147 // (10^6 * CHAIN_LENGTH/4), iterative (fp*decay_per)>>40,
//     decayed_att = att*fp >> 40, amount = weight*worker_payout // total_weight,
//     remainder and the 1-sat floor to the donation) — not by running the code
//     under test. They are [PROVISIONAL] in the PR body in the same sense as the
//     F1/F2 producer goldens.
//   * AN INDEPENDENT TX MIRROR: the expected coinbase bytes are re-serialized in
//     this file from the hand amounts, and compared byte-for-byte.
//   * PRODUCER == VERIFIER: build_share_v36's coinbase passes
//     generate_share_transaction / verify_payout_commitment on the same chain.
//   * DRIFT FENCES: payout::v36_worker_amount == payout_share(..., v36) on the
//     uint64 domain; compute_dash_payouts' v36 arm == compute_v36_amounts ==
//     the v36 gentx outputs; ring buffer == walk (the cache-priming premise).
//
// Linked into test_dash_network_id_override: the private/isolated profile is
// keyed on the process-global SharechainConfig identity (IdentityGuard resets it
// around every test; make_coin_params snapshots it, so params are built after).

#include <gtest/gtest.h>

#include <impl/dash/coinbase_builder.hpp>   // compute_dash_payouts (v36 arm drift fence)
#include <impl/dash/config_pool.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/payout_muldiv.hpp>
#include <impl/dash/pplns_v36.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>
#include <impl/dash/share_producer.hpp>
#include <impl/dash/share_tracker.hpp>      // DensePPLNSWindow, ShareTracker (cache key)
#include "dash_v36_chain_fixture.hpp"

#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using dash::SharechainConfig;
using Bytes = std::vector<unsigned char>;

constexpr const char* ISO_ID  = "d3a5c0920263617";   // any custom id => isolated v36
constexpr const char* ISO_PFX = "0badc0ffee11";
constexpr uint32_t PAST_TS = 1700000000u;
constexpr uint64_t NONCE64 = 0x0807060504030201ull;
constexpr uint64_t SUBSIDY = 500000000ull;

struct IdentityGuard {
    IdentityGuard()  { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
    ~IdentityGuard() { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
};

core::CoinParams iso_params() {
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    return dash::make_coin_params(false);
}

uint160 h160_uniform(uint8_t b) { return uint160(Bytes(20, b)); }

Bytes p2pkh(uint8_t b) {
    Bytes s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, b);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

Bytes donation() { return Bytes(dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end()); }

std::string hexs(const Bytes& b) {
    static const char* h = "0123456789abcdef";
    std::string o;
    for (unsigned char c : b) { o.push_back(h[c >> 4]); o.push_back(h[c & 0xf]); }
    return o;
}

uint288 u288(uint64_t v) { return uint288(v); }
uint288 u288_hex(const char* h) { uint288 v; v.SetHex(h); return v; }
uint288 pow2(unsigned n) { uint288 v(1); v <<= n; return v; }

// "!<hex>" raw-script payee (decode_payee_script yields exactly the script).
dash::PackedPayment raw_payment(const Bytes& script, uint64_t amount) {
    dash::PackedPayment p;
    p.m_payee = std::string("!") + hexs(script);
    p.m_amount = amount;
    return p;
}

// ── coinbase tx reader (dash tx_type layout) ─────────────────────────────────
struct Out { uint64_t value; Bytes script; bool operator==(const Out&) const = default; };
struct ParsedTx {
    uint16_t version{0}, type{0};
    Bytes script_sig;
    std::vector<Out> outs;
    uint32_t locktime{0xffffffffu};
    Bytes payload;              // extra_payload (raw), CbTx only
};

struct Reader {
    const Bytes& b; size_t i{0};
    uint64_t le(int n) { uint64_t v = 0; for (int k = 0; k < n; ++k) v |= uint64_t(b.at(i++)) << (8 * k); return v; }
    uint64_t varint() {
        uint8_t c = static_cast<uint8_t>(le(1));
        if (c < 0xfd) return c;
        if (c == 0xfd) return le(2);
        if (c == 0xfe) return le(4);
        return le(8);
    }
    Bytes str() { uint64_t n = varint(); Bytes o(b.begin() + i, b.begin() + i + n); i += n; return o; }
};

ParsedTx parse_tx(const Bytes& b) {
    ParsedTx t;
    Reader r{b};
    t.version = static_cast<uint16_t>(r.le(2));
    t.type = static_cast<uint16_t>(r.le(2));
    EXPECT_EQ(r.varint(), 1u);
    for (int k = 0; k < 32; ++k) EXPECT_EQ(r.le(1), 0u);
    EXPECT_EQ(r.le(4), 0xffffffffu);
    t.script_sig = r.str();
    EXPECT_EQ(r.le(4), 0xffffffffu);
    const uint64_t n = r.varint();
    for (uint64_t k = 0; k < n; ++k) { Out o; o.value = r.le(8); o.script = r.str(); t.outs.push_back(o); }
    t.locktime = static_cast<uint32_t>(r.le(4));
    if (t.version >= 3 && t.type != 0) t.payload = r.str();
    EXPECT_EQ(r.i, b.size()) << "trailing bytes after the coinbase";
    return t;
}

// Independent serializer: the expected coinbase bytes from hand amounts.
Bytes mirror_tx(const Bytes& script_sig, const std::vector<Out>& outs, const Bytes& payload) {
    Bytes b;
    auto le = [&](uint64_t v, int n) { for (int k = 0; k < n; ++k) b.push_back(static_cast<unsigned char>(v >> (8 * k))); };
    auto vi = [&](uint64_t v) { if (v < 0xfd) le(v, 1); else { b.push_back(0xfd); le(v, 2); } };
    auto vs = [&](const Bytes& s) { vi(s.size()); b.insert(b.end(), s.begin(), s.end()); };
    const bool cbtx = !payload.empty();
    le(cbtx ? 3 : 1, 2); le(cbtx ? 5 : 0, 2);
    vi(1); b.insert(b.end(), 32, 0x00); le(0xffffffffu, 4); vs(script_sig); le(0xffffffffu, 4);
    vi(outs.size());
    for (const auto& o : outs) { le(o.value, 8); vs(o.script); }
    le(0, 4);
    if (cbtx) vs(payload);
    return b;
}

Bytes op_return(const uint256& ref_hash, uint64_t nonce) {
    Bytes s = {0x6a, 0x28};
    s.insert(s.end(), ref_hash.data(), ref_hash.data() + 32);
    for (int k = 0; k < 8; ++k) s.push_back(static_cast<unsigned char>(nonce >> (8 * k)));
    return s;
}

uint256 sha256d(const Bytes& b) { return Hash(std::span<const unsigned char>(b.data(), b.size())); }

template <typename F>
std::string invalid_arg_text(F&& fn) {
    try { fn(); } catch (const std::invalid_argument& e) { return e.what(); }
    return "<no std::invalid_argument>";
}

// ── the 3-miner scene ────────────────────────────────────────────────────────
//   g(A, bits 0x1d00ffff, donation 0) <- s1(B, 0x1c00ffff, donation 0x0100)
//   <- s2(C, 0x1b00ffff, donation 0) ; miner D mints on s2.
// v36 window (from the PARENT s2): depth0 C, depth1 B, depth2 A.
// Hand goldens (CHAIN_LENGTH 4320):
//   w[A] = 281113789798590, w[B] = 71730048656397056,
//   w[C] = 18446744073709551615 (= 2^64 - 1), total = 18519036534773312445 (> 2^64),
//   donation weight = 281298617565184.
struct Scene {
    SyntheticV36Chain sc;
    uint256 g, s1, s2;
    Scene() {
        g  = sc.add(0x01, uint256(), 0x1d00ffffu, 0x1d00ffffu, 1699999900, h160_uniform(0xaa), 0,      1);
        s1 = sc.add(0x02, g,         0x1c00ffffu, 0x1d00ffffu, 1699999920, h160_uniform(0xbb), 0x0100, 2);
        s2 = sc.add(0x03, s1,        0x1b00ffffu, 0x1d00ffffu, 1699999940, h160_uniform(0xcc), 0,      3);
    }
};

const char* SCENE_W_A = "ffabe79518be";          // 281113789798590
const char* SCENE_W_B = "fed61965e2d300";        // 71730048656397056
const char* SCENE_TOTAL = "10100d59c3da4ebbd";   // 18519036534773312445

bitcoin_family::coin::SmallBlockHeaderType min_header() {
    bitcoin_family::coin::SmallBlockHeaderType h;
    h.m_version = 536870912;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000000000aa");
    h.m_timestamp = PAST_TS + 5;
    h.m_bits = 0x1b00ffffu;   // block target far harder than the share target: not a block
    h.m_nonce = 0xdeadbeefu;
    return h;
}

dash::producer::ProspectiveShareInfo info_for(const uint256& prev, uint32_t absheight) {
    dash::producer::ProspectiveShareInfo info;
    info.prev_hash = prev;
    info.coinbase = {0x03, 0x01, 0x02, 0x03};
    info.nonce = 7;
    info.pubkey_hash = h160_uniform(0xdd);
    info.subsidy = SUBSIDY;
    info.donation = 0;
    info.desired_version = 36;
    info.max_bits = 0x1d00ffffu;
    info.bits = 0x1d00ffffu;
    info.timestamp = PAST_TS;
    info.absheight = absheight;
    info.abswork = uint128(0x100010001ull * absheight);
    return info;
}

// The expected outputs of the scene coinbase.
std::vector<Out> scene_outs(uint64_t a, uint64_t b, uint64_t c, const std::vector<Out>& payments,
                            uint64_t don, const uint256& ref_hash) {
    std::vector<Out> o = {{a, p2pkh(0xaa)}, {b, p2pkh(0xbb)}, {c, p2pkh(0xcc)}};
    o.insert(o.end(), payments.begin(), payments.end());
    o.push_back({don, donation()});
    o.push_back({0, op_return(ref_hash, NONCE64)});
    return o;
}

uint64_t sum_values(const std::vector<Out>& outs) {
    uint64_t s = 0; for (const auto& o : outs) s += o.value; return s;
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// 1-2. The ONE exact muldiv (payout_muldiv.hpp v36_worker_amount)
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Muldiv, WideEqualsNarrowOnUint64Domain) {
    using dash::payout::payout_share;
    using dash::payout::v36_worker_amount;
    // The known answers pinned for payout_share(..., v36=true).
    EXPECT_EQ(v36_worker_amount(u288(1), 100, u288(4)), 25u);
    EXPECT_EQ(v36_worker_amount(u288(3), 100, u288(4)), 75u);
    EXPECT_EQ(v36_worker_amount(u288(4), 100, u288(4)), 100u);
    EXPECT_EQ(v36_worker_amount(u288(0), 100, u288(4)), 0u);
    EXPECT_EQ(v36_worker_amount(u288(1ull << 40), 1ull << 40, u288(1ull << 40)), 1ull << 40);

    const uint64_t U64MAX = std::numeric_limits<uint64_t>::max();
    const uint64_t totals[] = {1, 2, 50, 100, 37938, 1000000ULL, (1ULL << 30), (1ULL << 40),
                               (1ULL << 62), U64MAX};
    const uint64_t payouts[] = {0, 1, 100, 5000000000ULL, (1ULL << 40), (1ULL << 50) - 1};
    int compared = 0;
    for (uint64_t total : totals) {
        const uint64_t weights[] = {0, 1, total / 2, total - 1, total};
        for (uint64_t w : weights)
            for (uint64_t wp : payouts) {
                ASSERT_EQ(v36_worker_amount(u288(w), wp, u288(total)), payout_share(w, wp, total, true))
                    << "w=" << w << " wp=" << wp << " total=" << total;
                ++compared;
            }
    }
    uint64_t s = 0x9E3779B97F4A7C15ULL;
    auto next = [&] { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; };
    for (int i = 0; i < 50000; ++i) {
        uint64_t total = next(); if (total == 0) total = 1;
        const uint64_t w = next() % total;
        const uint64_t wp = next() & ((1ULL << 50) - 1);
        ASSERT_EQ(v36_worker_amount(u288(w), wp, u288(total)), payout_share(w, wp, total, true))
            << "fuzz i=" << i;
        ++compared;
    }
    EXPECT_EQ(compared, 300 + 50000);
}

TEST(DashV36Muldiv, ExactAbove64Bits) {
    using dash::payout::v36_worker_amount;
    // w = 2^70, total = 3*2^70 + 1, P = 5e8 -> floor(5e8 * 2^70 / (3*2^70+1)) = 166666666.
    const uint288 w = pow2(70);
    const uint288 t = pow2(70) * 3 + 1;
    EXPECT_EQ(v36_worker_amount(w, 500000000ull, t), 166666666u);
    // w = total (wide) -> the whole payout; w = 0 -> 0.
    const uint288 big = pow2(287) + 12345;
    EXPECT_EQ(v36_worker_amount(big, (1ull << 50) - 1, big), (1ull << 50) - 1);
    EXPECT_EQ(v36_worker_amount(uint288(), 500000000ull, big), 0u);
    // A 2^200-scale weight against a 2^200-scale total (uint288 * uint64 would
    // not fit a 128-bit intermediate): 7/8 of the payout, exactly.
    EXPECT_EQ(v36_worker_amount(pow2(200) * 7, 800, pow2(200) * 8), 700u);
    // Guards: zero total throws; weight > total with an out-of-range quotient throws.
    EXPECT_THROW(v36_worker_amount(u288(1), 1, uint288()), std::invalid_argument);
    EXPECT_THROW(v36_worker_amount(pow2(100), 1, u288(1)), std::overflow_error);
}

// ═════════════════════════════════════════════════════════════════════════════
// 3-6. The ONE amounts rule (pplns_v36.hpp compute_v36_amounts)
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Amounts, ThreeMinerFullWeightNoFinder) {
    std::map<Bytes, uint288> w = {{p2pkh(0xaa), u288(30)}, {p2pkh(0xbb), u288(10)}, {p2pkh(0xcc), u288(5)}};
    auto r = dash::compute_v36_amounts(w, u288(50), 500000000ull, donation());
    const std::map<Bytes, uint64_t> want = {
        {p2pkh(0xaa), 300000000ull}, {p2pkh(0xbb), 100000000ull}, {p2pkh(0xcc), 50000000ull}};
    EXPECT_EQ(r.amounts, want);            // full weight: no 49/50 scaling, no finder entry
    EXPECT_EQ(r.donation_amount, 50000000ull);
    EXPECT_EQ(r.pplns_sum, 450000000ull);
    EXPECT_EQ(r.remainder, 50000000ull);
}

TEST(DashV36Amounts, RoundingRemainderToDonation) {
    std::map<Bytes, uint288> w = {{p2pkh(0xaa), u288(1)}, {p2pkh(0xbb), u288(1)}, {p2pkh(0xcc), u288(1)}};
    auto r = dash::compute_v36_amounts(w, u288(3), 100, donation());
    for (uint8_t b : {0xaa, 0xbb, 0xcc}) EXPECT_EQ(r.amounts.at(p2pkh(b)), 33u);
    EXPECT_EQ(r.donation_amount, 1u);      // rounding remainder, no floor deduction
}

TEST(DashV36Amounts, DonationFloorExactlyOneSat) {
    {
        std::map<Bytes, uint288> w = {{p2pkh(0xaa), u288(1)}, {p2pkh(0xbb), u288(1)}};
        auto r = dash::compute_v36_amounts(w, u288(2), 1000, donation());
        EXPECT_EQ(r.amounts.at(p2pkh(0xaa)), 500u);
        EXPECT_EQ(r.amounts.at(p2pkh(0xbb)), 499u);   // tie on amount -> larger script pays the sat
        EXPECT_EQ(r.donation_amount, 1u);
    }
    {
        // Single miner, worker_payout 1: the miner's only satoshi moves to the
        // donation and the zero miner entry is dropped.
        std::map<Bytes, uint288> w = {{p2pkh(0xaa), u288(1)}};
        auto r = dash::compute_v36_amounts(w, u288(1), 1, donation());
        EXPECT_TRUE(r.amounts.empty());
        EXPECT_EQ(r.donation_amount, 1u);
    }
    {
        // worker_payout 0 (payments consumed the subsidy): nothing to floor.
        std::map<Bytes, uint288> w = {{p2pkh(0xaa), u288(1)}};
        auto r = dash::compute_v36_amounts(w, u288(1), 0, donation());
        EXPECT_TRUE(r.amounts.empty());
        EXPECT_EQ(r.donation_amount, 0u);
    }
}

TEST(DashV36Amounts, DonationKeyedMinerMergesAndIsNeverFloorCandidate) {
    // A weight keyed on the donation script itself (a share whose payout
    // address IS the donation address): its amount merges into the single
    // donation output, and the floor sat comes from a real miner, not from it.
    std::map<Bytes, uint288> w = {{donation(), u288(10)}, {p2pkh(0xaa), u288(20)}, {p2pkh(0xbb), u288(20)}};
    auto r = dash::compute_v36_amounts(w, u288(50), 100, donation());
    EXPECT_EQ(r.amounts.count(donation()), 0u);
    EXPECT_EQ(r.amounts.at(p2pkh(0xaa)), 40u);
    EXPECT_EQ(r.amounts.at(p2pkh(0xbb)), 39u);        // remainder 0 -> floor from B (tie, larger script)
    EXPECT_EQ(r.donation_amount, 21u);                // 20 (merged) + 1 (floor)
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. Decayed weights: walk == hand integer goldens == ring buffer
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36DecayedWeights, WalkMatchesHandIntegerGoldenAndRing) {
    IdentityGuard guard;
    (void)iso_params();
    ASSERT_EQ(SharechainConfig::chain_length(), 4320u);

    // decay constants (hand: 2^40 - 2^40*693147 // (10^6*1080) and iterates).
    EXPECT_EQ(dash::v36_pplns::decay_per(4320), 1098805958160ull);
    const uint64_t fp_gold[4] = {1099511627776ull, 1098805958160ull, 1098100741444ull, 1097395977338ull};
    uint64_t fp = dash::v36_pplns::DECAY_SCALE;
    for (int d = 0; d < 4; ++d) {
        EXPECT_EQ(fp, fp_gold[d]) << "depth " << d;
        fp = dash::v36_pplns::mul_shift_precision(fp, dash::v36_pplns::decay_per(4320));
    }
    dash::DensePPLNSWindow::init_decay_table(4320);
    for (int d = 0; d < 4; ++d)
        EXPECT_EQ(dash::DensePPLNSWindow::s_decay_table[d], fp_gold[d]) << "ring table depth " << d;

    // Chain (deepest first): s0 B'(0x1c7fffff) <- s1 A(0x1d00ffff) <- s2 B(0x1c00ffff, don 0x1234)
    // <- s3 C(0x1b00ffff). Walk from s3: C, B(0x1234), A, B'.
    SyntheticV36Chain sc;
    auto s0 = sc.add(0x10, uint256(), 0x1c7fffffu, 0x1d00ffffu, 1, h160_uniform(0xbb));
    auto s1 = sc.add(0x11, s0, 0x1d00ffffu, 0x1d00ffffu, 2, h160_uniform(0xaa));
    auto s2 = sc.add(0x12, s1, 0x1c00ffffu, 0x1d00ffffu, 3, h160_uniform(0xbb), 0x1234);
    auto s3 = sc.add(0x13, s2, 0x1b00ffffu, 0x1d00ffffu, 4, h160_uniform(0xcc));

    auto walk = dash::v36_decayed_cumulative_weights(sc.chain, s3, 4320, dash::v36_pplns::unlimited_weight());
    // Hand goldens: decayed_att per depth = 281479271743489, 1098822724864,
    // 4289521474, 8573407094.
    EXPECT_EQ(walk.weights.size(), 3u);
    EXPECT_EQ(walk.weights.at(p2pkh(0xaa)), u288(281113789798590ull));
    EXPECT_EQ(walk.weights.at(p2pkh(0xbb)), u288(67452691610001290ull));
    EXPECT_EQ(walk.weights.at(p2pkh(0xcc)), u288(18446744073709551615ull));
    EXPECT_EQ(walk.total_weight, u288_hex("10102d49e0e171c47"));   // 18519598393007217735 > 2^64
    EXPECT_EQ(walk.total_donation_weight, u288(5120513897866240ull));

    // The v36 window rule (parent start, CHAIN_LENGTH, unlimited) is exactly
    // this walk; the chain is rooted, so a short height is accepted.
    auto win = dash::v36_pplns_window(sc.chain, s3);
    EXPECT_EQ(win.weights, walk.weights);
    EXPECT_EQ(win.total_weight, walk.total_weight);
    EXPECT_EQ(win.total_donation_weight, walk.total_donation_weight);

    // Ring buffer (what think() primes the tracker cache with) == walk.
    dash::DensePPLNSWindow ring;
    ring.rebuild(sc.chain, s3, 4320);
    auto rw = ring.compute_v36_weights();
    EXPECT_EQ(rw.weights, walk.weights);
    EXPECT_EQ(rw.total_weight, walk.total_weight);
    EXPECT_EQ(rw.total_donation_weight, walk.total_donation_weight);
}

TEST(DashV36DecayedWeights, FullWindowRingEqualsWalk) {
    IdentityGuard guard;
    (void)iso_params();
    // 4400 shares (> CHAIN_LENGTH): varied bits, donations (incl. 0xffff) and
    // 7 miners. The window truncates at 4320 shares; ring and walk must agree
    // bit for bit over the whole table (iterative truncation vs stored table).
    const uint32_t bits_set[4] = {0x1d00ffffu, 0x1c7fffffu, 0x1c00ffffu, 0x1b00ffffu};
    const uint16_t don_set[4] = {0, 0x0100, 0x1234, 0xffff};
    SyntheticV36Chain sc;
    uint256 prev;
    uint64_t r = 12345;
    for (uint32_t i = 0; i < 4400; ++i) {
        r = r * 6364136223846793005ULL + 1442695040888963407ULL;
        prev = sc.add_hash(v36_index_hash(i), prev, bits_set[(r >> 33) & 3], 0x1d00ffffu, i,
                           h160_uniform(static_cast<uint8_t>(0x10 + ((r >> 40) % 7))),
                           don_set[(r >> 50) & 3]);
    }
    auto walk = dash::v36_pplns_window(sc.chain, prev);
    dash::DensePPLNSWindow ring;
    ring.rebuild(sc.chain, prev, 4320);
    ASSERT_EQ(ring.size(), 4320);
    auto rw = ring.compute_v36_weights();
    EXPECT_EQ(rw.weights, walk.weights);
    EXPECT_EQ(rw.total_weight, walk.total_weight);
    EXPECT_EQ(rw.total_donation_weight, walk.total_donation_weight);
    EXPECT_EQ(walk.weights.size(), 7u);
}

TEST(DashV36DecayedWeights, TrackerWindowQueriesThePrimedCacheKey) {
    IdentityGuard guard;
    auto params = iso_params();
    // The live tracker's v36_pplns_window must read the cache under the key
    // think() primes: (prev_hash, CHAIN_LENGTH, unlimited). Fill the cache
    // under that key, then change a window share WITHOUT invalidating the
    // cache: the tracker form returns the cached value (same key), the free
    // form recomputes.
    dash::ShareTracker tracker;
    auto add16 = [&](uint8_t tag, const uint256& prev, uint32_t bits, uint8_t pkh) {
        auto* s = new dash::DashShare();
        s->m_hash = v36_tag_hash(tag, 0x16);
        s->m_prev_hash = prev;
        s->m_bits = bits; s->m_max_bits = 0x1d00ffffu;
        s->m_pubkey_hash = h160_uniform(pkh);
        const uint256 h = s->m_hash;
        tracker.chain.add(s);
        return h;
    };
    auto g = add16(1, uint256(), 0x1d00ffffu, 0xaa);
    auto s1 = add16(2, g, 0x1c00ffffu, 0xbb);
    auto s2 = add16(3, s1, 0x1b00ffffu, 0xcc);

    const auto primed = tracker.get_v36_decayed_cumulative_weights(
        s2, static_cast<int32_t>(SharechainConfig::chain_length()), dash::v36_pplns::unlimited_weight());
    EXPECT_EQ(tracker.v36_pplns_window(s2).weights, dash::v36_pplns_window(tracker.chain, s2).weights);

    tracker.chain.get_share(s1).invoke([](auto* obj) { obj->m_donation = 0x4000; });
    const auto via_tracker = tracker.v36_pplns_window(s2);
    const auto fresh = dash::v36_pplns_window(tracker.chain, s2);
    EXPECT_EQ(via_tracker.weights, primed.weights);
    EXPECT_EQ(via_tracker.total_donation_weight, primed.total_donation_weight);
    EXPECT_NE(fresh.total_donation_weight, primed.total_donation_weight);

    // generate_share_transaction(DashV36Share) takes the tracker's cached path.
    dash::DashV36Share v;
    v.m_prev_hash = s2;
    v.m_coinbase = BaseScript(Bytes{0x01, 0x02});
    v.m_subsidy = SUBSIDY;
    dash::coin::GentxCoinbase gc_tracker, gc_free;
    dash::generate_share_transaction(v, tracker, params, &gc_tracker);
    struct FreeView { dash::ShareChain& chain; } fv{tracker.chain};
    dash::generate_share_transaction(v, fv, params, &gc_free);
    EXPECT_NE(gc_tracker.bytes, gc_free.bytes);   // cached (pre-change) vs recomputed window
}

// ═════════════════════════════════════════════════════════════════════════════
// 8-15. The v36 generation transaction (verifier + producer)
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36Gentx, ThreeMinerWindowGoldenNoPayments) {
    IdentityGuard guard;
    auto params = iso_params();
    Scene sn;

    auto w = dash::v36_pplns_window(sn.sc.chain, sn.s2);
    EXPECT_EQ(w.weights.at(p2pkh(0xaa)), u288_hex(SCENE_W_A));
    EXPECT_EQ(w.weights.at(p2pkh(0xbb)), u288_hex(SCENE_W_B));
    EXPECT_EQ(w.weights.at(p2pkh(0xcc)), u288(18446744073709551615ull));
    EXPECT_EQ(w.total_weight, u288_hex(SCENE_TOTAL));

    auto built = dash::producer::build_share_v36(sn.sc.chain, params, info_for(sn.s2, 4),
                                                 min_header(), NONCE64, /*check_pow=*/false);
    V36ChainView view{sn.sc.chain};
    dash::coin::GentxCoinbase gc;
    ASSERT_EQ(dash::generate_share_transaction(built.share, view, params, &gc), built.gentx_hash);

    // Hand amounts: A 7589, B 1936657, C 498048158, donation 7596 (Σ = 5e8).
    const auto want = scene_outs(7589, 1936657, 498048158, {}, 7596, built.ref_hash);
    ParsedTx tx = parse_tx(gc.bytes);
    EXPECT_EQ(tx.version, 1u);
    EXPECT_EQ(tx.type, 0u);
    EXPECT_EQ(tx.script_sig, (Bytes{0x03, 0x01, 0x02, 0x03}));
    EXPECT_EQ(tx.outs, want);
    EXPECT_EQ(tx.locktime, 0u);
    EXPECT_EQ(sum_values(tx.outs), SUBSIDY);
    // No finder output: D (the minting miner) is absent.
    for (const auto& o : tx.outs) EXPECT_NE(o.script, p2pkh(0xdd));
    // Byte-exact vs the independent mirror, and txid.
    EXPECT_EQ(hexs(gc.bytes), hexs(mirror_tx(tx.script_sig, want, {})));
    EXPECT_EQ(sha256d(gc.bytes), built.gentx_hash);
    EXPECT_EQ(built.ref_hash, dash::compute_v36_ref_hash(params, built.share));
}

TEST(DashV36Gentx, ThreeMinerWindowWithMasternodePayments) {
    IdentityGuard guard;
    auto params = iso_params();
    Scene sn;
    auto info = info_for(sn.s2, 4);
    info.packed_payments = {raw_payment(p2pkh(0xd1), 150000000), raw_payment(p2pkh(0xd2), 100000000)};
    info.payment_amount = 999;   // NOT consulted: the emitted payments are
    auto built = dash::producer::build_share_v36(sn.sc.chain, params, info, min_header(), NONCE64, false);

    V36ChainView view{sn.sc.chain};
    dash::coin::GentxCoinbase gc;
    ASSERT_EQ(dash::generate_share_transaction(built.share, view, params, &gc), built.gentx_hash);
    // worker_payout = 5e8 - 2.5e8 = 2.5e8 -> A 3794, B 968328, C 249024079, donation 3799.
    const auto want = scene_outs(3794, 968328, 249024079,
                                 {{150000000, p2pkh(0xd1)}, {100000000, p2pkh(0xd2)}}, 3799,
                                 built.ref_hash);
    EXPECT_EQ(parse_tx(gc.bytes).outs, want);
    EXPECT_EQ(sum_values(want), SUBSIDY);
    EXPECT_EQ(hexs(gc.bytes), hexs(mirror_tx(info.coinbase, want, {})));
}

TEST(DashV36Gentx, SuperblockPayeesDeductedEmittedOnly) {
    IdentityGuard guard;
    auto params = iso_params();
    Scene sn;
    auto info = info_for(sn.s2, 4);
    const Bytes platform = {0x6a, 0x04, 0x01, 0x02, 0x03, 0x04};
    dash::PackedPayment undecodable; undecodable.m_payee = "script:76a914"; undecodable.m_amount = 70000000;
    info.packed_payments = {
        raw_payment(p2pkh(0xd1), 100000000),   // emitted
        raw_payment(p2pkh(0xd3), 0),           // amount 0: dropped
        raw_payment(platform, 5000000),        // "!"-raw script: emitted
        undecodable,                           // undecodable: dropped, NOT deducted
    };
    info.coinbase_payload = {0x02, 0x00, 0xaa, 0xbb, 0xcc};   // DIP4 CbTx
    auto built = dash::producer::build_share_v36(sn.sc.chain, params, info, min_header(), NONCE64, false);

    V36ChainView view{sn.sc.chain};
    dash::coin::GentxCoinbase gc;
    ASSERT_EQ(dash::generate_share_transaction(built.share, view, params, &gc), built.gentx_hash);
    // worker_payout = 5e8 - (1e8 + 5e6) = 3.95e8 -> A 5995, B 1529959, C 393458044, donation 6002.
    const auto want = scene_outs(5995, 1529959, 393458044,
                                 {{100000000, p2pkh(0xd1)}, {5000000, platform}}, 6002,
                                 built.ref_hash);
    ParsedTx tx = parse_tx(gc.bytes);
    EXPECT_EQ(tx.version, 3u);
    EXPECT_EQ(tx.type, 5u);
    EXPECT_EQ(tx.payload, info.coinbase_payload);
    EXPECT_EQ(tx.outs, want);
    EXPECT_EQ(sum_values(want), SUBSIDY);
    EXPECT_EQ(hexs(gc.bytes), hexs(mirror_tx(info.coinbase, want, info.coinbase_payload)));
    // The CbTx share passes the v36 verifier with the outer-payload framing.
    EXPECT_EQ(dash::share_init_verify(built.share, params, false), built.share.m_hash);
    EXPECT_EQ(dash::g_last_gentx_hash, built.gentx_hash);
}

TEST(DashV36Gentx, WindowStartsAtParent) {
    IdentityGuard guard;
    auto params = iso_params();
    // v36: the parent's miner (C) IS paid.
    Scene sn;
    auto built = dash::producer::build_share_v36(sn.sc.chain, params, info_for(sn.s2, 4),
                                                 min_header(), NONCE64, false);
    V36ChainView view{sn.sc.chain};
    dash::coin::GentxCoinbase gc;
    dash::generate_share_transaction(built.share, view, params, &gc);
    bool c_paid = false, d_paid = false;
    for (const auto& o : parse_tx(gc.bytes).outs) {
        c_paid |= (o.script == p2pkh(0xcc));
        d_paid |= (o.script == p2pkh(0xdd));
    }
    EXPECT_TRUE(c_paid);
    EXPECT_FALSE(d_paid);

    // v16 on the equivalent v16 chain: the window starts at the GRANDPARENT,
    // so C is absent and the minting miner D takes the 2% finder fee.
    dash::ShareChain chain16;
    auto add16 = [&](uint8_t tag, const uint256& prev, uint32_t bits, uint8_t pkh, uint16_t don) {
        auto* s = new dash::DashShare();
        s->m_hash = v36_tag_hash(tag, 0x16);
        s->m_prev_hash = prev;
        s->m_bits = bits; s->m_max_bits = 0x1d00ffffu;
        s->m_pubkey_hash = h160_uniform(pkh);
        s->m_donation = don;
        const uint256 h = s->m_hash;
        chain16.add(s);
        return h;
    };
    auto g = add16(1, uint256(), 0x1d00ffffu, 0xaa, 0);
    auto s1 = add16(2, g, 0x1c00ffffu, 0xbb, 0x0100);
    auto s2 = add16(3, s1, 0x1b00ffffu, 0xcc, 0);
    auto info16 = info_for(s2, 4);
    info16.desired_version = 16;
    auto built16 = dash::producer::build_share(chain16, params, info16, min_header(), NONCE64, false);
    struct View16 { dash::ShareChain& chain; } v16{chain16};
    dash::coin::GentxCoinbase gc16;
    ASSERT_EQ(dash::generate_share_transaction(built16.share, v16, params, &gc16), built16.gentx_hash);
    c_paid = d_paid = false;
    for (const auto& o : parse_tx(gc16.bytes).outs) {
        c_paid |= (o.script == p2pkh(0xcc));
        d_paid |= (o.script == p2pkh(0xdd));
    }
    EXPECT_FALSE(c_paid);
    EXPECT_TRUE(d_paid);
}

TEST(DashV36Gentx, ProducerEqualsVerifierOnSameWindow) {
    IdentityGuard guard;
    auto params = iso_params();
    Scene sn;
    auto info = info_for(sn.s2, 4);
    info.packed_payments = {raw_payment(p2pkh(0xd1), 150000000)};
    info.other_transaction_hashes = {v36_tag_hash(0x71), v36_tag_hash(0x72)};
    auto built = dash::producer::build_share_v36(sn.sc.chain, params, info, min_header(), NONCE64, false);

    // Donation / const_ending on the private/isolated profile: the P2PKH DONATION_SCRIPT.
    ASSERT_EQ(params.donation_script_func(36), donation());
    const Bytes const_ending = dash::compute_gentx_before_refhash(donation());

    // Producer bytes (build_gentx_v36 on the same window) == verifier bytes.
    auto w = dash::v36_pplns_window(sn.sc.chain, sn.s2);
    auto pg = dash::producer::build_gentx_v36(info, w, built.ref_hash, NONCE64, params);
    V36ChainView view{sn.sc.chain};
    dash::coin::GentxCoinbase gc;
    EXPECT_EQ(dash::generate_share_transaction(built.share, view, params, &gc), built.gentx_hash);
    EXPECT_EQ(gc.bytes, pg.bytes);
    EXPECT_EQ(pg.txid, built.gentx_hash);
    // Nonce slot contract: ref_hash at prefix_len, nonce at prefix_len + 32.
    EXPECT_EQ(Bytes(pg.bytes.begin() + pg.prefix_len, pg.bytes.begin() + pg.prefix_len + 32),
              Bytes(built.ref_hash.data(), built.ref_hash.data() + 32));
    EXPECT_EQ(static_cast<int>(pg.bytes[pg.prefix_len + 32]), 0x01);   // LE64(NONCE64) low byte
    EXPECT_TRUE(std::equal(const_ending.rbegin(), const_ending.rend(),
                           Bytes(pg.bytes.begin(), pg.bytes.begin() + pg.prefix_len).rbegin()));

    // The share passes the v36 verifier; its committed gentx is the produced one;
    // the payout commitment holds on the same chain.
    EXPECT_EQ(dash::share_init_verify(built.share, params, false), built.share.m_hash);
    EXPECT_EQ(dash::g_last_gentx_hash, built.gentx_hash);
    EXPECT_NO_THROW(dash::verify_payout_commitment(built.share, view, params, dash::g_last_gentx_hash));
    EXPECT_EQ(dash::check_hash_link(built.share.m_hash_link,
                                    dash::v36_hash_link_data(built.ref_hash, NONCE64,
                                                             built.share.m_coinbase_payload_outer),
                                    const_ending),
              built.gentx_hash);
    // merkle_link over the job tx set (v36::MerkleLink).
    EXPECT_EQ(built.share.m_merkle_link.m_branch.size(), 2u);
}

TEST(DashV36Gentx, WrongCoinbaseRejected) {
    IdentityGuard guard;
    auto params = iso_params();
    Scene sn;
    auto built = dash::producer::build_share_v36(sn.sc.chain, params, info_for(sn.s2, 4),
                                                 min_header(), NONCE64, false);
    V36ChainView view{sn.sc.chain};
    const Bytes const_ending = dash::compute_gentx_before_refhash(params.donation_script_func(36));

    // (a) A peer share whose coinbase pays only its submitter.
    {
        dash::DashV36Share s = built.share;
        dash::CumulativeWeights self_pay;
        self_pay.weights[p2pkh(0xdd)] = u288(1);
        self_pay.total_weight = u288(1);
        auto g = dash::build_v36_gentx(s.m_coinbase.m_data, s.m_coinbase_payload.m_data, s.m_subsidy,
                                       s.m_packed_payments, self_pay, built.ref_hash, NONCE64, params);
        s.m_hash_link = dash::producer::prefix_to_hash_link<dash::v36::V36HashLinkType>(
            Bytes(g.bytes.begin(), g.bytes.begin() + g.prefix_len), const_ending);
        dash::share_init_verify(s, params, false);
        ASSERT_EQ(dash::g_last_gentx_hash, g.txid);
        const std::string e = invalid_arg_text([&] {
            dash::verify_payout_commitment(s, view, params, dash::g_last_gentx_hash); });
        EXPECT_EQ(e.substr(0, 14), "GENTX-MISMATCH") << e;
    }
    // (b) A tampered subsidy (the share claims more than its coinbase pays out).
    {
        dash::DashV36Share s = built.share;
        s.m_subsidy += 1;
        dash::share_init_verify(s, params, false);
        const std::string e = invalid_arg_text([&] {
            dash::verify_payout_commitment(s, view, params, dash::g_last_gentx_hash); });
        EXPECT_EQ(e.substr(0, 14), "GENTX-MISMATCH") << e;
    }
    // (c) A relabelled pubkey_hash is not a payout change in v36 (no finder
    //     output), so the commitment still holds — but the share identity
    //     moves (ref_hash -> gentx -> merkle root -> X11), so the relabelled
    //     share no longer carries the original PoW.
    {
        dash::DashV36Share s = built.share;
        s.m_pubkey_hash = h160_uniform(0xee);
        const uint256 h = dash::share_init_verify(s, params, false);
        EXPECT_NO_THROW(dash::verify_payout_commitment(s, view, params, dash::g_last_gentx_hash));
        EXPECT_NE(h, built.share.m_hash);
    }
    // (d) The window changes under an unchanged share: a window share's donation.
    {
        dash::share_init_verify(built.share, params, false);
        const uint256 committed = dash::g_last_gentx_hash;
        EXPECT_NO_THROW(dash::verify_payout_commitment(built.share, view, params, committed));
        sn.sc.chain.get_share(sn.s1).invoke([](auto* obj) { obj->m_donation = 0; });
        const std::string e = invalid_arg_text([&] {
            dash::verify_payout_commitment(built.share, view, params, committed); });
        EXPECT_EQ(e.substr(0, 14), "GENTX-MISMATCH") << e;
    }
}

TEST(DashV36Gentx, GenesisPaysDonationOnlyNoFinder) {
    IdentityGuard guard;
    auto params = iso_params();
    SyntheticV36Chain empty;
    auto built = dash::producer::build_share_v36(empty.chain, params, info_for(uint256(), 1),
                                                 min_header(), NONCE64, false);
    V36ChainView view{empty.chain};
    dash::coin::GentxCoinbase gc;
    ASSERT_EQ(dash::generate_share_transaction(built.share, view, params, &gc), built.gentx_hash);
    const std::vector<Out> want = {{SUBSIDY, donation()}, {0, op_return(built.ref_hash, NONCE64)}};
    EXPECT_EQ(parse_tx(gc.bytes).outs, want);
    EXPECT_NO_THROW(dash::verify_payout_commitment(built.share, view, params, built.gentx_hash));
}

TEST(DashV36Gentx, UnrootedShortChainThrows) {
    IdentityGuard guard;
    auto params = iso_params();
    SyntheticV36Chain sc;
    // g's parent is unknown (non-null): the chain is unrooted and only 2 deep.
    auto g = sc.add(0x01, v36_tag_hash(0x99), 0x1d00ffffu, 0x1d00ffffu, 1, h160_uniform(0xaa));
    auto s1 = sc.add(0x02, g, 0x1d00ffffu, 0x1d00ffffu, 2, h160_uniform(0xbb));
    const std::string want = "share chain not long enough for PPLNS verification (height=2 need=4320)";
    EXPECT_EQ(invalid_arg_text([&] { dash::v36_pplns_window(sc.chain, s1); }), want);
    EXPECT_EQ(invalid_arg_text([&] {
        dash::producer::build_share_v36(sc.chain, params, info_for(s1, 3), min_header(), NONCE64, false);
    }), want);
    dash::DashV36Share v;
    v.m_prev_hash = s1;
    V36ChainView view{sc.chain};
    EXPECT_EQ(invalid_arg_text([&] { dash::generate_share_transaction(v, view, params); }), want);
}

// ═════════════════════════════════════════════════════════════════════════════
// 16. Drift fence across the three consumers of the amounts rule
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36CoinbaseBuilder, V36ArmEqualsSharedAmounts) {
    IdentityGuard guard;
    auto params = iso_params();
    params.current_share_version = 36;   // select the v36 arm
    // On the private/isolated profile the v36 donation is the P2PKH script the
    // builder pays.
    ASSERT_EQ(params.donation_script_func(36), donation());

    using W64 = std::map<Bytes, uint64_t>;
    struct Case { W64 w; uint64_t total; uint64_t payout; };
    const std::vector<Case> cases = {
        {{{p2pkh(0xaa), 30}, {p2pkh(0xbb), 10}, {p2pkh(0xcc), 5}}, 50, 500000000},
        {{{p2pkh(0xaa), 1}, {p2pkh(0xbb), 1}, {p2pkh(0xcc), 1}}, 3, 100},
        {{{p2pkh(0xaa), 1}, {p2pkh(0xbb), 1}}, 2, 1000},
        {{{donation(), 10}, {p2pkh(0xaa), 20}, {p2pkh(0xbb), 20}}, 50, 100},
    };
    for (size_t k = 0; k < cases.size(); ++k) {
        const auto& c = cases[k];
        auto outs = dash::coinbase::compute_dash_payouts(c.payout, {}, h160_uniform(0x07), c.w,
                                                         c.total, params);
        std::map<Bytes, uint288> wide;
        for (const auto& [s, v] : c.w) wide[s] = u288(v);
        auto a = dash::compute_v36_amounts(wide, u288(c.total), c.payout, donation());
        std::vector<Out> want;
        for (const auto& [s, v] : a.amounts) want.push_back({v, s});
        want.push_back({a.donation_amount, donation()});
        std::vector<Out> got;
        for (const auto& o : outs) got.push_back({o.amount, o.script});
        EXPECT_EQ(got, want) << "case " << k;
    }

    // The same chain through the stratum builder and through the v36 gentx:
    // identical outputs (weights < 2^64 so the builder's uint64 inputs hold).
    // (the Scene chain's weights exceed 2^64; this one stays below it)
    SyntheticV36Chain easy;
    auto g = easy.add(0x21, uint256(), 0x1d00ffffu, 0x1d00ffffu, 1, h160_uniform(0xaa));
    auto s1 = easy.add(0x22, g, 0x1d00ffffu, 0x1d00ffffu, 2, h160_uniform(0xbb), 0x0200);
    auto s2 = easy.add(0x23, s1, 0x1d00ffffu, 0x1d00ffffu, 3, h160_uniform(0xcc));
    auto w = dash::v36_pplns_window(easy.chain, s2);
    W64 w64;
    for (const auto& [s, v] : w.weights) w64[s] = v.GetLow64();
    ASSERT_TRUE(w.total_weight < pow2(64));
    std::vector<dash::coin::PackedPayment> pays = {{"!" + hexs(p2pkh(0xd1)), 150000000}};
    auto outs = dash::coinbase::compute_dash_payouts(SUBSIDY, pays, h160_uniform(0xdd), w64,
                                                     w.total_weight.GetLow64(), params);
    auto info = info_for(s2, 4);
    info.packed_payments = {raw_payment(p2pkh(0xd1), 150000000)};
    auto g36 = dash::producer::build_gentx_v36(info, w, uint256(), NONCE64, params);
    auto tx = parse_tx(g36.bytes);
    ASSERT_EQ(tx.outs.size(), outs.size() + 1);   // + OP_RETURN
    for (size_t k = 0; k < outs.size(); ++k) {
        EXPECT_EQ(tx.outs[k].value, outs[k].amount) << "output " << k;
        EXPECT_EQ(tx.outs[k].script, outs[k].script) << "output " << k;
    }
}
