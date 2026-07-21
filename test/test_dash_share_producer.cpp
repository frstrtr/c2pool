// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH share-producer KATs (mint campaign slice 1/3).
//
// Oracle: github.com/frstrtr/p2pool-dash (master, python2) — p2pool/data.py
// generate_transaction / get_share / get_ref_hash / prefix_to_hash_link,
// p2pool/dash/data.py FloatingInteger + tx_type, p2pool/networks/dash.py
// consensus constants. All pinned goldens below were derived by HAND-TRACING
// the oracle source with exact big-integer arithmetic (CPython ints /
// hashlib), NOT by running the oracle process — provisional values are marked
// [PROVISIONAL] and listed in the PR body for oracle-replay confirmation.
//
// Coverage (KAT plan a-e):
//   (a) producer share_info -> ref stream / ref_hash goldens + the built share
//       passing the in-tree verifier (share_init_verify / verify_share);
//   (b) built share round-trips the wire codec byte-identically (DashFormatter
//       + RawShare + load_share), with the oracle outer-payload framing pinned;
//   (c) retarget KATs at several chain positions (genesis, short, deep-uniform,
//       fast-pool low clamp, slow-pool high clamp);
//   (d) absheight/abswork accumulation incl. the mod 2^32 / 2^128 wrap;
//   (e) hash_link producer -> checker round trip across buffer boundaries.

#include <gtest/gtest.h>

#include <impl/dash/share_producer.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/coinbase_builder.hpp>   // coinbase::merkle_branches_raw (drift fence)

#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <vector>

namespace {

using dash::producer::ProducerJobInputs;
using dash::producer::ProspectiveShareInfo;

std::string hex_of(const uint256& h) {
    auto c = h.GetChars();
    return HexStr(std::span<const unsigned char>(c.data(), c.size()));
}

std::string hex_of_bytes(const std::vector<unsigned char>& v) {
    return HexStr(std::span<const unsigned char>(v.data(), v.size()));
}

uint256 h256_tag(uint8_t tag) {
    std::vector<unsigned char> v(32, 0x00);
    v[0] = tag; v[31] = 0xa5;
    return uint256(v);
}

uint160 h160_uniform(uint8_t byte) {
    return uint160(std::vector<unsigned char>(20, byte));
}

// Compact bits for the DASH mainnet MAX_TARGET (0xFFFF * 2^208, bdiff 1.0).
constexpr uint32_t BITS_DIFF1 = 0x1d00ffffu;

// ata(bits_to_target(0x1d00ffff)) = 2^256 // (0xFFFF*2^208 + 1) = 0x100010001.
const char* ATA_DIFF1_HEX = "100010001";

// Synthetic back-linked chain owning DashShares (test_dash_conformance idiom).
struct SyntheticChain {
    dash::ShareChain chain;

    uint256 add(uint8_t tag, const uint256& prev, uint32_t bits, uint32_t max_bits,
                uint32_t timestamp, const uint160& pkh, uint16_t donation = 0,
                uint32_t absheight = 0, uint128 abswork = uint128(),
                std::vector<uint256> new_tx_hashes = {}) {
        auto* s = new dash::DashShare();
        s->m_hash            = h256_tag(tag);
        s->m_prev_hash       = prev;
        s->m_bits            = bits;
        s->m_max_bits        = max_bits;
        s->m_timestamp       = timestamp;
        s->m_pubkey_hash     = pkh;
        s->m_donation        = donation;
        s->m_desired_version = 16;
        s->m_absheight       = absheight;
        s->m_abswork         = abswork;
        s->m_new_transaction_hashes = std::move(new_tx_hashes);
        const uint256 h = s->m_hash;
        chain.add(s);
        return h;
    }
};

// Build a uniform chain of `n` shares: fixed bits/max_bits, timestamps
// t0, t0+spacing, ...; returns the tip hash. Tags 1..n (n <= 250).
uint256 build_uniform_chain(SyntheticChain& sc, int n, uint32_t bits,
                            uint32_t t0, uint32_t spacing,
                            const uint160& pkh) {
    uint256 prev;
    for (int i = 0; i < n; ++i)
        prev = sc.add(static_cast<uint8_t>(1 + i), prev, bits, bits,
                      t0 + static_cast<uint32_t>(i) * spacing, pkh);
    return prev;
}

uint288 u288_hex(const char* h) { uint288 v; v.SetHex(h); return v; }
uint128 u128_hex(const char* h) { uint128 v; v.SetHex(h); return v; }

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// (c) Retarget — oracle data.py:135-145, networks/dash.py MAX_TARGET/SHARE_PERIOD
// /TARGET_LOOKBEHIND. Goldens: exact big-int trace of the oracle formula.
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashShareProducerRetarget, GenesisUsesMaxTarget) {
    const auto params = dash::make_coin_params(false);
    dash::ShareChain chain;

    // desired = MAX -> bits = max_bits = compact(MAX_TARGET) = 0x1d00ffff.
    auto st = dash::producer::compute_share_target(
        chain, uint256(), params.max_target, params);
    EXPECT_EQ(st.max_bits, BITS_DIFF1);
    EXPECT_EQ(st.bits, BITS_DIFF1);

    // desired = 1 -> clipped to pre_target3//30 = MAX//30 -> compact 0x1c088880
    // (oracle trace: 0xFFFF*2^208 // 30 = 0x08888000..., truncating compact).
    auto st2 = dash::producer::compute_share_target(
        chain, uint256(), uint256(1), params);
    EXPECT_EQ(st2.max_bits, BITS_DIFF1);
    EXPECT_EQ(st2.bits, 0x1c088880u);
}

TEST(DashShareProducerRetarget, ShortChainUsesMaxTarget) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    // 50 shares < TARGET_LOOKBEHIND (100) -> pre_target3 = MAX_TARGET.
    uint256 tip = build_uniform_chain(sc, 50, BITS_DIFF1, 1000000, 20, h160_uniform(0x11));

    auto st = dash::producer::compute_share_target(sc.chain, tip, uint256(1), params);
    EXPECT_EQ(st.max_bits, BITS_DIFF1);
    EXPECT_EQ(st.bits, 0x1c088880u);
}

TEST(DashShareProducerRetarget, DeepUniformDiff1ClampsToMax) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    // 100 diff-1 shares at perfect 20 s spacing. Oracle trace:
    //   attempts = 99*ata(diff1); time = 1980; aps = attempts//1980
    //   pre_target = 2^256//(20*aps)-1 = 0xffff000cffe7... > MAX (aps floor)
    //   pre2 within ±10% of prev max; pre3 = clip(.., MAX) = MAX -> 0x1d00ffff.
    uint256 tip = build_uniform_chain(sc, 100, BITS_DIFF1, 1000000, 20, h160_uniform(0x11));
    ASSERT_EQ(sc.chain.get_acc_height(tip), 100);

    auto st = dash::producer::compute_share_target(sc.chain, tip, params.max_target, params);
    EXPECT_EQ(st.max_bits, BITS_DIFF1);
    EXPECT_EQ(st.bits, BITS_DIFF1);
}

TEST(DashShareProducerRetarget, FastPoolClampsToNineTenths) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    // 100 shares at bits 0x1c1fffff, 2 s spacing (shares 10x too fast).
    // Oracle trace: pre_target < prev_max*9//10 -> clipped low.
    //   prev_max*9//10 = 0x1ccccbe666... -> TRUNCATING compact 0x1c1ccccb
    //   (a rounding-up implementation would emit 0x1c1ccccc — discriminating).
    // desired=1 -> bits = compact(pre_target3//30 = 0x00f5c287ae...) = 0x1c00f5c2.
    uint256 tip = build_uniform_chain(sc, 100, 0x1c1fffffu, 1000000, 2, h160_uniform(0x11));

    auto st = dash::producer::compute_share_target(sc.chain, tip, uint256(1), params);
    EXPECT_EQ(st.max_bits, 0x1c1ccccbu);
    EXPECT_EQ(st.bits, 0x1c00f5c2u);
}

TEST(DashShareProducerRetarget, SlowPoolClampsToElevenTenths) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    // 100 shares at bits 0x1c1fffff, 200 s spacing (10x too slow).
    // Oracle trace: pre_target > prev_max*11//10 -> clipped high.
    //   prev_max*11//10 = 0x2333321999... -> compact 0x1c233332.
    // desired = old target (within [pre3//30, pre3]) -> unchanged 0x1c1fffff.
    uint256 tip = build_uniform_chain(sc, 100, 0x1c1fffffu, 1000000, 200, h160_uniform(0x11));

    auto st = dash::producer::compute_share_target(
        sc.chain, tip, chain::bits_to_target(0x1c1fffffu), params);
    EXPECT_EQ(st.max_bits, 0x1c233332u);
    EXPECT_EQ(st.bits, 0x1c1fffffu);
}

// ═════════════════════════════════════════════════════════════════════════════
// share_info scalar mechanics: timestamp clip, far_share_hash, tx refs,
// (d) absheight/abswork accumulation.
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashShareProducerInfo, TimestampClip) {
    using dash::producer::clip_timestamp;
    // clip(desired, (prev+1, prev+2*SHARE_PERIOD-1)) — data.py:238-241, SP=20.
    EXPECT_EQ(clip_timestamp(900,  true, 1000, 20), 1001u);
    EXPECT_EQ(clip_timestamp(1500, true, 1000, 20), 1039u);
    EXPECT_EQ(clip_timestamp(1010, true, 1000, 20), 1010u);
    EXPECT_EQ(clip_timestamp(777,  false, 0, 20), 777u);   // no previous share
}

TEST(DashShareProducerInfo, FarShareHash) {
    SyntheticChain sc;
    std::vector<uint256> hashes;
    uint256 prev;
    for (int i = 0; i < 100; ++i) {
        prev = sc.add(static_cast<uint8_t>(1 + i), prev, BITS_DIFF1, BITS_DIFF1,
                      1000000 + i * 20, h160_uniform(0x11));
        hashes.push_back(prev);
    }
    // height(prev)=100: 99 hops from tip -> shares[0] (data.py:235).
    EXPECT_EQ(dash::producer::compute_far_share_hash(sc.chain, hashes[99]), hashes[0]);
    // height 98 (< 99) -> None.
    EXPECT_TRUE(dash::producer::compute_far_share_hash(sc.chain, hashes[97]).IsNull());
    // height exactly 99: the walk lands on the genesis' previous pointer
    // (None) -> null. [PROVISIONAL] — oracle's DistanceSkipList at this exact
    // boundary hand-traced to the genesis prev (None); confirm on replay.
    EXPECT_TRUE(dash::producer::compute_far_share_hash(sc.chain, hashes[98]).IsNull());
}

TEST(DashShareProducerInfo, TxForwardingRefs) {
    SyntheticChain sc;
    const uint256 A = h256_tag(0xa1), B = h256_tag(0xb2), C = h256_tag(0xc3);
    // Past share (the tip, i == 0 in the walk) carries new hashes [A, B].
    uint256 g   = sc.add(0x01, uint256(), BITS_DIFF1, BITS_DIFF1, 1000000, h160_uniform(0x11));
    uint256 tip = sc.add(0x02, g,         BITS_DIFF1, BITS_DIFF1, 1000020, h160_uniform(0x11),
                         0, 0, uint128(), {A, B});

    // desired [B, C, A]: B -> [1,1] (share_count 1+i=1, tx_count 1);
    // C unseen -> new [0,0]; A -> [1,0]. (data.py:147-170)
    auto refs = dash::producer::assemble_tx_refs(sc.chain, tip, {B, C, A});
    ASSERT_EQ(refs.new_transaction_hashes.size(), 1u);
    EXPECT_EQ(refs.new_transaction_hashes[0], C);
    EXPECT_EQ(refs.transaction_hash_refs,
              (std::vector<uint64_t>{1, 1, 0, 0, 1, 0}));
    EXPECT_EQ(refs.other_transaction_hashes, (std::vector<uint256>{B, C, A}));
}

TEST(DashShareProducerInfo, AbsAccumulationAndWrap) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    // Previous share at the wrap boundary: absheight 2^32-1, abswork 2^128-1.
    uint128 max128 = u128_hex("ffffffffffffffffffffffffffffffff");
    uint256 tip = sc.add(0x01, uint256(), BITS_DIFF1, BITS_DIFF1, 1000000,
                         h160_uniform(0x11), 0, 0xffffffffu, max128);

    ProducerJobInputs in;
    in.prev_share_hash   = tip;
    in.coinbase_scriptSig = {0x51, 0x52};
    in.pubkey_hash       = h160_uniform(0x22);
    in.subsidy           = 500000000;
    in.desired_timestamp = 1000010;
    in.desired_target    = params.max_target;

    auto info = dash::producer::generate_prospective_share_info(sc.chain, params, in);
    // (prev + 1) % 2^32 = 0; (prev + ata(diff1)) % 2^128 = ata(diff1) - 1.
    EXPECT_EQ(info.absheight, 0u);
    EXPECT_EQ(info.abswork, u128_hex("100010000"));
    EXPECT_EQ(info.bits, BITS_DIFF1);        // height 1 < lookbehind
    EXPECT_EQ(info.timestamp, 1000010u);     // inside the clip window
    EXPECT_TRUE(info.far_share_hash.IsNull());

    // Genesis accumulation: absheight 0+1, abswork 0+ata(bits).
    ProducerJobInputs gin = in;
    gin.prev_share_hash = uint256();
    auto ginfo = dash::producer::generate_prospective_share_info(sc.chain, params, gin);
    EXPECT_EQ(ginfo.absheight, 1u);
    EXPECT_EQ(ginfo.abswork, u128_hex(ATA_DIFF1_HEX));
}

// ═════════════════════════════════════════════════════════════════════════════
// PPLNS weights — ORACLE window (data.py:181-184) + partial inclusion
// (data.py:473-481). The window starts at the GRANDPARENT of the share being
// built; the tip (previous share) itself is EXCLUDED. NOTE: the in-tree
// verifier generate_share_transaction walks from the tip — this KAT pins the
// oracle semantics for the producer (review hotspot, see PR body).
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashShareProducerWeights, OracleWindowStartsAtGrandparent) {
    SyntheticChain sc;
    const uint160 A = h160_uniform(0xaa), B = h160_uniform(0xbb), C = h160_uniform(0xcc);
    uint256 g  = sc.add(0x01, uint256(), BITS_DIFF1, BITS_DIFF1, 1000000, A);
    uint256 s1 = sc.add(0x02, g,         BITS_DIFF1, BITS_DIFF1, 1000020, B);
    uint256 s2 = sc.add(0x03, s1,        BITS_DIFF1, BITS_DIFF1, 1000040, C);   // tip = prev of new share
    (void)s2;

    // Building on s2: start = s2.prev = s1; max_shares = min(3, RCL) - 1 = 2.
    // Window = [s1 (B), g (A)] — C is NOT in its own window.
    uint288 huge = u288_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto w = dash::producer::get_cumulative_weights(sc.chain, s1, 2, huge);

    const uint288 a1_65535 = u288_hex(ATA_DIFF1_HEX) * 65535u;
    ASSERT_EQ(w.weights.size(), 2u);
    EXPECT_EQ(w.weights.at(dash::pubkey_hash_to_script2(A)), a1_65535);
    EXPECT_EQ(w.weights.at(dash::pubkey_hash_to_script2(B)), a1_65535);
    EXPECT_EQ(w.weights.count(dash::pubkey_hash_to_script2(C)), 0u);
    EXPECT_EQ(w.total_weight, a1_65535 + a1_65535);
    EXPECT_TRUE(w.donation_weight.IsNull());
}

TEST(DashShareProducerWeights, PartialInclusionMatchesOracleDivision) {
    SyntheticChain sc;
    const uint160 A = h160_uniform(0xaa), B = h160_uniform(0xbb);
    // Window walk order: [s1 (B, don 0), g (A, don 6553)].
    uint256 g  = sc.add(0x01, uint256(), BITS_DIFF1, BITS_DIFF1, 1000000, A, 6553);
    uint256 s1 = sc.add(0x02, g,         BITS_DIFF1, BITS_DIFF1, 1000020, B, 0);

    // desired = 65535*a1 + 65535*(a1//2): s1 fully included, g partially.
    // Oracle apply_delta trace (exact ints):
    //   remaining//65535 = a1//2 = 0x80008000
    //   partial_addr = 0x80008000 * (a1*58982) // a1 = 0x733373330000
    //   partial_don  = 0x80008000 * (a1*6553)  // a1 = 0x0ccc8ccc8000
    auto w = dash::producer::get_cumulative_weights(
        sc.chain, s1, 2, u288_hex("17fffffff7fff"));

    EXPECT_EQ(w.weights.at(dash::pubkey_hash_to_script2(B)),
              u288_hex(ATA_DIFF1_HEX) * 65535u);
    EXPECT_EQ(w.weights.at(dash::pubkey_hash_to_script2(A)),
              u288_hex("733373330000"));
    EXPECT_EQ(w.donation_weight, u288_hex("ccc8ccc8000"));
    EXPECT_EQ(w.total_weight, u288_hex("17fffffff7fff"));   // capped at desired
}

// ═════════════════════════════════════════════════════════════════════════════
// (a) ref stream / ref_hash goldens — fixture F1 (genesis mint, no payload,
// one '!' script payment). Byte layout hand-assembled from share_info_type
// (data.py:81-106) + ref_type (data.py:124-127); digests via CPython hashlib.
// ═════════════════════════════════════════════════════════════════════════════

namespace {

ProspectiveShareInfo fixture_f1_info() {
    ProspectiveShareInfo info;
    info.prev_hash        = uint256();
    info.coinbase         = {0x03, 0x01, 0x02, 0x03};
    info.coinbase_payload = {};
    info.nonce            = 0x01020304;
    info.pubkey_hash      = h160_uniform(0x11);
    info.subsidy          = 500000000;
    info.donation         = 200;
    info.stale_info       = dash::StaleInfo::none;
    info.desired_version  = 16;
    info.payment_amount   = 100000000;
    {
        dash::PackedPayment pp;
        pp.m_payee  = "!6a04deadbeef";
        pp.m_amount = 100000000;
        info.packed_payments.push_back(pp);
    }
    info.far_share_hash = uint256();
    info.max_bits  = BITS_DIFF1;
    info.bits      = BITS_DIFF1;
    info.timestamp = 1700000000;
    info.absheight = 1;
    info.abswork   = u128_hex(ATA_DIFF1_HEX);
    return info;
}

const char* F1_REF_STREAM_HEX =
    "7242ef345e1bed6b"                                                  // IDENTIFIER
    "0000000000000000000000000000000000000000000000000000000000000000"  // prev None
    "0403010203"                                                        // coinbase VarStr
    "00"                                                                // inner payload None
    "04030201"                                                          // nonce LE
    "1111111111111111111111111111111111111111"                          // pubkey_hash
    "0065cd1d00000000"                                                  // subsidy LE
    "c800"                                                              // donation LE
    "00"                                                                // stale_info
    "10"                                                                // desired_version VarInt
    "00e1f50500000000"                                                  // payment_amount LE
    "010d213661303464656164626565660" "0e1f50500000000"                 // packed_payments[1]
    "00"                                                                // new_tx_hashes
    "00"                                                                // tx_hash_ref pairs
    "0000000000000000000000000000000000000000000000000000000000000000"  // far None
    "ffff001d" "ffff001d"                                               // max_bits, bits
    "00f15365"                                                          // timestamp LE
    "01000000"                                                          // absheight LE
    "01000100010000000000000000000000";                                 // abswork LE (128)

const char* F1_REF_HASH_HEX =
    "ae9fd236e3de3647ce76bf2eb3172ad0ec51d3edba4b231b4b1e2d204771880b";

const char* F1_GENTX_HEX =
    "01000000"                                                          // version 1, type 0
    "010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff" "0403010203" "ffffffff"                                  // coinbase input
    "04"                                                                // 4 outputs
    "00127a0000000000" "1976a914111111111111111111111111111111111111111188ac"  // finder 8000000
    "00e1f50500000000" "066a04deadbeef"                                 // payment 100000000
    "00725d1700000000" "1976a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac"  // donation 392000000
    "0000000000000000" "2a6a28"
    "ae9fd236e3de3647ce76bf2eb3172ad0ec51d3edba4b231b4b1e2d204771880b"  // ref_hash
    "0102030405060708"                                                  // last_txout_nonce LE
    "00000000";                                                         // locktime

const char* F1_TXID_HEX =
    "4cf27aa8726d1df1af549cf905e1b747288dcca9a418f15d052ad45cc0d0b9a0";

constexpr uint64_t F1_NONCE64 = 0x0807060504030201ull;

} // namespace

TEST(DashShareProducerRefHash, F1StreamAndRefHashGolden) {
    const auto params = dash::make_coin_params(false);
    const auto info = fixture_f1_info();

    // Full ref preimage bytes (identifier || share_info) — pinned.
    PackStream s;
    {
        const std::string hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            unsigned char b = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            s.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&b), 1));
        }
    }
    dash::producer::serialize_share_info(s, info);
    std::vector<unsigned char> bytes(
        reinterpret_cast<const unsigned char*>(s.data()),
        reinterpret_cast<const unsigned char*>(s.data()) + s.size());
    EXPECT_EQ(hex_of_bytes(bytes), F1_REF_STREAM_HEX);
    EXPECT_EQ(bytes.size(), 179u);

    // ref_hash = sha256d(stream) folded through the (empty) ref merkle link.
    EXPECT_EQ(hex_of(dash::producer::compute_ref_hash(params, info)), F1_REF_HASH_HEX);
}

TEST(DashShareProducerGentx, F1BytesGolden) {
    const auto params = dash::make_coin_params(false);
    const auto info = fixture_f1_info();

    uint256 ref_hash;
    {
        std::vector<unsigned char> raw;
        const std::string h = F1_REF_HASH_HEX;
        for (size_t i = 0; i + 1 < h.size(); i += 2)
            raw.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
        std::memcpy(ref_hash.data(), raw.data(), 32);
    }

    // Genesis: empty weights -> finder 2% + donation remainder only.
    auto gentx = dash::producer::build_gentx(
        info, dash::producer::CumulativeWeights{}, ref_hash, F1_NONCE64, params);

    EXPECT_EQ(hex_of_bytes(gentx.bytes), F1_GENTX_HEX);
    EXPECT_EQ(gentx.bytes.size(), 189u);
    EXPECT_EQ(gentx.prefix_len, 145u);          // len - 0 (no payload) - 32 - 8 - 4
    EXPECT_EQ(hex_of(gentx.txid), F1_TXID_HEX);
}

// F2: same fixture with a DIP4 CbTx payload (0xdeadbeef). version|type flip to
// {3,5}, VarStr(extra_payload) tail, prefix cut excludes it. Goldens: CPython.
TEST(DashShareProducerGentx, F2PayloadGolden) {
    const auto params = dash::make_coin_params(false);
    auto info = fixture_f1_info();
    info.coinbase_payload = {0xde, 0xad, 0xbe, 0xef};

    const uint256 ref_hash = dash::producer::compute_ref_hash(params, info);
    EXPECT_EQ(hex_of(ref_hash),
              "e5efc58b08be49d7bc03b6f1731114d84068346817017465ce07e46c516196e1");

    auto gentx = dash::producer::build_gentx(
        info, dash::producer::CumulativeWeights{}, ref_hash, F1_NONCE64, params);
    EXPECT_EQ(gentx.bytes.size(), 194u);
    EXPECT_EQ(gentx.prefix_len, 145u);          // len - 5 (VarStr payload) - 44
    EXPECT_EQ(hex_of(gentx.txid),
              "6835d59cfe4c564b06dc55b3d235fe201869a3aca3c1368eb295a831e8e36239");
    // version int16 / type int16 (dash/data.py:97-98) + payload tail.
    ASSERT_GE(gentx.bytes.size(), 5u);
    EXPECT_EQ(gentx.bytes[0], 0x03); EXPECT_EQ(gentx.bytes[1], 0x00);
    EXPECT_EQ(gentx.bytes[2], 0x05); EXPECT_EQ(gentx.bytes[3], 0x00);
    const auto tail = std::vector<unsigned char>(gentx.bytes.end() - 5, gentx.bytes.end());
    EXPECT_EQ(hex_of_bytes(tail), "04deadbeef");
}

// ═════════════════════════════════════════════════════════════════════════════
// (e) hash_link producer -> checker round trip.
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashShareProducerHashLink, RoundTripAcrossBufferBoundaries) {
    const auto ce = dash::compute_gentx_before_refhash();   // 37 bytes
    ASSERT_EQ(ce.size(), 37u);

    // Sweep prefix lengths across several SHA256 block boundaries: prefix =
    // [pattern...] || const_ending; resumed fold must equal fresh SHA256d.
    for (size_t total = ce.size(); total <= ce.size() + 130; ++total) {
        std::vector<unsigned char> prefix(total - ce.size());
        for (size_t i = 0; i < prefix.size(); ++i)
            prefix[i] = static_cast<unsigned char>(i * 7 + 3);
        prefix.insert(prefix.end(), ce.begin(), ce.end());

        std::vector<unsigned char> data;
        for (int i = 0; i < 44; ++i) data.push_back(static_cast<unsigned char>(0xf0 - i));

        auto hl = dash::producer::prefix_to_hash_link(prefix, ce);
        uint256 folded = dash::check_hash_link(hl, data, ce);

        std::vector<unsigned char> whole(prefix);
        whole.insert(whole.end(), data.begin(), data.end());
        uint256 direct = Hash(std::span<const unsigned char>(whole.data(), whole.size()));
        ASSERT_EQ(hex_of(folded), hex_of(direct)) << "prefix len " << total;
    }
}

TEST(DashShareProducerHashLink, RejectsPrefixWithoutConstEnding) {
    const auto ce = dash::compute_gentx_before_refhash();
    std::vector<unsigned char> bad(50, 0xab);
    EXPECT_THROW(dash::producer::prefix_to_hash_link(bad, ce), std::runtime_error);
}

// Non-circular pin: length-0 midstate == SHA-256 IV; extra_data empty.
// (CPython: hashlib state of b'' is the IV by definition.)
TEST(DashShareProducerHashLink, EmptyPrefixIsIV) {
    auto hl = dash::producer::prefix_to_hash_link({}, {});
    EXPECT_EQ(hex_of_bytes(hl.m_state.m_data),
              "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19");
    EXPECT_TRUE(hl.m_extra_data.m_data.empty());
    EXPECT_EQ(hl.m_length, 0u);
}

// ═════════════════════════════════════════════════════════════════════════════
// (a)+(b) Full DashShare build: mandatory self-verify against the in-tree
// verifier, wire-codec round trip, oracle outer-payload framing.
// ═════════════════════════════════════════════════════════════════════════════

namespace {

bitcoin_family::coin::SmallBlockHeaderType fixture_min_header() {
    bitcoin_family::coin::SmallBlockHeaderType h;
    h.m_version = 536870912;                    // BIP9 base version
    h.m_previous_block = h256_tag(0x77);
    h.m_timestamp = 1700000005;
    h.m_bits = 0x1b00ffffu;                     // block target (much harder than share)
    h.m_nonce = 0xdeadbeefu;
    return h;
}

} // namespace

TEST(DashShareProducerBuild, F1GenesisSelfVerifies) {
    const auto params = dash::make_coin_params(false);
    dash::ShareChain chain;

    auto built = dash::producer::build_share(
        chain, params, fixture_f1_info(), fixture_min_header(), F1_NONCE64,
        /*check_pow=*/false);

    EXPECT_EQ(hex_of(built.ref_hash), F1_REF_HASH_HEX);
    EXPECT_EQ(hex_of(built.gentx_hash), F1_TXID_HEX);
    EXPECT_FALSE(built.share.m_hash.IsNull());
    EXPECT_TRUE(built.share.m_coinbase_payload_outer.m_data.empty());
    // prefix_len 145: buf tail 145 % 64 = 17 bytes, fully covered by the
    // 37-byte const_ending -> extra_data empty (oracle data.py:37).
    EXPECT_EQ(built.share.m_hash_link.m_length, 145u);
    EXPECT_TRUE(built.share.m_hash_link.m_extra_data.m_data.empty());

    // Independent re-run of the verifier reproduces the same share hash.
    EXPECT_EQ(hex_of(dash::share_init_verify(built.share, params, false)),
              hex_of(built.share.m_hash));
}

TEST(DashShareProducerBuild, F2PayloadOuterFramingAndWireRoundTrip) {
    const auto params = dash::make_coin_params(false);
    dash::ShareChain chain;

    auto info = fixture_f1_info();
    info.coinbase_payload = {0xde, 0xad, 0xbe, 0xef};

    auto built = dash::producer::build_share(
        chain, params, info, fixture_min_header(), F1_NONCE64, /*check_pow=*/false);

    // Oracle outer field VALUE = VarStr(raw payload) (data.py:277-289).
    EXPECT_EQ(hex_of_bytes(built.share.m_coinbase_payload_outer.m_data), "04deadbeef");

    // Wire codec round trip (DashFormatter): serialize -> parse -> serialize
    // must be byte-identical, and the wire tail must carry the DOUBLE length
    // prefix the oracle's PossiblyNone(b'', VarStr) outer layer produces:
    // [merkle branch count 00] [05] [04 de ad be ef].
    PackStream w1;
    dash::DashFormatter::Write(w1, &built.share);
    std::vector<unsigned char> wire1(
        reinterpret_cast<const unsigned char*>(w1.data()),
        reinterpret_cast<const unsigned char*>(w1.data()) + w1.size());
    ASSERT_GE(wire1.size(), 7u);
    EXPECT_EQ(hex_of_bytes(std::vector<unsigned char>(wire1.end() - 7, wire1.end())),
              "00050" "4deadbeef");

    // Parse back through the full load_share path (RawShare, type 16).
    chain::RawShare raw(16, PackStream(wire1));
    auto loaded = dash::load_share(raw, NetService());
    PackStream w2;
    loaded.invoke([&](auto* obj) {
        dash::DashFormatter::Write(w2, obj);
        // The loaded share must also pass the verifier with the same hash.
        EXPECT_EQ(hex_of(dash::share_init_verify(*obj, params, false)),
                  hex_of(built.share.m_hash));
    });
    std::vector<unsigned char> wire2(
        reinterpret_cast<const unsigned char*>(w2.data()),
        reinterpret_cast<const unsigned char*>(w2.data()) + w2.size());
    EXPECT_EQ(hex_of_bytes(wire1), hex_of_bytes(wire2));
    loaded.destroy();

    // RawShare framing round trip (message_shares element).
    PackStream m1; m1 << raw;
    chain::RawShare raw2; PackStream m1copy(std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(m1.data()),
        reinterpret_cast<const unsigned char*>(m1.data()) + m1.size()));
    m1copy >> raw2;
    EXPECT_EQ(raw2.type, 16u);
    PackStream m2; m2 << raw2;
    EXPECT_EQ(m1.size(), m2.size());
    EXPECT_EQ(std::memcmp(m1.data(), m2.data(), m1.size()), 0);
}

TEST(DashShareProducerBuild, ChainMintPaysWindowAndPassesVerifier) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    const uint160 A = h160_uniform(0xaa), B = h160_uniform(0xbb), C = h160_uniform(0xcc);
    // g(A) <- s1(B) <- s2(C, tip). abswork/absheight tracked for accumulation.
    uint256 g  = sc.add(0x01, uint256(), BITS_DIFF1, BITS_DIFF1, 1699999900, A, 0,
                        1, u128_hex(ATA_DIFF1_HEX));
    uint256 s1 = sc.add(0x02, g,  BITS_DIFF1, BITS_DIFF1, 1699999920, B, 0,
                        2, u128_hex(ATA_DIFF1_HEX) * 2u);
    uint256 s2 = sc.add(0x03, s1, BITS_DIFF1, BITS_DIFF1, 1699999940, C, 0,
                        3, u128_hex(ATA_DIFF1_HEX) * 3u);

    ProducerJobInputs in;
    in.prev_share_hash    = s2;
    in.coinbase_scriptSig = {0x03, 0x01, 0x02, 0x03};
    in.share_nonce        = 7;
    in.pubkey_hash        = C;                   // miner C mints again
    in.subsidy            = 500000000;
    in.donation           = 0;
    in.desired_version    = 16;
    in.desired_timestamp  = 1700000000;          // clipped to prev+39 = 1699999979
    in.desired_target     = params.max_target;

    auto info = dash::producer::generate_prospective_share_info(sc.chain, params, in);
    EXPECT_EQ(info.timestamp, 1699999979u);
    EXPECT_EQ(info.absheight, 4u);
    EXPECT_EQ(info.abswork, u128_hex(ATA_DIFF1_HEX) * 4u);
    EXPECT_EQ(info.bits, BITS_DIFF1);            // height 3 < lookbehind
    EXPECT_TRUE(info.far_share_hash.IsNull());

    auto built = dash::producer::build_share(
        sc.chain, params, info, fixture_min_header(), F1_NONCE64, /*check_pow=*/false);

    // Parse the produced gentx outputs: PPLNS window = [s1(B), g(A)] (oracle
    // grandparent window), each 49/100 of the payout; finder fee to C;
    // donation output ALWAYS present (amount 0 here).
    //   worker_payout = 5e8; A = B = 5e8*49*w//(50*2w) = 245000000;
    //   C = 5e8//50 = 10000000; donation = 0.
    struct Out { uint64_t value; std::vector<unsigned char> script; };
    std::vector<Out> outs;
    {
        // Minimal reader over the produced bytes (layout pinned by F1 golden).
        auto gentx = dash::producer::build_gentx(
            info,
            [&] {
                uint256 grandparent = s1;
                const uint288 desired = chain::target_to_average_attempts(
                    chain::bits_to_target(fixture_min_header().m_bits)) * params.spread * 65535u;
                return dash::producer::get_cumulative_weights(sc.chain, grandparent, 2, desired);
            }(),
            built.ref_hash, F1_NONCE64, params);
        // Same inputs -> the exact gentx build_share committed to (txid match).
        EXPECT_EQ(hex_of(gentx.txid), hex_of(built.gentx_hash));
        const auto& v = gentx.bytes;
        size_t p = 4 /*ver+type*/ + 1 /*vin cnt*/ + 32 + 4;
        p += 1 + v[p];                     // scriptSig VarStr (short)
        p += 4;                            // sequence
        size_t n = v[p++];                 // vout count (short)
        for (size_t i = 0; i < n; ++i) {
            Out o; o.value = 0;
            for (int k = 0; k < 8; ++k) o.value |= static_cast<uint64_t>(v[p + k]) << (8 * k);
            p += 8;
            size_t sl = v[p++];
            o.script.assign(v.begin() + p, v.begin() + p + sl);
            p += sl;
            outs.push_back(std::move(o));
        }
    }
    ASSERT_EQ(outs.size(), 5u);            // A, B, finder C, donation, OP_RETURN
    EXPECT_EQ(outs[0].script, dash::pubkey_hash_to_script2(A));
    EXPECT_EQ(outs[0].value, 245000000u);
    EXPECT_EQ(outs[1].script, dash::pubkey_hash_to_script2(B));
    EXPECT_EQ(outs[1].value, 245000000u);
    EXPECT_EQ(outs[2].script, dash::pubkey_hash_to_script2(C));
    EXPECT_EQ(outs[2].value, 10000000u);
    EXPECT_EQ(outs[3].value, 0u);          // donation output, always emitted
    EXPECT_EQ(outs[3].script,
              std::vector<unsigned char>(dash::DONATION_SCRIPT.begin(),
                                         dash::DONATION_SCRIPT.end()));
    EXPECT_EQ(outs[4].value, 0u);          // OP_RETURN ref_hash commitment
    ASSERT_EQ(outs[4].script.size(), 42u);
    EXPECT_EQ(outs[4].script[0], 0x6a);
    EXPECT_EQ(outs[4].script[1], 0x28);

    // Full accept-path verifier (Phase 1 + version-transition gate).
    EXPECT_NO_THROW(dash::verify_share(built.share, sc.chain,
                                       params.chain_length, params,
                                       /*verify_init=*/true, /*check_pow=*/false));
}

// Merkle link over a non-empty job tx set: branch = [h1, sha256d(h2||h2)]
// (odd layer duplicates its last element — dash/data.py:189-207), and the
// built share still passes the verifier (merkle fold consistency).
TEST(DashShareProducerBuild, MerkleLinkWithTransactions) {
    const auto params = dash::make_coin_params(false);
    dash::ShareChain chain;

    const uint256 h1 = h256_tag(0x41), h2 = h256_tag(0x42);
    auto info = fixture_f1_info();
    info.new_transaction_hashes = {h1, h2};
    info.transaction_hash_refs  = {0, 0, 0, 1};
    info.other_transaction_hashes = {h1, h2};

    auto link = dash::producer::calculate_merkle_link_index0({h1, h2});
    ASSERT_EQ(link.m_branch.size(), 2u);
    EXPECT_EQ(link.m_branch[0], h1);
    {
        std::vector<unsigned char> buf(64);
        std::memcpy(buf.data(), h2.data(), 32);
        std::memcpy(buf.data() + 32, h2.data(), 32);
        EXPECT_EQ(link.m_branch[1],
                  Hash(std::span<const unsigned char>(buf.data(), buf.size())));
    }

    auto built = dash::producer::build_share(
        chain, params, info, fixture_min_header(), F1_NONCE64, /*check_pow=*/false);
    EXPECT_EQ(built.share.m_merkle_link.m_branch.size(), 2u);
    EXPECT_EQ(hex_of(dash::share_init_verify(built.share, params, false)),
              hex_of(built.share.m_hash));
}

// Drift fence: the producer's local merkle walk must stay byte-identical to
// the stratum-side dash::coinbase::merkle_branches_raw over the same tx set
// (both implement dash/data.py calculate_merkle_link for index 0). Swept over
// several set sizes incl. the odd-layer duplication cases.
TEST(DashShareProducerBuild, MerkleLinkMatchesCoinbaseBuilder) {
    for (size_t n = 0; n <= 9; ++n) {
        std::vector<uint256> txs;
        for (size_t i = 0; i < n; ++i)
            txs.push_back(h256_tag(static_cast<uint8_t>(0x50 + i)));

        auto link = dash::producer::calculate_merkle_link_index0(txs);

        std::vector<uint256> with_placeholder;
        with_placeholder.emplace_back();
        with_placeholder.insert(with_placeholder.end(), txs.begin(), txs.end());
        auto branches = dash::coinbase::merkle_branches_raw(with_placeholder);

        ASSERT_EQ(link.m_branch.size(), branches.size()) << "n=" << n;
        for (size_t i = 0; i < branches.size(); ++i)
            EXPECT_EQ(link.m_branch[i], branches[i]) << "n=" << n << " i=" << i;
        EXPECT_EQ(link.m_index, 0u);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// KEYSTONE: trustless PPLNS payout-commitment gate (dash::verify_payout_commitment
// / generate_share_transaction). Ports the ltc/btc/dgb GENTX-MISMATCH guard onto
// the DASH accept path. Invariants:
//   (a) a coinbase paying the WRONG set (e.g. only the submitter) is REJECTED;
//   (b) a coinbase paying the CORRECT PPLNS window is ACCEPTED;
//   (c) our own producer-minted share is NOT self-rejected (producer and the
//       accept-path recompute walk the SAME grandparent window -> same coinbase).
// ═════════════════════════════════════════════════════════════════════════════

// generate_share_transaction takes a TRACKER exposing .chain (in prod the live
// ShareTracker). This minimal view over the synthetic ShareChain is enough to
// drive the recompute/compare exactly as attempt_verify does with *this.
namespace { struct PayoutTrackerView { dash::ShareChain& chain; }; }

// Build the canonical g(A) <- s1(B) <- s2(C, tip) window into `sc` and mint miner
// C's next share on top (finder = C; PPLNS window = grandparent walk {s1(B),
// g(A)}). Returns the built share (BuiltShare is movable; SyntheticChain, holding
// a non-movable ShareChain, stays owned by the caller).
static dash::producer::BuiltShare mint_scene(SyntheticChain& sc,
                                             const core::CoinParams& params) {
    const uint160 A = h160_uniform(0xaa), B = h160_uniform(0xbb), C = h160_uniform(0xcc);
    uint256 g  = sc.add(0x01, uint256(), BITS_DIFF1, BITS_DIFF1, 1699999900, A, 0,
                        1, u128_hex(ATA_DIFF1_HEX));
    uint256 s1 = sc.add(0x02, g,  BITS_DIFF1, BITS_DIFF1, 1699999920, B, 0,
                        2, u128_hex(ATA_DIFF1_HEX) * 2u);
    uint256 s2 = sc.add(0x03, s1, BITS_DIFF1, BITS_DIFF1, 1699999940, C, 0,
                        3, u128_hex(ATA_DIFF1_HEX) * 3u);
    ProducerJobInputs in;
    in.prev_share_hash = s2; in.coinbase_scriptSig = {0x03,0x01,0x02,0x03};
    in.share_nonce = 7; in.pubkey_hash = C; in.subsidy = 500000000;
    in.donation = 0; in.desired_version = 16; in.desired_timestamp = 1700000000;
    in.desired_target = params.max_target;
    auto info = dash::producer::generate_prospective_share_info(sc.chain, params, in);
    return dash::producer::build_share(
        sc.chain, params, info, fixture_min_header(), F1_NONCE64, /*check_pow=*/false);
}

// (b)+(c) The accept-path recompute reproduces the EXACT gentx the producer
// committed to, so verify_payout_commitment admits our own freshly-minted share.
TEST(DashPayoutCommitment, LocalMintCoinbaseAccepted) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    auto built = mint_scene(sc, params);
    PayoutTrackerView tv{sc.chain};

    // Recompute matches the committed gentx byte-for-byte.
    uint256 expected = dash::generate_share_transaction(built.share, tv, params);
    EXPECT_EQ(hex_of(expected), hex_of(built.gentx_hash));

    // The gate admits the producer's own coinbase commitment (no throw).
    EXPECT_NO_THROW(dash::verify_payout_commitment(
        built.share, tv, params, built.gentx_hash));
}

// (a) A coinbase that does NOT pay the PPLNS window (here: the empty-window /
// "solo" coinbase a self-dealing peer would commit to) has a txid != the
// window-derived expected, so the gate REJECTS it.
TEST(DashPayoutCommitment, WrongCoinbaseRejected) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    auto built = mint_scene(sc, params);
    PayoutTrackerView tv{sc.chain};

    // Expected coinbase pays the window {A,B} + finder C. Model the attacker's
    // self-paying commitment as the coinbase for the SAME share fields but with
    // NO PPLNS window (prev null) -- it pays only finder/donation, not A & B.
    dash::DashShare solo = built.share;
    solo.m_prev_hash = uint256();  // empty window -> nothing paid to A/B
    uint256 solo_txid = dash::generate_share_transaction(solo, tv, params);
    ASSERT_NE(hex_of(solo_txid), hex_of(built.gentx_hash))
        << "solo coinbase must differ from the honest window coinbase";

    // Honest share, but committing to the solo (wrong) coinbase -> REJECTED.
    EXPECT_THROW(dash::verify_payout_commitment(
        built.share, tv, params, solo_txid), std::invalid_argument);
}

// Sanity: the recompute is payout-sensitive -- changing the finder (pubkey_hash)
// changes the expected txid, so a share whose committed coinbase does not match
// its declared finder is rejected (defends against payout-field tampering).
TEST(DashPayoutCommitment, FinderTamperRejected) {
    const auto params = dash::make_coin_params(false);
    SyntheticChain sc;
    auto built = mint_scene(sc, params);
    PayoutTrackerView tv{sc.chain};

    dash::DashShare tampered = built.share;
    tampered.m_pubkey_hash = h160_uniform(0xee);  // redirect finder fee to attacker
    uint256 tampered_expected = dash::generate_share_transaction(tampered, tv, params);
    ASSERT_NE(hex_of(tampered_expected), hex_of(built.gentx_hash));

    // The committed coinbase (built.gentx_hash) still pays finder C, so the
    // tampered share's recomputed coinbase no longer matches -> REJECTED.
    EXPECT_THROW(dash::verify_payout_commitment(
        tampered, tv, params, built.gentx_hash), std::invalid_argument);
}
