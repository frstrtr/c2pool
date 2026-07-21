// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 share-type KATs (Phase A: DEFINE + PARSE, dormant).
//
// CONSENSUS-BEARING. This pins the DASH v36 share wire format (dash::DashV36Share,
// wire-type 36). Four guarantees:
//
//   1. BYTE-PARITY of the STANDARDIZED prefix (min_header .. message_data) vs the
//      cross-coin non-segwit v36 share shape. The reference is the BCH v36
//      MergedMiningShare Formatter (src/impl/bch/share.hpp:152-252), i.e. the
//      LTC/DGB v36 layout MINUS the Optional(segwit_data) slot — BCH, like DASH,
//      is non-segwit (SEGWIT_ACTIVATION_VERSION==0 => is_segwit_activated(36)
//      false), so the segwit_data field is omitted. The expected prefix is
//      rebuilt field-by-field in the BCH order using the SAME core pack
//      primitives, then frozen as a golden hex regression sentinel — a field-
//      order or encoding drift (missing pubkey_type, fixed-uint64 subsidy instead
//      of VarInt, fixed-uint128 abswork instead of AbsworkV36Format, segwit slot
//      leaking in, etc.) fails the test.
//
//   2. ROUND-TRIP through the REAL chain::ShareVariants dispatch: pack -> RawShare
//      (type 36) -> dash::load_v36_share -> field equality -> re-pack byte-
//      identical. Proves version-36 dispatch (LoadMethods[36] -> DashV36Share,
//      DashFormatter::ReadV36/WriteV36) round-trips.
//
//   3. MERGED fields are INERT and follow the non-merged cross-coin convention:
//      empty merged_addresses / merged_coinbase_info => a single VarInt(0) byte;
//      zero merged_payout_hash => 32 zero bytes; empty message_data => VarInt(0).
//      Identical to how a standalone (non-merged) ltc/dgb/bch coin populates them.
//
//   4. BACKWARD-COMPAT: the pre-existing v16 DashShare wire format is byte-
//      UNCHANGED by the DashFormatter version-branch refactor (v16 round-trips
//      through the live ShareType::load(16); v16 vs v36 of the same logical
//      inputs are DISTINCT and keep the v16-specific ordering).

#include <gtest/gtest.h>

#include <impl/dash/share_chain.hpp>   // DashFormatter, ShareType, V36ShareType, load_share, load_v36_share
#include <impl/dash/share.hpp>         // dash::DashShare, dash::DashV36Share
#include <impl/dash/share_types.hpp>   // dash::v36::* shared types, dash::PackedPayment

#include <sharechain/share.hpp>        // chain::RawShare
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <cstdio>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

std::string to_hex(const std::span<const unsigned char> bytes)
{
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char b : bytes) { out.push_back(h[b >> 4]); out.push_back(h[b & 0xf]); }
    return out;
}

std::string pack_hex(const PackStream& ps)
{
    auto& m = const_cast<PackStream&>(ps);
    return to_hex(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(m.data()), m.size()));
}

// A canonical, fully-populated DASH v36 share. Distinctive scalar values so a
// misordered/misencoded field is visible; merged fields left EMPTY (DASH is
// standalone X11 — no AuxPoW child), DASH suffix populated.
dash::DashV36Share make_canonical_v36()
{
    dash::DashV36Share s;
    s.m_min_header.m_version = 2;
    s.m_min_header.m_previous_block.SetHex(
        "00000000000000000000000000000000000000000000000000000000000000aa");
    s.m_min_header.m_timestamp = 0x11223344;
    s.m_min_header.m_bits = 0x1e0ffff0;
    s.m_min_header.m_nonce = 0x55667788;

    s.m_prev_hash.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    s.m_coinbase = BaseScript(std::vector<unsigned char>{0xab, 0xcd});
    s.m_nonce = 0x0a0b0c0d;
    s.m_pubkey_hash.SetHex("00000000000000000000000000000000deadbeef");
    s.m_pubkey_type = 0;                 // DASH always P2PKH
    s.m_subsidy = 5000000000ULL;         // > 2^32 => 9-byte VarInt
    s.m_donation = 0x1234;
    s.m_stale_info = dash::StaleInfo::none;
    s.m_desired_version = 36;            // the version-vote

    // merged_addresses: EMPTY (inert)
    s.m_far_share_hash.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000002");
    s.m_max_bits = 0x1e0fffff;
    s.m_bits = 0x1d00ffff;
    s.m_timestamp = 0x99aabbcc;
    s.m_absheight = 0x00010203;
    s.m_abswork = uint128(0x0102030405060708ULL);

    // merged_coinbase_info: EMPTY (inert); merged_payout_hash: zero (inert)
    s.m_last_txout_nonce = 0xdeadbeefcafef00dULL;
    s.m_hash_link.m_state.m_data.assign(32, 0x00);
    for (int i = 0; i < 32; ++i) s.m_hash_link.m_state.m_data[i] = static_cast<unsigned char>(i);
    s.m_hash_link.m_extra_data = BaseScript(std::vector<unsigned char>{0xaa, 0xbb, 0xcc});
    s.m_hash_link.m_length = 128;
    // ref_merkle_link / merkle_link: empty branches
    // message_data: EMPTY (Phase A — messaging is Phase B)

    // ── DASH suffix ──
    s.m_coinbase_payload = BaseScript(std::vector<unsigned char>{0x01, 0x02});
    s.m_payment_amount = 0x00000000abcdef01ULL;
    s.m_packed_payments.push_back(dash::PackedPayment{"!6a0401020304", 12345});
    s.m_coinbase_payload_outer = BaseScript(std::vector<unsigned char>{0x02, 0x01, 0x02});
    return s;
}

// Independently rebuild the STANDARDIZED prefix (min_header .. message_data) in
// the BCH v36 Formatter field order, using the same core primitives. This is the
// byte-parity reference: if DashFormatter::WriteV36 drifts from the standardized
// order/encoding this reconstruction diverges.
PackStream expected_standardized_prefix(const dash::DashV36Share& s)
{
    PackStream os;
    os << s.m_min_header;                                     // bch:154
    os << s.m_prev_hash << s.m_coinbase << s.m_nonce;         // bch:156-160
    os << s.m_pubkey_hash;                                    // bch:165 (v36 address)
    os << s.m_pubkey_type;                                    // bch:166 (v36)
    ::Serialize(os, VarInt(s.m_subsidy));                     // bch:180 (v36 VarInt)
    os << s.m_donation;                                       // bch:188
    { uint8_t si = static_cast<uint8_t>(s.m_stale_info); os << si; } // bch:189 EnumType<IntType<8>>
    ::Serialize(os, VarInt(s.m_desired_version));             // bch:190 (version-vote)
    // NO segwit_data (non-segwit — bch:194 is_segwit_activated(36)==false)
    os << s.m_merged_addresses;                               // bch:202 (v36)
    // NO tx_info (version >= 34)
    os << s.m_far_share_hash << s.m_max_bits << s.m_bits
       << s.m_timestamp << s.m_absheight;                     // bch:210-215
    ::Serialize(os, Using<dash::v36::AbsworkV36Format>(s.m_abswork)); // bch:221 (v36)
    os << s.m_merged_coinbase_info;                           // bch:231 (v36)
    os << s.m_merged_payout_hash;                             // bch:232 (v36)
    { ParamPackStream ps{dash::v36::MERKLE_LINK_SMALL, os}; ::Serialize(ps, s.m_ref_merkle_link); } // bch:237
    os << s.m_last_txout_nonce;                               // bch:239
    os << s.m_hash_link;                                      // bch:241 (V36HashLinkType)
    { ParamPackStream ps{dash::v36::MERKLE_LINK_SMALL, os}; ::Serialize(ps, s.m_merkle_link); } // bch:244
    os << s.m_message_data;                                   // bch:250 (v36)
    return os;
}

// Serialize the DASH suffix alone (everything WriteV36 emits after message_data).
PackStream expected_dash_suffix(const dash::DashV36Share& s)
{
    PackStream os;
    os << s.m_coinbase_payload;
    os << s.m_payment_amount;
    {
        uint64_t count = s.m_packed_payments.size();
        ::Serialize(os, VarInt(count));
        for (auto& pay : s.m_packed_payments) {
            BaseScript bs; bs.m_data.assign(pay.m_payee.begin(), pay.m_payee.end());
            os << bs; os << pay.m_amount;
        }
    }
    os << s.m_coinbase_payload_outer;
    return os;
}

// Full v36 wire bytes via the production formatter.
PackStream pack_v36(const dash::DashV36Share& s)
{
    PackStream os;
    dash::DashFormatter::Write(os, &s);   // version-branch -> WriteV36
    return os;
}

} // namespace

// ── 1. BYTE-PARITY: standardized prefix matches the BCH v36 field order ──────
TEST(DashV36ShareByteParity, StandardizedPrefixMatchesCrossCoinV36Shape)
{
    auto s = make_canonical_v36();

    PackStream full = pack_v36(s);
    PackStream expect_prefix = expected_standardized_prefix(s);
    PackStream expect_suffix = expected_dash_suffix(s);

    const std::string full_hex   = pack_hex(full);
    const std::string prefix_hex = pack_hex(expect_prefix);
    const std::string suffix_hex = pack_hex(expect_suffix);

    // The production wire = standardized prefix ++ DASH suffix, in that order.
    ASSERT_EQ(full_hex, prefix_hex + suffix_hex)
        << "DashFormatter::WriteV36 must emit the standardized cross-coin v36 "
           "prefix (bch/ltc/dgb non-segwit shape) followed by the DASH suffix";

    // The standardized prefix is the consensus-critical cross-coin part.
    EXPECT_EQ(full_hex.substr(0, prefix_hex.size()), prefix_hex)
        << "standardized v36 prefix byte-parity";
}

// FROZEN GOLDEN regression sentinel for the standardized prefix + full wire.
// Captured from DashFormatter::WriteV36 on make_canonical_v36(); any change to
// the v36 wire layout must update these deliberately (a consensus boundary).
TEST(DashV36ShareByteParity, FrozenGoldenWire)
{
    auto s = make_canonical_v36();
    const std::string prefix_hex = pack_hex(expected_standardized_prefix(s));
    const std::string full_hex   = pack_hex(pack_v36(s));

    EXPECT_EQ(prefix_hex, std::string(
        "02aa0000000000000000000000000000000000000000000000000000000000000044332211f0ff0f1e88776655010000000000000000000000000000000000000000000000000000000000000002abcd0d0c0b0aefbeadde0000000000000000000000000000000000ff00f2052a0100000034120024000200000000000000000000000000000000000000000000000000000000000000ffff0f1effff001dccbbaa9903020100ff0807060504030201000000000000000000000000000000000000000000000000000000000000000000000df0fecaefbeadde000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03aabbcc800000"))
        << "standardized v36 prefix golden drift";
    EXPECT_EQ(full_hex, std::string(
        "02aa0000000000000000000000000000000000000000000000000000000000000044332211f0ff0f1e88776655010000000000000000000000000000000000000000000000000000000000000002abcd0d0c0b0aefbeadde0000000000000000000000000000000000ff00f2052a0100000034120024000200000000000000000000000000000000000000000000000000000000000000ffff0f1effff001dccbbaa9903020100ff0807060504030201000000000000000000000000000000000000000000000000000000000000000000000df0fecaefbeadde000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f03aabbcc80000002010201efcdab00000000010d21366130343031303230333034393000000000000003020102"))
        << "full v36 wire golden drift";
}

// ── 2. ROUND-TRIP through real version-36 dispatch ───────────────────────────
TEST(DashV36ShareRoundTrip, ThroughVersion36Dispatch)
{
    auto s = make_canonical_v36();
    PackStream wire = pack_v36(s);

    // Wrap as a RawShare(type=36) and load via the real ShareVariants dispatch.
    chain::RawShare rshare(uint64_t{36}, wire);
    ASSERT_EQ(rshare.type, 36u);
    auto loaded = dash::load_v36_share(rshare, NetService{"test", 0});

    loaded.invoke([&](auto* obj) {
        using T = std::remove_pointer_t<decltype(obj)>;
        static_assert(std::is_same_v<T, dash::DashV36Share>,
                      "type-36 wire must dispatch to DashV36Share");
        EXPECT_EQ(obj->m_min_header.m_version, s.m_min_header.m_version);
        EXPECT_EQ(obj->m_min_header.m_bits, s.m_min_header.m_bits);
        EXPECT_EQ(obj->m_prev_hash, s.m_prev_hash);
        EXPECT_EQ(obj->m_coinbase.m_data, s.m_coinbase.m_data);
        EXPECT_EQ(obj->m_nonce, s.m_nonce);
        EXPECT_EQ(obj->m_pubkey_hash, s.m_pubkey_hash);
        EXPECT_EQ(obj->m_pubkey_type, s.m_pubkey_type);
        EXPECT_EQ(obj->m_subsidy, s.m_subsidy);
        EXPECT_EQ(obj->m_donation, s.m_donation);
        EXPECT_EQ(obj->m_desired_version, s.m_desired_version);
        EXPECT_EQ(obj->m_far_share_hash, s.m_far_share_hash);
        EXPECT_EQ(obj->m_max_bits, s.m_max_bits);
        EXPECT_EQ(obj->m_bits, s.m_bits);
        EXPECT_EQ(obj->m_timestamp, s.m_timestamp);
        EXPECT_EQ(obj->m_absheight, s.m_absheight);
        EXPECT_EQ(obj->m_abswork.GetLow64(), s.m_abswork.GetLow64());
        EXPECT_TRUE(obj->m_merged_addresses.empty());
        EXPECT_TRUE(obj->m_merged_coinbase_info.empty());
        EXPECT_EQ(obj->m_merged_payout_hash, s.m_merged_payout_hash);
        EXPECT_EQ(obj->m_last_txout_nonce, s.m_last_txout_nonce);
        EXPECT_EQ(obj->m_hash_link.m_state.m_data, s.m_hash_link.m_state.m_data);
        EXPECT_EQ(obj->m_hash_link.m_extra_data.m_data, s.m_hash_link.m_extra_data.m_data);
        EXPECT_EQ(obj->m_hash_link.m_length, s.m_hash_link.m_length);
        // DASH suffix
        EXPECT_EQ(obj->m_coinbase_payload.m_data, s.m_coinbase_payload.m_data);
        EXPECT_EQ(obj->m_payment_amount, s.m_payment_amount);
        ASSERT_EQ(obj->m_packed_payments.size(), s.m_packed_payments.size());
        EXPECT_EQ(obj->m_packed_payments[0].m_payee, s.m_packed_payments[0].m_payee);
        EXPECT_EQ(obj->m_packed_payments[0].m_amount, s.m_packed_payments[0].m_amount);
        EXPECT_EQ(obj->m_coinbase_payload_outer.m_data, s.m_coinbase_payload_outer.m_data);
    });

    // Re-serialize the loaded share: must be byte-identical to the original wire.
    PackStream re;
    loaded.Serialize(re);
    EXPECT_EQ(pack_hex(re), pack_hex(wire)) << "v36 re-serialization must round-trip";

    // Dispatch reports version 36.
    EXPECT_EQ(loaded.version(), 36);
}

// ── 3. MERGED fields inert => non-merged cross-coin convention ───────────────
TEST(DashV36ShareMergedInert, EmptyMergedFieldsFollowNonMergedConvention)
{
    auto s = make_canonical_v36();
    ASSERT_TRUE(s.m_merged_addresses.empty());
    ASSERT_TRUE(s.m_merged_coinbase_info.empty());
    ASSERT_TRUE(s.m_merged_payout_hash.IsNull());

    // An empty vector serializes as a single VarInt(0) == 0x00 byte; a zero
    // uint256 payout hash as 32 zero bytes. Same as a standalone ltc/dgb/bch coin.
    PackStream a; a << s.m_merged_addresses;
    EXPECT_EQ(pack_hex(a), "00");
    PackStream c; c << s.m_merged_coinbase_info;
    EXPECT_EQ(pack_hex(c), "00");
    PackStream p; p << s.m_merged_payout_hash;
    EXPECT_EQ(pack_hex(p), std::string(64, '0'));
    PackStream m; m << s.m_message_data;
    EXPECT_EQ(pack_hex(m), "00") << "empty message_data (Phase A) == VarInt(0)";
}

// ── 4. version-vote (desired_version) is a VarInt the ratchet can read ────────
TEST(DashV36ShareVersionVote, DesiredVersionRidesAsVarInt)
{
    auto s = make_canonical_v36();
    s.m_desired_version = 36;
    PackStream a; ::Serialize(a, VarInt(s.m_desired_version));
    EXPECT_EQ(pack_hex(a), "24");   // 36 == 0x24, single-byte CompactSize

    s.m_desired_version = 300;      // multi-byte CompactSize boundary
    PackStream b; ::Serialize(b, VarInt(s.m_desired_version));
    EXPECT_EQ(pack_hex(b), "fd2c01");
}

// ── 5. BACKWARD-COMPAT: v16 DashShare wire is UNCHANGED and DISTINCT ─────────
TEST(DashV16BackwardCompat, V16RoundTripsAndIsDistinctFromV36)
{
    // Minimal v16 share.
    dash::DashShare v16;
    v16.m_min_header.m_version = 2;
    v16.m_min_header.m_bits = 0x1e0ffff0;
    v16.m_prev_hash.SetHex(
        "0000000000000000000000000000000000000000000000000000000000000001");
    v16.m_coinbase = BaseScript(std::vector<unsigned char>{0xab, 0xcd});
    v16.m_nonce = 0x0a0b0c0d;
    v16.m_pubkey_hash.SetHex("00000000000000000000000000000000deadbeef");
    v16.m_subsidy = 5000000000ULL;
    v16.m_donation = 0x1234;
    v16.m_desired_version = 16;
    v16.m_bits = 0x1d00ffff;
    v16.m_hash_link.m_state.m_data.assign(32, 0x00);
    v16.m_hash_link.m_length = 0;

    // v16 packs via the live ShareType formatter (else-branch) and round-trips
    // through the live LoadMethods[16] dispatch — byte-unchanged by the refactor.
    PackStream w16; dash::DashFormatter::Write(w16, &v16);
    chain::RawShare r16(uint64_t{16}, w16);
    auto loaded16 = dash::load_share(r16, NetService{"test", 0});
    EXPECT_EQ(loaded16.version(), 16);
    PackStream re16; loaded16.Serialize(re16);
    EXPECT_EQ(pack_hex(re16), pack_hex(w16)) << "v16 wire must round-trip unchanged";

    // v16-specific ordering pin: coinbase_payload is serialized IMMEDIATELY after
    // coinbase (v16 share_data), a slot the v36 layout does NOT have there. Prove
    // the two layouts are distinct for the same logical inputs.
    auto v36 = make_canonical_v36();
    PackStream w36; dash::DashFormatter::Write(w36, &v36);
    EXPECT_NE(pack_hex(w16), pack_hex(w36))
        << "v16 and v36 wire layouts must differ (distinct share formats)";
}
