// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH share hash_link / gentx_hash byte-parity vs oracle (frstrtr/p2pool-dash).
//
// Pins the coinbase_payload encoding inside the gentx hash_link_data assembly.
// Oracle data.py:278,346-348: the outer coinbase_payload is appended to the
// check_hash_link data as pack.VarStrType().pack(payload) == [compactsize(len)]
// [payload] when non-empty, and as b"" (nothing) when None/empty. A prior
// c2pool defect appended the RAW payload bytes with NO compactsize prefix, so
// for any non-empty (DIP4 CbTx) payload the gentx_hash — and therefore share
// accept/reject — diverged from the oracle. This is net-new coverage: DASH had
// no caller of share_init_verify under test.
//
// Two complementary anchors:
//   1. OracleCheckHashLinkVarStrPayload — a non-circular pin. With a length-0
//      hash_link seeded by the SHA-256 IV, dash::check_hash_link degenerates to
//      plain SHA256d(data), so the expected digest is computed OUT-OF-BAND with
//      CPython hashlib over a fully-known byte vector (ref || nonce || 0 ||
//      VarStr(payload)). Also asserts the buggy raw-append form yields a
//      DIFFERENT, separately-pinned digest, proving the prefix is load-bearing.
//   2. ShareInitVerifyAppendsOuterValueVerbatim — exercises the production
//      share_init_verify() end-to-end on a DashShare with a non-empty outer
//      payload. With empty merkle/ref links the block merkle_root equals the
//      gentx_hash, so X11(reconstructed header) is a faithful proxy for the
//      gentx_hash. Oracle framing (data.py:277-289, 346-348): the outer field
//      VALUE m_data is the VarStr-PACKED payload ([compactsize][raw]) and is
//      appended VERBATIM — so the check data carries exactly ONE compactsize
//      prefix. The double-prefix form (re-VarStr'ing m_data, the pre-producer
//      -slice defect) and the bare-raw form (no prefix at all, the pre-#412
//      defect) are both asserted to differ, so the test is discriminating in
//      both directions.

#include <gtest/gtest.h>

#include <impl/dash/share_check.hpp>   // share_init_verify, check_hash_link, check_merkle_link, compute_gentx_before_refhash
#include <impl/dash/share.hpp>         // dash::DashShare
#include <impl/dash/share_types.hpp>   // dash::HashLinkType, dash::MerkleLink
#include <impl/dash/params.hpp>        // dash::make_coin_params

#include <core/coin_params.hpp>
#include <core/hash.hpp>               // Hash (sha256d)
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>       // chain::bits_to_target
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

// SHA-256 initial hash values (big-endian). Seeding a length-0 hash_link with
// these makes check_hash_link == SHA256d(data) — see header note (1).
constexpr std::array<unsigned char, 32> SHA256_IV = {
    0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85, 0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
    0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c, 0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19,
};

// Raw-digest / uint256-internal order (matches test_dash_conformance idiom).
std::string hex_of(const uint256& h) {
    auto c = h.GetChars();
    return HexStr(std::span<const unsigned char>(c.data(), c.size()));
}

dash::HashLinkType iv_hash_link() {
    dash::HashLinkType hl;
    hl.m_state.m_data.assign(SHA256_IV.begin(), SHA256_IV.end());
    hl.m_extra_data.m_data.clear();
    hl.m_length = 0;  // length % 64 == 0 -> no const_ending consumed; CSHA256 starts fresh
    return hl;
}

void put_le(std::vector<unsigned char>& v, uint64_t x, int n) {
    for (int i = 0; i < n; ++i) v.push_back(static_cast<unsigned char>((x >> (8 * i)) & 0xff));
}

// Parse a hex string to bytes (test fixtures embed real on-chain payloads).
std::vector<unsigned char> bytes_from_hex(const std::string& h) {
    std::vector<unsigned char> v; v.reserve(h.size() / 2);
    auto nib = [](char c) -> int { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return v;
}

// Append Bitcoin CompactSize(n) == oracle pack.VarStrType length prefix.
void append_compactsize(std::vector<unsigned char>& v, uint64_t n) {
    if (n < 0xfd) { v.push_back(static_cast<unsigned char>(n)); }
    else if (n <= 0xffff) { v.push_back(0xfd); put_le(v, n, 2); }
    else if (n <= 0xffffffffULL) { v.push_back(0xfe); put_le(v, n, 4); }
    else { v.push_back(0xff); put_le(v, n, 8); }
}

const std::vector<unsigned char> kPayload = {0xde, 0xad, 0xbe, 0xef};

} // namespace

// (1) Non-circular oracle anchor: SHA256d over a fully-known byte vector.
TEST(DashShareHashLink, OracleCheckHashLinkVarStrPayload) {
    auto hl = iv_hash_link();
    const auto ce = dash::compute_gentx_before_refhash();  // unused at length%64==0

    std::vector<unsigned char> data;
    for (int i = 0; i < 32; ++i) data.push_back(static_cast<unsigned char>(i));  // ref_hash
    put_le(data, 0, 8);   // last_txout_nonce
    put_le(data, 0, 4);   // IntType(32).pack(0)
    data.push_back(static_cast<unsigned char>(kPayload.size()));                 // compactsize
    data.insert(data.end(), kPayload.begin(), kPayload.end());                   // VarStr(payload)

    uint256 g = dash::check_hash_link(hl, data, ce);
    // CPython: sha256d(bytes(range(32)) + 0*8 + 0*4 + b"\x04\xde\xad\xbe\xef")
    EXPECT_EQ(hex_of(g), "2d21628941d5bd07d5fe90349bb113ed0fad495a0d33bf4f5c270697c40e8843");

    // Buggy raw-append (no compactsize) -> different, separately-pinned digest.
    std::vector<unsigned char> raw;
    for (int i = 0; i < 32; ++i) raw.push_back(static_cast<unsigned char>(i));
    put_le(raw, 0, 8);
    put_le(raw, 0, 4);
    raw.insert(raw.end(), kPayload.begin(), kPayload.end());
    uint256 gr = dash::check_hash_link(hl, raw, ce);
    EXPECT_EQ(hex_of(gr), "75e4562b843ac74b7c78db29dc40ce10d6659c578159c5952638b3340f877fb2");
    EXPECT_NE(hex_of(g), hex_of(gr)) << "compactsize prefix must change gentx_hash";
}

// (1b) Non-circular oracle anchor over REAL testnet3 DIP4 special-tx payloads.
// #412 proved the VarStr(coinbase_payload) assembly with a 4-byte synthetic
// payload; G0/G1 (per-coin byte-parity gate before the G2 crossing) pins the
// SAME assembly against ACTUAL on-chain extraPayloads captured from dashd
// (testnet3), covering BOTH compactsize branches: single-byte (<0xfd) and
// 0xfd+u16-LE. Expected digests are computed OUT-OF-BAND with CPython
// (sha256d), so they are non-circular with the C++ check_hash_link path.
//   A: blk 1502030 txid 7d292a63... type-5 CbTx, 175B (compactsize 0xaf)
//   B: blk 1501948 txid b4d1a2a5... type-6 qcTx, 419B (compactsize 0xfd a3 01)
TEST(DashShareHashLink, RealTestnet3SpecialTxVarStrParity) {
    auto hl = iv_hash_link();
    const auto ce = dash::compute_gentx_before_refhash();  // unused at length%64==0

    struct CbTxKat { const char* name; const char* payload_hex;
                     const char* varstr; const char* raw_append; };
    const CbTxKat kats[] = {
        {"testnet3-1502030-cbtx-type5",
         "03004eeb1600286ca33b2ec502759646df1259df9ee5b599722122f5bb4ba6a01062782e489ff09af4994ea6306dbe1aa636373c0d9c0fabc6c61d4402754b9878f63f4c277e008b96e1d2f74c1717728f47d319e151460adc51ffd76686c10ede2e3a31d5faaeb724a65736167a7d8f17b1f880585a0c1164f6882d5e5d6c8a5ff3b75d47ee6359d0662964109e7fa17658d04843e4c6eca499a55ed01bd4efd49b10848aa04a5a36b0fcdb1d0000",
         "6e985201f8a1d0cf46c97a1379c140c9564ee56c1649af5cbce8b7d9cc986665",
         "69ebfd8ee54d039ffece6bb1c8cab97ec3c6b24715e4ae57c30428a9dbc4ac1a"},
        {"testnet3-1501948-qctx-type6",
         "0100fcea160003000270282f59392f2433c05a9f4c948c9f31dab53cf42e112ca68b9854fdc5000000fd90010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fd900100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
         "e60ea7ea8c11c17af6a7573b0399c87e4672175986cf54d407875bf33c05c84f",
         "4fa8a56bb753593362540b9d8006c2b80a191d2d194eba2714162a9cd41bbe56"},
    };
    for (const auto& k : kats) {
        const auto payload = bytes_from_hex(k.payload_hex);

        // VarStr(payload) = CompactSize(len) || payload  (oracle data.py:278)
        std::vector<unsigned char> data;
        for (int i = 0; i < 32; ++i) data.push_back(static_cast<unsigned char>(i));
        put_le(data, 0, 8);   // last_txout_nonce
        put_le(data, 0, 4);   // IntType(32).pack(0)
        append_compactsize(data, payload.size());
        data.insert(data.end(), payload.begin(), payload.end());
        uint256 g = dash::check_hash_link(hl, data, ce);
        EXPECT_EQ(hex_of(g), k.varstr) << k.name;

        // Buggy raw-append (no compactsize) -> separately-pinned, must differ.
        std::vector<unsigned char> raw;
        for (int i = 0; i < 32; ++i) raw.push_back(static_cast<unsigned char>(i));
        put_le(raw, 0, 8);
        put_le(raw, 0, 4);
        raw.insert(raw.end(), payload.begin(), payload.end());
        uint256 gr = dash::check_hash_link(hl, raw, ce);
        EXPECT_EQ(hex_of(gr), k.raw_append) << k.name;
        EXPECT_NE(hex_of(g), hex_of(gr)) << k.name << ": compactsize prefix must matter";
    }
}

// (2) End-to-end through the production share_init_verify().
TEST(DashShareHashLink, ShareInitVerifyAppendsOuterValueVerbatim) {
    const core::CoinParams params = dash::make_coin_params(/*testnet=*/false);

    // Oracle field value: VarStr-packed payload ([compactsize][raw]) — what
    // DashFormatter's single strip leaves in m_data for a live oracle share.
    std::vector<unsigned char> outer_value;
    outer_value.push_back(static_cast<unsigned char>(kPayload.size()));
    outer_value.insert(outer_value.end(), kPayload.begin(), kPayload.end());

    dash::DashShare share;
    share.m_coinbase = BaseScript(std::vector<unsigned char>{0x00, 0x00});  // 2 bytes (valid 2..100)
    share.m_coinbase_payload_outer.m_data = outer_value;                    // NON-empty (under test)
    share.m_desired_version = 16;
    share.m_bits = 0x1d00ffffu;       // bits_to_target == mainnet max_target (passes validity guard)
    share.m_max_bits = 0x1d00ffffu;
    share.m_hash_link = iv_hash_link();
    // empty m_ref_merkle_link / m_merkle_link -> ref_hash == hash_ref, merkle_root == gentx_hash

    // ---- mirror share_init_verify ref_hash assembly (to feed expected gentx) ----
    PackStream ref_stream;
    {
        auto hex = params.active_identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            unsigned char b = static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&b), 1));
        }
    }
    ref_stream << share.m_prev_hash;
    ref_stream << share.m_coinbase;
    ref_stream << share.m_coinbase_payload;
    ref_stream << share.m_nonce;
    ref_stream << share.m_pubkey_hash;
    ref_stream << share.m_subsidy;
    ref_stream << share.m_donation;
    { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref_stream << si; }
    ::Serialize(ref_stream, VarInt(share.m_desired_version));
    ref_stream << share.m_payment_amount;
    ref_stream << share.m_packed_payments;
    ref_stream << share.m_new_transaction_hashes;
    {
        uint64_t pair_count = share.m_transaction_hash_refs.size() / 2;
        ::Serialize(ref_stream, VarInt(pair_count));
        for (auto& v : share.m_transaction_hash_refs) ::Serialize(ref_stream, VarInt(v));
    }
    ref_stream << share.m_far_share_hash;
    ref_stream << share.m_max_bits;
    ref_stream << share.m_bits;
    ref_stream << share.m_timestamp;
    ref_stream << share.m_absheight;
    ref_stream << share.m_abswork;
    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 ref_hash = dash::check_merkle_link(Hash(ref_span), share.m_ref_merkle_link);

    // expected gentx: 0 = ORACLE (append field value verbatim = ONE prefix);
    // 1 = double-prefix defect (re-VarStr the value); 2 = bare-raw defect.
    auto build_gentx = [&](int form) {
        std::vector<unsigned char> hd(ref_hash.data(), ref_hash.data() + 32);
        put_le(hd, share.m_last_txout_nonce, 8);
        put_le(hd, 0, 4);
        if (form == 0) {
            hd.insert(hd.end(), outer_value.begin(), outer_value.end());
        } else if (form == 1) {
            PackStream ps; ps << share.m_coinbase_payload_outer;
            auto* cp = reinterpret_cast<const unsigned char*>(ps.data());
            hd.insert(hd.end(), cp, cp + ps.size());
        } else {
            hd.insert(hd.end(), kPayload.begin(), kPayload.end());
        }
        return dash::check_hash_link(share.m_hash_link, hd, dash::compute_gentx_before_refhash());
    };

    auto share_hash_for = [&](const uint256& gentx) {
        uint256 merkle_root = dash::check_merkle_link(gentx, share.m_merkle_link);  // empty -> gentx
        PackStream hs;
        uint32_t v = static_cast<uint32_t>(share.m_min_header.m_version); hs << v;
        hs << share.m_min_header.m_previous_block;
        hs << merkle_root;
        hs << share.m_min_header.m_timestamp;
        hs << share.m_min_header.m_bits;
        hs << share.m_min_header.m_nonce;
        auto hsp = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(hs.data()), hs.size());
        return params.pow_func(hsp);
    };

    uint256 expected      = share_hash_for(build_gentx(0));
    uint256 double_prefix = share_hash_for(build_gentx(1));
    uint256 bare_raw      = share_hash_for(build_gentx(2));
    ASSERT_NE(hex_of(expected), hex_of(double_prefix)) << "test must discriminate";
    ASSERT_NE(hex_of(expected), hex_of(bare_raw)) << "test must discriminate";

    uint256 actual = dash::share_init_verify(share, params, /*check_pow=*/false);
    EXPECT_EQ(hex_of(actual), hex_of(expected))
        << "share_init_verify must append the outer field value verbatim "
           "(it already carries the oracle's single compactsize prefix)";
    EXPECT_NE(hex_of(actual), hex_of(double_prefix));
    EXPECT_NE(hex_of(actual), hex_of(bare_raw));
}