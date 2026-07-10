// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH V36 conformance — merkle-root-equality precondition (S6 slice).
//
// Before any share/block can be conformance-checked against DASH's own
// older-than-v35 oracle (frstrtr/p2pool-dash), one structural invariant must
// hold: the gentx hash plus the share's merkle_link must reconstruct the
// SAME block merkle root that a full-tree reduction of the transaction set
// produces. If that precondition fails, every downstream equality comparison
// is meaningless (you'd be comparing roots derived two different ways).
//
// This test pins that precondition WITHOUT a node dependency. It cross-checks
// the production path —
//     dash::coinbase::merkle_branches_raw()  (build the index-0 branch)
//     dash::check_merkle_link()              (walk gentx + branch -> root)
// — against an INDEPENDENT in-test reference reduction (canonical Bitcoin/
// p2pool merkle: pairwise SHA256d, duplicate-last on odd). Two implementations
// agreeing is the invariant.
//
// The expected-root hex strings are KAT vectors computed OUT-OF-BAND with
// CPython hashlib (double-SHA256), so the pins are not circular with the C++
// code under test. Leaves are sha256d(single byte i) so the fixtures are
// reproducible with a three-line script and carry no byte-order ambiguity
// (raw digest bytes == uint256 internal order == HexStr(GetChars())).
//
// NOTE: real captured-corpus KAT vectors from a live Dash node (VM200/201)
// are the S6 follow-on and gate on node-state-green; this slice locks the
// structural precondition those vectors will later exercise.

#include <gtest/gtest.h>

#include <impl/dash/coinbase_builder.hpp>   // dash::coinbase::merkle_branches_raw, HexStr
#include <impl/dash/share_check.hpp>        // dash::check_merkle_link
#include <impl/dash/chain_admit.hpp>        // dash::admit_chain_relative (accept-path seam)
#include <impl/dash/share_types.hpp>        // dash::MerkleLink
#include <impl/dash/pplns.hpp>           // dash::pplns::compute_payouts, dash::ShareChain, DashShare
#include <impl/dash/version_negotiation.hpp> // dash::version_negotiation::get_desired_version_counts/weights
#include <impl/dash/coin/vendor/cbtx.hpp> // dash::coin::vendor::CCbTx, parse_cbtx
#include <impl/dash/config_pool.hpp>     // dash::SharechainConfig (sharechain SSOT)
#include <impl/bitcoin_family/coin/base_block.hpp>  // bitcoin_family::coin::SmallBlockHeaderType

#include <core/hash.hpp>                     // Hash (sha256d)
#include <core/uint256.hpp>
#include <core/donation.hpp>                 // cross-coin COMBINED_DONATION_SCRIPT SSOT

#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <vector>

namespace {

// Leaf fixture: sha256d of a single byte. Matches CPython
//   hashlib.sha256(hashlib.sha256(bytes([i])).digest()).digest()
uint256 leaf(uint8_t b) {
    unsigned char x = b;
    return Hash(std::span<const unsigned char>(&x, 1));
}

// Independent canonical merkle-root reduction (NOT the production walk):
// pairwise SHA256d over the whole layer, duplicate the last on odd width.
uint256 reference_root(std::vector<uint256> layer) {
    while (layer.size() > 1) {
        if (layer.size() % 2 == 1) layer.push_back(layer.back());
        std::vector<uint256> next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i + 1 < layer.size(); i += 2) {
            unsigned char buf[64];
            std::memcpy(buf,      layer[i].data(),     32);
            std::memcpy(buf + 32, layer[i + 1].data(), 32);
            next.push_back(Hash(std::span<const unsigned char>(buf, 64)));
        }
        layer.swap(next);
    }
    return layer.empty() ? uint256() : layer[0];
}

std::string hex_internal(const uint256& h) {
    auto c = h.GetChars();
    return HexStr(std::span<const unsigned char>(c.data(), c.size()));
}

// Production path: build the index-0 branch and walk gentx (=leaf[0]) back.
uint256 production_root(const std::vector<uint256>& txs) {
    dash::MerkleLink link;
    link.m_branch = dash::coinbase::merkle_branches_raw(txs);
    link.m_index  = 0;  // coinbase / gentx is always at position 0
    return dash::check_merkle_link(txs[0], link);
}

struct Kat { int n; const char* root_hex; };

// KAT vectors — CPython hashlib double-SHA256, internal (raw-digest) byte order.
const Kat KATS[] = {
    {1, "1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a"},
    {2, "4bbe83bc38ebe2bcc7520d234139df1c0eb9ffa51f83eab1c5129b5b906b7655"},
    {3, "e129dfe02f567fc612d126596d43406144f40a771810ac7143421d2df3e5c1d0"},
    {5, "f4113849d628f7c3bc91cc0ff785a6aee3ee236c1c912b28cc09c44f9f97b748"},
    {7, "7de65c7d57cdc72971c9beab94af6ad4e99f233fb6ccebd2b4b19f13697ca54d"},
};

}  // namespace

// Production walk == independent reference reduction, across tree shapes
// (1 leaf, even, odd/duplicate-last). This is the merkle-root-equality
// precondition itself.
TEST(DashConformanceMerkle, ProductionWalkMatchesReferenceReduction) {
    for (const auto& k : KATS) {
        std::vector<uint256> txs;
        for (int i = 0; i < k.n; ++i) txs.push_back(leaf(static_cast<uint8_t>(i)));
        EXPECT_EQ(production_root(txs), reference_root(txs))
            << "n=" << k.n << ": gentx+merkle_link did not reconstruct the full-tree root";
    }
}

// Both paths must equal the out-of-band CPython KAT — locks byte order and
// guards against a coordinated regression in BOTH C++ implementations.
TEST(DashConformanceMerkle, MatchesOutOfBandKat) {
    for (const auto& k : KATS) {
        std::vector<uint256> txs;
        for (int i = 0; i < k.n; ++i) txs.push_back(leaf(static_cast<uint8_t>(i)));
        EXPECT_EQ(hex_internal(production_root(txs)), std::string(k.root_hex))
            << "n=" << k.n << ": production root != CPython KAT";
        EXPECT_EQ(hex_internal(reference_root(txs)), std::string(k.root_hex))
            << "n=" << k.n << ": reference root != CPython KAT";
    }
}

// A single transaction (coinbase only): the gentx IS the merkle root, branch
// is empty, and the walk must be the identity.
TEST(DashConformanceMerkle, SingleTxRootIsGentx) {
    std::vector<uint256> txs{leaf(0)};
    EXPECT_TRUE(dash::coinbase::merkle_branches_raw(txs).empty());
    EXPECT_EQ(production_root(txs), txs[0]);
}

// ── Payout-script-encoding conformance (S6 slice 2) ──────────────────────────
// Before any PPLNS payout SET can be conformance-checked against DASH's own
// older oracle (frstrtr/p2pool-dash data.py), each recipient's scriptPubKey
// must encode byte-identically. Dash payouts are ALWAYS P2PKH (no segwit):
//     OP_DUP OP_HASH160 <0x14> <20-byte hash160> OP_EQUALVERIFY OP_CHECKSIG
// i.e. 76 a9 14 <hash> 88 ac, total 25 bytes, with the hash emitted in uint160
// internal (GetChars) order and NO reversal. These KATs pin that encoding with
// no node dependency; the donation cross-check proves two independent
// representations of the same recipient agree.
namespace {

uint160 h160(const std::vector<unsigned char>& v) { return uint160(v); }

std::string hex_bytes(const std::vector<unsigned char>& v) {
    return HexStr(std::span<const unsigned char>(v.data(), v.size()));
}

// p2pool-dash DONATION_SCRIPT hash160 (data.py) — the 20 bytes between the
// 76 a9 14 prefix and the 88 ac suffix of dash::DONATION_SCRIPT.
const std::vector<unsigned char> DONATION_H160 = {
    0x20, 0xcb, 0x5c, 0x22, 0xb1, 0xe4, 0xd5, 0x94,
    0x7e, 0x5c, 0x11, 0x2c, 0x76, 0x96, 0xb5, 0x1a,
    0xd9, 0xaf, 0x3c, 0x61
};

struct ScriptKat { std::vector<unsigned char> h160; const char* script_hex; };

}  // namespace

// Canonical P2PKH shape for arbitrary hash160s, hash bytes in GetChars order.
TEST(DashConformancePayoutScript, CanonicalP2PKHStructure) {
    const std::vector<std::vector<unsigned char>> hashes = {
        std::vector<unsigned char>(20, 0x00),
        std::vector<unsigned char>(20, 0xff),
        DONATION_H160,
    };
    for (const auto& hv : hashes) {
        auto s = dash::pubkey_hash_to_script2(h160(hv));
        ASSERT_EQ(s.size(), 25u);
        EXPECT_EQ(s[0], 0x76); EXPECT_EQ(s[1], 0xa9); EXPECT_EQ(s[2], 0x14);
        EXPECT_EQ(s[23], 0x88); EXPECT_EQ(s[24], 0xac);
        for (size_t i = 0; i < 20; ++i)
            EXPECT_EQ(s[3 + i], hv[i]) << "hash byte " << i << " not in GetChars order";
    }
}

// Out-of-band KAT: full 25-byte P2PKH script hex for fixed hash160s.
TEST(DashConformancePayoutScript, MatchesOutOfBandKat) {
    const ScriptKat kats[] = {
        { std::vector<unsigned char>(20, 0x00),
          "76a914000000000000000000000000000000000000000088ac" },
        { DONATION_H160,
          "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac" },
    };
    for (const auto& k : kats)
        EXPECT_EQ(hex_bytes(dash::pubkey_hash_to_script2(h160(k.h160))),
                  std::string(k.script_hex));
}

// Two independent representations of the donation recipient agree: the literal
// DONATION_SCRIPT array (data.py copy) equals the script-builder over the
// donation hash160. Catches an accidental edit to either path.
TEST(DashConformancePayoutScript, DonationScriptIsP2PKHOverDonationHash) {
    EXPECT_EQ(dash::pubkey_hash_to_script2(h160(DONATION_H160)),
              dash::DONATION_SCRIPT);
}

// ── v36 unified P2SH (Bucket-2) cross-coin SSOT lock ─────────────────────────
// Pillar-4 of the v36-migration-std sweep: DASH's v36+ donation P2SH must be the
// cross-coin SHARED shape, not a per-coin dialect. Proves (1) DASH's
// COMBINED_DONATION_SCRIPT is the SSOT core::donation::COMBINED_DONATION_SCRIPT
// byte-for-byte (so the literal can never drift from btc/bch/dgb/ltc), and
// (2) it is exactly the 23-byte P2SH a914<8c627262..8e85>87. Pre-v36 donation
// stays the DASH-specific P2PKH (Bucket-3) and is covered by the tests above.
TEST(DashConformanceCombinedDonation, MatchesCrossCoinSSOT) {
    const std::vector<unsigned char> ssot(
        core::donation::COMBINED_DONATION_SCRIPT.begin(),
        core::donation::COMBINED_DONATION_SCRIPT.end());
    EXPECT_EQ(dash::COMBINED_DONATION_SCRIPT, ssot);

    const std::vector<unsigned char> expected = {
        0xa9, 0x14,
        0x8c, 0x62, 0x72, 0x62, 0x1d, 0x89, 0xe8, 0xfa,
        0x52, 0x6d, 0xd8, 0x6a, 0xcf, 0xf6, 0x0c, 0x71,
        0x36, 0xbe, 0x8e, 0x85,
        0x87
    };
    EXPECT_EQ(dash::COMBINED_DONATION_SCRIPT, expected);
    EXPECT_EQ(dash::COMBINED_DONATION_SCRIPT.size(), 23u);
}

// ── Masternode-payment-packing conformance (S6 slice 3) ──────────────────────
// Dash's PPLNS payout set carries DASH-SPECIFIC entries BTC p2pool has no
// analogue for: masternode / superblock / platform payments, each packed as
// PackedPayment{ payee (PossiblyNone VarStr), amount (LE uint64) }. Before a
// full payout SET can be conformance-checked against frstrtr/p2pool-dash
// (data.py packed_payments), the single-entry and vector wire framing must
// match byte-for-byte: a CompactSize-prefixed payee string + 8-byte LE amount,
// and a CompactSize-prefixed vector count. These KATs are computed OUT-OF-BAND
// with CPython (CompactSize + struct "<Q"), so they are NOT circular with the
// C++ Serialize path. The round-trip case proves Unserialize is its inverse.
namespace {
std::string ps_hex(const PackStream& ps) {
    auto& m = const_cast<PackStream&>(ps);
    return HexStr(std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(m.data()), m.size()));
}

dash::PackedPayment payment(const std::string& payee, uint64_t amount) {
    dash::PackedPayment pp;
    pp.m_payee = payee;
    pp.m_amount = amount;
    return pp;
}

}  // namespace

// Single PackedPayment: CompactSize(len) + payee bytes + LE64 amount. The empty
// payee is PossiblyNone(None) -> a single 0x00 length, NOT a sentinel.
TEST(DashConformancePayment, SingleEntryMatchesOutOfBandKat) {
    struct PayKat { const char* payee; uint64_t amount; const char* hex; };
    const PayKat kats[] = {
        {"", 0, "000000000000000000"},
        {"XyPmasternodePayeeAddr00", 200000000,
         "185879506d61737465726e6f6465506179656541646472303000c2eb0b00000000"},
        {"!76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac", 500000000,
         "332137366139313432306362356332326231653464353934376535633131326337"
         "363936623531616439616633633631383861630065cd1d00000000"},
    };
    for (const auto& k : kats) {
        PackStream ps;
        ::Serialize(ps, payment(k.payee, k.amount));
        EXPECT_EQ(ps_hex(ps), std::string(k.hex))
            << "payee=\"" << k.payee << "\" amount=" << k.amount;
    }
}

// std::vector<PackedPayment> prefixes a CompactSize count, then each entry.
TEST(DashConformancePayment, VectorFramingMatchesOutOfBandKat) {
    std::vector<dash::PackedPayment> v{
        payment("XyPmasternodePayeeAddr00", 200000000),
        payment("", 0),
    };
    PackStream ps;
    ::Serialize(ps, v);
    EXPECT_EQ(ps_hex(ps),
        std::string("02185879506d61737465726e6f6465506179656541646472303000c2eb0b"
                    "00000000000000000000000000"));
}

// Unserialize is the exact inverse of Serialize (payee + amount recovered).
TEST(DashConformancePayment, RoundTripRecoversFields) {
    const auto orig = payment("XyPmasternodePayeeAddr00", 200000000);
    PackStream ps;
    ::Serialize(ps, orig);
    dash::PackedPayment back;
    ::Unserialize(ps, back);
    EXPECT_EQ(back.m_payee, orig.m_payee);
    EXPECT_EQ(back.m_amount, orig.m_amount);
}

// ── Share-header wire-equality conformance (S6 slice 4) ──────────────────────
// A DASH share embeds a compact min_header (bitcoin_family::coin::
// SmallBlockHeaderType): CompactSize(version) + prev_block(32, internal order)
// + LE32 timestamp + LE32 bits + LE32 nonce. The VarInt(version) is c2pool's
// CompactFormat == Bitcoin CompactSize (0xfd/0xfe prefixes), the SAME encoding
// frstrtr/p2pool-dash's small_block_header_type uses for 'version'. Before a
// share header can be conformance-checked against that older-than-v35 oracle,
// this framing must match byte-for-byte. KATs are computed OUT-OF-BAND with
// CPython (CompactSize + struct "<I" + sha256d), so they are NOT circular with
// the C++ Serialize path. prev_block = sha256d(byte) reuses slice-1's
// unambiguous byte-order convention (raw digest == uint256 internal order ==
// serialized bytes, no reversal).
namespace {
bitcoin_family::coin::SmallBlockHeaderType
small_header(uint64_t version, uint8_t prev_seed, uint32_t ts, uint32_t bits, uint32_t nonce) {
    bitcoin_family::coin::SmallBlockHeaderType h;
    h.m_version = version;
    h.m_previous_block = leaf(prev_seed);   // Hash(single byte): internal order, no reversal
    h.m_timestamp = ts;
    h.m_bits = bits;
    h.m_nonce = nonce;
    return h;
}
}  // namespace

TEST(DashConformanceShareHeader, SmallHeaderMatchesOutOfBandKat) {
    struct HdrKat { uint64_t version; uint8_t prev; uint32_t ts, bits, nonce; const char* hex; };
    const HdrKat kats[] = {
        {1,     0, 0x00000000u, 0x00000000u, 0x00000000u,
         "011406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a000000000000000000000000"},
        {20,    1, 0x5f5e1000u, 0x1e0ffff0u, 0xdeadbeefu,
         "149c12cfdc04c74584d787ac3d23772132c18524bc7ab28dec4219b8fc5b425f7000105e5ff0ff0f1eefbeadde"},
        {253,   2, 0x12345678u, 0x207fffffu, 0x00000001u,
         "fdfd001cc3adea40ebfd94433ac004777d68150cce9db4c771bc7de1b297a7b795bbba78563412ffff7f2001000000"},
        {70221, 3, 0x499602d2u, 0x1b0404cbu, 0xfeedfaceu,
         "fe4d120100c942a06c127c2c18022677e888020afb174208d299354f3ecfedb124a1f3fa45d2029649cb04041bcefaedfe"},
    };
    for (const auto& k : kats) {
        PackStream ps;
        ::Serialize(ps, small_header(k.version, k.prev, k.ts, k.bits, k.nonce));
        EXPECT_EQ(ps_hex(ps), std::string(k.hex))
            << "version=" << k.version << " bits=" << k.bits;
    }
}

// The CompactSize(version) byte is the conformance-critical boundary: a 1-byte
// encoding below 0xfd, a 0xfd + u16-LE at/above it. Pin both so a regression to
// a fixed-width version field (or to base-128 VarInt) is caught immediately.
TEST(DashConformanceShareHeader, VersionCompactSizeBoundary) {
    PackStream a; ::Serialize(a, small_header(252, 0, 0, 0, 0));
    EXPECT_EQ(ps_hex(a).substr(0, 2), std::string("fc"));     // 252 -> single byte
    PackStream b; ::Serialize(b, small_header(253, 0, 0, 0, 0));
    EXPECT_EQ(ps_hex(b).substr(0, 6), std::string("fdfd00"));  // 253 -> 0xfd + u16 LE
}

// Unserialize is the exact inverse of Serialize (all five fields recovered).
TEST(DashConformanceShareHeader, RoundTripRecoversFields) {
    const auto orig = small_header(70221, 3, 0x499602d2u, 0x1b0404cbu, 0xfeedfaceu);
    PackStream ps;
    ::Serialize(ps, orig);
    bitcoin_family::coin::SmallBlockHeaderType back;
    ::Unserialize(ps, back);
    EXPECT_EQ(back.m_version, orig.m_version);
    EXPECT_EQ(back.m_previous_block, orig.m_previous_block);
    EXPECT_EQ(back.m_timestamp, orig.m_timestamp);
    EXPECT_EQ(back.m_bits, orig.m_bits);
    EXPECT_EQ(back.m_nonce, orig.m_nonce);
}

// ── S6 conformance: nbits -> share difficulty equality vs frstrtr/p2pool-dash ──
//
// dash::coinbase::bits_to_difficulty() is the share-difficulty convention the
// pool advertises and that p2pool-dash peers expect. It must equal p2pool-dash
// bitcoin_data.target_to_difficulty(target):
//
//     difficulty_1 = 0xffff * 2**208 ;  difficulty = difficulty_1 / target
//
// Expected values are KAT vectors computed OUT-OF-BAND in CPython from that
// exact rational (big-int target via a re-implemented compact decode, then the
// p2pool ratio) — NOT from the C++ path — so the pins are not circular. The
// production path takes the top-64 target bits (target >> 192) and divides
// 0xffff0000 by them; for these vectors (compact size 0x1b..0x20) the targets
// significant bits never fall below bit 192, so that truncation is lossless and
// the two agree to the last ULP across diff 4.7e-10 .. 1.6e4.
TEST(DashConformanceDifficulty, BitsToDifficultyMatchesP2poolDash) {
    struct DiffKat { uint32_t nbits; double diff; };
    const DiffKat kats[] = {
        {0x1b104c8bu, 4020.7998157598363},
        {0x1e0ffff0u, 0.000244140625},
        {0x1d00ffffu, 1.0},
        {0x1b0404cbu, 16307.420938523983},
        {0x1c0fffffu, 15.999771117945784},
        {0x207fffffu, 4.6565423739069247e-10},
    };
    for (const auto& k : kats) {
        const double got = dash::coinbase::bits_to_difficulty(k.nbits);
        EXPECT_NEAR(got, k.diff, k.diff * 1e-12 + 1e-18) << "nbits=" << k.nbits;
    }
}

// ── Pillar-3 conformance: share-target validity guard vs p2pool-dash oracle ──
// Oracle data.py Share.__init__ rejects `self.target > net.MAX_TARGET`
// ("share target invalid") AND a zero target. c2pool share_init_verify previously
// enforced only the zero case — no share-diff-floor upper bound. This pins the
// restored guard against the mainnet floor (params.max_target == 0xFFFF*2**208).
TEST(DashConformanceShareTarget, RejectsTargetEasierThanFloorAndZero) {
    core::CoinParams params;
    params.max_target = dash::SharechainConfig::max_target();   // 00000000ffff00..00

    const uint256 floor = params.max_target;

    // exactly at the floor -> accepted (boundary, not "> floor")
    EXPECT_NO_THROW(dash::check_share_target_valid(floor, params));

    // strictly harder (numerically smaller target) -> accepted
    uint256 harder; harder.SetHex("000000000000ffff000000000000000000000000000000000000000000000000");
    EXPECT_NO_THROW(dash::check_share_target_valid(harder, params));

    // strictly easier than the floor (numerically larger) -> rejected
    uint256 easier; easier.SetHex("00000001ffff0000000000000000000000000000000000000000000000000000");
    EXPECT_THROW(dash::check_share_target_valid(easier, params), std::invalid_argument);

    // zero target -> rejected
    uint256 zero;
    EXPECT_THROW(dash::check_share_target_valid(zero, params), std::invalid_argument);
}

// ── PPLNS payout-SET equality conformance (S6 slice 6) ───────────────────────
// The miner-facing output of the whole sharechain is the PPLNS payout SET:
// the {scriptPubKey -> amount} map a coinbase pays. For DASH to be value-
// equivalent to its own older oracle (frstrtr/p2pool-dash data.py
// get_expected_payouts) every recipient AND every satoshi must agree. This
// slice pins that floored-proportional split — per-share weight = difficulty
// (bits_to_difficulty), worker/donation split by m_donation/65535, dust drop,
// and the ALWAYS-emitted donation residue line — against OUT-OF-BAND CPython
// KAT vectors (no node dependency, not circular with the C++ doubles).
//
// The synthetic ShareChain is test-local scaffolding: minimal back-linked
// DashShares carrying only the fields compute_payouts() reads. bits is fixed
// to 0x1d00ffff, whose difficulty is EXACTLY 1.0 (difficulty_1 == target), so
// every weight is the integer 1.0 and the running sums are bit-exact in any
// order — the only floating ops left are the split fractions (e.g. 2.0/3.0),
// which IEEE-double C++ and CPython evaluate identically. That removes the
// summation-order fragility that would otherwise make the KAT non-reproducible.
namespace {

// Compact bits whose Dash share difficulty is exactly 1.0 (see slice 5 KAT).
constexpr uint32_t BITS_DIFF1 = 0x1d00ffffu;

uint256 pplns_share_hash(uint8_t tag) {
    std::vector<unsigned char> v(32, 0x00);
    v[0]  = tag;
    v[31] = 0xa5;  // keep non-null independent of tag
    return uint256(v);
}

uint160 miner_h160(uint8_t tag) {
    std::vector<unsigned char> v(20, 0x00);
    v[0] = tag;
    return uint160(v);
}

// Owns a set of synthetic shares and the chain that indexes them. Shares are
// added tip-last; each links to `prev` via m_prev_hash. Only m_hash /
// m_prev_hash / m_bits / m_max_bits / m_donation / m_pubkey_hash are set.
struct SyntheticChain {
    dash::ShareChain chain;
    std::vector<dash::DashShare*> pool;  // chain (ShareVariants::destroy) owns the shares; raw avoids double-free

    uint256 add(uint8_t tag, const uint256& prev, uint16_t donation,
                const uint160& pkh,
                uint32_t bits = BITS_DIFF1, uint64_t version = 0) {
        auto* s = new dash::DashShare();
        s->m_hash        = pplns_share_hash(tag);
        s->m_prev_hash   = prev;
        // Final fields set BEFORE chain.add(): ShareIndex caches
        // work=target_to_average_attempts(bits_to_target(m_bits)) at insertion,
        // and a production share has immutable bits once it enters the chain.
        // (m_max_bits stays at diff1 -- min_work basis unchanged.)
        s->m_bits            = bits;
        s->m_max_bits        = BITS_DIFF1;
        s->m_desired_version = version;
        s->m_donation    = donation;
        s->m_pubkey_hash = pkh;
        const uint256 h  = s->m_hash;
        chain.add(s);
        pool.push_back(s);
        return h;
    }
};

// Flatten a payout result into {script_hex -> amount} for set comparison, and
// separately assert the outputs are sorted ascending by script bytes (the
// deterministic coinbase-output order compute_payouts() guarantees).
std::map<std::string, uint64_t> payout_set(const dash::pplns::Result& r) {
    std::map<std::string, uint64_t> out;
    for (const auto& p : r.payouts)
        out[HexStr(std::span<const unsigned char>(p.script.data(), p.script.size()))]
            = p.amount;
    return out;
}

std::string script_hex(const std::vector<unsigned char>& v) {
    return HexStr(std::span<const unsigned char>(v.data(), v.size()));
}

}  // namespace

// Two miners, A with two shares and B with one (all weight 1.0), V = 1 DASH.
// p2pool floored split: A = floor(2/3 * 1e8) = 66666666, B = floor(1/3 * 1e8)
// = 33333333, donation residue = 1. Outputs sorted by script bytes (A < B <
// donation). KAT amounts computed OUT-OF-BAND in CPython.
TEST(DashConformancePplns, ProportionalSplitMatchesOutOfBandKat) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x01), B = miner_h160(0x02);
    uint256 g   = sc.add(0x10, uint256(), 0, B);  // genesis: miner B
    uint256 s1  = sc.add(0x11, g,         0, A);  // miner A
    uint256 tip = sc.add(0x12, s1,        0, A);  // tip: miner A

    const uint64_t V = 100000000;  // 1 DASH
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xee));
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 2);

    ASSERT_FALSE(r.used_fallback);
    EXPECT_EQ(r.shares_used, 3u);

    const std::string a_hex = script_hex(dash::pubkey_hash_to_script2(A));
    const std::string b_hex = script_hex(dash::pubkey_hash_to_script2(B));
    const std::string d_hex = script_hex(dash::DONATION_SCRIPT);

    const std::map<std::string, uint64_t> expected = {
        {a_hex, 66666666u},
        {b_hex, 33333333u},
        {d_hex, 1u},
    };
    EXPECT_EQ(payout_set(r), expected);

    // Conservation: every satoshi of miner_value is accounted for.
    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);

    // Deterministic order: outputs sorted ascending by script bytes.
    for (size_t i = 1; i < r.payouts.size(); ++i)
        EXPECT_TRUE(r.payouts[i - 1].script < r.payouts[i].script)
            << "payout outputs not in canonical script order at index " << i;
}

// A single miner share with a ~10% donation (m_donation = 6553/65535). The
// worker keeps frac = 1 - 6553/65535 of the value; the unallocated remainder
// (donation portion + rounding) flows to the always-emitted donation line.
// CPython KAT: A = floor((1 - 6553/65535) * 1e8) = 90000762, donation = 9999238.
TEST(DashConformancePplns, DonationWeightSplitMatchesOutOfBandKat) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x01);
    uint256 tip = sc.add(0x20, uint256(), /*donation bps*/ 6553, A);

    const uint64_t V = 100000000;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xee));
    // min_shares = 1 so a single-share chain takes the PPLNS path, not fallback.
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 1);

    ASSERT_FALSE(r.used_fallback);
    const std::map<std::string, uint64_t> expected = {
        {script_hex(dash::pubkey_hash_to_script2(A)), 90000762u},
        {script_hex(dash::DONATION_SCRIPT),            9999238u},
    };
    EXPECT_EQ(payout_set(r), expected);

    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);
}

// Cold / insufficient chain: when fewer than min_shares ancestors are
// reachable, p2pool mines solo — a single payout of the full value to the
// caller's fallback script. Tip absent from the chain hits the same path.
TEST(DashConformancePplns, ColdChainFallsBackToSingleRecipient) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x01);
    uint256 tip = sc.add(0x30, uint256(), 0, A);  // only one share

    const uint64_t V = 100000000;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xee));

    // Default min_shares (20) is unmet by a 1-share chain -> fallback.
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback);
    ASSERT_TRUE(r.used_fallback);
    ASSERT_EQ(r.payouts.size(), 1u);
    EXPECT_EQ(r.payouts[0].script, fallback);
    EXPECT_EQ(r.payouts[0].amount, V);

    // A tip that isn't in the chain at all also falls back.
    auto r2 = dash::pplns::compute_payouts(sc.chain, pplns_share_hash(0x7f),
                                           10, V, fallback, 1);
    ASSERT_TRUE(r2.used_fallback);
    ASSERT_EQ(r2.payouts.size(), 1u);
    EXPECT_EQ(r2.payouts[0].amount, V);
}

// ── S6 conformance: payout dust-threshold (A1–A4) vs frstrtr/p2pool-dash ──────
//
// V36 oracle-conformance (operator 2026-06-18 "CONFORM TO ORACLE", option a):
// the PAYOUT path carries NO dust floor. Every worker whose proportional split
// floor(weight_frac * miner_value) is NONZERO is paid that amount to its own
// script, exactly as p2pool-dash data.py get_expected_payouts does
// (amounts[script] = subsidy*weight//total_weight). Only EXACTLY-zero outputs
// are dropped (oracle `if amounts[script]`). The always-emitted DONATION line
// carries ONLY the rounding remainder (miner_value - Σworkers), which may be 0.
//
// dash::SharechainConfig::dust_threshold() (100000 duff) survives as the vardiff /
// share-difficulty floor (c2pool_refactored.cpp mirror of work.py:326); it is
// NO LONGER consulted in the payout path. These KATs pin the oracle behaviour:
// a sub-dust-but-nonzero worker is PAID, not swept to donation. Amounts are
// OUT-OF-BAND oracle arithmetic; per-share work = diff-1 so each share weighs
// exactly 1.0 and the fractions below are exact.

// A1 + A2: a worker whose proportional split is nonzero but below the old
// 100000 floor is PAID to its own script (oracle pays every nonzero output);
// the donation line carries only the rounding remainder. A has 3 shares, B has
// 1 (weights 3.0 / 1.0); V = 200000. A = floor(0.75*200000) = 150000; B =
// floor(0.25*200000) = 50000 (sub-dust, PAID); residue = 0 -> donation = 0.
TEST(DashConformancePayoutDust, SubDustNonzeroWorkerPaidNotSwept) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x07), B = miner_h160(0x08);
    uint256 g   = sc.add(0x60, uint256(), 0, B);  // genesis: miner B (1 share)
    uint256 s1  = sc.add(0x61, g,         0, A);  // miner A
    uint256 s2  = sc.add(0x62, s1,        0, A);  // miner A
    uint256 tip = sc.add(0x63, s2,        0, A);  // tip: miner A (A has 3)

    const uint64_t V = 200000;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xef));
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 2);

    ASSERT_FALSE(r.used_fallback);
    EXPECT_EQ(r.shares_used, 4u);

    const std::string a_hex = script_hex(dash::pubkey_hash_to_script2(A));
    const std::string b_hex = script_hex(dash::pubkey_hash_to_script2(B));
    const std::string d_hex = script_hex(dash::DONATION_SCRIPT);

    const std::map<std::string, uint64_t> expected = {
        {a_hex, 150000u},
        {b_hex,  50000u},
        {d_hex,      0u},
    };
    EXPECT_EQ(payout_set(r), expected);

    // A1: sub-dust worker B is PAID its own output (oracle pays all nonzero).
    EXPECT_EQ(payout_set(r).at(b_hex), 50000u) << "sub-dust nonzero worker B must be paid";

    // A2: donation carries only the rounding remainder (here 0), NOT B's value.
    EXPECT_EQ(payout_set(r).at(d_hex), 0u) << "donation is the rounding remainder only";

    // A2: conservation — every duff of miner_value accounted for.
    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);
}

// A2b: every nonzero worker near the old threshold is paid. Same chain,
// V = 400000: B = floor(0.25*400000) = 100000 (paid), A = 300000, residue 0 ->
// donation 0. Under the oracle there is no `<`/`<=` boundary at all — any
// nonzero output is kept; this guards that the region at the old floor is paid.
TEST(DashConformancePayoutDust, ThresholdRegionNonzeroWorkersAllPaid) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x07), B = miner_h160(0x08);
    uint256 g   = sc.add(0x64, uint256(), 0, B);
    uint256 s1  = sc.add(0x65, g,         0, A);
    uint256 s2  = sc.add(0x66, s1,        0, A);
    uint256 tip = sc.add(0x67, s2,        0, A);

    const uint64_t V = 400000;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xef));
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 2);

    ASSERT_FALSE(r.used_fallback);
    const std::map<std::string, uint64_t> expected = {
        {script_hex(dash::pubkey_hash_to_script2(A)), 300000u},
        {script_hex(dash::pubkey_hash_to_script2(B)), 100000u},
        {script_hex(dash::DONATION_SCRIPT),                0u},
    };
    EXPECT_EQ(payout_set(r), expected);

    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);
}

// A3 (donation = rounding remainder only): the always-emitted donation line
// carries exactly miner_value - Σworkers, nothing else. A has 3 shares, B has 1;
// V = 200002 (not divisible by the weight total 4). A = floor(0.75*200002) =
// 150001; B = floor(0.25*200002) = 50000 (sub-dust, PAID); allocated = 200001;
// residue = 1 -> donation = 1. Proves the donation line is the remainder sink,
// not a dust sink, and that a sub-dust worker is paid alongside it.
TEST(DashConformancePayoutDust, DonationLineIsRoundingRemainderOnly) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x07), B = miner_h160(0x08);
    uint256 g   = sc.add(0x68, uint256(), 0, B);
    uint256 s1  = sc.add(0x69, g,         0, A);
    uint256 s2  = sc.add(0x6a, s1,        0, A);
    uint256 tip = sc.add(0x6b, s2,        0, A);

    const uint64_t V = 200002;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xef));
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 2);

    ASSERT_FALSE(r.used_fallback);
    const auto set = payout_set(r);
    const std::string a_hex = script_hex(dash::pubkey_hash_to_script2(A));
    const std::string b_hex = script_hex(dash::pubkey_hash_to_script2(B));
    const std::string d_hex = script_hex(dash::DONATION_SCRIPT);

    EXPECT_EQ(set.at(a_hex), 150001u);
    EXPECT_EQ(set.at(b_hex),  50000u) << "sub-dust nonzero worker still paid";
    ASSERT_EQ(set.count(d_hex), 1u) << "donation line must always be emitted";
    EXPECT_EQ(set.at(d_hex), 1u) << "donation == miner_value - sum(workers) (rounding remainder)";

    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);
}

// A4a (generated boundary, just-BELOW the old floor): 3:1 split, V = 399996.
// B = floor(399996/4) = 99999 -> under the OLD floor it was dropped; under the
// oracle it is PAID. A = floor(3*399996/4) = 299997; residue 0 -> donation 0.
// One duff under the old floor must now be paid to the worker.
TEST(DashConformancePayoutDust, GeneratedBoundaryJustBelowNowPaid) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x07), B = miner_h160(0x08);
    uint256 g   = sc.add(0x70, uint256(), 0, B);
    uint256 s1  = sc.add(0x71, g,         0, A);
    uint256 s2  = sc.add(0x72, s1,        0, A);
    uint256 tip = sc.add(0x73, s2,        0, A);

    const uint64_t V = 399996;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xef));
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 2);

    ASSERT_FALSE(r.used_fallback);
    const std::string a_hex = script_hex(dash::pubkey_hash_to_script2(A));
    const std::string b_hex = script_hex(dash::pubkey_hash_to_script2(B));
    const std::string d_hex = script_hex(dash::DONATION_SCRIPT);

    const std::map<std::string, uint64_t> expected = {
        {a_hex, 299997u},
        {b_hex,  99999u},
        {d_hex,      0u},
    };
    EXPECT_EQ(payout_set(r), expected);
    EXPECT_EQ(payout_set(r).at(b_hex), 99999u)
        << "99999 (one duff under the old floor) must now be paid";

    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);
}

// A4b (generated boundary, just-ABOVE the old floor): same split, V = 400004.
// B = floor(400004/4) = 100001 -> paid (as before); A = floor(3*400004/4) =
// 300003; residue 0 -> donation 0. Symmetric partner to A4a.
TEST(DashConformancePayoutDust, GeneratedBoundaryJustAbovePaid) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x07), B = miner_h160(0x08);
    uint256 g   = sc.add(0x74, uint256(), 0, B);
    uint256 s1  = sc.add(0x75, g,         0, A);
    uint256 s2  = sc.add(0x76, s1,        0, A);
    uint256 tip = sc.add(0x77, s2,        0, A);

    const uint64_t V = 400004;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xef));
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 2);

    ASSERT_FALSE(r.used_fallback);
    const std::map<std::string, uint64_t> expected = {
        {script_hex(dash::pubkey_hash_to_script2(A)), 300003u},
        {script_hex(dash::pubkey_hash_to_script2(B)), 100001u},
        {script_hex(dash::DONATION_SCRIPT),                0u},
    };
    EXPECT_EQ(payout_set(r), expected);

    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);
}

// A5 (surviving zero-filter): an EXACTLY-zero proportional split is the only
// thing still dropped (oracle `if amounts[script]`). 3:1 split, V = 3:
// B = floor(0.25*3) = 0 -> DROPPED (zero output); A = floor(0.75*3) = 2;
// residue = 1 -> donation = 1. Pins that the zero filter survives the floor's
// removal.
TEST(DashConformancePayoutDust, ExactlyZeroWorkerOutputDropped) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x07), B = miner_h160(0x08);
    uint256 g   = sc.add(0x78, uint256(), 0, B);
    uint256 s1  = sc.add(0x79, g,         0, A);
    uint256 s2  = sc.add(0x7a, s1,        0, A);
    uint256 tip = sc.add(0x7b, s2,        0, A);

    const uint64_t V = 3;
    auto fallback = dash::pubkey_hash_to_script2(miner_h160(0xef));
    auto r = dash::pplns::compute_payouts(sc.chain, tip, /*window*/ 10, V,
                                          fallback, /*min_shares*/ 2);

    ASSERT_FALSE(r.used_fallback);
    const std::string a_hex = script_hex(dash::pubkey_hash_to_script2(A));
    const std::string b_hex = script_hex(dash::pubkey_hash_to_script2(B));
    const std::string d_hex = script_hex(dash::DONATION_SCRIPT);

    EXPECT_EQ(payout_set(r).count(b_hex), 0u) << "exactly-zero worker output must be dropped";
    EXPECT_EQ(payout_set(r).at(a_hex), 2u);
    EXPECT_EQ(payout_set(r).at(d_hex), 1u);

    uint64_t sum = 0;
    for (const auto& p : r.payouts) sum += p.amount;
    EXPECT_EQ(sum, V);
}

// ── S6 conformance: share-version transition negotiation vs frstrtr/p2pool-dash ──
//
// The older-than-v35 -> v36 handshake. Two tallies are kept deliberately apart
// (the F10 version-gate trap): a PLAIN per-share vote count drives the
// SUCCESSOR confirmed-state guard / AutoRatchet, while a SEPARATE work-WEIGHTED
// tally drives the v36 activation gate. Mixing them is the exact divergence the
// fleet is converging on for V36.
//
// Reference: p2pool-dash data.py Share.check (60% SUCCESSOR guard, plain
// get_desired_version_counts) and p2pool-merged-v36 work.py (v36_active =
// weight[36]/Sum >= 0.95). All thresholds and weights below are KAT vectors
// computed OUT-OF-BAND in CPython from the exact integer formulas
//   target_to_average_attempts = 2**256 // (target + 1)
//   switch gate : have_w*100 >= total_w*60      (weighted, exact rational)
//   v36 gate    : w36*100 >= total*95           (exact rational)
// so the pins are not circular with the C++ path.

// Out-of-band CPython: diff-1 (0x1d00ffff) work = 2**256//(target+1).
static constexpr uint64_t W_DIFF1 = 4295032833ULL;   // 0x100010001
// Heavier share, bits 0x1c7fff00 (target = 0x7fff00 << (8*25)): work doubles+.
static constexpr uint32_t BITS_HEAVY = 0x1c7fff00u;
static constexpr uint64_t W_HEAVY  = 8590196744ULL;  // 0x200040008

namespace {
// Append a share with an explicit desired_version and bits. SyntheticChain's
// ShareIndex caches work from m_bits at add() time; version_negotiation reads
// obj->m_bits live, so post-add patching is what the production walk observes.
uint256 add_versioned(SyntheticChain& sc, uint8_t tag, const uint256& prev,
                      uint64_t version, uint32_t bits, const uint160& pkh) {
    // Bits/version set pre-insertion so the cached ShareIndex::work matches.
    return sc.add(tag, prev, /*donation*/ 0, pkh, bits, version);
}
}  // namespace

// Production plain count and work-weighted tally over the same window must equal
// the out-of-band CPython KATs: a 3x-v36(diff1) + 1x-v16(heavy) chain.
TEST(DashConformanceVersionNeg, PlainCountAndWeightVsOutOfBandKat) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x01);
    uint256 g   = add_versioned(sc, 0x40, uint256(), 16, BITS_HEAVY, A); // old, heavy
    uint256 s1  = add_versioned(sc, 0x41, g,         36, BITS_DIFF1,  A);
    uint256 s2  = add_versioned(sc, 0x42, s1,        36, BITS_DIFF1,  A);
    uint256 tip = add_versioned(sc, 0x43, s2,        36, BITS_DIFF1,  A);

    auto plain = dash::version_negotiation::get_desired_version_counts(sc.chain, tip, 4);
    const std::map<uint64_t, uint64_t> plain_expected = {{16u, 1u}, {36u, 3u}};
    EXPECT_EQ(plain, plain_expected) << "plain vote count != CPython KAT";

    auto weights = dash::version_negotiation::get_desired_version_weights(sc.chain, tip, 4);
    ASSERT_TRUE(weights.contains(16u) && weights.contains(36u));
    EXPECT_TRUE(weights[16u] == uint288(W_HEAVY))
        << "v16 weight != CPython KAT (heavy share work)";
    EXPECT_TRUE(weights[36u] == uint288(3ULL * W_DIFF1))
        << "v36 weight != CPython KAT (3x diff1 work)";
}

// 60% SUCCESSOR switch gate, PPLNS-WEIGHTED exact-rational semantics (D1 /
// F10 685669e9). KAT booleans from CPython have_w*100 >= total_w*60 (no floor).
// The 4/7 case now REJECTS (400 < 420) where the prior plain-floor gate cleared
// it (thr=floor(4.2)=4) -- the exact divergence D1 standardizes away.
TEST(DashConformanceVersionNeg, SuccessorGuard60PercentWeightedKat) {
    using dash::version_negotiation::successor_switch_allowed;
    EXPECT_TRUE (successor_switch_allowed({{36u, uint288(6u)},  {16u, uint288(4u)}},  36u)); // 6/10 = 60%
    EXPECT_FALSE(successor_switch_allowed({{36u, uint288(5u)},  {16u, uint288(5u)}},  36u)); // 5/10 = 50%
    EXPECT_TRUE (successor_switch_allowed({{36u, uint288(60u)}, {16u, uint288(40u)}}, 36u)); // 60/100 = 60%
    EXPECT_FALSE(successor_switch_allowed({{36u, uint288(59u)}, {16u, uint288(41u)}}, 36u)); // 59/100 = 59%
    EXPECT_FALSE(successor_switch_allowed({{36u, uint288(4u)},  {16u, uint288(3u)}},  36u)); // 4/7: 400 < 420 -> reject
    EXPECT_FALSE(successor_switch_allowed({{36u, uint288(3u)},  {16u, uint288(4u)}},  36u)); // 3/7: 300 < 420 -> reject
    EXPECT_FALSE(successor_switch_allowed({}, 36u));                                          // empty
}

// Bucket-3 crossing FLOOR (PRE-V36 transition-compat). During the G2 crossing-soak
// the successor gate holds the legacy 85% floor (lockstep with canonical
// p2pool-dash peers); it flips to the unified 60% only post-crossing
// (crossing_active=false). The 60-85% weighted-support band is exactly where a
// 60%-vs-85% split would fork the sharechain -- the floor closes it. Additive +
// reversible: the 2-arg unified gate is byte-unchanged and the flip is one bool.
TEST(DashConformanceVersionNeg, CrossingSuccessorFloor85Kat) {
    using dash::version_negotiation::successor_switch_allowed;
    EXPECT_EQ(dash::version_negotiation::CROSSING_SUCCESSOR_FLOOR_PCT, 85u);
    EXPECT_EQ(dash::version_negotiation::UNIFIED_SUCCESSOR_PCT,        60u);

    const std::map<uint64_t, uint288> w70 = {{36u, uint288(70u)}, {16u, uint288(30u)}}; // 70%
    const std::map<uint64_t, uint288> w85 = {{36u, uint288(85u)}, {16u, uint288(15u)}}; // 85%
    const std::map<uint64_t, uint288> w84 = {{36u, uint288(84u)}, {16u, uint288(16u)}}; // 84%
    const std::map<uint64_t, uint288> w90 = {{36u, uint288(90u)}, {16u, uint288(10u)}}; // 90%
    const std::map<uint64_t, uint288> w50 = {{36u, uint288(50u)}, {16u, uint288(50u)}}; // 50%

    // In the 60-85% fork band the crossing floor DENIES where the unified gate clears.
    EXPECT_TRUE (successor_switch_allowed(w70, 36u));        // unified 60%: clears
    EXPECT_TRUE (successor_switch_allowed(w70, 36u, false)); // post-crossing: clears (delegates)
    EXPECT_FALSE(successor_switch_allowed(w70, 36u, true));  // crossing: 70 < 85 -> DENY (fork-safe)

    // 85% boundary: exact rational, floor cleared at exactly 85%.
    EXPECT_TRUE (successor_switch_allowed(w85, 36u, true));  // 8500 >= 8500
    EXPECT_FALSE(successor_switch_allowed(w84, 36u, true));  // 8400 <  8500 -> deny

    // Above the floor: both gates agree.
    EXPECT_TRUE (successor_switch_allowed(w90, 36u, true));
    EXPECT_TRUE (successor_switch_allowed(w90, 36u, false));

    // Below the unified 60%: both paths deny.
    EXPECT_FALSE(successor_switch_allowed(w50, 36u, true));
    EXPECT_FALSE(successor_switch_allowed(w50, 36u, false));

    // Empty tally denies on every path.
    EXPECT_FALSE(successor_switch_allowed({}, 36u, true));
    EXPECT_FALSE(successor_switch_allowed({}, 36u, false));

    // Delegation identity: crossing_active=false is byte-identical to the 2-arg gate.
    for (const auto* w : {&w50, &w70, &w85, &w90})
        EXPECT_EQ(successor_switch_allowed(*w, 36u, false),
                  successor_switch_allowed(*w, 36u));
}

// v36 activation gate, exact-rational 95% on the work-weighted tally. KAT
// booleans from CPython w36*100 >= total*95.
TEST(DashConformanceVersionNeg, V36GateWeighted95PercentKat) {
    using dash::version_negotiation::v36_active;
    EXPECT_TRUE (v36_active({{36u, uint288(95u)}, {16u, uint288(5u)}}));  // exactly 95%
    EXPECT_FALSE(v36_active({{36u, uint288(94u)}, {16u, uint288(6u)}}));  // 94%
    EXPECT_TRUE (v36_active({{36u, uint288(19u)}, {16u, uint288(1u)}}));  // 19/20 = 95%
    EXPECT_FALSE(v36_active({{36u, uint288(18u)}, {16u, uint288(2u)}}));  // 18/20 = 90%
    EXPECT_FALSE(v36_active({{16u, uint288(100u)}}));                     // no v36 vote

    // Wide-value boundary: exercises the uint288 path at scale (no overflow,
    // exactly 95%). big = 2^240.
    uint288 big(1u); big <<= 240;
    EXPECT_TRUE (v36_active({{36u, big * uint288(95u)}, {16u, big * uint288(5u)}}));
    EXPECT_FALSE(v36_active({{36u, big * uint288(94u)}, {16u, big * uint288(6u)}}));
}

// D1 + F10 separation: the 60% SUCCESSOR gate consumes the WEIGHTED tally, not
// the plain count. On the 3x-v36(diff1)+1x-v16(heavy) chain the two disagree at
// the 60% boundary: plain v36 = 3/4 = 75% (a plain-count gate WOULD clear), but
// weighted v36 = 3*W_DIFF1 / (3*W_DIFF1 + W_HEAVY) = 59.9996% < 60%, so the
// canonical weighted gate DENIES. The 95% activation gate likewise denies.
TEST(DashConformanceVersionNeg, GateUsesWeightNotPlainCount) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x02);
    uint256 g   = add_versioned(sc, 0x50, uint256(), 16, BITS_HEAVY, A);
    uint256 s1  = add_versioned(sc, 0x51, g,         36, BITS_DIFF1,  A);
    uint256 s2  = add_versioned(sc, 0x52, s1,        36, BITS_DIFF1,  A);
    uint256 tip = add_versioned(sc, 0x53, s2,        36, BITS_DIFF1,  A);

    auto plain   = dash::version_negotiation::get_desired_version_counts(sc.chain, tip, 4);
    auto weights = dash::version_negotiation::get_desired_version_weights(sc.chain, tip, 4);

    // Plain count: v36 holds 3/4 = 75% of votes -- a plain-count 60% gate WOULD clear.
    const std::map<uint64_t, uint64_t> plain_expected = {{16u, 1u}, {36u, 3u}};
    EXPECT_EQ(plain, plain_expected);
    // Weighted 60% SUCCESSOR gate (D1): v36 work ~59.9996% < 60% -> DENY.
    EXPECT_FALSE(dash::version_negotiation::successor_switch_allowed(weights, 36u));
    // Weighted 95% activation gate: v36 work ~60% < 95% -> not active.
    EXPECT_FALSE(dash::version_negotiation::v36_active(weights));
}

// D2: unified 5-case version-switch classifier (F10 share_check.hpp step 2).
// Pins classify_switch() over every transition shape and the switch_accepted()
// decision table, then cross-checks the SuccessorGated body against the live D1
// 60% weighted gate so the classifier can never diverge from successor_switch_allowed.
TEST(DashConformanceVersionNeg, SwitchClassifier5CaseKat) {
    using namespace dash::version_negotiation;
    using C = dash::version_negotiation::SwitchClass;

    // classify_switch: structural transition classification (prev, desired, has_history).
    EXPECT_EQ(classify_switch(36u, 36u, true),  C::Same);                // continuation
    EXPECT_EQ(classify_switch(36u, 36u, false), C::Same);                // history irrelevant
    EXPECT_EQ(classify_switch(35u, 34u, true),  C::PredecessorAllowed);  // downgrade-by-one
    EXPECT_EQ(classify_switch(35u, 34u, false), C::PredecessorAllowed);  // needs no window
    EXPECT_EQ(classify_switch(35u, 36u, true),  C::SuccessorGated);      // +1 with support window
    EXPECT_EQ(classify_switch(35u, 36u, false), C::NoHistory);           // +1, window absent
    EXPECT_EQ(classify_switch(35u, 37u, true),  C::InvalidJump);         // +2 skip
    EXPECT_EQ(classify_switch(35u, 33u, true),  C::InvalidJump);         // -2 skip
    EXPECT_EQ(classify_switch(35u, 40u, false), C::InvalidJump);         // +5, structural reject

    // switch_accepted: final verdict. SuccessorGated defers to the 60% gate;
    // every other case is decided structurally (gate_cleared is then ignored).
    EXPECT_TRUE (switch_accepted(C::Same,               false));  // continuation always ok
    EXPECT_TRUE (switch_accepted(C::PredecessorAllowed, false));  // rollback always ok
    EXPECT_TRUE (switch_accepted(C::SuccessorGated,     true));   // +1, gate cleared
    EXPECT_FALSE(switch_accepted(C::SuccessorGated,     false));  // +1, gate denied
    EXPECT_FALSE(switch_accepted(C::InvalidJump,        true));   // skip never ok
    EXPECT_FALSE(switch_accepted(C::NoHistory,          true));   // no support window

    // Cross-check the gated body against the live D1 weighted gate: a +1 switch
    // to v36 with history is accepted exactly when successor_switch_allowed clears.
    const std::map<uint64_t, uint288> clears  = {{36u, uint288(6u)}, {16u, uint288(4u)}};  // 60%
    const std::map<uint64_t, uint288> denies  = {{36u, uint288(5u)}, {16u, uint288(5u)}};  // 50%
    EXPECT_TRUE (switch_accepted(classify_switch(35u, 36u, true),
                                 successor_switch_allowed(clears, 36u)));
    EXPECT_FALSE(switch_accepted(classify_switch(35u, 36u, true),
                                 successor_switch_allowed(denies, 36u)));
    // Same chain, but window absent -> NoHistory short-circuits the gate entirely.
    EXPECT_FALSE(switch_accepted(classify_switch(35u, 36u, false),
                                 successor_switch_allowed(clears, 36u)));
}

// === dash::verify_share: the WIRED accept-path entry (not the isolated
// primitives above, and not the orphan verify_version_transition the S8-prep
// KAT used). Proves the version-boundary gate fires through the SAME combined
// entry a node calls -- closing the enforcement hole where the gate had ZERO
// accept-path consumers. verify_init=false because Phase 1 (X11 PoW/hash_link)
// runs in the node thread pool; these cases lock the Phase-2 chain-context
// WIRING. The init-composition case below proves Phase 1 is wired too. CHAIN_LENGTH (CL) is small (20) so the [9/10..10/10] tail window is
// reachable in a synthetic chain; the exact 60%/95% floors are pinned by the
// isolation KATs above, so these lock the WIRING, not the thresholds.
namespace {
// Build a uniform run of `count` shares (all `version`/`bits`) on a fresh chain
// and return the tip hash. The candidate is added separately by each test.
uint256 build_uniform(SyntheticChain& sc, int count, uint64_t version,
                      uint32_t bits, const uint160& pkh, uint8_t tag0 = 0x60) {
    uint256 prev = uint256();
    for (int i = 0; i < count; ++i)
        prev = add_versioned(sc, static_cast<uint8_t>(tag0 + i), prev, version, bits, pkh);
    return prev;
}
constexpr uint64_t CL = 20;  // synthetic CHAIN_LENGTH for the gate window
core::CoinParams kVgParams;  // accept-entry param (unused when verify_init=false)
}  // namespace

// Same-version share is never a boundary -> always admitted (data.py:382).
TEST(DashConformanceVersionWiring, SameVersionAdmitted) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x10);
    uint256 tip = build_uniform(sc, 22, 36, BITS_DIFF1, A);
    add_versioned(sc, 0x80, tip, 36, BITS_DIFF1, A);
    EXPECT_NO_THROW(dash::verify_share(*sc.pool.back(), sc.chain, CL, kVgParams, /*verify_init=*/false));
}

// Upgrade boundary with fewer than CHAIN_LENGTH ancestors -> rejected
// ("switch without enough history"). data.py:385-387.
TEST(DashConformanceVersionWiring, UpgradeWithoutHistoryRejected) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x11);
    uint256 tip = build_uniform(sc, 5, 16, BITS_DIFF1, A);  // < CL ancestors
    add_versioned(sc, 0x81, tip, 36, BITS_DIFF1, A);        // v16 -> v36 upgrade
    try {
        dash::verify_share(*sc.pool.back(), sc.chain, CL, kVgParams, /*verify_init=*/false);
        FAIL() << "expected throw on upgrade without enough history";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("enough history"), std::string::npos);
    }
}

// Upgrade boundary, history present, tail window already on the successor
// version -> admitted (>=60% plain successor votes). data.py:388-393.
TEST(DashConformanceVersionWiring, UpgradeWithSuccessorMajorityAdmitted) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x12);
    uint256 tip = build_uniform(sc, 22, 36, BITS_DIFF1, A);   // tail window = v36
    uint256 prev = add_versioned(sc, 0x82, tip, 16, BITS_DIFF1, A);  // a lone v16 prev
    add_versioned(sc, 0x83, prev, 36, BITS_DIFF1, A);         // v16 -> v36 upgrade
    EXPECT_NO_THROW(dash::verify_share(*sc.pool.back(), sc.chain, CL, kVgParams, /*verify_init=*/false));
}

// Upgrade boundary, history present, but the tail window has NO successor votes
// -> rejected ("without enough hash power upgraded"). data.py:392.
TEST(DashConformanceVersionWiring, UpgradeWithoutSuccessorVotesRejected) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x13);
    uint256 tip = build_uniform(sc, 22, 16, BITS_DIFF1, A);   // tail window = all v16
    add_versioned(sc, 0x84, tip, 36, BITS_DIFF1, A);          // v16 -> v36 upgrade
    try {
        dash::verify_share(*sc.pool.back(), sc.chain, CL, kVgParams, /*verify_init=*/false);
        FAIL() << "expected throw on upgrade without successor votes";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("hash power upgraded"),
                  std::string::npos);
    }
}

// Obsolescence gate: a pre-v36 share whose CHAIN_LENGTH lookbehind is already
// >=95% WEIGHTED v36 -> rejected ("share version too old"). Mirrors btc
// should_punish_version; consumes the WEIGHTED tally (work.py v36_active).
TEST(DashConformanceVersionWiring, StalePreV36ShareRejected) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x14);
    uint256 tip = build_uniform(sc, 22, 36, BITS_DIFF1, A);   // lookbehind = all v36
    add_versioned(sc, 0x85, tip, 16, BITS_DIFF1, A);          // stale v16 on v36 tip
    try {
        dash::verify_share(*sc.pool.back(), sc.chain, CL, kVgParams, /*verify_init=*/false);
        FAIL() << "expected throw on stale pre-v36 share";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("too old"), std::string::npos);
    }
}

// Genesis / no-parent share is admitted unconditionally (nothing to gate).
TEST(DashConformanceVersionWiring, GenesisShareAdmitted) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x15);
    add_versioned(sc, 0x86, uint256(), 36, BITS_DIFF1, A);    // null prev_hash
    EXPECT_NO_THROW(dash::verify_share(*sc.pool.back(), sc.chain, CL, kVgParams, /*verify_init=*/false));
}

// Phase-1 composition: with verify_init=true the combined entry runs
// share_init_verify FIRST, so a structurally invalid share (empty coinbase) is
// rejected by verify_share BEFORE the version gate is ever consulted. Proves
// Phase 1 is wired into the accept entry, not bypassed.
TEST(DashConformanceVersionWiring, InitPhaseComposedAndRejectsBeforeGate) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x16);
    add_versioned(sc, 0x87, uint256(), 36, BITS_DIFF1, A);  // genesis: gate is a no-op
    // Synthetic shares carry an empty coinbase -> share_init_verify rejects on
    // the size guard. verify_init=true must surface that, proving init runs.
    try {
        dash::verify_share(*sc.pool.back(), sc.chain, CL, kVgParams, /*verify_init=*/true);
        FAIL() << "expected Phase-1 init to reject the empty-coinbase share";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("coinbase"), std::string::npos);
    }
}

// ── Accept-path SEAM: dash::admit_chain_relative (chain_admit.hpp) ───────────
// The DashConformanceVersionWiring group above proves the gate primitive
// (verify_version_transition). These prove the FIRST src/ CONSUMER seam routes
// through to that gate: dash::admit_chain_relative — the single call the S8 node
// run-loop / launcher --run share-receive path makes after share_init_verify.
// Before chain_admit.hpp the gate had ZERO src/ consumers (test-only). These
// lock the consumer boundary; the 60%/95% floors stay pinned by the KATs above.
TEST(DashChainAdmitSeam, AdmitsSameVersionThroughSeam) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x16);
    uint256 tip = build_uniform(sc, 22, 36, BITS_DIFF1, A);
    add_versioned(sc, 0x90, tip, 36, BITS_DIFF1, A);
    EXPECT_NO_THROW(dash::admit_chain_relative(*sc.pool.back(), sc.chain, CL));
}

// Seam rejects a stale pre-v36 share once the lookbehind is >=95% weighted v36
// (routes to the obsolescence arm of the gate).
TEST(DashChainAdmitSeam, RejectsStalePreV36ThroughSeam) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x17);
    uint256 tip = build_uniform(sc, 22, 36, BITS_DIFF1, A);
    add_versioned(sc, 0x91, tip, 16, BITS_DIFF1, A);  // stale v16 on v36 tip
    try {
        dash::admit_chain_relative(*sc.pool.back(), sc.chain, CL);
        FAIL() << "expected seam to reject stale pre-v36 share";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("too old"), std::string::npos);
    }
}

// Seam rejects an upgrade boundary lacking CHAIN_LENGTH history (routes to the
// successor-guard arm; no-history short-circuit throws "enough history").
TEST(DashChainAdmitSeam, RejectsUpgradeWithoutHistoryThroughSeam) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x18);
    uint256 tip = build_uniform(sc, 5, 16, BITS_DIFF1, A);  // < CL ancestors
    add_versioned(sc, 0x92, tip, 36, BITS_DIFF1, A);        // v16 -> v36 upgrade
    try {
        dash::admit_chain_relative(*sc.pool.back(), sc.chain, CL);
        FAIL() << "expected seam to reject upgrade without enough history";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("enough history"), std::string::npos);
    }
}

// Seam admits an upgrade boundary whose tail window already carries the
// successor version (>=60% successor votes) — the gate's admit path.
TEST(DashChainAdmitSeam, AdmitsSuccessorMajorityThroughSeam) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x19);
    uint256 tip = build_uniform(sc, 22, 36, BITS_DIFF1, A);          // tail = v36
    uint256 prev = add_versioned(sc, 0x93, tip, 16, BITS_DIFF1, A);  // lone v16 prev
    add_versioned(sc, 0x94, prev, 36, BITS_DIFF1, A);                // v16 -> v36 upgrade
    EXPECT_NO_THROW(dash::admit_chain_relative(*sc.pool.back(), sc.chain, CL));
}

// Genesis / no-parent share is admitted unconditionally through the seam.
TEST(DashChainAdmitSeam, AdmitsGenesisThroughSeam) {
    SyntheticChain sc;
    const uint160 A = miner_h160(0x1a);
    add_versioned(sc, 0x95, uint256(), 36, BITS_DIFF1, A);  // null prev_hash
    EXPECT_NO_THROW(dash::admit_chain_relative(*sc.pool.back(), sc.chain, CL));
}

// ── DIP4 special-tx coinbase payload (CCbTx) wire-encoding conformance ──────
// DASH coinbase transactions carry a DIP-0004 "special transaction" extra
// payload: the CCbTx. Its merkleRootMNList / merkleRootQuorums fields are what
// every downstream SML / quorum conformance check reads, so the wire framing
// must match dashcore (evo/cbtx.h) byte-for-byte. These KATs are computed
// OUT-OF-BAND with CPython (LE struct pack + Bitcoin base-128 VarInt + raw
// sha256d digest bytes for the uint256 fields), so the pins are NOT circular
// with the C++ ::Serialize path. The decode case proves parse_cbtx is the
// exact inverse on the very same bytes.
namespace {
// Self-contained hex -> bytes. Feeding the out-of-band hex straight into the
// C++ parser keeps the decode KAT non-circular (no Serialize round-trip).
std::vector<unsigned char> unhex(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    std::vector<unsigned char> out;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}
}  // namespace

// v=2 (MERKLE_ROOT_QUORUMS): nVersion(LE16) nHeight(LE32) mnlist(32) quorums(32).
TEST(DashConformanceCbtx, V2QuorumsMatchesOutOfBandKat) {
    dash::coin::vendor::CCbTx tx;
    tx.nVersion          = dash::coin::vendor::CCbTx::VERSION_MERKLE_ROOT_QUORUMS;
    tx.nHeight           = 1000000;
    tx.merkleRootMNList  = leaf(0x01);
    tx.merkleRootQuorums = leaf(0x02);

    PackStream ps; ::Serialize(ps, tx);
    EXPECT_EQ(ps_hex(ps),
        "020040420f00"
        "9c12cfdc04c74584d787ac3d23772132c18524bc7ab28dec4219b8fc5b425f70"
        "1cc3adea40ebfd94433ac004777d68150cce9db4c771bc7de1b297a7b795bbba")
        << "v2 CCbTx wire != CPython KAT (DIP4 special-tx payload framing drift)";
}

// v=3 (CLSIG_AND_BALANCE): v2 prefix + VarInt(clHeightDiff) + 96B BLS sig +
// LE64 signed creditPoolBalance.
TEST(DashConformanceCbtx, V3ClsigBalanceMatchesOutOfBandKat) {
    dash::coin::vendor::CCbTx tx;
    tx.nVersion          = dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    tx.nHeight           = 2000000;
    tx.merkleRootMNList  = leaf(0x03);
    tx.merkleRootQuorums = leaf(0x04);
    tx.bestCLHeightDiff  = 24;                       // single-byte base-128 VarInt 0x18
    tx.bestCLSignature.fill(0xAB);
    tx.creditPoolBalance = 123456789;

    PackStream ps; ::Serialize(ps, tx);
    EXPECT_EQ(ps_hex(ps),
        "030080841e00"
        "c942a06c127c2c18022677e888020afb174208d299354f3ecfedb124a1f3fa45"
        "214e63bf41490e67d34476778f6707aa6c8d2c8dccdf78ae11e40ee9f91e89a7"
        "18"
        "abababababababababababababababababababababababababababababababab"
        "abababababababababababababababababababababababababababababababab"
        "abababababababababababababababababababababababababababababababab"
        "15cd5b0700000000")
        << "v3 CCbTx wire != CPython KAT (VarInt / BLS-sig / creditPool framing drift)";
}

// Decode path: parse_cbtx must be the exact inverse on the out-of-band bytes,
// and must reject trailing garbage (the wire-drift guard).
TEST(DashConformanceCbtx, ParseCbtxIsExactInverseOfKat) {
    const std::string kat_v3 =
        "030080841e00"
        "c942a06c127c2c18022677e888020afb174208d299354f3ecfedb124a1f3fa45"
        "214e63bf41490e67d34476778f6707aa6c8d2c8dccdf78ae11e40ee9f91e89a7"
        "18"
        "abababababababababababababababababababababababababababababababab"
        "abababababababababababababababababababababababababababababababab"
        "abababababababababababababababababababababababababababababababab"
        "15cd5b0700000000";
    dash::coin::vendor::CCbTx tx;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(unhex(kat_v3), tx))
        << "parse_cbtx rejected a valid out-of-band v3 payload";
    EXPECT_EQ(tx.nVersion, dash::coin::vendor::CCbTx::VERSION_CLSIG_AND_BALANCE);
    EXPECT_EQ(tx.nHeight, 2000000);
    EXPECT_TRUE(tx.merkleRootMNList  == leaf(0x03));
    EXPECT_TRUE(tx.merkleRootQuorums == leaf(0x04));
    EXPECT_EQ(tx.bestCLHeightDiff, 24u);
    EXPECT_TRUE(tx.has_best_cl_signature());
    EXPECT_EQ(tx.creditPoolBalance, 123456789);

    auto bytes = unhex(kat_v3); bytes.push_back(0x00);  // one trailing byte
    dash::coin::vendor::CCbTx tx2;
    EXPECT_FALSE(dash::coin::vendor::parse_cbtx(bytes, tx2))
        << "parse_cbtx accepted trailing garbage (wire-drift guard defeated)";
}


// -- Sharechain network-params conformance (S6 slice 3) -----------------------
// Pin DASH's p2pool sharechain framing constants against its OWN older-than-v35
// oracle (frstrtr/p2pool-dash networks/dash.py + dash_testnet.py). The expected
// values below are an INDEPENDENT transcription of the oracle, NOT a re-export of
// dash::SharechainConfig, so the assertions catch a drift in either copy -- the same
// anti-circularity design used by the merkle/payout KATs above.
//
// PREFIX/IDENTIFIER are isolation primitives: pinned per-coin here, never to be
// unified cross-coin (operator v36_standardization_goal 2026-06-17).
TEST(DashConformanceNetworkParams, MainnetMatchesP2poolDashOracle) {
    dash::SharechainConfig::is_testnet = false;
    EXPECT_EQ(dash::SharechainConfig::p2p_port(), 8999);
    EXPECT_EQ(dash::SharechainConfig::worker_port(), 7903);
    EXPECT_EQ(dash::SharechainConfig::share_period(), 20u);
    EXPECT_EQ(dash::SharechainConfig::chain_length(), 4320u);       // 24*60*60//20
    EXPECT_EQ(dash::SharechainConfig::real_chain_length(), 4320u);
    EXPECT_EQ(dash::SharechainConfig::TARGET_LOOKBEHIND, 100u);
    EXPECT_EQ(dash::SharechainConfig::SPREAD, 10u);
    EXPECT_EQ(dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION, 1700u);
    EXPECT_EQ(dash::SharechainConfig::identifier_hex(), std::string("7242ef345e1bed6b"));
    EXPECT_EQ(dash::SharechainConfig::prefix_hex(),     std::string("3b3e1286f446b891"));
    uint256 expect_max;
    expect_max.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
    EXPECT_EQ(dash::SharechainConfig::max_target(), expect_max);    // 0xFFFF * 2**208
}

TEST(DashConformanceNetworkParams, TestnetMatchesP2poolDashOracle) {
    dash::SharechainConfig::is_testnet = true;
    EXPECT_EQ(dash::SharechainConfig::p2p_port(), 18999);
    EXPECT_EQ(dash::SharechainConfig::worker_port(), 17903);
    EXPECT_EQ(dash::SharechainConfig::share_period(), 20u);
    EXPECT_EQ(dash::SharechainConfig::chain_length(), 4320u);
    EXPECT_EQ(dash::SharechainConfig::identifier_hex(), std::string("b6deb1e543fe2427"));
    EXPECT_EQ(dash::SharechainConfig::prefix_hex(),     std::string("198b644f6821e3b3"));
    uint256 expect_max;
    expect_max.SetHex("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    EXPECT_EQ(dash::SharechainConfig::max_target(), expect_max);    // 2**256 // 2**20 - 1
    dash::SharechainConfig::is_testnet = false;  // restore global for any later tests
}

// ── Factory↔SSOT conformance (S6 slice: make_coin_params wiring) ─────────────
// The dash::make_coin_params factory MUST populate core::CoinParams pool-level
// fields from the dash::SharechainConfig SSOT (config_pool.hpp) and the coin-level
// fields from the DASH oracle, so share_check/coinbase_builder — which consume a
// const core::CoinParams& — never run on an unpopulated or drifted struct. This
// pins the factory output WITHOUT a node dependency: it is the node-free half of
// S6, complementary to the real-node KAT capture.
#include <impl/dash/params.hpp>  // dash::make_coin_params

TEST(DashConformanceFactory, PoolFieldsSourcedFromSSOT) {
    for (bool testnet : {false, true}) {
        dash::SharechainConfig::is_testnet = testnet;
        auto p = dash::make_coin_params(testnet);
        EXPECT_EQ(p.p2p_port,                 dash::SharechainConfig::p2p_port());
        EXPECT_EQ(p.worker_port,              dash::SharechainConfig::worker_port());
        EXPECT_EQ(p.share_period,             dash::SharechainConfig::share_period());
        EXPECT_EQ(p.chain_length,             dash::SharechainConfig::chain_length());
        EXPECT_EQ(p.real_chain_length,        dash::SharechainConfig::real_chain_length());
        EXPECT_EQ(p.target_lookbehind,        dash::SharechainConfig::TARGET_LOOKBEHIND);
        EXPECT_EQ(p.spread,                   dash::SharechainConfig::SPREAD);
        EXPECT_EQ(p.minimum_protocol_version, dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION);
        EXPECT_EQ(p.identifier_hex,           dash::SharechainConfig::IDENTIFIER_HEX);
        EXPECT_EQ(p.prefix_hex,               dash::SharechainConfig::PREFIX_HEX);
        EXPECT_EQ(p.testnet_identifier_hex,   dash::SharechainConfig::TESTNET_IDENTIFIER_HEX);
        EXPECT_EQ(p.testnet_prefix_hex,       dash::SharechainConfig::TESTNET_PREFIX_HEX);
        dash::SharechainConfig::is_testnet = testnet;
        EXPECT_EQ(p.max_target,               dash::SharechainConfig::max_target());
        EXPECT_EQ(p.is_testnet,               testnet);
    }
}

TEST(DashConformanceFactory, CoinFieldsMatchDashOracle) {
    auto mn = dash::make_coin_params(/*testnet=*/false);
    EXPECT_EQ(mn.symbol, "DASH");
    EXPECT_EQ(mn.block_period, 150u);
    EXPECT_EQ(mn.address_version, 76);        // X...
    EXPECT_EQ(mn.address_p2sh_version, 16);   // 7...
    EXPECT_EQ(mn.address_p2sh_version2, 0);   // no secondary P2SH
    EXPECT_EQ(mn.segwit_activation_version, 0u);  // DASH: no segwit
    EXPECT_EQ(mn.current_share_version, 16u);     // older-than-v35 baseline

    auto tn = dash::make_coin_params(/*testnet=*/true);
    EXPECT_EQ(tn.address_version, 140);       // y...
    EXPECT_EQ(tn.address_p2sh_version, 19);
}

// The factory donation script is version-gated SSOT: pre-v36 share versions use
// the per-coin P2PKH DONATION_SCRIPT (Bucket-3, keep-for-soak); v36+ shares use
// the unified cross-coin COMBINED_DONATION_SCRIPT P2SH (Bucket-2). Both pinned to
// the SSOT symbols, never an ad-hoc literal.
TEST(DashConformanceFactory, DonationScriptIsSSOTForAllVersions) {
    auto p = dash::make_coin_params(/*testnet=*/false);
    for (int64_t v : {0, 15, 16, 35}) {
        EXPECT_EQ(p.donation_script_func(v), dash::DONATION_SCRIPT)
            << "pre-v36 donation script diverged at share_version=" << v;
    }
    EXPECT_EQ(p.donation_script_func(36), dash::COMBINED_DONATION_SCRIPT)
        << "v36 donation script must be the unified combined P2SH";
}

// PoW and block-identity hashes are BOTH X11 (DASH identifies blocks by X11,
// not SHA256d) — guard against an accidental copy of the LTC sha256d shape.
TEST(DashConformanceFactory, PowAndBlockHashAreBothX11) {
    auto p = dash::make_coin_params(/*testnet=*/false);
    ASSERT_TRUE(p.pow_func);
    ASSERT_TRUE(p.block_hash_func);
    std::vector<unsigned char> sample(80, 0xab);
    std::span<const unsigned char> s(sample.data(), sample.size());
    uint256 expect = dash::crypto::hash_x11(s);
    EXPECT_EQ(p.pow_func(s), expect);
    EXPECT_EQ(p.block_hash_func(s), expect);
}

// ── pool.yaml runtime-override seam (S6 slice: make_coin_params overrides) ────
// The override overload lets an operator pool.yaml retune ONLY non-consensus,
// non-isolation pool fields (ports, bootstrap peers). With no overrides the
// factory output is byte-identical to the pure-SSOT overload; consensus-critical
// and isolation fields are NEVER reachable from PoolOverrides (compile-time:
// the struct has no field for them) and stay pinned to the SSOT even when the
// tunable fields are overridden. Node-free — pins the seam pool.yaml populates.
TEST(DashConformanceFactory, NoOverridesEqualsSSOTOverload) {
    for (bool testnet : {false, true}) {
        auto base = dash::make_coin_params(testnet);
        auto ovr  = dash::make_coin_params(testnet, dash::PoolOverrides{});
        EXPECT_EQ(ovr.p2p_port,        base.p2p_port);
        EXPECT_EQ(ovr.worker_port,     base.worker_port);
        EXPECT_EQ(ovr.bootstrap_addrs, base.bootstrap_addrs);
    }
}

TEST(DashConformanceFactory, OverridesApplyToTunableFields) {
    dash::PoolOverrides ov;
    ov.p2p_port        = 19000;
    ov.worker_port     = 19001;
    ov.bootstrap_addrs = std::vector<std::string>{"seed.example:8999", "node2.example:8999"};
    auto p = dash::make_coin_params(/*testnet=*/false, ov);
    EXPECT_EQ(p.p2p_port,    19000);
    EXPECT_EQ(p.worker_port, 19001);
    ASSERT_EQ(p.bootstrap_addrs.size(), 2u);
    EXPECT_EQ(p.bootstrap_addrs[0], "seed.example:8999");
    EXPECT_EQ(p.bootstrap_addrs[1], "node2.example:8999");
}

// Even with tunable overrides set, consensus + isolation fields MUST equal the
// SSOT/oracle values — a mis-edited pool.yaml can never fork the sharechain.
TEST(DashConformanceFactory, OverridesNeverTouchConsensusOrIsolation) {
    dash::PoolOverrides ov;
    ov.p2p_port    = 19000;
    ov.worker_port = 19001;
    auto ssot = dash::make_coin_params(/*testnet=*/false);
    auto p    = dash::make_coin_params(/*testnet=*/false, ov);
    EXPECT_EQ(p.identifier_hex,         ssot.identifier_hex);
    EXPECT_EQ(p.prefix_hex,             ssot.prefix_hex);
    EXPECT_EQ(p.testnet_identifier_hex, ssot.testnet_identifier_hex);
    EXPECT_EQ(p.testnet_prefix_hex,     ssot.testnet_prefix_hex);
    EXPECT_EQ(p.max_target,             ssot.max_target);
    EXPECT_EQ(p.current_share_version,  ssot.current_share_version);
    EXPECT_EQ(p.minimum_protocol_version, ssot.minimum_protocol_version);
    // Overrides must not change the donation script at ANY version: the override
    // overload must agree with the pure-SSOT overload version-for-version
    // (pre-v36 P2PKH and v36 combined-P2SH alike).
    for (int64_t v : {0, 16, 35, 36})
        EXPECT_EQ(p.donation_script_func(v), ssot.donation_script_func(v));
}

// ── Threshold-SSOT dedup (dash/version-gate-threshold-ssot) ──────────────────
// version_negotiation now reads the 60% successor gate and 95% v36-activation
// signal from NAMED constants instead of bare literals (the #533 dialect-drift
// fix applied to the version gate). This KAT pins the named constants to their
// canonical v36-native values so a future edit cannot silently fork the gate,
// and re-confirms the gates behave byte-identically through the named path.
TEST(DashVersionGateThresholdSSOT, NamedConstantsArePinned) {
    using namespace dash::version_negotiation;
    EXPECT_EQ(UNIFIED_SUCCESSOR_PCT,        60u);  // v36-native successor gate
    EXPECT_EQ(V36_SIGNAL_ACTIVATION_PCT,    95u);  // v36 weighted-signal activation
    EXPECT_EQ(CROSSING_SUCCESSOR_FLOOR_PCT, 85u);  // Bucket-3 legacy crossing floor
}

TEST(DashVersionGateThresholdSSOT, GatesUnchangedThroughNamedPath) {
    using dash::version_negotiation::successor_switch_allowed;
    using dash::version_negotiation::v36_active;
    // 60% successor gate — exact boundary unchanged (uint288 exact-rational).
    EXPECT_TRUE (successor_switch_allowed({{36u, uint288(60u)}, {16u, uint288(40u)}}, 36u)); // 60/100
    EXPECT_FALSE(successor_switch_allowed({{36u, uint288(59u)}, {16u, uint288(41u)}}, 36u)); // 59/100
    // 95% v36 activation signal — exact boundary unchanged.
    EXPECT_TRUE (v36_active({{36u, uint288(95u)}, {16u, uint288(5u)}}, 36u));  // 95/100
    EXPECT_FALSE(v36_active({{36u, uint288(94u)}, {16u, uint288(6u)}}, 36u));  // 94/100
    // 85% crossing floor (3-arg) — unchanged: 84% fails, 85% passes when active.
    EXPECT_FALSE(successor_switch_allowed({{36u, uint288(84u)}, {16u, uint288(16u)}}, 36u, /*crossing_active=*/true));
    EXPECT_TRUE (successor_switch_allowed({{36u, uint288(85u)}, {16u, uint288(15u)}}, 36u, /*crossing_active=*/true));
}