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
#include <impl/dash/share_types.hpp>        // dash::MerkleLink
#include <impl/dash/pplns.hpp>           // dash::pplns::compute_payouts, dash::ShareChain, DashShare
#include <impl/dash/version_negotiation.hpp> // dash::version_negotiation::get_desired_version_counts/weights
#include <impl/dash/coin/vendor/cbtx.hpp> // dash::coin::vendor::CCbTx, parse_cbtx
#include <impl/bitcoin_family/coin/base_block.hpp>  // bitcoin_family::coin::SmallBlockHeaderType

#include <core/hash.hpp>                     // Hash (sha256d)
#include <core/uint256.hpp>

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
