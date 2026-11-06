// SPDX-License-Identifier: AGPL-3.0-or-later
/// Dash Core v24 provider-payload codecs (slice S2): KATs.
///
/// What is pinned, by suite:
///
///   DashV24Testnet*   Real testnet transactions (v24 active from height
///                     1,578,000): 8 ProRegTx v3 (Evo with core_p2p /
///                     platform_p2p / platform_https, and regular), 8
///                     ProUpServTx v3 (Evo and regular, incl. v2->v3 raises)
///                     and 1 ProUpRevTx v3. Each raw tx was rebuilt from its
///                     verbose JSON (dashd 24.0.0 getrawtransaction) and
///                     checked against its txid by the generator; here the
///                     tx codec re-derives the txid, the payload decodes to
///                     the fields the JSON reported and re-encodes byte for
///                     byte, and Core's payload-only checks accept it under
///                     testnet rules at its height.
///   DashV24CbTx*      The first CbTx v4 (height 1,578,000): what the probe
///                     captured (payload size 207, first 4 bytes) and the v3
///                     codec's refusal of a v4 payload (B1, fixed by S1).
///   DashV24Synthetic* Shapes testnet does not carry yet (shared masternodes,
///                     multi-entry payout lists, types 10-12, every ADDRv2
///                     network, domains): encoded by the generator from Dash
///                     Core v24.0.0's SERIALIZE_METHODS with real BLS operator
///                     keys and signatures, every payload decoded by dashd
///                     24.0.0 with the same key; decoded here, and the same
///                     objects built in C++ re-encode to the same bytes.
///   DashV24Bls*       Core's BLS decoding: an operator key must decode under
///                     the payload's scheme, not be the identity and
///                     re-encode exactly (else bad-protx-key-null); a type-2/4
///                     signature canonical under neither scheme fails
///                     GetTxPayload (bad-protx-payload). Facts confirmed by
///                     dashd and dashbls (kBlsKeyFacts / kBlsSigFacts). A
///                     build without BLS refuses what it cannot decide; its
///                     rule tests run against those facts instead.
///   DashV24Sml*       SML entry v3 wire bytes and leaf hashes (vs the same
///                     masternode at v2), an mnlistdiff carrying v3 entries
///                     whose root matches its CbTx, unknown entry versions.
///   DashV24NetInfo*   ADDRv2 / NetInfoEntry / DomainPort reading rules
///                     (including the reads Core swallows), validation and
///                     the MnNetInfo -> ExtNetInfo conversion.
///   DashV24Reject*    One negative case (at least) per reject reason the
///                     payload-only checks can produce.
///   DashV24Golden*    Mainnet before activation is unchanged: a frozen copy
///                     of the pre-v24 (master a66754bb9) v1/v2 codecs agrees
///                     with the new codecs on real mainnet payloads, a seeded
///                     corpus of v1/v2 payloads and their mutations, and the
///                     real testnet mnlistdiff captures (v1/v2 entries)
///                     re-encode byte for byte with master's leaf hashes.
///
/// Vectors: dash_v24_s2_vectors.inc, written by
/// test/fixtures/dash_v24/gen_s2_vectors.py (independent Python encoder +
/// decoder). The regtest harness (S9) will replace the synthetic rows with
/// bytes produced by dashd v24.0.0.

#include <gtest/gtest.h>

#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/tx_version_rules.hpp>
#include <impl/dash/coin/v24_rules.hpp>
#include <impl/dash/coin/vendor/bls_canonical.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/netinfo.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace {

#include "dash_v24_s2_vectors.inc"

namespace v = dash::coin::vendor;
using dash::coin::DashNetwork;
using dash::coin::MutableTransaction;
using dash::coin::ProviderTxRules;
using dash::coin::provider_payload_refusal;

using Bytes = std::vector<uint8_t>;

Bytes unhex(const char* h)
{
    Bytes out;
    const size_t n = std::strlen(h);
    for (size_t i = 0; i + 1 < n; i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(std::string(h + i, 2), nullptr, 16)));
    return out;
}

std::string hex(const uint8_t* p, size_t n)
{
    static constexpr char d[] = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
std::string hex(const Bytes& b) { return hex(b.data(), b.size()); }
template <size_t N> std::string hex(const std::array<uint8_t, N>& a) { return hex(a.data(), N); }
std::string rawhex(const uint160& h) { return hex(h.data(), 20); }

template <typename T>
Bytes pack_bytes(const T& obj)
{
    auto ps = ::pack(obj);
    auto sp = ps.get_span();
    return Bytes(reinterpret_cast<const uint8_t*>(sp.data()),
                 reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

uint256 sha256d(const Bytes& b)
{
    uint256 h;
    CHash256().Write(std::span<const unsigned char>(b.data(), b.size()))
              .Finalize(std::span<unsigned char>(h.data(), 32));
    return h;
}

uint256 raw256(const Bytes& b)
{
    uint256 h;
    std::memcpy(h.data(), b.data(), 32);
    return h;
}

/// The generator's pat(n, seed).
Bytes pat(size_t n, uint8_t seed)
{
    Bytes b(n);
    for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>((seed * 31 + i * 7) & 0xFF);
    return b;
}
uint160 pat160(uint8_t seed) { uint160 h; auto b = pat(20, seed); std::memcpy(h.data(), b.data(), 20); return h; }
uint256 pat256(uint8_t seed) { return raw256(pat(32, seed)); }
template <size_t N> std::array<uint8_t, N> pat_arr(uint8_t seed)
{
    std::array<uint8_t, N> a{};
    auto b = pat(N, seed);
    std::copy(b.begin(), b.end(), a.begin());
    return a;
}

template <size_t N> std::array<uint8_t, N> arr(const char* hex_str)
{
    const Bytes b = unhex(hex_str);
    EXPECT_EQ(b.size(), N);
    std::array<uint8_t, N> a{};
    std::copy_n(b.begin(), std::min(N, b.size()), a.begin());
    return a;
}

OPScript script(const Bytes& b) { OPScript s; s.m_data = b; return s; }
OPScript p2pkh(const uint160& h)
{
    Bytes b{0x76, 0xa9, 0x14};
    b.insert(b.end(), h.data(), h.data() + 20);
    b.push_back(0x88); b.push_back(0xac);
    return script(b);
}
OPScript p2sh(const uint160& h)
{
    Bytes b{0xa9, 0x14};
    b.insert(b.end(), h.data(), h.data() + 20);
    b.push_back(0x87);
    return script(b);
}

v::NetInfoEntry svc4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    return v::NetInfoEntry{v::NetService::ipv4(a, b, c, d, port)};
}

v::ExtNetInfo ext(std::vector<std::pair<uint8_t, std::vector<v::NetInfoEntry>>> p)
{
    v::ExtNetInfo e;
    e.purposes = std::move(p);
    return e;
}

std::string payouts_str(const v::MasternodePayoutShares& ps)
{
    std::string s;
    for (size_t i = 0; i < ps.size(); ++i) {
        if (i) s += ',';
        s += hex(ps[i].scriptPayout.m_data) + ":" + std::to_string(ps[i].reward);
    }
    return s;
}

MutableTransaction parse_tx(const Bytes& raw)
{
    ::PackStream ps(raw);
    MutableTransaction tx;
    ps >> tx;
    EXPECT_TRUE(ps.empty()) << "tx bytes fully consumed";
    return tx;
}

// ── Core's BLS decoding in the rules ────────────────────────────────────────
// With the dashbls backend the rules use it, as in production. A build
// without it refuses every payload whose BLS key or signature it cannot
// check ("unverifiable-..."); to keep the rest of the rule logic covered
// there, the tests hand such a build an oracle of the answers dashd and
// dashbls gave for each encoding the tests use (kBlsKeyFacts/kBlsSigFacts,
// gen_s2_vectors.py). Unknown encodings stay undecidable. The real backend
// is checked against the same facts in DashV24Bls.

/// Signatures of mined (chainlocked) transactions: Core decoded them.
std::vector<std::array<uint8_t, 96>>& mined_sigs()
{
    static std::vector<std::array<uint8_t, 96>> v;
    return v;
}

std::optional<bool> oracle_pubkey_valid(const std::array<uint8_t, 48>& k, bool legacy)
{
    for (const auto& f : kBlsKeyFacts)
        if (f.legacy == legacy && unhex(f.bytes) == Bytes(k.begin(), k.end())) return f.core_ok;
    return v::bls_pubkey_core_valid(k, legacy);   // the all-zero answer, else nullopt
}

std::optional<bool> oracle_sig_decodes(const std::array<uint8_t, 96>& s, bool legacy)
{
    for (const auto& f : kBlsSigFacts)
        if (f.legacy == legacy && unhex(f.bytes) == Bytes(s.begin(), s.end())) return f.core_ok;
    for (const auto& m : mined_sigs())
        if (m == s) return true;
    return v::bls_sig_core_decodes(s, legacy);
}

ProviderTxRules with_bls(ProviderTxRules r)
{
    if (!v::bls_backend_available()) {
        r.bls.pubkey_valid = &oracle_pubkey_valid;
        r.bls.sig_decodes  = &oracle_sig_decodes;
    }
    return r;
}

ProviderTxRules rules_for(DashNetwork n, uint32_t height)
{
    return with_bls(ProviderTxRules::for_block(n, height));
}

ProviderTxRules mainnet_v24()
{
    auto r = rules_for(DashNetwork::MAINNET, 2'600'000);
    r.v24_active = true;   // the S0 hook says "not yet" for mainnet; force the post-activation rules
    return r;
}
ProviderTxRules mainnet_pre_v24() { return rules_for(DashNetwork::MAINNET, 2'570'000); }

template <typename T>
std::optional<std::string> refusal(const T& p, const ProviderTxRules& r)
{
    return provider_payload_refusal(T::SPECIALTX_TYPE, v::serialize_special_payload(p), r);
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// Gate hook and tx types
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24Gate, ActivationHookAndVersionCeiling)
{
    // S0 seam defaults: mainnet never (not locked in), testnet from the
    // first CbTx v4 block, devnet/regtest unknown.
    EXPECT_FALSE(dash::coin::v24_active(DashNetwork::MAINNET, 2'580'480));
    EXPECT_FALSE(dash::coin::v24_active(DashNetwork::MAINNET, 4'000'000));
    EXPECT_FALSE(dash::coin::v24_active(DashNetwork::TESTNET, 1'577'999));
    EXPECT_TRUE(dash::coin::v24_active(DashNetwork::TESTNET, 1'578'000));
    EXPECT_FALSE(dash::coin::v24_active(DashNetwork::REGTEST, 1'000'000));
    // ProTxVersion::GetMax(v19, v24).
    EXPECT_EQ(dash::coin::protx_max_version(false, false), 1);
    EXPECT_EQ(dash::coin::protx_max_version(false, true), 1);
    EXPECT_EQ(dash::coin::protx_max_version(true, false), 2);
    EXPECT_EQ(dash::coin::protx_max_version(true, true), 3);
    // The v23.1.9 whitelist stays 0..9 (fail closed until S3); the v24 one is 0..12.
    EXPECT_FALSE(dash::coin::tx_type_is_known(10));
    EXPECT_TRUE(dash::coin::tx_type_is_known_v24(10));
    EXPECT_TRUE(dash::coin::tx_type_is_known_v24(12));
    EXPECT_FALSE(dash::coin::tx_type_is_known_v24(13));
    MutableTransaction t;
    t.version = 3;
    t.type = 11;
    EXPECT_EQ(dash::coin::contextual_tx_check(t, false), std::optional<std::string_view>{"bad-txns-type"});
    EXPECT_EQ(dash::coin::contextual_tx_check_v24(t, false), std::nullopt);
    t.type = 13;
    EXPECT_EQ(dash::coin::contextual_tx_check_v24(t, false), std::optional<std::string_view>{"bad-txns-type"});
}

TEST(DashV24Gate, UnknownVersionsFailClosedInTheFoldParse)
{
    // Core GetTxPayload semantics: a payload that is only an unknown version
    // decodes (to the version alone); with any tail it does not.
    v::CProRegTx reg;
    EXPECT_TRUE(v::decode_special_payload(unhex("0400"), reg));
    EXPECT_EQ(reg.nVersion, 4);
    EXPECT_FALSE(v::decode_special_payload(unhex("040000"), reg));
    // The fold-facing parse refuses every unknown version: never a partial object.
    for (const char* p : {"0000", "0400", "ffff"}) {
        v::CProRegTx a; v::CProUpServTx b; v::CProUpRegTx c; v::CProUpRevTx d;
        EXPECT_FALSE(v::parse_protx_payload(unhex(p), a)) << p;
        EXPECT_FALSE(v::parse_protx_payload(unhex(p), b)) << p;
        EXPECT_FALSE(v::parse_protx_payload(unhex(p), c)) << p;
        EXPECT_FALSE(v::parse_protx_payload(unhex(p), d)) << p;
    }
    // Types 10-12 read every field whatever the version (as Core); the fold
    // parse still refuses a version other than 1.
    v::CProDisTx dis;
    dis.nVersion = 2;
    dis.vchSigs.resize(1);
    const auto bytes = v::serialize_special_payload(dis);
    EXPECT_TRUE(v::decode_special_payload(bytes, dis));
    EXPECT_FALSE(v::parse_protx_payload(bytes, dis));
}

// ═══════════════════════════════════════════════════════════════════════════
// Testnet captures
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24Testnet, RawTxRebuildsTheTxidAndRoundTrips)
{
    ASSERT_EQ(std::size(kTestnetProTx), 17u);
    for (const auto& f : kTestnetProTx) {
        const Bytes raw = unhex(f.raw);
        const MutableTransaction tx = parse_tx(raw);
        EXPECT_EQ(pack_bytes(tx), raw) << f.txid;
        EXPECT_EQ(sha256d(raw).GetHex(), f.txid);
        EXPECT_EQ(tx.version, 3);
        EXPECT_EQ(tx.type, f.txtype);
        EXPECT_EQ(Bytes(tx.extra_payload.begin(), tx.extra_payload.end()), unhex(f.payload)) << f.txid;
    }
}

TEST(DashV24Testnet, PayloadsDecodeToInsightFieldsAndReencodeByteExact)
{
    size_t reg = 0, serv = 0, rev = 0, evo = 0;
    for (const auto& f : kTestnetProTx) {
        const Bytes payload = unhex(f.payload);
        SCOPED_TRACE(f.txid);
        if (f.txtype == 1) {
            v::CProRegTx p;
            ASSERT_TRUE(v::parse_protx_payload(payload, p));
            EXPECT_EQ(p.nVersion, 3);
            EXPECT_EQ(p.nType, f.mntype);
            EXPECT_EQ(p.collateralOutpoint.hash.GetHex(), f.ref);
            EXPECT_EQ(p.collateralOutpoint.index, f.index);
            EXPECT_EQ(p.extNetInfo.to_string(), f.addresses);
            EXPECT_EQ(rawhex(p.keyIDOwner), f.owner);
            EXPECT_EQ(rawhex(p.keyIDVoting), f.voting);
            EXPECT_EQ(hex(p.pubKeyOperator), f.opkey);
            EXPECT_EQ(payouts_str(p.payouts), f.payouts);
            EXPECT_TRUE(p.shares.empty());
            EXPECT_EQ(p.nEarlyPeriodBlocks, 0u);
            EXPECT_EQ(p.nEarlyPenalty, 0);
            EXPECT_EQ(p.inputsHash.GetHex(), f.inputs);
            if (p.nType == v::MnType::EVO) {
                EXPECT_EQ(p.platformNodeID.GetHex(), f.nodeid);
                EXPECT_EQ(p.platformP2PPort, 0) << "no scalar Platform ports at v3";
                ++evo;
            }
            EXPECT_EQ(v::serialize_special_payload(p), payload);
            ++reg;
        } else if (f.txtype == 2) {
            v::CProUpServTx p;
            ASSERT_TRUE(v::parse_protx_payload(payload, p));
            EXPECT_EQ(p.nVersion, 3);
            EXPECT_EQ(p.nType, f.mntype);
            EXPECT_EQ(p.proTxHash.GetHex(), f.ref);
            EXPECT_EQ(p.extNetInfo.to_string(), f.addresses);
            EXPECT_EQ(p.inputsHash.GetHex(), f.inputs);
            if (p.nType == v::MnType::EVO) EXPECT_EQ(p.platformNodeID.GetHex(), f.nodeid);
            EXPECT_EQ(v::serialize_special_payload(p), payload);
            // The operator signature preimage is still "payload minus 96 bytes".
            EXPECT_TRUE(v::protx_operator_sign_hash(payload).has_value());
            ++serv;
        } else {
            v::CProUpRevTx p;
            ASSERT_TRUE(v::parse_protx_payload(payload, p));
            EXPECT_EQ(p.nVersion, 3);
            EXPECT_EQ(p.proTxHash.GetHex(), f.ref);
            EXPECT_EQ(p.nReason, f.index);
            EXPECT_EQ(p.inputsHash.GetHex(), f.inputs);
            EXPECT_EQ(v::serialize_special_payload(p), payload);
            EXPECT_EQ(payload.size(), 164u) << "v3 revocation keeps the v2 layout";
            ++rev;
        }
    }
    EXPECT_EQ(reg, 8u);
    EXPECT_EQ(serv, 8u);
    EXPECT_EQ(rev, 1u);
    EXPECT_GE(evo, 1u);
}

TEST(DashV24Testnet, MinedPayloadsPassCorePayloadChecksOnlyOnceV24IsActive)
{
    for (const auto& f : kTestnetProTx) {
        SCOPED_TRACE(f.txid);
        const Bytes payload = unhex(f.payload);
        const auto at = rules_for(DashNetwork::TESTNET, f.height);
        ASSERT_TRUE(at.v24_active);
        EXPECT_EQ(provider_payload_refusal(f.txtype, payload, at), std::nullopt);
        // The same bytes one block before activation: GetMax(v19, !v24) = 2.
        const auto before = rules_for(DashNetwork::TESTNET, 1'577'999);
        EXPECT_EQ(provider_payload_refusal(f.txtype, payload, before),
                  std::optional<std::string>{"bad-protx-version"});
        EXPECT_EQ(provider_payload_refusal(f.txtype, payload, mainnet_pre_v24()),
                  std::optional<std::string>{"bad-protx-version"});
    }
}

TEST(DashV24Testnet, EvoRegistrationNetInfoMatchesTheCapturedBytes)
{
    // 2770d249… (1,578,168): the first Evo ProRegTx v3, three purposes.
    size_t idx = std::size(kTestnetProTx);
    for (size_t i = 0; i < std::size(kTestnetProTx); ++i)
        if (std::string(kTestnetProTx[i].txid).rfind("2770d249", 0) == 0) idx = i;
    ASSERT_LT(idx, std::size(kTestnetProTx));
    const auto& f = kTestnetProTx[idx];
    v::CProRegTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(f.payload), p));
    EXPECT_EQ(hex(pack_bytes(p.extNetInfo)),
              "0103"
              "0001" "01" "010455d1f30a4e1f"     // core_p2p      85.209.243.10:19999
              "0101" "01" "010455d1f30a8f30"     // platform_p2p  85.209.243.10:36656
              "0201" "01" "010455d1f30a05a3");   // platform_https 85.209.243.10:1443
    EXPECT_EQ(p.extNetInfo.GetPrimary().ToStringAddrPort(), "85.209.243.10:19999");
    EXPECT_EQ(v::validate_ext_netinfo(p.extNetInfo, v::NetInfoRules::testnet()), v::NetInfoStatus::Success);
    // On mainnet the same entries break the primary-port rule (19999 != 9999).
    EXPECT_EQ(v::validate_ext_netinfo(p.extNetInfo, v::NetInfoRules::mainnet()), v::NetInfoStatus::BadPort);
}

// ═══════════════════════════════════════════════════════════════════════════
// CbTx v4 at 1,578,000
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24CbTx, FirstV4CoinbaseLayoutAndTheV3CodecRefusal)
{
    // Captured by the probe (scan_post.jsonl, block 0000009c…639c): coinbase
    // ab22dcb7…bacc, payload 207 bytes, first bytes 04 00 10 14. The probe did
    // not keep the full coinbase, so its txid cannot be re-derived here (S1 /
    // S9 fixture).
    const Bytes prefix = unhex("04001014");
    // A v4 payload with the same version/height and creditPoolBalance
    // 376422.49077902 (Insight), null unlock root: v3 fields + 32 bytes.
    v::CCbTx v3;
    v3.nVersion = 3;
    v3.nHeight = 1'578'000;
    v3.creditPoolBalance = 37'642'249'077'902;
    Bytes v4 = pack_bytes(v3);
    ASSERT_EQ(v4.size(), 175u);
    v4[0] = 4;
    v4.insert(v4.end(), 32, 0x00);                 // merkleRootAssetUnlocks = null
    EXPECT_EQ(v4.size(), 207u) << "the captured payload size";
    EXPECT_TRUE(std::equal(prefix.begin(), prefix.end(), v4.begin()));
    // B1: the v3 codec refuses it (32 trailing bytes) -- fail closed until S1.
    v::CCbTx out;
    EXPECT_FALSE(v::parse_cbtx(std::vector<unsigned char>(v4.begin(), v4.end()), out));
}

// ═══════════════════════════════════════════════════════════════════════════
// Synthetic payloads (Core v24.0.0 layout)
// ═══════════════════════════════════════════════════════════════════════════

namespace {

v::CProRegTx make_shared_reg()
{
    v::CProRegTx p;
    p.nVersion = 3;
    p.nType = v::MnType::REGULAR;
    p.collateralOutpoint.index = 0;                       // hash null: internal collateral
    p.extNetInfo = ext({{0, {svc4(1, 2, 3, 4, 9999)}}});
    p.pubKeyOperator = arr<48>(kOpKey_proreg_shared);
    p.keyIDVoting = pat160(0x06);
    p.nOperatorReward = 500;
    const int64_t COIN = v::CCollateralShare::COIN;
    v::CCollateralShare a, b, c;
    a.amount = 400 * COIN; a.scriptRefund = p2pkh(pat160(0x11)); a.keyIDOwner = pat160(0x21);
    b.amount = 350 * COIN; b.scriptRefund = p2pkh(pat160(0x12)); b.scriptReward = p2sh(pat160(0x32));
    b.keyIDOwner = pat160(0x22);
    c.amount = 250 * COIN; c.scriptRefund = p2sh(pat160(0x13)); c.scriptReward = p2pkh(pat160(0x33));
    c.keyIDOwner = pat160(0x23);
    p.shares = {a, b, c};
    for (uint8_t i = 0; i < 3; ++i) p.vchJoinSigs.push_back(pat_arr<65>(static_cast<uint8_t>(0x41 + i)));
    p.nEarlyPeriodBlocks = 210240;
    p.nEarlyPenalty = 10 * COIN;
    p.inputsHash = pat256(0x07);
    return p;
}

v::CProRegTx make_multipayout_reg()
{
    v::CProRegTx p;
    p.nVersion = 3;
    p.collateralOutpoint.hash = pat256(0x61);
    p.collateralOutpoint.index = 1;
    const Bytes v6 = unhex("2a0104f8000000000000000000000001");
    p.extNetInfo = ext({{0, {svc4(5, 6, 7, 8, 9999),
                             v::NetInfoEntry{v::NetService::make(v::NetService::IPV6, v6, 9999)}}}});
    p.keyIDOwner = pat160(0x62);
    p.pubKeyOperator = arr<48>(kOpKey_proreg_multipayout);
    p.keyIDVoting = pat160(0x64);
    v::MasternodePayoutShare x, y, z;
    x.scriptPayout = p2pkh(pat160(0x51)); x.reward = 5000;
    y.scriptPayout = p2sh(pat160(0x52));  y.reward = 3000;
    z.scriptPayout = p2pkh(pat160(0x53)); z.reward = 2000;
    p.payouts = {x, y, z};
    p.inputsHash = pat256(0x65);
    auto sig = pat(65, 0x66);
    p.vchSig.assign(sig.begin(), sig.end());
    return p;
}

v::CProRegTx make_evo_reg()
{
    v::CProRegTx p;
    p.nVersion = 3;
    p.nType = v::MnType::EVO;
    p.collateralOutpoint.hash = pat256(0x71);
    p.collateralOutpoint.index = 0;
    v::DomainPort d;
    d.addr = "evo.dash.org";
    d.port = 443;
    p.extNetInfo = ext({{0, {svc4(9, 9, 9, 9, 9999),
                             v::NetInfoEntry{v::NetService::make(v::NetService::ONION, pat(32, 0x7a), 9999)}}},
                        {1, {svc4(9, 9, 9, 9, 26656)}},
                        {2, {svc4(9, 9, 9, 9, 443), v::NetInfoEntry{d}}}});
    p.keyIDOwner = pat160(0x72);
    p.pubKeyOperator = arr<48>(kOpKey_proreg_evo);
    p.keyIDVoting = pat160(0x74);
    p.nOperatorReward = 1000;
    v::MasternodePayoutShare x;
    x.scriptPayout = p2pkh(pat160(0x75));
    p.payouts = {x};
    p.inputsHash = pat256(0x76);
    p.platformNodeID = pat160(0x77);
    auto sig = pat(65, 0x78);
    p.vchSig.assign(sig.begin(), sig.end());
    return p;
}

v::CProUpRegTx make_upreg_v3()
{
    v::CProUpRegTx p;
    p.nVersion = 3;
    p.proTxHash = pat256(0x81);
    p.pubKeyOperator = arr<48>(kOpKey_proupreg);
    p.keyIDVoting = pat160(0x83);
    v::MasternodePayoutShare x, y;
    x.scriptPayout = p2pkh(pat160(0x84)); x.reward = 6000;
    y.scriptPayout = p2sh(pat160(0x85));  y.reward = 4000;
    p.payouts = {x, y};
    p.inputsHash = pat256(0x86);
    auto sig = pat(65, 0x87);
    p.vchSig.assign(sig.begin(), sig.end());
    return p;
}

v::CProUpServTx make_upserv_v3()
{
    v::CProUpServTx p;
    p.nVersion = 3;
    p.nType = v::MnType::REGULAR;
    p.proTxHash = pat256(0x92);
    Bytes cj{0xfc};
    auto tail = pat(15, 0x91);
    cj.insert(cj.end(), tail.begin(), tail.end());
    p.extNetInfo = ext({{0, {svc4(8, 8, 4, 4, 9999),
                             v::NetInfoEntry{v::NetService::make(v::NetService::CJDNS, cj, 9999)},
                             v::NetInfoEntry{v::NetService::make(v::NetService::I2P, pat(32, 0x93), 0)}}}});
    p.scriptOperatorPayout = p2pkh(pat160(0x94));
    p.inputsHash = pat256(0x95);
    p.sig = arr<96>(kSig_proupserv);
    return p;
}

v::CProUpRevTx make_rev_v3()
{
    v::CProUpRevTx p;
    p.nVersion = 3;
    p.proTxHash = pat256(0x9a);
    p.nReason = v::CProUpRevTx::REASON_CHANGE_OF_KEYS;
    p.inputsHash = pat256(0x9b);
    p.sig = arr<96>(kSig_prouprev);
    return p;
}

v::CProDisTx make_dis(bool unanimous)
{
    v::CProDisTx p;
    p.proTxHash = pat256(0xa1);
    if (unanimous) {
        p.actorIndex = 0;
        for (uint8_t i = 0; i < 3; ++i) p.vchSigs.push_back(pat_arr<65>(static_cast<uint8_t>(0xa3 + i)));
    } else {
        p.actorIndex = 1;
        p.vchSigs.push_back(pat_arr<65>(0xa2));
    }
    return p;
}

v::CProUpShareTx make_upshare()
{
    v::CProUpShareTx p;
    p.proTxHash = pat256(0xb1);
    p.shareIndex = 2;
    p.scriptReward = p2pkh(pat160(0xb2));
    p.inputsHash = pat256(0xb3);
    auto sig = pat(65, 0xb4);
    p.vchSig.assign(sig.begin(), sig.end());
    return p;
}

v::CProUpSharedRegTx make_upsharedreg()
{
    v::CProUpSharedRegTx p;
    p.proTxHash = pat256(0xc1);
    p.pubKeyOperator = arr<48>(kOpKey_proupsharedreg);
    p.keyIDVoting = pat160(0xc3);
    p.inputsHash = pat256(0xc4);
    for (uint8_t i = 0; i < 3; ++i) p.vchSigs.push_back(pat_arr<65>(static_cast<uint8_t>(0xc5 + i)));
    return p;
}

/// decode(vector) == built object, encode(built) == vector, encode(decode) == vector.
template <typename T>
void expect_vector(const char* hex_vec, const T& built)
{
    const Bytes want = unhex(hex_vec);
    EXPECT_EQ(hex(v::serialize_special_payload(built)), hex(want)) << "C++ encoder vs generator";
    T got;
    ASSERT_TRUE(v::parse_protx_payload(want, got));
    EXPECT_EQ(v::serialize_special_payload(got), want);
}

} // namespace

TEST(DashV24Synthetic, SharedRegistrationRoundTripsAndPassesCoreChecks)
{
    const auto built = make_shared_reg();
    expect_vector(kSyn_proreg_shared, built);
    v::CProRegTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_proreg_shared), p));
    EXPECT_TRUE(p.IsShared());
    EXPECT_TRUE(p.keyIDOwner.IsNull()) << "a shared registration has no owner key";
    EXPECT_TRUE(p.collateralOutpoint.hash.IsNull());
    ASSERT_EQ(p.shares.size(), 3u);
    ASSERT_EQ(p.vchJoinSigs.size(), 3u);
    EXPECT_EQ(p.shares[0].amount, 400 * v::CCollateralShare::COIN);
    EXPECT_EQ(p.shares[0].RewardScript(), p.shares[0].scriptRefund) << "empty reward -> refund script";
    EXPECT_EQ(p.shares[1].RewardScript(), p.shares[1].scriptReward);
    EXPECT_EQ(p.vchJoinSigs[2], pat_arr<65>(0x43));
    EXPECT_EQ(p.nEarlyPeriodBlocks, 210240u);
    EXPECT_EQ(p.nEarlyPenalty, 10 * v::CCollateralShare::COIN);
    EXPECT_TRUE(p.vchSig.empty());
    EXPECT_TRUE(p.payouts.empty());
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
    EXPECT_EQ(refusal(p, mainnet_pre_v24()), std::optional<std::string>{"bad-protx-version"});
    // One join signature per share or the object cannot be encoded (Core throws).
    auto broken = built;
    broken.vchJoinSigs.pop_back();
    EXPECT_THROW(v::serialize_special_payload(broken), std::ios_base::failure);
}

TEST(DashV24Synthetic, MultiPayoutRegistrationRoundTripsWithIPv6)
{
    expect_vector(kSyn_proreg_multipayout, make_multipayout_reg());
    v::CProRegTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_proreg_multipayout), p));
    ASSERT_EQ(p.payouts.size(), 3u);
    EXPECT_EQ(p.owner_payouts().size(), 3u);
    EXPECT_EQ(p.payouts[1].reward, 3000);
    EXPECT_EQ(p.extNetInfo.to_string(), "core_p2p=5.6.7.8:9999,[2a01:4f8::1]:9999");
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
}

TEST(DashV24Synthetic, EvoRegistrationWithTorAndDomainEntries)
{
    expect_vector(kSyn_proreg_evo, make_evo_reg());
    v::CProRegTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_proreg_evo), p));
    EXPECT_EQ(p.nType, v::MnType::EVO);
    ASSERT_EQ(p.extNetInfo.purposes.size(), 3u);
    const auto https = p.extNetInfo.GetEntries(v::NetInfoPurpose::PLATFORM_HTTPS);
    ASSERT_EQ(https.size(), 2u);
    ASSERT_NE(https[1].domain(), nullptr);
    EXPECT_EQ(https[1].ToStringAddrPort(), "evo.dash.org:443");
    const auto core = p.extNetInfo.GetEntries(v::NetInfoPurpose::CORE_P2P);
    ASSERT_NE(core[1].service(), nullptr);
    EXPECT_TRUE(core[1].service()->IsTor());
    EXPECT_EQ(p.platformNodeID, pat160(0x77));
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
}

TEST(DashV24Synthetic, ProUpRegTxV3CarriesAPayoutList)
{
    expect_vector(kSyn_proupreg, make_upreg_v3());
    v::CProUpRegTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_proupreg), p));
    ASSERT_EQ(p.payouts.size(), 2u);
    EXPECT_TRUE(p.scriptPayout.m_data.empty());
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
}

TEST(DashV24Synthetic, ProUpServTxV3WithCjdnsAndI2P)
{
    expect_vector(kSyn_proupserv, make_upserv_v3());
    v::CProUpServTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_proupserv), p));
    const auto core = p.extNetInfo.GetEntries(v::NetInfoPurpose::CORE_P2P);
    ASSERT_EQ(core.size(), 3u);
    EXPECT_TRUE(core[1].service()->IsCJDNS());
    EXPECT_EQ(core[1].ToStringAddrPort().front(), '[');
    EXPECT_TRUE(core[2].service()->IsI2P());
    EXPECT_EQ(core[2].GetPort(), 0) << "I2P SAM 3.1 has no ports";
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
    EXPECT_EQ(v::protx_operator_sign_hash(unhex(kSyn_proupserv)),
              std::optional<uint256>{[] {
                  auto b = unhex(kSyn_proupserv);
                  b.resize(b.size() - 96);
                  return sha256d(b);
              }()});
}

TEST(DashV24Synthetic, ProUpRevTxV3KeepsTheV2Layout)
{
    const auto p = make_rev_v3();
    expect_vector(kSyn_prouprev, p);
    const auto b = v::serialize_special_payload(p);
    EXPECT_EQ(b.size(), 164u);
    v::CProUpRevTx q;
    ASSERT_TRUE(v::parse_protx_payload(b, q));
    EXPECT_EQ(q.nReason, 3);
    EXPECT_EQ(refusal(q, mainnet_v24()), std::nullopt);
}

TEST(DashV24Synthetic, Type10ProDisTxUnilateralAndUnanimous)
{
    expect_vector(kSyn_prodis_uni, make_dis(false));
    expect_vector(kSyn_prodis_all, make_dis(true));
    v::CProDisTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_prodis_all), p));
    EXPECT_EQ(p.vchSigs.size(), 3u);
    EXPECT_EQ(unhex(kSyn_prodis_uni).size(), 2u + 32 + 2 + 1 + 65);
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
    EXPECT_EQ(refusal(p, mainnet_pre_v24()), std::optional<std::string>{"bad-prodis-too-early"});
}

TEST(DashV24Synthetic, Type11ProUpShareTx)
{
    expect_vector(kSyn_proupshare, make_upshare());
    v::CProUpShareTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_proupshare), p));
    EXPECT_EQ(p.shareIndex, 2);
    EXPECT_EQ(p.vchSig.size(), 65u);
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
    EXPECT_EQ(refusal(p, mainnet_pre_v24()), std::optional<std::string>{"bad-proupshare-too-early"});
}

TEST(DashV24Synthetic, Type12ProUpSharedRegTx)
{
    expect_vector(kSyn_proupsharedreg, make_upsharedreg());
    v::CProUpSharedRegTx p;
    ASSERT_TRUE(v::parse_protx_payload(unhex(kSyn_proupsharedreg), p));
    EXPECT_EQ(p.vchSigs.size(), 3u);
    EXPECT_EQ(unhex(kSyn_proupsharedreg).size(), 2u + 32 + 48 + 20 + 32 + 1 + 3 * 65);
    EXPECT_EQ(refusal(p, mainnet_v24()), std::nullopt);
    EXPECT_EQ(refusal(p, mainnet_pre_v24()), std::optional<std::string>{"bad-proupsharedreg-too-early"});
}

// ═══════════════════════════════════════════════════════════════════════════
// SML entry v3 and mnlistdiff
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24Sml, EntryWireBytesAndLeafHashes)
{
    struct Row { const char* wire; const char* hash; uint16_t ver; };
    const Row rows[] = {
        {kSml_sml_evo_v3_wire, kSml_sml_evo_v3_hash, 3},
        {kSml_sml_evo_v2_wire, kSml_sml_evo_v2_hash, 2},
        {kSml_sml_reg_v3_wire, kSml_sml_reg_v3_hash, 3},
        {kSml_sml_reg_v2_wire, kSml_sml_reg_v2_hash, 2},
        {kSml_sml_reg_v3_empty_wire, kSml_sml_reg_v3_empty_hash, 3},
    };
    for (const auto& r : rows) {
        const Bytes wire = unhex(r.wire);
        ::PackStream ps(wire);
        v::CSimplifiedMNListEntry e;
        ps >> e;
        EXPECT_TRUE(ps.empty());
        EXPECT_EQ(e.nVersion, r.ver);
        EXPECT_EQ(pack_bytes(e), wire);
        EXPECT_EQ(hex(e.CalcHash().data(), 32), std::string(r.hash)) << r.wire;
    }
    // The same EvoNode at v2 and at v3: different wire, different leaf.
    ::PackStream a(unhex(kSml_sml_evo_v3_wire)), b(unhex(kSml_sml_evo_v2_wire));
    v::CSimplifiedMNListEntry e3, e2;
    a >> e3;
    b >> e2;
    EXPECT_EQ(e3.proRegTxHash, e2.proRegTxHash);
    EXPECT_NE(e3.CalcHash(), e2.CalcHash());
    EXPECT_EQ(e3.platformHTTPPort, 0) << "no platformHTTPPort at v3";
    EXPECT_EQ(e2.platformHTTPPort, 443);
    EXPECT_EQ(e3.extNetInfo.to_string(),
              "core_p2p=7.7.7.7:9999;platform_p2p=7.7.7.7:26656;platform_https=7.7.7.7:443");
    // A revoked v3 masternode keeps an empty ExtNetInfo: "01 00".
    ::PackStream c(unhex(kSml_sml_reg_v3_empty_wire));
    v::CSimplifiedMNListEntry ee;
    c >> ee;
    EXPECT_TRUE(ee.extNetInfo.IsEmpty());
    EXPECT_EQ(hex(pack_bytes(ee.extNetInfo)), "0100");
}

TEST(DashV24Sml, MnListDiffWithV3EntriesParsesAndMatchesItsCbTxRoot)
{
    const Bytes wire = unhex(kSml_diff);
    ::PackStream ps(wire);
    v::CSimplifiedMNListDiff diff;
    ps >> diff;
    ASSERT_EQ(diff.mnList.size(), 4u);
    EXPECT_EQ(diff.mnList[0].nVersion, 2);
    EXPECT_EQ(diff.mnList[1].nVersion, 3);
    EXPECT_EQ(diff.mnList[2].nVersion, 3);
    EXPECT_EQ(diff.deletedMNs.size(), 1u);
    EXPECT_EQ(hex(diff.quorum_tail), "000000");
    EXPECT_EQ(pack_bytes(diff), wire) << "byte-exact re-serialization";

    v::CSimplifiedMNList sml;
    v::apply_diff(sml, diff);
    const uint256 root = sml.CalcMerkleRoot();
    EXPECT_EQ(hex(root.data(), 32), std::string(kSml_diff_root));
    v::CCbTx cbtx;
    ASSERT_TRUE(v::parse_cbtx(diff.cbTx.extra_payload, cbtx));
    EXPECT_EQ(cbtx.merkleRootMNList, root) << "the B3 check: SML root == committed root";
}

TEST(DashV24Sml, UnknownEntryVersionFailsTheDiffParse)
{
    for (uint16_t bad : {uint16_t{0}, uint16_t{4}}) {
        Bytes wire = unhex(kSml_sml_reg_v3_wire);
        wire[0] = static_cast<uint8_t>(bad);
        ::PackStream ps(wire);
        v::CSimplifiedMNListEntry e;
        EXPECT_THROW(ps >> e, std::ios_base::failure) << bad;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// NetInfo reading, validation, conversion
// ═══════════════════════════════════════════════════════════════════════════

namespace {
v::NetInfoEntry read_entry(const Bytes& b, size_t* left = nullptr)
{
    ::PackStream ps(b);
    v::NetInfoEntry e;
    ps >> e;
    if (left) *left = ps.cursor_size();
    return e;
}
} // namespace

TEST(DashV24NetInfo, EntryReadsMirrorCore)
{
    size_t left = 0;
    // A valid IPv4 service: 01 | 01 04 01020304 | 270f.
    auto e = read_entry(unhex("01010401020304270f"), &left);
    ASSERT_NE(e.service(), nullptr);
    EXPECT_EQ(e.ToStringAddrPort(), "1.2.3.4:9999");
    EXPECT_EQ(left, 0u);
    // Known network, wrong length: Core swallows the throw and marks the
    // entry invalid; only the type, net id and length were consumed.
    e = read_entry(unhex("010105aabbccddee270f"), &left);
    EXPECT_EQ(e.type, v::NetInfoEntry::TYPE_INVALID);
    EXPECT_EQ(left, 7u);
    // Unknown network id: the address is skipped, the entry is invalid, the
    // port is still read.
    e = read_entry(unhex("010703aabbcc270f"), &left);
    EXPECT_EQ(e.type, v::NetInfoEntry::TYPE_INVALID);
    EXPECT_EQ(left, 0u);
    // IPv4 embedded in an ADDRv2 IPv6 record: invalid.
    e = read_entry(unhex("01021000000000000000000000ffff01020304270f"), &left);
    EXPECT_EQ(e.type, v::NetInfoEntry::TYPE_INVALID);
    EXPECT_EQ(left, 0u);
    // Unknown entry type: only its own byte is consumed.
    e = read_entry(unhex("03aabb"), &left);
    EXPECT_EQ(e.type, v::NetInfoEntry::TYPE_INVALID);
    EXPECT_EQ(left, 2u);
    // Domains: upper case is not a valid domain (entry invalid); a domain
    // longer than 253 bytes throws out of the whole payload.
    {
        Bytes up{0x02, 0x08};
        for (char c : std::string("Evo.Dash")) up.push_back(static_cast<uint8_t>(c));
        up.push_back(0x01); up.push_back(0xbb);
        e = read_entry(up, &left);
        EXPECT_EQ(e.type, v::NetInfoEntry::TYPE_INVALID);
    }
    Bytes longd{0x02, 0xfd, 0xfe, 0x00};
    longd.insert(longd.end(), 254, 'a');
    longd.push_back(0x01); longd.push_back(0xbb);
    EXPECT_THROW(read_entry(longd), std::ios_base::failure);
    // An invalid entry re-encodes as the single byte 0xff.
    EXPECT_EQ(hex(pack_bytes(v::NetInfoEntry{})), "ff");
}

TEST(DashV24NetInfo, ExtNetInfoReadRules)
{
    // Purposes must be known and strictly ascending.
    v::ExtNetInfo n;
    for (const char* bad : {"0102" "0101" "01010401020304270f" "0001" "01010401020304270f",   // 1 then 0
                            "0101" "0301" "01010401020304270f",                                // purpose 3
                            "0102" "0001" "01010401020304270f" "0001" "01010401020304270f"}) { // 0 twice
        ::PackStream ps(unhex(bad));
        EXPECT_THROW(ps >> n, std::ios_base::failure) << bad;
    }
    // An unknown ExtNetInfo version reads (and writes) only its version byte.
    ::PackStream ps(unhex("02"));
    ps >> n;
    EXPECT_EQ(n.version, 2);
    EXPECT_FALSE(n.IsEmpty());
    EXPECT_EQ(hex(pack_bytes(n)), "02");
    EXPECT_EQ(v::validate_ext_netinfo(n, v::NetInfoRules::mainnet()), v::NetInfoStatus::Malformed);
}

TEST(DashV24NetInfo, ServicePredicatesAndFormatting)
{
    EXPECT_FALSE(v::NetService::ipv4(0, 0, 0, 0, 1).IsValid());
    EXPECT_FALSE(v::NetService::ipv4(255, 255, 255, 255, 1).IsValid());
    EXPECT_TRUE(v::NetService::ipv4(10, 0, 0, 1, 1).IsRFC1918());
    EXPECT_FALSE(v::NetService::ipv4(10, 0, 0, 1, 1).IsRoutable());
    EXPECT_FALSE(v::NetService::ipv4(127, 0, 0, 1, 1).IsRoutable());
    EXPECT_FALSE(v::NetService::ipv4(100, 64, 0, 1, 1).IsRoutable());   // RFC 6598
    EXPECT_TRUE(v::NetService::ipv4(85, 209, 243, 10, 1).IsRoutable());
    EXPECT_FALSE(v::NetService::make(v::NetService::IPV6, unhex("20010db8000000000000000000000001"), 1).IsValid());
    EXPECT_FALSE(v::NetService::make(v::NetService::CJDNS, unhex("fd000000000000000000000000000001"), 1).IsValid());
    EXPECT_EQ(v::NetService::make(v::NetService::IPV6, unhex("20010000000000000000000000000001"), 7).ToStringAddrPort(),
              "[2001::1]:7");
    EXPECT_EQ(v::NetService::make(v::NetService::IPV6, unhex("00010000000000010000000000000001"), 7).ToStringAddr(),
              "1:0:0:1::1") << "RFC 5952: the longest zero run is compressed, not the first";
    EXPECT_EQ(v::NetService::make(v::NetService::IPV6, unhex("00010000000000010000000000010001"), 7).ToStringAddr(),
              "1::1:0:0:1:1") << "RFC 5952: of equal runs, the first is compressed";
    EXPECT_EQ(v::NetService::make(v::NetService::IPV6, unhex("00010000000100000000000000000001"), 7).ToStringAddr(),
              "1:0:1::1") << "a single zero group is never compressed";
    EXPECT_TRUE(v::is_bad_port(443));
    EXPECT_TRUE(v::is_bad_port(8333));
    EXPECT_FALSE(v::is_bad_port(9999));
    EXPECT_FALSE(v::is_bad_port(0));
}

TEST(DashV24NetInfo, LegacyToExtendedConversion)
{
    auto legacy = [](std::array<uint8_t, 4> a, uint16_t port) {
        v::LegacyNetService l;
        l.ip[10] = 0xff; l.ip[11] = 0xff;
        std::copy(a.begin(), a.end(), l.ip.begin() + 12);
        l.port_be = port;
        return l;
    };
    auto m = v::ext_netinfo_from_legacy(legacy({1, 2, 3, 4}, 9999), v::NetInfoRules::mainnet());
    ASSERT_TRUE(m);
    EXPECT_EQ(hex(pack_bytes(*m)), "01010001" "01010401020304270f");
    EXPECT_TRUE(v::ext_netinfo_from_legacy(legacy({1, 2, 3, 4}, 19999), v::NetInfoRules::testnet()));
    EXPECT_FALSE(v::ext_netinfo_from_legacy(legacy({1, 2, 3, 4}, 19999), v::NetInfoRules::mainnet()))
        << "mainnet primary port";
    EXPECT_FALSE(v::ext_netinfo_from_legacy(legacy({10, 0, 0, 1}, 9999), v::NetInfoRules::mainnet()))
        << "not routable";
    EXPECT_TRUE(v::ext_netinfo_from_legacy(legacy({10, 0, 0, 1}, 19899), v::NetInfoRules::regtest()));
    // An empty MnNetInfo converts to an empty ExtNetInfo.
    auto empty = v::ext_netinfo_from_legacy(v::LegacyNetService{}, v::NetInfoRules::mainnet());
    ASSERT_TRUE(empty);
    EXPECT_EQ(hex(pack_bytes(*empty)), "0100");
}

// ═══════════════════════════════════════════════════════════════════════════
// Reject reasons (Core v24.0.0 codes), one or more negative case each
// ═══════════════════════════════════════════════════════════════════════════

namespace {
using Code = std::optional<std::string>;
Code C(const char* s) { return std::string(s); }

v::CProRegTx make_v1_reg()
{
    v::CProRegTx p;
    p.nVersion = 1;
    p.collateralOutpoint.hash = pat256(0x01);
    p.collateralOutpoint.index = 0;   // the outpoint index has no default
    p.netInfo.ip[10] = 0xff; p.netInfo.ip[11] = 0xff;
    p.netInfo.ip[12] = 1; p.netInfo.ip[13] = 2; p.netInfo.ip[14] = 3; p.netInfo.ip[15] = 4;
    p.netInfo.port_be = 9999;
    p.keyIDOwner = pat160(0x02);
    p.pubKeyOperator = arr<48>(kOpKey_proreg_v1);   // legacy scheme (v1)
    p.keyIDVoting = pat160(0x04);
    p.scriptPayout = p2pkh(pat160(0x05));
    p.inputsHash = pat256(0x06);
    return p;
}

v::CProRegTx make_v2_evo_reg()
{
    auto p = make_v1_reg();
    p.nVersion = 2;
    p.nType = v::MnType::EVO;
    p.pubKeyOperator = arr<48>(kOpKey_proreg_v2_evo);   // the same secret, basic scheme
    p.platformNodeID = pat160(0x07);
    p.platformP2PPort = 26656;
    p.platformHTTPPort = 443;
    return p;
}

v::CProRegTx make_shared_evo()
{
    auto p = make_shared_reg();
    p.nType = v::MnType::EVO;
    p.shares.pop_back();
    p.vchJoinSigs.pop_back();
    p.shares[0].amount = 2000 * v::CCollateralShare::COIN;
    p.shares[1].amount = 2000 * v::CCollateralShare::COIN;
    p.extNetInfo = make_evo_reg().extNetInfo;
    p.platformNodeID = pat160(0x77);
    return p;
}
} // namespace

TEST(DashV24Reject, BasesAreValid)
{
    const auto r = mainnet_v24();
    EXPECT_EQ(refusal(make_shared_reg(), r), std::nullopt);
    EXPECT_EQ(refusal(make_multipayout_reg(), r), std::nullopt);
    EXPECT_EQ(refusal(make_evo_reg(), r), std::nullopt);
    EXPECT_EQ(refusal(make_v1_reg(), mainnet_pre_v24()), std::nullopt);
    EXPECT_EQ(refusal(make_v2_evo_reg(), mainnet_pre_v24()), std::nullopt);
    EXPECT_EQ(refusal(make_upreg_v3(), r), std::nullopt);
    EXPECT_EQ(refusal(make_upserv_v3(), r), std::nullopt);
    EXPECT_EQ(refusal(make_rev_v3(), r), std::nullopt);
    EXPECT_EQ(refusal(make_dis(false), r), std::nullopt);
    EXPECT_EQ(refusal(make_upshare(), r), std::nullopt);
    EXPECT_EQ(refusal(make_upsharedreg(), r), std::nullopt);
    auto se = make_shared_evo();
    auto rs = r;
    rs.evo_shares_active = true;
    EXPECT_EQ(refusal(se, rs), std::nullopt) << "valid once evo_shares is active";
}

// ═══════════════════════════════════════════════════════════════════════════
// Core's BLS decoding of operator keys and signatures
// ═══════════════════════════════════════════════════════════════════════════

TEST(DashV24Synthetic, LegacyRegistrationsCarryTheirVersionsScheme)
{
    expect_vector(kSyn_proreg_v1, make_v1_reg());
    expect_vector(kSyn_proreg_v2_evo, make_v2_evo_reg());
    // One secret, two encodings: a v1 payload carries the legacy one.
    EXPECT_NE(std::string(kOpKey_proreg_v1), std::string(kOpKey_proreg_v2_evo));
}

// CBLSLazyPublicKey::Get().IsValid() fails (bad-protx-key-null) for every
// invalid encoding, in every payload with an operator key, under the
// payload's scheme.
TEST(DashV24Bls, InvalidOperatorKeysAreKeyNull)
{
    const auto r = mainnet_v24();
    size_t invalid = 0;
    for (const auto& f : kBlsKeyFacts) {
        SCOPED_TRACE(f.what);
        const Code want = f.core_ok ? std::nullopt : C("bad-protx-key-null");
        invalid += !f.core_ok;
        const auto k = arr<48>(f.bytes);
        if (f.legacy) {
            auto a = make_v1_reg();
            a.pubKeyOperator = k;
            EXPECT_EQ(refusal(a, mainnet_pre_v24()), want);
            continue;
        }
        auto a = make_upreg_v3();
        a.pubKeyOperator = k;
        EXPECT_EQ(refusal(a, r), want);
        auto b = make_multipayout_reg();
        b.pubKeyOperator = k;
        EXPECT_EQ(refusal(b, r), want);
        auto c = make_upsharedreg();
        c.pubKeyOperator = k;
        EXPECT_EQ(refusal(c, r), want);
        auto d = make_v2_evo_reg();
        d.pubKeyOperator = k;
        EXPECT_EQ(refusal(d, mainnet_pre_v24()), want);
    }
    EXPECT_GE(invalid, 6u);
    // A legacy-scheme encoding is not the same key in a basic payload.
    auto w = make_upreg_v3();
    w.pubKeyOperator = arr<48>(kOpKey_proreg_v1);
    EXPECT_EQ(refusal(w, r), C("bad-protx-key-null"));
    auto z = make_upreg_v3();
    z.pubKeyOperator = {};
    EXPECT_EQ(refusal(z, r), C("bad-protx-key-null"));
}

// CBLSSignature::Unserialize throws ("malleable BLS object") on a type-2/4
// signature canonical under neither scheme: GetTxPayload fails.
TEST(DashV24Bls, UndecodableSignaturesAreBadPayload)
{
    const auto r = mainnet_v24();
    size_t bad = 0;
    for (const auto& f : kBlsSigFacts) {
        SCOPED_TRACE(f.what);
        const Code want = f.core_ok ? std::nullopt : C("bad-protx-payload");
        bad += !f.core_ok;
        auto a = make_upserv_v3();
        a.sig = arr<96>(f.bytes);
        EXPECT_EQ(refusal(a, r), want);
        auto b = make_rev_v3();
        b.sig = arr<96>(f.bytes);
        EXPECT_EQ(refusal(b, r), want);
    }
    EXPECT_GE(bad, 3u);
}

// The fold codec reads the structure only (no BLS math, byte-identical to
// master for v1/v2); GetTxPayload's signature rule lives in the rules and in
// decode_special_payload.
TEST(DashV24Bls, TheFoldCodecDoesNoBlsMath)
{
    auto a = make_upserv_v3();
    a.sig.fill(0xff);
    const auto b = v::serialize_special_payload(a);
    v::CProUpServTx q;
    EXPECT_TRUE(v::parse_protx_payload(b, q));
    EXPECT_FALSE(v::decode_special_payload(b, q));
    a.sig = {};
    EXPECT_TRUE(v::decode_special_payload(v::serialize_special_payload(a), q)) << "a null signature decodes";
}

#ifdef C2POOL_DASH_BLS
// The dashbls backend agrees with dashd on every fact.
TEST(DashV24Bls, BackendMatchesDashdOnEveryFact)
{
    ASSERT_TRUE(v::bls_backend_available());
    for (const auto& f : kBlsKeyFacts)
        EXPECT_EQ(v::bls_pubkey_core_valid(arr<48>(f.bytes), f.legacy), std::optional<bool>{f.core_ok}) << f.what;
    for (const auto& f : kBlsSigFacts)
        EXPECT_EQ(v::bls_sig_core_decodes(arr<96>(f.bytes), f.legacy), std::optional<bool>{f.core_ok}) << f.what;
}

// The generated signatures are the operator secret's over our sign hash.
TEST(DashV24Bls, GeneratedSignaturesVerifyAgainstTheirKeys)
{
    const auto hs = v::protx_operator_sign_hash(unhex(kSyn_proupserv));
    const auto hr = v::protx_operator_sign_hash(unhex(kSyn_prouprev));
    ASSERT_TRUE(hs && hr);
    EXPECT_TRUE(v::verify_protx_operator_sig(arr<48>(kOpKey_proupserv), false, *hs, arr<96>(kSig_proupserv), false));
    EXPECT_TRUE(v::verify_protx_operator_sig(arr<48>(kOpKey_prouprev), false, *hr, arr<96>(kSig_prouprev), false));
    EXPECT_FALSE(v::verify_protx_operator_sig(arr<48>(kOpKey_prouprev), false, *hs, arr<96>(kSig_proupserv), false));
}

// Production rules (no oracle) decide with the backend.
TEST(DashV24Bls, ProductionRulesUseTheBackend)
{
    auto r = ProviderTxRules::for_block(DashNetwork::MAINNET, 2'600'000);
    r.v24_active = true;
    EXPECT_EQ(refusal(make_upreg_v3(), r), std::nullopt);
    EXPECT_EQ(refusal(make_shared_reg(), r), std::nullopt);
    EXPECT_EQ(refusal(make_upserv_v3(), r), std::nullopt);
    EXPECT_EQ(refusal(make_rev_v3(), r), std::nullopt);
    EXPECT_EQ(refusal(make_upsharedreg(), r), std::nullopt);
    auto bad = make_upreg_v3();
    bad.pubKeyOperator = pat_arr<48>(0x82);
    EXPECT_EQ(refusal(bad, r), C("bad-protx-key-null"));
}
#else
// Without the backend the production rules refuse every payload whose BLS
// key or signature they cannot decide; only all-zero bytes need no math.
TEST(DashV24Bls, StubBuildRefusesWhatItCannotDecide)
{
    ASSERT_FALSE(v::bls_backend_available());
    auto r = ProviderTxRules::for_block(DashNetwork::MAINNET, 2'600'000);
    r.v24_active = true;
    const Code key = C("unverifiable-operator-key (no BLS backend in this build)");
    const Code sig = C("unverifiable-bls-signature (no BLS backend in this build)");
    EXPECT_EQ(refusal(make_upreg_v3(), r), key);
    EXPECT_EQ(refusal(make_shared_reg(), r), key);
    EXPECT_EQ(refusal(make_upsharedreg(), r), key);
    EXPECT_EQ(refusal(make_upserv_v3(), r), sig);
    EXPECT_EQ(refusal(make_rev_v3(), r), sig);
    auto z = make_upreg_v3();
    z.pubKeyOperator = {};
    EXPECT_EQ(refusal(z, r), C("bad-protx-key-null"));
    auto n = make_rev_v3();
    n.sig = {};
    EXPECT_EQ(refusal(n, r), std::nullopt);
    EXPECT_EQ(refusal(make_dis(false), r), std::nullopt) << "no BLS object";
}
#endif

TEST(DashV24Reject, PayloadAndVersionCodes)
{
    const auto r = mainnet_v24();
    Bytes b = v::serialize_special_payload(make_multipayout_reg());
    Bytes trunc(b.begin(), b.end() - 1), extra = b;
    extra.push_back(0);
    EXPECT_EQ(provider_payload_refusal(1, trunc, r), C("bad-protx-payload"));
    EXPECT_EQ(provider_payload_refusal(1, extra, r), C("bad-protx-payload"));
    EXPECT_EQ(provider_payload_refusal(1, {}, r), C("bad-protx-payload"));
    EXPECT_EQ(provider_payload_refusal(1, unhex("0400"), r), C("bad-protx-version"));
    EXPECT_EQ(provider_payload_refusal(4, unhex("0000"), r), C("bad-protx-version"));
    EXPECT_EQ(refusal(make_multipayout_reg(), mainnet_pre_v24()), C("bad-protx-version"));
    auto pre19 = r;
    pre19.v19_active = false;
    EXPECT_EQ(refusal(make_v2_evo_reg(), pre19), C("bad-protx-version")) << "GetMax(false, *) = 1";
    EXPECT_EQ(refusal(make_v1_reg(), r), C("bad-protx-version-disallowed"));
    auto dis = make_dis(false);
    dis.nVersion = 2;
    EXPECT_EQ(refusal(dis, r), C("bad-prodis-version"));
    dis.nVersion = 4;
    EXPECT_EQ(refusal(dis, r), C("bad-protx-version")) << "GetMax gate before IsTriviallyValid";
    auto sh = make_upshare();
    sh.nVersion = 0;
    EXPECT_EQ(refusal(sh, r), C("bad-proupshare-version"));
    auto sr = make_upsharedreg();
    sr.nVersion = 2;
    EXPECT_EQ(refusal(sr, r), C("bad-proupsharedreg-version"));
}

TEST(DashV24Reject, ProRegTxTrivialCodes)
{
    const auto r = mainnet_v24();
    auto pre = mainnet_pre_v24();
    struct Case { const char* code; std::function<void(v::CProRegTx&)> mutate; bool shared; };
    const int64_t COIN = v::CCollateralShare::COIN;
    const std::vector<Case> cases = {
        {"bad-protx-type",                [](auto& p) { p.nType = 2; }, false},
        {"bad-protx-mode",                [](auto& p) { p.nMode = 1; }, false},
        {"bad-protx-shares-external",     [](auto& p) { p.collateralOutpoint.hash = pat256(0x99); }, true},
        {"bad-protx-shares-owner-key",    [](auto& p) { p.keyIDOwner = pat160(0x99); }, true},
        {"bad-protx-shares-payouts",      [](auto& p) { p.payouts.push_back({}); }, true},
        {"bad-protx-shares-empty-fields", [](auto& p) { p.nEarlyPeriodBlocks = 1; }, false},
        {"bad-protx-key-null",            [](auto& p) { p.keyIDOwner = uint160{}; }, false},
        {"bad-protx-key-null",            [](auto& p) { p.pubKeyOperator = {}; }, false},
        {"bad-protx-key-null",            [](auto& p) { p.keyIDVoting = uint160{}; }, true},
        {"bad-protx-payouts-count",       [](auto& p) { p.payouts.clear(); }, false},
        {"bad-protx-payouts-count",       [](auto& p) {
            p.payouts.clear();
            for (uint8_t i = 0; i < 9; ++i) {
                v::MasternodePayoutShare s; s.scriptPayout = p2pkh(pat160(0xe0 + i)); s.reward = 1000;
                p.payouts.push_back(s);
            } }, false},
        {"bad-protx-payout-reward",       [](auto& p) { p.payouts[0].reward = 99; }, false},
        {"bad-protx-payout-reward",       [](auto& p) { p.payouts[0].reward = 10001; }, false},
        {"bad-protx-payee",               [](auto& p) { p.payouts[1].scriptPayout = script({0x6a}); }, false},
        {"bad-protx-payee-dup",           [](auto& p) { p.payouts[2].scriptPayout = p.payouts[0].scriptPayout; }, false},
        {"bad-protx-payee-reuse",         [](auto& p) { p.payouts[2].scriptPayout = p2pkh(p.keyIDOwner); }, false},
        {"bad-protx-payee-reuse",         [](auto& p) { p.payouts[2].scriptPayout = p2pkh(p.keyIDVoting); }, false},
        {"bad-protx-payout-reward-sum",   [](auto& p) { p.payouts[2].reward = 1000; }, false},
        {"bad-protx-shares-count",        [](auto& p) { p.shares.resize(1); p.vchJoinSigs.resize(1);
                                                        p.shares[0].amount = 1000 * v::CCollateralShare::COIN; }, true},
        {"bad-protx-shares-count",        [](auto& p) {
            p.shares.resize(9); p.vchJoinSigs.resize(9);
            for (uint8_t i = 0; i < 9; ++i) { p.shares[i].amount = 100 * v::CCollateralShare::COIN;
                p.shares[i].keyIDOwner = pat160(0xd0 + i); p.shares[i].scriptRefund = p2pkh(pat160(0xc0 + i)); }
            }, true},
        {"bad-protx-shares-amount",       [COIN](auto& p) { p.shares[2].amount = 99 * COIN; }, true},
        {"bad-protx-shares-amount",       [COIN](auto& p) { p.shares[2].amount = 1001 * COIN; }, true},
        {"bad-protx-shares-amount-sum",   [COIN](auto& p) { p.shares[2].amount = 200 * COIN; }, true},
        {"bad-protx-shares-early-period", [](auto& p) { p.nEarlyPeriodBlocks = 420481; }, true},
        {"bad-protx-shares-key-null",     [](auto& p) { p.shares[1].keyIDOwner = uint160{}; }, true},
        {"bad-protx-shares-dup-key",      [](auto& p) { p.shares[2].keyIDOwner = p.shares[0].keyIDOwner; }, true},
        {"bad-protx-shares-dup-refund",   [](auto& p) { p.shares[2].scriptRefund = p.shares[0].scriptRefund; }, true},
        {"bad-protx-shares-payee",        [](auto& p) { p.shares[0].scriptRefund = script({0x51}); }, true},
        {"bad-protx-shares-payee",        [](auto& p) { p.shares[0].scriptReward = script({0x51}); }, true},
        {"bad-protx-shares-payee-reuse",  [](auto& p) { p.shares[0].scriptRefund = p2pkh(p.keyIDVoting); }, true},
        {"bad-protx-shares-payee-reuse",  [](auto& p) { p.shares[1].scriptReward = p2pkh(p.shares[2].keyIDOwner); }, true},
        {"bad-protx-shares-penalty",      [](auto& p) { p.nEarlyPenalty = -1; }, true},
        {"bad-protx-shares-penalty",      [COIN](auto& p) { p.nEarlyPenalty = 250 * COIN; }, true},
        {"bad-protx-shares-penalty",      [](auto& p) { p.nEarlyPeriodBlocks = 0; }, true},
        {"bad-protx-netinfo-bad",         [](auto& p) { p.extNetInfo.set(1, {svc4(5, 6, 7, 8, 26656)}); }, false},
        {"bad-protx-netinfo-empty",       [](auto& p) { p.extNetInfo = ext({{1, {svc4(5, 6, 7, 8, 26656)}}}); }, false},
        {"bad-protx-operator-reward",     [](auto& p) { p.nOperatorReward = 10001; }, false},
    };
    for (const auto& c : cases) {
        auto p = c.shared ? make_shared_reg() : make_multipayout_reg();
        c.mutate(p);
        EXPECT_EQ(refusal(p, r), C(c.code)) << c.code;
    }
    // Version-dependent ProRegTx codes.
    auto evo1 = make_v2_evo_reg();
    evo1.nVersion = 1;
    EXPECT_EQ(refusal(evo1, pre), C("bad-protx-evo-version"));
    auto evo = make_evo_reg();
    evo.extNetInfo = ext({{0, {svc4(9, 9, 9, 9, 9999)}}, {1, {svc4(9, 9, 9, 9, 26656)}}});
    EXPECT_EQ(refusal(evo, r), C("bad-protx-netinfo-empty")) << "an EvoNode needs both Platform purposes";
    EXPECT_EQ(refusal(make_shared_evo(), r), C("bad-protx-shares-evo"));
    auto evo2 = make_evo_reg();
    evo2.payouts[0].reward = 5000;
    v::MasternodePayoutShare second;
    second.scriptPayout = p2sh(pat160(0x7f));
    second.reward = 5000;
    evo2.payouts.push_back(second);
    EXPECT_EQ(refusal(evo2, r), C("bad-protx-payouts-evo"));
}

TEST(DashV24Reject, NetworkFieldCodes)
{
    const auto r = mainnet_v24();
    auto reg = [](v::ExtNetInfo n) { auto p = make_multipayout_reg(); p.extNetInfo = std::move(n); return p; };
    auto evo = [](v::ExtNetInfo n) { auto p = make_evo_reg(); p.extNetInfo = std::move(n); return p; };
    const auto tor = v::NetInfoEntry{v::NetService::make(v::NetService::ONION, pat(32, 0x7a), 9999)};
    auto dom = [](const char* name, uint16_t port) { v::DomainPort d; d.addr = name; d.port = port; return v::NetInfoEntry{d}; };

    // Validate(): port, type, routability, malformed, input, duplicates, limit.
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9998)}}})), r), C("bad-protx-netinfo-port")) << "mainnet primary";
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9999), svc4(5, 6, 7, 9, 8333)}}})), r), C("bad-protx-netinfo-port"));
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9999), svc4(5, 6, 7, 9, 0)}}})), r), C("bad-protx-netinfo-port"));
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9999),
                                    v::NetInfoEntry{v::NetService::make(v::NetService::I2P, pat(32, 1), 1)}}}})), r),
              C("bad-protx-netinfo-port")) << "I2P must use port 0";
    {
        auto e = evo(make_evo_reg().extNetInfo);
        e.extNetInfo.set(2, {svc4(9, 9, 9, 9, 444)});
        EXPECT_EQ(refusal(e, r), C("bad-protx-netinfo-port")) << "mainnet HTTPS primary is 443";
    }
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(10, 0, 0, 1, 9999)}}})), r), C("bad-protx-netinfo-addr-unroutable"));
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(127, 0, 0, 1, 9999)}}})), r), C("bad-protx-netinfo-addr-unroutable"));
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9999), v::NetInfoEntry{}}}})), r), C("bad-protx-netinfo-bad"));
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9999)}}, {1, {}}})), r), C("bad-protx-netinfo-bad"))
        << "a purpose present with no entries (the regular-MN purpose rule only looks at non-empty lists)";
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9999), dom("node.dash.org", 9999)}}})), r),
              C("bad-protx-netinfo-entry")) << "domains only for Platform HTTPS";
    {
        auto e = evo(make_evo_reg().extNetInfo);
        e.extNetInfo.set(2, {svc4(9, 9, 9, 9, 443), dom("evo.dash.local", 443)});
        EXPECT_EQ(refusal(e, r), C("bad-protx-netinfo-entry")) << "reserved TLD";
        e.extNetInfo.set(2, {svc4(9, 9, 9, 9, 443), dom("evo.dash.123", 443)});
        EXPECT_EQ(refusal(e, r), C("bad-protx-netinfo-entry")) << "numeric TLD";
        e.extNetInfo.set(1, {svc4(9, 9, 9, 9, 9999)});
        EXPECT_EQ(refusal(e, r), C("bad-protx-dup-netinfo-entry")) << "same addr:port in two purposes";
    }
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 8, 9999), svc4(5, 6, 7, 8, 10000)}}})), r),
              C("bad-protx-dup-netinfo-entry")) << "same address twice in one purpose";
    EXPECT_EQ(refusal(reg(ext({{0, {svc4(5, 6, 7, 1, 9999), svc4(5, 6, 7, 2, 9999), svc4(5, 6, 7, 3, 9999),
                                    svc4(5, 6, 7, 4, 9999), svc4(5, 6, 7, 5, 9999)}}})), r),
              C("bad-protx-netinfo-maxlimit"));
    // CheckIPv4Primaries (mainnet only: ipv4_optional on testnet/devnet).
    const auto v6 = v::NetInfoEntry{v::NetService::make(v::NetService::IPV6, unhex("2a0104f8000000000000000000000001"), 9999)};
    EXPECT_EQ(refusal(reg(ext({{0, {v6}}})), r), C("bad-protx-netinfo-addr-type")) << "first core entry not IPv4";
    auto tn = rules_for(DashNetwork::TESTNET, 1'600'000);
    {
        auto p = reg(ext({{0, {v::NetInfoEntry{v::NetService::make(v::NetService::IPV6, unhex("2a0104f8000000000000000000000001"), 19999)}}}}));
        EXPECT_EQ(refusal(p, tn), std::nullopt) << "IPv4 primaries are optional on testnet";
    }
    {
        auto e = evo(make_evo_reg().extNetInfo);
        e.extNetInfo.set(1, {v::NetInfoEntry{v::NetService::make(v::NetService::ONION, pat(32, 0x55), 26656)}});
        EXPECT_EQ(refusal(e, r), C("bad-protx-netinfo-addr-type")) << "first Platform entry not IPv4";
        e.extNetInfo.set(1, {svc4(9, 9, 9, 8, 26656)});
        EXPECT_EQ(refusal(e, r), C("bad-protx-netinfo-addr")) << "Platform primary on another address";
    }
    (void)tor;
    // Platform scalar fields and node id.
    {
        auto e = make_evo_reg();
        e.platformNodeID = uint160{};
        EXPECT_EQ(refusal(e, r), C("bad-protx-platform-nodeid"));
        auto l = make_v2_evo_reg();
        l.platformP2PPort = 26657;
        EXPECT_EQ(refusal(l, mainnet_pre_v24()), C("bad-protx-platform-p2p-port"));
        l = make_v2_evo_reg();
        l.platformHTTPPort = 8080;
        EXPECT_EQ(refusal(l, mainnet_pre_v24()), C("bad-protx-platform-http-port"));
        auto t = make_v2_evo_reg();
        t.netInfo.port_be = 19999;
        t.platformP2PPort = 22000;
        t.platformHTTPPort = 22000;
        EXPECT_EQ(refusal(t, rules_for(DashNetwork::TESTNET, 1'500'000)),
                  C("bad-protx-platform-dup-ports"));
    }
    // MnNetInfo (v1/v2) rules.
    {
        auto p = make_v1_reg();
        p.netInfo.port_be = 19999;
        EXPECT_EQ(refusal(p, mainnet_pre_v24()), C("bad-protx-netinfo-port")) << "mainnet must use 9999";
        auto q = make_v1_reg();
        EXPECT_EQ(refusal(q, rules_for(DashNetwork::TESTNET, 1'500'000)),
                  C("bad-protx-netinfo-port")) << "other networks must NOT use 9999";
        auto s6 = make_v1_reg();
        s6.netInfo.ip = {0x2a, 0x01, 0x04, 0xf8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        EXPECT_EQ(refusal(s6, mainnet_pre_v24()), C("bad-protx-netinfo-addr-type")) << "MnNetInfo is IPv4 only";
    }
    // ProUpServTx: an empty netInfo is never allowed; a null netInfo is a version error.
    {
        auto s = make_upserv_v3();
        s.extNetInfo = v::ExtNetInfo{};
        EXPECT_EQ(refusal(s, r), C("bad-protx-netinfo-empty"));
        EXPECT_EQ(v::check_provider_network_fields(v::NetInfoRef{}, 0, 3, nullptr, 0, 0, true, false,
                                                   v::NetInfoRules::mainnet()),
                  C("bad-protx-netinfo-version"));
        v::LegacyNetService l;
        EXPECT_EQ(v::check_provider_network_fields(v::NetInfoRef{&l, nullptr}, 0, 3, nullptr, 0, 0, true, false,
                                                   v::NetInfoRules::mainnet()),
                  C("bad-protx-netinfo-version")) << "legacy netInfo on a v3 payload";
    }
    // Regtest does not require routable addresses.
    {
        auto rt = rules_for(DashNetwork::REGTEST, 1000);
        rt.v24_active = true;
        auto p = reg(ext({{0, {svc4(10, 0, 0, 1, 19899)}}}));
        EXPECT_EQ(refusal(p, rt), std::nullopt);
    }
}

TEST(DashV24Reject, UpdateAndNewTypeCodes)
{
    const auto r = mainnet_v24();
    auto ur = make_upreg_v3();
    ur.nMode = 1;
    EXPECT_EQ(refusal(ur, r), C("bad-protx-mode"));
    ur = make_upreg_v3();
    ur.keyIDVoting = uint160{};
    EXPECT_EQ(refusal(ur, r), C("bad-protx-key-null"));
    ur = make_upreg_v3();
    ur.payouts.clear();
    EXPECT_EQ(refusal(ur, r), C("bad-protx-payouts-count"));

    auto us = make_upserv_v3();
    us.nType = 2;
    EXPECT_EQ(refusal(us, r), C("bad-protx-type"));
    auto us1 = make_upserv_v3();
    us1.nVersion = 1;
    us1.nType = v::MnType::EVO;
    us1.netInfo = make_v1_reg().netInfo;
    // A v1 payload never carries nType on the wire, so an EvoNode v1 update
    // cannot be expressed; the check is reachable for in-memory objects only.
    EXPECT_EQ(dash::coin::trivial_refusal(us1), C("bad-protx-evo-version"));
    auto evo_v2 = make_upserv_v3();
    evo_v2.nVersion = 2;
    evo_v2.nType = v::MnType::EVO;
    EXPECT_EQ(dash::coin::proupserv_post_state_refusal(evo_v2, r), C("bad-protx-version-disallowed"));
    EXPECT_EQ(dash::coin::proupserv_post_state_refusal(make_upserv_v3(), r), std::nullopt);

    auto rev = make_rev_v3();
    rev.nReason = 4;
    EXPECT_EQ(refusal(rev, r), C("bad-protx-reason"));

    auto dis = make_dis(false);
    dis.vchSigs.clear();
    EXPECT_EQ(refusal(dis, r), C("bad-prodis-sig-count"));
    dis.vchSigs.resize(9);
    EXPECT_EQ(refusal(dis, r), C("bad-prodis-sig-count"));

    auto sh = make_upshare();
    sh.vchSig.pop_back();
    EXPECT_EQ(refusal(sh, r), C("bad-proupshare-sig-size"));
    sh = make_upshare();
    sh.scriptReward = script({0x6a, 0x01, 0x00});
    EXPECT_EQ(refusal(sh, r), C("bad-proupshare-payee"));

    auto sr = make_upsharedreg();
    sr.pubKeyOperator = {};
    EXPECT_EQ(refusal(sr, r), C("bad-protx-key-null"));
    sr = make_upsharedreg();
    sr.vchSigs.clear();
    EXPECT_EQ(refusal(sr, r), C("bad-proupsharedreg-sig-count"));
    sr.vchSigs.resize(9);
    EXPECT_EQ(refusal(sr, r), C("bad-proupsharedreg-sig-count"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Golden: mainnet before activation is byte-identical to master (a66754bb9)
// ═══════════════════════════════════════════════════════════════════════════

namespace master_codec {
// Verbatim serialization bodies of the pre-v24 vendored codecs (master
// a66754bb9 src/impl/dash/coin/vendor/{providertx,simplifiedmns}.hpp): every
// version read with the v1/v2 layout, no version bail-out.
using v::LegacyNetService;
using v::RawBytesFormat;
using v::BLS_PUBKEY_SIZE;
using v::BLS_SIG_SIZE;

struct CProRegTx {
    uint16_t nVersion{2}; uint16_t nType{0}; uint16_t nMode{0};
    bitcoin_family::coin::TxPrevOut collateralOutpoint; LegacyNetService netInfo;
    uint160 keyIDOwner; std::array<uint8_t, BLS_PUBKEY_SIZE> pubKeyOperator{}; uint160 keyIDVoting;
    uint16_t nOperatorReward{0}; OPScript scriptPayout; uint256 inputsHash; std::vector<uint8_t> vchSig;
    uint160 platformNodeID; uint16_t platformP2PPort{0}; uint16_t platformHTTPPort{0};
    C2POOL_SERIALIZE_METHODS(CProRegTx)
    {
        READWRITE(obj.nVersion);
        READWRITE(obj.nType, obj.nMode, obj.collateralOutpoint, obj.netInfo, obj.keyIDOwner,
                  Using<RawBytesFormat<BLS_PUBKEY_SIZE>>(obj.pubKeyOperator), obj.keyIDVoting,
                  obj.nOperatorReward, obj.scriptPayout, obj.inputsHash);
        if (obj.nType == 1) {
            READWRITE(obj.platformNodeID);
            if (obj.nVersion < 3) READWRITE(obj.platformP2PPort, obj.platformHTTPPort);
        }
        READWRITE(obj.vchSig);
    }
};
struct CProUpServTx {
    uint16_t nVersion{2}; uint16_t nType{0}; uint256 proTxHash; LegacyNetService netInfo;
    OPScript scriptOperatorPayout; uint256 inputsHash; std::array<uint8_t, BLS_SIG_SIZE> sig{};
    uint160 platformNodeID; uint16_t platformP2PPort{0}; uint16_t platformHTTPPort{0};
    C2POOL_SERIALIZE_METHODS(CProUpServTx)
    {
        READWRITE(obj.nVersion);
        if (obj.nVersion >= 2) READWRITE(obj.nType);
        READWRITE(obj.proTxHash, obj.netInfo, obj.scriptOperatorPayout, obj.inputsHash);
        if (obj.nType == 1) {
            READWRITE(obj.platformNodeID);
            if (obj.nVersion < 3) READWRITE(obj.platformP2PPort, obj.platformHTTPPort);
        }
        READWRITE(Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.sig));
    }
};
struct CProUpRegTx {
    uint16_t nVersion{2}; uint256 proTxHash; uint16_t nMode{0};
    std::array<uint8_t, BLS_PUBKEY_SIZE> pubKeyOperator{}; uint160 keyIDVoting; OPScript scriptPayout;
    uint256 inputsHash; std::vector<uint8_t> vchSig;
    C2POOL_SERIALIZE_METHODS(CProUpRegTx)
    {
        READWRITE(obj.nVersion, obj.proTxHash, obj.nMode,
                  Using<RawBytesFormat<BLS_PUBKEY_SIZE>>(obj.pubKeyOperator), obj.keyIDVoting,
                  obj.scriptPayout, obj.inputsHash, obj.vchSig);
    }
};
struct CProUpRevTx {
    uint16_t nVersion{2}; uint256 proTxHash; uint16_t nReason{0}; uint256 inputsHash;
    std::array<uint8_t, BLS_SIG_SIZE> sig{};
    C2POOL_SERIALIZE_METHODS(CProUpRevTx)
    {
        READWRITE(obj.nVersion, obj.proTxHash, obj.nReason, obj.inputsHash,
                  Using<RawBytesFormat<BLS_SIG_SIZE>>(obj.sig));
    }
};
template <typename T>
bool parse(const Bytes& payload, T& out)
{
    if (payload.empty()) return false;
    try { ::PackStream s(payload); s >> out; return s.empty(); } catch (const std::exception&) { return false; }
}
/// master CSimplifiedMNListEntry::CalcHash over a decoded entry (legacy netInfo always).
uint256 sml_leaf_hash(const v::CSimplifiedMNListEntry& e)
{
    ::PackStream s;
    s << e.proRegTxHash << e.confirmedHash;
    s.write(std::as_bytes(std::span{e.netAddress}));
    const uint8_t pb[2] = {static_cast<uint8_t>(e.netPort >> 8), static_cast<uint8_t>(e.netPort & 0xff)};
    s.write(std::as_bytes(std::span{pb}));
    s.write(std::as_bytes(std::span{e.pubKeyOperator}));
    s << e.keyIDVoting << e.isValid;
    if (e.nVersion >= 2) {
        s << e.nType;
        if (e.nType == 1) {
            if (e.nVersion < 3) s << e.platformHTTPPort;
            s << e.platformNodeID;
        }
    }
    auto sp = s.get_span();
    return sha256d(Bytes(reinterpret_cast<const uint8_t*>(sp.data()),
                         reinterpret_cast<const uint8_t*>(sp.data()) + sp.size()));
}
} // namespace master_codec

namespace {

struct Rng {
    std::mt19937_64 g{0x5d24'0002'c2c0'00ffULL};
    uint8_t byte() { return static_cast<uint8_t>(g()); }
    uint16_t u16() { return static_cast<uint16_t>(g()); }
    template <size_t N> std::array<uint8_t, N> arr() { std::array<uint8_t, N> a{}; for (auto& b : a) b = byte(); return a; }
    uint160 h160() { uint160 h; for (size_t i = 0; i < 20; ++i) h.data()[i] = byte(); return h; }
    uint256 h256() { uint256 h; for (size_t i = 0; i < 32; ++i) h.data()[i] = byte(); return h; }
    Bytes bytes(size_t max) { Bytes b(g() % (max + 1)); for (auto& x : b) x = byte(); return b; }
    v::LegacyNetService net() { v::LegacyNetService n; n.ip = arr<16>(); n.port_be = u16(); return n; }
};

/// The four master codecs vs the new ones on one byte string: same verdict,
/// and for an accepted payload the same fields and the same re-encoding.
struct Agreement { size_t accepted{0}, rejected{0}; };

void agree(uint16_t type, const Bytes& b, Agreement& a)
{
    auto check = [&](auto& m, auto& n, auto&& same_fields) {
        const bool mo = master_codec::parse(b, m);
        const bool no = v::parse_protx_payload(b, n);
        ASSERT_EQ(mo, no) << "type " << type << " bytes " << hex(b);
        if (!mo) { ++a.rejected; return; }
        ++a.accepted;
        EXPECT_TRUE(same_fields(m, n)) << "type " << type << " bytes " << hex(b);
        EXPECT_EQ(pack_bytes(m), b);
        EXPECT_EQ(v::serialize_special_payload(n), b);
    };
    switch (type) {
    case 1: { master_codec::CProRegTx m; v::CProRegTx n;
        check(m, n, [](const auto& x, const auto& y) {
            return x.nVersion == y.nVersion && x.nType == y.nType && x.nMode == y.nMode
                && x.collateralOutpoint.hash == y.collateralOutpoint.hash
                && x.collateralOutpoint.index == y.collateralOutpoint.index && x.netInfo == y.netInfo
                && x.keyIDOwner == y.keyIDOwner && x.pubKeyOperator == y.pubKeyOperator
                && x.keyIDVoting == y.keyIDVoting && x.nOperatorReward == y.nOperatorReward
                && x.scriptPayout == y.scriptPayout && x.inputsHash == y.inputsHash && x.vchSig == y.vchSig
                && x.platformNodeID == y.platformNodeID && x.platformP2PPort == y.platformP2PPort
                && x.platformHTTPPort == y.platformHTTPPort; });
        break; }
    case 2: { master_codec::CProUpServTx m; v::CProUpServTx n;
        check(m, n, [](const auto& x, const auto& y) {
            return x.nVersion == y.nVersion && x.nType == y.nType && x.proTxHash == y.proTxHash
                && x.netInfo == y.netInfo && x.scriptOperatorPayout == y.scriptOperatorPayout
                && x.inputsHash == y.inputsHash && x.sig == y.sig && x.platformNodeID == y.platformNodeID
                && x.platformP2PPort == y.platformP2PPort && x.platformHTTPPort == y.platformHTTPPort; });
        break; }
    case 3: { master_codec::CProUpRegTx m; v::CProUpRegTx n;
        check(m, n, [](const auto& x, const auto& y) {
            return x.nVersion == y.nVersion && x.proTxHash == y.proTxHash && x.nMode == y.nMode
                && x.pubKeyOperator == y.pubKeyOperator && x.keyIDVoting == y.keyIDVoting
                && x.scriptPayout == y.scriptPayout && x.inputsHash == y.inputsHash && x.vchSig == y.vchSig; });
        break; }
    case 4: { master_codec::CProUpRevTx m; v::CProUpRevTx n;
        check(m, n, [](const auto& x, const auto& y) {
            return x.nVersion == y.nVersion && x.proTxHash == y.proTxHash && x.nReason == y.nReason
                && x.inputsHash == y.inputsHash && x.sig == y.sig; });
        break; }
    }
}

Bytes random_master_payload(uint16_t type, uint16_t version, Rng& r)
{
    switch (type) {
    case 1: { master_codec::CProRegTx p; p.nVersion = version; p.nType = r.byte() & 1; p.nMode = r.u16() % 2;
        p.collateralOutpoint.hash = r.h256(); p.collateralOutpoint.index = static_cast<uint32_t>(r.g());
        p.netInfo = r.net(); p.keyIDOwner = r.h160(); p.pubKeyOperator = r.arr<48>(); p.keyIDVoting = r.h160();
        p.nOperatorReward = r.u16(); p.scriptPayout.m_data = r.bytes(40); p.inputsHash = r.h256();
        p.vchSig = r.bytes(80);
        if (p.nType == 1) { p.platformNodeID = r.h160(); p.platformP2PPort = r.u16(); p.platformHTTPPort = r.u16(); }
        return pack_bytes(p); }
    case 2: { master_codec::CProUpServTx p; p.nVersion = version; p.nType = version >= 2 ? (r.byte() & 1) : 0;
        p.proTxHash = r.h256(); p.netInfo = r.net(); p.scriptOperatorPayout.m_data = r.bytes(40);
        p.inputsHash = r.h256(); p.sig = r.arr<96>();
        if (p.nType == 1) { p.platformNodeID = r.h160(); p.platformP2PPort = r.u16(); p.platformHTTPPort = r.u16(); }
        return pack_bytes(p); }
    case 3: { master_codec::CProUpRegTx p; p.nVersion = version; p.proTxHash = r.h256(); p.nMode = r.u16() % 2;
        p.pubKeyOperator = r.arr<48>(); p.keyIDVoting = r.h160(); p.scriptPayout.m_data = r.bytes(40);
        p.inputsHash = r.h256(); p.vchSig = r.bytes(80);
        return pack_bytes(p); }
    default: { master_codec::CProUpRevTx p; p.nVersion = version; p.proTxHash = r.h256(); p.nReason = r.u16();
        p.inputsHash = r.h256(); p.sig = r.arr<96>();
        return pack_bytes(p); }
    }
}

} // namespace

TEST(DashV24Golden, RealMainnetV2ProUpServTxDecodeIdenticallyToMaster)
{
    // test_dash_protx_sig_bls.cpp kVectors: two mined mainnet ProUpServTx v2
    // (2,555,756 regular; 2,561,949 EvoNode), Dash Core 23.1.7 archival node.
    const char* raws[] = {
        "0300020001eb08ccbdc43d4ca93696eb8685a4dd2505a94c69cdd164a92ca5fb7330015508000000006a473044022012f3185adcc699d2dbe4039db6e64d5913ffbf190580e85b9dbc7aff8247356c02201d8db0ba520034137cd56d2c4c475c9d24afc2f762a5aaf3a2265c48d1776d370121035ffbab73725c430b2904c10563007c5047257aae6caefcda4b47ed70c03b2f6efeffffff01286e7000000000001976a914b734da3d63094c95589fcf9252cd8d9c46eebafa88ac00000000b70200000009c40d4664fa991af5c89e9d5322f7137204c55f5bb8464a1f7d9f60dd46a11f00000000000000000000ffff5fd835c1270f00482f3ea24239aa948b99e100553cbd9b43e93a2d1532b3406c98f3100c4399178ccc794803d0efac7b301eb377c8ef9f8e15f1ecc9723b074ae27404dfcde2889c809e08705ebe2bb98ef564f3a0a45c0abcd94e01867bb54d71d4a81f84785a7ec13340c724d0e0a360121485e0cde3c4a339eb5afc75847be14d13b7b84370",
        "030002000102e0315717164e0ab9333d10ff4cbb108f7702531eabbc8fd3e5caf593262ebd0a0000006a473044022019acbf538e8fee546a28a62f8b44a8ae2c1c78778069ed32f8326fb42645c2590220717f53e4a37d557dd64bc057a2c96bc8f9903df38ca80be47f452827b5e2ad660121038fe4e6ce652bd57dc0a9061d7e516b85750f0372c29b5b9064170b3a0d010c17feffffff0108850100000000001976a914e7ea00a9693de82bf24bcf0a2760c59994fd134188ac00000000cf020001000c3b617d6c3cc7086840b700d6496d60edc5bf0599af45bea2e4ca90a8b094c000000000000000000000ffff54f7b4c6270f00b8084100a353bc9d0fa63ba3c5bdb9461965126495edc724dae2a647708ef1d3bc3b17ac533e74321ead59434f9bfddd5a4196012068bb01ad7681f826f14056887b4261c15d8924fd4c99b8a43c14d1f7e7ecfef1eb60a53d54e7b2a99100631a858c8f295dbdcb041c87e7f5247f61ab42897bc35eab182cb3da0646b3b2a9974be13f1bdcf658f1ca9affc3c95b458f901a0a7e6b6069",
    };
    const char* txids[] = {"415dc3539c6836583497879301d491d204dde68caf692dfbca46e69e2badd6ad",
                           "3e090864ef14260d12d7b4fa37cadd8ac9cd0f45721536ae0d426403f8ef6ab2"};
    Agreement a;
    for (size_t i = 0; i < 2; ++i) {
        const Bytes raw = unhex(raws[i]);
        const auto tx = parse_tx(raw);
        EXPECT_EQ(sha256d(raw).GetHex(), txids[i]);
        EXPECT_EQ(pack_bytes(tx), raw);
        const Bytes payload(tx.extra_payload.begin(), tx.extra_payload.end());
        agree(2, payload, a);
        std::array<uint8_t, 96> sig{};
        std::copy(payload.end() - 96, payload.end(), sig.begin());
        mined_sigs().push_back(sig);   // mined on mainnet: Core decoded it
        // And the full mainnet payload-only checks accept them before v24.
        EXPECT_EQ(provider_payload_refusal(2, payload, mainnet_pre_v24()), std::nullopt);
    }
    EXPECT_EQ(a.accepted, 2u);
}

TEST(DashV24Golden, SeededV1V2CorpusAgreesWithMaster)
{
    Rng r;
    Agreement a;
    size_t master_only = 0;
    for (int iter = 0; iter < 400; ++iter) {
        for (uint16_t type = 1; type <= 4; ++type) {
            for (uint16_t version : {uint16_t{1}, uint16_t{2}}) {
                const Bytes b = random_master_payload(type, version, r);
                agree(type, b, a);                              // the payload itself
                Bytes t(b.begin(), b.end() - 1 - (r.g() % std::min<size_t>(b.size() - 1, 40)));
                agree(type, t, a);                              // truncated
                Bytes x = b;
                x.push_back(r.byte());
                agree(type, x, a);                              // one trailing byte
            }
            // Unknown versions: master read them with the v2 layout; the new
            // parse refuses them (fail closed). This is the one intended
            // difference, and no block dashd accepts can carry such a payload.
            for (uint16_t version : {uint16_t{0}, uint16_t{4}, uint16_t{0xffff}}) {
                const Bytes b = random_master_payload(type, version, r);
                bool mo = false;
                switch (type) {
                case 1: { master_codec::CProRegTx m; mo = master_codec::parse(b, m); break; }
                case 2: { master_codec::CProUpServTx m; mo = master_codec::parse(b, m); break; }
                case 3: { master_codec::CProUpRegTx m; mo = master_codec::parse(b, m); break; }
                default: { master_codec::CProUpRevTx m; mo = master_codec::parse(b, m); break; }
                }
                master_only += mo ? 1 : 0;
                v::CProRegTx n1; v::CProUpServTx n2; v::CProUpRegTx n3; v::CProUpRevTx n4;
                const bool no = type == 1 ? v::parse_protx_payload(b, n1)
                              : type == 2 ? v::parse_protx_payload(b, n2)
                              : type == 3 ? v::parse_protx_payload(b, n3)
                                          : v::parse_protx_payload(b, n4);
                EXPECT_FALSE(no) << "type " << type << " version " << version;
            }
        }
    }
    EXPECT_EQ(a.accepted, 400u * 4 * 2) << "every well-formed v1/v2 payload";
    EXPECT_EQ(a.rejected, 400u * 4 * 2 * 2) << "every truncation and extension, by both";
    EXPECT_EQ(master_only, 400u * 4 * 3) << "master accepted every unknown-version payload";
}

TEST(DashV24Golden, RealTestnetMnListDiffsReencodeWithMasterLeafHashes)
{
    // The full snapshot (base = genesis, ~375 entries) and an incremental
    // diff (1518667 -> 1518669, which changes no entry).
    struct Capture { const char* name; bool full; };
    for (const auto& c : {Capture{"/dash_testnet_mnlistdiff_1518412.bin", true},
                          Capture{"/dash_testnet_mnlistdiff_incremental_1518669.bin", false}}) {
        SCOPED_TRACE(c.name);
        std::ifstream f(std::string(DASH_FIXTURE_DIR) + c.name, std::ios::binary);
        ASSERT_TRUE(f.good());
        const Bytes wire((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        ::PackStream ps(wire);
        v::CSimplifiedMNListDiff diff;
        ps >> diff;
        EXPECT_EQ(pack_bytes(diff), wire) << "byte-exact re-encoding";
        if (c.full) ASSERT_GT(diff.mnList.size(), 300u);
        for (const auto& e : diff.mnList) {
            ASSERT_LT(e.nVersion, 3) << "a pre-v24 capture";
            EXPECT_EQ(e.CalcHash(), master_codec::sml_leaf_hash(e));
            EXPECT_TRUE(e.extNetInfo.IsEmpty());
        }
    }
}
