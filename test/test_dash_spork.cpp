// SPDX-License-Identifier: AGPL-3.0-or-later
/// DASH SPORK LISTENER — registry-membership gate + verification + state KATs
/// (spork.hpp + the p2p_client spork handler).
///
/// THE REGISTRY GATE COMES FIRST (the qrinfo #1077 lesson, verbatim): a
/// handler that exists but whose message type is absent from the p2p::Handler
/// type list can never run — MessageHandler::parse() throws std::out_of_range
/// and the payload dies on the unhandled-command path at DEBUG. Every spork
/// dashd pushed at us died exactly there, silently, until this branch. So the
/// first KAT starts at the RAW BYTES the way a peer delivers them and pins
/// registry membership directly.
///
/// VERIFIED TO FAIL ON THE PRE-FIX TREE: with message_spork removed from the
/// p2p::Handler list (master as of this branch point), HandlerRegistry
/// DispatchesSpork REDs with out_of_range thrown from parse(), and the
/// end-to-end rig KATs RED with zero listener refinement.
///
/// The rest pins, in dependency order:
///   * the two dashd signature digests byte-exact (pinned known answers);
///   * compact-sig recovery against a key ID (synthetic signer — accept,
///     tamper-reject, wrong-key-reject, legacy-fallback, compressed and
///     uncompressed header flags);
///   * SporkState: the assume-active mainnet seed (a spork-blind node holds
///     dashd's own hardened 7/7-active answer), listener refinement, the
///     staleness rule, and that a bad signature NEVER touches state;
///   * the client end-to-end: handshake sends getsporks, a signed spork
///     refines the map, a garbage spork is dropped without costing the peer
///     (the registered-but-unparseable hazard), state + counters readable.
///
/// This TU compiles into the EXISTING allowlisted test_dash_p2p_node target
/// (no new test target, no workflow edit — the #769 rule).

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_client.hpp>
#include <impl/dash/coin/spork.hpp>
#include <impl/dash/config.hpp>

#include <core/hash.hpp>
#include <core/netaddress.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>   // ParseHexBytes (wire-magic bytes)

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <boost/asio.hpp>

#include <array>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using dash::coin::MAINNET_SPORK_PUBKEY_ID;
using dash::coin::SporkIngest;
using dash::coin::SporkState;
using dash::coin::mainnet_spork_defaults;
using dash::coin::spork_legacy_message_hash;
using dash::coin::spork_name;
using dash::coin::spork_signature_hash;
using dash::coin::verify_spork_signature;
using dash::coin::p2p::CoinClient;

namespace p2p = dash::coin::p2p;

namespace {

// ── synthetic signer (KATs cannot hold the real spork key) ────────────────

const unsigned char kTestSeckey[32] = {
    0x1e, 0x99, 0x42, 0x3a, 0x4e, 0xd2, 0x76, 0x08,
    0xa1, 0x5a, 0x26, 0x16, 0xa2, 0xb0, 0xe9, 0xe5,
    0x2c, 0xed, 0x33, 0x0a, 0xc5, 0x30, 0xed, 0xcc,
    0x32, 0xc8, 0xff, 0xc6, 0xa5, 0x26, 0xae, 0xdd,
};

struct SignCtx
{
    secp256k1_context* ctx;
    SignCtx() : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN)) {}
    ~SignCtx() { secp256k1_context_destroy(ctx); }
};

std::array<uint8_t, 20> keyid_of(const unsigned char* seckey, bool compressed)
{
    SignCtx s;
    secp256k1_pubkey pubkey;
    EXPECT_EQ(secp256k1_ec_pubkey_create(s.ctx, &pubkey, seckey), 1);
    unsigned char pub[65];
    size_t publen = sizeof(pub);
    secp256k1_ec_pubkey_serialize(s.ctx, pub, &publen, &pubkey,
        compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    uint160 h;
    CHash160().Write(std::span<const unsigned char>(pub, publen))
              .Finalize(std::span<unsigned char>(h.data(), 20));
    std::array<uint8_t, 20> out{};
    std::memcpy(out.data(), h.data(), 20);
    return out;
}

/// dashd CHashSigner::SignHash shape: 65-byte compact sig, header byte
/// 27 + recid (+4 when the key ID is of the COMPRESSED serialization).
std::vector<uint8_t> sign_compact(const unsigned char* seckey, const uint256& hash,
                                  bool compressed)
{
    SignCtx s;
    secp256k1_ecdsa_recoverable_signature rsig;
    EXPECT_EQ(secp256k1_ecdsa_sign_recoverable(
        s.ctx, &rsig, hash.data(), seckey, nullptr, nullptr), 1);
    unsigned char sig64[64];
    int recid = 0;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(s.ctx, sig64, &recid, &rsig);
    std::vector<uint8_t> out(65);
    out[0] = static_cast<uint8_t>(27 + recid + (compressed ? 4 : 0));
    std::memcpy(out.data() + 1, sig64, 64);
    return out;
}

// ── minimal client rig (same shape as the PoolRig in the sibling TUs) ─────

struct SporkRig
{
    boost::asio::io_context ioc;
    dash::interfaces::Node coin_state;
    dash::Config config;
    CoinClient<dash::Config> client;

    SporkRig()
        : config("dash-spork-kat")
        , client(&ioc, &coin_state, &config, "COIN-P2P-SPORK-KAT")
    {
        config.coin()->m_p2p.prefix = ParseHexBytes("cee2caff");
    }

    static NetService peer_addr(int n)
    {
        return NetService{"192.0.2." + std::to_string(n), 19999};
    }
    static std::string peer_key(int n) { return peer_addr(n).to_string(); }

    void deliver(int n, std::unique_ptr<RawMessage> rmsg)
    {
        client.handle(std::move(rmsg), peer_addr(n));
    }

    void handshake(int n, uint32_t height = 1000)
    {
        client.attach_peer_for_test(peer_addr(n));
        deliver(n, p2p::message_version::make_raw(
            70230, /*services=*/1, /*timestamp=*/1234567890ull,
            addr_t{1, NetService{"127.0.0.1", 19999}},
            addr_t{1, NetService{"127.0.0.1", 19999}},
            /*nonce=*/0x1122334455667788ull, "/Dash Core:21.1.0/", height));
        deliver(n, p2p::message_verack::make_raw());
    }
};

// A "now" comfortably past every hardened mainnet spork value (0 / 1).
constexpr int64_t kNow = 1'700'000'000;

} // namespace

// ══════════════════════════════════════════════════════════════════════════
// (1) REGISTRY MEMBERSHIP — the #1077 gate. Raw bytes, the way a peer
// delivers them, through the REAL p2p::Handler.
// ══════════════════════════════════════════════════════════════════════════

TEST(DashSpork, HandlerRegistryDispatchesSpork)
{
    // Pack a syntactically valid spork through the codec's own writer, then
    // hand it to the registry as a RawMessage. On the pre-fix tree parse()
    // throws std::out_of_range here ("spork" not in MessageHandler) and the
    // message dies exactly the way every real spork died in production.
    auto raw = p2p::message_spork::make_raw(
        dash::coin::SPORK_19_CHAINLOCKS_ENABLED, /*value=*/0,
        /*time_signed=*/kNow, std::vector<uint8_t>(65, 0));

    p2p::Handler handler;
    p2p::Handler::result_t result;
    ASSERT_NO_THROW(result = handler.parse(raw))
        << "message_spork is not registered in the p2p::Handler type list — "
           "every spork a peer sends is silently dropped (#1077 class)";

    auto* parsed = std::get_if<std::unique_ptr<p2p::message_spork>>(&result);
    ASSERT_NE(parsed, nullptr) << "spork payload dispatched to the wrong type";
    EXPECT_EQ((*parsed)->m_spork_id, dash::coin::SPORK_19_CHAINLOCKS_ENABLED);
    EXPECT_EQ((*parsed)->m_value, 0);
    EXPECT_EQ((*parsed)->m_time_signed, kNow);
    EXPECT_EQ((*parsed)->m_sig.size(), 65u);
}

TEST(DashSpork, HandlerRegistryDispatchesGetSporks)
{
    // The empty-payload request must also be registered: a masternode-syncing
    // peer sends it to US, and unregistered it would be one more permanent
    // WARNING per peer for a message we intentionally do not serve.
    auto raw = p2p::message_getsporks::make_raw();
    p2p::Handler handler;
    ASSERT_NO_THROW(handler.parse(raw));
}

// ══════════════════════════════════════════════════════════════════════════
// (2) SIGNATURE DIGESTS — byte-exact against dashd CSporkMessage
// ══════════════════════════════════════════════════════════════════════════

TEST(DashSpork, NewSigDigestPinned)
{
    // dashd GetSignatureHash: dsha256 of nSporkID(i32 LE)+nValue(i64 LE)+
    // nTimeSigned(i64 LE). Pinned known answer (independently computed).
    EXPECT_EQ(spork_signature_hash(10001, 0, 1'700'000'000).GetHex(),
              "d0dcde35d697efbf2f4674cc7689359c1ce710adc3d22bc90dbb193a7d4d1340");
}

TEST(DashSpork, LegacyMessageDigestPinned)
{
    // dashd CMessageSigner fallback: dsha256 of varstr("DarkCoin Signed
    // Message:\n") + varstr("1000101700000000"). Pinned known answer.
    EXPECT_EQ(spork_legacy_message_hash(10001, 0, 1'700'000'000).GetHex(),
              "a23b874364ba48b12a725c129a5ac58909b166f6f118a7da17d2a6b6d64c77f4");
}

TEST(DashSpork, MainnetSporkKeyIdMatchesChainparamsAddress)
{
    // Independent derivation of the hardcoded key ID from the chainparams
    // spork address "Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh": base58check payload
    // 4c441c7d2b023ccb805c02f627937206ba9fe0365a (version 0x4C + HASH160).
    const std::array<uint8_t, 20> expected = {
        0x44, 0x1c, 0x7d, 0x2b, 0x02, 0x3c, 0xcb, 0x80, 0x5c, 0x02,
        0xf6, 0x27, 0x93, 0x72, 0x06, 0xba, 0x9f, 0xe0, 0x36, 0x5a};
    EXPECT_EQ(MAINNET_SPORK_PUBKEY_ID, expected);
}

// ══════════════════════════════════════════════════════════════════════════
// (3) COMPACT-SIG RECOVERY vs a key ID (synthetic signer)
// ══════════════════════════════════════════════════════════════════════════

TEST(DashSpork, VerifyAcceptsNewSigAndRejectsTamper)
{
    const int32_t id = dash::coin::SPORK_17_QUORUM_DKG_ENABLED;
    const int64_t value = 0, ts = kNow;
    const auto key_id = keyid_of(kTestSeckey, /*compressed=*/true);
    const auto sig = sign_compact(kTestSeckey, spork_signature_hash(id, value, ts),
                                  /*compressed=*/true);

    EXPECT_TRUE(verify_spork_signature(id, value, ts, sig, key_id));
    // Any signed-field tamper must break recovery-to-this-key.
    EXPECT_FALSE(verify_spork_signature(id, value + 1, ts, sig, key_id));
    EXPECT_FALSE(verify_spork_signature(id, value, ts + 1, sig, key_id));
    EXPECT_FALSE(verify_spork_signature(id + 1, value, ts, sig, key_id));
    // The real gate: a valid signature by the WRONG key is not evidence.
    EXPECT_FALSE(verify_spork_signature(id, value, ts, sig, MAINNET_SPORK_PUBKEY_ID));
    // Malformed shapes.
    EXPECT_FALSE(verify_spork_signature(id, value, ts, {}, key_id));
    EXPECT_FALSE(verify_spork_signature(id, value, ts,
                                        std::vector<uint8_t>(64, 0), key_id));
    auto bad_header = sig;
    bad_header[0] = 12;   // outside the 27..34 compact-header range
    EXPECT_FALSE(verify_spork_signature(id, value, ts, bad_header, key_id));
}

TEST(DashSpork, VerifyFallsBackToLegacyMessageDigest)
{
    // dashd tries the new digest first, then the signed-message digest — a
    // spork signed the legacy way must still verify (and tamper still fail).
    const int32_t id = dash::coin::SPORK_9_SUPERBLOCKS_ENABLED;
    const int64_t value = 0, ts = kNow;
    const auto key_id = keyid_of(kTestSeckey, /*compressed=*/true);
    const auto sig = sign_compact(
        kTestSeckey, spork_legacy_message_hash(id, value, ts), /*compressed=*/true);

    EXPECT_TRUE(verify_spork_signature(id, value, ts, sig, key_id));
    EXPECT_FALSE(verify_spork_signature(id, value + 1, ts, sig, key_id));
}

TEST(DashSpork, VerifyHonoursUncompressedHeaderFlag)
{
    // The header byte's +4 flag selects WHICH pubkey serialization the key ID
    // hashes. Both encodings of the same key must verify against their own
    // key ID and fail against the other's.
    const int32_t id = dash::coin::SPORK_2_INSTANTSEND_ENABLED;
    const int64_t value = 0, ts = kNow;
    const uint256 h = spork_signature_hash(id, value, ts);

    const auto keyid_c = keyid_of(kTestSeckey, /*compressed=*/true);
    const auto keyid_u = keyid_of(kTestSeckey, /*compressed=*/false);
    ASSERT_NE(keyid_c, keyid_u);

    EXPECT_TRUE(verify_spork_signature(id, value, ts,
        sign_compact(kTestSeckey, h, /*compressed=*/true), keyid_c));
    EXPECT_TRUE(verify_spork_signature(id, value, ts,
        sign_compact(kTestSeckey, h, /*compressed=*/false), keyid_u));
    EXPECT_FALSE(verify_spork_signature(id, value, ts,
        sign_compact(kTestSeckey, h, /*compressed=*/true), keyid_u));
    EXPECT_FALSE(verify_spork_signature(id, value, ts,
        sign_compact(kTestSeckey, h, /*compressed=*/false), keyid_c));
}

// ══════════════════════════════════════════════════════════════════════════
// (4) STATE — assume-active seed, refinement, staleness, bad-sig isolation
// ══════════════════════════════════════════════════════════════════════════

TEST(DashSpork, SporkBlindNodeHoldsMainnetAnswer)
{
    // The seed IS the current mainnet posture (dashd's hardened values): all
    // 7 sporks known and active with zero messages heard. A spork-blind node
    // is RIGHT; the listener only refines.
    SporkState s;
    EXPECT_EQ(s.known_count(), 7u);
    EXPECT_EQ(s.active_count(kNow), 7u);
    EXPECT_EQ(s.listener_refined_count(), 0u);
    for (const auto& [id, value] : mainnet_spork_defaults())
    {
        EXPECT_TRUE(s.is_active(id, kNow)) << spork_name(id);
        ASSERT_TRUE(s.value(id).has_value());
        EXPECT_EQ(*s.value(id), value) << spork_name(id);
    }
    // dashd mainnet hardening: 1 for SPORK_21, 0 for everything else.
    EXPECT_EQ(*s.value(dash::coin::SPORK_21_QUORUM_ALL_CONNECTED), 1);
    EXPECT_EQ(*s.value(dash::coin::SPORK_19_CHAINLOCKS_ENABLED), 0);
    // Unknown spork: inactive, no value.
    EXPECT_FALSE(s.is_active(10099, kNow));
    EXPECT_FALSE(s.value(10099).has_value());
}

TEST(DashSpork, ListenerRefinesSeedAndStalenessRuleHolds)
{
    SporkState s;
    const int32_t id = dash::coin::SPORK_19_CHAINLOCKS_ENABLED;

    // A verified message refines the seed (regardless of its timestamp — the
    // seed is a stand-in, not evidence).
    EXPECT_EQ(s.on_spork(id, 0, kNow, /*sig_ok=*/true), SporkIngest::Applied);
    EXPECT_EQ(s.listener_refined_count(), 1u);
    EXPECT_TRUE(s.is_active(id, kNow + 1));

    // Not-strictly-newer than a listener-held entry: dropped as stale.
    EXPECT_EQ(s.on_spork(id, 12345, kNow, true), SporkIngest::Stale);
    EXPECT_EQ(s.on_spork(id, 12345, kNow - 10, true), SporkIngest::Stale);
    EXPECT_EQ(*s.value(id), 0);

    // Strictly newer wins — including a DEACTIVATION (value in the far
    // future => value < now false => inactive). The listener must be able to
    // move the state OFF the assume-active answer, or it is not a listener.
    EXPECT_EQ(s.on_spork(id, /*value=*/4'070'908'800LL, kNow + 60, true),
              SporkIngest::Applied);
    EXPECT_FALSE(s.is_active(id, kNow + 120));
    EXPECT_EQ(s.active_count(kNow + 120), 6u);

    const auto& c = s.counters();
    EXPECT_EQ(c.received, 4u);
    EXPECT_EQ(c.verified, 4u);
    EXPECT_EQ(c.applied, 2u);
    EXPECT_EQ(c.stale, 2u);
    EXPECT_EQ(c.rejected_sig, 0u);
}

TEST(DashSpork, BadSignatureNeverTouchesState)
{
    SporkState s;
    const int32_t id = dash::coin::SPORK_17_QUORUM_DKG_ENABLED;
    EXPECT_EQ(s.on_spork(id, 999'999'999'999LL, kNow, /*sig_ok=*/false),
              SporkIngest::BadSignature);
    EXPECT_EQ(*s.value(id), 0) << "an unverified spork mutated the state";
    EXPECT_EQ(s.listener_refined_count(), 0u);
    EXPECT_EQ(s.counters().rejected_sig, 1u);
    EXPECT_EQ(s.counters().applied, 0u);
    // An unknown-id bad spork must not create an entry either.
    EXPECT_EQ(s.on_spork(10099, 0, kNow, false), SporkIngest::BadSignature);
    EXPECT_EQ(s.known_count(), 7u);
}

// ══════════════════════════════════════════════════════════════════════════
// (5) CLIENT END-TO-END — handshake asks, verified spork refines, garbage
// costs the message and never the peer
// ══════════════════════════════════════════════════════════════════════════

TEST(DashSpork, HandshakeSendsGetSporks)
{
    SporkRig rig;
    rig.handshake(1);
    ASSERT_TRUE(rig.client.is_handshake_complete());
    const auto* p = rig.client.peer_session(SporkRig::peer_key(1));
    ASSERT_NE(p, nullptr);
    // Exactly three writes this session: our version on attach, the verack
    // ack, and the getsporks pull on handshake completion. (promote_primary
    // writes nothing; no discovery consumer is registered.)
    EXPECT_EQ(p->msgs_sent, 3u)
        << "expected version + verack + getsporks by handshake completion";
}

TEST(DashSpork, VerifiedSporkRefinesClientStateAndBadSigDoesNot)
{
    SporkRig rig;
    rig.handshake(1);

    // Arm the rig's synthetic spork key (production verifies the hardcoded
    // mainnet chainparams key; KATs cannot hold that private key).
    const auto key_id = keyid_of(kTestSeckey, /*compressed=*/true);
    rig.client.set_spork_pubkey_id_for_test(key_id);

    // A properly signed spork refines the assume-active seed.
    const int32_t id = dash::coin::SPORK_19_CHAINLOCKS_ENABLED;
    const auto sig = sign_compact(
        kTestSeckey, spork_signature_hash(id, 0, kNow), /*compressed=*/true);
    rig.deliver(1, p2p::message_spork::make_raw(id, 0, kNow, sig));

    EXPECT_EQ(rig.client.spork_state().listener_refined_count(), 1u)
        << "a verified spork message did not reach SporkState — is "
           "message_spork registered in p2p::Handler? (#1077 class)";
    EXPECT_EQ(rig.client.spork_state().counters().applied, 1u);

    // A bad-signature spork is counted + dropped; state untouched.
    auto tampered = sig;
    tampered[10] ^= 0x01;
    rig.deliver(1, p2p::message_spork::make_raw(
        dash::coin::SPORK_17_QUORUM_DKG_ENABLED, 999, kNow, tampered));
    EXPECT_EQ(rig.client.spork_state().counters().rejected_sig, 1u);
    EXPECT_EQ(*rig.client.spork_state().value(
        dash::coin::SPORK_17_QUORUM_DKG_ENABLED), 0);
    EXPECT_EQ(rig.client.spork_state().listener_refined_count(), 1u);

    // The spork surface is telemetry: json is readable and self-describing.
    const auto j = rig.client.spork_json();
    EXPECT_EQ(j["spork-known"].get<size_t>(), 7u);
    EXPECT_EQ(j["spork-listener-refined"].get<size_t>(), 1u);
    EXPECT_EQ(j["spork-rejected-sig"].get<uint64_t>(), 1u);
}

TEST(DashSpork, TruncatedSporkIsContainedBySignatureGateNeverCostsThePeer)
{
    // The counterpart hazard to non-registration: REGISTERED but unparseable.
    // This codec does NOT reject a truncated payload at parse time —
    // MessageHandler::add_handlers swallows the unserialize throw and delivers
    // the partially-read message anyway (the known registered-but-unparseable
    // seam). For spork that is safe BY CONSTRUCTION: the surviving fields
    // cannot carry a valid 65-byte signature, so the verification gate rejects
    // the message before any state is touched — and the peer is kept.
    SporkRig rig;
    rig.handshake(1);
    const auto rejected_before = rig.client.spork_state().counters().rejected_sig;

    ASSERT_NO_THROW(
        rig.deliver(1, std::make_unique<RawMessage>("spork", PackStream{})));

    EXPECT_TRUE(rig.client.is_handshake_complete()) << "garbage spork cost the peer";
    EXPECT_EQ(rig.client.connected_peer_count(), 1u);
    EXPECT_EQ(rig.client.spork_state().counters().rejected_sig, rejected_before + 1)
        << "a truncated spork was not rejected by the signature gate";
    EXPECT_EQ(rig.client.spork_state().counters().applied, 0u);
    EXPECT_EQ(rig.client.spork_state().listener_refined_count(), 0u)
        << "a truncated spork mutated the state";
}
