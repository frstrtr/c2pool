// SPDX-License-Identifier: AGPL-3.0-or-later
// KAT for the signed featured developer-node dashboard banner (subtype 0x06):
//   - FeaturedNodeStore freshest-wins / replay-protection / expiry / retract /
//     cross-restart persistence  (the consensus-neutral presentation logic)
//   - the ECDSA sign-then-verify render gate (a valid signature verifies; a
//     forged/tampered/wrong-key one does not; a non-authority blob is rejected
//     by the production validate_message_data() gate; unknown subtypes parse
//     without crashing / rejecting).
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <string>

#include <core/featured_node.hpp>
#include <impl/dash/share_messages.hpp>
#include <secp256k1.h>

using core::FeaturedNodeStore;

// ── helpers ─────────────────────────────────────────────────────────────────
static std::string tmp_state_path(const char* tag)
{
    auto p = std::filesystem::temp_directory_path() /
             ("featnode_" + std::string(tag) + "_" +
              std::to_string(::getpid()) + ".json");
    std::error_code ec; std::filesystem::remove(p, ec);
    return p.string();
}

static std::string payload(uint64_t seq, const std::string& url,
                           unsigned hl = 1, uint32_t exp = 0,
                           const std::string& com = "0.5%",
                           const std::string& loc = "EU/DE")
{
    std::string j = "{\"v\":1,\"seq\":" + std::to_string(seq) +
                    ",\"url\":\"" + url + "\",\"label\":\"Featured developer node\"" +
                    ",\"com\":\"" + com + "\",\"loc\":\"" + loc + "\"" +
                    ",\"hl\":" + std::to_string(hl);
    if (exp) j += ",\"exp\":" + std::to_string(exp);
    j += "}";
    return j;
}

// ── FeaturedNodeStore: freshest-wins supersession ───────────────────────────
TEST(FeaturedNode, NewerSeqSupersedesAndRenders)
{
    FeaturedNodeStore s; s.set_path(tmp_state_path("supersede"));
    EXPECT_TRUE(s.apply(100, 111, payload(100, "old.example.com"), "aa"));
    ASSERT_TRUE(s.emit().is_object());
    EXPECT_EQ(s.emit()["url"], "old.example.com");
    EXPECT_EQ(s.current_seq(), 100u);

    // strictly-newer seq → replaces url/commission/location atomically
    EXPECT_TRUE(s.apply(200, 222, payload(200, "dash.voidbind.com", 1, 0, "0.3%", "US"), "bb"));
    EXPECT_EQ(s.current_seq(), 200u);
    auto e = s.emit();
    EXPECT_EQ(e["url"], "dash.voidbind.com");
    EXPECT_EQ(e["commission"], "0.3%");
    EXPECT_EQ(e["location"], "US");
    EXPECT_EQ(e["verified"], true);
}

// ── FeaturedNodeStore: replay protection ────────────────────────────────────
TEST(FeaturedNode, OlderOrEqualSeqRejected)
{
    FeaturedNodeStore s; s.set_path(tmp_state_path("replay"));
    ASSERT_TRUE(s.apply(200, 1, payload(200, "dash.voidbind.com"), "bb"));

    EXPECT_FALSE(s.apply(199, 9, payload(199, "attacker.example"), "cc"));  // older
    EXPECT_FALSE(s.apply(200, 9, payload(200, "attacker.example"), "cc"));  // equal (re-broadcast no-op)
    EXPECT_EQ(s.current_seq(), 200u);
    EXPECT_EQ(s.emit()["url"], "dash.voidbind.com");  // banner unchanged
}

TEST(FeaturedNode, SeqZeroRejected)
{
    FeaturedNodeStore s; s.set_path(tmp_state_path("seqzero"));
    EXPECT_FALSE(s.apply(0, 1, payload(0, "x.example"), "aa"));
    EXPECT_FALSE(s.present());
    EXPECT_TRUE(s.emit().is_null());
}

// ── FeaturedNodeStore: persistence across a restart ─────────────────────────
TEST(FeaturedNode, HighestSeqPersistsAcrossRestart)
{
    auto path = tmp_state_path("persist");
    {
        FeaturedNodeStore s; s.set_path(path);
        ASSERT_TRUE(s.apply(500, 42, payload(500, "dash.voidbind.com"), "dd"));
    }
    // fresh instance = process restart
    FeaturedNodeStore s2; s2.set_path(path); s2.load();
    EXPECT_EQ(s2.current_seq(), 500u);
    ASSERT_TRUE(s2.emit().is_object());
    EXPECT_EQ(s2.emit()["url"], "dash.voidbind.com");
    // an older signed message must NOT override after restart (replay)
    EXPECT_FALSE(s2.apply(499, 1, payload(499, "attacker.example"), "ee"));
    EXPECT_EQ(s2.emit()["url"], "dash.voidbind.com");
}

// ── FeaturedNodeStore: expiry self-clears rendering, keeps seq ───────────────
TEST(FeaturedNode, ExpiryHidesButKeepsSeq)
{
    FeaturedNodeStore s; s.set_path(tmp_state_path("expiry"));
    ASSERT_TRUE(s.apply(700, 1, payload(700, "dash.voidbind.com", 1, /*exp=*/1u), "ff"));
    EXPECT_TRUE(s.emit().is_null());     // exp in the past → hidden
    EXPECT_EQ(s.current_seq(), 700u);    // but seq stays for replay protection
    EXPECT_FALSE(s.apply(699, 1, payload(699, "attacker.example"), "gg"));
}

// ── FeaturedNodeStore: hl bit0 cleared = sanctioned retract ─────────────────
TEST(FeaturedNode, HighlightBitClearedRetractsBanner)
{
    FeaturedNodeStore s; s.set_path(tmp_state_path("retract"));
    ASSERT_TRUE(s.apply(800, 1, payload(800, "dash.voidbind.com", 1), "hh"));
    ASSERT_TRUE(s.emit().is_object());
    EXPECT_TRUE(s.apply(801, 1, payload(801, "dash.voidbind.com", /*hl=*/0), "hh"));  // retract
    EXPECT_TRUE(s.emit().is_null());    // hidden
    EXPECT_EQ(s.current_seq(), 801u);   // seq advanced (no downgrade attack)
}

// ── ECDSA render gate: sign→verify roundtrip + tamper/wrong-key rejection ────
namespace {
struct TestKey { unsigned char sk[32]; dash::AuthorityPubkey pk; };

TestKey make_test_key(unsigned char fill)
{
    TestKey k; std::fill(std::begin(k.sk), std::end(k.sk), fill);
    const auto* ctx = dash::get_secp256k1_context();
    secp256k1_pubkey pub;
    EXPECT_EQ(secp256k1_ec_pubkey_create(ctx, &pub, k.sk), 1);
    size_t len = k.pk.size();
    secp256k1_ec_pubkey_serialize(ctx, k.pk.data(), &len, &pub, SECP256K1_EC_COMPRESSED);
    EXPECT_EQ(len, 33u);
    return k;
}
} // namespace

TEST(FeaturedNodeGate, ValidSignatureVerifies_ForgedDoesNot)
{
    auto key = make_test_key(0x11);
    std::string pl = payload(1766000000ull, "dash.voidbind.com");
    std::vector<unsigned char> pbytes(pl.begin(), pl.end());

    uint8_t wire_flags = dash::FLAG_HAS_SIGNATURE | dash::FLAG_PROTOCOL_AUTHORITY;
    auto h = dash::compute_message_hash(dash::MSG_FEATURED_NODE, wire_flags,
                                        1766000000u, pbytes.data(), pbytes.size());
    auto sig = dash::ecdsa_sign(h.data(), key.sk);
    ASSERT_FALSE(sig.empty());

    // valid signature verifies against the signer's pubkey
    EXPECT_TRUE(dash::ecdsa_verify(key.pk.data(), key.pk.size(),
                                   h.data(), sig.data(), sig.size()));

    // tampered payload (seq bumped by attacker) → different digest → REJECT
    std::string pl2 = payload(1766000001ull, "attacker.example");
    std::vector<unsigned char> p2(pl2.begin(), pl2.end());
    auto h2 = dash::compute_message_hash(dash::MSG_FEATURED_NODE, wire_flags,
                                         1766000000u, p2.data(), p2.size());
    EXPECT_FALSE(dash::ecdsa_verify(key.pk.data(), key.pk.size(),
                                    h2.data(), sig.data(), sig.size()));

    // wrong key → REJECT
    auto other = make_test_key(0x22);
    EXPECT_FALSE(dash::ecdsa_verify(other.pk.data(), other.pk.size(),
                                    h.data(), sig.data(), sig.size()));
}

// ── production gate: a non-authority (forged) blob is rejected ──────────────
TEST(FeaturedNodeGate, NonAuthorityBlobRejectedByValidate)
{
    // Build a fully-formed signed+encrypted 0x06 blob with a THROWAWAY key.
    auto key = make_test_key(0x33);
    dash::ShareMessage msg;
    msg.msg_type = dash::MSG_FEATURED_NODE;
    msg.wire_flags = dash::FLAG_HAS_SIGNATURE | dash::FLAG_PROTOCOL_AUTHORITY;
    msg.timestamp = 1766000000u;
    std::string pl = payload(1766000000ull, "attacker.example");
    msg.payload.assign(pl.begin(), pl.end());
    std::vector<dash::ShareMessage> msgs{msg};
    auto blob = dash::create_message_data(key.sk, key.pk, msgs);
    ASSERT_FALSE(blob.empty());

    // The production render gate: validate_message_data must REJECT it because
    // the signer is not a pinned COMBINED_DONATION_SCRIPT authority key.
    std::string err = dash::validate_message_data(blob);
    EXPECT_FALSE(err.empty());  // rejected → banner never renders

    // And the decrypt step itself fails against the pinned key set.
    auto un = dash::unpack_share_messages(blob.data(), blob.size());
    EXPECT_FALSE(un.decrypted);
}

// ── forward-compat: an unknown subtype parses without crash/reject ──────────
TEST(FeaturedNodeGate, UnknownSubtypeParsesGracefully)
{
    // Hand-pack a message with a made-up msg_type (0x7E) and confirm the
    // wire parser accepts it (no throw, no reject) — an old node that does not
    // know 0x06 (or any new subtype) simply ignores it rather than disconnecting.
    dash::ShareMessage msg;
    msg.msg_type = 0x7E;                       // unknown / future subtype
    msg.wire_flags = dash::FLAG_HAS_SIGNATURE;
    msg.timestamp = 1766000000u;
    msg.payload = {0x01, 0x02, 0x03};
    msg.signing_id.fill(0);
    msg.signature = {0xAA, 0xBB};
    auto packed = dash::pack_message(msg);

    dash::ShareMessage out;
    auto off = dash::ShareMessage::unpack(packed.data(), packed.size(), 0, out);
    ASSERT_TRUE(off.has_value());
    EXPECT_EQ(out.msg_type, 0x7E);             // preserved, not rejected
    EXPECT_EQ(out.payload.size(), 3u);
}
