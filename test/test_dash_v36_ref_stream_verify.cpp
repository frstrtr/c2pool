// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 share ref stream + share_init_verify(DashV36Share) + message_data
// validation KATs, for the private/isolated DASH v36 sharechain.
//
// CONSENSUS-BEARING. There is no external oracle for a DASH v36 share (no
// p2pool-dash node mints one), so correctness is pinned four ways:
//   * LAYOUT: the ref stream equals identifier || the standardized v36
//     share_info (cross-coin non-segwit shape, rebuilt by hand in the BCH field
//     order) || the DASH suffix (coinbase_payload, payment_amount,
//     packed_payments) AFTER message_data; and its share_info bytes are an exact
//     slice of the production DashV36Share wire (DashFormatter::WriteV36) with
//     the link fields and coinbase_payload_outer removed.
//   * FROZEN GOLDENS: stream + ref_hash hex for the canonical share on the
//     public and on a private identity, computed independently (Python
//     hashlib/struct over the canonical field values, cross-checked against the
//     frozen v36 wire golden in test_dash_v36_share.cpp).
//   * MIRROR: producer::compute_ref_hash(DashV36Share) == verifier ref_hash ==
//     the hand mirror, and share_init_verify folds a gentx built around that
//     ref_hash back to its txid.
//   * NEGATIVES: check order, tampered DASH suffix / message_data move the
//     commitment, and message_data authority / signature / size rejects.
//
// Linked into test_dash_network_id_override because the isolated profile is
// keyed on the process-global SharechainConfig identity; every test resets it
// on entry and exit (IdentityGuard). make_coin_params SNAPSHOTS the profile, so
// every test sets the identity BEFORE building params.

#include <gtest/gtest.h>

#include <impl/dash/config_pool.hpp>
#include <impl/dash/params.hpp>
#include <impl/dash/share.hpp>
#include <impl/dash/share_chain.hpp>      // DashFormatter (wire slice cross-check)
#include <impl/dash/share_check.hpp>
#include <impl/dash/share_messages.hpp>
#include <impl/dash/share_producer.hpp>
#include "dash_v36_share_fixture.hpp"      // make_canonical_v36, to_hex, pack_hex

#include <core/coin_params.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using dash::SharechainConfig;
using Bytes = std::vector<unsigned char>;
using KeySpan = std::span<const dash::AuthorityPubkey* const>;

constexpr const char* MAIN_ID = "7242ef345e1bed6b";  // oracle networks/dash.py
constexpr const char* ISO_ID  = "d3a5c0920263617";   // any custom id => isolated v36
constexpr const char* ISO_PFX = "0badc0ffee11";

struct IdentityGuard {
    IdentityGuard()  { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
    ~IdentityGuard() { SharechainConfig::reset_network_id(); SharechainConfig::is_testnet = false; }
};

core::CoinParams iso_params() {
    SharechainConfig::set_network_id(ISO_ID, ISO_PFX);
    return dash::make_coin_params(false);
}

Bytes bytes_of(const PackStream& ps) {
    auto& m = const_cast<PackStream&>(ps);
    const auto* p = reinterpret_cast<const unsigned char*>(m.data());
    return Bytes(p, p + m.size());
}

std::string hex(const Bytes& b) { return to_hex(std::span<const unsigned char>(b.data(), b.size())); }
std::string hex(const uint256& h) { return to_hex(std::span<const unsigned char>(h.data(), 32)); }

Bytes unhex(const std::string& h) {
    Bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}

uint256 sha256d(const Bytes& b) { return Hash(std::span<const unsigned char>(b.data(), b.size())); }

void append(Bytes& a, const Bytes& b) { a.insert(a.end(), b.begin(), b.end()); }

// ── Hand mirror of the v36 ref stream, written independently of the builder ──
// Standardized v36 share_info in the BCH v36 Formatter field order
// (bch/share_check.hpp ref stream; LTC v36 minus segwit_data), no tx_info,
// ending with message_data.
Bytes mirror_standardized_share_info(const dash::DashV36Share& s) {
    PackStream os;
    os << s.m_prev_hash << s.m_coinbase << s.m_nonce;
    os << s.m_pubkey_hash << s.m_pubkey_type;
    ::Serialize(os, VarInt(s.m_subsidy));
    os << s.m_donation;
    { uint8_t si = static_cast<uint8_t>(s.m_stale_info); os << si; }
    ::Serialize(os, VarInt(s.m_desired_version));
    os << s.m_merged_addresses;
    os << s.m_far_share_hash << s.m_max_bits << s.m_bits << s.m_timestamp << s.m_absheight;
    ::Serialize(os, Using<dash::v36::AbsworkV36Format>(s.m_abswork));
    os << s.m_merged_coinbase_info << s.m_merged_payout_hash;
    os << s.m_message_data;
    return bytes_of(os);
}

// DASH suffix in the ref stream: coinbase_payload, payment_amount,
// packed_payments (coinbase_payload_outer is hash_link data, NOT here).
Bytes mirror_dash_suffix(const dash::DashV36Share& s) {
    PackStream os;
    os << s.m_coinbase_payload;
    os << s.m_payment_amount;
    uint64_t count = s.m_packed_payments.size();
    ::Serialize(os, VarInt(count));
    for (const auto& p : s.m_packed_payments) {
        BaseScript bs; bs.m_data.assign(p.m_payee.begin(), p.m_payee.end());
        os << bs << p.m_amount;
    }
    return bytes_of(os);
}

Bytes identifier_bytes(const core::CoinParams& pm) { return unhex(pm.active_identifier_hex()); }

Bytes mirror_ref_stream(const core::CoinParams& pm, const dash::DashV36Share& s) {
    Bytes out = identifier_bytes(pm);
    append(out, mirror_standardized_share_info(s));
    append(out, mirror_dash_suffix(s));
    return out;
}

// Frozen goldens: identifier || share_info of make_canonical_v36(), and
// sha256d of it (raw uint256 byte order). Computed independently in Python
// (hashlib + struct over the canonical field values); the share_info part was
// cross-checked against the frozen v36 wire golden (FrozenGoldenWire).
constexpr const char* CANON_SHARE_INFO_HEX =
    "010000000000000000000000000000000000000000000000000000000000000002abcd0d0c0b0a"
    "efbeadde0000000000000000000000000000000000ff00f2052a01000000341200240002000000"
    "00000000000000000000000000000000000000000000000000000000ffff0f1effff001dccbbaa"
    "9903020100ff080706050403020100000000000000000000000000000000000000000000000000"
    "00000000000000000002010201efcdab00000000010d2136613034303130323033303439300000"
    "00000000";
constexpr const char* CANON_MAIN_REF_HASH_RAW =
    "f61e155a05286e07bc8bbf6e510f008fa004ccbc1d40c2de7c2e8e4de987d115";
constexpr const char* CANON_ISO_REF_HASH_RAW =
    "8c9d98a18011aff7a5bd6eb33ad8b3a91a24f44289d73d47dea37419b2a7d14f";

// ── Verifiable fixture ───────────────────────────────────────────────────────
// The canonical share made verifiable: past timestamp, a harder block target so
// it is not a block, and a hash_link / gentx built around the ref_hash computed
// by the HAND MIRROR (not by the code under test).
struct Verifiable {
    dash::DashV36Share share;
    Bytes const_ending;
    uint256 ref_hash;      // mirror-computed
    uint256 txid;          // sha256d(gentx)
    uint256 expected_hash; // X11 of the hand-built header over txid
};

constexpr uint32_t PAST_TS = 1700000000u;

uint256 x11_of_header(const core::CoinParams& pm, const dash::DashV36Share& s,
                      const uint256& merkle_root) {
    PackStream h;
    h << static_cast<uint32_t>(s.m_min_header.m_version);
    h << s.m_min_header.m_previous_block << merkle_root
      << s.m_min_header.m_timestamp << s.m_min_header.m_bits << s.m_min_header.m_nonce;
    auto b = bytes_of(h);
    EXPECT_EQ(b.size(), 80u);
    return pm.pow_func(std::span<const unsigned char>(b.data(), b.size()));
}

// Rebuild the hash_link / txid / expected hash of `s` (after any edit).
Verifiable seal(const core::CoinParams& pm, dash::DashV36Share s) {
    Verifiable v;
    v.const_ending = dash::compute_gentx_before_refhash(pm.donation_script_func(36));
    v.ref_hash = sha256d(mirror_ref_stream(pm, s));  // empty ref_merkle_link

    Bytes prefix(41, 0x5a);  // arbitrary coinbase-tx prefix; must end in const_ending
    append(prefix, v.const_ending);

    Bytes gentx = prefix;
    append(gentx, Bytes(v.ref_hash.data(), v.ref_hash.data() + 32));
    for (int i = 0; i < 8; ++i) gentx.push_back(static_cast<unsigned char>(s.m_last_txout_nonce >> (8 * i)));
    append(gentx, Bytes(4, 0x00));
    append(gentx, s.m_coinbase_payload_outer.m_data);
    v.txid = sha256d(gentx);

    s.m_hash_link = dash::producer::prefix_to_hash_link<dash::v36::V36HashLinkType>(prefix, v.const_ending);
    v.expected_hash = x11_of_header(pm, s, v.txid);  // empty merkle_link => root == txid
    v.share = s;
    return v;
}

dash::DashV36Share verifiable_base() {
    auto s = make_canonical_v36();
    s.m_timestamp = PAST_TS;
    s.m_min_header.m_bits = 0x1b00ffffu;  // hard block target: not a block
    return s;
}

// Throws std::invalid_argument whose what() equals / starts with `want`.
void expect_reject(const std::function<void()>& fn, const std::string& want, bool prefix = false) {
    bool threw = false;
    try { fn(); } catch (const std::invalid_argument& e) {
        threw = true;
        const std::string got = e.what();
        if (prefix) EXPECT_EQ(got.substr(0, want.size()), want) << got;
        else        EXPECT_EQ(got, want);
    }
    EXPECT_TRUE(threw) << "expected std::invalid_argument(\"" << want << "\")";
}

// ── Message key material ─────────────────────────────────────────────────────
// No authority seckey exists in-tree; a test keypair signs, and the envelope
// is encrypted under whichever PUBKEY a test picks (encryption needs only it).
struct TestKey { unsigned char sk[32]; dash::AuthorityPubkey pk; };

TestKey make_test_key(unsigned char fill) {
    TestKey k; std::fill(std::begin(k.sk), std::end(k.sk), fill);
    const auto* ctx = dash::get_secp256k1_context();
    secp256k1_pubkey pub;
    EXPECT_EQ(secp256k1_ec_pubkey_create(ctx, &pub, k.sk), 1);
    size_t len = k.pk.size();
    secp256k1_ec_pubkey_serialize(ctx, k.pk.data(), &len, &pub, SECP256K1_EC_COMPRESSED);
    EXPECT_EQ(len, 33u);
    return k;
}

std::vector<dash::ShareMessage> one_signed_message() {
    dash::ShareMessage m;
    m.msg_type = dash::MSG_NODE_STATUS;
    m.wire_flags = dash::FLAG_HAS_SIGNATURE;
    m.timestamp = 1710000000;
    m.payload = {0x01, 0x02, 0x03, 0x04};
    return {m};
}

// Signed by `signer`, envelope encrypted under `envelope_key`.
Bytes signed_blob(const TestKey& signer, const dash::AuthorityPubkey& envelope_key) {
    auto msgs = one_signed_message();
    return dash::create_message_data(signer.sk, envelope_key, msgs);
}

constexpr const char* ERR_DECRYPT =
    "message_data failed decryption against all COMBINED_DONATION_SCRIPT authority keys";
constexpr const char* ERR_ECDSA = "message ECDSA signature verification failed";
constexpr const char* ERR_NO_MSGS = "message_data decrypted but contains no valid messages";
constexpr const char* ERR_OVERSIZE = "share message_data exceeds MAX_TOTAL_MESSAGE_BYTES";

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// 1. Layout (operator Q1): identifier || standardized v36 share_info ending in
//    message_data || DASH suffix. coinbase_payload_outer and the link fields
//    are NOT in the ref stream; the share_info is an exact slice of the
//    production v36 wire.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36RefStream, LayoutIsIdentifierStandardizedPrefixThenDashSuffix) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto s = make_canonical_v36();

    const Bytes got = dash::v36_ref_stream_bytes(pm, s);
    const Bytes id = identifier_bytes(pm);
    const Bytes std_part = mirror_standardized_share_info(s);
    const Bytes suffix = mirror_dash_suffix(s);

    ASSERT_EQ(id.size(), 8u);
    ASSERT_EQ(got.size(), id.size() + std_part.size() + suffix.size());
    EXPECT_EQ(hex(Bytes(got.begin(), got.begin() + 8)), hex(id));
    EXPECT_EQ(hex(Bytes(got.begin() + 8, got.begin() + 8 + std_part.size())), hex(std_part));
    EXPECT_EQ(hex(Bytes(got.end() - suffix.size(), got.end())), hex(suffix))
        << "DASH suffix must follow message_data (operator Q1)";
    // Suffix order: payload first, then payment_amount, then packed_payments.
    EXPECT_EQ(hex(Bytes(suffix.begin(), suffix.begin() + 3)), "020102");

    // Wire slice cross-check against DashFormatter::WriteV36:
    //   wire = min_header || [share_info up to merged_payout_hash] || links ||
    //          message_data || suffix || coinbase_payload_outer
    PackStream w; dash::DashFormatter::Write(w, &s);
    const Bytes wire = bytes_of(w);
    PackStream mh; mh << s.m_min_header;
    const size_t mh_len = bytes_of(mh).size();
    PackStream md; md << s.m_message_data;
    const size_t md_len = bytes_of(md).size();
    PackStream links;
    { ParamPackStream ps{dash::v36::MERKLE_LINK_SMALL, links}; ::Serialize(ps, s.m_ref_merkle_link); }
    links << s.m_last_txout_nonce << s.m_hash_link;
    { ParamPackStream ps{dash::v36::MERKLE_LINK_SMALL, links}; ::Serialize(ps, s.m_merkle_link); }
    const size_t links_len = bytes_of(links).size();
    PackStream outer; outer << s.m_coinbase_payload_outer;
    const size_t outer_len = bytes_of(outer).size();

    const size_t core_len = std_part.size() - md_len;  // share_info before message_data
    Bytes from_wire(wire.begin() + mh_len, wire.begin() + mh_len + core_len);
    const size_t md_at = mh_len + core_len + links_len;
    append(from_wire, Bytes(wire.begin() + md_at, wire.end() - outer_len));
    EXPECT_EQ(hex(Bytes(got.begin() + 8, got.end())), hex(from_wire))
        << "ref share_info must be the v36 wire minus min_header, link fields and outer payload";

    // coinbase_payload_outer (value 02 01 02, VarStr 03 02 01 02) is absent.
    const Bytes outer_b = bytes_of(outer);
    EXPECT_TRUE(std::search(got.begin(), got.end(), outer_b.begin(), outer_b.end()) == got.end());
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Frozen goldens (independently computed). The identifier is the only
//    per-network byte range.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36RefStream, FrozenGoldenStreamAndRefHash) {
    IdentityGuard g;
    const auto s = make_canonical_v36();

    const auto pm_main = dash::make_coin_params(false);  // public identity
    ASSERT_EQ(pm_main.active_identifier_hex(), MAIN_ID);
    const Bytes main_stream = dash::v36_ref_stream_bytes(pm_main, s);
    EXPECT_EQ(hex(main_stream), std::string(MAIN_ID) + CANON_SHARE_INFO_HEX);
    EXPECT_EQ(hex(dash::compute_v36_ref_hash(pm_main, s)), CANON_MAIN_REF_HASH_RAW);

    const auto pm_iso = iso_params();
    ASSERT_EQ(pm_iso.active_identifier_hex(), "0d3a5c0920263617");
    const Bytes iso_stream = dash::v36_ref_stream_bytes(pm_iso, s);
    EXPECT_EQ(hex(iso_stream), std::string("0d3a5c0920263617") + CANON_SHARE_INFO_HEX);
    EXPECT_EQ(hex(dash::compute_v36_ref_hash(pm_iso, s)), CANON_ISO_REF_HASH_RAW);

    ASSERT_EQ(main_stream.size(), iso_stream.size());
    EXPECT_EQ(hex(Bytes(main_stream.begin() + 8, main_stream.end())),
              hex(Bytes(iso_stream.begin() + 8, iso_stream.end())));
    EXPECT_NE(hex(dash::compute_v36_ref_hash(pm_main, s)), hex(dash::compute_v36_ref_hash(pm_iso, s)));
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Producer == verifier == hand mirror; the verifier commits that ref_hash.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36RefStream, ProducerRefHashEqualsVerifierMirror) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto v = seal(pm, verifiable_base());

    const uint256 producer = dash::producer::compute_ref_hash(pm, v.share);
    const uint256 verifier = dash::compute_v36_ref_hash(pm, v.share);
    const uint256 mirror = dash::check_merkle_link(sha256d(mirror_ref_stream(pm, v.share)),
                                                   dash::v36::MerkleLink{});
    EXPECT_EQ(hex(producer), hex(verifier));
    EXPECT_EQ(hex(verifier), hex(mirror));
    EXPECT_EQ(hex(mirror), hex(v.ref_hash));

    // The verifier folds a gentx built around THAT ref_hash back to its txid.
    (void)dash::share_init_verify(v.share, pm, /*check_pow=*/false);
    EXPECT_EQ(hex(dash::g_last_gentx_hash), hex(v.txid));
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. message_data and every DASH suffix field are committed, each at its slot.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36RefStream, MessageDataAndSuffixAreCommitted) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto base = make_canonical_v36();
    const Bytes base_stream = dash::v36_ref_stream_bytes(pm, base);
    const std::string base_ref = hex(dash::compute_v36_ref_hash(pm, base));

    // Stream offset of each slot (from the hand mirror).
    const size_t md_off = 8 + mirror_standardized_share_info(base).size() - 1;  // empty md = 1 byte

    struct Case { const char* name; std::function<void(dash::DashV36Share&)> edit; size_t first_diff; };
    const std::vector<Case> cases = {
        {"message_data", [](dash::DashV36Share& s) {
             s.m_message_data = BaseScript(Bytes{0x01, 0x02, 0x03}); }, md_off},
        {"coinbase_payload", [](dash::DashV36Share& s) {
             s.m_coinbase_payload = BaseScript(Bytes{0x01, 0x03}); }, md_off + 1 + 2},
        {"payment_amount", [](dash::DashV36Share& s) { s.m_payment_amount += 1; }, md_off + 1 + 3},
        {"packed_payee", [](dash::DashV36Share& s) {
             s.m_packed_payments[0].m_payee = "!6a0401020305"; }, md_off + 1 + 3 + 8 + 1 + 13},
        {"packed_amount", [](dash::DashV36Share& s) {
             s.m_packed_payments[0].m_amount += 1; }, md_off + 1 + 3 + 8 + 1 + 1 + 13},
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        auto s = base;
        c.edit(s);
        const Bytes st = dash::v36_ref_stream_bytes(pm, s);
        EXPECT_NE(hex(dash::compute_v36_ref_hash(pm, s)), base_ref);
        const size_t n = std::min(st.size(), base_stream.size());
        size_t i = 0;
        while (i < n && st[i] == base_stream[i]) ++i;
        EXPECT_EQ(i, c.first_diff) << "first differing byte must be the edited slot";
    }

    // coinbase_payload_outer is NOT committed by the ref stream (hash_link data).
    auto s = base;
    s.m_coinbase_payload_outer = BaseScript(Bytes{0x02, 0x09, 0x09});
    EXPECT_EQ(hex(dash::compute_v36_ref_hash(pm, s)), base_ref);
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. A well-formed isolated v36 share passes share_init_verify.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36Verify, IsolatedCanonicalSharePassesShareInitVerify) {
    IdentityGuard g;
    const auto pm = iso_params();
    ASSERT_TRUE(SharechainConfig::share_profile().maintainer_only_authority);

    // On the isolated chain the v36 const_ending is the v16 one (P2PKH donation).
    EXPECT_EQ(hex(dash::compute_gentx_before_refhash(pm.donation_script_func(36))),
              hex(dash::compute_gentx_before_refhash()));
    // The zero-argument v16 form is the DONATION_SCRIPT form (identical bytes).
    EXPECT_EQ(hex(dash::compute_gentx_before_refhash()),
              hex(dash::compute_gentx_before_refhash(dash::DONATION_SCRIPT)));

    const auto v = seal(pm, verifiable_base());
    ASSERT_EQ(chain::bits_to_target(v.share.m_bits), pm.max_target);

    dash::g_last_init_is_block = true;
    const uint256 h = dash::share_init_verify(v.share, pm, /*check_pow=*/false);
    EXPECT_EQ(hex(h), hex(v.expected_hash));
    EXPECT_EQ(hex(dash::g_last_pow_hash), hex(v.expected_hash));
    EXPECT_EQ(hex(dash::g_last_gentx_hash), hex(v.txid));
    EXPECT_FALSE(dash::g_last_init_is_block);

    // Same share through the explicit-authority overload with the isolated set.
    EXPECT_EQ(hex(dash::share_init_verify(v.share, pm, false, dash::authority_pubkeys(true))),
              hex(v.expected_hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. Check order is the v16 order; message_data is checked after PoW.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36Verify, CheckOrderMatchesV16) {
    IdentityGuard g;
    const uint32_t now = dash::share_clock_now();
    {
        const auto pm = iso_params();
        auto s = seal(pm, verifiable_base()).share;
        s.m_timestamp = now + 10000;
        s.m_coinbase = BaseScript(Bytes{0x01});
        expect_reject([&] { (void)dash::share_init_verify(s, pm, false); },
                      "share timestamp is too far in the future");
    }
    SharechainConfig::reset_network_id();
    {
        const auto pm = dash::make_coin_params(false);  // public identity: no bound
        auto s = seal(pm, verifiable_base()).share;
        s.m_timestamp = now + 10000;
        s.m_coinbase = BaseScript(Bytes{0x01});
        expect_reject([&] { (void)dash::share_init_verify(s, pm, false, dash::authority_pubkeys(false)); },
                      "bad coinbase size");
        s.m_coinbase = BaseScript(Bytes(101, 0x00));
        expect_reject([&] { (void)dash::share_init_verify(s, pm, false, dash::authority_pubkeys(false)); },
                      "bad coinbase size");
    }
    {
        const auto pm = iso_params();
        auto s = seal(pm, verifiable_base()).share;
        s.m_bits = 0;
        expect_reject([&] { (void)dash::share_init_verify(s, pm, false); }, "share target is zero");
        s.m_bits = 0x1e0fffffu;  // easier than max_target
        expect_reject([&] { (void)dash::share_init_verify(s, pm, false); }, "share target invalid");

        // PoW before message_data: an unmined diff-1 share carrying a bad blob
        // is rejected by the PoW check, not by the message check.
        const auto key = make_test_key(0x21);
        auto bad = verifiable_base();
        bad.m_message_data = BaseScript(signed_blob(key, dash::DONATION_PUBKEY_FORRESTV()));
        const auto v = seal(pm, bad);
        expect_reject([&] { (void)dash::share_init_verify(v.share, pm, true); },
                      "share PoW hash does not meet target");
        expect_reject([&] { (void)dash::share_init_verify(v.share, pm, false); },
                      std::string("share ") + ERR_DECRYPT);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. A tampered DASH suffix moves the ref_hash, so the hash_link no longer
//    folds to the committed gentx (the header / share hash change with it).
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36Verify, TamperedDashSuffixBreaksHashLinkCommitment) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto v = seal(pm, verifiable_base());
    const std::string ref0 = hex(dash::compute_v36_ref_hash(pm, v.share));

    const std::vector<std::pair<const char*, std::function<void(dash::DashV36Share&)>>> edits = {
        {"payment_amount", [](dash::DashV36Share& s) { s.m_payment_amount += 1; }},
        {"packed_payee", [](dash::DashV36Share& s) { s.m_packed_payments[0].m_payee = "!6a0401020399"; }},
        {"packed_amount", [](dash::DashV36Share& s) { s.m_packed_payments[0].m_amount -= 1; }},
        {"coinbase_payload", [](dash::DashV36Share& s) { s.m_coinbase_payload = BaseScript(Bytes{0x07}); }},
    };
    for (const auto& [name, edit] : edits) {
        SCOPED_TRACE(name);
        auto t = v.share;  // hash_link still commits to the ORIGINAL ref_hash
        edit(t);
        EXPECT_NE(hex(dash::compute_v36_ref_hash(pm, t)), ref0);
        const uint256 h = dash::share_init_verify(t, pm, /*check_pow=*/false);
        EXPECT_NE(hex(dash::g_last_gentx_hash), hex(v.txid));
        EXPECT_NE(hex(h), hex(v.expected_hash));
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 8. Same for message_data: adding a (valid) blob after sealing moves the
//    commitment.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36Verify, TamperedMessageDataBreaksHashLinkCommitment) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto v = seal(pm, verifiable_base());
    ASSERT_TRUE(v.share.m_message_data.m_data.empty());

    const auto key = make_test_key(0x33);
    const dash::AuthorityPubkey* set[] = {&key.pk};
    auto t = v.share;
    t.m_message_data = BaseScript(signed_blob(key, key.pk));
    ASSERT_FALSE(t.m_message_data.m_data.empty());

    EXPECT_NE(hex(dash::compute_v36_ref_hash(pm, t)), hex(v.ref_hash));
    const uint256 h = dash::share_init_verify(t, pm, false, KeySpan(set));  // blob itself is valid
    EXPECT_NE(hex(dash::g_last_gentx_hash), hex(v.txid));
    EXPECT_NE(hex(h), hex(v.expected_hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// 9..13. message_data validation.
// ═════════════════════════════════════════════════════════════════════════════
TEST(DashV36MessageData, EmptyIsValidOnBothAuthoritySets) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto v = seal(pm, verifiable_base());
    EXPECT_EQ(hex(dash::share_init_verify(v.share, pm, false)), hex(v.expected_hash));
    EXPECT_EQ(hex(dash::share_init_verify(v.share, pm, false, dash::authority_pubkeys(false))),
              hex(v.expected_hash));
    EXPECT_EQ(dash::validate_message_data({}, dash::authority_pubkeys(true)), "");
}

TEST(DashV36MessageData, ForrestvEnvelopeRejectedOnIsolatedProfile) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto key = make_test_key(0x44);
    const Bytes blob = signed_blob(key, dash::DONATION_PUBKEY_FORRESTV());
    ASSERT_FALSE(blob.empty());

    // The key set is the sole discriminator: the isolated set cannot open a
    // forrestv envelope; the public set opens it and reaches the signature stage.
    EXPECT_EQ(dash::validate_message_data(blob, dash::authority_pubkeys(true)), ERR_DECRYPT);
    const std::string pub_err = dash::validate_message_data(blob, dash::authority_pubkeys(false));
    EXPECT_EQ(pub_err.substr(0, std::string(ERR_ECDSA).size()), ERR_ECDSA) << pub_err;
    EXPECT_FALSE(dash::unpack_share_messages(blob.data(), blob.size(), dash::authority_pubkeys(true)).decrypted);
    EXPECT_TRUE(dash::unpack_share_messages(blob.data(), blob.size(), dash::authority_pubkeys(false)).decrypted);

    // Public wrappers (default argument) are the public 2-key set, unchanged.
    EXPECT_EQ(dash::validate_message_data(blob),
              dash::validate_message_data(blob, KeySpan(dash::DONATION_AUTHORITY_PUBKEYS())));

    // Share level, isolated profile (default authority from the profile).
    auto s = verifiable_base();
    s.m_message_data = BaseScript(blob);
    const auto v = seal(pm, s);
    expect_reject([&] { (void)dash::share_init_verify(v.share, pm, false); },
                  std::string("share ") + ERR_DECRYPT);
}

TEST(DashV36MessageData, MaintainerEnvelopeWithForgedSignatureRejected) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto key = make_test_key(0x55);  // not the maintainer key
    const Bytes blob = signed_blob(key, dash::DONATION_PUBKEY_MAINTAINER());
    ASSERT_FALSE(blob.empty());

    // The maintainer envelope opens on the isolated set; the signature does not verify.
    auto un = dash::unpack_share_messages(blob.data(), blob.size(), dash::authority_pubkeys(true));
    ASSERT_TRUE(un.decrypted);
    EXPECT_EQ(un.authority_pubkey, &dash::DONATION_PUBKEY_MAINTAINER());
    const std::string err = dash::validate_message_data(blob, dash::authority_pubkeys(true));
    EXPECT_EQ(err.substr(0, std::string(ERR_ECDSA).size()), ERR_ECDSA) << err;

    auto s = verifiable_base();
    s.m_message_data = BaseScript(blob);
    const auto v = seal(pm, s);
    expect_reject([&] { (void)dash::share_init_verify(v.share, pm, false); },
                  std::string("share ") + ERR_ECDSA, /*prefix=*/true);
}

TEST(DashV36MessageData, SignedMessageAcceptedViaInjectedAuthoritySet) {
    IdentityGuard g;
    const auto pm = iso_params();
    const auto key = make_test_key(0x66);
    const dash::AuthorityPubkey* set[] = {&key.pk};
    const Bytes blob = signed_blob(key, key.pk);
    ASSERT_FALSE(blob.empty());
    EXPECT_EQ(dash::validate_message_data(blob, KeySpan(set)), "");

    auto s = verifiable_base();
    s.m_message_data = BaseScript(blob);
    const auto v = seal(pm, s);
    EXPECT_EQ(hex(dash::share_init_verify(v.share, pm, false, KeySpan(set))), hex(v.expected_hash));
    EXPECT_EQ(hex(dash::g_last_gentx_hash), hex(v.txid));

    // Same share under the isolated default set: not an authority key.
    expect_reject([&] { (void)dash::share_init_verify(v.share, pm, false); },
                  std::string("share ") + ERR_DECRYPT);
}

TEST(DashV36MessageData, OversizeRejected) {
    IdentityGuard g;
    const auto pm = iso_params();
    static_assert(dash::MAX_MESSAGE_DATA_WIRE_BYTES == 49 + 512);

    // (a) one message with payload_len = MAX_MESSAGE_PAYLOAD + 1 inside a
    //     maintainer envelope: parses to zero messages.
    {
        dash::ShareMessage m;
        m.msg_type = dash::MSG_NODE_STATUS;
        m.wire_flags = dash::FLAG_HAS_SIGNATURE;
        m.timestamp = 1710000000;
        m.payload.assign(dash::MAX_MESSAGE_PAYLOAD + 1, 0xab);
        m.signing_id.fill(0x11);
        m.signature = {0x30, 0x00};
        Bytes inner = {0x01, 0x00, 0x01, 0x00};
        append(inner, dash::pack_message(m));
        const Bytes blob = dash::encrypt_message_envelope(inner, dash::DONATION_PUBKEY_MAINTAINER());
        ASSERT_LE(blob.size(), dash::MAX_MESSAGE_DATA_WIRE_BYTES);
        EXPECT_EQ(dash::validate_message_data(blob, dash::authority_pubkeys(true)), ERR_NO_MSGS);
        EXPECT_EQ(dash::validate_message_data(blob), ERR_NO_MSGS);  // public wrapper, unchanged

        auto s = verifiable_base();
        s.m_message_data = BaseScript(blob);
        const auto v = seal(pm, s);
        expect_reject([&] { (void)dash::share_init_verify(v.share, pm, false); },
                      std::string("share ") + ERR_NO_MSGS);
    }
    // (b) the wire cap: 562 bytes rejects before any decryption; 561 does not
    //     hit the cap (it fails decryption instead).
    {
        auto s = verifiable_base();
        s.m_message_data = BaseScript(Bytes(dash::MAX_MESSAGE_DATA_WIRE_BYTES + 1, 0x01));
        auto v = seal(pm, s);
        expect_reject([&] { (void)dash::share_init_verify(v.share, pm, false); }, ERR_OVERSIZE);

        s.m_message_data = BaseScript(Bytes(dash::MAX_MESSAGE_DATA_WIRE_BYTES, 0x01));
        v = seal(pm, s);
        expect_reject([&] { (void)dash::share_init_verify(v.share, pm, false); },
                      std::string("share ") + ERR_DECRYPT);
    }
    // (c) the producer refuses MAX_MESSAGES_PER_SHARE + 1 messages.
    {
        const auto key = make_test_key(0x77);
        std::vector<dash::ShareMessage> msgs;
        for (size_t i = 0; i < dash::MAX_MESSAGES_PER_SHARE + 1; ++i)
            msgs.push_back(one_signed_message()[0]);
        EXPECT_TRUE(dash::create_message_data(key.sk, dash::DONATION_PUBKEY_MAINTAINER(), msgs).empty());
    }
}
