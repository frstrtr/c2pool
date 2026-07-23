// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
// DASH share-v16 BYTE-PARITY KAT — real captured-corpus vectors (T1c gate).
//
// The 2026-07-21 join-lane audit flagged that test_dash_conformance.cpp only
// exercises SYNTHETIC / out-of-band merkle vectors — there was no byte-parity
// test against a REAL p2pool-dash node. This KAT closes that gap: it pins
// c2pool's DASH v16 share serialization to the CANONICAL fork wire bytes.
//
// Corpus: test/data/dash_oracle_corpus.hpp — 29 distinct shares captured off a
// controlled p2pool-dash node JOINED to the live public sharechain (share-v16 /
// min-proto-1700), each `raw` cross-validated byte-identical across 4 peers.
//
// The invariant proved per vector (the T1c byte-parity gate):
//     serialize( load_share( raw ) )  ==  raw          (round-trip byte parity)
// i.e. c2pool parses the canonical wire bytes AND re-emits them byte-for-byte
// — the exact condition for c2pool to relay a share the fork will VERIFY_PASS.
// Plus semantic cross-checks (prev_hash / donation / new_tx_count / pubkey_hash
// -> payout_script) against the fork's independently-parsed SHARE_RECV fields.
// ═══════════════════════════════════════════════════════════════════════════

#include <gtest/gtest.h>

#include <impl/dash/share_chain.hpp>   // dash::load_share, dash::ShareType, DashShare
#include <sharechain/share.hpp>        // chain::RawShare
#include <core/pack.hpp>               // PackStream
#include <core/pack_types.hpp>
#include <core/uint256.hpp>
#include <core/netaddress.hpp>         // NetService

#include "data/dash_oracle_corpus.hpp"

#include <cctype>
#include <string>
#include <vector>

namespace {

std::vector<unsigned char> from_hex(const std::string& h)
{
    std::vector<unsigned char> out;
    out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return out;
}

std::string to_hex(const unsigned char* p, size_t n)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 0xf]); }
    return s;
}

} // namespace

// One parametrized test instance per captured canonical share.
class DashOracleByteParity : public ::testing::TestWithParam<dash_oracle_corpus::OracleVector> {};

TEST_P(DashOracleByteParity, RoundTripsCanonicalWireBytes)
{
    const auto& v = GetParam();

    // ── Parse the full wire entry: [VarInt type][VarStr contents] (chain::RawShare).
    auto raw_bytes = from_hex(v.raw_hex);
    ASSERT_FALSE(raw_bytes.empty());

    PackStream stream(raw_bytes);
    chain::RawShare rshare;
    rshare.Unserialize(stream);

    EXPECT_EQ(rshare.type, 16u) << "wire share type must be v16";
    EXPECT_EQ(rshare.type, v.share_version);

    // Canonical inner contents (post length-prefix) — the byte-parity target.
    const std::vector<unsigned char> canonical_contents = rshare.contents.m_data;
    ASSERT_FALSE(canonical_contents.empty());

    // ── Deserialize contents into a concrete DashShare via the production path.
    dash::ShareType share = dash::load_share(rshare, NetService{});

    // ── Re-serialize through DashFormatter::Write and demand byte identity.
    PackStream out;
    share.Serialize(out);
    const std::string got = to_hex(reinterpret_cast<unsigned char*>(out.data()), out.size());
    const std::string want = to_hex(canonical_contents.data(), canonical_contents.size());

    EXPECT_EQ(got, want)
        << "share " << v.share_hash << ": re-serialized contents diverge from canonical wire bytes";

    // ── Semantic cross-checks vs the fork's independently-parsed SHARE_RECV.
    share.ACTION({
        if constexpr (std::is_same_v<share_t, dash::DashShare>) {
            EXPECT_EQ(obj->m_donation, v.donation)
                << "share " << v.share_hash << ": donation";
            EXPECT_EQ(obj->m_new_transaction_hashes.size(), v.new_tx_count)
                << "share " << v.share_hash << ": new_tx_count";
            // prev_hash: uint256 GetHex() is display (reversed) order == oracle log.
            EXPECT_EQ(obj->m_prev_hash.GetHex(), std::string(v.prev_hash))
                << "share " << v.share_hash << ": prev_hash";
            // pubkey_hash: internal bytes go verbatim into the P2PKH scriptPubKey
            // (wire order); the oracle logs payout_pubkey_hash in display order.
            auto pkh = obj->m_pubkey_hash.GetChars();
            const std::string pkh_wire = to_hex(pkh.data(), pkh.size());
            EXPECT_EQ("76a914" + pkh_wire + "88ac", std::string(v.payout_script))
                << "share " << v.share_hash << ": payout_script";
            EXPECT_EQ(obj->m_pubkey_hash.GetHex(), std::string(v.payout_pubkey_hash))
                << "share " << v.share_hash << ": payout_pubkey_hash (display)";
        }
    });

    share.destroy();
}

INSTANTIATE_TEST_SUITE_P(
    OracleGateCorpus,
    DashOracleByteParity,
    ::testing::ValuesIn(dash_oracle_corpus::vectors()));

// Guard: the corpus must actually be present and non-trivial, so a stripped or
// empty header can never make the gate vacuously pass.
TEST(DashOracleByteParityCorpus, IsPresentAndNonTrivial)
{
    ASSERT_GE(dash_oracle_corpus::vectors().size(), 20u)
        << "oracle byte-parity corpus missing or too small";
    for (const auto& v : dash_oracle_corpus::vectors())
        EXPECT_EQ(v.share_version, 16u);
}
