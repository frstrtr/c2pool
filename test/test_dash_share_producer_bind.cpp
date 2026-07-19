// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH share-producer BIND KATs (mint campaign slice 2/3).
//
// Exercises share_producer_bind.hpp -- the adapter that turns a stratum-found
// solution (DASHWorkSource::MintShareInputs) plus the per-job context frozen at
// job assembly (FrozenMintJob) into a fully-built, self-verified DashShare and
// returns its X11 share hash. This is the wire-in half of the mint campaign;
// nothing here touches src/core or wires into --run (that is slice 3/3).
//
// Coverage:
//   (a) parse_min_header_80: 80-byte canonical header -> SmallBlockHeaderType
//       (merkle_root sliced off); short buffer -> nullopt (fail-closed).
//   (b) pubkey_hash_from_p2pkh: exact inverse of pubkey_hash_to_script2;
//       non-canonical script -> nullopt (fail-closed).
//   (c) build_mint_share: genesis mint reproduces the DIRECT
//       generate_prospective_share_info + build_share path byte-for-byte
//       (share hash, ref_hash, gentx_hash), proving the MintShareInputs +
//       FrozenMintJob -> ProducerJobInputs mapping is faithful.
//   (d) the X11 integrity gate: a solution whose pow_hash does not match the
//       rebuilt share hash is DECLINED (nullopt / null hash), never minted.
//   (e) make_producer_mint_fn: binds the transform into a MintShareFn and
//       returns the minted hash on success / null on decline.

#include <gtest/gtest.h>

#include <impl/dash/share_producer_bind.hpp>
#include <impl/dash/share_producer.hpp>
#include <impl/dash/share_chain.hpp>
#include <impl/dash/share_check.hpp>       // dash::pubkey_hash_to_script2
#include <impl/dash/share_types.hpp>       // dash::StaleInfo, dash::PackedPayment
#include <impl/dash/params.hpp>            // dash::make_coin_params
#include <impl/dash/stratum/work_source.hpp>
#include <impl/bitcoin_family/coin/base_block.hpp>

#include <core/coin_params.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <optional>
#include <vector>

namespace {

using dash::stratum::parse_min_header_80;
using dash::stratum::pubkey_hash_from_p2pkh;
using dash::stratum::FrozenMintJob;
using dash::stratum::build_mint_share;
using dash::stratum::make_producer_mint_fn;
using MintShareInputs = dash::stratum::DASHWorkSource::MintShareInputs;

uint256 h256_tag(uint8_t tag) {
    std::vector<unsigned char> v(32, 0x00);
    v[0] = tag; v[31] = 0xa5;
    return uint256(v);
}

uint160 h160_uniform(uint8_t tag) {
    return uint160(std::vector<unsigned char>(20, tag));
}

bitcoin_family::coin::BlockHeaderType make_full_header() {
    bitcoin_family::coin::BlockHeaderType h;
    h.m_version = 536870912;                 // BIP9 base version (fixed 4 bytes on the wire)
    h.m_previous_block = h256_tag(0x77);
    h.m_merkle_root = h256_tag(0x99);        // sliced off by the small header
    h.m_timestamp = 1700000005;
    h.m_bits = 0x1b00ffffu;
    h.m_nonce = 0xdeadbeefu;
    return h;
}

std::vector<unsigned char> serialize80(const bitcoin_family::coin::BlockHeaderType& h) {
    PackStream s;
    s << h;
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(s.data()),
        reinterpret_cast<const unsigned char*>(s.data()) + s.size());
}

// Shared genesis fixture: chosen job context + solved header, and the DIRECT
// (non-adapter) build of the same inputs to compare against.
struct GenesisFixture {
    core::CoinParams params = dash::make_coin_params(false);
    dash::ShareChain chain;
    FrozenMintJob job;
    uint160 pubkey_hash = h160_uniform(0x22);
    uint64_t subsidy = 500000000;
    std::vector<unsigned char> header_bytes;
    dash::producer::BuiltShare expected;

    GenesisFixture() {
        job.coinbase_scriptSig = {0x51, 0x52};
        job.share_nonce = 0;
        job.donation = 0;
        job.desired_version = 16;
        job.desired_timestamp = 1700000005;
        job.desired_target = params.max_target;
        job.last_txout_nonce = 0x0102030405060708ull;

        auto full = make_full_header();
        header_bytes = serialize80(full);

        dash::producer::ProducerJobInputs pin;
        pin.prev_share_hash    = uint256();
        pin.coinbase_scriptSig = job.coinbase_scriptSig;
        pin.share_nonce        = job.share_nonce;
        pin.pubkey_hash        = pubkey_hash;
        pin.subsidy            = subsidy;
        pin.donation           = job.donation;
        pin.desired_version    = job.desired_version;
        pin.desired_timestamp  = job.desired_timestamp;
        pin.desired_target     = job.desired_target;
        auto info = dash::producer::generate_prospective_share_info(chain, params, pin);
        auto small = static_cast<bitcoin_family::coin::SmallBlockHeaderType&>(full);
        expected = dash::producer::build_share(
            chain, params, info, small, job.last_txout_nonce, /*check_pow=*/false);
    }

    MintShareInputs good_inputs() const {
        MintShareInputs in;
        in.header_bytes    = header_bytes;
        in.subsidy         = subsidy;
        in.prev_share_hash = uint256();
        in.payout_script   = dash::pubkey_hash_to_script2(pubkey_hash);
        in.pow_hash        = expected.share.m_hash;
        return in;
    }
};

}  // namespace

// (a) parse_min_header_80 -----------------------------------------------------
TEST(DashShareProducerBind, ParseMinHeader80SlicesMerkleRoot) {
    auto full = make_full_header();
    auto bytes = serialize80(full);
    ASSERT_EQ(bytes.size(), 80u);

    auto parsed = parse_min_header_80(bytes);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->m_version, full.m_version);
    EXPECT_EQ(parsed->m_previous_block, full.m_previous_block);
    EXPECT_EQ(parsed->m_timestamp, full.m_timestamp);
    EXPECT_EQ(parsed->m_bits, full.m_bits);
    EXPECT_EQ(parsed->m_nonce, full.m_nonce);

    // Short buffer -> fail-closed.
    bytes.resize(40);
    EXPECT_FALSE(parse_min_header_80(bytes).has_value());
    EXPECT_FALSE(parse_min_header_80({}).has_value());
}

// (b) pubkey_hash_from_p2pkh --------------------------------------------------
TEST(DashShareProducerBind, PubkeyHashP2PKHRoundTrip) {
    const uint160 h = h160_uniform(0x3c);
    auto script = dash::pubkey_hash_to_script2(h);
    ASSERT_EQ(script.size(), 25u);

    auto back = pubkey_hash_from_p2pkh(script);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(*back, h);

    // Non-canonical scripts -> fail-closed.
    EXPECT_FALSE(pubkey_hash_from_p2pkh({}).has_value());
    EXPECT_FALSE(pubkey_hash_from_p2pkh(std::vector<unsigned char>(25, 0x00)).has_value());
    auto wrong_len = script; wrong_len.pop_back();
    EXPECT_FALSE(pubkey_hash_from_p2pkh(wrong_len).has_value());
    auto wrong_tail = script; wrong_tail[24] = 0x00;  // not OP_CHECKSIG
    EXPECT_FALSE(pubkey_hash_from_p2pkh(wrong_tail).has_value());
}

// (c) build_mint_share reproduces the direct producer path --------------------
TEST(DashShareProducerBind, GenesisMintMatchesDirectBuild) {
    GenesisFixture fx;
    ASSERT_FALSE(fx.expected.share.m_hash.IsNull());

    auto got = build_mint_share(fx.chain, fx.params, fx.good_inputs(), fx.job);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->share.m_hash, fx.expected.share.m_hash);
    EXPECT_EQ(got->ref_hash, fx.expected.ref_hash);
    EXPECT_EQ(got->gentx_hash, fx.expected.gentx_hash);
}

// (d) the X11 integrity gate + fail-closed inputs -----------------------------
TEST(DashShareProducerBind, DeclinesOnPowMismatchAndMalformedInputs) {
    GenesisFixture fx;

    // pow_hash does not reproduce the rebuilt share -> DECLINE.
    auto in = fx.good_inputs();
    in.pow_hash = h256_tag(0xEE);
    EXPECT_FALSE(build_mint_share(fx.chain, fx.params, in, fx.job).has_value());

    // Non-P2PKH payout script -> DECLINE.
    in = fx.good_inputs();
    in.payout_script = {0x00, 0x14};
    EXPECT_FALSE(build_mint_share(fx.chain, fx.params, in, fx.job).has_value());

    // Truncated header -> DECLINE.
    in = fx.good_inputs();
    in.header_bytes.resize(40);
    EXPECT_FALSE(build_mint_share(fx.chain, fx.params, in, fx.job).has_value());
}

// (e) make_producer_mint_fn ---------------------------------------------------
TEST(DashShareProducerBind, MintFnBindsAndReturnsHashOrNull) {
    GenesisFixture fx;
    auto fn = make_producer_mint_fn(
        fx.chain, fx.params,
        [&fx](const MintShareInputs&) { return fx.job; });

    EXPECT_EQ(fn(fx.good_inputs()), fx.expected.share.m_hash);

    auto bad = fx.good_inputs();
    bad.pow_hash = h256_tag(0xEE);
    EXPECT_TRUE(fn(bad).IsNull());
}
