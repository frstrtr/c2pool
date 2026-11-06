// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Dash Core v24 CbTx version 4 (slice S1): codec, merkleRootAssetUnlocks,
// the version switch in build_embedded_cbtx / build_embedded_workdata, and the
// pre-emit gate. The byte-exact anchor is the first version-4 CbTx on testnet,
// block 1,578,000, captured from the LAN testnet dashd 24.0.0 (VM504).

#include <gtest/gtest.h>

#include <impl/dash/coin/asset_unlock_verify.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/coin/cbtx_asset_unlocks.hpp>
#include <impl/dash/coin/dash_txid.hpp>
#include <impl/dash/coin/vendor/assetlock.hpp>
#include <impl/dash/coin/deployment_status.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <string>
#include <vector>

using dash::coin::DashWorkData;
using dash::coin::MutableTransaction;
using dash::coin::QuorumManager;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::CSimplifiedMNList;
using dash::coin::vendor::CSimplifiedMNListEntry;

namespace {

std::vector<unsigned char> v24_unhex(const std::string& h)
{
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}

uint256 v24_leaf(uint8_t b)
{
    uint256 x;
    for (size_t i = 0; i < 32; ++i) x.data()[i] = static_cast<uint8_t>(b + i);
    return x;
}

CCbTx sample_cbtx(uint16_t version)
{
    CCbTx c;
    c.nVersion = version;
    c.nHeight = 2'580'480;
    c.merkleRootMNList = v24_leaf(0x10);
    c.merkleRootQuorums = v24_leaf(0x40);
    c.bestCLHeightDiff = 0;
    for (size_t i = 0; i < c.bestCLSignature.size(); ++i) c.bestCLSignature[i] = static_cast<uint8_t>(0xa0 + i);
    c.creditPoolBalance = 3'028'884'293'639LL;
    if (version >= CCbTx::VERSION_MERKLE_ROOT_ASSETUNLOCKS) c.merkleRootAssetUnlocks = v24_leaf(0x70);
    return c;
}

/// A type-9 asset unlock with a 145-byte payload of the given version byte.
MutableTransaction unlock_tx(uint8_t payload_version, uint8_t salt, size_t payload_size = 145)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 9;
    tx.extra_payload.assign(payload_size, salt);
    tx.extra_payload[0] = payload_version;
    bitcoin_family::coin::TxOut o;
    o.value = 1000 + salt;
    o.scriptPubKey.m_data = {0x76, 0xa9, 0x14};
    o.scriptPubKey.m_data.resize(23, salt);
    o.scriptPubKey.m_data.push_back(0x88);
    o.scriptPubKey.m_data.push_back(0xac);
    tx.vout.push_back(o);
    return tx;
}

} // namespace

// ── Codec ───────────────────────────────────────────────────────────────────

TEST(DashV24CbTx, Version4AppendsTheUnlockRootToVersion3)
{
    const auto v3 = dash::coin::encode_cbtx(sample_cbtx(3));
    const auto v4 = dash::coin::encode_cbtx(sample_cbtx(4));
    EXPECT_EQ(v3.size(), 175u);
    EXPECT_EQ(v4.size(), 207u) << "testnet 1,578,000 carries a 207-byte payload";
    ASSERT_EQ(v4.size(), v3.size() + 32);
    EXPECT_EQ(v4[0], 0x04);
    EXPECT_EQ(v3[0], 0x03);
    EXPECT_TRUE(std::equal(v3.begin() + 1, v3.end(), v4.begin() + 1)) << "fields 2..7 unchanged";
    const auto root = v24_leaf(0x70);
    EXPECT_TRUE(std::equal(v4.end() - 32, v4.end(), root.data()));

    CCbTx back;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(v4, back));
    EXPECT_EQ(back.nVersion, 4);
    EXPECT_EQ(back.merkleRootAssetUnlocks, root);
    EXPECT_EQ(back.creditPoolBalance, 3'028'884'293'639LL);
    EXPECT_EQ(dash::coin::encode_cbtx(back), v4);

    // The strict trailing check holds for version 4 too, and a version-4
    // header without its root (a version-3 body relabelled) is refused.
    auto extra = v4; extra.push_back(0);
    EXPECT_FALSE(dash::coin::vendor::parse_cbtx(extra, back));
    auto relabelled = v3; relabelled[0] = 0x04;
    EXPECT_FALSE(dash::coin::vendor::parse_cbtx(relabelled, back));
    auto v3_with_root = v4; v3_with_root[0] = 0x03;
    EXPECT_FALSE(dash::coin::vendor::parse_cbtx(v3_with_root, back));
}

TEST(DashV24CbTx, RequiredVersionTable)
{
    EXPECT_EQ(dash::coin::required_cbtx_version(true, true), 4);
    EXPECT_EQ(dash::coin::required_cbtx_version(true, false), 3);
    EXPECT_EQ(dash::coin::required_cbtx_version(false, true), 2) << "v24 alone never asks for 4";
}

// ── merkleRootAssetUnlocks ──────────────────────────────────────────────────

TEST(DashV24CbTx, AssetUnlockRootOverStableTxidUnlocksOnly)
{
    // No unlocks: null.
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(std::vector<MutableTransaction>{}), uint256::ZERO);

    // Real testnet v1 unlock (tx cb39c385..., block 1,578,005): not a leaf,
    // so that block's version-4 CbTx commits a null root.
    MutableTransaction real_v1;
    real_v1.version = 3;
    real_v1.type = 9;
    real_v1.extra_payload = v24_unhex(
        "016408000000000000be00000014141800863d622fc805c73f1dc89a18ab30ed04f736f4cd4b2328e460bd2ed7"
        "0501000084651a73098bbb4c45e978a284819bbe447d2cbd91780641017170216c7fa722467c29b14c0393e4"
        "8f3e3010d2ca0a9402b7a9bb736f4c399194e627687ff62c582769ae50076fde741c194932ff8f68d30621a4"
        "2db5f8bd2ee8182f68786357");
    ASSERT_EQ(real_v1.extra_payload.size(), 145u);
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(real_v1));
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(std::vector<MutableTransaction>{real_v1}), uint256::ZERO);

    // Version 2: the leaf is the full-serialization (instance) hash.
    const auto a = unlock_tx(2, 0x11);
    const auto b = unlock_tx(3, 0x22);
    ASSERT_TRUE(dash::coin::is_asset_unlock_with_stable_txid(a));
    ASSERT_TRUE(dash::coin::is_asset_unlock_with_stable_txid(b));
    const uint256 ha = dash::coin::tx_full_serialization_hash(a);
    const uint256 hb = dash::coin::tx_full_serialization_hash(b);
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(std::vector<MutableTransaction>{a}), ha) << "one leaf: the leaf";
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(std::vector<MutableTransaction>{a, real_v1, b}),
              dash::coin::merkle_pair_hash(ha, hb)) << "block order, v1 skipped";
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(std::vector<MutableTransaction>{b, a}),
              dash::coin::merkle_pair_hash(hb, ha));
    // Odd count duplicates the last leaf (ComputeMerkleRoot).
    const auto c = unlock_tx(2, 0x33);
    const uint256 hc = dash::coin::tx_full_serialization_hash(c);
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(std::vector<MutableTransaction>{a, b, c}),
              dash::coin::merkle_pair_hash(dash::coin::merkle_pair_hash(ha, hb),
                                           dash::coin::merkle_pair_hash(hc, hc)));

    // Not stable-txid unlocks: wrong payload size, wrong type, legacy version.
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(unlock_tx(2, 0x44, 144)));
    auto t8 = unlock_tx(2, 0x55); t8.type = 8;
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(t8));
    auto v2tx = unlock_tx(2, 0x66); v2tx.version = 2;
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(v2tx));
}

// ── The switch in the builders ──────────────────────────────────────────────

TEST(DashV24CbTx, BuildEmbeddedCbtxSwitchesOnV24Active)
{
    CSimplifiedMNListEntry e;
    e.proRegTxHash = v24_leaf(0x01);
    e.confirmedHash = v24_leaf(0x02);
    e.isValid = true;
    CSimplifiedMNList sml(std::vector<CSimplifiedMNListEntry>{e});
    QuorumManager qmgr;
    const std::array<uint8_t, 96> sig{};
    const auto pre = dash::coin::build_embedded_cbtx(2'580'478, sml, qmgr, 0, sig, 1234, nullptr);
    EXPECT_EQ(pre.nVersion, 3) << "default: pre-v24, byte-identical";
    const auto pre2 = dash::coin::build_embedded_cbtx(2'580'478, sml, qmgr, 0, sig, 1234, nullptr,
                                                      /*v24_active=*/false, v24_leaf(0x99));
    EXPECT_EQ(dash::coin::encode_cbtx(pre2), dash::coin::encode_cbtx(pre))
        << "a root is ignored while v24 is inactive";
    const auto post = dash::coin::build_embedded_cbtx(2'580'479, sml, qmgr, 0, sig, 1234, nullptr,
                                                      /*v24_active=*/true, v24_leaf(0x99));
    EXPECT_EQ(post.nVersion, 4);
    EXPECT_EQ(post.nHeight, 2'580'480);
    EXPECT_EQ(post.merkleRootAssetUnlocks, v24_leaf(0x99));
    EXPECT_EQ(dash::coin::encode_cbtx(post).size(), 207u);
}

TEST(DashV24CbTx, WorkdataCarriesVersion4AcrossTheBoundary)
{
    // A one-masternode set and an SML so the template carries a real CbTx.
    dash::coin::MnStateMachine mns;
    {
        dash::coin::MNState st;
        st.nVersion = 2;
        st.isValid = true;
        st.nRegisteredHeight = 1;
        st.scriptPayout.m_data = {0x76, 0xa9, 0x14};
        st.scriptPayout.m_data.resize(23, 0x30);
        st.scriptPayout.m_data.push_back(0x88);
        st.scriptPayout.m_data.push_back(0xac);
        st.payoutSplitProvenance = dash::coin::MNState::SPLIT_KNOWN;
        mns.load({{v24_leaf(0x01), st}}, 2'580'000);
    }
    ::core::coin::UTXOViewCache utxo(nullptr);
    dash::coin::Mempool mp;
    mp.set_utxo(&utxo);
    CSimplifiedMNListEntry e;
    e.proRegTxHash = v24_leaf(0x01);
    e.confirmedHash = v24_leaf(0x02);
    e.isValid = true;
    CSimplifiedMNList sml(std::vector<CSimplifiedMNListEntry>{e});
    QuorumManager qmgr;
    auto build = [&](uint32_t prev, bool v24) {
        return dash::coin::build_embedded_workdata(
            prev, v24_leaf(0xAB), mns, mp, 0x1b104be3u, 1'800'000'000u, 76, 16,
            1'800'000'100u, 0x20000000u, nullptr, &sml, &qmgr, 0, dash::coin::k_zero_cl_sig,
            5'000'000'000LL, nullptr, nullptr, dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr,
            dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET, /*suppress=*/true, "mempool-txs-disabled",
            nullptr, false, nullptr, false, nullptr, nullptr, nullptr, v24);
    };
    const auto last_v3 = build(2'580'478, false);   // block 2,580,479
    const auto first_v4 = build(2'580'479, true);   // block 2,580,480
    CCbTx a, b;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(last_v3.m_coinbase_payload, a));
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(first_v4.m_coinbase_payload, b));
    EXPECT_EQ(a.nVersion, 3);
    EXPECT_EQ(b.nVersion, 4);
    EXPECT_EQ(b.merkleRootAssetUnlocks, uint256::ZERO) << "no unlock rides the body";
    EXPECT_EQ(last_v3.m_coinbase_payload.size(), 175u);
    EXPECT_EQ(first_v4.m_coinbase_payload.size(), 207u);
}

TEST(DashV24CbTx, EmitGateRequiresVersion4ExactlyWhenV24IsActive)
{
    using dash::coin::V24State;
    const uint32_t H = 2'580'480;
    const uint256 prev_hash = v24_leaf(0xAB);
    std::vector<CSimplifiedMNListEntry> entries;
    for (uint8_t b : {0x01, 0x02}) {
        CSimplifiedMNListEntry e;
        e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
        e.proRegTxHash = v24_leaf(b);
        e.confirmedHash = v24_leaf(0x77);
        e.isValid = true;
        entries.push_back(e);
    }
    CSimplifiedMNList sml(std::move(entries));
    dash::coin::MNState mn;
    mn.isValid = true;
    mn.nRegisteredHeight = 2'300'000;
    mn.scriptPayout.m_data = {0x76, 0xa9, 0x14};
    mn.scriptPayout.m_data.resize(23, 0x30);
    mn.scriptPayout.m_data.push_back(0x88);
    mn.scriptPayout.m_data.push_back(0xac);
    mn.payoutSplitProvenance = dash::coin::MNState::SPLIT_KNOWN;

    dash::coin::NodeCoinState st;
    st.set_require_sml(true);
    st.sml() = sml;
    st.set_have_sml(true);
    st.set_sml_current_hash(prev_hash);
    st.mnstates().load({{v24_leaf(0x01), mn}}, H - 1);
    st.set_tip(H - 1, prev_hash, 0x1b104be3u, 1'800'000'000u, 76, 16);

    auto make = [&](bool v24, const uint256& root) {
        DashWorkData w;
        auto cb = dash::coin::build_embedded_cbtx(H - 1, sml, st.qmgr(), 0,
                                                  std::array<uint8_t, 96>{}, 0, nullptr, v24, root);
        w.m_coinbase_payload = dash::coin::encode_cbtx(cb);
        return w;
    };
    const auto w3 = make(false, uint256::ZERO);
    const auto w4 = make(true, uint256::ZERO);
    dash::coin::DeclineReport why;

    // Seam unset: the network answer. Mainnet with no status installed is
    // UNKNOWN from the earliest possible activation (2,580,480): nothing
    // emits (VERIFY-H0-S0-S1 N2, no fail-open default).
    EXPECT_FALSE(st.embedded_template_emit_ok(w3, &why));
    EXPECT_EQ(why.cause, "emit-v24-state-unknown");
    EXPECT_FALSE(st.embedded_template_emit_ok(w4, &why));
    EXPECT_EQ(why.cause, "emit-v24-state-unknown");

    // Inactive: version 3 passes, version 4 is refused.
    st.set_v24_state_fn([](uint32_t) { return V24State::INACTIVE; });
    EXPECT_TRUE(st.embedded_template_emit_ok(w3, &why)) << why.one_line();
    EXPECT_FALSE(st.embedded_template_emit_ok(w4, &why));
    EXPECT_EQ(why.cause, "emit-cbtx-version");

    st.set_v24_state_fn([&](uint32_t h) { return h >= H ? V24State::ACTIVE : V24State::INACTIVE; });
    EXPECT_TRUE(st.embedded_template_emit_ok(w4, &why)) << why.one_line();
    EXPECT_FALSE(st.embedded_template_emit_ok(w3, &why));
    EXPECT_EQ(why.cause, "emit-cbtx-version");
    EXPECT_EQ(why.value, "3");
    EXPECT_EQ(why.threshold, "4");

    // A root that is not this body's (null here) is refused.
    EXPECT_FALSE(st.embedded_template_emit_ok(make(true, v24_leaf(0x99)), &why));
    EXPECT_EQ(why.cause, "emit-asset-unlock-root-drift");

    // UNKNOWN never emits.
    st.set_v24_state_fn([](uint32_t) { return V24State::UNKNOWN; });
    EXPECT_FALSE(st.embedded_template_emit_ok(w4, &why));
    EXPECT_EQ(why.cause, "emit-v24-state-unknown");
}

// ── Testnet: the last CbTx v3 and the first CbTx v4, byte-exact ────────────
// Captured from the LAN testnet dashd 24.0.0 (VM504, `getblock <hash> 2` /
// `getblock <hash> 0`) on 2026-11-06. The coinbase txids recompute from the
// captured transactions: 1,577,999 cc81dd36..., 1,578,000 ab22dcb7...,
// 1,578,005 72e820c7....
namespace {
static const char* kTn1577999CbTx =
    "03000f141800862e14d3f60bd6dd69c31c7b8701dc06a1a9afd4468c036e1d21ea7085763a1c8b4c9add4f6d4802fd5b"
    "cf953c9a8adc35b33acd2e38fcb56d6004fe827bf16a0090d6a3e263e616bd4fc9aa6112287b0b7e70a6ecea934f2f2b"
    "639743fb6928096a412864f346e3fbcbbf53a92b5aec441346b7c8000740b6a33f43d19e0a56e6c9cd1ec2b71e77d132"
    "7f881f4f491102176f7876b6abb49b45c96833032f266b60afe4403c220000";
static const char* kTn1578000CbTx =
    "040010141800862e14d3f60bd6dd69c31c7b8701dc06a1a9afd4468c036e1d21ea7085763a1c8b4c9add4f6d4802fd5b"
    "cf953c9a8adc35b33acd2e38fcb56d6004fe827bf16a00b1b7dae9158b2650024f2fba75c75f1fc4fe202468b620aab4"
    "45e8732dd3384ead3cf3c7fcdfee23b21d35087de5ce2414f209c0cb5b1c02ebd31d62117a7b10f393e6545d9419cd47"
    "5b79f46a1526bd9c1a331ff0e0cc3fa328490e86cc019b8e84e2443c2200000000000000000000000000000000000000"
    "000000000000000000000000000000";
static const char* kTn1578005Block =
    "00000020aa55968d86542018c0fd7bfd93b3ac53eacc4350f0c730352a7a4d00a0000000dc872c2e6cde7a4a3a308b0f"
    "ec52c4d29e5d795cb92d109b3a7dde24af9bb31c6989db6a10e0001e3b0d020002030005000100000000000000000000"
    "00000000000000000000000000000000000000000000ffffffff016affffffff03e74b8c03000000001976a914b48911"
    "5851ca07a26a5ad8bac3cec3c7dbebd83188ac2ed5fd0300000000016a870ea706000000001976a91464f2b2b84f62d6"
    "8a2cd7f7f5fb2b5aa75ef716d788ac00000000cf040015141800862e14d3f60bd6dd69c31c7b8701dc06a1a9afd4468c"
    "036e1d21ea7085763a1c8b4c9add4f6d4802fd5bcf953c9a8adc35b33acd2e38fcb56d6004fe827bf16a00a631bb4c25"
    "971923f2ff0d38fb0d417094ddb6b4a896223c43f4575fc45ce39a52081977f83c1d52cb30a107cf71d05f0c0c1e601b"
    "1b219d41941bffacab04140e60297e50b1f3de70c04ecf116318d76a8829f3ea943a968dbe4ee75feebea660d213583c"
    "220000000000000000000000000000000000000000000000000000000000000000000003000900000102f35e01000000"
    "001976a9147ff380fad990f373ed92c41433395006c1fe12b688ac0000000091016408000000000000be000000141418"
    "00863d622fc805c73f1dc89a18ab30ed04f736f4cd4b2328e460bd2ed70501000084651a73098bbb4c45e978a284819b"
    "be447d2cbd91780641017170216c7fa722467c29b14c0393e48f3e3010d2ca0a9402b7a9bb736f4c399194e627687ff6"
    "2c582769ae50076fde741c194932ff8f68d30621a42db5f8bd2ee8182f68786357";

} // namespace

TEST(DashV24CbTx, TestnetLastV3AndFirstV4AreByteExact)
{
    const auto v3 = v24_unhex(kTn1577999CbTx);
    const auto v4 = v24_unhex(kTn1578000CbTx);
    ASSERT_EQ(v3.size(), 175u);
    ASSERT_EQ(v4.size(), 207u);
    CCbTx a, b;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(v3, a));
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(v4, b));

    uint256 mnlist, quorums;
    mnlist.SetHex("1c3a768570ea211d6e038c46d4afa9a106dc01877b1cc369ddd60bf6d3142e86");
    quorums.SetHex("6af17b82fe04606db5fc382ecd3ab335dc8a9a3c95cf5bfd02486d4fdd9a4c8b");
    EXPECT_EQ(a.nVersion, 3);
    EXPECT_EQ(a.nHeight, 1'577'999);
    EXPECT_EQ(a.creditPoolBalance, 37'642'182'111'072LL);   // 376421.82111072 DASH
    EXPECT_EQ(b.nVersion, 4);
    EXPECT_EQ(b.nHeight, 1'578'000);
    EXPECT_EQ(b.merkleRootMNList, mnlist);
    EXPECT_EQ(b.merkleRootQuorums, quorums);
    EXPECT_EQ(b.bestCLHeightDiff, 0u);
    EXPECT_EQ(b.creditPoolBalance, 37'642'249'077'902LL);   // 376422.49077902 DASH
    EXPECT_EQ(b.merkleRootAssetUnlocks, uint256::ZERO);
    EXPECT_EQ(dash::coin::encode_cbtx(a), v3);
    EXPECT_EQ(dash::coin::encode_cbtx(b), v4);

    // The S0 switch names exactly these versions for these heights.
    using dash::coin::DashNetwork;
    EXPECT_EQ(dash::coin::required_cbtx_version(true, dash::coin::v24_active(DashNetwork::TESTNET, 1'577'999)),
              a.nVersion);
    EXPECT_EQ(dash::coin::required_cbtx_version(true, dash::coin::v24_active(DashNetwork::TESTNET, 1'578'000)),
              b.nVersion);

    // build_embedded_cbtx assembles both payloads byte for byte from the same
    // inputs dashd used: version (from the switch), height, bestCL diff and
    // signature, creditPoolBalance, the quorum root and the unlock root over
    // the (unlock-free) body. merkleRootMNList comes from the SML, which this
    // KAT does not rebuild (as in test_dash_embedded_cbtx_byte_parity), so it
    // is taken from the chain.
    CSimplifiedMNList sml;
    QuorumManager qmgr;
    auto built3 = dash::coin::build_embedded_cbtx(
        1'577'998, sml, qmgr, /*best_cl_height=*/1'577'998, a.bestCLSignature, a.creditPoolBalance,
        &quorums, /*v24_active=*/false, uint256::ZERO);
    built3.merkleRootMNList = a.merkleRootMNList;
    EXPECT_EQ(dash::coin::encode_cbtx(built3), v3);
    auto built4 = dash::coin::build_embedded_cbtx(
        1'577'999, sml, qmgr, /*best_cl_height=*/1'577'999, b.bestCLSignature, b.creditPoolBalance,
        &quorums, /*v24_active=*/true,
        dash::coin::compute_merkle_root_asset_unlocks(std::vector<MutableTransaction>{}));
    built4.merkleRootMNList = b.merkleRootMNList;
    EXPECT_EQ(dash::coin::encode_cbtx(built4), v4) << "first CbTx v4 of testnet, byte-exact";
}

TEST(DashV24CbTx, TestnetBlockWithV1UnlockCommitsANullRoot)
{
    // Block 1,578,005: the coinbase and one version-1 asset unlock.
    const auto raw = v24_unhex(kTn1578005Block);
    ASSERT_EQ(raw.size(), 609u);
    dash::coin::BlockType blk;
    {
        ::PackStream s(raw);
        s >> blk;
        ASSERT_TRUE(s.empty());
    }
    ASSERT_EQ(blk.m_txs.size(), 2u);
    EXPECT_EQ(blk.m_txs[1].type, 9);
    EXPECT_EQ(blk.m_txs[1].extra_payload.size(), 145u);
    EXPECT_EQ(blk.m_txs[1].extra_payload[0], 1);
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(blk.m_txs[1]));
    CCbTx cb;
    ASSERT_TRUE(dash::coin::vendor::parse_cbtx(blk.m_txs[0].extra_payload, cb));
    EXPECT_EQ(cb.nVersion, 4);
    EXPECT_EQ(cb.nHeight, 1'578'005);
    EXPECT_EQ(cb.merkleRootAssetUnlocks, uint256::ZERO);
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(blk.m_txs), cb.merkleRootAssetUnlocks)
        << "our root over the real body equals the committed one";
    // The coinbase txid recomputes from our serialization.
    uint256 want;
    want.SetHex("72e820c77588ef0689858f27a115a13355489c7c5b1c933600cb8667fe0e8d8f");
    EXPECT_EQ(dash::coin::tx_full_serialization_hash(blk.m_txs[0]), want);
}


// ═══ Stable txid (Dash Core v24 IsAssetUnlockWithStableTxid; S5) ═══════════
// Cases from Dash Core v24.0.0 src/test/evo_assetlocks_tests.cpp (the
// "txid of a version 2 payload is invariant" block and the DIP-0027 worked
// examples).

namespace {

uint256 u256_one()
{
    uint256 x;
    x.data()[0] = 1;
    return x;
}
uint256 u256_two()
{
    uint256 x;
    x.data()[0] = 2;
    return x;
}

/// A type-9 asset unlock: one 1-DASH P2PKH output (pubkey hash 0x11 x 20, as
/// DIP-0027's worked example) and the given payload.
MutableTransaction stable_unlock(uint8_t version, uint64_t index, uint32_t fee,
                                 uint32_t requested_height, const uint256& quorum_hash,
                                 uint8_t sig_byte = 0)
{
    dash::coin::vendor::CAssetUnlockPayload pl;
    pl.nVersion = version;
    pl.index = index;
    pl.fee = fee;
    pl.requestedHeight = requested_height;
    pl.quorumHash = quorum_hash;
    pl.quorumSig.fill(sig_byte);
    auto ps = ::pack(pl);
    auto sp = ps.get_span();
    MutableTransaction tx;
    tx.version = 3;
    tx.type = 9;
    bitcoin_family::coin::TxOut o;
    o.value = 100'000'000;
    o.scriptPubKey.m_data = {0x76, 0xa9, 0x14};
    o.scriptPubKey.m_data.resize(23, 0x11);
    o.scriptPubKey.m_data.push_back(0x88);
    o.scriptPubKey.m_data.push_back(0xac);
    tx.vout.push_back(o);
    tx.extra_payload.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                            reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

uint256 plain_sha256d(const MutableTransaction& tx)
{
    auto ps = ::pack(tx);
    return ::Hash(ps.get_span());
}

} // namespace

TEST(DashV24StableTxid, Version1TxidIsTheFullHash)
{
    const auto v1 = stable_unlock(1, 0x11, 2000, 500, u256_one());
    ASSERT_EQ(v1.extra_payload.size(), dash::coin::kAssetUnlockPayloadSize);
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(v1));
    EXPECT_EQ(dash::coin::dash_txid(v1), dash::coin::dash_instance_hash(v1));
    EXPECT_EQ(dash::coin::dash_txid(v1), plain_sha256d(v1));
    // Version 1 commits to the signature in the txid.
    EXPECT_NE(dash::coin::dash_txid(stable_unlock(1, 0x11, 2000, 500, u256_one(), 0xab)),
              dash::coin::dash_txid(v1));
}

TEST(DashV24StableTxid, Version2TxidIgnoresTheSigningInfoOnly)
{
    const auto v2 = stable_unlock(2, 0x11, 2000, 500, u256_one());
    EXPECT_TRUE(dash::coin::is_asset_unlock_with_stable_txid(v2));
    EXPECT_NE(dash::coin::dash_txid(v2), dash::coin::dash_instance_hash(v2));
    EXPECT_EQ(dash::coin::dash_instance_hash(v2), plain_sha256d(v2));
    // Re-signing changes requestedHeight and quorumHash, not the txid.
    const auto resigned = stable_unlock(2, 0x11, 2000, 700, u256_two());
    EXPECT_EQ(dash::coin::dash_txid(resigned), dash::coin::dash_txid(v2));
    EXPECT_NE(dash::coin::dash_instance_hash(resigned), dash::coin::dash_instance_hash(v2));
    // ...and so does a different quorumSig on its own.
    const auto sig_a = stable_unlock(2, 0x11, 2000, 500, u256_one(), 0xa1);
    const auto sig_b = stable_unlock(2, 0x11, 2000, 500, u256_one(), 0xb2);
    EXPECT_EQ(dash::coin::dash_txid(sig_a), dash::coin::dash_txid(v2));
    EXPECT_EQ(dash::coin::dash_txid(sig_b), dash::coin::dash_txid(v2));
    EXPECT_NE(dash::coin::dash_instance_hash(sig_a), dash::coin::dash_instance_hash(v2));
    EXPECT_NE(dash::coin::dash_instance_hash(sig_a), dash::coin::dash_instance_hash(sig_b));
    // A different withdrawal (index or fee) has a different txid.
    EXPECT_NE(dash::coin::dash_txid(stable_unlock(2, 0x12, 2000, 500, u256_one())), dash::coin::dash_txid(v2));
    EXPECT_NE(dash::coin::dash_txid(stable_unlock(2, 0x11, 3000, 500, u256_one())), dash::coin::dash_txid(v2));
    // The txid equals the full hash with the signing info zeroed.
    EXPECT_EQ(plain_sha256d(stable_unlock(2, 0x11, 2000, 0, uint256())), dash::coin::dash_txid(v2));
    // The same rule through the Transaction type (the template's txs).
    EXPECT_EQ(dash::coin::dash_txid(MutableTransaction(dash::coin::Transaction(v2))),
              dash::coin::dash_txid(v2));
}

TEST(DashV24StableTxid, OnlyA145BytePayloadIsStable)
{
    auto short_v2 = stable_unlock(2, 0x11, 2000, 500, u256_one());
    short_v2.extra_payload.pop_back();
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(short_v2));
    EXPECT_EQ(dash::coin::dash_txid(short_v2), plain_sha256d(short_v2));
    auto not_special = stable_unlock(2, 0x11, 2000, 500, u256_one());
    not_special.version = 2;
    EXPECT_FALSE(dash::coin::is_asset_unlock_with_stable_txid(not_special));
}

// DIP-0027 dip-0027-txid-calc.py, as Dash Core v24 pins them.
TEST(DashV24StableTxid, Dip0027WorkedExamples)
{
    EXPECT_EQ(dash::coin::dash_txid(stable_unlock(2, 101, 70000, 500, u256_one())).GetHex(),
              "3c4db73c8356407a5d7c78df5045bd280f2dc4fd644b06c4bfbdead3d5ae41cf");
    EXPECT_EQ(dash::coin::dash_txid(stable_unlock(2, 123456789, 70000, 500, u256_one())).GetHex(),
              "a67e1107ae6e04b813bc8e81348266f5206d1ca93d305dc4323940e18cdbaf34");
}

// CheckAssetUnlockTx: the signed message is the FULL serialization with only
// quorumSig zeroed, so it commits to requestedHeight and quorumHash (which the
// version-2 txid excludes) and must never be the txid.
TEST(DashV24StableTxid, SignedMessageCommitsToTheSigningInfo)
{
    namespace uv = dash::coin::unlockverify;
    auto msg = [](const MutableTransaction& t) {
        dash::coin::vendor::CAssetUnlockPayload pl;
        EXPECT_TRUE(dash::coin::vendor::parse_assetunlock_payload(t.extra_payload, pl));
        return uv::unlock_msg_hash(t, pl);
    };
    const auto v2 = stable_unlock(2, 0x11, 2000, 500, u256_one(), 0x33);
    EXPECT_EQ(msg(v2), plain_sha256d(stable_unlock(2, 0x11, 2000, 500, u256_one(), 0)));
    EXPECT_NE(msg(v2), msg(stable_unlock(2, 0x11, 2000, 700, u256_two(), 0x33)));
    EXPECT_NE(msg(v2), dash::coin::dash_txid(v2));
    EXPECT_EQ(msg(stable_unlock(2, 0x11, 2000, 500, u256_one(), 0xa1)),
              msg(stable_unlock(2, 0x11, 2000, 500, u256_one(), 0xb2)));
}

// The block merkle root commits the txid (BlockMerkleRoot: GetHash), so a
// block with a version-2 unlock binds through the stable txid; the CbTx v4
// root commits the instance hash.
TEST(DashV24StableTxid, BlockBindingUsesTheStableTxid)
{
    dash::coin::BlockType b;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;
    b.m_txs.push_back(cb);
    b.m_txs.push_back(stable_unlock(2, 0x11, 2000, 500, u256_one(), 0x44));
    const uint256 id0 = dash::coin::dash_txid(b.m_txs[0]);
    b.m_merkle_root = dash::coin::compute_merkle_root({id0, dash::coin::dash_txid(b.m_txs[1])});
    EXPECT_TRUE(dash::coin::block_body_binds_to_header(b));
    b.m_merkle_root = dash::coin::compute_merkle_root({id0, dash::coin::dash_instance_hash(b.m_txs[1])});
    EXPECT_FALSE(dash::coin::block_body_binds_to_header(b));
    // CbTx v4 root: the single leaf is the instance hash.
    EXPECT_EQ(dash::coin::compute_merkle_root_asset_unlocks(b.m_txs),
              dash::coin::dash_instance_hash(b.m_txs[1]));
}

TEST(DashV24StableTxid, RealTestnetBlock1578005StillBinds)
{
    const auto raw = v24_unhex(kTn1578005Block);
    dash::coin::BlockType blk;
    ::PackStream s(raw);
    s >> blk;
    ASSERT_TRUE(s.empty());
    EXPECT_TRUE(dash::coin::block_body_binds_to_header(blk));
    EXPECT_EQ(dash::coin::dash_txid(blk.m_txs[1]), dash::coin::dash_instance_hash(blk.m_txs[1]))
        << "a version-1 unlock keeps its full-hash txid";
}
