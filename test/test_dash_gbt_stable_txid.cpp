// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The txids a dashd getblocktemplate reply is read with (coin/gbt_transactions.hpp)
// and the body memo of build_producer_job (mint_runloop.hpp), on real Dash Core
// 24.0.2 testnet blocks that carry version 2 asset unlocks.
//
// A version 2 asset unlock's txid (CTransaction::GetHash) zeroes the quorum
// signing info before hashing; the SHA256d of its whole bytes is its instance
// hash. A template read with instance hashes yields stratum branches, and so a
// header, that dashd rejects as bad-txnmrklroot.
//
//   * block 1599900 (16 txs, 11 v2 unlocks) and block 1599924 (48 txs, 9 v2
//     unlocks, the block that closed the height of a live dashd-fallback
//     template whose proposal dashd rejected as bad-txnmrklroot and accepted
//     with the stable-txid root): every non-coinbase tx is fed through the
//     reader as a getblocktemplate entry {data, hash}; m_tx_hashes must equal
//     dashd's txids, the fold [coinbase txid] + m_tx_hashes and the stratum
//     branch ascent must equal the header's committed root, and the old rule
//     (SHA256d of the bytes) must give the instance-hash root instead;
//   * with "hash" omitted, the reader still derives the stable txid itself;
//   * when the bytes do not deserialize, dashd's "hash" is the txid;
//   * a "hash" that disagrees with the dash_txid of the bytes is served (it is
//     Core's GetHash of those bytes) and the disagreement is reported;
//   * the embedded build's ids (dash_txid of the same txs) fold to the same
//     body root as the reader's, so the embedded-vs-dashd tx-root xcheck
//     compares like with like;
//   * TemplateBodiesMemo never serves a re-signed unlock (same stable txid,
//     other bytes) with its previous instance's bytes.

#include <gtest/gtest.h>

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/block_producer.hpp>    // compute_merkle_root, coinbase_txid
#include <impl/dash/coin/dash_txid.hpp>
#include <impl/dash/coin/gbt_transactions.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coinbase_builder.hpp>       // merkle_branches_raw, sha256d
#include <impl/dash/mint_runloop.hpp>           // TemplateBodiesMemo

#include <btclibs/util/strencodings.h>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "data/dash_block_testnet_1599900.inc"
#include "data/dash_block_testnet_1599924.inc"
#include "data/dash_block_testnet_txids_1599900_1599924.inc"

namespace {

using dash::coin::DashWorkData;
using dash::coin::GbtEntryTxid;
using dash::coin::MutableTransaction;

struct RealBlock {
    std::vector<unsigned char>  bytes;
    dash::coin::BlockType       block;
    std::vector<std::string>    tx_hex;     // every tx, block order, coinbase first
    std::vector<uint256>        dashd_txids;
    uint256                     header_root;
};

std::string strip_newlines(const char* text)
{
    std::string hex;
    for (const char* p = text; *p; ++p)
        if (*p != '\n' && *p != '\r') hex.push_back(*p);
    return hex;
}

std::string tx_to_hex(const MutableTransaction& tx)
{
    auto packed = ::pack(tx);
    auto sp = packed.get_span();
    return HexStr(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()), sp.size()));
}

template <size_t N>
RealBlock load(const char* block_text, const char* const (&txids)[N], const char* root_hex)
{
    RealBlock rb;
    rb.bytes = ParseHex(strip_newlines(block_text));
    PackStream s(rb.bytes);
    s >> rb.block;
    EXPECT_TRUE(s.empty()) << "trailing bytes after the block";
    for (const auto& tx : rb.block.m_txs) rb.tx_hex.push_back(tx_to_hex(tx));
    for (const char* t : txids) rb.dashd_txids.push_back(uint256S(t));
    rb.header_root = rb.block.m_merkle_root;
    EXPECT_EQ(rb.header_root, uint256S(root_hex)) << "fixture header vs dashd's merkleroot";
    EXPECT_EQ(rb.tx_hex.size(), rb.dashd_txids.size());
    return rb;
}

const RealBlock& block_1599900()
{
    static const RealBlock rb = load(kDashBlockTestnet1599900, kDashBlockTestnet1599900Txids,
                                     kDashBlockTestnet1599900MerkleRoot);
    return rb;
}

const RealBlock& block_1599924()
{
    static const RealBlock rb = load(kDashBlockTestnet1599924, kDashBlockTestnet1599924Txids,
                                     kDashBlockTestnet1599924MerkleRoot);
    return rb;
}

// The block's non-coinbase txs as getblocktemplate entries.
nlohmann::json gbt_entries(const RealBlock& rb, bool with_hash)
{
    nlohmann::json txs = nlohmann::json::array();
    for (size_t i = 1; i < rb.tx_hex.size(); ++i) {
        nlohmann::json e = {{"data", rb.tx_hex[i]}, {"fee", 0}, {"depends", nlohmann::json::array()}};
        if (with_hash) e["hash"] = rb.dashd_txids[i].GetHex();
        txs.push_back(std::move(e));
    }
    return txs;
}

uint256 sha256d_bytes(const std::vector<unsigned char>& b)
{
    return dash::coin::dash_sha256d(std::span<const unsigned char>(b.data(), b.size()));
}

uint256 header_root_over(const RealBlock& rb, const std::vector<uint256>& non_coinbase_ids)
{
    std::vector<uint256> leaves;
    leaves.push_back(dash::coin::coinbase_txid(ParseHex(rb.tx_hex[0])));
    leaves.insert(leaves.end(), non_coinbase_ids.begin(), non_coinbase_ids.end());
    return dash::coin::compute_merkle_root(leaves);
}

// What a miner hashes: the coinbase txid ascended through the stratum branch
// built from the template's ids (work_source.cpp get_stratum_merkle_branches).
uint256 stratum_ascent(const RealBlock& rb, const std::vector<uint256>& non_coinbase_ids)
{
    std::vector<uint256> leaves;
    leaves.push_back(uint256::ZERO);
    leaves.insert(leaves.end(), non_coinbase_ids.begin(), non_coinbase_ids.end());
    uint256 root = dash::coin::coinbase_txid(ParseHex(rb.tx_hex[0]));
    for (const auto& b : dash::coinbase::merkle_branches_raw(leaves)) {
        unsigned char buf[64];
        std::memcpy(buf, root.data(), 32);
        std::memcpy(buf + 32, b.data(), 32);
        root = dash::coinbase::sha256d(std::span<const unsigned char>(buf, 64));
    }
    return root;
}

size_t count_v2_unlocks(const RealBlock& rb)
{
    size_t n = 0;
    for (const auto& tx : rb.block.m_txs) n += dash::coin::is_asset_unlock_with_stable_txid(tx) ? 1 : 0;
    return n;
}

void expect_reader_matches_dashd(const RealBlock& rb, bool with_hash)
{
    DashWorkData w;
    const auto rep = dash::coin::append_gbt_transactions(gbt_entries(rb, with_hash), w);
    EXPECT_TRUE(rep.disagreements.empty());
    EXPECT_TRUE(rep.parse_failures.empty());
    ASSERT_EQ(w.m_tx_hashes.size(), rb.dashd_txids.size() - 1);
    ASSERT_EQ(w.m_tx_data_hex.size(), w.m_tx_hashes.size());
    ASSERT_EQ(w.m_txs.size(), w.m_tx_hashes.size());
    ASSERT_EQ(w.m_tx_fees.size(), w.m_tx_hashes.size());
    for (size_t i = 0; i < w.m_tx_hashes.size(); ++i) {
        EXPECT_EQ(w.m_tx_hashes[i], rb.dashd_txids[i + 1]) << "entry " << i;
        EXPECT_EQ(w.m_tx_data_hex[i], rb.tx_hex[i + 1]) << "entry " << i;
    }
    EXPECT_EQ(header_root_over(rb, w.m_tx_hashes), rb.header_root);
    EXPECT_EQ(stratum_ascent(rb, w.m_tx_hashes), rb.header_root);
}

// ── The fixtures are what they claim ─────────────────────────────────────────

TEST(DashGbtStableTxid, FixturesAreRealV2UnlockBlocks)
{
    for (const RealBlock* rb : {&block_1599900(), &block_1599924()}) {
        // The codec round-trips the block byte for byte.
        std::vector<unsigned char> re;
        {
            auto packed = ::pack(rb->block);
            auto sp = packed.get_span();
            re.assign(reinterpret_cast<const unsigned char*>(sp.data()),
                      reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
        }
        EXPECT_EQ(re, rb->bytes);
        // dashd's txids are dash_txid of each tx, and differ from the SHA256d of
        // the bytes exactly for the v2 unlocks.
        size_t differ = 0;
        for (size_t i = 0; i < rb->block.m_txs.size(); ++i) {
            const auto& tx = rb->block.m_txs[i];
            EXPECT_EQ(dash::coin::dash_txid(tx), rb->dashd_txids[i]) << "tx " << i;
            const bool v2 = dash::coin::is_asset_unlock_with_stable_txid(tx);
            EXPECT_EQ(sha256d_bytes(ParseHex(rb->tx_hex[i])) != rb->dashd_txids[i], v2) << "tx " << i;
            differ += v2 ? 1 : 0;
        }
        EXPECT_GT(differ, 0u);
    }
    EXPECT_EQ(count_v2_unlocks(block_1599900()), 11u);
    EXPECT_EQ(count_v2_unlocks(block_1599924()), 9u);
}

// ── The reader on real bytes ─────────────────────────────────────────────────

TEST(DashGbtStableTxid, Block1599900EntriesReadWithDashdTxids)
{
    const auto& rb = block_1599900();
    expect_reader_matches_dashd(rb, /*with_hash=*/true);
    EXPECT_EQ(rb.header_root.GetHex(),
              "abd5d782cd7d0071a6f63472426074053eb5703dd74d70fff500da4d22c0f827");

    // The first v2 unlock, by name: dashd's txid, not its instance hash.
    DashWorkData w;
    dash::coin::append_gbt_transactions(gbt_entries(rb, true), w);
    EXPECT_EQ(w.m_tx_hashes[4].GetHex(),
              "1dcf9b62604bd53c454e4880f6be1c51606455da1f8829cfd0d112978527c422");
    EXPECT_EQ(sha256d_bytes(ParseHex(w.m_tx_data_hex[4])).GetHex(),
              "ec92ca6b7ca32430c9cbe4e1365673b97526a76ea0fa2fa30a277fc44ce78e3a");
}

TEST(DashGbtStableTxid, Block1599924EntriesReadWithDashdTxids)
{
    const auto& rb = block_1599924();
    expect_reader_matches_dashd(rb, /*with_hash=*/true);
    EXPECT_EQ(rb.header_root.GetHex(),
              "af091c1bccc019d924511cdfa4f4925bd80752a23fa18694b4dbfea02acf71a2");
}

// The old rule (the SHA256d of each entry's bytes) folds the instance-hash root,
// which dashd rejects as bad-txnmrklroot; the fixed reader folds the committed root.
TEST(DashGbtStableTxid, OldRuleFoldsTheRejectedRootFixedRuleTheCommittedOne)
{
    struct Case { const RealBlock* rb; const char* instance_root; };
    const Case cases[] = {
        {&block_1599900(), "257a090830b9c2452db3c359f9c4e0efc0db0eb16c50d4a5c18d571c77e06989"},
        {&block_1599924(), "f928286202c3e407f5b9938fba9b3ca3007a02c692b7dbc9f3e04489763859ea"},
    };
    for (const auto& c : cases) {
        std::vector<uint256> old_ids;
        for (size_t i = 1; i < c.rb->tx_hex.size(); ++i)
            old_ids.push_back(sha256d_bytes(ParseHex(c.rb->tx_hex[i])));
        const uint256 old_root = header_root_over(*c.rb, old_ids);
        EXPECT_EQ(old_root.GetHex(), c.instance_root);
        EXPECT_NE(old_root, c.rb->header_root);
        EXPECT_NE(stratum_ascent(*c.rb, old_ids), c.rb->header_root);

        DashWorkData w;
        dash::coin::append_gbt_transactions(gbt_entries(*c.rb, true), w);
        EXPECT_EQ(header_root_over(*c.rb, w.m_tx_hashes), c.rb->header_root);
    }
}

// With "hash" omitted the reader derives the stable txid itself.
TEST(DashGbtStableTxid, WithoutGbtHashTheStableTxidIsDerived)
{
    expect_reader_matches_dashd(block_1599900(), /*with_hash=*/false);
    expect_reader_matches_dashd(block_1599924(), /*with_hash=*/false);
}

// ── The per-entry rule ───────────────────────────────────────────────────────

TEST(DashGbtStableTxid, UnparsableBytesUseDashdHash)
{
    const auto& rb = block_1599900();
    const std::string unlock_hex = rb.tx_hex[5];
    const uint256 dashd_id = rb.dashd_txids[5];
    ASSERT_TRUE(dash::coin::is_asset_unlock_with_stable_txid(rb.block.m_txs[5]));

    // Truncated bytes: the codec throws.
    const std::string truncated = unlock_hex.substr(0, unlock_hex.size() - 20);
    // Trailing bytes: the codec reads a tx and leaves bytes over.
    const std::string trailing = unlock_hex + "00";
    for (const std::string& bad : {truncated, trailing}) {
        DashWorkData w;
        nlohmann::json txs = nlohmann::json::array({{{"data", bad}, {"hash", dashd_id.GetHex()}}});
        const auto rep = dash::coin::append_gbt_transactions(txs, w);
        ASSERT_EQ(w.m_tx_hashes.size(), 1u);
        EXPECT_EQ(w.m_tx_hashes[0], dashd_id);
        ASSERT_EQ(rep.parse_failures.size(), 1u);
        EXPECT_TRUE(rep.parse_failures[0].used_gbt_hash);
        EXPECT_EQ(w.m_txs.size(), 1u);
        EXPECT_EQ(w.m_tx_data_hex[0], bad);   // the body is kept verbatim

        // Neither a parse nor a "hash": the SHA256d of the bytes, reported.
        DashWorkData w2;
        nlohmann::json bare = nlohmann::json::array({{{"data", bad}}});
        const auto rep2 = dash::coin::append_gbt_transactions(bare, w2);
        ASSERT_EQ(w2.m_tx_hashes.size(), 1u);
        EXPECT_EQ(w2.m_tx_hashes[0], sha256d_bytes(ParseHex(bad)));
        ASSERT_EQ(rep2.parse_failures.size(), 1u);
        EXPECT_FALSE(rep2.parse_failures[0].used_gbt_hash);
    }

    const auto raw = ParseHex(truncated);
    const auto r = dash::coin::gbt_entry_txid(nullptr, dashd_id, std::span<const unsigned char>(raw));
    EXPECT_EQ(r.txid, dashd_id);
    EXPECT_EQ(r.source, GbtEntryTxid::Source::GbtHash);
}

// dashd's "hash" is Core's GetHash of the very bytes the body carries: on a
// disagreement it is served, and the node's own derivation is only reported.
TEST(DashGbtStableTxid, DisagreeingHashIsReportedAndDashdHashDecides)
{
    const auto& rb = block_1599900();
    // A "hash" other than dash_txid of the bytes (here: the instance hash).
    const uint256 other = sha256d_bytes(ParseHex(rb.tx_hex[5]));
    ASSERT_NE(other, rb.dashd_txids[5]);
    DashWorkData w;
    nlohmann::json txs = nlohmann::json::array({
        {{"data", rb.tx_hex[1]}, {"hash", rb.dashd_txids[1].GetHex()}},   // agrees
        {{"data", rb.tx_hex[5]}, {"hash", other.GetHex()}}});             // disagrees
    const auto rep = dash::coin::append_gbt_transactions(txs, w);
    ASSERT_EQ(w.m_tx_hashes.size(), 2u);
    EXPECT_EQ(w.m_tx_hashes[0], rb.dashd_txids[1]);
    EXPECT_EQ(w.m_tx_hashes[1], other);
    ASSERT_EQ(rep.disagreements.size(), 1u);
    EXPECT_EQ(rep.disagreements[0].index, 1u);
    EXPECT_EQ(rep.disagreements[0].gbt_hash, other);
    EXPECT_EQ(rep.disagreements[0].derived_txid, rb.dashd_txids[5]);
    EXPECT_TRUE(rep.parse_failures.empty());

    const auto raw = ParseHex(rb.tx_hex[5]);
    const auto& tx = rb.block.m_txs[5];
    const auto r = dash::coin::gbt_entry_txid(&tx, other, std::span<const unsigned char>(raw));
    EXPECT_EQ(r.txid, other);
    EXPECT_EQ(r.source, GbtEntryTxid::Source::GbtHash);
    EXPECT_EQ(r.derived, rb.dashd_txids[5]);
    EXPECT_TRUE(r.hash_disagrees);
    // No "hash": the bytes decide.
    const auto r2 = dash::coin::gbt_entry_txid(&tx, std::nullopt, std::span<const unsigned char>(raw));
    EXPECT_EQ(r2.txid, rb.dashd_txids[5]);
    EXPECT_EQ(r2.source, GbtEntryTxid::Source::ParsedTx);
    EXPECT_FALSE(r2.hash_disagrees);
}

TEST(DashGbtStableTxid, BareStringEntriesAndEmptyDataAreHandled)
{
    const auto& rb = block_1599900();
    DashWorkData w;
    nlohmann::json txs = nlohmann::json::array({rb.tx_hex[5], {{"data", ""}}, {{"hash", "00"}}});
    dash::coin::append_gbt_transactions(txs, w);
    ASSERT_EQ(w.m_tx_hashes.size(), 1u);   // the two entries without bytes are skipped
    EXPECT_EQ(w.m_tx_hashes[0], rb.dashd_txids[5]);
}

// ── The embedded-vs-dashd tx-root xcheck compares like with like ─────────────
// work_source.cpp folds compute_merkle_root(m_tx_hashes) of the embedded build
// (dash_txid of each selected tx, embedded_gbt.hpp) against the same fold of the
// dashd template read here. Over the same txs both folds must agree.
TEST(DashGbtStableTxid, EmbeddedAndDashdBodyFoldsAgreeOverTheSameTxs)
{
    for (const RealBlock* rb : {&block_1599900(), &block_1599924()}) {
        std::vector<uint256> embedded_ids;
        for (size_t i = 1; i < rb->block.m_txs.size(); ++i)
            embedded_ids.push_back(dash::coin::dash_txid(rb->block.m_txs[i]));
        DashWorkData dref;
        dash::coin::append_gbt_transactions(gbt_entries(*rb, true), dref);
        EXPECT_EQ(dash::coin::compute_merkle_root(embedded_ids),
                  dash::coin::compute_merkle_root(dref.m_tx_hashes));
    }
}

// ── TemplateBodiesMemo: a re-signed unlock is never served with old bytes ────

// Another instance of the same withdrawal: one byte of its quorum signature
// changed. Same stable txid, other bytes, other instance hash.
std::string resigned(const std::string& unlock_hex)
{
    std::string h = unlock_hex;
    const size_t pos = h.size() - 2;             // the last byte of quorumSig
    h[pos] = h[pos] == 'a' ? 'b' : 'a';
    return h;
}

DashWorkData template_with(const std::vector<std::string>& bodies)
{
    DashWorkData w;
    nlohmann::json txs = nlohmann::json::array();
    for (const auto& b : bodies) txs.push_back(nlohmann::json{{"data", b}});
    dash::coin::append_gbt_transactions(txs, w);
    return w;
}

TEST(DashGbtStableTxid, ResignedUnlockSharesTheTxidNotTheBytes)
{
    const auto& rb = block_1599900();
    const std::string a = rb.tx_hex[5];
    const std::string b = resigned(a);
    ASSERT_NE(a, b);
    MutableTransaction ta, tb;
    { PackStream s(ParseHex(a)); s >> ta; }
    { PackStream s(ParseHex(b)); s >> tb; }
    EXPECT_EQ(dash::coin::dash_txid(ta), dash::coin::dash_txid(tb));
    EXPECT_NE(dash::coin::dash_instance_hash(ta), dash::coin::dash_instance_hash(tb));
    EXPECT_TRUE(dash::coin::txid_may_omit_body_bytes(a));
    EXPECT_FALSE(dash::coin::bodies_match_under_equal_txids({a}, {b}));
    EXPECT_TRUE(dash::coin::bodies_match_under_equal_txids({a}, {a}));
}

TEST(DashGbtStableTxid, BodiesMemoNeverServesAResignedUnlockWithOldBytes)
{
    const auto& rb = block_1599900();
    // A normal tx, then a v2 unlock: two templates over the same txids, the
    // second carrying a re-signed instance of the unlock.
    size_t normal = 0;
    for (size_t i = 1; i < rb.block.m_txs.size(); ++i)
        if (rb.block.m_txs[i].type == 0) { normal = i; break; }
    ASSERT_NE(normal, 0u);
    const std::string unlock = rb.tx_hex[5];
    const DashWorkData first  = template_with({rb.tx_hex[normal], unlock});
    const DashWorkData second = template_with({rb.tx_hex[normal], resigned(unlock)});
    ASSERT_EQ(first.m_tx_hashes, second.m_tx_hashes);
    ASSERT_NE(first.m_tx_data_hex, second.m_tx_data_hex);

    dash::mint::TemplateBodiesMemo memo;
    const auto sp1 = memo.get(first);               // kept alive: a frozen job holds it
    ASSERT_TRUE(sp1);
    EXPECT_EQ(*sp1, first.m_tx_data_hex);
    const auto sp2 = memo.get(second);
    ASSERT_TRUE(sp2);
    EXPECT_EQ(*sp2, second.m_tx_data_hex) << "memo served the previous instance's bytes";
    EXPECT_NE(sp1.get(), sp2.get());

    // Equal bodies still share one vector, and each instance finds its own.
    EXPECT_EQ(memo.get(first).get(), sp1.get());
    EXPECT_EQ(memo.get(second).get(), sp2.get());
}

// The store's reuse rule shares the predicate: a re-signed unlock on the same
// tip is a fresh vector, never the previous template's.
TEST(DashGbtStableTxid, TemplateStoreReuseRejectsAResignedUnlock)
{
    const auto& rb = block_1599900();
    DashWorkData prev = template_with({rb.tx_hex[5]});
    prev.m_tx_hex_shared = dash::coin::TemplateTxHex::encode(prev.m_tx_data_hex, 1);
    DashWorkData same = template_with({rb.tx_hex[5]});
    DashWorkData next = template_with({resigned(rb.tx_hex[5])});
    ASSERT_EQ(prev.m_tx_hashes, next.m_tx_hashes);
    EXPECT_TRUE(dash::coin::template_tx_hex_reusable(prev, same));
    EXPECT_FALSE(dash::coin::template_tx_hex_reusable(prev, next));
}

} // namespace
