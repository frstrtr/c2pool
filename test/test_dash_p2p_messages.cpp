// SPDX-License-Identifier: AGPL-3.0-or-later
/// Phase S8 — Dash coin-daemon P2P wire-message KATs
///
/// Exercises the Dash-specific messages in
/// src/impl/dash/coin/p2p_messages.hpp — the embedded-P2P message layer the
/// S8 block-submission lane (p2p_connection -> p2p_node -> broadcaster) builds
/// on. The generic bitcoin_family messages (version/verack/inv/...) are
/// already covered by the family suite; this pins the Dash-only additions
/// that carry no segwit/MWEB plus the Dash consensus side-channels:
///
///   - block / headers : Dash fixed 80-byte header round-trip (no witness).
///   - clsig           : ChainLock sig — i32 height + 32B hash + FIXED 96B BLS
///                       blob. Byte-layout PINNED by independent stream
///                       reconstruction (NOT a self round-trip), and a
///                       transposed layout is rejected — proving the
///                       comparator is layout-sensitive (integrator gate b).
///   - getmnlistd      : two uint256 (base, block) at fixed 0/32 offsets.
///   - mnlistdiff      : carries the vendored CSimplifiedMNListDiff (S8.1).
///   - command strings : every Dash message maps to its exact wire command.
///
/// SCOPE NOTE (honest): structural + bit-exact-layout wire KATs, fully
/// self-contained. The live "connect to a dashd peer and exchange these on a
/// real socket" leg is the p2p_connection/p2p_node integration leaf, NOT
/// claimed here.

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_messages.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/vendor/smldiff.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace dash::coin::p2p;
using dash::coin::BlockType;
using dash::coin::vendor::CSimplifiedMNListDiff;

// ─── helpers ────────────────────────────────────────────────────────────────

// Non-destructive byte view of a PackStream (does not advance the read cursor).
static std::vector<unsigned char> bytes_of(PackStream& ps) {
    auto sp = ps.get_span();
    auto* p = reinterpret_cast<const unsigned char*>(sp.data());
    return std::vector<unsigned char>(p, p + sp.size());
}

static uint256 raw256_seq(uint8_t base) {
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    uint256 h; std::memcpy(h.data(), p.data(), 32); return h;
}

static BlockType make_header(uint8_t seed) {
    BlockType b;
    b.m_version        = 0x20000000u | seed;
    b.m_previous_block = raw256_seq(0x10 + seed);
    b.m_merkle_root    = raw256_seq(0x50 + seed);
    b.m_timestamp      = 0x5f5e1000u + seed;
    b.m_bits           = 0x1d00ffffu;
    b.m_nonce          = 0xdeadbeefu - seed;
    return b;
}

// ─── block / headers ────────────────────────────────────────────────────────

TEST(DashP2PMessages, Message_Block_RoundTrip) {
    auto blk = make_header(3);
    auto rmsg = message_block::make_raw(blk);
    EXPECT_EQ(rmsg->m_command, "block");
    // E2a: BlockType now serializes the standard Bitcoin block body — the
    // 80-byte header PLUS a CompactSize tx-count. An empty-body block is
    // 80 + 1 = 81 bytes (CompactSize(0) == 0x00), matching what a real dashd
    // `block` message with no transactions would carry. (Pre-E2a this was a
    // header-only 80 bytes — the deferred-parser regression E2a closes.)
    EXPECT_EQ(bytes_of(rmsg->m_data).size(), 81u);

    auto parsed = message_block::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_block.m_previous_block, blk.m_previous_block);
    EXPECT_EQ(parsed->m_block.m_merkle_root,    blk.m_merkle_root);
    EXPECT_EQ(parsed->m_block.m_bits,           blk.m_bits);
    EXPECT_EQ(parsed->m_block.m_nonce,          blk.m_nonce);
    EXPECT_TRUE(parsed->m_block.m_txs.empty());
}

// E2a: a full `block` message body with transactions must deserialize into the
// exact tx set the ingest legs (MnStateMachine::apply_block, UTXO connect_block)
// consume. Pre-E2a the body was dropped (header-only) and m_txs stayed empty.
TEST(DashP2PMessages, Message_Block_Body_TxSet_RoundTrip) {
    using dash::coin::MutableTransaction;
    using bitcoin_family::coin::TxIn;
    using bitcoin_family::coin::TxOut;

    auto blk = make_header(7);
    // Coinbase-like tx0 (type 0) + a special tx (type 5 with extra_payload) to
    // exercise the Dash version|type<<16 + extra_payload codec through the body.
    MutableTransaction cb;
    cb.version = 1; cb.type = 0;
    cb.vin.push_back(TxIn{}); cb.vout.push_back(TxOut{});
    cb.vout.back().value = 500000000;
    MutableTransaction special;
    special.version = 3; special.type = 5;
    special.vin.push_back(TxIn{}); special.vout.push_back(TxOut{});
    special.extra_payload = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02};
    blk.m_txs = {cb, special};

    auto rmsg = message_block::make_raw(blk);
    auto parsed = message_block::make(rmsg->m_data);
    ASSERT_EQ(parsed->m_block.m_txs.size(), 2u);
    EXPECT_EQ(parsed->m_block.m_txs[0].type, 0);
    EXPECT_EQ(parsed->m_block.m_txs[0].vout.size(), 1u);
    EXPECT_EQ(parsed->m_block.m_txs[0].vout[0].value, 500000000);
    EXPECT_EQ(parsed->m_block.m_txs[1].version, 3);
    EXPECT_EQ(parsed->m_block.m_txs[1].type, 5);
    EXPECT_EQ(parsed->m_block.m_txs[1].extra_payload,
              (std::vector<unsigned char>{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}));
    // Header still intact after the body.
    EXPECT_EQ(parsed->m_block.m_nonce, blk.m_nonce);
    EXPECT_EQ(parsed->m_block.m_merkle_root, blk.m_merkle_root);
}

TEST(DashP2PMessages, Message_Headers_RoundTrip) {
    std::vector<BlockType> hs{make_header(1), make_header(2)};
    auto rmsg = message_headers::make_raw(hs);
    EXPECT_EQ(rmsg->m_command, "headers");

    auto parsed = message_headers::make(rmsg->m_data);
    ASSERT_EQ(parsed->m_headers.size(), 2u);
    EXPECT_EQ(parsed->m_headers[0].m_nonce, hs[0].m_nonce);
    EXPECT_EQ(parsed->m_headers[1].m_merkle_root, hs[1].m_merkle_root);
}

// ─── clsig: round-trip, fixed 96B BLS sig, layout pin ────────────────────────

TEST(DashP2PMessages, Message_ClSig_RoundTrip) {
    int32_t height = 0x00abcdef;
    uint256 bhash  = raw256_seq(0x80);
    std::vector<uint8_t> sig(96);
    for (size_t i = 0; i < 96; ++i) sig[i] = static_cast<uint8_t>(0x11 + i);

    auto rmsg = message_clsig::make_raw(height, bhash, sig);
    EXPECT_EQ(rmsg->m_command, "clsig");

    auto parsed = message_clsig::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_height, height);
    EXPECT_EQ(parsed->m_block_hash, bhash);
    ASSERT_EQ(parsed->m_sig.size(), 96u);
    EXPECT_EQ(parsed->m_sig, sig);
}

TEST(DashP2PMessages, Message_ClSig_LayoutPinned) {
    int32_t height = 0x00abcdef;
    uint256 bhash  = raw256_seq(0x80);
    std::vector<uint8_t> sig(96);
    for (size_t i = 0; i < 96; ++i) sig[i] = static_cast<uint8_t>(0x11 + i);

    auto rmsg = message_clsig::make_raw(height, bhash, sig);
    auto wire = bytes_of(rmsg->m_data);

    // Independent reconstruction of the exact wire stream:
    //   height(i32 LE) || blockHash(32B) || sig(FIXED 96B, no length prefix)
    std::vector<unsigned char> expect;
    for (int i = 0; i < 4; ++i) expect.push_back(static_cast<unsigned char>((height >> (8 * i)) & 0xff));
    expect.insert(expect.end(), bhash.data(), bhash.data() + 32);
    expect.insert(expect.end(), sig.begin(), sig.end());

    ASSERT_EQ(expect.size(), 132u);               // 4 + 32 + 96, fixed
    ASSERT_EQ(wire.size(), 132u);
    EXPECT_EQ(wire, expect);

    // Layout-sensitivity: a transposed reconstruction (hash before height)
    // must NOT match — proves the comparator pins ORDER, not just contents.
    std::vector<unsigned char> transposed;
    transposed.insert(transposed.end(), bhash.data(), bhash.data() + 32);
    for (int i = 0; i < 4; ++i) transposed.push_back(static_cast<unsigned char>((height >> (8 * i)) & 0xff));
    transposed.insert(transposed.end(), sig.begin(), sig.end());
    EXPECT_NE(wire, transposed);
}

// ─── getmnlistd: two uint256 at fixed offsets ───────────────────────────────

TEST(DashP2PMessages, Message_GetMnListD_RoundTrip) {
    uint256 base = raw256_seq(0x01);
    uint256 blk  = raw256_seq(0xA1);
    auto rmsg = message_getmnlistd::make_raw(base, blk);
    EXPECT_EQ(rmsg->m_command, "getmnlistd");

    auto wire = bytes_of(rmsg->m_data);
    ASSERT_EQ(wire.size(), 64u);                  // 32 + 32
    // base occupies [0,32), block occupies [32,64) — pinned offsets.
    EXPECT_EQ(0, std::memcmp(wire.data() + 0,  base.data(), 32));
    EXPECT_EQ(0, std::memcmp(wire.data() + 32, blk.data(),  32));

    auto parsed = message_getmnlistd::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_base_block_hash, base);
    EXPECT_EQ(parsed->m_block_hash, blk);
}

// ─── mnlistdiff: carries the vendored CSimplifiedMNListDiff ──────────────────

TEST(DashP2PMessages, Message_MnListDiff_RoundTrip) {
    CSimplifiedMNListDiff diff;
    diff.baseBlockHash = raw256_seq(0x02);
    diff.blockHash     = raw256_seq(0xB2);

    auto rmsg = message_mnlistdiff::make_raw(diff);
    EXPECT_EQ(rmsg->m_command, "mnlistdiff");
    EXPECT_GT(bytes_of(rmsg->m_data).size(), 0u);

    auto parsed = message_mnlistdiff::make(rmsg->m_data);
    EXPECT_EQ(parsed->m_diff.baseBlockHash, diff.baseBlockHash);
    EXPECT_EQ(parsed->m_diff.blockHash, diff.blockHash);
}

// ─── command-string registration sweep ──────────────────────────────────────

TEST(DashP2PMessages, CommandStringsPinned) {
    EXPECT_EQ(message_block::make_raw(make_header(0))->m_command, "block");
    EXPECT_EQ(message_headers::make_raw(std::vector<BlockType>{})->m_command, "headers");
    EXPECT_EQ(message_getmnlistd::make_raw(raw256_seq(0), raw256_seq(1))->m_command, "getmnlistd");
    CSimplifiedMNListDiff d;
    EXPECT_EQ(message_mnlistdiff::make_raw(d)->m_command, "mnlistdiff");
}
// ─── inv → getdata sourcing policy (the ChainLock acquisition leg) ──────────
//
// MSG_CLSIG was decodable and handled long before it was ever REQUESTED: the
// inv handler only ever issued a getdata for type 21, so `clsig` never arrived
// and on_new_chainlock never fired. These lock the pull policy the inv handler
// actually consults (dash::coin::p2p::inv_type_is_pulled), so dropping the
// ChainLock leg again goes red.

TEST(DashP2PMessages, InvTypeNumbersMatchDashcoreProtocol) {
    // dashcore src/protocol.h enum GetDataMsg
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::quorum_final_commitment), 21u);
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::clsig), 29u);   // protocol.h:522
    // E-SUPERBLOCK governance inv types (dashcore protocol.h:508-509)
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::govobject), 17u);
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::govobjectvote), 18u);
}

// E-SUPERBLOCK feed hook (red-on-master -> green). Before this change the inv
// handler getdata-pulled only types 21/29/31, so a govsync answer's
// MSG_GOVERNANCE_OBJECT (17) / _VOTE (18) invs were never requested — the
// govobj/govobjvote handlers could never fire and the GovernanceStore stayed
// empty, which is exactly why every superblock height refused to serve
// daemonlessly. Admitting 17/18 to the pull TYPE predicate is the wire change
// that lets the store populate (the runtime pull is additionally flag-gated in
// the inv handler by m_gov_pull_enabled, the is_dstx precedent).
TEST(DashP2PMessages, InvPullPolicyCoversGovernanceObjectsAndVotes) {
    EXPECT_TRUE(inv_type_is_pulled(inventory_type::govobject))
        << "governance objects are inv-announced and served only on getdata; "
           "without this the govobj handler can never fire and the superblock "
           "store never populates";
    EXPECT_TRUE(inv_type_is_pulled(inventory_type::govobjectvote))
        << "a trigger's funding votes are inv-announced and served only on "
           "getdata; without this the tally can never reach the funding "
           "threshold";
}

TEST(DashP2PMessages, InvPullPolicyCoversChainLocksAndCommitments) {
    EXPECT_TRUE(inv_type_is_pulled(inventory_type::clsig))
        << "ChainLocks are inv-announced and served only on getdata; without "
           "this the clsig handler can never fire";
    EXPECT_TRUE(inv_type_is_pulled(inventory_type::quorum_final_commitment));

    // Types we must NOT blind-getdata: blocks take the getheaders-first path,
    // and we do not pull the tx mempool.
    EXPECT_FALSE(inv_type_is_pulled(inventory_type::block));
    EXPECT_FALSE(inv_type_is_pulled(inventory_type::tx));
    EXPECT_FALSE(inv_type_is_pulled(inventory_type::filtered_block));
}

TEST(DashP2PMessages, GetdataForClsigInvRoundTripsOnTheWire) {
    // What the inv handler builds for an announced ChainLock: a getdata
    // echoing the announcement's type and hash (the hash is
    // SerializeHash(clsig), which we cannot derive and must echo verbatim).
    const uint256 inv_hash = raw256_seq(0xC1);
    auto raw = message_getdata::make_raw(
        {inventory_type(inventory_type::clsig, inv_hash)});
    EXPECT_EQ(raw->m_command, "getdata");

    auto parsed = message_getdata::make(raw->m_data);
    ASSERT_EQ(parsed->m_requests.size(), 1u);
    EXPECT_EQ(static_cast<uint32_t>(parsed->m_requests[0].m_type), 29u);
    EXPECT_EQ(parsed->m_requests[0].m_hash, inv_hash);
}

TEST(DashP2PMessages, ClsigWireLayoutMatchesRealMainnetChainLock) {
    // The real 132-byte clsig body from mainnet `getbestchainlock` at 2515965:
    // int32LE height || blockHash(32 LE) || sig(96). Decoding it must recover
    // exactly the height and block hash dashd reported.
    const std::string hex =
        "fd632600"
        "8ba8205c0861bc9b6063b67aeff818075a148d1a989502250b00000000000000"
        "b37fa65f662141fde71d5ead7f3548547aa08915274c188c47554e814770a381"
        "6b0c772c10fdb6ca1cc8bf851bcb218301454d5aa6c2fd0d3d25162096f416b9"
        "a629196307efe214b20380c2606c9191550cbefee9ad7e59c05d691929d4a7dd";
    std::vector<std::byte> body;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        body.push_back(static_cast<std::byte>(
            std::stoul(hex.substr(i, 2), nullptr, 16)));
    ASSERT_EQ(body.size(), 132u);

    PackStream ps(body);
    auto parsed = message_clsig::make(ps);
    EXPECT_EQ(parsed->m_height, 2515965);
    EXPECT_EQ(parsed->m_sig.size(), 96u);
    EXPECT_EQ(parsed->m_block_hash.GetHex(),
              "000000000000000b250295981a8d145a0718f8ef7ab663609bbc61085c20a88b");
}
