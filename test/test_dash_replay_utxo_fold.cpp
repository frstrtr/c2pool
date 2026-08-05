// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DASH FULL-HISTORY REPLAY — W3 unit KATs: the standalone UTXO fold
// (src/impl/dash/coin/replay_utxo_fold.hpp).
//
// What is proven HERE, on small synthetic chains:
//   * dashd serialize.h primitive parity: WriteVarInt (MSB-base-128 with the
//     -1 offset) pinned byte vectors + decode round-trip; WriteCompactSize
//     pinned vectors.
//   * the hash_serialized_2 stream layout: an independently hand-assembled
//     preimage (own mini-encoders in this TU, deliberately NOT the module's)
//     double-SHA256'd and compared against the module's set hash — covering
//     txid-group ordering (byte-lexicographic), ascending-vout grouping,
//     script/amount encoding, per-group 0x00 terminator and the hashBlock
//     prefix.
//   * the v23.1.x ApplyHash TERNARY QUIRK: the per-group "code" varint is the
//     literal 0x01 — (nHeight*2+fCoinBase) ? 1u : 0u — never the height code.
//     A future "fix" of the transcription breaks this KAT on purpose.
//   * fold rules: zero-value spendable outputs INCLUDED, OP_RETURN excluded,
//     coinbase-maturity metadata carried, missing-input REFUSED with state
//     rolled back, gap/cold-start REFUSED, BIP30 duplicate REFUSED, genesis
//     folds nothing, idempotent redelivery acknowledged.
//   * persistence: resumable cursor across close/reopen (byte-identical set
//     hash), format-version fail-loud, undo window (default 100) retention +
//     prune, disconnect_tip/reconnect returning to the identical set hash.
//
// What is NOT proven here and gates the module (see the module header):
// byte-equality against live dashd at the full-chain anchor
//   hash_serialized_2 = 3d14913768a9d492bfa7a42fe9b111cff625b80e35bb4133e1d60cf3991c2319
//   @ h=2,516,758
// via `c2pool-dash --replay-utxo-db ... --replay-utxo-hash --replay-utxo-expect ...`.

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_utxo_fold.hpp>

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <unistd.h>
#include <vector>

using dash::coin::BlockType;
using dash::coin::MutableTransaction;
using dash::coin::TxIn;
using dash::coin::TxOut;
using dash::coin::dash_txid;
using dash::coin::replay::ReplayUtxoFold;
using dash::coin::replay::ReplayUtxoFoldOptions;
using dash::coin::replay::REPLAY_UTXO_UNDO_WINDOW;
using dash::coin::replay::write_compact_size;
using dash::coin::replay::write_dashd_varint;

namespace {

// ── Fixture plumbing ───────────────────────────────────────────────────────

struct TmpDir {
    std::filesystem::path root;
    TmpDir()
    {
        root = std::filesystem::temp_directory_path() /
               ("c2pool_replay_utxo_" + std::to_string(::getpid()) + "_" +
                std::to_string(reinterpret_cast<uintptr_t>(this)));
        std::filesystem::create_directories(root);
    }
    ~TmpDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }
    std::string sub(const char* name) const { return (root / name).string(); }
};

uint256 fake_block_hash(uint32_t height)
{
    // Any deterministic 32-byte value works: the fold treats the hash as an
    // opaque PoW-pinned identity supplied by the transport.
    std::vector<uint8_t> seed = {'b', 'l', 'k'};
    write_dashd_varint(seed, height);
    return ::Hash(seed);
}

std::vector<uint8_t> p2pkh(uint8_t tag)
{
    // 25-byte P2PKH shape with a distinguishing byte.
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

MutableTransaction make_coinbase(uint32_t height,
                                 const std::vector<std::pair<int64_t, std::vector<uint8_t>>>& outs)
{
    MutableTransaction tx;
    TxIn cin;
    cin.prevout.hash = uint256();
    cin.prevout.index = 0xFFFFFFFF;
    // BIP34-style uniqueness: the height in scriptSig keeps synthetic
    // coinbase txids distinct per block.
    write_dashd_varint(cin.scriptSig.m_data, height);
    cin.sequence = 0xFFFFFFFF;
    tx.vin.push_back(cin);
    for (const auto& [value, script] : outs) {
        TxOut o;
        o.value = value;
        o.scriptPubKey.m_data = script;
        tx.vout.push_back(o);
    }
    return tx;
}

MutableTransaction make_spend(const std::vector<std::pair<uint256, uint32_t>>& ins,
                              const std::vector<std::pair<int64_t, std::vector<uint8_t>>>& outs)
{
    MutableTransaction tx;
    for (const auto& [txid, n] : ins) {
        TxIn in;
        in.prevout.hash = txid;
        in.prevout.index = n;
        in.sequence = 0xFFFFFFFF;
        tx.vin.push_back(in);
    }
    for (const auto& [value, script] : outs) {
        TxOut o;
        o.value = value;
        o.scriptPubKey.m_data = script;
        tx.vout.push_back(o);
    }
    return tx;
}

BlockType make_block(std::vector<MutableTransaction> txs)
{
    BlockType b;
    b.m_txs = std::move(txs);
    return b;
}

std::string hex(const std::vector<uint8_t>& v)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 0xF]);
    }
    return s;
}

// ── Independent mini-encoders (deliberately re-implemented; see header) ────

void ref_varint(std::vector<uint8_t>& out, uint64_t n)
{
    // Build the MSB-base-128/-1-offset encoding backwards, then reverse.
    std::vector<uint8_t> rev;
    rev.push_back(n & 0x7F);
    while (n > 0x7F) {
        n = (n >> 7) - 1;
        rev.push_back(0x80 | (n & 0x7F));
    }
    for (auto it = rev.rbegin(); it != rev.rend(); ++it) out.push_back(*it);
}

uint64_t ref_varint_decode(const std::vector<uint8_t>& in, size_t& pos)
{
    // Bitcoin serialize.h ReadVarInt.
    uint64_t n = 0;
    while (true) {
        uint8_t chData = in.at(pos++);
        n = (n << 7) | (chData & 0x7F);
        if (chData & 0x80)
            n++;
        else
            return n;
    }
}

// The expected hash_serialized_2 for a coin map, assembled from scratch:
// dashd kernel/coinstats.cpp ComputeUTXOStats over a cursor ordered by the
// raw txid bytes, PrepareHash (hashBlock), ApplyHash per txid group (WITH the
// ternary quirk), FinalizeHash (double SHA256).
struct RefCoin {
    uint32_t vout;
    int64_t value;
    std::vector<uint8_t> script;
    uint32_t height;
    bool coinbase;
};

uint256 ref_hash_serialized_2(const uint256& best_block,
                              const std::map<std::string, std::pair<uint256, std::vector<RefCoin>>>& groups)
{
    std::vector<uint8_t> pre(best_block.data(), best_block.data() + 32);
    for (const auto& [key_bytes, group] : groups) {
        const auto& [txid, coins] = group;
        std::map<uint32_t, const RefCoin*> ordered;
        for (const auto& c : coins) ordered[c.vout] = &c;
        bool first = true;
        for (auto it = ordered.begin(); it != ordered.end(); ++it) {
            const RefCoin& c = *it->second;
            if (first) {
                first = false;
                pre.insert(pre.end(), txid.data(), txid.data() + 32);
                const uint64_t code = uint64_t(c.height) * 2 + (c.coinbase ? 1 : 0);
                ref_varint(pre, code ? 1u : 0u);  // the v23.1.x ternary quirk
            }
            ref_varint(pre, uint64_t(c.vout) + 1);
            // CScript: CompactSize length + raw bytes.
            if (c.script.size() < 253) {
                pre.push_back(uint8_t(c.script.size()));
            } else {
                pre.push_back(253);
                pre.push_back(c.script.size() & 0xFF);
                pre.push_back((c.script.size() >> 8) & 0xFF);
            }
            pre.insert(pre.end(), c.script.begin(), c.script.end());
            ref_varint(pre, uint64_t(c.value));
            if (std::next(it) == ordered.end()) ref_varint(pre, 0);
        }
    }
    return ::Hash(pre);  // core double-SHA256
}

std::string txid_key_bytes(const uint256& txid)
{
    return std::string(reinterpret_cast<const char*>(txid.data()), 32);
}

// ── dashd serialize.h primitive KATs ───────────────────────────────────────

TEST(ReplayUtxoVarint, PinnedVectors)
{
    // Safe pinned vectors of Bitcoin/dashd WriteVarInt (NOT LEB128): the
    // 1-byte range is identity; 0x80 starts the 2-byte range at "8000".
    struct V { uint64_t n; const char* expect; };
    const V vectors[] = {
        {0x00, "00"}, {0x01, "01"}, {0x7f, "7f"},
        {0x80, "8000"}, {0xff, "807f"}, {0x100, "8100"},
    };
    for (const auto& v : vectors) {
        std::vector<uint8_t> out;
        write_dashd_varint(out, v.n);
        EXPECT_EQ(hex(out), v.expect) << "n=" << v.n;
    }
}

TEST(ReplayUtxoVarint, RoundTripAndIndependentEncoderAgree)
{
    const uint64_t samples[] = {
        0, 1, 2, 0x7e, 0x7f, 0x80, 0x81, 0xff, 0x100, 0x3fff, 0x4000,
        0x407e, 0x407f, 0x4080, 0xffff, 0x10000, 12345678, 0xffffffffULL,
        2516758ULL * 2 + 1,     // a real (height*2+coinbase) code magnitude
        500000000, 2100000000000000ULL,  // duff amounts incl. MAX_MONEY scale
    };
    for (uint64_t n : samples) {
        std::vector<uint8_t> a, b;
        write_dashd_varint(a, n);
        ref_varint(b, n);
        EXPECT_EQ(hex(a), hex(b)) << "encoders disagree at n=" << n;
        size_t pos = 0;
        EXPECT_EQ(ref_varint_decode(a, pos), n) << "round-trip failed at n=" << n;
        EXPECT_EQ(pos, a.size());
    }
}

TEST(ReplayUtxoVarint, CompactSizePinnedVectors)
{
    struct V { uint64_t n; const char* expect; };
    const V vectors[] = {
        {0, "00"}, {252, "fc"}, {253, "fdfd00"}, {0x1234, "fd3412"},
        {0xffff, "fdffff"}, {0x10000, "fe00000100"},
    };
    for (const auto& v : vectors) {
        std::vector<uint8_t> out;
        write_compact_size(out, v.n);
        EXPECT_EQ(hex(out), v.expect) << "n=" << v.n;
    }
}

// ── The ternary quirk, pinned on its own ───────────────────────────────────

TEST(ReplayUtxoHash, GroupCodeIsTernaryQuirkLiteralOne)
{
    // dashd v23.1.0 kernel/coinstats.cpp:61 —
    //   ss << VARINT(it->second.nHeight * 2 + it->second.fCoinBase ? 1u : 0u);
    // binds as (nHeight*2 + fCoinBase) ? 1u : 0u. A high non-coinbase coin
    // must contribute the single byte 0x01, never VARINT(2*height).
    ::core::coin::Coin coin(77, OPScript{}, /*height=*/123456,
                            /*cb=*/false);
    coin.scriptPubKey.m_data = p2pkh(0xaa);
    std::map<uint32_t, ::core::coin::Coin> outputs{{0, coin}};
    uint256 txid = fake_block_hash(1);

    CHash256 quirk_hasher;
    dash::coin::replay::apply_hash_group(quirk_hasher, txid, outputs);
    uint256 got;
    quirk_hasher.Finalize(std::span<unsigned char>(got.data(), 32));

    // Reference stream with the literal 0x01 code byte.
    std::vector<uint8_t> pre(txid.data(), txid.data() + 32);
    pre.push_back(0x01);                       // the quirk byte
    pre.push_back(0x01);                       // VARINT(vout 0 + 1)
    pre.push_back(uint8_t(coin.scriptPubKey.m_data.size()));
    pre.insert(pre.end(), coin.scriptPubKey.m_data.begin(),
               coin.scriptPubKey.m_data.end());
    pre.push_back(77);                         // VARINT(value 77)
    pre.push_back(0x00);                       // group terminator
    EXPECT_EQ(got.GetHex(), ::Hash(pre).GetHex());

    // And the un-quirked encoding (what hash_serialized_3 would fold) must
    // NOT match — proving the quirk is load-bearing, not incidental.
    std::vector<uint8_t> fixed(txid.data(), txid.data() + 32);
    ref_varint(fixed, uint64_t(123456) * 2);
    fixed.push_back(0x01);
    fixed.push_back(uint8_t(coin.scriptPubKey.m_data.size()));
    fixed.insert(fixed.end(), coin.scriptPubKey.m_data.begin(),
                 coin.scriptPubKey.m_data.end());
    fixed.push_back(77);
    fixed.push_back(0x00);
    EXPECT_NE(got.GetHex(), ::Hash(fixed).GetHex());
}

// ── Fold rule + set-hash KATs on a synthetic chain ─────────────────────────

TEST(ReplayUtxoFoldTest, SyntheticChainMatchesHandAssembledHash)
{
    TmpDir tmp;
    ReplayUtxoFoldOptions opts;
    opts.flush_interval = 1;
    ReplayUtxoFold fold(opts);
    ASSERT_TRUE(fold.open(tmp.sub("db")));

    // h=1: coinbase with a P2PKH output, an OP_RETURN output (must be
    // EXCLUDED), and a ZERO-VALUE spendable output (must be INCLUDED).
    auto cb1 = make_coinbase(
        1, {{50'000'000'000LL, p2pkh(0x11)},
            {0, {0x6a, 0x01, 0x42}},          // OP_RETURN — excluded
            {0, p2pkh(0x22)}});               // 0-duff spendable — included
    const uint256 cb1_id = dash_txid(cb1);
    ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb1})))
        << fold.refusal();

    // h=2: coinbase + a tx spending cb1:0 into two outputs.
    auto cb2 = make_coinbase(2, {{50'000'000'000LL, p2pkh(0x33)}});
    auto spend = make_spend({{cb1_id, 0}},
                            {{30'000'000'000LL, p2pkh(0x44)},
                             {19'000'000'000LL, p2pkh(0x55)}});
    const uint256 cb2_id = dash_txid(cb2);
    const uint256 spend_id = dash_txid(spend);
    const uint256 tip_hash = fake_block_hash(2);
    ASSERT_TRUE(fold.on_replay_block(2, tip_hash, make_block({cb2, spend})))
        << fold.refusal();

    // Expected set: cb1:2 (zero-value, coinbase h=1), cb2:0 (coinbase h=2),
    // spend:0 + spend:1 (non-coinbase h=2). cb1:0 spent, cb1:1 never entered.
    EXPECT_TRUE(fold.have_coin({cb1_id, 2}));
    EXPECT_FALSE(fold.have_coin({cb1_id, 0}));
    EXPECT_FALSE(fold.have_coin({cb1_id, 1}));

    std::map<std::string, std::pair<uint256, std::vector<RefCoin>>> groups;
    groups[txid_key_bytes(cb1_id)] = {
        cb1_id, {{2, 0, p2pkh(0x22), 1, true}}};
    groups[txid_key_bytes(cb2_id)] = {
        cb2_id, {{0, 50'000'000'000LL, p2pkh(0x33), 2, true}}};
    groups[txid_key_bytes(spend_id)] = {
        spend_id,
        {{0, 30'000'000'000LL, p2pkh(0x44), 2, false},
         {1, 19'000'000'000LL, p2pkh(0x55), 2, false}}};

    auto res = fold.hash_serialized_2();
    ASSERT_TRUE(res.has_value()) << fold.refusal();
    EXPECT_EQ(res->coins, 4u);
    EXPECT_EQ(res->tx_groups, 3u);
    EXPECT_EQ(res->best_height, 2u);
    EXPECT_EQ(res->best_block.GetHex(), tip_hash.GetHex());
    EXPECT_EQ(res->hash.GetHex(),
              ref_hash_serialized_2(tip_hash, groups).GetHex());
}

TEST(ReplayUtxoFoldTest, CoinbaseMaturityMetadataCarried)
{
    TmpDir tmp;
    ReplayUtxoFold fold;
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    auto cb = make_coinbase(1, {{100, p2pkh(0x01)}});
    ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb})));

    ::core::coin::Coin c;
    ASSERT_TRUE(fold.get_coin({dash_txid(cb), 0}, c));
    EXPECT_TRUE(c.coinbase);
    EXPECT_EQ(c.height, 1u);
    // dashd COINBASE_MATURITY = 100: spendable at h=101, not at h=100.
    EXPECT_FALSE(ReplayUtxoFold::is_mature(c, 100));
    EXPECT_TRUE(ReplayUtxoFold::is_mature(c, 101));
}

TEST(ReplayUtxoFoldTest, StrictOrderingAndFailClosedRefusals)
{
    TmpDir tmp;
    ReplayUtxoFold fold;
    ASSERT_TRUE(fold.open(tmp.sub("db")));

    // Cold start above height 1: refused, named.
    auto cb = make_coinbase(5, {{100, p2pkh(0x05)}});
    EXPECT_FALSE(fold.on_replay_block(5, fake_block_hash(5), make_block({cb})));
    EXPECT_NE(fold.refusal().find("cold-start"), std::string::npos);

    auto cb1 = make_coinbase(1, {{100, p2pkh(0x01)}});
    ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb1})));

    // Gap: h=3 after h=1 is refused; h=2 still accepted afterwards.
    auto cb3 = make_coinbase(3, {{100, p2pkh(0x03)}});
    EXPECT_FALSE(fold.on_replay_block(3, fake_block_hash(3), make_block({cb3})));
    EXPECT_NE(fold.refusal().find("gap"), std::string::npos);

    // Missing input: refused, and the block's partial changes rolled back.
    auto cb2 = make_coinbase(2, {{100, p2pkh(0x02)}});
    auto bad = make_spend({{fake_block_hash(99), 0}}, {{50, p2pkh(0x06)}});
    const uint256 cb2_id = dash_txid(cb2);
    EXPECT_FALSE(
        fold.on_replay_block(2, fake_block_hash(2), make_block({cb2, bad})));
    EXPECT_NE(fold.refusal().find("missing-input"), std::string::npos);
    EXPECT_EQ(fold.best_height(), 1u);
    EXPECT_FALSE(fold.have_coin({cb2_id, 0}))
        << "refused block must contribute nothing (rollback)";

    // The valid h=2 (coinbase only) then folds cleanly.
    ASSERT_TRUE(fold.on_replay_block(2, fake_block_hash(2), make_block({cb2})))
        << fold.refusal();
    EXPECT_TRUE(fold.have_coin({cb2_id, 0}));

    // Idempotent redelivery of an already-folded height is acknowledged.
    EXPECT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb1})));
    EXPECT_EQ(fold.best_height(), 2u);
}

TEST(ReplayUtxoFoldTest, Bip30DuplicateRefused)
{
    TmpDir tmp;
    ReplayUtxoFold fold;
    ASSERT_TRUE(fold.open(tmp.sub("db")));

    // Two blocks carrying the byte-identical coinbase (same txid — the BIP30
    // shape). The second add must be refused, not overwritten.
    auto cb = make_coinbase(7, {{100, p2pkh(0x07)}});
    ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb})));
    EXPECT_FALSE(fold.on_replay_block(2, fake_block_hash(2), make_block({cb})));
    EXPECT_NE(fold.refusal().find("bip30"), std::string::npos);
    EXPECT_EQ(fold.best_height(), 1u);
}

TEST(ReplayUtxoFoldTest, GenesisFoldsNothing)
{
    TmpDir tmp;
    ReplayUtxoFold fold;
    ASSERT_TRUE(fold.open(tmp.sub("db")));

    auto gcb = make_coinbase(0, {{50'000'000'000LL, p2pkh(0xa0)}});
    const uint256 ghash = fake_block_hash(0);
    ASSERT_TRUE(fold.on_replay_block(0, ghash, make_block({gcb})));
    EXPECT_FALSE(fold.have_coin({dash_txid(gcb), 0}))
        << "genesis coinbase must never enter the set (dashd short-circuit)";
    EXPECT_EQ(fold.best_height(), 0u);
    EXPECT_EQ(fold.resume_height(), 1u);
    EXPECT_EQ(fold.best_hash().GetHex(), ghash.GetHex());
}

TEST(ReplayUtxoFoldTest, ResumableAcrossReopen)
{
    TmpDir tmp;
    const std::string db = tmp.sub("db");
    std::string hash_before;
    {
        ReplayUtxoFoldOptions opts;
        opts.flush_interval = 1;  // persist every block
        ReplayUtxoFold fold(opts);
        ASSERT_TRUE(fold.open(db));
        for (uint32_t h = 1; h <= 5; ++h) {
            auto cb = make_coinbase(h, {{int64_t(h) * 1000, p2pkh(uint8_t(h))}});
            ASSERT_TRUE(
                fold.on_replay_block(h, fake_block_hash(h), make_block({cb})))
                << fold.refusal();
        }
        auto res = fold.hash_serialized_2();
        ASSERT_TRUE(res.has_value());
        hash_before = res->hash.GetHex();
        fold.close();
    }
    {
        ReplayUtxoFold fold;
        ASSERT_TRUE(fold.open(db));
        EXPECT_TRUE(fold.have_cursor());
        EXPECT_EQ(fold.best_height(), 5u);
        EXPECT_EQ(fold.resume_height(), 6u);
        EXPECT_EQ(fold.best_hash().GetHex(), fake_block_hash(5).GetHex());
        auto res = fold.hash_serialized_2();
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(res->hash.GetHex(), hash_before)
            << "reopen must resume the byte-identical set";
        // Redelivery of an already-folded height after reopen: idempotent.
        auto cb3 = make_coinbase(3, {{3000, p2pkh(3)}});
        EXPECT_TRUE(fold.on_replay_block(3, fake_block_hash(3), make_block({cb3})));
        EXPECT_EQ(fold.best_height(), 5u);
    }
}

TEST(ReplayUtxoFoldTest, FormatVersionFailsLoud)
{
    TmpDir tmp;
    const std::string db = tmp.sub("db");
    {
        ReplayUtxoFold fold;
        ASSERT_TRUE(fold.open(db));
        auto cb = make_coinbase(1, {{100, p2pkh(1)}});
        ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb})));
        fold.close();
    }
    {
        // Corrupt the version key the way a future format bump would look.
        ::core::LevelDBStore raw(db, ::core::LevelDBOptions{});
        ASSERT_TRUE(raw.open());
        ASSERT_TRUE(raw.put("V", std::vector<uint8_t>{99, 0, 0, 0}));
        raw.close();
    }
    ReplayUtxoFold fold;
    EXPECT_FALSE(fold.open(db)) << "version mismatch must refuse to open";
}

TEST(ReplayUtxoFoldTest, UndoWindowDefaultAndRetention)
{
    // The shipped window is exactly the Tier-B sizing's 100 blocks.
    EXPECT_EQ(REPLAY_UTXO_UNDO_WINDOW, 100u);
    EXPECT_EQ(ReplayUtxoFoldOptions{}.undo_window, 100u);

    TmpDir tmp;
    ReplayUtxoFoldOptions opts;
    opts.undo_window = 10;  // small window to exercise the prune cheaply
    opts.flush_interval = 1;
    ReplayUtxoFold fold(opts);
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    for (uint32_t h = 1; h <= 25; ++h) {
        auto cb = make_coinbase(h, {{int64_t(h), p2pkh(uint8_t(h))}});
        ASSERT_TRUE(fold.on_replay_block(h, fake_block_hash(h), make_block({cb})))
            << fold.refusal();
    }
    // Window [16..25] retained, everything below pruned.
    for (uint32_t h = 16; h <= 25; ++h)
        EXPECT_TRUE(fold.undo_available(h)) << "h=" << h;
    for (uint32_t h = 1; h <= 15; ++h)
        EXPECT_FALSE(fold.undo_available(h)) << "h=" << h;
}

TEST(ReplayUtxoFoldTest, DisconnectTipRestoresIdenticalSet)
{
    TmpDir tmp;
    ReplayUtxoFoldOptions opts;
    opts.flush_interval = 1;
    ReplayUtxoFold fold(opts);
    ASSERT_TRUE(fold.open(tmp.sub("db")));

    auto cb1 = make_coinbase(1, {{5000, p2pkh(0x11)}});
    const uint256 cb1_id = dash_txid(cb1);
    ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb1})));
    auto cb2 = make_coinbase(2, {{5000, p2pkh(0x22)}});
    ASSERT_TRUE(fold.on_replay_block(2, fake_block_hash(2), make_block({cb2})));

    auto before = fold.hash_serialized_2();
    ASSERT_TRUE(before.has_value());

    // h=3 spends cb1:0; then a reorg disconnects it.
    auto cb3 = make_coinbase(3, {{5000, p2pkh(0x33)}});
    auto sp = make_spend({{cb1_id, 0}}, {{4000, p2pkh(0x44)}});
    auto blk3 = make_block({cb3, sp});
    ASSERT_TRUE(fold.on_replay_block(3, fake_block_hash(3), blk3))
        << fold.refusal();
    EXPECT_FALSE(fold.have_coin({cb1_id, 0}));

    ASSERT_TRUE(fold.disconnect_tip(blk3)) << fold.refusal();
    EXPECT_EQ(fold.best_height(), 2u);
    EXPECT_EQ(fold.best_hash().GetHex(), fake_block_hash(2).GetHex());
    EXPECT_TRUE(fold.have_coin({cb1_id, 0}))
        << "disconnect must restore the spent coin";

    auto after = fold.hash_serialized_2();
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->hash.GetHex(), before->hash.GetHex())
        << "connect+disconnect must be byte-identical to never-connected";

    // Reconnect: same block folds again, resume contract intact.
    ASSERT_TRUE(fold.on_replay_block(3, fake_block_hash(3), blk3))
        << fold.refusal();
    EXPECT_FALSE(fold.have_coin({cb1_id, 0}));
}

TEST(ReplayUtxoFoldTest, EmptyVinSpecialTxShapeFoldsOutputsOnly)
{
    // Asset-unlock (type 9) shape: NO inputs, plain vouts — must fold its
    // outputs without any coinbase or spend semantics.
    TmpDir tmp;
    ReplayUtxoFold fold;
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    auto cb1 = make_coinbase(1, {{100, p2pkh(0x01)}});
    ASSERT_TRUE(fold.on_replay_block(1, fake_block_hash(1), make_block({cb1})));

    auto cb2 = make_coinbase(2, {{100, p2pkh(0x02)}});
    MutableTransaction unlock = make_spend({}, {{777, p2pkh(0x99)}});
    unlock.type = 9;
    unlock.extra_payload = {0x01, 0x02, 0x03};
    ASSERT_TRUE(
        fold.on_replay_block(2, fake_block_hash(2), make_block({cb2, unlock})))
        << fold.refusal();

    ::core::coin::Coin c;
    ASSERT_TRUE(fold.get_coin({dash_txid(unlock), 0}, c));
    EXPECT_EQ(c.value, 777);
    EXPECT_FALSE(c.coinbase) << "asset-unlock vouts are NOT coinbase coins";
}

TEST(ReplayUtxoFoldTest, ConsumerCallbackMirrorsSeamShape)
{
    // The plain-callback form W5 will hand the transport: same contract,
    // no interface type shared with the sibling PRs.
    TmpDir tmp;
    ReplayUtxoFold fold;
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    auto consume = fold.consumer();
    auto cb = make_coinbase(1, {{100, p2pkh(0x01)}});
    EXPECT_TRUE(consume(1, fake_block_hash(1), make_block({cb})));
    EXPECT_EQ(fold.best_height(), 1u);
}

TEST(ReplayUtxoFoldTest, EmptySetHashIsHashBlockOnly)
{
    // Degenerate but pinned: an empty set hashes to SHA256d(hashBlock) —
    // for a store with only the genesis pin, that is SHA256d(genesis hash).
    TmpDir tmp;
    ReplayUtxoFold fold;
    ASSERT_TRUE(fold.open(tmp.sub("db")));
    auto gcb = make_coinbase(0, {{1, p2pkh(0x01)}});
    const uint256 ghash = fake_block_hash(0);
    ASSERT_TRUE(fold.on_replay_block(0, ghash, make_block({gcb})));
    auto res = fold.hash_serialized_2();
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->coins, 0u);
    std::vector<uint8_t> pre(ghash.data(), ghash.data() + 32);
    EXPECT_EQ(res->hash.GetHex(), ::Hash(pre).GetHex());
}

}  // namespace
