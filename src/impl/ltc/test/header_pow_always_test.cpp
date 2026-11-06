// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded LTC header chain verifies every header's scrypt PoW above the
// checkpoint, whatever height a peer reports (rides share_test):
//   - with a peer-reported height of 4,000,000,000 a header that fails its
//     PoW is refused, the one that passes accepted; the reported height is
//     bounded by the growth the tip allows;
//   - a pinned checkpoint's height takes only the checkpoint's block: a
//     sibling there is refused; a chain already holding another block there
//     loses it and its descendants;
//   - the normal sync (add_headers, batches past HEADER_BATCH) accepts a
//     mined chain and stops at the first header that fails;
//   - a store written before this check holds headers whose PoW hash is the
//     placeholder (the block hash): each is verified at load, one that fails
//     dropped with its descendants;
//   - the scrypt cost per header, printed (the sync's price).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/test/ltc_mined_headers.hpp>

namespace {

using namespace ltc::coin;
using ltc_test::easy_testnet_genesis;
using ltc_test::easy_testnet_params;
using ltc_test::kEasyBits;

uint256 hash_of(const BlockHeaderType& h) { return Hash(pack(h).get_span()); }

BlockHeaderType child(const uint256& prev, uint32_t height, uint32_t tag = 0)
{
    BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = prev;
    h.m_merkle_root.SetHex(std::to_string(9000 + height * 16 + tag));
    h.m_timestamp = 1486949366 + 150 * height;
    h.m_bits = kEasyBits;
    h.m_nonce = (height << 8) | tag;
    return h;
}

/// Genesis, then n mined headers.
std::vector<BlockHeaderType> mined_chain(uint32_t n)
{
    std::vector<BlockHeaderType> c;
    uint256 prev = hash_of(easy_testnet_genesis());
    for (uint32_t h = 1; h <= n; ++h) {
        BlockHeaderType x = child(prev, h);
        ltc_test::mine(x);
        prev = hash_of(x);
        c.push_back(x);
    }
    return c;
}

struct TempDir {
    std::filesystem::path dir;
    TempDir()
    {
        std::mt19937_64 rng(std::random_device{}());
        dir = std::filesystem::temp_directory_path() / ("ltc_header_pow_" + std::to_string(rng()));
    }
    ~TempDir()
    {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

} // namespace

TEST(LtcHeaderPow, AClaimedHeightNeverSkipsThePowCheck)
{
    HeaderChain chain(easy_testnet_params());
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(easy_testnet_genesis()));
    chain.set_peer_tip_height(4'000'000'000u);

    BlockHeaderType bad = child(hash_of(easy_testnet_genesis()), 1);
    ltc_test::unmine(bad);
    EXPECT_FALSE(chain.add_header(bad)) << "a header failing its PoW, 4e9 blocks below the claimed tip";
    EXPECT_EQ(chain.height(), 0u);
    std::vector<BlockHeaderType> batch{bad};
    EXPECT_EQ(chain.add_headers(batch), 0);

    BlockHeaderType good = child(hash_of(easy_testnet_genesis()), 1);
    ltc_test::mine(good);
    EXPECT_TRUE(chain.add_header(good));
    EXPECT_EQ(chain.height(), 1u);

    // The claim is bounded by the growth the tip's age allows, and one peer's
    // claim gives way to the median of the peers'.
    const uint64_t age = static_cast<uint64_t>(std::time(nullptr)) - good.m_timestamp;
    EXPECT_LE(chain.peer_tip_height(), 1u + age / (150 / 4) + 2016);
    EXPECT_LT(chain.peer_tip_height(), 4'000'000'000u);
    for (int i = 0; i < 3; ++i)
        chain.set_peer_tip_height(5);
    EXPECT_EQ(chain.peer_tip_height(), 5u) << "the median of 4e9, 5, 5, 5";

    // The real difficulty: testnet's own bits, a header nobody mined.
    HeaderChain real(make_ltc_chain_params_testnet());
    ASSERT_TRUE(real.init());
    BlockHeaderType g = easy_testnet_genesis();
    g.m_bits = 0x1e0ffff0;  // testnet's genesis
    ASSERT_TRUE(real.add_header(g));
    real.set_peer_tip_height(4'000'000'000u);
    BlockHeaderType x = child(hash_of(g), 1);
    x.m_bits = 0x1e0ffff0;
    x.m_timestamp = g.m_timestamp + 150;
    EXPECT_FALSE(real.add_header(x));
    EXPECT_EQ(real.height(), 0u);
}

TEST(LtcHeaderPow, AWrongHashAtTheCheckpointHeightIsRefused)
{
    const auto c = mined_chain(3);
    {
        HeaderChain chain(easy_testnet_params());
        ASSERT_TRUE(chain.init());
        ASSERT_TRUE(chain.add_header(easy_testnet_genesis()));
        for (const auto& h : c)
            ASSERT_TRUE(chain.add_header(h));
        chain.set_dynamic_checkpoint(2, hash_of(c[1]));  // below the tip: pinned only
        EXPECT_EQ(chain.height(), 3u);
        BlockHeaderType sibling = child(hash_of(c[0]), 2, 1);
        ltc_test::mine(sibling);
        EXPECT_FALSE(chain.add_header(sibling)) << "another block at the checkpoint height";
        BlockHeaderType above = child(hash_of(c[2]), 4);
        ltc_test::mine(above);
        EXPECT_TRUE(chain.add_header(above)) << "the checkpoint's chain goes on";
    }
    {
        // The chain holds another block at the checkpoint's height: it and
        // its descendants go; the checkpoint, now above the tip, seeds the
        // chain at its height.
        HeaderChain chain(easy_testnet_params());
        ASSERT_TRUE(chain.init());
        ASSERT_TRUE(chain.add_header(easy_testnet_genesis()));
        for (const auto& h : c)
            ASSERT_TRUE(chain.add_header(h));
        uint256 other;
        other.SetHex("00000000000000000000000000000000000000000000000000000000000c0ffe");
        chain.set_dynamic_checkpoint(2, other);
        EXPECT_FALSE(chain.has_header(hash_of(c[1])));
        EXPECT_FALSE(chain.has_header(hash_of(c[2])));
        EXPECT_TRUE(chain.has_header(hash_of(c[0])));
        EXPECT_EQ(chain.height(), 2u);
        EXPECT_EQ(chain.tip()->block_hash, other);
        EXPECT_FALSE(chain.add_header(c[1])) << "not the checkpoint";
    }
    {
        // A checkpoint in the parameters is pinned too.
        auto p = easy_testnet_params();
        LTCChainParams::Checkpoint cp;
        cp.height = 0;
        cp.hash = p.genesis_hash;
        p.fast_start_checkpoint = cp;
        HeaderChain chain(p);
        ASSERT_TRUE(chain.init());
        EXPECT_TRUE(chain.add_header(c[0]));
    }
}

TEST(LtcHeaderPow, TheNormalSyncStillWorks)
{
    const uint32_t n = static_cast<uint32_t>(3 * HeaderChain::HEADER_BATCH + 7);
    auto c = mined_chain(n);
    HeaderChain chain(easy_testnet_params());
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(easy_testnet_genesis()));
    chain.set_peer_tip_height(n);
    EXPECT_EQ(chain.add_headers(c), static_cast<int>(n));
    EXPECT_EQ(chain.height(), n);
    EXPECT_EQ(chain.tip()->block_hash, hash_of(c.back()));

    // A batch with a header that fails its PoW stops there: what follows has
    // no parent.
    auto d = mined_chain(20);
    HeaderChain other(easy_testnet_params());
    ASSERT_TRUE(other.init());
    ASSERT_TRUE(other.add_header(easy_testnet_genesis()));
    other.set_peer_tip_height(4'000'000'000u);
    ltc_test::unmine(d[9]);
    EXPECT_EQ(other.add_headers(d), 9);
    EXPECT_EQ(other.height(), 9u);
}

TEST(LtcHeaderPow, HeadersStoredUnverifiedAreVerifiedAtLoad)
{
    TempDir t;
    const auto c = mined_chain(6);
    {
        HeaderChain chain(easy_testnet_params(), t.dir.string());
        ASSERT_TRUE(chain.init());
        ASSERT_TRUE(chain.add_header(easy_testnet_genesis()));
        for (const auto& h : c)
            ASSERT_TRUE(chain.add_header(h));
    }
    // As a store written before every header's PoW was checked: headers 2..5
    // with the placeholder PoW hash, and header 7 on top whose PoW fails.
    BlockHeaderType bad = child(hash_of(c[5]), 7);
    ltc_test::unmine(bad);
    {
        core::LevelDBStore db(t.dir.string(), core::LevelDBOptions{});
        ASSERT_TRUE(db.open());
        auto put_entry = [&](const BlockHeaderType& h, uint32_t height, const uint256& work) {
            IndexEntry e;
            e.header = h;
            e.block_hash = hash_of(h);
            e.hash = e.block_hash;  // the placeholder
            e.height = height;
            e.chain_work = work;
            e.prev_hash = h.m_previous_block;
            e.status = HEADER_VALID_CHAIN;
            auto packed = pack(e);
            std::vector<uint8_t> data(reinterpret_cast<const uint8_t*>(packed.data()),
                                      reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());
            std::string key = "h";
            key.append(reinterpret_cast<const char*>(e.block_hash.data()), 32);
            ASSERT_TRUE(db.put(key, data));
        };
        for (uint32_t h = 2; h <= 5; ++h)
            put_entry(c[h - 1], h, uint256::ONE);
        uint256 work;
        work.SetHex("ffff");
        put_entry(bad, 7, work);
        const uint256 tip = hash_of(bad);
        ASSERT_TRUE(db.put("tip", std::vector<uint8_t>(tip.data(), tip.data() + 32)));
    }
    HeaderChain chain(easy_testnet_params(), t.dir.string());
    ASSERT_TRUE(chain.init());
    EXPECT_FALSE(chain.has_header(hash_of(bad))) << "its PoW fails: dropped";
    EXPECT_EQ(chain.height(), 6u) << "the tip moved back to the failing header's parent";
    for (const auto& h : c)
        EXPECT_TRUE(chain.has_header(hash_of(h)));
    EXPECT_NE(chain.get_header(hash_of(c[2]))->hash, hash_of(c[2])) << "stored with its scrypt hash now";
}

// The price of checking every header: scrypt per header on this host (LTC
// above the 3,088,000 checkpoint is ~120,000 headers; from genesis ~3.2 M).
TEST(LtcHeaderPow, ScryptCostPerHeader)
{
    const auto p = make_ltc_chain_params_mainnet();
    BlockHeaderType h = child(hash_of(easy_testnet_genesis()), 1);
    constexpr int N = 2000;
    const auto t0 = std::chrono::steady_clock::now();
    uint256 acc;
    for (int i = 0; i < N; ++i) {
        h.m_nonce = static_cast<uint32_t>(i);
        acc = pow_hash(h, p.pow_func);
    }
    const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count() / N;
    std::cout << "[ltc-header-pow] scrypt " << us << " us/header: 120,000 headers " << us * 120000 / 1e6
              << " s, 3,200,000 headers " << us * 3200000 / 1e6 << " s (one thread)" << std::endl;
    EXPECT_FALSE(acc.IsNull());
}
