// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A restart reloads the whole persisted window, whatever was pruned before a
// graceful stop.
//
// THE incident (2026-11-13, LTC): after a restart the nodes could not
// reconnect their saved tip to the live share chain and stalled for hours.
// The sharechain store kept ONE hash per absheight in its `height:` index,
// and removing ANY share of a height deleted that key: every fork share that
// clean_tracker pruned took the main-chain share of its height out of the
// index. load_persisted_shares read only that index. A copy of a production
// store held 18,478 contiguous verified main-chain shares; 4,172 of them were
// reachable through the height index, so the node reloaded ~23 % of its window
// in fragments. The ungraceful-shutdown rebuild of the index repairs it, but a
// graceful stop clears the dirty flag and the rebuild never runs.
//
// Pinned here:
//   * the store: removing one share of a height leaves the other shares of
//     that height in the height index (both orders; single and batch remove),
//     and a store written with the old one-hash index is rebuilt once on open;
//   * the loader (the REAL ltc::NodeImpl::load_persisted_shares over a REAL
//     LevelDB store): fork shares pruned before a graceful stop cost nothing
//     of the main chain; the window is the 2*CHAIN_LENGTH+10 absheights ending
//     at the highest VERIFIED share, so an unverified share claiming a huge
//     absheight neither hides the chain nor gets it pruned; with nothing
//     verified, nothing is pruned.
//
// RED on master: every store and loader test here except
// GracefulStopReloadsTheNewestWindowAndPrunesBelowIt (master's count-based
// window passes it too). The pure window test does not build on master.
//
// Folded into the existing allowlisted `share_test` target (the #769 trap).

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#include <c2pool/storage/sharechain_storage.hpp>
#include <core/filesystem.hpp>
#include <core/leveldb_store.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/persisted_reload.hpp>
#include <impl/ltc/share.hpp>
#include <sharechain/share.hpp>

namespace {

std::filesystem::path fresh_dir(const char* tag)
{
    static std::atomic<uint64_t> ctr{0};
    auto dir = std::filesystem::temp_directory_path() /
               ("c2pool_kat_reload_" + std::string(tag) + "_" + std::to_string(::getpid()) + "_" +
                std::to_string(ctr.fetch_add(1)));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

// The data dir is process-wide: set it for one test, put it back after.
struct DataDir
{
    std::filesystem::path saved = core::filesystem::data_dir_override();
    std::filesystem::path dir;
    explicit DataDir(const char* tag) : dir(fresh_dir(tag)) { core::filesystem::set_data_dir(dir); }
    ~DataDir()
    {
        core::filesystem::set_data_dir(saved);
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

uint256 H(uint64_t n) { return uint256(n); }

core::ShareMetadata meta_at(const uint256& prev, uint64_t height)
{
    core::ShareMetadata m;
    m.prev_hash = prev;
    m.height = height;
    return m;
}

const std::vector<uint8_t> kBlob(16, 0x5a);   // the store does not parse share bytes

std::vector<uint256> all_indexed(core::SharechainLevelDBStore& st)
{
    return st.get_shares_by_height_range(0, UINT64_MAX);
}

// ---- the store --------------------------------------------------------------

// Two shares of one absheight; removing either one keeps the other indexed.
// Master: the key held one hash, and remove deleted it whichever share it named.
TEST(LtcRestartReload, RemovingOneShareOfAHeightKeepsTheOtherIndexed)
{
    for (const bool remove_the_later_one : {true, false}) {
        SCOPED_TRACE(remove_the_later_one ? "remove the share stored second"
                                          : "remove the share stored first");
        const auto dir = fresh_dir("same_height");
        const uint256 parent = H(0x10), first = H(0x11), second = H(0x12);
        const uint256 removed = remove_the_later_one ? second : first;
        const uint256 kept = remove_the_later_one ? first : second;
        {
            core::SharechainLevelDBStore st(dir.string(), "kat");
            ASSERT_TRUE(st.open());
            ASSERT_TRUE(st.store_share(first, kBlob, meta_at(parent, 5)));
            ASSERT_TRUE(st.store_share(second, kBlob, meta_at(parent, 5)));
            ASSERT_TRUE(st.remove_share(removed));
            st.close();   // graceful: the dirty flag is cleared, no rebuild on open
        }
        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        EXPECT_EQ(all_indexed(st), std::vector<uint256>{kept})
            << "the share left at absheight 5 must still be in the height index";
        st.close();
        std::filesystem::remove_all(dir);
    }
}

// The node's clean-up path: fork shares removed in one batch (some stored
// before, some after the main-chain share of their height). The main chain
// stays whole in the height index.
TEST(LtcRestartReload, BatchRemovalOfForkSharesKeepsTheMainChainIndexed)
{
    const auto dir = fresh_dir("batch_forks");
    std::vector<uint256> main;
    std::vector<uint256> forks;
    {
        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        std::vector<core::SharechainLevelDBStore::BatchShareEntry> early, chain, late;
        uint256 prev;
        for (uint64_t h = 1; h <= 20; ++h) {
            const uint256 m = H(0x1000 + h);
            chain.push_back({m, kBlob, meta_at(prev, h)});
            if (h % 3 == 0) {   // a fork share of this height, off the same parent
                const uint256 f = H(0x2000 + h);
                (h % 2 ? early : late).push_back({f, kBlob, meta_at(prev, h)});
                forks.push_back(f);
            }
            main.push_back(m);
            prev = m;
        }
        ASSERT_TRUE(st.store_shares_batch(early));
        ASSERT_TRUE(st.store_shares_batch(chain));
        ASSERT_TRUE(st.store_shares_batch(late));
        ASSERT_TRUE(st.remove_shares_batch(forks));
        st.close();
    }
    core::SharechainLevelDBStore st(dir.string(), "kat");
    ASSERT_TRUE(st.open());
    EXPECT_EQ(all_indexed(st), main) << "every main-chain share, in absheight order, none missing";
    st.close();
    std::filesystem::remove_all(dir);
}

// A store written by a binary whose height index held one hash per height
// (and has the holes that left) is rebuilt from the share records once.
TEST(LtcRestartReload, AStoreWithTheOldOneHashIndexIsRebuiltOnOpen)
{
    const auto dir = fresh_dir("old_index");
    std::vector<uint256> main;
    std::string db_path;
    {
        core::SharechainLevelDBStore st(dir.string(), "kat");
        ASSERT_TRUE(st.open());
        uint256 prev;
        for (uint64_t h = 1; h <= 10; ++h) {
            const uint256 m = H(0x3000 + h);
            ASSERT_TRUE(st.store_share(m, kBlob, meta_at(prev, h)));
            main.push_back(m);
            prev = m;
        }
        db_path = st.db_path();
        st.close();
    }
    {
        // What a pre-fix binary leaves behind after it pruned a fork share of
        // absheight 4 and stopped gracefully.
        core::LevelDBStore raw(db_path, core::LevelDBOptions{});
        ASSERT_TRUE(raw.open());
        raw.remove("height_index_format");
        raw.remove("height:0000000000000004");
        raw.put("dirty", std::vector<uint8_t>{0});
        raw.close();
    }
    core::SharechainLevelDBStore st(dir.string(), "kat");
    ASSERT_TRUE(st.open());
    EXPECT_EQ(all_indexed(st), main) << "the rebuilt index has absheight 4 back";
    st.close();
    std::filesystem::remove_all(dir);
}

// ---- the loader -------------------------------------------------------------

struct ReloadNode : public ltc::NodeImpl
{
    explicit ReloadNode(uint32_t chain_length) : ltc::NodeImpl()
    {
        m_chain = &m_tracker.chain;
        m_coin_params.chain_length = chain_length;       // window = 2*CL+10
        m_coin_params.real_chain_length = chain_length;
    }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    using ltc::NodeImpl::m_storage;
    using ltc::NodeImpl::m_tracker;
};

// share_test.cpp's golden v35 share (type 0x23): real bytes the store's
// [type][bytes] row round-trips. Each test share is a copy of it with its own
// hash (the LevelDB key), parent, absheight and timestamp.
constexpr const char* kGoldenShareHex =
    "23fd9601fe00000020654f11363698fc9a54e43f126f294bd1a33b650148e8b6bb532fc0"
    "8500cb6966e8103066140b041db0022a77e3af9c1de80a16583bed2a6179b63ed410b890"
    "b113cfd0fcd68bafa4096779b90503fd823100731a92d3226d6839617a4b447852353747"
    "66374a575a756e6e43324a7a37325351747746544b68dec14025000000000000fe2302a4"
    "1fb37f52f6747afbbeae61462feaa40b8b3655f8fb7af60843111101ec5f958e93b9a76bb"
    "46536bf807b1caef9635f432d982bd907eb5050130b6ec00aeabc2bb9ca34c5f1ba0bd332"
    "fc3d217d9853754fe42797e32cf9ddddcab6f66ab8056f1b64efa2157281c406fc6a5d9de"
    "6db5e2adf63c86646a4edc91c51f86d74c707c0221e8828011ef310306675b32100739905"
    "93df0d00000000000000000000000100000000000000c357550d5a390b342f665a3d853c0"
    "39a626b803bb37976c20ba0b5ee5a56fceedc0220e67c088987582af73218c99820276bbf"
    "0004c5c18f7dd691f9c4326bfd9930d5567a6d109fec00f4eca887c42e80ddaa57df9bda8"
    "db8b277110a50a9a268b6";

ltc::ShareType mk_share(const uint256& hash, const uint256& prev, uint32_t absheight)
{
    PackStream in;
    in.from_hex(kGoldenShareHex);
    chain::RawShare raw;
    in >> raw;
    ltc::ShareType v = ltc::load_share(raw, NetService{"kat", 0});
    v.invoke([&](auto* obj) {
        obj->m_hash = hash;
        obj->m_prev_hash = prev;
        obj->m_absheight = absheight;
        obj->m_timestamp = 1700000000u + absheight;   // before any flag day
    });
    return v;
}

struct Spec { uint256 hash; uint256 prev; uint32_t absheight; };

// Stores the shares exactly as processing_shares_phase2 does (share_db_entry).
void persist(c2pool::storage::SharechainStorage& st, const std::vector<Spec>& specs)
{
    std::vector<c2pool::storage::SharechainStorage::ShareBatchEntry> batch;
    for (const auto& sp : specs) {
        auto v = mk_share(sp.hash, sp.prev, sp.absheight);
        batch.push_back(ltc::NodeImpl::share_db_entry(v, nullptr));
        v.destroy();
    }
    ASSERT_TRUE(st.store_shares_batch(batch));
}

// As flush_verified_to_leveldb does once think() verified them.
void mark_verified(c2pool::storage::SharechainStorage& st, const std::vector<Spec>& specs)
{
    std::vector<std::pair<uint256, uint256>> pairs;
    for (const auto& sp : specs)
        pairs.emplace_back(sp.hash, H(0xabcdef));   // any non-null cached pow hash
    ASSERT_TRUE(st.mark_shares_verified_with_pow(pairs));
}

std::vector<Spec> linear_chain(uint64_t salt, uint32_t from, uint32_t to)
{
    std::vector<Spec> out;
    uint256 prev;
    for (uint32_t h = from; h <= to; ++h) {
        const uint256 hash = H((salt << 32) + h);
        out.push_back({hash, prev, h});
        prev = hash;
    }
    return out;
}

// Main chain persisted and verified; fork shares at every 4th absheight
// persisted too (half before, half after the main share of their height),
// then pruned — clean_tracker's LevelDB flush — before a graceful stop. The
// restart must reload the whole main chain, verified.
TEST(LtcRestartReload, ForkSharesPrunedBeforeAGracefulStopCostNothingOfTheMainChain)
{
    DataDir dd("forks");
    const auto main = linear_chain(0x51, 1, 60);
    std::vector<Spec> forks_early, forks_late;
    std::vector<uint256> fork_hashes;
    for (const auto& m : main) {
        if (m.absheight % 4 != 0)
            continue;
        Spec f{H(0x9000 + m.absheight), m.prev, m.absheight};
        ((m.absheight / 4) % 2 ? forks_early : forks_late).push_back(f);
        fork_hashes.push_back(f.hash);
    }
    {
        c2pool::storage::SharechainStorage st("kat_reload_forks");
        ASSERT_TRUE(st.is_available());
        persist(st, forks_early);
        persist(st, main);
        persist(st, forks_late);
        mark_verified(st, main);
        ASSERT_TRUE(st.remove_shares_batch(fork_hashes));
    }   // graceful close: the dirty flag is cleared

    ReloadNode node(/*chain_length=*/100);   // window 210 > 60: everything is in it
    node.m_storage = std::make_unique<c2pool::storage::SharechainStorage>("kat_reload_forks");
    node.load_persisted_shares();

    size_t missing = 0;
    for (const auto& m : main)
        missing += node.m_tracker.chain.contains(m.hash) ? 0 : 1;
    EXPECT_EQ(missing, 0u) << "main-chain shares the restart failed to reload";
    EXPECT_EQ(node.m_tracker.chain.size(), main.size());
    EXPECT_EQ(node.m_tracker.verified.size(), main.size()) << "reloaded verified, not re-verified";
}

// No forks: a graceful stop reloads exactly the newest 2*CL+10 absheights and
// prunes what is below them from the store. Green on master too (its
// count-based window is the same here); pins that the new window keeps it.
TEST(LtcRestartReload, GracefulStopReloadsTheNewestWindowAndPrunesBelowIt)
{
    DataDir dd("window");
    const auto main = linear_chain(0x52, 1, 100);
    {
        c2pool::storage::SharechainStorage st("kat_reload_window");
        persist(st, main);
        mark_verified(st, main);
    }
    {
        ReloadNode node(/*chain_length=*/10);   // window 30: absheights 71..100
        node.m_storage = std::make_unique<c2pool::storage::SharechainStorage>("kat_reload_window");
        node.load_persisted_shares();
        EXPECT_EQ(node.m_tracker.chain.size(), 30u);
        for (const auto& m : main)
            EXPECT_EQ(node.m_tracker.chain.contains(m.hash), m.absheight >= 71) << m.absheight;
    }
    c2pool::storage::SharechainStorage st("kat_reload_window");
    EXPECT_EQ(st.get_shares_by_height_range(0, UINT64_MAX).size(), 30u)
        << "the 70 shares below the window are pruned from the store";
}

// An unverified share (a peer's claim) at a huge absheight must not move the
// window: the window ends at the highest VERIFIED share, the whole verified
// window is reloaded, and only shares below it are pruned.
TEST(LtcRestartReload, AnUnverifiedHugeAbsheightNeitherHidesNorPrunesTheChain)
{
    DataDir dd("claim");
    const auto main = linear_chain(0x53, 1, 50);
    const Spec claim{H(0x777777), H(0x666666), 1000000};
    {
        c2pool::storage::SharechainStorage st("kat_reload_claim");
        persist(st, main);
        mark_verified(st, main);
        persist(st, {claim});   // stored, never verified
    }
    {
        ReloadNode node(/*chain_length=*/10);   // window 30: absheights 21..50
        node.m_storage = std::make_unique<c2pool::storage::SharechainStorage>("kat_reload_claim");
        node.load_persisted_shares();
        for (const auto& m : main)
            EXPECT_EQ(node.m_tracker.chain.contains(m.hash), m.absheight >= 21) << m.absheight;
        EXPECT_TRUE(node.m_tracker.chain.contains(claim.hash)) << "above the window: loaded";
    }
    c2pool::storage::SharechainStorage st("kat_reload_claim");
    EXPECT_EQ(st.get_shares_by_height_range(0, UINT64_MAX).size(), 31u)
        << "the 20 verified shares below the window are pruned, nothing else";
}

// Nothing verified (a node that never verified a share): the newest window is
// loaded, and nothing is pruned — no deletion is decided by claimed absheights.
TEST(LtcRestartReload, WithNothingVerifiedNothingIsPruned)
{
    DataDir dd("unverified");
    const auto main = linear_chain(0x54, 1, 50);
    {
        c2pool::storage::SharechainStorage st("kat_reload_unverified");
        persist(st, main);
    }
    {
        ReloadNode node(/*chain_length=*/10);
        node.m_storage = std::make_unique<c2pool::storage::SharechainStorage>("kat_reload_unverified");
        node.load_persisted_shares();
        EXPECT_EQ(node.m_tracker.chain.size(), 30u);
    }
    c2pool::storage::SharechainStorage st("kat_reload_unverified");
    EXPECT_EQ(st.get_shares_by_height_range(0, UINT64_MAX).size(), 50u);
}

// ---- the window (pure: persisted_reload.hpp) --------------------------------

struct E { uint64_t height; bool is_verified; };

TEST(LtcRestartReload, WindowEndsAtTheHighestVerifiedShare)
{
    EXPECT_EQ(ltc::reload_window(std::vector<E>{}, 30).anchor, 0u);
    EXPECT_FALSE(ltc::reload_window(std::vector<E>{}, 30).prune_below);

    // 1..100 verified, 101..120 unverified (received after the last verified
    // flush), plus a claimed 10^9.
    std::vector<E> es;
    for (uint64_t h = 1; h <= 120; ++h)
        es.push_back({h, h <= 100});
    es.push_back({1000000000ull, false});
    const auto w = ltc::reload_window(es, 30);
    EXPECT_EQ(w.anchor, 100u);
    EXPECT_TRUE(w.anchored_on_verified);
    EXPECT_EQ(w.low, 71u) << "the 30 absheights 71..100";
    EXPECT_TRUE(w.prune_below);

    // A window taller than the chain starts at 0 and prunes nothing below.
    EXPECT_EQ(ltc::reload_window(es, 1000).low, 0u);

    // Nothing verified: the highest share anchors, nothing may be pruned.
    std::vector<E> unverified{{5, false}, {9, false}};
    const auto u = ltc::reload_window(unverified, 3);
    EXPECT_EQ(u.anchor, 9u);
    EXPECT_FALSE(u.anchored_on_verified);
    EXPECT_EQ(u.low, 7u);
    EXPECT_FALSE(u.prune_below);
}

} // namespace
