// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Serve-path regression: handle_get_share must answer an ancestor request from
// the persistent LevelDB store when the hot in-memory tracker cannot.
//
// THE defect this pins (kr1z1s desync, 2026-09): a python p2pool-merged peer
// that has this C++ node as its only/primary peer downloads the sharechain by
// walking parents backward with SHAREREQ. handle_get_share answered from the
// hot in-memory tracker ONLY, and on two paths it returned an empty "success":
//
//   (1) try_to_lock MISS — the compute thread holds m_tracker_mutex exclusively
//       during a long think()/fold self-check (a large fraction of wall-clock on
//       a 23k-share chain at ~75% CPU). Every SHAREREQ that landed in that window
//       got {} back.
//   (2) hot-tracker MISS — the requested ancestor was pruned out of the
//       chain_length*2+10 in-memory window but still lives in LevelDB (never
//       pruned). A 5000+ deep sync gap is ENTIRELY this case.
//
// An empty reply is a "good" sharereply with zero shares (protocol_actual.cpp
// HANDLER(sharereq)), so the peer never gets the ancestor and re-requests the
// same parent forever — an intermittent BLACK HOLE. This node became exactly
// that for kr1z1s. The fix serves both paths from the immutable LevelDB history
// (serve_shares_from_storage), which needs no tracker lock.
//
// Red on master: both cases return an EMPTY vector.
// Green after the fix: both return the requested share, byte-identical to what
// was stored.
//
// Folded into the EXISTING allowlisted btc_share_test target — a new
// add_executable would be absent from build.yml and reported "Not Run" by CTest
// (the #769 / #868 trap).

#include <gtest/gtest.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include <core/filesystem.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <impl/btc/node.hpp>
#include <impl/btc/share.hpp>
#include <sharechain/share.hpp>
#include <c2pool/storage/sharechain_storage.hpp>

namespace {

uint256 H(uint64_t n) { return uint256(n); }

// Canonical golden v35 BTC share (leading VarInt type 0x23 == 35), the same
// vector g0_share_wire_parity_test / share_test pin. Gives us a REAL, packable
// share body without standing up a miner.
constexpr const char* GOLDEN_SHARE_HEX =
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

// Minimal concrete NodeImpl (same shape as broadcast_lock_discipline_test):
// the default ctor opens no LevelDB and starts no timers, so a unit test owns
// one. We point m_chain at the tracker chain by hand, and attach a fresh
// LevelDB store in a unique temp directory.
struct TestNode : public btc::NodeImpl
{
    TestNode() : btc::NodeImpl() { m_chain = &m_tracker.chain; }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}

    using btc::NodeImpl::handle_get_share;
    using btc::NodeImpl::m_storage;
    using btc::NodeImpl::m_tracker;
};

std::vector<uint8_t> to_bytes(std::span<std::byte> sp) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                               reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

// Build a node with a private LevelDB store holding exactly one golden share
// under key `key`. The share is deliberately NOT added to the hot tracker, so
// answering the request REQUIRES the storage path. Returns the packed share
// body (version-less) so the caller can assert byte-parity on the reply.
std::unique_ptr<TestNode> make_node_with_stored_share(
    const uint256& key, const uint256& prev, std::vector<uint8_t>& content_out)
{
    // Unique per-node datadir so concurrent/sequential tests never share a
    // LevelDB LOCK.
    static std::atomic<uint64_t> ctr{0};
    auto dir = std::filesystem::temp_directory_path() /
               ("c2pool_kat_serve_" + std::to_string(::getpid()) + "_" +
                std::to_string(ctr.fetch_add(1)));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    core::filesystem::set_data_dir(dir);

    // Decode the golden share into a real ShareType.
    PackStream in;
    in.from_hex(GOLDEN_SHARE_HEX);
    chain::RawShare rshare;
    in >> rshare;
    NetService src{"golden", 0};
    btc::ShareType golden = btc::load_share(rshare, src);

    // Serialize exactly as the production store path does: [version:u64 LE][body].
    uint64_t ver = golden.version();
    PackStream ps = pack(golden);
    content_out = to_bytes(ps.get_span());
    golden.destroy();

    std::vector<uint8_t> versioned(8 + content_out.size());
    std::memcpy(versioned.data(), &ver, 8);
    std::memcpy(versioned.data() + 8, content_out.data(), content_out.size());

    auto node = std::make_unique<TestNode>();
    node->m_storage = std::make_unique<c2pool::storage::SharechainStorage>("kat");
    EXPECT_TRUE(node->m_storage->is_available());
    // m_hash is not part of the serialized body — it is the LevelDB key, exactly
    // how the production store/load path addresses a share.
    EXPECT_TRUE(node->m_storage->store_share(
        key, versioned, prev, /*height=*/5, /*timestamp=*/1000,
        /*work=*/uint256::ZERO, /*target=*/uint256::ZERO, /*is_orphan=*/false));

    return node;
}

} // namespace

// Case (2): no lock held, but the requested hash is not in the hot tracker.
// This is the deep-gap case that dominates a 5000+ ancestor sync.
TEST(BtcServeFromStorage, HotTrackerMissIsServedFromStorage)
{
    const uint256 key = H(1000);
    const uint256 prev = H(999);
    std::vector<uint8_t> content;
    auto node = make_node_with_stored_share(key, prev, content);

    NetService peer{"peer", 0};
    ASSERT_FALSE(node->m_tracker.chain.contains(key))
        << "precondition: the share must be absent from the hot tracker";

    auto reply = node->handle_get_share({key}, /*parents=*/0, /*stops=*/{}, peer);

    ASSERT_EQ(reply.size(), 1u)
        << "master returns {} for a hash pruned out of memory — the black hole "
           "that starves a python peer filling a deep gap";
    EXPECT_EQ(reply[0].hash(), key);
    EXPECT_EQ(to_bytes(pack(reply[0]).get_span()), content)
        << "served bytes must be byte-identical to the stored share body";

    for (auto& s : reply) s.destroy();
}

// Case (1): the compute thread holds m_tracker_mutex exclusively (long think()).
// The IO thread's try_to_lock misses. Same-thread exclusive-hold reproduces the
// miss deterministically (the idiom used by broadcast_lock_discipline_test).
TEST(BtcServeFromStorage, TryLockMissIsServedFromStorage)
{
    const uint256 key = H(2000);
    const uint256 prev = H(1999);
    std::vector<uint8_t> content;
    auto node = make_node_with_stored_share(key, prev, content);

    NetService peer{"peer", 0};

    std::vector<btc::ShareType> reply;
    {
        std::unique_lock<std::shared_mutex> exclusive(node->tracker_mutex());
        ASSERT_TRUE(exclusive.owns_lock());
        reply = node->handle_get_share({key}, /*parents=*/0, /*stops=*/{}, peer);
    }

    ASSERT_EQ(reply.size(), 1u)
        << "master returns {} whenever the exclusive lock is held — the "
           "intermittent black hole under the fold self-check";
    EXPECT_EQ(reply[0].hash(), key);
    EXPECT_EQ(to_bytes(pack(reply[0]).get_span()), content);

    for (auto& s : reply) s.destroy();
}

// A hash that is in NEITHER the hot tracker NOR storage must still yield an
// empty reply — the fix must not fabricate shares.
TEST(BtcServeFromStorage, UnknownHashStillReturnsEmpty)
{
    const uint256 key = H(3000);
    const uint256 prev = H(2999);
    std::vector<uint8_t> content;
    auto node = make_node_with_stored_share(key, prev, content);

    NetService peer{"peer", 0};
    auto reply = node->handle_get_share({H(999999)}, /*parents=*/0, {}, peer);
    EXPECT_TRUE(reply.empty());
    for (auto& s : reply) s.destroy();
}
