// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// test_dash_dashboard_found_block — the BINDING KAT for DASH's any-participant
// found-block dashboard feed.
//
// THE DEFECT. /recent_blocks is served from MiningInterface::m_found_blocks,
// appended only by record_found_block(). On DASH the sole binding of that was
// the LOCAL stratum win, so a block found by ANOTHER pool participant paid out
// correctly and appeared NOWHERE on the dashboard. dash::ShareTracker already
// fires m_on_block_found for that event (share_tracker.hpp:368 declared, :398
// and :574-578 fired) and ltc/btc/dgb/bch all bind it; DASH did not.
//
// WHY THESE KATs ARE NOT VACUOUS. The hook fires with the caller ALREADY
// holding m_tracker_mutex EXCLUSIVELY (compute thread inside think() ->
// attempt_verify, or add_local_share's try-lock). A handler that took that
// lock would be permanently dead code — the #878/#881 class, where a callee
// under a caller-held exclusive lock never runs and its unit tests pass on
// unreachable code. So KAT 1 reproduces the PRODUCTION lock context exactly:
// a real dash::NodeImpl, the exclusive tracker lock HELD, this thread marked
// as the compute thread, and the REAL tracker firing the REAL handler
// (dash::dashboard::make_on_block_found — the same closure main_dash.cpp
// installs). KAT 2 is the negative control: identical setup with the hook
// UNBOUND records nothing, which is precisely the shipped defect.
//
// Display-only surface: no block submission, mint, target or payout path is
// reachable from any code these KATs drive.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dash/node.hpp>
#include <impl/dash/dashboard_found_block.hpp>
#include <impl/dash/share.hpp>

#include <core/uint256.hpp>
#include <core/target_utils.hpp>
#include <core/web_server.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// A block target so slack that any pow_hash we choose clears it — the block
// detection arithmetic itself is pinned elsewhere; here we only need the
// tracker to decide "this share is a block" and fire.
constexpr uint32_t BLOCK_BITS = 0x1d00ffff;
// A distinct, harder share target so share_difficulty is non-zero and
// demonstrably read from the share's OWN bits, not from min_header.
constexpr uint32_t SHARE_BITS = 0x1e0ffff0;

constexpr uint32_t BLOCK_HEIGHT = 2511303;   // 0x2651c7 — a real DASH height
constexpr uint32_t HEADER_TIME  = 1753000000;
constexpr uint64_t SUBSIDY      = 155000000; // duffs

// Distinct, deterministic share identities. base_uint::begin() yields
// uint32_t*, so these go through SetHex rather than byte indexing.
uint256 hash_from_byte(unsigned char b)
{
    static const char* digits = "0123456789abcdef";
    std::string s = "11";
    s += digits[b >> 4];
    s += digits[b & 0x0f];
    s += std::string(64 - s.size(), '0');
    uint256 h;
    h.SetHex(s);
    return h;
}

// A pow_hash small enough to clear BLOCK_BITS (0x1d00ffff -> 0x00000000ffff…).
uint256 winning_pow_hash()
{
    uint256 h;
    h.SetHex(std::string(63, '0') + "1");
    return h;
}

uint160 miner_pubkey_hash()
{
    uint160 h;
    h.SetHex("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");
    return h;
}

// BIP34 height push, hand-encoded here rather than reused from the production
// builder so the decode under test is pinned against an INDEPENDENT encoding.
// 2511303 == 0x2651c7 -> LE c7 51 26, minimal data push of length 3.
std::vector<unsigned char> bip34_scriptsig()
{
    std::vector<unsigned char> cb{0x03, 0xc7, 0x51, 0x26};
    const std::string tag = "/P2Pool-DASH/c2pool/";
    cb.insert(cb.end(), tag.begin(), tag.end());
    return cb;
}

// A share whose header hash also clears the coin BLOCK target — i.e. exactly
// what a peer gossips in when the pool wins a block off a foreign rig.
dash::DashShare* make_won_block_share(const uint256& share_hash)
{
    auto* s = new dash::DashShare();
    s->m_hash      = share_hash;
    s->m_prev_hash = uint256::ZERO;
    s->m_min_header.m_bits      = BLOCK_BITS;
    s->m_min_header.m_timestamp = HEADER_TIME;
    s->m_bits        = SHARE_BITS;
    s->m_pubkey_hash = miner_pubkey_hash();
    s->m_subsidy     = SUBSIDY;
    s->m_coinbase.m_data = bip34_scriptsig();
    return s;
}

// Real node, with the one seam a KAT needs: the ability to declare THIS thread
// the compute thread, so read_tracker() takes the production (no-lock,
// exclusive-already-held) branch instead of the try-lock branch.
class HookNode : public dash::NodeImpl
{
public:
    using dash::NodeImpl::NodeImpl;
    void mark_this_thread_compute()
    {
        m_compute_thread_id.store(std::this_thread::get_id(), std::memory_order_relaxed);
    }
};

// The fixture stands up the node + share + handler exactly as main_dash.cpp
// does, and captures the rows the sink is handed.
struct Harness
{
    HookNode                                    node;
    boost::asio::io_context                     ioc;
    std::vector<dash::dashboard::FoundBlockRow> rows;
    uint256                                     share_hash{hash_from_byte(0x7e)};

    Harness()
    {
        node.tracker().chain.add(make_won_block_share(share_hash));
        auto* idx = node.tracker().chain.get_index(share_hash);
        idx->pow_hash = winning_pow_hash();
    }

    // Bind the PRODUCTION handler (the closure main_dash.cpp installs).
    void bind(bool testnet)
    {
        node.tracker().m_on_block_found =
            dash::dashboard::make_on_block_found(
                &node, testnet,
                [this](std::function<void()> work) {
                    boost::asio::post(ioc, std::move(work));
                },
                [this](const dash::dashboard::FoundBlockRow& row) {
                    rows.push_back(row);
                });
    }

    // Run whatever the handler posted. restart() is required before every
    // poll() after the first: an io_context that has run out of work is left
    // stopped and silently drops later handlers otherwise.
    void drain()
    {
        ioc.restart();
        ioc.poll();
    }

    // Drive the REAL tracker fire path under the REAL production lock context:
    // exclusive tracker lock held, this thread marked as the compute thread.
    // Returns the number of rows delivered BEFORE the io_context is drained.
    size_t fire_under_exclusive_lock()
    {
        size_t during_lock = 0;
        {
            std::unique_lock<std::shared_mutex> lk(node.tracker_mutex());
            node.mark_this_thread_compute();
            node.tracker().scan_chain_for_blocks(share_hash, 4);
            during_lock = rows.size();
        }
        drain();
        return during_lock;
    }
};

} // namespace

// 1) THE GATE. With the hook BOUND, a block found by any pool participant
//    reaches the dashboard sink — fired from inside the tracker with the
//    exclusive lock held, i.e. the handler is NOT dead code under the
//    caller-side lock (#878/#881).
TEST(DashDashboardFoundBlock, BoundHookRecordsPeerFoundBlock)
{
    Harness h;
    h.bind(/*testnet=*/false);

    const size_t during_lock = h.fire_under_exclusive_lock();

    ASSERT_EQ(h.rows.size(), 1u)
        << "the tracker fired m_on_block_found but no dashboard row arrived";
    EXPECT_EQ(during_lock, 0u)
        << "the dashboard write must be POSTED, never performed under the "
           "exclusive tracker lock";

    const auto& row = h.rows.front();
    // Block identity is the tracker's own key: on DASH the share hash IS
    // X11(block header), which is what the stratum arm records too.
    EXPECT_EQ(row.block_hash, h.share_hash);
    EXPECT_EQ(row.share_hash, h.share_hash.GetHex());
    // Chain label must match the stratum arm's exactly or a local win double-lists.
    EXPECT_EQ(row.chain, "DASH");
    // Coin block height comes from the BIP34 push, NOT the sharechain absheight.
    EXPECT_EQ(row.height, static_cast<uint64_t>(BLOCK_HEIGHT));
    EXPECT_EQ(row.timestamp, static_cast<uint64_t>(HEADER_TIME));
    EXPECT_EQ(row.subsidy, SUBSIDY);
    // Share difficulty is read from the share's own committed target.
    EXPECT_DOUBLE_EQ(row.share_difficulty,
                     chain::target_to_difficulty(chain::bits_to_target(SHARE_BITS)));
    EXPECT_NE(row.share_difficulty,
              chain::target_to_difficulty(chain::bits_to_target(BLOCK_BITS)));
    // Finder renders as a DASH mainnet address, not a Bitcoin '1…'.
    ASSERT_FALSE(row.miner.empty());
    EXPECT_EQ(row.miner[0], 'X');
}

// 2) THE NEGATIVE CONTROL — the shipped defect. Identical tracker, identical
//    won block, hook UNBOUND: nothing is recorded. This is the assertion that
//    fails without the main_dash.cpp binding.
TEST(DashDashboardFoundBlock, UnboundHookRecordsNothing)
{
    Harness h;   // deliberately no bind()

    h.fire_under_exclusive_lock();

    EXPECT_TRUE(h.rows.empty())
        << "no binding must mean no dashboard row — this is the defect state";
}

// 3) Testnet renders a testnet address. Pins the version-byte selection the
//    row derivation makes (76/'X' vs 140/'y'), which is the only thing that
//    can silently mis-render a finder.
TEST(DashDashboardFoundBlock, TestnetFinderAddressUsesTestnetVersion)
{
    Harness main_h;   main_h.bind(/*testnet=*/false);
    Harness test_h;   test_h.bind(/*testnet=*/true);
    main_h.fire_under_exclusive_lock();
    test_h.fire_under_exclusive_lock();

    ASSERT_EQ(main_h.rows.size(), 1u);
    ASSERT_EQ(test_h.rows.size(), 1u);
    EXPECT_EQ(test_h.rows.front().miner[0], 'y');
    EXPECT_NE(test_h.rows.front().miner, main_h.rows.front().miner);
}

// 4) THE LOCK TRACE, pinned. When the exclusive tracker lock is held by a
//    DIFFERENT thread and we are not the compute thread, read_tracker() hands
//    back a falsy guard: the handler SKIPS. It must never block behind
//    think() and never deadlock. (The only production path that reaches here
//    falsy is the local mint, whose win the stratum arm already recorded.)
TEST(DashDashboardFoundBlock, HandlerSkipsRatherThanBlockingWhenTrackerBusy)
{
    Harness h;
    h.bind(/*testnet=*/false);

    std::mutex               m;
    std::condition_variable  cv;
    bool                     locked = false;
    bool                     release = false;

    std::thread holder([&] {
        std::unique_lock<std::shared_mutex> lk(h.node.tracker_mutex());
        {
            std::lock_guard<std::mutex> g(m);
            locked = true;
        }
        cv.notify_one();
        std::unique_lock<std::mutex> g(m);
        cv.wait(g, [&] { return release; });
    });

    {
        std::unique_lock<std::mutex> g(m);
        cv.wait(g, [&] { return locked; });
    }

    // Not the compute thread, exclusive lock held elsewhere: must return
    // promptly having recorded nothing.
    h.node.tracker().m_on_block_found(h.share_hash);
    h.drain();
    EXPECT_TRUE(h.rows.empty()) << "a busy tracker must be skipped, not read unlocked";

    {
        std::lock_guard<std::mutex> g(m);
        release = true;
    }
    cv.notify_one();
    holder.join();

    // With the lock free again the same call records normally — the skip above
    // was a live try-lock miss, not a permanently dead handler.
    h.node.tracker().m_on_block_found(h.share_hash);
    h.drain();
    EXPECT_EQ(h.rows.size(), 1u);
}

// 5) DEDUP is keyed on the BLOCK HASH (never a prev-hash). A local win is
//    recorded by the stratum arm and then re-fires through this hook once the
//    winning share is minted onto the sharechain (#888); both carry the same
//    block hash and the same "DASH" label, and record_found_block collapses
//    them. A genuinely different block still lists.
TEST(DashDashboardFoundBlock, RecordFoundBlockDedupsOnBlockHash)
{
    core::MiningInterface mi(/*testnet=*/false, nullptr, Blockchain::DASH);

    const uint256 block_a = hash_from_byte(0x41);
    const uint256 block_b = hash_from_byte(0x42);

    // The stratum arm records the local win first.
    mi.record_found_block(BLOCK_HEIGHT, block_a, HEADER_TIME, "DASH",
                          "Xminer", block_a.GetHex(), 1.0, 2.0, 3.0, SUBSIDY);
    ASSERT_EQ(mi.rest_recent_blocks().size(), 1u);

    // The sharechain arm re-fires for the SAME block — same hash, same chain.
    mi.record_found_block(BLOCK_HEIGHT, block_a, HEADER_TIME + 5, "DASH",
                          "Xminer", block_a.GetHex(), 1.0, 2.0, 3.0, SUBSIDY);
    EXPECT_EQ(mi.rest_recent_blocks().size(), 1u)
        << "a locally-won block must not list twice";

    // A different block at the SAME height must still list — the key is the
    // block hash, not the height and not any prev-hash.
    mi.record_found_block(BLOCK_HEIGHT, block_b, HEADER_TIME + 9, "DASH",
                          "Xminer", block_b.GetHex(), 1.0, 2.0, 3.0, SUBSIDY);
    EXPECT_EQ(mi.rest_recent_blocks().size(), 2u);
}

// 6) FINDER ATTRIBUTION IS THE SHARE'S OWN COMMITTED PAYOUT — pinned against
//    the 2026-08-05 h=2516911 incident. The reserve dashboard showed
//    miner=XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4 for our pool's block and the
//    operator read it as a wrong pick of a coinbase output (the MN payee or
//    the operator split). It is neither: row_from_share() reads
//    s.m_pubkey_hash — the payout identity the winning share itself commits
//    to, i.e. the FINDER, who can be any pool participant on any node — and
//    never inspects a coinbase output. The accepted coinbase paying that
//    same address a small PPLNS slice (output 1, 0.0407 DASH) is what
//    CONFIRMS the finder was a genuine (small) participant. This KAT builds
//    a share committing to XghF…'s real hash160 while the coinbase
//    scriptSig-side data carries a DIFFERENT (miner_pubkey_hash) identity
//    everywhere else in this file, and pins that the row encodes exactly the
//    share's committed payout.
TEST(DashDashboardFoundBlock, MinerIsTheSharesCommittedPayoutNotACoinbaseOutput)
{
    dash::DashShare s;
    s.m_hash      = hash_from_byte(0x66);
    s.m_min_header.m_timestamp = HEADER_TIME;
    s.m_bits      = SHARE_BITS;
    s.m_subsidy   = 177109977;   // the real h=2516911 coinbase total
    s.m_coinbase.m_data = bip34_scriptsig();
    // XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4 == P2PKH(version 76) over hash160
    // 41e4d6d8971a735946494cdbc5e8602c5209b98e (decoded from the address;
    // the accepted block's output 1 pays the same script). SetHex parses a
    // big-endian NUMBER into little-endian storage, and the P2PKH script is
    // built from the INTERNAL bytes — so the hex is fed reversed to land the
    // script bytes in wire order.
    s.m_pubkey_hash.SetHex("8eb909522c60e8c5db4c494659731a97d8d6e441");

    const auto row = dash::dashboard::row_from_share(
        s.m_hash, s, /*testnet=*/false);

    EXPECT_EQ(row.miner, "XghFtkZ8W3vhEHejUBbD3n387hemVJ6Pt4")
        << "the row's miner must be the share's committed payout address";
    EXPECT_EQ(row.subsidy, 177109977u);
}
