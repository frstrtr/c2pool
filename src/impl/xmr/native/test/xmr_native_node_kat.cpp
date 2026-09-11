// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_node_kat.cpp
//
// M0: the parts of the ASSEMBLY that can be judged without a daemon.
//
// The node itself is proven against a real monerod (node/README.md carries the
// regtest run). What is proven HERE is everything that would otherwise only be
// true because a live run happened to pass, and each of these is a regression
// the live run would show as a puzzling symptom rather than as a failed check:
//
//   * THE IO-THREAD FENCE, as a number. ThreadWitnessPowSource counts RandomX
//     evaluations that ran on a forbidden thread. The claim "RandomX never runs
//     on the io thread" is only as good as this counter being zero, so the
//     counter itself is tested: it must catch a call made on a forbidden thread
//     and must not fire on the worker.
//   * THE QUEUES. A bounded queue that silently grew, or a control task that a
//     peer's flood could push out, would both look fine right up to the moment
//     they mattered.
//   * THE DEFERRED TXPOOL VERDICT. TxSinkLoop answers the io thread with NO
//     verdicts and reports drop-offences afterwards. Inventing an "accepted"
//     verdict would disarm C1c's peer scoring invisibly, so the test asserts
//     both halves: the immediate answer is empty AND the offence still arrives.
//   * THE GENESIS DERIVATION. Every number in row zero is computed from the
//     genesis BLOB, against monerod's own published values for that block
//     (block_weight 80, reward 17592186044415, timestamp 0, major_version 1).
//     The blob is the one a real monerod returned for height 0; nothing in this
//     repository produced any of the numbers it is checked against.
//   * THE PRE-BOOT ADVERTISEMENT. The first live regtest run died here: an
//     empty index advertises an all-zero top id, monerod does not have that
//     block, so it asks for a chain, we have no common block, and monerod's own
//     rule closes the connection before the boot fetch is issued. The fix is
//     that ChainBoot answers the serving reads itself until the seed lands, and
//     it is pinned here.
//   * THE SYNC SCHEDULE. Who gets asked (greatest cumulative difficulty, not
//     greatest height), when nobody is asked (we are level), and that the
//     read-only probe asks exactly once and never for a block.
//
// STL, boost::asio (header-only) and xmr_coin. No RandomX, no network, no
// daemon: everything here runs in the ordinary ctest lane on both CI legs.
// ---------------------------------------------------------------------------
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "impl/xmr/native/contracts/fakes/fake_chain.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/contracts/fakes/fake_txpool.hpp"
#include "impl/xmr/native/node/xmr_chain_boot.hpp"
#include "impl/xmr/native/node/xmr_sync_driver.hpp"
#include "impl/xmr/native/node/xmr_worker_loops.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace rt     = c2pool::xmr::native::rt;
namespace kat    = c2pool::xmr::native::kat;

using native::BlockEntry;
using native::ChainEntry;
using native::Hash;
using native::PeerFault;
using native::PeerRef;
using native::PeerSyncData;
using native::U128;

namespace {

// The genesis block of the Monero MAINNET chain, exactly as monerod 0.18.5.1
// returned it from get_block(height=0). monerod's own header for it says
// block_weight 80, reward 17592186044415, timestamp 0, major_version 1,
// difficulty 1, cumulative_difficulty 1 -- the numbers this file checks the
// derivation against. A regtest (fakechain) daemon serves the SAME block at
// height 0, which is why the regtest boot path can use the mainnet genesis id.
constexpr const char* MAINNET_GENESIS_BLOB_HEX =
    "010000000000000000000000000000000000000000000000000000000000000000000010"
    "270000013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883"
    "f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582"
    "fda69d24a28e9d0bc890d100";

std::vector<std::uint8_t> from_hex(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::vector<std::uint8_t> genesis_blob() { return from_hex(MAINNET_GENESIS_BLOB_HEX); }

// The first two blocks of a private regtest (fakechain) chain, exactly as
// monerod 0.18.5.1 returned them from get_block. Both sit on the genesis above:
// block 1's prev_id IS the mainnet genesis id, and block 2's prev_id is block 1.
// monerod's own headers for them say block_weight 85 and rewards
// 35184338534400 / 35184271425600.
//
// They are here for ONE regression, and it is a defect the M0 assembly found
// against a live daemon rather than one anybody predicted: see
// test_out_of_order_push_connects().
constexpr const char* REGTEST_BLOCK_1_HEX =
    "1010e2af8dd506418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f46"
    "32e300000000023d01ff0101808080f0ffff070347f2bfeafe0e647adeaf3f60dfa55f9c74"
    "ce51468d78f4ddd70023df13e6a3e64424017b23d07ca10040c63700a3cddffb0c49bfc29f"
    "702153657d238a9323a7d16c950201000000";
constexpr const char* REGTEST_BLOCK_2_HEX =
    "1010e7af8dd5061705bccea7049d81ac4d7ab1ac72ddb52e97647dcc6cef386796f9de3554"
    "f86300000000023e01ff0201c08080d0ffff07032f8039e5730424f008a9a5261d4ae18994"
    "09f036f4b86e12438f3210fdc79971a32401c8190b259647845761ef6bb5542dec7e7c47ac"
    "9355588c0bf26f17205704383b0201000000";


PeerRef peer(const char* addr, std::uint64_t id) {
    PeerRef p;
    p.addr    = addr;
    p.peer_id = id;
    return p;
}

PeerSyncData sync_at(std::uint64_t height, std::uint64_t cumdiff) {
    PeerSyncData d;
    d.current_height        = height;
    d.cumulative_difficulty = U128{cumdiff, 0};
    d.top_version           = 16;
    return d;
}

// =========================================================================
// 1. WorkerLoop
// =========================================================================
void test_worker_loop() {
    // A loop roomy enough that nothing is refused: this half is about ORDER.
    rt::WorkerLoop loop("t", /*capacity=*/64);

    // Nothing is accepted before start(): a post that vanished into a stopped
    // loop would look exactly like a task that ran.
    kat::check(!loop.post([] {}), "a stopped loop refuses a post");

    loop.start();
    std::atomic<int> ran{0};
    int accepted_posts = 0;
    for (int i = 0; i < 10; ++i) if (loop.post([&] { ++ran; })) ++accepted_posts;
    kat::check(accepted_posts == 10, "ten posts into a roomy queue are all accepted");

    bool seen_after_all = false;
    loop.call([&] { seen_after_all = (ran.load() == 10); });
    kat::check(seen_after_all, "call() is ordered behind every earlier post");

    // The loop's own thread runs call() inline rather than deadlocking on
    // itself.
    bool inline_ok = false;
    loop.call([&] { loop.call([&] { inline_ok = true; }); });
    kat::check(inline_ok, "call() from inside the loop runs inline");
    loop.stop();

    // The other half is about the CAP. Park the worker on a blocking task so
    // nothing drains, then prove the queue refuses rather than grows.
    rt::WorkerLoop small("small", /*capacity=*/4);
    small.start();
    std::atomic<bool> release{false};
    small.post([&] {
        while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    int accepted = 0;
    for (int i = 0; i < 8; ++i) if (small.post([] {})) ++accepted;
    kat::checkf(accepted == 4, "the data queue is bounded at its capacity (accepted %d)", accepted);
    kat::check(small.post([] {}, /*control=*/true), "a control task is admitted past the cap");
    kat::checkf(small.stats().refused == 4, "every refusal is counted (refused=%llu)",
                (unsigned long long)small.stats().refused);

    release.store(true);
    small.stop();
    kat::check(!small.running(), "stop() stops the loop");
}

// =========================================================================
// 2. VerifyInbound
// =========================================================================
class ThreadRecordingChain final : public native::IChainIndexInbound {
public:
    std::atomic<int> calls{0};
    std::thread::id  last_thread{};

    void on_peer_sync_data(const PeerRef&, const PeerSyncData&) override { note(); }
    void on_chain_entry(const PeerRef&, ChainEntry&&) override { note(); }
    void on_objects(const PeerRef&, std::vector<BlockEntry>&&, std::vector<Hash>&&,
                    std::uint64_t) override { note(); }
    void on_new_block(const PeerRef&, BlockEntry&&, std::uint64_t, bool) override { note(); }
    void on_peer_gone(const PeerRef&) override { note(); }

private:
    void note() {
        last_thread = std::this_thread::get_id();
        ++calls;
    }
};

void test_verify_inbound() {
    rt::WorkerLoop        loop("verify", /*capacity=*/2);
    ThreadRecordingChain  target;
    rt::VerifyInbound     inbound(loop, target);
    loop.start();

    const std::thread::id caller = std::this_thread::get_id();
    inbound.on_new_block(peer("1.2.3.4:18080", 7), BlockEntry{}, 42, true);
    loop.call([] {});                      // drain
    kat::check(target.calls.load() == 1, "the message reached the index");
    kat::check(target.last_thread != caller,
               "the index was touched on the loop's thread, never the caller's");
    kat::check(target.last_thread == loop.thread_id(), "and it was THIS loop's thread");

    // Overflow drops data messages, counts them, and still delivers a peer
    // departure: a lost on_peer_gone strands the cohort height forever.
    std::atomic<bool> release{false};
    loop.post([&] { while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    for (int i = 0; i < 6; ++i) inbound.on_new_block(peer("1.2.3.4:18080", 7), BlockEntry{}, 42, true);
    inbound.on_peer_gone(peer("1.2.3.4:18080", 7));
    release.store(true);
    loop.call([] {});
    const rt::VerifyInbound::Stats s = inbound.stats();
    kat::checkf(s.refused >= 1, "an overflowing queue refuses and counts (refused=%llu)",
                (unsigned long long)s.refused);
    kat::check(s.new_block == 7, "every offered message is counted, refused or not");
    loop.stop();
}

// =========================================================================
// 3. TxSinkLoop
// =========================================================================
class OffendingPool final : public native::IRelayedTxSink {
public:
    std::atomic<int> batches{0};
    std::thread::id  last_thread{};
    bool             offend = true;

    std::vector<native::TxRelayVerdict> on_relayed(const PeerRef&,
                                                   std::vector<std::vector<std::uint8_t>>,
                                                   bool) override {
        last_thread = std::this_thread::get_id();
        ++batches;
        native::TxRelayVerdict v;
        v.reason       = native::TxRelayVerdict::Reason::Structural;
        v.drop_offense = offend;
        return {v};
    }
    std::vector<Hash> complement_request_ids() const override { return {}; }
};

void test_txsink_loop() {
    rt::WorkerLoop  loop("txpool", 16);
    OffendingPool   pool;
    std::atomic<int> faults{0};
    PeerFault        got = PeerFault::Unresponsive;
    rt::TxSinkLoop  sink(loop, pool, [&](const PeerRef&, PeerFault f, const std::string&) {
        got = f;
        ++faults;
    });
    loop.start();

    const std::vector<native::TxRelayVerdict> immediate =
        sink.on_relayed(peer("5.6.7.8:18080", 9), {{1, 2, 3}}, true);
    kat::check(immediate.empty(),
               "no verdict is invented on the io thread (an invented Accepted would "
               "silently disarm C1c's peer scoring)");
    loop.call([] {});
    kat::check(pool.batches.load() == 1, "the batch reached the pool");
    kat::check(pool.last_thread == loop.thread_id(), "the pool decoded on its own thread");
    kat::check(faults.load() == 1 && got == PeerFault::BadData,
               "a drop-offence still reaches the peer's fail score, just later");

    pool.offend = false;
    sink.on_relayed(peer("5.6.7.8:18080", 9), {{4, 5}}, true);
    loop.call([] {});
    kat::check(faults.load() == 1, "a clean batch raises no fault");
    loop.stop();
}

// =========================================================================
// 4. ThreadWitnessPowSource
// =========================================================================
class CountingPow final : public native::IPowSource {
public:
    int calls = 0;
    bool prefetch(const Hash&, const std::optional<Hash>&) override { return true; }
    bool seed_resident(const Hash&) const override { return true; }
    native::PowVerdict verify(const std::uint8_t*, std::size_t, const Hash&, const U128&,
                              Hash&) override {
        ++calls;
        return native::PowVerdict::Accept;
    }
    native::RandomXMode mode() const override { return native::RandomXMode::LightJit; }
};

void test_pow_witness() {
    native::NoPowSource          null_pow;
    rt::ThreadWitnessPowSource   witness(null_pow);
    CountingPow                  real;

    kat::check(witness.mode() == native::RandomXMode::Disabled,
               "the witness reports the inner source's mode");
    witness.set_inner(real);
    kat::check(witness.mode() == native::RandomXMode::LightJit,
               "set_inner re-points it without changing its address");

    // A call on a FORBIDDEN thread must be caught: this is the whole assertion
    // the node's status line makes.
    witness.forbid(std::this_thread::get_id());
    Hash out{};
    const std::uint8_t blob[4] = {0, 1, 2, 3};
    (void)witness.verify(blob, sizeof(blob), Hash{}, U128{1, 0}, out);
    kat::check(witness.witness().foreign_calls == 1,
               "a RandomX evaluation on a forbidden thread is counted");

    // And a call on a worker thread must not be.
    rt::WorkerLoop loop("verify", 8);
    loop.start();
    loop.call([&] { (void)witness.verify(blob, sizeof(blob), Hash{}, U128{1, 0}, out); });
    loop.stop();
    const rt::ThreadWitnessPowSource::Witness w = witness.witness();
    kat::check(w.foreign_calls == 1, "a call on a permitted thread is not counted foreign");
    kat::check(w.hashes == 2, "every evaluation is counted");
    kat::check(w.threads.size() == 2, "and the threads it ran on are named");
    kat::check(real.calls == 2, "the inner source did the work");
}

// =========================================================================
// 5. The genesis derivation
// =========================================================================
void test_genesis_row() {
    const std::vector<std::uint8_t> blob = genesis_blob();
    kat::checkf(blob.size() == 120, "the genesis blob is 120 bytes (got %zu)", blob.size());

    native::ChainRow row;
    std::string      why;
    const bool ok = rt::genesis_row_from_blob(blob, native::p2p::MAINNET_GENESIS, row, why);
    kat::checkf(ok, "the genesis blob derives a row (%s)", why.c_str());
    if (ok) {
        kat::check(row.height == 0, "height 0");
        kat::check(row.id == native::p2p::MAINNET_GENESIS, "the id recomputes to the pinned one");
        kat::check(row.prev_id == Hash{}, "prev_id is zero");
        kat::check(row.timestamp == 0, "monerod's genesis timestamp is 0");
        kat::check(row.major_version == 1, "monerod reports major_version 1 for it");
        kat::checkf(row.block_weight == 80, "monerod reports block_weight 80 (got %llu)",
                    (unsigned long long)row.block_weight);
        kat::check(row.long_term_weight == 80, "long-term weight is the same at height 0");
        kat::checkf(row.reward == 17592186044415ull,
                    "monerod reports reward 17592186044415 (got %llu)",
                    (unsigned long long)row.reward);
        kat::check(row.already_generated_coins == 17592186044415ull,
                   "emission after the genesis block is its own coinbase");
        kat::check(row.difficulty.lo == 1 && row.cumulative_difficulty.lo == 1,
                   "monerod reports difficulty 1 and cumulative_difficulty 1 at height 0");
        kat::check(row.pow_verified, "the trust root counts as verified");
    }

    // The negative controls: the derivation must refuse rather than believe.
    native::ChainRow bad;
    std::vector<std::uint8_t> flipped = blob;
    flipped[10] ^= 0x01;
    kat::check(!rt::genesis_row_from_blob(flipped, native::p2p::MAINNET_GENESIS, bad, why),
               "one flipped byte no longer hashes to the pinned genesis id");
    std::vector<std::uint8_t> truncated(blob.begin(), blob.begin() + 60);
    kat::check(!rt::genesis_row_from_blob(truncated, native::p2p::MAINNET_GENESIS, bad, why),
               "a truncated blob is refused");
    kat::check(!rt::genesis_row_from_blob(blob, native::p2p::STAGENET_GENESIS, bad, why),
               "the right block for the WRONG network is refused");
    kat::check(!rt::genesis_row_from_blob({}, native::p2p::MAINNET_GENESIS, bad, why),
               "an empty blob is refused");
}

// =========================================================================
// 6. ChainBoot: the pre-boot advertisement, and the seed
// =========================================================================
native::ChainIndexOptions regtest_options() {
    native::ChainIndexOptions o;
    o.net         = native::XmrNet::Regtest;
    o.require_pow = false;    // this test is about wiring, not hashes
    return o;
}

void test_chain_boot() {
    native::NoPowSource pow;
    native::ChainIndex  index(regtest_options(), pow);
    rt::ChainBoot       boot(index, rt::BootMode::Genesis, native::p2p::MAINNET_GENESIS,
                             native::XmrNet::Regtest);

    // --- pre-boot: what we advertise --------------------------------------
    kat::check(!boot.booted(), "a genesis boot starts un-booted");
    const PeerSyncData pre = boot.our_sync_data();
    kat::check(pre.top_id == native::p2p::MAINNET_GENESIS,
               "pre-boot we advertise the pinned genesis as our top, NOT an all-zero id "
               "(monerod asks have_block(top_id); a zero id sends it to "
               "state_synchronizing and closes us)");
    kat::check(pre.current_height == 1, "current_height is one past the tip, monerod's spelling");
    kat::check(pre.cumulative_difficulty.lo == 1, "the genesis block's own cumulative difficulty");
    kat::check(boot.have_block(native::p2p::MAINNET_GENESIS), "we claim the genesis");
    kat::check(!boot.have_block(native::p2p::STAGENET_GENESIS), "and nothing else");
    kat::check(boot.locator().size() == 1 && boot.locator().front() == native::p2p::MAINNET_GENESIS,
               "the pre-boot locator is the genesis alone");

    const auto sup = boot.find_supplement({native::p2p::MAINNET_GENESIS});
    kat::check(sup.has_value(), "a genesis-terminated locator gets a supplement");
    if (sup) {
        kat::check(sup->start_height == 0 && sup->total_height == 1 && sup->ids.size() == 1,
                   "and it describes a node holding only the genesis");
    }
    kat::check(!boot.find_supplement({native::p2p::STAGENET_GENESIS}).has_value(),
               "a locator with no block of ours gets nullopt (the caller then closes)");
    kat::check(!boot.get_block_entry(native::p2p::MAINNET_GENESIS, false).has_value(),
               "we never serve bytes we do not hold, even for a block we claim");

    // --- the seed ----------------------------------------------------------
    BlockEntry ge;
    ge.block_blob = genesis_blob();
    std::vector<BlockEntry> batch{ge};
    boot.on_objects(peer("127.0.0.1:18080", 1), std::move(batch), {}, 1);
    kat::check(boot.booted(), "the genesis blob seeds the index");
    const auto tip = index.tip();
    kat::check(tip.has_value() && tip->height == 0, "and the index now has row zero");
    kat::check(boot.stats().blobs_inspected == 1, "the inspection is counted");
    kat::check(boot.stats().refusals == 0, "the right blob is not a refusal");

    // After the seed everything is a plain forward.
    kat::check(boot.our_sync_data().top_id == native::p2p::MAINNET_GENESIS,
               "post-boot the advertisement comes from the index and still says genesis");
}

void test_chain_boot_refuses_a_foreign_blob() {
    native::NoPowSource pow;
    native::ChainIndex  index(regtest_options(), pow);
    rt::ChainBoot       boot(index, rt::BootMode::Genesis, native::p2p::STAGENET_GENESIS,
                             native::XmrNet::Stagenet);

    BlockEntry wrong;
    wrong.block_blob = genesis_blob();   // the MAINNET genesis, on a stagenet node
    std::vector<BlockEntry> batch{wrong};
    boot.on_objects(peer("127.0.0.1:38080", 1), std::move(batch), {}, 1);
    kat::check(!boot.booted(), "a peer cannot seed us with another network's genesis");
    kat::check(boot.stats().refusals == 1, "the refusal is counted");
    kat::check(boot.stats().dropped_preboot == 1, "and the batch is dropped, not queued");
    kat::check(!index.tip().has_value(), "the index is untouched");
}


// The regression the M0 assembly found on a live regtest run.
//
// monerod sends its TOP BLOCK to any peer whose advertised height is behind its
// own (process_payload_sync_data), so the first block a cold node receives is
// normally one whose parent it does not have yet. The index parked it, exactly
// as it should. What it then did NOT do was revisit it when the parent arrived:
// the branch path resolves descendants, the fast path (a block that extends the
// tip) did not. The live symptom was a node that backfilled to height 8, sat
// there, and let four already-delivered blocks rot in the alt pool while its
// peer kept climbing -- with no error anywhere, because nothing had failed.
void test_out_of_order_push_connects() {
    native::NoPowSource pow;
    native::ChainIndex  index(regtest_options(), pow);
    rt::ChainBoot       boot(index, rt::BootMode::Genesis, native::p2p::MAINNET_GENESIS,
                             native::XmrNet::Regtest);

    BlockEntry ge;
    ge.block_blob = genesis_blob();
    std::vector<BlockEntry> seed{ge};
    boot.on_objects(peer("127.0.0.1:18080", 1), std::move(seed), {}, 1);
    kat::check(boot.booted(), "seeded at the genesis");

    BlockEntry b1, b2;
    b1.block_blob = from_hex(REGTEST_BLOCK_1_HEX);
    b2.block_blob = from_hex(REGTEST_BLOCK_2_HEX);
    kat::check(!b1.block_blob.empty() && !b2.block_blob.empty(), "the two blobs decode");

    // Out of order, exactly as the wire delivered them: the child first.
    const native::OfferResult r2 = index.offer_block(nullptr, b2, /*own_mined=*/false);
    kat::checkf(r2.outcome == native::OfferOutcome::ParkedOrphan,
                "a block whose parent is unknown is parked (got %s)",
                native::to_string(r2.outcome));
    kat::check(index.tip() && index.tip()->height == 0, "and the tip does not move");

    const native::OfferResult r1 = index.offer_block(nullptr, b1, /*own_mined=*/false);
    kat::checkf(r1.outcome == native::OfferOutcome::Connected,
                "the parent connects (got %s: %s)", native::to_string(r1.outcome),
                r1.why.c_str());

    const auto tip = index.tip();
    kat::check(tip.has_value(), "there is a tip");
    if (tip) {
        kat::checkf(tip->height == 2,
                    "the parked child is drained onto the new tip in the same pass "
                    "(height %llu, expected 2)", (unsigned long long)tip->height);
    }
    kat::check(index.alt_size() == 0, "and it is no longer parked");

    // It arrived as an EXTEND, not as a Reorg of depth 0: going through the
    // fork-choice switch would have announced a reorg that never happened.
    kat::check(index.sync_state().reorgs == 0,
               "draining a parked child announces no reorg");
}

// =========================================================================
// 7. SyncDriver
// =========================================================================
void test_sync_driver_schedule() {
    native::fakes::FakeFetcher fetcher;
    native::fakes::FakeChain   chain;
    bool booted = false;
    std::vector<Hash> refetch;

    rt::SyncDriver driver(fetcher, chain, chain, native::p2p::MAINNET_GENESIS,
                          [&] { return booted; }, [&] { return refetch; });

    // No peers: nothing is asked, and it is visible that nothing was asked.
    driver.tick(1000);
    kat::check(fetcher.chain_requests.empty() && fetcher.object_requests.empty(),
               "with no peers the driver asks nobody");
    kat::check(driver.stats().no_peer_ticks == 1, "and says so");

    // Pre-boot: exactly one object, the genesis.
    fetcher.peer_table.push_back({peer("a:18080", 1), sync_at(100, 100)});
    driver.tick(2000);
    kat::check(fetcher.object_requests.size() == 1, "pre-boot the driver asks for one object");
    if (!fetcher.object_requests.empty()) {
        kat::check(fetcher.object_requests[0].ids.size() == 1 &&
                       fetcher.object_requests[0].ids[0] == native::p2p::MAINNET_GENESIS,
                   "and it is the pinned genesis id");
    }
    kat::check(fetcher.chain_requests.empty(), "no chain is asked before the trust root exists");

    // The boot ask is not repeated every tick.
    driver.tick(2100);
    kat::check(fetcher.object_requests.size() == 1, "the boot ask is not re-issued while in flight");

    // The moment the boot completes, the FIRST chain request must go out: the
    // boot fetch and the chain request are different questions, and making the
    // second wait out the first one's timeout is 20 s of a node that looks
    // connected, synced=0 and idle on every cold start.
    booted = true;
    chain.rows.push_back([] {
        native::node::ChainMainBlock b;
        b.height = 0;
        b.id.fill(0x10);
        return b;
    }());
    chain.state.header_frontier = 0;
    driver.tick(2200);
    kat::check(fetcher.chain_requests.size() == 1,
               "the first chain request follows the boot immediately, not after a timeout");
    chain.rows.clear();
    fetcher.chain_requests.clear();

    // Post-boot, behind the cohort: a chain request carrying OUR locator.
    chain.rows.push_back([] {
        native::node::ChainMainBlock b;
        b.height = 10;
        b.id.fill(0x11);
        return b;
    }());
    chain.state.header_frontier = 10;
    driver.tick(3000);
    kat::check(fetcher.chain_requests.size() == 1, "behind the cohort, the driver asks for a chain");

    // Level with the cohort: nothing is asked, which is what tip-follow looks
    // like -- the height keeps moving while this counter stops.
    native::fakes::FakeFetcher quiet;
    quiet.peer_table.push_back({peer("a:18080", 1), sync_at(11, 100)});
    rt::SyncDriver level(quiet, chain, chain, native::p2p::MAINNET_GENESIS,
                         [] { return true; }, [] { return std::vector<Hash>{}; });
    level.tick(4000);
    kat::check(quiet.chain_requests.empty(),
               "level with the cohort (peer current_height == our tip + 1) asks for nothing");

    // The parked parents are asked for regardless.
    native::fakes::FakeFetcher orphan_fetch;
    orphan_fetch.peer_table.push_back({peer("a:18080", 1), sync_at(11, 100)});
    Hash want{};
    want.fill(0x22);
    rt::SyncDriver orphans(orphan_fetch, chain, chain, native::p2p::MAINNET_GENESIS,
                           [] { return true; }, [&] { return std::vector<Hash>{want}; });
    orphans.tick(5000);
    kat::check(orphan_fetch.object_requests.size() == 1 &&
                   orphan_fetch.object_requests[0].ids[0] == want,
               "a parked block's parent is re-fetched even when we are level");

    // The index's refetch list is a standing want list: it is not cleared when
    // the block arrives. So the driver must rate-limit it, or a 12-block
    // backfill turns into hundreds of answers to questions already answered.
    orphans.tick(5100);
    orphans.tick(6000);
    kat::check(orphan_fetch.object_requests.size() == 1,
               "the same missing id is not re-asked on every tick");
    orphans.tick(5000 + 20'000);
    kat::check(orphan_fetch.object_requests.size() == 2,
               "but it IS asked again once the re-ask interval passes");
}

void test_sync_driver_picks_the_heaviest_peer() {
    native::fakes::FakeFetcher fetcher;
    native::fakes::FakeChain   chain;
    chain.rows.push_back([] {
        native::node::ChainMainBlock b;
        b.height = 5;
        b.id.fill(0x33);
        return b;
    }());
    chain.state.header_frontier = 5;

    // The taller peer is the LIGHTER one: height is a number a peer can pick,
    // cumulative difficulty is the same claim priced in work.
    fetcher.peer_table.push_back({peer("tall:18080", 1), sync_at(9000, 10)});
    fetcher.peer_table.push_back({peer("heavy:18080", 2), sync_at(50, 1'000'000)});

    rt::SyncDriver driver(fetcher, chain, chain, native::p2p::MAINNET_GENESIS,
                          [] { return true; }, [] { return std::vector<Hash>{}; });
    driver.tick(1000);
    kat::check(fetcher.chain_requests.size() == 1, "one chain request");
    if (!fetcher.chain_requests.empty())
        kat::check(fetcher.chain_requests[0].peer.addr == "heavy:18080",
                   "the driver asks the peer with the greatest cumulative difficulty");
}

void test_sync_driver_probe_is_one_question() {
    native::fakes::FakeFetcher fetcher;
    native::fakes::FakeChain   chain;
    fetcher.peer_table.push_back({peer("live:38080", 1), sync_at(1'000'000, 1'000'000)});

    rt::SyncDriverConfig cfg;
    cfg.probe_only = true;
    rt::SyncDriver probe(fetcher, chain, chain, native::p2p::STAGENET_GENESIS,
                         [] { return false; }, [] { return std::vector<Hash>{}; }, cfg);
    for (int i = 0; i < 20; ++i) probe.tick(1000 + 100 * i);

    kat::check(fetcher.chain_requests.size() == 1,
               "the read-only probe asks exactly one NOTIFY_REQUEST_CHAIN, ever");
    kat::check(fetcher.object_requests.empty(),
               "and never asks a syncing daemon for a block");
    if (!fetcher.chain_requests.empty())
        kat::check(fetcher.chain_requests[0].locator.size() == 1 &&
                       fetcher.chain_requests[0].locator[0] == native::p2p::STAGENET_GENESIS,
                   "the probe's locator terminates at the network's genesis id");
}

} // namespace

int main() {
    test_worker_loop();
    test_verify_inbound();
    test_txsink_loop();
    test_pow_witness();
    test_genesis_row();
    test_chain_boot();
    test_chain_boot_refuses_a_foreign_blob();
    test_out_of_order_push_connects();
    test_sync_driver_schedule();
    test_sync_driver_picks_the_heaviest_peer();
    test_sync_driver_probe_is_one_question();
    return kat::report("xmr_native_node_kat");
}
