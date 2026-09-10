// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/contracts_kat.cpp
//
// Wave 0 contracts KAT. Its job is narrow and its job is the point:
//
//   1. EVERY contract header and EVERY fake compiles, in ONE translation unit,
//      with no ordering requirement between them. That is what makes the family
//      a collision fence for the parallel waves. It is also the assertion that
//      caught the two colliding RelayVerdict structs.
//   2. The fakes really do implement the interfaces -- they are instantiated
//      and called through base-class pointers, so a signature drift in either
//      direction is a compile error rather than a wave-1 surprise.
//   3. The pinned semantics that are expressible here are checked here:
//      to_miner_data() leaves the backlog empty, the evidence bitmask covers
//      the case a scalar tier could not, the object-request chunk cap holds,
//      fail-closed readiness refuses to serve, and a relay verdict that reached
//      nobody says why.
//
// STL only. No network, no crypto, no daemon.
// ---------------------------------------------------------------------------

#include <cstdio>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <vector>

#include "impl/xmr/native/contracts/contracts.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/consensus/xmr_hf_table.hpp"

using namespace c2pool::xmr::native;
namespace F = c2pool::xmr::native::fakes;

// --- tiny harness ------------------------------------------------------------
static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

static Hash hash_of(std::uint8_t seed) {
    Hash h{};
    for (std::size_t i = 0; i < h.size(); ++i)
        h[i] = static_cast<std::uint8_t>(seed + i);
    return h;
}

// ---------------------------------------------------------------------------
// 1. Static contract properties
// ---------------------------------------------------------------------------

// The fakes must be usable through the interfaces, and the interfaces must be
// abstract (nobody accidentally instantiates a contract).
static_assert(std::is_abstract<IChainIndexInbound>::value, "IChainIndexInbound is a contract");
static_assert(std::is_abstract<IChainView>::value,         "IChainView is a contract");
static_assert(std::is_abstract<IChainServing>::value,      "IChainServing is a contract");
static_assert(std::is_abstract<IChainFetcher>::value,      "IChainFetcher is a contract");
static_assert(std::is_abstract<IRelayedTxSink>::value,     "IRelayedTxSink is a contract");
static_assert(std::is_abstract<ITxpoolSnapshot>::value,    "ITxpoolSnapshot is a contract");
static_assert(std::is_abstract<ITxSource>::value,          "ITxSource is a contract");
static_assert(std::is_abstract<ITxBlobSource>::value,      "ITxBlobSource is a contract");
static_assert(std::is_abstract<IBroadcastPort>::value,     "IBroadcastPort is a contract");
static_assert(std::is_abstract<IMinerDataSource>::value,   "IMinerDataSource is a contract");
static_assert(std::is_abstract<IBlockRelay>::value,        "IBlockRelay is a contract");
static_assert(std::is_abstract<IParityOracle>::value,      "IParityOracle is a contract");

static_assert(std::is_base_of<IChainIndexInbound, F::FakeChain>::value, "fake implements inbound");
static_assert(std::is_base_of<IChainView,         F::FakeChain>::value, "fake implements view");
static_assert(std::is_base_of<IChainServing,      F::FakeChain>::value, "fake implements serving");
static_assert(std::is_base_of<IChainFetcher,      F::FakeFetcher>::value, "fake implements fetcher");
static_assert(std::is_base_of<IRelayedTxSink,     F::FakeTxpool>::value, "fake implements relay sink");
static_assert(std::is_base_of<ITxpoolSnapshot,    F::FakeTxpool>::value, "fake implements snapshot");
static_assert(std::is_base_of<ITxSource,          F::FakeTxpool>::value, "fake implements tx source");
static_assert(std::is_base_of<ITxBlobSource,      F::FakeTxpool>::value, "fake implements blob source");
static_assert(std::is_base_of<IBroadcastPort,     F::FakeBroadcastPort>::value, "fake implements broadcast");
static_assert(std::is_base_of<IMinerDataSource,   F::FakeMinerDataSource>::value, "fake implements miner data");
static_assert(std::is_base_of<IBlockRelay,        F::FakeBlockRelay>::value, "fake implements relay");
static_assert(std::is_base_of<IParityOracle,      F::FakeParityOracle>::value, "fake implements oracle");

// MUST-FIX (a): the two verdicts are distinct types with distinct names, and
// both are visible at once. Before the rename they could not be.
static_assert(!std::is_same<TxRelayVerdict, BlockRelayVerdict>::value,
              "tx and block relay verdicts must be different types");

// D-3 caps are compile-time facts, not runtime configuration.
static_assert(MAX_OBJECT_REQUEST_IDS == 100, "monerod drops larger object requests");
static_assert(MAX_SPAN_IDS == 2048, "span planning size");

// ---------------------------------------------------------------------------
// 2. Value-type semantics
// ---------------------------------------------------------------------------
static void test_u128() {
    const U128 a{0xFFFFFFFFFFFFFFFFull, 0};
    const U128 one{1, 0};
    const U128 sum = u128_add(a, one);
    check(sum.lo == 0 && sum.hi == 1, "u128_add carries into the high word");
    check(u128_greater(sum, a), "carry result is greater");
    check(!u128_greater(a, a), "strictly greater is strict at equality");
    check(u128_less(a, sum), "u128_less agrees with u128_greater");
}

static void test_to_miner_data() {
    TemplateInputs ti;
    ti.major_version = 16;
    ti.height        = 2204738;
    ti.prev_id       = hash_of(0x10);
    ti.seed_hash     = hash_of(0x20);
    ti.difficulty    = U128{3767883, 0};
    ti.median_weight = 300000;
    ti.already_generated_coins = 18000000000000000ull;
    ti.median_timestamp = 1789054000;

    const node::MinerData m = ti.to_miner_data();
    check(m.major_version == ti.major_version, "to_miner_data carries the fork version");
    check(m.height == ti.height,               "to_miner_data carries the height");
    check(m.prev_id == ti.prev_id,             "to_miner_data carries prev_id");
    check(m.seed_hash == ti.seed_hash,         "to_miner_data carries the seed");
    check(m.difficulty == ti.difficulty,       "to_miner_data carries the difficulty");
    check(m.median_weight == ti.median_weight, "to_miner_data carries the median weight");
    check(m.already_generated_coins == ti.already_generated_coins,
          "to_miner_data carries the coin supply");
    // The backlog belongs to the txpool, not to chain state: the conversion
    // must stay a pure function of the five windows.
    check(m.tx_backlog.empty(), "to_miner_data leaves the tx backlog empty");
    check(m.valid(), "a populated template input converts to a valid MinerData");
}

// MUST-FIX (b): the case a scalar tier could not express.
static void test_admission_evidence() {
    AdmissionEvidence e = AdmissionEvidence::None;
    check(!any(e), "an empty mask carries no evidence");

    e |= AdmissionEvidence::Structural;
    e |= AdmissionEvidence::DaemonConfirmed;

    check(covers(e, AdmissionEvidence::DaemonConfirmed),
          "daemon confirmation is expressible on its own");
    check(!covers(e, AdmissionEvidence::FeePolicy),
          "daemon confirmation does not imply the fee replica ran");
    check(!covers(e, EVIDENCE_DAEMONLESS_DEFAULT),
          "a daemon-confirmed tx does not automatically satisfy the daemonless gate");

    e |= AdmissionEvidence::FeePolicy;
    check(covers(e, EVIDENCE_DAEMONLESS_DEFAULT),
          "structural plus fee policy satisfies the daemonless default");
    check(!covers(e, AdmissionEvidence::NonInputConsensus),
          "the ringct leg is still independently absent");

    // The four flags are orthogonal: no flag is implied by any other.
    const AdmissionEvidence all[] = {
        AdmissionEvidence::Structural, AdmissionEvidence::FeePolicy,
        AdmissionEvidence::NonInputConsensus, AdmissionEvidence::DaemonConfirmed };
    for (AdmissionEvidence a : all)
        for (AdmissionEvidence b : all)
            if (static_cast<std::uint8_t>(a) != static_cast<std::uint8_t>(b))
                check(!covers(a, b), "evidence flags are orthogonal");
}

// ---------------------------------------------------------------------------
// 3. Fakes driven through the contracts
// ---------------------------------------------------------------------------
static void test_chain_fake() {
    F::FakeChain chain;

    node::ChainMainBlock b0; b0.height = 100; b0.id = hash_of(1); b0.prev_id = hash_of(0);
    node::ChainMainBlock b1; b1.height = 101; b1.id = hash_of(2); b1.prev_id = b0.id;
    chain.rows = {b0, b1};
    chain.anchor = 90;
    chain.frontier = 101;

    IChainView&    view = chain;
    IChainServing& serv = chain;
    IChainIndexInbound& in = chain;

    check(view.tip().has_value() && view.tip()->height == 101, "tip is the last row");
    check(view.height_of(b0.id).value_or(0) == 100, "height_of finds a row");
    check(view.confirmation_depth(b0.id) == 2, "confirmation depth counts the tip");
    check(view.is_on_best_chain(b1.id), "tip is on the best chain");
    check(!view.is_on_best_chain(hash_of(9)), "an unknown id is not on the chain");
    check(view.anchor_height() == 90, "anchor is reported");
    check(view.verified_frontier() == 101, "verified frontier is reported");

    // Fail-closed: no template while the index is not synced.
    TemplateInputs ti; ti.height = 102; ti.synced = false;
    chain.inputs = ti;
    check(!view.template_inputs().has_value(), "no template inputs while unsynced");
    chain.state.synced = true;
    check(view.template_inputs().has_value(), "template inputs appear once synced");

    // Serving: a locator with no common id must yield nullopt, not a guess.
    check(serv.our_sync_data().current_height == 102, "advertised height is tip + 1");
    check(serv.find_supplement({hash_of(2)}).has_value(), "supplement found for a known id");
    check(!serv.find_supplement({hash_of(200)}).has_value(),
          "no common locator id yields nullopt so the caller can close the peer");
    check(serv.have_block(b1.id), "have_block sees a retained row");

    BlockEntry be; be.block_blob = {1, 2, 3};
    chain.serve(b1.id, be);
    check(serv.get_block_entry(b1.id, true).has_value(), "a served block comes back");
    check(!serv.get_block_entry(hash_of(77), true).has_value(),
          "an unknown block is a miss, not an empty answer");

    // Inbound side records what the wire handed it.
    PeerRef peer{7, "10.0.0.1:38080", 64512};
    PeerSyncData psd; psd.current_height = 200;
    in.on_peer_sync_data(peer, psd);
    ChainEntry ce; ce.start_height = 100; ce.cumulative_difficulty_hint = U128{5, 0};
    in.on_chain_entry(peer, std::move(ce));
    in.on_objects(peer, {}, {}, 200);
    BlockEntry nb; nb.block_weight_claimed_hint = 12345;
    in.on_new_block(peer, std::move(nb), 200, true);
    in.on_peer_gone(peer);

    check(chain.sync_data_calls.size() == 1,   "sync data recorded");
    check(chain.chain_entry_calls.size() == 1, "chain entry recorded");
    check(chain.objects_calls.size() == 1,     "objects recorded");
    check(chain.new_block_calls.size() == 1 && chain.new_block_calls[0].fluffy,
          "fluffy flag survives the call");
    check(chain.peer_gone_calls.size() == 1,   "peer gone recorded");

    // Events reach every subscriber.
    int seen = 0;
    view.subscribe([&](const node::MainchainEvent&) { ++seen; });
    view.subscribe([&](const node::MainchainEvent&) { ++seen; });
    node::MainchainEvent ev; ev.kind = node::MainchainEventKind::Extend; ev.block = b1;
    chain.emit(ev);
    check(seen == 2, "both event sinks fire");

    // must-fix (d): a Disconnected event may carry fewer bodies than hashes and
    // must say so rather than let a consumer assume completeness.
    int tx_seen = 0;
    bool complete_flag = true;
    view.subscribe_txs([&](const BlockTxEvent& e) {
        ++tx_seen;
        complete_flag = e.tx_blobs_complete;
    });
    BlockTxEvent dis;
    dis.kind = BlockTxEvent::Kind::Disconnected;
    dis.tx_hashes = {hash_of(3), hash_of(4)};
    dis.tx_blobs  = {{0x01}};                 // best effort: one body of two
    dis.tx_blobs_complete = dis.tx_blobs.size() == dis.tx_hashes.size();
    chain.emit_tx(dis);
    check(tx_seen == 1, "tx event sink fires");
    check(!complete_flag, "a short best-effort body list reports itself incomplete");

    // Own-block submission is refusable, with a reason.
    std::string why;
    check(view.submit_own_block(be, why), "own block accepted by default");
    chain.accept_own_block = false;
    check(!view.submit_own_block(be, why) && !why.empty(),
          "a refused own block always carries a reason");
}

static void test_fetcher_chunking() {
    F::FakeFetcher fetcher;
    IChainFetcher& f = fetcher;

    std::vector<Hash> ids;
    for (int i = 0; i < 250; ++i) ids.push_back(hash_of(static_cast<std::uint8_t>(i)));

    PeerRef peer{1, "10.0.0.2:38080", 0};
    check(f.request_objects(peer, ids, true), "objects request accepted");
    check(fetcher.chunking_ok(), "no request exceeds the 100-id cap");
    check(fetcher.object_requests.size() == 3, "250 ids chunk into 3 requests");
    check(fetcher.object_requests[0].ids.size() == 100
       && fetcher.object_requests[2].ids.size() == 50,
          "chunks are full then remainder");
    check(fetcher.object_requests[0].prune, "D-4 syncs pruned");

    f.penalize(peer, PeerFault::BadPow, "randomx below target");
    check(fetcher.penalties.size() == 1
       && fetcher.penalties[0].fault == PeerFault::BadPow,
          "penalty recorded with its cause");

    fetcher.accept = false;
    check(!f.request_chain(peer, {}, true), "a refused write returns false");
}

static void test_txpool_fake() {
    F::FakeTxpool pool;
    IRelayedTxSink&  sink = pool;
    ITxpoolSnapshot& snap = pool;
    ITxBlobSource&   blobs = pool;

    pool.add(hash_of(0x30), 2000, 30000, EVIDENCE_DAEMONLESS_DEFAULT, 2);
    pool.add(hash_of(0x40), 3000, 45000,
             AdmissionEvidence::Structural | AdmissionEvidence::DaemonConfirmed, 2);
    pool.add(hash_of(0x50), 1500, 10000, EVIDENCE_DAEMONLESS_DEFAULT, 2, /*conflicted*/ true);

    const auto backlog = snap.selectable_backlog();
    check(backlog.size() == 1,
          "only the tx whose evidence covers the configured mask is selectable");
    check(backlog[0].weight == 2000, "the selectable entry is the expected one");

    // Same pool, a deployment that trusts an armed daemon instead.
    pool.required_evidence = AdmissionEvidence::Structural | AdmissionEvidence::DaemonConfirmed;
    check(snap.selectable_backlog().size() == 1,
          "switching the required mask switches which tx is selectable");

    // Corroboration is a separate condition from evidence.
    pool.required_evidence = EVIDENCE_DAEMONLESS_DEFAULT;
    pool.min_peers = 3;
    check(snap.selectable_backlog().empty(), "peer corroboration gates independently");
    pool.min_peers = 1;

    const auto verdicts = sink.on_relayed(PeerRef{2, "10.0.0.3:38080", 0},
                                          {{0x01, 0x02}, {}}, true);
    check(verdicts.size() == 2, "one verdict per input blob");
    check(verdicts[0].reason == TxRelayVerdict::Reason::Accepted, "good blob accepted");
    check(verdicts[1].drop_offense, "an empty blob is a drop offence");
    check(std::string(to_string(verdicts[1].reason)) == "Structural",
          "verdict reasons render");

    std::vector<std::vector<std::uint8_t>> out;
    std::vector<Hash> missing;
    check(blobs.get_blobs({hash_of(0x30)}, out, missing) && missing.empty(),
          "a held body is returned");
    check(!blobs.get_blobs({hash_of(0x99)}, out, missing) && missing.size() == 1,
          "an absent body is reported missing, never silently skipped");

    blobs.pin(hash_of(0x60), {hash_of(0x30)});
    check(pool.pins.size() == 1, "pin recorded");
    blobs.unpin(hash_of(0x60));
    check(pool.pins.empty(), "unpin releases");
}

static void test_miner_data_seam() {
    F::FakeMinerDataSource src("native");
    IMinerDataSource& s = src;

    check(std::string(s.name()) == "native", "a source names its arm");

    std::string why;
    check(!s.snapshot(&why).has_value() && !why.empty(),
          "fail-closed: an unready source serves nothing and says why");

    // Each readiness flag on its own is enough to keep the gate shut.
    src.make_ready();
    check(s.readiness().ok(), "all inputs present means ready");
    src.ready.coins_known = false;
    src.ready.why = "already_generated_coins not carried forward";
    check(!s.readiness().ok(), "one missing window closes the gate");
    check(!s.snapshot(&why).has_value(), "and no template is served");

    src.make_ready();
    node::MinerData md; md.height = 5; md.prev_id = hash_of(3); md.difficulty = U128{7, 0};
    src.data = md;
    check(s.snapshot(&why).has_value(), "a ready source with data serves");

    const MinerDataEpoch same{5, hash_of(3), 11};
    const MinerDataEpoch bumped{5, hash_of(3), 12};
    src.ep = same;
    check(s.epoch() == same,   "epoch compares by value");
    check(s.epoch() != bumped, "a backlog bump is a new epoch");
}

static void test_relay_and_oracle() {
    F::FakeBroadcastPort port;
    IBroadcastPort& p = port;
    port.state_normal_peers = 4;
    check(p.broadcast_notify(2008, {0x01}) == 4,
          "broadcast reports how many state_normal peers were written to");
    check(port.broadcasts.size() == 1, "the frame was recorded");

    F::FakeBlockRelay relay;
    IBlockRelay& r = relay;
    BlockRelayRequest req;
    req.block_id = hash_of(0x70);
    req.height   = 2204739;

    relay.daemon_armed = true; relay.daemon_accepts = true; relay.p2p_peers = 3;
    BlockRelayVerdict v = r.relay(req);
    check(v.reached_network() && v.landed_first == "daemon",
          "with both arms up, the daemon arm lands first");
    check(v.why.empty(), "a successful relay needs no explanation");

    relay.daemon_armed = false; relay.p2p_peers = 2;
    v = r.relay(req);
    check(v.reached_network() && v.landed_first == "p2p", "p2p alone still reaches the network");

    relay.p2p_peers = 0;
    v = r.relay(req);
    check(!v.reached_network(), "no arm means the block did not reach the network");
    check(!v.why.empty(), "never-silent-drop: a failed relay always says why");

    F::FakeParityOracle oracle;
    IParityOracle& o = oracle;
    node::MainchainEvent ev; ev.block.height = 2204739;
    o.on_tip(ev, "native");
    o.on_serve(MinerDataEpoch{2204740, hash_of(4), 1}, "native");
    o.on_submit(hash_of(0x70), /*daemon_accepted*/ false, /*p2p*/ 0);

    check(o.coverage().samples == 3, "every probe produced a sample");
    check(o.coverage().voided == 1,
          "an unjudgeable submit is Void, and Void is never counted as agreement");
    check(o.coverage().clean == 2, "the two judgeable probes are clean");
    o.revoke("operator");
    check(o.state() == GraduationState::Revoked, "graduation is revocable");
}

// ---------------------------------------------------------------------------
// 4. The Wave 0 consensus tables that ship alongside the contracts
// ---------------------------------------------------------------------------
static void test_hard_fork_table() {
    // The rows either side of each activation, on all three public networks.
    check(hf_version_for_height(XmrNet::Mainnet, 2689607) == 15, "mainnet is v15 below the v16 row");
    check(hf_version_for_height(XmrNet::Mainnet, 2689608) == 16, "mainnet v16 activates on its row");
    check(hf_version_for_height(XmrNet::Mainnet, 1) == 1,        "mainnet starts at v1");
    check(hf_version_for_height(XmrNet::Testnet, 1983520) == 16, "testnet v16 activates on its row");
    check(hf_version_for_height(XmrNet::Stagenet, 1151719) == 15, "stagenet is v15 below the v16 row");
    check(hf_version_for_height(XmrNet::Stagenet, 1151720) == 16, "stagenet v16 activates on its row");
    // Cross-check against the live stagenet daemon the tx-weight golden was
    // captured from: it reports v14 at 1100000 and v16 at 1399268.
    check(hf_version_for_height(XmrNet::Stagenet, 1100000) == 14,
          "stagenet table agrees with the captured block at 1100000");
    check(hf_version_for_height(XmrNet::Stagenet, 1399268) == 16,
          "stagenet table agrees with the captured block at 1399268");
    check(hf_height_for_version(XmrNet::Mainnet, 12) == 1978433, "activation heights are queryable");
    check(hf_height_for_version(XmrNet::Mainnet, 99) == 0, "an unknown version has no height");

    // Version-dependent rules.
    check(hf_randomx_active(12) && !hf_randomx_active(11), "RandomX starts at v12");
    check(hf_ring_size(12) == 11 && hf_ring_size(15) == 16, "ring size steps at v15");
    check(hf_required_rct_type(13) == 5 && hf_required_rct_type(15) == 6,
          "CLSAG at v13, bulletproof plus at v15");
    check(hf_view_tags_active(15) && !hf_view_tags_active(14), "view tags start at v15");

    // The fence: fail-closed above what this build implements.
    std::string why;
    check(hf_check_block_version(XmrNet::Mainnet, 2689608, 16, 16, why) == HfStatus::Ok,
          "a current block passes");
    check(hf_check_block_version(XmrNet::Mainnet, 2689608, 15, 16, why) == HfStatus::VersionTooLow
          && !why.empty(),
          "a block below the required fork version is refused with a reason");
    check(hf_check_block_version(XmrNet::Mainnet, 2689608, 17, 17, why) == HfStatus::Fenced
          && !why.empty(),
          "the CARROT / FCMP fence trips on an unimplemented fork, with a reason");
    check(hf_check_block_version(XmrNet::Mainnet, 2689608, 16, 15, why) == HfStatus::MinorTooLow,
          "minor below major is refused");
    check(hf_is_fenced(MAX_IMPLEMENTED_HF_VERSION + 1)
          && !hf_is_fenced(MAX_IMPLEMENTED_HF_VERSION),
          "the fence sits exactly above the implemented range");

    std::uint8_t top = 0;
    check(hf_top_version(XmrNet::Stagenet, 2204737, top, why) == HfStatus::Ok && top == 16,
          "we advertise the fork version our tip is at");

    // Regtest starts at the newest implemented version, from height 1.
    check(hf_version_for_height(XmrNet::Regtest, 1) == MAX_IMPLEMENTED_HF_VERSION,
          "regtest starts at the newest implemented fork");
}

static void test_seed_epoch() {
    // Rule 1: the geometry, taken from the coin tree rather than re-derived.
    check(SEEDHASH_EPOCH_BLOCKS == 2048 && SEEDHASH_EPOCH_LAG == 64,
          "the epoch constants come from one place");
    check(rx_seedheight(2112) == 0, "the genesis epoch runs to EPOCH_BLOCKS + LAG");
    check(rx_seedheight(2113) == 2048, "the first rollover is one past that");

    // Rule 2 and 3: the pair, and when the next seed is published.
    const SeedPair steady = seed_pair_for_height(3000);
    check(!steady.in_lag_window, "mid-epoch there is nothing to publish");
    check(steady.seed_height == steady.next_seed_height, "and the pair collapses");

    const SeedPair lag = seed_pair_for_height(4096 + 64);
    check(lag.in_lag_window, "inside the lag the next seed differs");
    check(lag.next_seed_height == lag.seed_height + SEEDHASH_EPOCH_BLOCKS,
          "and it is exactly one epoch ahead");
    check(should_prefetch_next_seed(4096 + 64), "which is the prefetch trigger");
    check(!should_prefetch_next_seed(4096 + 65), "and it stops once the rollover has happened");

    // Rule 4: exactly one re-key per epoch when following the tip.
    std::size_t rekeys = 0;
    for (std::uint64_t h = 2113; h < 2113 + 2 * SEEDHASH_EPOCH_BLOCKS; ++h)
        if (crosses_seed_edge(h - 1, h)) ++rekeys;
    check(rekeys == 2, "two epochs of tip-follow cost exactly two re-keys");

    // The retention floor the index owes the verifier.
    const std::uint64_t reach = seed_reach_required(4096 + 64);
    check(reach >= SEEDHASH_EPOCH_LAG, "the seed always sits at least a lag behind");
    check(reach <= SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 1,
          "and never more than an epoch plus the lag behind");
}

// ---------------------------------------------------------------------------
int main() {
    test_u128();
    test_to_miner_data();
    test_admission_evidence();
    test_chain_fake();
    test_fetcher_chunking();
    test_txpool_fake();
    test_miner_data_seam();
    test_relay_and_oracle();
    test_hard_fork_table();
    test_seed_epoch();

    std::printf("contracts_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
