// SPDX-License-Identifier: AGPL-3.0-or-later
// DASH v36 two-node end-to-end KATs for the private/isolated DASH v36
// sharechain (a custom --network-id). Two REAL ctx-bound dash::NodeImpl
// instances (LiveNode), each over its own identity-scoped LevelDB, exchange
// shares over the node receive path (wire bytes -> load_share ->
// processing_shares -> verify pool -> tracker -> think -> LevelDB). Every
// test draws a FRESH random identity (fresh_iso_identity), never a compiled
// public/testnet identity and never the reserved future v36 self-identity.
//
// What is pinned:
//   1. Genesis bootstrap from EITHER node: run twice, A mints the genesis v36
//      share / B mints it; the other node accepts, verifies (share_init_verify
//      v36 + payout commitment), persists and elects it.
//   2. Both nodes build byte-identical producer jobs (gentx, ref_hash, share
//      bits) and identical PPLNS weights for the same parent over a 6-share
//      chain from two miners and two minters; every coinbase pays only the
//      window miners plus the P2PKH donation (>= 1 sat), no finder fee; each
//      node's own gentx rebuild matches the other node's committed gentx.
//   3. Restart: a node reloads the v36 chain from its identity-scoped store
//      (every share, every verified flag, the best share, byte-identical wire)
//      and continues minting on it; the other node accepts the new share.
//   4. Emergency decay: after TARGET_LOOKBEHIND shares, a job for a parent
//      that has had no child for 700 s commits an easier target than the
//      no-stall job, identically on both nodes and exactly per the rule; the
//      eased share passes the other node's peer checks and both nodes' next
//      job on top of it is identical.
//   5. A peer below the isolated protocol floor (3601) -- 1700 = p2pool-dash,
//      3599, and 3600 = a c2pool-dash build without v36 isolated support -- is
//      refused at the REAL handle_version with the floor text plus "peer build
//      lacks v36 isolated support -- upgrade" and is not banned; 3601 from the
//      same address is admitted; a v16 share wire is dropped at receive.
//   6. The version frame the rig's python peer stand-in sends
//      (scripts/dash_v36_peer_standin.py --self-test) is byte-identical to
//      core::Packet::from_message(message_version::make_raw(...)).
//   7. SeedStoreForLoopbackRig (skipped unless C2POOL_DASH_V36_E2E_SEED_DIR is
//      set): the seeder of scripts/dash_v36_isolated_e2e.sh. It mints a real
//      v36 chain at the PRODUCTION testnet share floor into a --data-dir that a
//      real c2pool-dash process then loads, and writes a manifest of what the
//      two real processes must agree on.
//
// Folded into test_dash_node (needs dash::NodeImpl + c2pool_storage + the dash
// OBJECT lib). The profile is keyed on the process-global SharechainConfig
// identity; IdentityGuard resets it around every test.

#include <gtest/gtest.h>

#include "dash_v36_live_fixture.hpp"   // IdentityGuard, DataDirGuard, LiveNode, relay, ...
#include "dash_v36_mint_fixture.hpp"   // make_wd, solve_job, coinbase_outputs, handshake_on, ...

#include <impl/dash/dashboard_pplns.hpp>
#include <impl/dash/messages.hpp>
#include <impl/dash/pplns_v36.hpp>

#include <core/message.hpp>
#include <core/packet.hpp>

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

using dash::mint::pplns_weights_for;
using PplnsWeights = dash::stratum::DASHWorkSource::PplnsWeights;

const Bytes& donation_script() {
    static const Bytes d(dash::DONATION_SCRIPT.begin(), dash::DONATION_SCRIPT.end());
    return d;
}

std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (unsigned char c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}

// A fresh private/isolated identity, set process-wide, and the production
// CoinParams of that profile (current_share_version 36 from the flip).
struct FreshIso {
    IsoIdentity ident;
    core::CoinParams p;
};

FreshIso fresh_iso(bool easy_pow = true) {
    SharechainConfig::reset_network_id();
    FreshIso f{fresh_iso_identity(), {}};
    SharechainConfig::set_network_id(f.ident.id, f.ident.prefix);
    const auto p = dash::make_coin_params(SharechainConfig::is_testnet);
    f.p = easy_pow ? easy(p) : p;
    return f;
}

// What one node would serve a miner for (prev, miner, template, timestamp):
// the producer job plus the two PPLNS views of the same parent.
struct JobView {
    bool built{false};
    Bytes gentx;
    uint256 ref_hash;
    uint32_t bits{0}, max_bits{0};
    uint64_t desired_version{0};
    std::optional<PplnsWeights> weights;   // pplns_weights_for (fallback coinbase / dashboard seam)
    bool has_window{false};
    dash::CumulativeWeights window;        // v36_pplns_window (what the gentx pays)
};

JobView job_on(LiveNode& n, const core::CoinParams& p, const uint256& prev, const uint160& miner,
               const dash::coin::DashWorkData& wd, uint32_t desired_ts, uint32_t share_nonce) {
    JobView v;
    const bool ok = n.settled([&](dash::ShareTracker& t) {
        auto b = build_producer_job(t.chain, p, prev, dash::pubkey_hash_to_script2(miner), wd,
                                    desired_ts, share_nonce, /*donation=*/0, "c2pool");
        if (b) {
            v.built = true;
            v.gentx = b->job.gentx_bytes;
            v.ref_hash = b->job.ref_hash;
            v.bits = b->job.share_bits;
            v.max_bits = b->job.share_max_bits;
            v.desired_version = b->frozen.desired_version;
        }
        if (!prev.IsNull())
            v.weights = pplns_weights_for(t.chain, p, prev, wd.m_bits);
        try {
            v.window = dash::v36_pplns_window(t.chain, prev);
            v.has_window = true;
        } catch (const std::exception&) {}
    });
    EXPECT_TRUE(ok) << "node tracker never settled";
    return v;
}

void expect_same_job(const JobView& a, const JobView& b) {
    ASSERT_TRUE(a.built);
    ASSERT_TRUE(b.built);
    EXPECT_EQ(a.gentx, b.gentx) << "byte-identical gentx on both nodes";
    EXPECT_EQ(a.ref_hash, b.ref_hash);
    EXPECT_EQ(a.bits, b.bits);
    EXPECT_EQ(a.max_bits, b.max_bits);
    EXPECT_EQ(a.desired_version, 36u);
    EXPECT_EQ(b.desired_version, 36u);
    ASSERT_EQ(a.weights.has_value(), b.weights.has_value());
    if (a.weights) {
        EXPECT_EQ(a.weights->weights, b.weights->weights);
        EXPECT_EQ(a.weights->total_weight, b.weights->total_weight);
    }
    ASSERT_EQ(a.has_window, b.has_window);
    EXPECT_EQ(a.window.weights, b.window.weights);
    EXPECT_EQ(a.window.total_weight, b.window.total_weight);
    EXPECT_EQ(a.window.total_donation_weight, b.window.total_donation_weight);
}

// One minted share as its minter served it.
struct Minted {
    uint256 hash;
    Bytes gentx;          // the served coinbase == the share's gentx
    uint256 gentx_hash;
    dash::DashV36Share share;
};

// Two real nodes, A and B, on sibling subdirs of the identity's data subdir.
struct TwoNodes {
    core::CoinParams p;
    dash::coin::DashWorkData wd;
    std::string sub;
    bool testnet{false};
    uint32_t max_nonce{4000000};
    unsigned threads{1};
    std::unique_ptr<LiveNode> a, b;

    TwoNodes(const core::CoinParams& p_, const std::string& sub_, bool testnet_ = false)
        : p(p_), wd(make_wd()), sub(sub_), testnet(testnet_)
    {
        a = make(sub + "_a");
        b = make(sub + "_b");
    }
    std::unique_ptr<LiveNode> make(const std::string& s) {
        return testnet ? std::make_unique<LiveNode>(p, s, true) : std::make_unique<LiveNode>(p, s);
    }
    LiveNode& node(int i) { return i == 0 ? *a : *b; }

    // Mint on node `minter` (0 = A, 1 = B) on top of `prev`, add it through
    // the node's mint hook (add_local_share), then — when `relay_now` — relay
    // it to the other node and check the other node's own gentx rebuild.
    // `check_jobs`: first build the job for the same inputs on BOTH nodes and
    // require them identical.
    Minted mint(int minter, const uint256& prev, const uint160& miner, uint32_t desired_ts,
                uint32_t share_nonce, bool check_jobs = true, bool relay_now = true)
    {
        LiveNode& m = node(minter);
        LiveNode& o = node(1 - minter);
        if (check_jobs) {
            const auto ja = job_on(*a, p, prev, miner, wd, desired_ts, share_nonce);
            const auto jb = job_on(*b, p, prev, miner, wd, desired_ts, share_nonce);
            expect_same_job(ja, jb);
        }
        SolvedJob j;
        std::optional<dash::stratum::MintedShare> ms;
        EXPECT_TRUE(m.settled([&](dash::ShareTracker& t) {
            j = solve_job(t.chain, p, prev, miner, wd, share_nonce, desired_ts, {}, max_nonce, threads);
            if (j.solved)
                ms = mint_from_inputs_any(t.chain, p, j.in, j.build.frozen);
        }));
        Minted out;
        if (!j.built || !j.solved || !ms || !ms->is_v36()) {
            ADD_FAILURE() << "mint failed (built=" << j.built << " solved=" << j.solved << ")";
            return out;
        }
        const auto& built = v36_of(*ms);
        out.hash = built.share.m_hash;
        out.gentx = j.in.coinbase_bytes;
        out.gentx_hash = built.gentx_hash;
        out.share = built.share;
        EXPECT_EQ(out.gentx_hash, sha256d_bytes(out.gentx)) << "the served coinbase IS the gentx";

        auto st = ms->to_share_type();
        if (m.node->add_local_share(st).IsNull()) {
            st.destroy();
            ADD_FAILURE() << "add_local_share declined the minted share";
            return out;
        }
        EXPECT_TRUE(m.pump_until([&](dash::ShareTracker& t) { return t.verified.contains(out.hash); }))
            << "the minter verifies its own share";
        if (relay_now)
            accept_on(o, out);
        return out;
    }

    // Relay `s` from the other node to `o` and require `o` to verify it with
    // its own gentx rebuild equal to the minter's committed gentx.
    void accept_on(LiveNode& o, const Minted& s)
    {
        LiveNode& from = (&o == a.get()) ? *b : *a;
        ASSERT_TRUE(relay(from, o, s.hash));
        ASSERT_TRUE(o.pump_until([&](dash::ShareTracker& t) { return t.verified.contains(s.hash); }))
            << "the other node verifies the relayed share";
        EXPECT_TRUE(o.settled([&](dash::ShareTracker& t) {
            EXPECT_EQ(t.chain.get_share(s.hash).version(), 36);
            EXPECT_EQ(dash::generate_share_transaction(s.share, t, p), s.gentx_hash)
                << "the receiving node rebuilds the minter's gentx byte for byte";
            EXPECT_NO_THROW(dash::verify_payout_commitment(s.share, t, p, s.gentx_hash));
        }));
        EXPECT_TRUE(o.node->stored(s.hash)) << "persisted on the receiving node";
    }
};

const uint160 MINER_A = h160(0xa1);
const uint160 MINER_B = h160(0xb2);

// The (value, script) outputs of a coinbase, OP_RETURN commitment dropped.
std::vector<std::pair<uint64_t, Bytes>> paid_outputs(const Bytes& gentx) {
    std::vector<std::pair<uint64_t, Bytes>> out;
    for (auto& o : coinbase_outputs(gentx))
        if (o.second.empty() || o.second[0] != 0x6a)
            out.push_back(std::move(o));
    return out;
}

// Six shares: miners {a,b} and minters {A,B} alternating out of phase.
// Returns the minted shares in order; `rig` holds both nodes afterwards.
std::vector<Minted> grow_six(TwoNodes& rig) {
    const int minter_of[6] = {0, 1, 0, 1, 0, 1};
    const uint160* miner_of[6] = {&MINER_A, &MINER_B, &MINER_B, &MINER_A, &MINER_A, &MINER_B};
    std::vector<Minted> out;
    uint256 prev;
    std::set<Bytes> in_window;   // scripts of every miner with a share in the chain so far
    for (int k = 0; k < 6; ++k) {
        SCOPED_TRACE("share " + std::to_string(k));
        const auto m = rig.mint(minter_of[k], prev, *miner_of[k], rig.wd.m_curtime + 20u * k,
                                10u + k);
        if (m.hash.IsNull()) return out;
        EXPECT_EQ(m.share.m_desired_version, 36u);
        EXPECT_EQ(m.share.m_prev_hash, prev);

        // The v36 payout split: only window miners + the P2PKH donation, the
        // whole subsidy, donation >= 1 sat, no block-finder fee.
        uint64_t sum = 0;
        bool donation = false;
        for (const auto& [v, script] : paid_outputs(m.gentx)) {
            sum += v;
            if (script == donation_script()) { donation = true; EXPECT_GE(v, 1u); continue; }
            EXPECT_TRUE(in_window.count(script))
                << "an output for a script with no share in the window (finder fee?)";
        }
        EXPECT_TRUE(donation) << "P2PKH donation output present";
        EXPECT_EQ(sum, SUBSIDY);
        if (k == 1) {   // miner b solves share 1 over a window holding only a's share
            for (const auto& [v, script] : paid_outputs(m.gentx))
                EXPECT_NE(script, dash::pubkey_hash_to_script2(MINER_B)) << "no finder fee on v36";
        }
        in_window.insert(dash::pubkey_hash_to_script2(*miner_of[k]));
        prev = m.hash;
        out.push_back(m);
    }
    return out;
}

// ── loopback peers that outlive the node they handshake with ────────────────
struct PeerSockets {
    StubCommunicator stub;
    std::vector<std::unique_ptr<LoopbackPair>> pairs;
    LoopbackPair& next() { pairs.push_back(std::make_unique<LoopbackPair>()); return *pairs.back(); }
};

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// 1. Genesis bootstrap from either node
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36E2E, GenesisBootstrapsFromEitherNode)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_e2e_genesis");
    for (int minter : {0, 1}) {
        SCOPED_TRACE(minter == 0 ? "genesis minted by node A" : "genesis minted by node B");
        const auto f = fresh_iso();   // a fresh identity for each run
        ASSERT_TRUE(SharechainConfig::isolated_v36());
        ASSERT_EQ(f.p.current_share_version, 36u);
        const std::string sub = SharechainConfig::data_subdir(false);
        ASSERT_EQ(sub, "dash_" + f.ident.id + "_v36") << "identity- and version-scoped store";

        TwoNodes rig(f.p, sub);
        const auto g = rig.mint(minter, uint256(), MINER_A, rig.wd.m_curtime, 7);
        ASSERT_FALSE(g.hash.IsNull());
        EXPECT_TRUE(g.share.m_prev_hash.IsNull()) << "genesis";
        EXPECT_EQ(g.share.m_desired_version, 36u);

        LiveNode& minter_node = rig.node(minter);
        LiveNode& other = rig.node(1 - minter);
        EXPECT_TRUE(other.wait_best(g.hash)) << "the other node elects the genesis share";
        EXPECT_TRUE(minter_node.wait_best(g.hash));
        EXPECT_TRUE(minter_node.node->stored(g.hash));
        EXPECT_TRUE(other.settled([&](dash::ShareTracker& t) {
            EXPECT_EQ(t.chain.size(), 1u);
            EXPECT_TRUE(t.attempt_verify(g.hash));
            EXPECT_EQ(dash::share_init_verify(g.share, f.p, /*check_pow=*/true), g.hash);
        }));

        // Genesis window is empty: the whole subsidy goes to the P2PKH donation.
        const auto outs = coinbase_outputs(g.gentx);
        ASSERT_EQ(outs.size(), 2u) << "donation + OP_RETURN; no finder output";
        EXPECT_EQ(outs[0].second, donation_script());
        EXPECT_EQ(outs[0].first, SUBSIDY);
        EXPECT_EQ(outs[1].second.at(0), 0x6a);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Byte-identical gentx and PPLNS weights on both nodes
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36E2E, SixSharesTwoMinersByteIdenticalGentxAndWeightsOnBothNodes)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_e2e_six");
    const auto f = fresh_iso();
    TwoNodes rig(f.p, SharechainConfig::data_subdir(false));
    const auto shares = grow_six(rig);
    ASSERT_EQ(shares.size(), 6u);
    const uint256 tip = shares.back().hash;

    EXPECT_TRUE(rig.a->wait_best(tip));
    EXPECT_TRUE(rig.b->wait_best(tip));
    for (auto* n : {rig.a.get(), rig.b.get()}) {
        EXPECT_TRUE(n->settled([&](dash::ShareTracker& t) {
            EXPECT_EQ(t.chain.size(), 6u);
            for (const auto& s : shares) EXPECT_TRUE(t.verified.contains(s.hash));
        }));
        for (const auto& s : shares) EXPECT_TRUE(n->node->stored(s.hash));
    }

    // The next job on top of the tip, for either miner: identical on both
    // nodes, and its window pays both miners.
    for (const uint160* miner : {&MINER_A, &MINER_B}) {
        const auto ja = job_on(*rig.a, f.p, tip, *miner, rig.wd, rig.wd.m_curtime + 200, 77);
        const auto jb = job_on(*rig.b, f.p, tip, *miner, rig.wd, rig.wd.m_curtime + 200, 77);
        expect_same_job(ja, jb);
        ASSERT_TRUE(ja.weights.has_value());
        EXPECT_EQ(ja.weights->weights.size(), 2u) << "both miners weighted";
        EXPECT_EQ(ja.window.weights.count(dash::pubkey_hash_to_script2(MINER_A)), 1u);
        EXPECT_EQ(ja.window.weights.count(dash::pubkey_hash_to_script2(MINER_B)), 1u);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Restart persistence
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36E2E, RestartReloadsV36ChainAndContinuesMinting)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_e2e_restart");
    const auto f = fresh_iso();
    TwoNodes rig(f.p, SharechainConfig::data_subdir(false));
    const auto shares = grow_six(rig);
    ASSERT_EQ(shares.size(), 6u);
    const uint256 tip = shares.back().hash;
    ASSERT_TRUE(rig.b->wait_best(tip));

    std::map<uint256, Bytes> wire_before;
    ASSERT_TRUE(rig.b->settled([&](dash::ShareTracker& t) {
        for (const auto& s : shares) wire_before[s.hash] = wire_of_variant(t.chain.get_share(s.hash));
    }));

    // Stop B (verify/think pools joined, verified flags flushed, store closed)
    // and start it again on the same identity-scoped subdir.
    rig.b.reset();
    rig.b = rig.make(rig.sub + "_b");
    EXPECT_EQ(rig.b->best(), tip) << "best share seeded from the persisted chain";
    ASSERT_TRUE(rig.b->settled([&](dash::ShareTracker& t) {
        EXPECT_EQ(t.chain.size(), 6u);
        for (const auto& s : shares) {
            ASSERT_TRUE(t.chain.contains(s.hash));
            EXPECT_TRUE(t.verified.contains(s.hash)) << "verified flag reloaded";
            EXPECT_EQ(t.chain.get_share(s.hash).version(), 36);
            EXPECT_EQ(wire_of_variant(t.chain.get_share(s.hash)), wire_before[s.hash])
                << "byte-identical after reload";
        }
    }));

    // The reloaded node continues: it mints share 7 on the reloaded chain
    // (job identical to A's), A accepts and verifies it.
    const auto s7 = rig.mint(/*minter=*/1, tip, MINER_A, rig.wd.m_curtime + 140, 21);
    ASSERT_FALSE(s7.hash.IsNull());
    EXPECT_EQ(s7.share.m_prev_hash, tip);
    EXPECT_TRUE(rig.a->wait_best(s7.hash));
    EXPECT_TRUE(rig.b->wait_best(s7.hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Emergency decay, observed on both nodes
// ═════════════════════════════════════════════════════════════════════════════
//
// The decay acts on the retarget band, which exists only once the parent has
// TARGET_LOOKBEHIND (100) ancestors; before that every share sits at
// max_target and there is nothing to ease. So: 100 shares at 1 s spacing (pool
// rate far above one share per SHARE_PERIOD) root the band, two more tighten
// it to 0.9 * 0.9 * max_target, then a job for the tip after a 700 s stall
// (threshold 20*20 = 400 s, one 200 s half-life + 100 s: clamp ref 3 * pm,
// which saturates at max_target) commits max_target * 9 / 10, where the
// no-stall job commits 0.9 * pm.
TEST(DashV36E2E, EmergencyStallEasesJobIdenticallyOnBothNodes)
{
    IdentityGuard guard;
    DataDirGuard dd("c2pool_dash_v36_e2e_decay");
    const auto f = fresh_iso();
    ASSERT_TRUE(SharechainConfig::share_profile().emergency_decay);
    TwoNodes rig(f.p, SharechainConfig::data_subdir(false));
    const uint32_t lookbehind = static_cast<uint32_t>(f.p.target_lookbehind);
    ASSERT_EQ(lookbehind, 100u);

    // Grow the chain on A; B takes it in one peer batch afterwards.
    uint256 prev;
    uint32_t ts = rig.wd.m_curtime;
    std::vector<Minted> shares;
    for (uint32_t k = 0; k < lookbehind + 2; ++k) {
        const auto m = rig.mint(0, prev, (k % 2) ? MINER_B : MINER_A, ts + 1, 100 + k,
                                /*check_jobs=*/false, /*relay_now=*/false);
        ASSERT_FALSE(m.hash.IsNull()) << "share " << k;
        prev = m.hash;
        ts = m.share.m_timestamp;
        shares.push_back(m);
    }
    const auto max_target = f.p.max_target;
    EXPECT_EQ(chain::bits_to_target(shares[lookbehind - 1].share.m_max_bits),
              chain::bits_to_target(chain::target_to_bits_upper_bound(max_target)))
        << "below the lookbehind every share sits at max_target";
    {
        std::vector<std::pair<uint64_t, Bytes>> wires;
        for (const auto& s : shares) wires.emplace_back(36, wire_of(s.share));
        rig.b->receive(wires);
        ASSERT_TRUE(rig.b->pump_until([&](dash::ShareTracker& t) {
            return t.verified.contains(prev);
        })) << "B verifies the whole chain";
    }
    const uint256 tip = prev;
    const uint32_t T = ts;
    const uint256 pm = chain::bits_to_target(shares.back().share.m_max_bits);
    EXPECT_LT(pm, max_target) << "the band tightened below max_target";

    auto band_floor = [](const uint256& ref) {   // (ref * 9) / 10 at full precision
        uint288 r;
        r.SetHex(ref.GetHex());
        r = r * 9;
        r = r / 10;
        uint256 out;
        out.SetHex(r.GetHex());
        return chain::target_to_bits_upper_bound(out);
    };

    // No stall (T + 20) vs a 700 s stall (T + 700): identical on A and B.
    const auto na = job_on(*rig.a, f.p, tip, MINER_A, rig.wd, T + 20, 5);
    const auto nb = job_on(*rig.b, f.p, tip, MINER_A, rig.wd, T + 20, 5);
    expect_same_job(na, nb);
    const auto sa = job_on(*rig.a, f.p, tip, MINER_A, rig.wd, T + 700, 5);
    const auto sb = job_on(*rig.b, f.p, tip, MINER_A, rig.wd, T + 700, 5);
    expect_same_job(sa, sb);

    EXPECT_EQ(na.max_bits, band_floor(pm)) << "no stall: the band floor 0.9 * prev max_target";
    EXPECT_EQ(sa.max_bits, band_floor(max_target))
        << "700 s stall: clamp ref 3 * pm saturates at max_target, floor 0.9 * max_target";
    EXPECT_GT(chain::bits_to_target(sa.max_bits), chain::bits_to_target(na.max_bits))
        << "the stalled chain's next job is easier (numerically higher target)";
    EXPECT_GT(chain::bits_to_target(sa.bits), chain::bits_to_target(na.bits));
    EXPECT_NE(sa.gentx, na.gentx);

    // A mints the eased share; B checks it as a peer and accepts it.
    const auto e = rig.mint(0, tip, MINER_A, T + 700, 5, /*check_jobs=*/false, /*relay_now=*/true);
    ASSERT_FALSE(e.hash.IsNull());
    EXPECT_EQ(e.share.m_max_bits, sa.max_bits);
    EXPECT_EQ(e.share.m_bits, sa.bits);
    EXPECT_EQ(e.share.m_timestamp, T + 2 * SharechainConfig::share_period() - 1)
        << "the committed timestamp is still clipped";
    EXPECT_EQ(dash::share_init_verify(e.share, f.p, /*check_pow=*/true), e.hash);
    EXPECT_NO_THROW(dash::check_share_target_valid(chain::bits_to_target(e.share.m_bits), f.p));
    EXPECT_TRUE(rig.a->wait_best(e.hash));
    EXPECT_TRUE(rig.b->wait_best(e.hash));

    // Both nodes' next job on top of the eased share is identical.
    const auto xa = job_on(*rig.a, f.p, e.hash, MINER_B, rig.wd, e.share.m_timestamp + 20, 6);
    const auto xb = job_on(*rig.b, f.p, e.hash, MINER_B, rig.wd, e.share.m_timestamp + 20, 6);
    expect_same_job(xa, xb);
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. A v16 peer is refused at the handshake and not banned
// ═════════════════════════════════════════════════════════════════════════════

TEST(DashV36E2E, V16PeerRefusedAtHandshakeAndNotBanned)
{
    IdentityGuard guard;
    const std::string floor_text = "peer protocol below min-protocol floor";
    const std::string upgrade_text = "peer build lacks v36 isolated support \u2014 upgrade";
    const auto f = fresh_iso();
    {
        PeerSockets sockets;   // outlives the node (declared first)
        dash::NodeImpl node;   // its ratchet seed is read from the live profile
        ASSERT_EQ(node.runtime_min_protocol_version(), 3601u);
        NetService a1700, a3599, a3600, a3601;
        const auto r1700 = handshake_on(node, sockets.next(), sockets.stub, 1700, 0x5eed'0000'0000'1700ull, &a1700);
        const auto r3599 = handshake_on(node, sockets.next(), sockets.stub, 3599, 0x5eed'0000'0000'3599ull, &a3599);
        const auto r3600 = handshake_on(node, sockets.next(), sockets.stub, 3600, 0x5eed'0000'0000'3600ull, &a3600);
        for (const auto* r : {&r1700, &r3599, &r3600}) {
            EXPECT_TRUE(has_substr(*r, floor_text));
            EXPECT_TRUE(has_substr(*r, upgrade_text));
            // Distinct from the generic (public / operator-knob) refusal text.
            EXPECT_NE(*r, floor_text);
        }
        EXPECT_TRUE(has_substr(r1700, "peer advertises protocol 1700")) << "a p2pool-dash (1700) peer is refused";
        EXPECT_TRUE(has_substr(r3600, "peer advertises protocol 3600"))
            << "a c2pool-dash build without v36 isolated support (3600) is refused";
        EXPECT_FALSE(node.is_banned(a1700)) << "refused, not banned";
        EXPECT_FALSE(node.is_banned(a3599));
        EXPECT_FALSE(node.is_banned(a3600));
        EXPECT_EQ(handshake_on(node, sockets.next(), sockets.stub, 3601, 0x5eed'0000'0000'3601ull, &a3601),
                  "") << "the same loopback address is admitted at 3601";
        EXPECT_EQ(a1700.address(), a3601.address());
        EXPECT_EQ(a3600.address(), a3601.address());
        EXPECT_FALSE(node.is_banned(a3601));
    }

    // A v16 share wire (what a v16 chain would relay) is dropped at receive.
    DataDirGuard dd("c2pool_dash_v36_e2e_v16");
    auto p16 = f.p;
    p16.current_share_version = 16;
    dash::ShareChain scratch;
    const auto s16 = mine_v16(scratch, p16, info(uint256(), 1, 0xaa, 16)).share;
    LiveNode n(f.p, SharechainConfig::data_subdir(false));
    n.node->hold_think_slot(true);
    n.receive({{16, wire_of(s16)}});
    for (int i = 0; i < 20; ++i) { n.ioc.restart(); n.ioc.run_for(std::chrono::milliseconds(20)); }
    auto& t = n.quiesce();
    EXPECT_FALSE(t.chain.contains(s16.m_hash));
    EXPECT_EQ(t.chain.size(), 0u);
    EXPECT_FALSE(n.node->stored(s16.m_hash));
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. The rig's peer stand-in frames `version` exactly as a c2pool node does
// ═════════════════════════════════════════════════════════════════════════════

// scripts/dash_v36_peer_standin.py --self-test prints this same frame.
constexpr const char* STANDIN_VERSION_FRAME =
    "001122334455667776657273696f6e00000000008100000098b7be8da40600000000000000000000"
    "010000000000000000000000000000000000ffff7f0000014d63010000000000000000000000000000"
    "000000ffff7f0000014dbbefcdab896745230114646173682d7633362d6532652d7374616e64696e01"
    "0000000000000000000000000000000000000000000000000000000000000000000000";

TEST(DashV36E2E, PeerStandInVersionFramingGolden)
{
    const std::vector<std::byte> prefix{std::byte{0x00}, std::byte{0x11}, std::byte{0x22},
                                        std::byte{0x33}, std::byte{0x44}, std::byte{0x55},
                                        std::byte{0x66}, std::byte{0x77}};
    auto raw = dash::message_version::make_raw(
        1700u, uint64_t{0},
        addr_t(1u, NetService("127.0.0.1", 19811)),
        addr_t(1u, NetService("127.0.0.1", 19899)),
        0x0123456789abcdefull, std::string("dash-v36-e2e-standin"), 1u, uint256());
    auto ps = core::Packet::from_message(prefix, raw);
    EXPECT_EQ(hex(to_bytes(ps)), STANDIN_VERSION_FRAME);
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. Seeder for scripts/dash_v36_isolated_e2e.sh (skipped in CI)
// ═════════════════════════════════════════════════════════════════════════════
//
// Env: C2POOL_DASH_V36_E2E_SEED_DIR (the node's --data-dir),
//      C2POOL_DASH_V36_E2E_NETID / _PREFIX (the rig's fresh identity),
//      optional _COUNT (default 104: 100 lookbehind shares + 2 tightening + the
//      stall share + one after it), _THREADS (default 8), _NOW (unix time).
// Mints COUNT v36 shares at the PRODUCTION testnet share floor (2^20 X11 per
// share; mainnet's diff-1 floor is not grindable in a test) through a real
// NodeImpl into <dir>/<data_subdir(true)>, stops it (verified flags flushed),
// and writes <dir>/manifest.json with what the real processes must agree on.
TEST(DashV36E2E, SeedStoreForLoopbackRig)
{
    const char* dir = std::getenv("C2POOL_DASH_V36_E2E_SEED_DIR");
    const char* netid = std::getenv("C2POOL_DASH_V36_E2E_NETID");
    const char* prefix = std::getenv("C2POOL_DASH_V36_E2E_PREFIX");
    if (!dir || !netid || !prefix)
        GTEST_SKIP() << "seeder for scripts/dash_v36_isolated_e2e.sh (C2POOL_DASH_V36_E2E_SEED_DIR unset)";
    auto env_u = [](const char* k, uint64_t d) {
        const char* v = std::getenv(k);
        return v ? std::strtoull(v, nullptr, 10) : d;
    };
    const uint32_t count = static_cast<uint32_t>(env_u("C2POOL_DASH_V36_E2E_COUNT", 104));
    const unsigned threads = static_cast<unsigned>(env_u("C2POOL_DASH_V36_E2E_THREADS", 8));
    const uint32_t now = static_cast<uint32_t>(env_u("C2POOL_DASH_V36_E2E_NOW",
                                                     static_cast<uint64_t>(std::time(nullptr))));

    IdentityGuard guard;
    const fs::path prev_dir = core::filesystem::data_dir_override();
    core::filesystem::set_data_dir(dir);
    SharechainConfig::is_testnet = true;
    SharechainConfig::set_network_id(netid, prefix);
    ASSERT_TRUE(SharechainConfig::isolated_v36());
    const auto p = dash::make_coin_params(true);   // production testnet params, no easy()
    ASSERT_EQ(p.current_share_version, 36u);
    const std::string sub = SharechainConfig::data_subdir(true);
    const uint32_t lookbehind = static_cast<uint32_t>(p.target_lookbehind);
    const uint32_t stall_at = count >= lookbehind + 4 ? lookbehind + 2 : UINT32_MAX;

    nlohmann::json manifest;
    manifest["network_id"] = SharechainConfig::identifier_hex();
    manifest["prefix"] = SharechainConfig::prefix_hex();
    manifest["data_subdir"] = sub;
    manifest["count"] = count;
    manifest["stall_index"] = stall_at == UINT32_MAX ? -1 : static_cast<int>(stall_at);
    manifest["max_target_bits"] = chain::target_to_bits_upper_bound(p.max_target);
    nlohmann::json rows = nlohmann::json::array();
    {
        LiveNode seeder(p, sub, /*testnet=*/true);
        auto wd = make_wd();
        wd.m_curtime = now - 7200;
        uint256 prev;
        uint32_t ts = now - 3600;
        for (uint32_t k = 0; k < count; ++k) {
            const bool stall = (k == stall_at);
            const uint32_t desired = k == 0 ? ts : (stall ? ts + 700 : ts + 1);
            const uint160 miner = (k % 2) ? MINER_B : MINER_A;
            SolvedJob j;
            std::optional<dash::stratum::MintedShare> ms;
            uint32_t no_stall_max_bits = 0;
            ASSERT_TRUE(seeder.settled([&](dash::ShareTracker& t) {
                if (stall) {
                    const auto n = build_producer_job(t.chain, p, prev, dash::pubkey_hash_to_script2(miner),
                                                      wd, ts + 20, 1000 + k, 0, "c2pool");
                    if (n) no_stall_max_bits = n->job.share_max_bits;
                }
                j = solve_job(t.chain, p, prev, miner, wd, 1000 + k, desired, {}, 0x7fffffffu, threads);
                if (j.solved) ms = mint_from_inputs_any(t.chain, p, j.in, j.build.frozen);
            }));
            ASSERT_TRUE(j.built) << "share " << k;
            ASSERT_TRUE(j.solved) << "share " << k;
            ASSERT_TRUE(ms.has_value() && ms->is_v36()) << "share " << k;
            const auto& b = v36_of(*ms);
            auto st = ms->to_share_type();
            ASSERT_FALSE(seeder.node->add_local_share(st).IsNull()) << "share " << k;
            ASSERT_TRUE(seeder.pump_until([&](dash::ShareTracker& t) {
                return t.verified.contains(b.share.m_hash);
            })) << "share " << k;
            nlohmann::json r;
            r["index"] = k;
            r["hash"] = b.share.m_hash.GetHex();
            r["prev"] = b.share.m_prev_hash.GetHex();
            r["absheight"] = b.share.m_absheight;
            r["timestamp"] = b.share.m_timestamp;
            r["bits"] = b.share.m_bits;
            r["max_bits"] = b.share.m_max_bits;
            r["miner_script"] = hex(dash::pubkey_hash_to_script2(miner));
            r["gentx_hex"] = hex(j.in.coinbase_bytes);
            r["gentx_hash"] = b.gentx_hash.GetHex();
            if (stall) {
                r["stall_desired_timestamp"] = desired;
                r["no_stall_job_max_bits"] = no_stall_max_bits;
                EXPECT_GT(chain::bits_to_target(b.share.m_max_bits), chain::bits_to_target(no_stall_max_bits))
                    << "the stall share commits an easier target than the no-stall job";
            }
            rows.push_back(r);
            prev = b.share.m_hash;
            ts = b.share.m_timestamp;
        }
        manifest["tip"] = prev.GetHex();
        ASSERT_TRUE(seeder.wait_best(prev));
        ASSERT_TRUE(seeder.settled([&](dash::ShareTracker& t) {
            dash::dashboard::TemplateSource no_template;   // a daemonless node's view
            const auto v = dash::dashboard::pplns_payouts_current(t.chain, p, prev, no_template, true);
            manifest["expected_current_payouts"] = v.ok ? v.payouts : nlohmann::json::object();
        }));
    }   // seeder stops: pools joined, verified flags flushed, store closed
    manifest["shares"] = rows;
    core::filesystem::set_data_dir(prev_dir);

    std::ofstream(fs::path(dir) / "manifest.json") << manifest.dump(2) << "\n";
    std::cout << "[seed] " << count << " v36 shares into " << (fs::path(dir) / sub).string()
              << " tip=" << manifest["tip"].get<std::string>() << "\n";
}
