// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Differential replay of X1 stage A1 over a RECORDED LTC mainnet share
// chain: the old and the new get_chain bound side by side on two trackers
// built from the same input, every output byte-compared.
//
//   old: get_chain's bounds check by a full get_height walk
//        (ShareChain::set_legacy_get_chain_bound_for_test);
//   new: ShareChain::has_depth, at most n steps.
//
// Compared at every step (heads, tails' children, the best share's ancestors
// at fixed depths, a stride over all shares):
//   heights, lasts, get_height_and_last, get_chain throw/no-throw at
//   height/height+1 and the walked sequence, is_child_of(best, head);
//   think(): best, desired (peer, hash) in order, bad peers, punish flag, top5;
//   PPLNS: get_v36_decayed_cumulative_weights and get_cumulative_weights
//   (every script's weight, the totals; the skip-list one also against a
//   plain walk), the DOGE get_merged_payout_weights (resolved scripts,
//   totals, sources), compute_share_target at the best;
//   then the drop-tails step as master runs it (the same loop on both
//   trackers), its removed sequence, the full chain and verified (shares,
//   heads, tails, reverse), and think() and PPLNS again on the drained chain.
//
// L1 (CI): a committed fixture, the topology of the newest 2400 absheights of
// a recorded LTC mainnet share store
// (fixtures/ltc_sharechain_topology_mainnet_20261127.txt): hashes renumbered
// and payout scripts replaced by indices, the rest as recorded (prev links,
// bits, max_bits, donation, timestamp, share version, desired version,
// verified flag, absheight). Replayed on testnet parameters (CHAIN_LENGTH 400)
// so the 2400-share window carries full-length PPLNS windows, in three
// arrival orders (parents first, the warm load; children first, the download
// order; seeded random). The drop runs at a threshold under the shortest
// head: at the node's own, the window's stale fork head holds the tail and
// nothing drains. A second L1 pass feeds the newest 60 absheights one share
// at a time: think() compared after every share, PPLNS every 10th.
//
// L2 (build host): the full recorded store, loaded twice by the REAL
// NodeImpl::load_persisted_shares from two copies of
// $C2POOL_REPLAY_STORE_LTC/litecoin/sharechain_leveldb (the copies are opened,
// the source never is), mainnet parameters, real shares, with the drop at the
// node's threshold (2*8640+10) and at one under the shortest head (a
// 1000-layer drain). Skipped when the variable is unset. With
// $C2POOL_REPLAY_FIXTURE_OUT set it also writes the L1 fixture from the store.
//
// Standalone target ltc_walk_replay_test.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include <boost/log/core.hpp>

#include <c2pool/storage/sharechain_storage.hpp>
#include <core/filesystem.hpp>
#include <core/uint256.hpp>
#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/params.hpp>
#include <impl/ltc/share.hpp>
#include <impl/ltc/share_check.hpp>
#include <impl/ltc/share_tracker.hpp>
#include <sharechain/test/random_forest.hpp>
#include <btclibs/util/strencodings.h>

#ifndef LTC_REPLAY_FIXTURE
#error "LTC_REPLAY_FIXTURE must be defined by CMake to the committed fixture path"
#endif

namespace {

constexpr uint32_t kDogeChainId = 0x62;   // DOGEChainParams::AUXPOW_CHAIN_ID

struct QuietLog {
    bool was;
    QuietLog() : was(boost::log::core::get()->get_logging_enabled())
    {
        boost::log::core::get()->set_logging_enabled(false);
    }
    ~QuietLog() { boost::log::core::get()->set_logging_enabled(was); }
};

struct TestnetScope {
    bool was = ltc::PoolConfig::is_testnet;
    explicit TestnetScope(bool on) { ltc::PoolConfig::is_testnet = on; }
    ~TestnetScope() { ltc::PoolConfig::is_testnet = was; }
};

// ── The master drop-tails loop, verbatim (node.cpp clean_tracker Step 3) ────
// m_tracker -> tracker, m_supersede_hint -> hint; the [drop-tails-QUALIFY]
// warning and the [drop-tails-PRE] stderr marker removed; `removed` records
// each share chain.remove() took.
void old_drop_tails(ltc::ShareTracker& tracker, const ltc::SupersedeHint& hint, int32_t CL,
                    std::vector<uint256>* removed)
{
    int total_dropped = 0;
    for (int iter = 0; iter < 1000; ++iter)
    {
        std::vector<uint256> to_remove;
        auto tails_copy = tracker.chain.get_tails();
        for (auto& [tail_hash, head_hashes] : tails_copy)
        {
            if (hint.active) {
                try {
                    if (tracker.chain.contains(tail_hash) &&
                        tracker.chain.get_last(tail_hash) == hint.target_segment_last)
                        continue;
                } catch (...) {}
            }

            int32_t min_height = 0;  // default 0 → skip if no valid heads
            for (auto& hh : head_hashes) {
                if (!tracker.chain.contains(hh)) continue;
                auto h = tracker.chain.get_height(hh);
                if (min_height == 0 || h < min_height)
                    min_height = h;
            }
            if (min_height < 2 * CL + 10) continue;

            auto& rev = tracker.chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end()) {
                for (const auto& child : rev_it->second)
                    to_remove.push_back(child);
            }
        }

        if (to_remove.empty()) break;

        size_t _drop_idx = 0;
        for (const auto& aftertail : to_remove)
        {
            try {
                ++_drop_idx;
                if (!tracker.chain.contains(aftertail)) continue;
                auto* idx = tracker.chain.get_index(aftertail);
                if (!idx) continue;
                if (!tracker.chain.get_tails().count(idx->tail)) {
                    continue;
                }
                if (tracker.verified.contains(aftertail))
                    tracker.verified.remove(aftertail, /*owns_data=*/false);
                const bool ok = tracker.chain.remove(aftertail);
                ++total_dropped;
                if (removed && ok)
                    removed->push_back(aftertail);
            } catch (...) {}
        }
    }
    (void)total_dropped;
}

// ── Fixture ──────────────────────────────────────────────────────────────────

struct TopoRecord {
    int64_t idx{0};
    int64_t prev{-1};          // -1: null parent
    uint32_t bits{0}, max_bits{0};
    uint32_t donation{0};
    uint32_t timestamp{0};
    int64_t version{36};
    uint64_t desired_version{36};
    uint32_t payee{0};
    uint32_t pubkey_type{0};
    bool verified{false};
    uint32_t absheight{0};
};

constexpr uint64_t kFixtureSalt = 0x51c0ffee;

uint256 fixture_hash(int64_t idx) { return forest_test::make_hash(kFixtureSalt, static_cast<uint64_t>(idx)); }

uint160 payee_hash(uint32_t payee)
{
    const uint256 h = forest_test::make_hash(0xba1ee, payee);
    std::vector<unsigned char> b(h.data(), h.data() + 20);
    return uint160(b);
}

std::vector<TopoRecord> read_fixture(const std::string& path)
{
    std::vector<TopoRecord> out;
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open fixture " << path;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream ss(line);
        TopoRecord r;
        int verified = 0;
        ss >> r.idx >> r.prev >> std::hex >> r.bits >> r.max_bits >> std::dec >> r.donation >> r.timestamp
           >> r.version >> r.desired_version >> r.payee >> r.pubkey_type >> verified >> r.absheight;
        EXPECT_FALSE(ss.fail()) << "bad fixture line: " << line;
        r.verified = verified != 0;
        out.push_back(r);
    }
    return out;
}

ltc::ShareType make_topo_share(const TopoRecord& r)
{
    auto fill = [&](auto* sh) {
        sh->m_hash = fixture_hash(r.idx);
        if (r.prev >= 0)
            sh->m_prev_hash = fixture_hash(r.prev);
        sh->m_bits = r.bits;
        sh->m_max_bits = r.max_bits;
        sh->m_donation = static_cast<uint16_t>(r.donation);
        sh->m_timestamp = r.timestamp;
        sh->m_absheight = r.absheight;
        sh->m_desired_version = r.desired_version;
        sh->m_pubkey_hash = payee_hash(r.payee);
        sh->m_pubkey_type = static_cast<uint8_t>(r.pubkey_type);
        sh->m_min_header.m_timestamp = r.timestamp;
        sh->m_min_header.m_bits = 0x1a0fffff;
    };
    ltc::ShareType st;
    if (r.version == ltc::FLAG_DAY_SHARE_VERSION) {
        auto* sh = new ltc::MergedMiningShareV3601();
        fill(sh);
        st = sh;
    } else {
        auto* sh = new ltc::MergedMiningShare();
        fill(sh);
        st = sh;
    }
    return st;
}

// Builds a tracker from the fixture: chain in `order`, then verified parents
// first (absheight order), as the warm load does; time_seen = timestamp.
void build_from_fixture(ltc::ShareTracker& t, const std::vector<TopoRecord>& recs,
                        const std::vector<size_t>& order)
{
    for (size_t i : order)
        t.add(make_topo_share(recs[i]));
    std::vector<size_t> by_abs(recs.size());
    for (size_t i = 0; i < recs.size(); ++i)
        by_abs[i] = i;
    std::stable_sort(by_abs.begin(), by_abs.end(), [&](size_t x, size_t y) {
        return recs[x].absheight < recs[y].absheight;
    });
    for (size_t i : by_abs) {
        const uint256 h = fixture_hash(recs[i].idx);
        if (auto* idx = t.chain.get_index(h))
            idx->time_seen = recs[i].timestamp;
        if (recs[i].verified && !t.verified.contains(h))
            t.verified.add(t.chain.get_share(h));
    }
}

// ── Comparisons ──────────────────────────────────────────────────────────────

std::string hex(const uint256& h) { return h.GetHex(); }

struct Counters {
    size_t walk_checks{0}, chain_checks{0}, pplns_checks{0}, think_checks{0}, removed{0};
};

// The query set: heads, the children of tails, ancestors of `best` at fixed
// depths, and a stride over all present shares.
std::vector<uint256> query_set(ltc::ShareTracker& t, const uint256& best, size_t stride)
{
    std::set<uint256> q;
    for (const auto& [h, tl] : t.chain.get_heads())
        q.insert(h);
    for (const auto& [h, tl] : t.verified.get_heads())
        q.insert(h);
    const auto& rev = t.chain.get_reverse();
    for (const auto& [tl, hs] : t.chain.get_tails()) {
        auto it = rev.find(tl);
        if (it != rev.end())
            q.insert(it->second.begin(), it->second.end());
    }
    if (!best.IsNull() && t.chain.contains(best)) {
        const int32_t h = t.chain.get_height(best);
        for (int32_t d : {0, 1, 5, 10, 100, 399, 400, 401, 1000, 4320, 8639, 8640, 8641, 17290}) {
            if (d < h)
                q.insert(t.chain.get_nth_parent_key(best, d));
        }
    }
    std::vector<uint256> all;
    for (const auto& [h, tl] : t.chain.get_heads()) {
        uint256 cur = h;
        for (int i = 0; i < 200000 && !cur.IsNull() && t.chain.contains(cur); ++i) {
            if (static_cast<size_t>(i) % stride == 0)
                q.insert(cur);
            cur = t.chain.get_index(cur)->tail;
        }
    }
    q.insert(uint256());
    return {q.begin(), q.end()};
}

void compare_walks(ltc::ShareChain& a, ltc::ShareChain& b, const std::vector<uint256>& qs,
                   const char* which, Counters& c)
{
    for (const auto& q : qs) {
        const int32_t ha = a.get_height(q), hb = b.get_height(q);
        ASSERT_EQ(ha, hb) << which << " height " << hex(q);
        ASSERT_EQ(a.get_last(q), b.get_last(q)) << which << " last " << hex(q);
        const auto hla = a.get_height_and_last(q), hlb = b.get_height_and_last(q);
        ASSERT_EQ(hla.height, hlb.height);
        ASSERT_EQ(hla.last, hlb.last);
        ++c.walk_checks;
        for (uint64_t n : {uint64_t(0), uint64_t(1), static_cast<uint64_t>(ha), static_cast<uint64_t>(ha) + 1}) {
            bool ta = false, tb = false;
            std::vector<uint256> sa, sb;
            try {
                for (auto [h, d] : a.get_chain(q, n)) {
                    sa.push_back(h);
                    if (sa.size() >= 64) break;
                }
            } catch (const std::invalid_argument&) { ta = true; }
            try {
                for (auto [h, d] : b.get_chain(q, n)) {
                    sb.push_back(h);
                    if (sb.size() >= 64) break;
                }
            } catch (const std::invalid_argument&) { tb = true; }
            ASSERT_EQ(ta, tb) << which << " get_chain throw " << hex(q) << " n=" << n;
            ASSERT_EQ(ta, n > static_cast<uint64_t>(ha));
            ASSERT_EQ(sa, sb) << which << " get_chain sequence " << hex(q) << " n=" << n;
            ++c.chain_checks;
        }
    }
}

void compare_trackers(ltc::ShareTracker& a, ltc::ShareTracker& b, const uint256& best_a,
                      const uint256& best_b, size_t stride, Counters& c)
{
    ASSERT_EQ(best_a, best_b);
    ASSERT_EQ(a.chain.size(), b.chain.size());
    ASSERT_EQ(a.verified.size(), b.verified.size());
    auto heads = [](ltc::ShareChain& ch) {
        std::map<uint256, uint256> m(ch.get_heads().begin(), ch.get_heads().end());
        return m;
    };
    auto tails = [](ltc::ShareChain& ch) {
        std::map<uint256, std::set<uint256>> m(ch.get_tails().begin(), ch.get_tails().end());
        return m;
    };
    auto reverse = [](ltc::ShareChain& ch) {
        std::map<uint256, std::set<uint256>> m(ch.get_reverse().begin(), ch.get_reverse().end());
        return m;
    };
    ASSERT_EQ(heads(a.chain), heads(b.chain));
    ASSERT_EQ(tails(a.chain), tails(b.chain));
    ASSERT_EQ(reverse(a.chain), reverse(b.chain));
    ASSERT_EQ(heads(a.verified), heads(b.verified));
    ASSERT_EQ(tails(a.verified), tails(b.verified));
    ASSERT_EQ(reverse(a.verified), reverse(b.verified));
    const auto qs = query_set(a, best_a, stride);
    ASSERT_EQ(qs, query_set(b, best_b, stride));
    compare_walks(a.chain, b.chain, qs, "chain", c);
    compare_walks(a.verified, b.verified, qs, "verified", c);
    if (!best_a.IsNull()) {
        for (const auto& [h, tl] : a.chain.get_heads())
            ASSERT_EQ(a.chain.is_child_of(best_a, h), b.chain.is_child_of(best_b, h)) << hex(h);
    }
}

std::string think_fingerprint(const ltc::TrackerThinkResult& r)
{
    std::ostringstream o;
    o << "best=" << hex(r.best) << " punish=" << r.punish_aggressively << "\ndesired:";
    for (const auto& [peer, h] : r.desired)
        o << " " << peer.to_string() << "/" << hex(h);
    o << "\nbad:";
    for (const auto& p : r.bad_peer_addresses)
        o << " " << p.to_string();
    o << "\ntop5:";
    for (const auto& h : r.top5_heads)
        o << " " << hex(h);
    return o.str();
}

std::string weights_fingerprint(const ltc::CumulativeWeights& w)
{
    std::ostringstream o;
    o << "total=" << w.total_weight.GetHex() << " don=" << w.total_donation_weight.GetHex();
    for (const auto& [script, wt] : w.weights)
        o << "\n" << HexStr(script) << "=" << wt.GetHex();
    return o.str();
}

std::string merged_fingerprint(const ltc::MergedPayoutWeights& w)
{
    std::ostringstream o;
    o << "best=" << hex(w.best) << " len=" << w.chain_len << " total=" << w.total_weight.GetHex()
      << " don=" << w.donation_weight.GetHex() << " acc=" << w.accepted_total.GetHex();
    for (const auto& [script, wt] : w.resolved)
        o << "\nR " << HexStr(script) << "=" << wt.GetHex();
    for (const auto& s : w.sources)
        o << "\nS " << HexStr(s.script) << " " << HexStr(s.parent) << " " << s.explicit_address << " "
          << s.weight.GetHex();
    return o.str();
}

// The flat (undecayed) PPLNS weights of the n shares from `start`, by a plain
// walk: what WeightsSkipList::query must sum (ShareTracker's per-share delta,
// desired weight unlimited).
ltc::CumulativeWeights flat_weights_by_walk(ltc::ShareTracker& t, const uint256& start, int32_t n)
{
    ltc::CumulativeWeights out;
    uint256 cur = start;
    for (int32_t i = 0; i < n && !cur.IsNull() && t.chain.contains(cur); ++i) {
        t.chain.get_share(cur).invoke([&](auto* obj) {
            const auto att = chain::target_to_average_attempts(chain::bits_to_target(obj->m_bits));
            out.total_weight += att * 65535;
            out.total_donation_weight += att * static_cast<uint32_t>(obj->m_donation);
            out.weights[ltc::get_share_script(obj)] += att * static_cast<uint32_t>(65535 - obj->m_donation);
        });
        cur = t.chain.get_index(cur)->tail;
    }
    return out;
}

// Out-of-range skip-list queries (max_shares above the shares there are),
// measured on both trackers against the plain walk. Printed, not asserted:
// a property of WeightsSkipList that this change does not touch.
void skiplist_past_end_note(ltc::ShareTracker& a, ltc::ShareTracker& b, const uint256& best, const char* tag)
{
    if (best.IsNull() || !a.chain.contains(best))
        return;
    const int32_t CL = static_cast<int32_t>(ltc::PoolConfig::chain_length());
    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const int32_t h = a.chain.get_height(best);
    int checked = 0, a_off = 0, b_off = 0, ab_differ = 0;
    for (int32_t d : {CL / 2, CL - 1, CL, h - CL / 2, h - 10}) {
        if (d <= 0 || d >= h)
            continue;
        const uint256 s = a.chain.get_nth_parent_key(best, d);
        if (a.chain.get_height(s) >= CL)
            continue;   // in range: asserted in compare_pplns
        const auto ref = weights_fingerprint(flat_weights_by_walk(a, s, CL));
        const auto fa = weights_fingerprint(a.get_cumulative_weights(s, CL, unlimited));
        const auto fb = weights_fingerprint(b.get_cumulative_weights(s, CL, unlimited));
        ++checked;
        a_off += fa != ref;
        b_off += fb != ref;
        ab_differ += fa != fb;
    }
    std::printf("[LtcWalkReplay %s] skip-list PPLNS past the chain end (max_shares > height): %d starts, "
                "old-side off the plain walk %d, new-side off %d, sides differ %d\n",
                tag, checked, a_off, b_off, ab_differ);
}

// PPLNS at the best share and at its ancestors at fixed depths and at heads.
void compare_pplns(ltc::ShareTracker& a, ltc::ShareTracker& b, const uint256& best, Counters& c)
{
    if (best.IsNull() || !a.chain.contains(best))
        return;
    const int32_t CL = static_cast<int32_t>(ltc::PoolConfig::chain_length());
    uint288 unlimited;
    unlimited.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    std::set<uint256> at;
    at.insert(best);
    const int32_t h = a.chain.get_height(best);
    for (int32_t d : {1, 2, 10, 100, CL / 2, CL - 1, CL})
        if (d < h)
            at.insert(a.chain.get_nth_parent_key(best, d));
    for (const auto& [hh, tl] : a.verified.get_heads())
        at.insert(hh);
    for (const auto& s : at) {
        ASSERT_EQ(weights_fingerprint(a.get_v36_decayed_cumulative_weights(s, CL, unlimited)),
                  weights_fingerprint(b.get_v36_decayed_cumulative_weights(s, CL, unlimited)))
            << "v36 decayed at " << hex(s);
        // The skip-list PPLNS is asked for at most the shares there are, as
        // its consensus callers ask (share_check: min(height, CL) - 1). Past
        // the chain's end its answer depends on the instance: skip heights are
        // drawn at random per instance and a skip cached before a prune still
        // spans the pruned shares (forget() drops only the removed share's
        // own entry). That is measured, not asserted, by
        // skiplist_past_end_note.
        const int32_t n_flat = std::min(a.chain.get_height(s), CL);
        ASSERT_EQ(weights_fingerprint(a.get_cumulative_weights(s, n_flat, unlimited)),
                  weights_fingerprint(b.get_cumulative_weights(s, n_flat, unlimited)))
            << "cumulative at " << hex(s);
        ASSERT_EQ(weights_fingerprint(a.get_cumulative_weights(s, n_flat, unlimited)),
                  weights_fingerprint(flat_weights_by_walk(a, s, n_flat)))
            << "cumulative (skip list) against a plain walk at " << hex(s);
        ASSERT_EQ(merged_fingerprint(a.get_merged_payout_weights(s, kDogeChainId)),
                  merged_fingerprint(b.get_merged_payout_weights(s, kDogeChainId)))
            << "merged DOGE at " << hex(s);
        uint32_t ts = 0;
        a.chain.get_share(s).invoke([&](auto* obj) { ts = obj->m_timestamp; });
        const auto ta = a.compute_share_target(s, ts + 10, ltc::PoolConfig::max_target());
        const auto tb = b.compute_share_target(s, ts + 10, ltc::PoolConfig::max_target());
        ASSERT_EQ(ta.bits, tb.bits);
        ASSERT_EQ(ta.max_bits, tb.max_bits);
        ++c.pplns_checks;
    }
}

// The whole replay on two trackers built from the same input: `a` runs the old
// code, `b` the new.
struct ReplayOut {
    Counters c;
    std::string first_think, final_think;
    size_t dropped{0};
    int64_t drop_us{0};
};

uint256 run_think(ltc::ShareTracker& t, std::string& fp)
{
    auto brh = [](uint256) -> int32_t { return 0; };
    uint256 prev_block;
    const auto r = t.think(brh, prev_block, 0, /*bootstrap=*/t.verified.size() == 0, ltc::SupersedeHint{});
    fp = think_fingerprint(r);
    return r.best;
}

void replay(ltc::ShareTracker& a, ltc::ShareTracker& b, int32_t drop_cl, size_t stride,
            ReplayOut& out)
{
    a.chain.set_legacy_get_chain_bound_for_test(true);
    a.verified.set_legacy_get_chain_bound_for_test(true);

    // 1. As loaded.
    compare_trackers(a, b, uint256(), uint256(), stride, out.c);
    if (::testing::Test::HasFatalFailure()) return;

    // 2. think() on both, twice (the second pass sees the first's verified).
    std::string fa, fb;
    uint256 best_a, best_b;
    for (int pass = 0; pass < 2; ++pass) {
        best_a = run_think(a, fa);
        best_b = run_think(b, fb);
        ASSERT_EQ(fa, fb) << "think pass " << pass;
        ++out.c.think_checks;
        if (pass == 0)
            out.first_think = fa;
    }
    compare_trackers(a, b, best_a, best_b, stride, out.c);
    if (::testing::Test::HasFatalFailure()) return;
    compare_pplns(a, b, best_a, out.c);
    if (::testing::Test::HasFatalFailure()) return;

    // 3. Drop tails as master does, on both (the loop reads heights, not
    //    get_chain: the trackers must stay identical through it).
    std::vector<uint256> rem_old, rem_new;
    const auto t0 = std::chrono::steady_clock::now();
    old_drop_tails(a, ltc::SupersedeHint{}, drop_cl, &rem_old);
    out.drop_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0).count();
    old_drop_tails(b, ltc::SupersedeHint{}, drop_cl, &rem_new);
    ASSERT_EQ(rem_new, rem_old) << "drop-tails removed sequence";
    out.dropped = rem_old.size();
    out.c.removed += rem_old.size();
    compare_trackers(a, b, best_a, best_b, stride, out.c);
    if (::testing::Test::HasFatalFailure()) return;

    // 4. think() and PPLNS on the drained chain.
    best_a = run_think(a, fa);
    best_b = run_think(b, fb);
    ASSERT_EQ(fa, fb) << "think after the drop";
    ++out.c.think_checks;
    out.final_think = fa;
    compare_trackers(a, b, best_a, best_b, stride, out.c);
    if (::testing::Test::HasFatalFailure()) return;
    compare_pplns(a, b, best_a, out.c);
    if (::testing::Test::HasFatalFailure()) return;
    skiplist_past_end_note(a, b, best_a, "after the drop");
}

std::string first_line(const std::string& s) { return s.substr(0, s.find('\n')); }

// A drop threshold just under the shortest head, so the tracker drains up to
// 1000 layers: a stale fork head low in the window holds the tail at the
// node's own threshold (the recorded stores show exactly that).
int32_t forced_drop_cl(ltc::ShareTracker& t)
{
    int32_t min_head = INT32_MAX;
    for (const auto& [h, tl] : t.chain.get_heads())
        if (t.chain.contains(h))
            min_head = std::min(min_head, t.chain.get_height(h));
    return std::max<int32_t>(1, (min_head - 10 - 1000) / 2);
}

}  // namespace

// ── L1: the committed fixture ────────────────────────────────────────────────

TEST(LtcWalkReplay, CommittedFixtureOldAndNewAgreeInEveryArrivalOrder)
{
    QuietLog quiet;
    TestnetScope testnet(true);   // CHAIN_LENGTH 400: full PPLNS windows in 2400 shares
    const core::CoinParams params = ltc::make_coin_params(true);
    const auto recs = read_fixture(LTC_REPLAY_FIXTURE);
    ASSERT_GT(recs.size(), 2000u);

    std::vector<size_t> forward(recs.size());
    for (size_t i = 0; i < recs.size(); ++i)
        forward[i] = i;
    std::stable_sort(forward.begin(), forward.end(), [&](size_t x, size_t y) {
        return recs[x].absheight < recs[y].absheight;
    });
    std::vector<size_t> backward(forward.rbegin(), forward.rend());
    std::vector<size_t> shuffled = forward;
    std::shuffle(shuffled.begin(), shuffled.end(), std::mt19937_64(20261127));

    const struct { const char* name; const std::vector<size_t>* order; } orders[] = {
        {"parents-first", &forward}, {"children-first", &backward}, {"random", &shuffled}};
    for (const auto& o : orders) {
        SCOPED_TRACE(o.name);
        ltc::ShareTracker a, b;
        a.m_params = &params;
        b.m_params = &params;
        build_from_fixture(a, recs, *o.order);
        build_from_fixture(b, recs, *o.order);
        ReplayOut out;
        // At the node's threshold (2*400+10) the stale fork head low in the
        // window holds the tail, so the drop runs at a threshold under the
        // shortest head.
        replay(a, b, forced_drop_cl(a), 7, out);
        if (::testing::Test::HasFatalFailure())
            return;
        EXPECT_GT(out.dropped, 0u) << "the fixture must exercise a drain";
        std::printf("[LtcWalkReplay L1 %s] shares=%zu walks=%zu get_chain=%zu pplns=%zu think=%zu "
                    "dropped=%zu drop=%.1fms | %s\n",
                    o.name, recs.size(), out.c.walk_checks, out.c.chain_checks, out.c.pplns_checks,
                    out.c.think_checks, out.dropped, out.drop_us / 1000.0,
                    first_line(out.final_think).c_str());
    }
}

// L1, share by share: both trackers hold the fixture minus its newest 60
// absheights; the rest arrive one at a time (verified flag as recorded) and
// after each the two think(), and every 10th the PPLNS at the best, compare.
TEST(LtcWalkReplay, CommittedFixtureShareByShareThinkAndPayouts)
{
    QuietLog quiet;
    TestnetScope testnet(true);
    const core::CoinParams params = ltc::make_coin_params(true);
    const auto recs = read_fixture(LTC_REPLAY_FIXTURE);
    ASSERT_GT(recs.size(), 2000u);
    std::vector<size_t> forward(recs.size());
    for (size_t i = 0; i < recs.size(); ++i)
        forward[i] = i;
    std::stable_sort(forward.begin(), forward.end(), [&](size_t x, size_t y) {
        return recs[x].absheight < recs[y].absheight;
    });
    const uint32_t cut = recs[forward.back()].absheight - 60;
    std::vector<size_t> base, late;
    for (size_t i : forward)
        (recs[i].absheight <= cut ? base : late).push_back(i);
    ASSERT_GT(late.size(), 50u);

    ltc::ShareTracker a, b;
    a.m_params = &params;
    b.m_params = &params;
    a.chain.set_legacy_get_chain_bound_for_test(true);
    a.verified.set_legacy_get_chain_bound_for_test(true);
    std::vector<TopoRecord> base_recs;
    for (size_t i : base)
        base_recs.push_back(recs[i]);
    std::vector<size_t> order(base_recs.size());
    for (size_t i = 0; i < order.size(); ++i)
        order[i] = i;
    build_from_fixture(a, base_recs, order);
    build_from_fixture(b, base_recs, order);

    Counters c;
    std::string fa, fb;
    size_t steps = 0, best_changes = 0;
    uint256 last_best;
    for (size_t i : late) {
        for (ltc::ShareTracker* t : {&a, &b}) {
            t->add(make_topo_share(recs[i]));
            const uint256 h = fixture_hash(recs[i].idx);
            t->chain.get_index(h)->time_seen = recs[i].timestamp;
            if (recs[i].verified && !t->verified.contains(h))
                t->verified.add(t->chain.get_share(h));
        }
        const uint256 best_a = run_think(a, fa);
        const uint256 best_b = run_think(b, fb);
        ASSERT_EQ(fa, fb) << "think after share " << steps;
        ++c.think_checks;
        best_changes += best_a != last_best;
        last_best = best_a;
        if (steps % 10 == 0) {
            compare_trackers(a, b, best_a, best_b, 29, c);
            if (::testing::Test::HasFatalFailure()) return;
            compare_pplns(a, b, best_a, c);
            if (::testing::Test::HasFatalFailure()) return;
        }
        ++steps;
    }
    std::printf("[LtcWalkReplay L1 share-by-share] %zu shares fed, %zu think() compared, "
                "%zu best changes, pplns=%zu walks=%zu get_chain=%zu\n",
                steps, c.think_checks, best_changes, c.pplns_checks, c.walk_checks, c.chain_checks);
}

// ── L2: the full recorded store ──────────────────────────────────────────────

namespace {

struct ReplayNode : public ltc::NodeImpl
{
    ReplayNode() : ltc::NodeImpl() { m_chain = &m_tracker.chain; }
    void handle(std::unique_ptr<RawMessage>, const NetService&) override {}
    using ltc::NodeImpl::m_storage;
    using ltc::NodeImpl::m_tracker;
    using ltc::NodeImpl::load_persisted_shares;
};

struct DataDirScope {
    std::filesystem::path saved = core::filesystem::data_dir_override();
    explicit DataDirScope(const std::filesystem::path& d) { core::filesystem::set_data_dir(d); }
    ~DataDirScope() { core::filesystem::set_data_dir(saved); }
};

// Copies <src>/litecoin/sharechain_leveldb to a fresh scratch root (the loader
// prunes below its window, so each node gets its own copy; the source is only
// read). Returns the root.
std::filesystem::path copy_store(const std::filesystem::path& src, const char* tag)
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("c2pool_ltc_replay_" + std::string(tag) + "_" + std::to_string(::getpid()));
    fs::remove_all(root);
    const fs::path dst = root / "litecoin" / "sharechain_leveldb";
    fs::create_directories(dst);
    // File by file: the source may be read-only (it should be), and a
    // recursive copy would carry its directory mode over.
    for (const auto& e : fs::directory_iterator(src / "litecoin" / "sharechain_leveldb")) {
        if (!e.is_regular_file() || e.path().filename() == "LOCK")
            continue;
        const fs::path to = dst / e.path().filename();
        fs::copy_file(e.path(), to);
        fs::permissions(to, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::add);
    }
    return root;
}

void load_node(ReplayNode& node, const std::filesystem::path& root)
{
    DataDirScope dd(root);
    node.m_storage = std::make_unique<c2pool::storage::SharechainStorage>("litecoin");
    ASSERT_TRUE(node.m_storage->is_available());
    node.load_persisted_shares();
    node.m_storage.reset();   // the replay never writes the store again
    // time_seen = the share's own timestamp on both sides: load time is not
    // an input (think's head scoring breaks ties on it).
    for (const auto& [h, tl] : node.m_tracker.chain.get_heads()) {
        uint256 cur = h;
        for (int i = 0; i < 200000 && !cur.IsNull() && node.m_tracker.chain.contains(cur); ++i) {
            auto* idx = node.m_tracker.chain.get_index(cur);
            node.m_tracker.chain.get_share(cur).invoke([&](auto* obj) { idx->time_seen = obj->m_timestamp; });
            cur = idx->tail;
        }
    }
}

// Writes the L1 fixture from a loaded tracker: the newest `window` absheights.
void write_fixture(ltc::ShareTracker& t, const std::string& path, uint32_t window, const std::string& source)
{
    struct Row { uint256 hash; uint256 prev; uint32_t bits, max_bits, donation, ts, abs; int64_t ver;
                 uint64_t dv; std::vector<unsigned char> script; uint32_t ptype; bool verified; };
    std::vector<Row> rows;
    uint32_t max_abs = 0;
    std::set<uint256> seen;
    for (const auto& [h, tl] : t.chain.get_heads()) {
        uint256 cur = h;
        while (!cur.IsNull() && t.chain.contains(cur) && seen.insert(cur).second) {
            Row r{};
            r.hash = cur;
            t.chain.get_share(cur).invoke([&](auto* obj) {
                r.prev = obj->m_prev_hash;
                r.bits = obj->m_bits;
                r.max_bits = obj->m_max_bits;
                r.donation = obj->m_donation;
                r.ts = obj->m_timestamp;
                r.abs = obj->m_absheight;
                r.ver = obj->version;
                r.dv = obj->m_desired_version;
                r.script = ltc::get_share_script(obj);
                if constexpr (requires { obj->m_pubkey_type; })
                    r.ptype = obj->m_pubkey_type;
                else
                    r.ptype = 0;
            });
            r.verified = t.verified.contains(cur);
            max_abs = std::max(max_abs, r.abs);
            rows.push_back(r);
            cur = t.chain.get_index(cur)->tail;
        }
    }
    const uint32_t low = max_abs > window ? max_abs - window + 1 : 0;
    std::vector<Row> kept;
    for (const auto& r : rows)
        if (r.abs >= low)
            kept.push_back(r);
    std::sort(kept.begin(), kept.end(), [](const Row& x, const Row& y) {
        return x.abs != y.abs ? x.abs < y.abs : x.hash < y.hash;
    });
    std::map<uint256, int64_t> idx;
    for (const auto& r : kept)
        idx.emplace(r.hash, static_cast<int64_t>(idx.size()));
    int64_t next = static_cast<int64_t>(idx.size());
    std::map<uint256, int64_t> missing;   // parents outside the window
    std::map<std::vector<unsigned char>, uint32_t> payees;
    std::ofstream o(path);
    o << "# c2pool LTC share-chain topology fixture v1 (ltc_walk_replay_test L1)\n"
      << "# source: " << source << "\n"
      << "# the newest " << window << " absheights (" << low << ".." << max_abs << "), every share in them\n"
      << "# hashes renumbered (forest_test::make_hash(0x51c0ffee, idx)); a parent outside the window\n"
      << "# gets an index with no line (a missing parent); payout scripts replaced by indices.\n"
      << "# idx prev bits(hex) max_bits(hex) donation timestamp version desired_version payee pubkey_type verified absheight\n";
    for (const auto& r : kept) {
        int64_t p = -1;
        if (!r.prev.IsNull()) {
            auto it = idx.find(r.prev);
            if (it != idx.end())
                p = it->second;
            else {
                auto m = missing.find(r.prev);
                if (m == missing.end())
                    m = missing.emplace(r.prev, next++).first;
                p = m->second;
            }
        }
        auto pe = payees.find(r.script);
        if (pe == payees.end())
            pe = payees.emplace(r.script, static_cast<uint32_t>(payees.size())).first;
        char bits[32];
        std::snprintf(bits, sizeof bits, "%08x %08x", r.bits, r.max_bits);
        o << idx[r.hash] << " " << p << " " << bits << " " << r.donation << " " << r.ts << " " << r.ver << " "
          << r.dv << " " << pe->second << " " << r.ptype << " " << (r.verified ? 1 : 0) << " " << r.abs << "\n";
    }
    std::printf("[LtcWalkReplay] wrote fixture %s: %zu shares, %zu missing parents, %zu payees\n",
                path.c_str(), kept.size(), missing.size(), payees.size());
}

}  // namespace

TEST(LtcWalkReplay, RecordedStoreOldAndNewAgree)
{
    const char* src = std::getenv("C2POOL_REPLAY_STORE_LTC");
    if (!src || !*src)
        GTEST_SKIP() << "C2POOL_REPLAY_STORE_LTC unset: the full-store replay runs on the build host";
    QuietLog quiet;
    TestnetScope mainnet(false);
    const std::filesystem::path source(src);

    const auto root_a = copy_store(source, "a");
    const auto root_b = copy_store(source, "b");
    ReplayNode na, nb;
    load_node(na, root_a);
    load_node(nb, root_b);
    ASSERT_GT(na.m_tracker.chain.size(), 1000u);
    std::printf("[LtcWalkReplay L2] loaded chain=%zu verified=%zu heads=%zu tails=%zu\n",
                na.m_tracker.chain.size(), na.m_tracker.verified.size(),
                na.m_tracker.chain.get_heads().size(), na.m_tracker.chain.get_tails().size());

    if (const char* fx = std::getenv("C2POOL_REPLAY_FIXTURE_OUT"); fx && *fx)
        write_fixture(na.m_tracker, fx, 2400, std::getenv("C2POOL_REPLAY_SOURCE_NOTE")
                                                  ? std::getenv("C2POOL_REPLAY_SOURCE_NOTE")
                                                  : "a recorded LTC mainnet share store");

    // Pass 1: the node's own drop threshold (2*8640+10).
    ReplayOut out;
    replay(na.m_tracker, nb.m_tracker, 8640, 97, out);
    if (::testing::Test::HasFatalFailure())
        return;
    std::printf("[LtcWalkReplay L2 real-CL] walks=%zu get_chain=%zu pplns=%zu think=%zu dropped=%zu "
                "drop=%.1fms\n  first think: %s\n  final think: %s\n",
                out.c.walk_checks, out.c.chain_checks, out.c.pplns_checks, out.c.think_checks, out.dropped,
                out.drop_us / 1000.0, first_line(out.first_think).c_str(), first_line(out.final_think).c_str());

    // Pass 2: a threshold just under the shortest head, so the store drains
    // the full 1000 layers.
    const int32_t forced_cl = forced_drop_cl(na.m_tracker);
    ReplayOut out2;
    replay(na.m_tracker, nb.m_tracker, forced_cl, 97, out2);
    if (::testing::Test::HasFatalFailure())
        return;
    std::printf("[LtcWalkReplay L2 forced-drain CL=%d] walks=%zu get_chain=%zu pplns=%zu think=%zu "
                "dropped=%zu drop=%.1fms\n  final think: %s\n",
                forced_cl, out2.c.walk_checks, out2.c.chain_checks, out2.c.pplns_checks,
                out2.c.think_checks, out2.dropped, out2.drop_us / 1000.0, first_line(out2.final_think).c_str());
    EXPECT_GE(out2.dropped, 900u) << "the forced pass must drain";

    std::error_code ec;
    std::filesystem::remove_all(root_a, ec);
    std::filesystem::remove_all(root_b, ec);
}
