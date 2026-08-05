// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ── THE PHASE-1 REPLAY RUN (W5 integration proving harness) ────────────────
//
// The KATs in test_dash_replay_fold.cpp prove the fold rules against a
// handful of hand-picked mainnet blocks. THIS runs the same engine over a
// CONTIGUOUS mainnet range and checks, at every single block, that
//
//     computed merkleRootMNList  ==  that block's committed cbTx root
//
// The committed root is the chain's own answer key, written by miners; a run
// of N consecutive byte-exact matches is N independent confirmations that our
// replayed DML equals dashd's. That is the daemonless-DASH claim, measured.
//
// It is DATA-DRIVEN and skips itself when the data is absent, so it is inert
// in CI and costs a normal build nothing:
//
//   C2POOL_REPLAY_PRESTATE  full-state anchor prestate
//                           (tools/dash/gen_replay_kat.py prestate)
//   C2POOL_REPLAY_CORPUS    "<height> <raw block hex>" per line, ascending,
//                           contiguous, starting at anchor+1
//   C2POOL_REPLAY_MEMBERS   optional quorum-member sets, format below
//   C2POOL_REPLAY_STOP      optional height to stop at (default: end of file)
//
// ── Trust posture, stated plainly ─────────────────────────────────────────
//
// The ANCHOR is trusted input (that is what Phase 1 means) — but not blindly:
// seed_engine_from_prestate re-derives the SML root from the seeded state and
// refuses it unless it reproduces the root the anchor block itself commits.
//
// The MEMBER SETS are likewise anchor-class input here. They are needed only
// for commitments that actually mark members invalid (see fold_qfcommit); the
// self-derivation of membership from the replayed list is W4's engine and is
// proven by W4's own KATs, not by this harness. This file therefore proves the
// DML FOLD + ROOT CHAIN, and is explicit that it does not, by itself, prove
// membership derivation.
//
// Nothing else is trusted: every block body is parsed from raw chain bytes and
// every root is recomputed from our own folded state.
//
// Members file format (`c2pool-dash-replay-quorum-members/1`):
//     quorum <llmqType> <quorumHash display hex> <count>
//     member <proTxHash display hex>          × count
//     ...

#include <gtest/gtest.h>

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/replay_fold_consumer.hpp>
#include <impl/dash/coin/replay_prestate.hpp>
#include <impl/dash/coin/block.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using dash::coin::BlockType;
using dash::coin::replay::DmlFoldEngine;
using dash::coin::replay::FoldConfig;

namespace {

const char* env_or_null(const char* k)
{
    const char* v = std::getenv(k);
    return (v && *v) ? v : nullptr;
}

std::vector<uint8_t> hex_to_bin(const std::string& h)
{
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// (llmqType, quorumHash) -> ordered member proTxHash list, bitset-aligned.
using MemberKey   = std::pair<uint8_t, std::string>;   // hash in DISPLAY hex
using MemberStore = std::map<MemberKey, std::vector<uint256>>;

MemberStore load_members(const std::string& path, std::string& err)
{
    MemberStore store;
    std::ifstream in(path);
    if (!in) { err = "cannot open members file " + path; return store; }
    std::string line;
    if (!std::getline(in, line)
        || line.rfind("c2pool-dash-replay-quorum-members/1", 0) != 0) {
        err = "bad members-file format tag: '" + line + "'";
        return store;
    }
    MemberKey cur{0, ""};
    size_t want = 0;
    while (std::getline(in, line)) {
        std::istringstream is(line);
        std::string kind;
        if (!(is >> kind)) continue;
        if (kind == "quorum") {
            int type = 0; std::string hash; size_t n = 0;
            if (!(is >> type >> hash >> n)) { err = "bad quorum line: " + line; return store; }
            cur  = MemberKey{static_cast<uint8_t>(type), hash};
            want = n;
            store[cur].reserve(n);
        } else if (kind == "member") {
            std::string h;
            if (!(is >> h) || cur.second.empty()) { err = "stray member line: " + line; return store; }
            uint256 m; m.SetHex(h);            // display hex, like the RPC prints
            store[cur].push_back(m);
        } else {
            err = "unknown members-file key '" + kind + "'";
            return store;
        }
        (void)want;
    }
    return store;
}

} // namespace

TEST(DashReplayRun, AnchorToTipRootChain)
{
    const char* prestate_path = env_or_null("C2POOL_REPLAY_PRESTATE");
    const char* corpus_path   = env_or_null("C2POOL_REPLAY_CORPUS");
    if (!prestate_path || !corpus_path)
        GTEST_SKIP() << "set C2POOL_REPLAY_PRESTATE and C2POOL_REPLAY_CORPUS "
                        "to run the Phase-1 replay (inert in CI by design)";

    // ── anchor ────────────────────────────────────────────────────────────
    auto ps = dash::coin::replay::load_prestate_file(prestate_path);
    ASSERT_TRUE(ps.ok) << ps.error;

    FoldConfig cfg;
    cfg.enabled = true;
    DmlFoldEngine engine(cfg);
    const std::string seed_err =
        dash::coin::replay::seed_engine_from_prestate(engine, ps);
    ASSERT_TRUE(seed_err.empty()) << seed_err;

    std::cout << "[replay] anchor h=" << ps.height
              << " mns=" << engine.size()
              << " root=" << engine.compute_sml_root().GetHex()
              << " (matches the anchor block's committed cbTx root)\n";

    // ── quorum member sets (only consulted where members change state) ────
    MemberStore members;
    if (const char* mp = env_or_null("C2POOL_REPLAY_MEMBERS")) {
        std::string merr;
        members = load_members(mp, merr);
        ASSERT_TRUE(merr.empty()) << merr;
        std::cout << "[replay] member sets loaded: " << members.size()
                  << " quorums\n";
    }
    size_t member_lookups = 0, member_misses = 0;
    engine.set_members_fn(
        [&](uint8_t type, const uint256& qhash)
            -> std::optional<std::vector<uint256>> {
            ++member_lookups;
            auto it = members.find(MemberKey{type, qhash.GetHex()});
            if (it == members.end()) { ++member_misses; return std::nullopt; }
            return it->second;
        });

    const uint32_t stop_at =
        env_or_null("C2POOL_REPLAY_STOP")
            ? static_cast<uint32_t>(std::strtoul(env_or_null("C2POOL_REPLAY_STOP"),
                                                 nullptr, 10))
            : 0;

    // ── the run ───────────────────────────────────────────────────────────
    std::ifstream corpus(corpus_path);
    ASSERT_TRUE(corpus.good()) << "cannot open corpus " << corpus_path;

    const auto t0 = std::chrono::steady_clock::now();
    uint64_t folded = 0, matched = 0, bytes = 0;
    uint32_t first_h = 0, last_h = 0;
    uint32_t diverged_at = 0;
    std::string diverge_reason, diverge_computed, diverge_committed;

    std::string line;
    while (std::getline(corpus, line)) {
        if (line.empty()) continue;
        const size_t sp = line.find(' ');
        ASSERT_NE(sp, std::string::npos) << "malformed corpus line";
        const uint32_t h =
            static_cast<uint32_t>(std::strtoul(line.substr(0, sp).c_str(), nullptr, 10));
        if (stop_at && h > stop_at) break;
        if (h <= engine.height()) continue;   // pre-anchor / already folded

        const std::string hex = line.substr(sp + 1);
        auto raw = hex_to_bin(hex);
        ASSERT_FALSE(raw.empty()) << "undecodable block hex at h=" << h;
        bytes += raw.size();

        BlockType block;
        try {
            ::PackStream s(raw);
            s >> block;
            ASSERT_TRUE(s.empty()) << "trailing bytes after block at h=" << h;
        } catch (const std::exception& ex) {
            FAIL() << "unparseable block at h=" << h << ": " << ex.what();
        }

        const auto r = engine.fold_block(block, h);
        if (!r.ok) {
            diverged_at       = h;
            diverge_reason    = r.error;
            diverge_computed  = r.computed_root.GetHex();
            diverge_committed = r.committed_root.GetHex();
            break;
        }
        // Assert the equality directly rather than trusting the ok flag —
        // the byte comparison IS the proof.
        if (r.computed_root != r.committed_root) {
            diverged_at       = h;
            diverge_reason    = "computed root != committed root";
            diverge_computed  = r.computed_root.GetHex();
            diverge_committed = r.committed_root.GetHex();
            break;
        }
        if (folded == 0) first_h = h;
        ++folded; ++matched; last_h = h;

        if (h % 500 == 0) {
            const double secs = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - t0).count();
            std::cout << "[replay] h=" << h << " matched=" << matched
                      << " mns=" << engine.size()
                      << " (" << secs << "s, " << (folded / std::max(secs, 1e-9))
                      << " blk/s)\n";
        }
    }

    const double secs = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();

    std::cout << "\n=== PHASE-1 REPLAY RESULT ===\n"
              << "  anchor            h=" << ps.height << "\n"
              << "  blocks folded     " << folded << "\n"
              << "  ROOT CHECKS PASSED " << matched << "\n"
              << "  range             " << first_h << ".." << last_h << "\n"
              << "  final mn count    " << engine.size() << "\n"
              << "  final root        " << engine.compute_sml_root().GetHex() << "\n"
              << "  block bytes       " << bytes << "\n"
              << "  wall clock        " << secs << " s\n"
              << "  fold rate         " << (folded / std::max(secs, 1e-9)) << " blocks/s\n"
              << "  member lookups    " << member_lookups
              << " (misses " << member_misses << ")\n";
    if (diverged_at)
        std::cout << "  *** FIRST DIVERGENCE at h=" << diverged_at << "\n"
                  << "      computed  " << diverge_computed << "\n"
                  << "      committed " << diverge_committed << "\n"
                  << "      reason    " << diverge_reason << "\n";
    else
        std::cout << "  DIVERGENCE        none\n";
    std::cout << "=============================\n";

    EXPECT_EQ(diverged_at, 0u)
        << "replay diverged at h=" << diverged_at << ": " << diverge_reason
        << " (computed " << diverge_computed
        << " vs committed " << diverge_committed << ")";
    EXPECT_GT(matched, 0u) << "no block was folded at all";
}
