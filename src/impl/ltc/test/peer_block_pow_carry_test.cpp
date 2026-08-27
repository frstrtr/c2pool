// SPDX-License-Identifier: AGPL-3.0-or-later
// PEER-BLOCK-POW-CARRY — source-structural guard pinning that the PoW result
// travels WITH the share across threads, so peer-found blocks are reported.
//
// THE DEFECT THIS PINS (ltc.voidbind.com, 2026-08-27):
//   Share reception is two-phase: phase 1 runs share_init_verify() (the
//   expensive PoW hash) on m_verify_pool WORKER threads; attempt_verify()
//   runs later on the COMPUTE thread and calls share_init_verify() with
//   check_pow=false (the hash is already set). The block-found signal lived
//   only in thread_local scratch (g_last_init_is_block / g_last_pow_hash) set
//   on the worker thread — invisible to the compute thread. Result: a peer
//   share that met the parent block target logged "[BLOCK] Peer share meets
//   block target" in phase 1 and then fired NOTHING: no m_on_block_found, no
//   m_on_merged_block_check, no record_found_block. Every peer-found block —
//   parent chain AND merged/aux (DOGE) — was invisible to /recent_blocks,
//   /recent_merged_blocks and the dashboard. Live repro: p2p-spb's share
//   521906df2ba641bf (2026-08-27 13:57:26 CEST) carried an accepted DOGE
//   block (height 6349371, 2f3e4d8aa870c238) and met the LTC block target;
//   the node surfaced neither.
//
//   A second, latent defect rode along: attempt_verify cached the stale
//   thread_local into idx->pow_hash ("if (!g_last_pow_hash.IsNull())
//   idx->pow_hash = g_last_pow_hash;") — on any thread that had previously
//   computed a DIFFERENT share's PoW, the WRONG pow hash could be cached and
//   fed to the merged-target comparison.
//
// THE FIX SHAPE THIS ASSERTS (per lane btc/ltc/dgb/bch):
//   1. phase 1 (node.cpp) copies the freshly computed PoW onto the share:
//      "obj->m_pow_hash = g_last_pow_hash;" — same thread, same call.
//   2. share_init_verify() (share_check.hpp) resets the thread_local scratch
//      UNCONDITIONALLY at entry, so a check_pow=false call can never leave a
//      stale value observable.
//   3. attempt_verify() (share_tracker.hpp) reads the share-carried
//      m_pow_hash (with same-thread g_last_pow_hash and idx->pow_hash as
//      fallbacks) and derives is-block from "pow_hash <= block_target" — it
//      must NOT consume the cross-thread g_last_init_is_block flag.
//
// WHY A STRUCTURAL TEST: a runtime repro needs a full CHAIN_LENGTH verified
// PPLNS chain (attempt_verify's GENTX gate) plus a two-thread pipeline — the
// same situation as the #1131 owns_data guard in this directory. Asserting
// the shipped source's shape over comment-stripped text is the deterministic
// red/green this invariant admits: restore the thread_local consumption in
// attempt_verify -> RED; drop the phase-1 carry -> RED.
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef C2POOL_IMPL_DIR
#error "C2POOL_IMPL_DIR must be defined by CMake to the path of src/impl"
#endif

namespace {

std::string read_text(const std::string& path)
{
    std::ifstream in(path);
    EXPECT_TRUE(in.good()) << "cannot open " << path;
    std::stringstream ss; ss << in.rdbuf();
    return ss.str();
}

// Replace every comment with spaces, preserving byte offsets and line breaks.
// The fix's own doc comments deliberately quote the pre-fix thread_local
// consumption, so the assertions below MUST run over comment-free code.
std::string strip_comments(const std::string& s)
{
    std::string out = s;
    enum { kCode, kLine, kBlock, kStr, kChr } st = kCode;
    for (size_t i = 0; i < out.size(); ++i) {
        const char c = out[i];
        const char n = (i + 1 < out.size()) ? out[i + 1] : '\0';
        switch (st) {
        case kCode:
            if (c == '/' && n == '/') { st = kLine; out[i] = ' '; }
            else if (c == '/' && n == '*') { st = kBlock; out[i] = ' '; }
            else if (c == '"') st = kStr;
            else if (c == '\'') st = kChr;
            break;
        case kLine:
            if (c == '\n') st = kCode; else out[i] = ' ';
            break;
        case kBlock:
            if (c == '*' && n == '/') { out[i] = ' '; out[i + 1] = ' '; ++i; st = kCode; }
            else if (c != '\n') out[i] = ' ';
            break;
        case kStr:
            if (c == '\\') ++i;
            else if (c == '"') st = kCode;
            break;
        case kChr:
            if (c == '\\') ++i;
            else if (c == '\'') st = kCode;
            break;
        }
    }
    return out;
}

struct Lane {
    const char* name;
    bool has_merged_check;  // bch is standalone-parent: no merged leg
};

const std::vector<Lane> kLanes = {
    {"btc", true}, {"ltc", true}, {"dgb", true}, {"bch", false},
};

std::string lane_file(const Lane& l, const char* fname)
{
    return std::string(C2POOL_IMPL_DIR) + "/" + l.name + "/" + fname;
}

} // namespace

// (1) attempt_verify must not consume the cross-thread flag, and must derive
//     the block verdict from the share-carried PoW hash vs the block target.
TEST(PeerBlockPowCarry, TrackerDerivesBlockFromCarriedPow)
{
    for (const auto& l : kLanes) {
        SCOPED_TRACE(l.name);
        const std::string code =
            strip_comments(read_text(lane_file(l, "share_tracker.hpp")));

        // The cross-thread flag must be GONE from the tracker entirely.
        EXPECT_EQ(code.find("g_last_init_is_block"), std::string::npos)
            << l.name << ": attempt_verify consumes the thread_local block "
            "flag again — peer-found blocks will vanish (set on a verify-pool "
            "worker, read on the compute thread).";

        // Share-carried PoW is the primary source...
        EXPECT_NE(code.find("pow_hash = s->m_pow_hash"), std::string::npos)
            << l.name << ": attempt_verify no longer reads the PoW hash "
            "carried on the share (m_pow_hash).";

        // ...and the block verdict is derived from it against the block target.
        EXPECT_NE(code.find("pow_hash <= block_target"), std::string::npos)
            << l.name << ": attempt_verify no longer derives the block verdict "
            "from the carried pow vs min_header block target.";

        if (l.has_merged_check) {
            // The merged (aux/DOGE) leg must feed the RESOLVED pow, not the
            // thread_local.
            EXPECT_NE(code.find("m_on_merged_block_check(share_hash, pow_hash)"),
                      std::string::npos)
                << l.name << ": merged block check no longer receives the "
                "resolved per-share pow_hash.";
            EXPECT_EQ(code.find("m_on_merged_block_check(share_hash, g_last_pow_hash)"),
                      std::string::npos)
                << l.name << ": merged block check reads the thread_local "
                "again — peer-found merged blocks will vanish.";
        }
    }
}

// (2) phase-1 reception must copy the PoW result onto the share on the SAME
//     thread that computed it.
TEST(PeerBlockPowCarry, Phase1CarriesPowOntoShare)
{
    for (const auto& l : kLanes) {
        SCOPED_TRACE(l.name);
        const std::string code =
            strip_comments(read_text(lane_file(l, "node.cpp")));
        EXPECT_NE(code.find("obj->m_pow_hash = g_last_pow_hash"), std::string::npos)
            << l.name << ": phase-1 reception no longer copies the computed "
            "PoW onto the share — attempt_verify on the compute thread will "
            "see a null pow and drop peer-found blocks.";
    }
}

// (3) share_init_verify must reset the thread_local scratch unconditionally
//     at entry (before any validation/early-out), so a check_pow=false call
//     can never leave a STALE pow/flag from a previous share on that thread.
TEST(PeerBlockPowCarry, InitVerifyResetsScratchUnconditionally)
{
    for (const auto& l : kLanes) {
        SCOPED_TRACE(l.name);
        const std::string code =
            strip_comments(read_text(lane_file(l, "share_check.hpp")));

        const size_t fn = code.find("uint256 share_init_verify(");
        ASSERT_NE(fn, std::string::npos) << l.name;
        // First early-out of the function body: the coinbase size check.
        const size_t first_check = code.find("bad coinbase size", fn);
        ASSERT_NE(first_check, std::string::npos) << l.name;

        const size_t flag_reset = code.find("g_last_init_is_block = false", fn);
        const size_t pow_reset  = code.find("g_last_pow_hash = uint256()", fn);
        EXPECT_TRUE(flag_reset != std::string::npos && flag_reset < first_check)
            << l.name << ": share_init_verify no longer resets "
            "g_last_init_is_block at entry — stale per-thread state can leak.";
        EXPECT_TRUE(pow_reset != std::string::npos && pow_reset < first_check)
            << l.name << ": share_init_verify no longer resets "
            "g_last_pow_hash at entry — a stale pow can be cached onto the "
            "WRONG share's index and fed to the merged-target comparison.";
    }
}
