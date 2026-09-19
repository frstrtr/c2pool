// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_output_set_kat.cpp
//
// The GLOBAL input-consensus KAT, in two halves.
//
// PART A -- ChainOutputSet as a data structure: the append-only output table
// numbers exactly the way monerod's global amount-0 table does, a reorg pops
// the outputs and un-spends the key images a disconnected block added, the
// frontier cross-check refuses a stream that skipped a block, and the on-chain
// spent-key-image view answers is_spent correctly. This is the oracle the
// txpool's global double-spend and ring resolution stand on.
//
// PART B -- the txpool admission seam, driven with REAL mainnet transactions
// (xmr_input_consensus_golden.hpp). A sparse ring source built from the golden
// members feeds RelayedTxPool::set_input_consensus_sources, and we assert that:
//
//   * a real transaction whose rings resolve correctly is ACCEPTED and gains
//     AdmissionEvidence::InputConsensus (the CLSAG verified over real members);
//   * the same transaction with its key image already spent ON CHAIN is refused
//     KeyImageSpent (the global double-spend, no drop) -- this needs no forgery:
//     the transaction is already mined, so its key image IS spent;
//   * the same transaction whose rings resolve to the WRONG members is refused
//     RingSigFail (a forged/mismatched ring, a drop offence);
//   * the same transaction whose rings do NOT resolve (below anchor / no
//     daemon) is admitted WITHOUT InputConsensus and counted unresolved_ring --
//     fail-closed at the policy, good-citizen at relay;
//   * a ring member that is too young is refused RingMemberLocked.
//
// Part B is the end-to-end proof that the daemonless node now rejects, at
// admission, exactly the two classes of transaction the network would reject:
// a forged ring signature and an on-chain double-spend.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_output_set.hpp"
#include "impl/xmr/native/contracts/txpool.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/rct/xmr_rct_ops.hpp"
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"
#include "xmr_input_consensus_golden.hpp"

using namespace c2pool::xmr::native;
namespace R = c2pool::xmr::native::rct;
namespace T = c2pool::xmr::native::test;

static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 40) std::fprintf(stderr, "FAIL: %s\n", what);
    }
}
static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 40) {
            va_list ap; va_start(ap, fmt);
            std::vfprintf(stderr, fmt, ap); va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

static std::vector<std::uint8_t> from_hex(const char* hex) {
    std::vector<std::uint8_t> out;
    const std::size_t n = std::strlen(hex);
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}
static Hash hash_from_hex(const char* hex) {
    Hash k{};
    std::vector<std::uint8_t> b = from_hex(hex);
    for (std::size_t i = 0; i < 32 && i < b.size(); ++i) k[i] = b[i];
    return k;
}
static Hash hash_byte(std::uint8_t v) { Hash h{}; h[0] = v; return h; }

// ---------------------------------------------------------------------------
// PART A: ChainOutputSet numbering, reorg, frontier, spent view.
// ---------------------------------------------------------------------------
static OutputRecord rec(std::uint8_t tag, std::uint64_t height = 0,
                        std::uint64_t unlock = 0) {
    OutputRecord o;
    o.pubkey      = hash_byte(tag);
    o.commitment  = hash_byte(static_cast<std::uint8_t>(tag ^ 0xff));
    o.height      = height;
    o.unlock_time = unlock;
    return o;
}
static BlockTxEvent connected(std::uint64_t height, std::uint64_t first_idx,
                              std::vector<OutputRecord> outs,
                              std::vector<Hash> kis) {
    BlockTxEvent e;
    e.kind               = BlockTxEvent::Kind::Connected;
    e.height             = height;
    e.first_output_index = first_idx;
    e.outputs            = std::move(outs);
    e.key_images         = std::move(kis);
    return e;
}

static void test_output_set() {
    ChainOutputSet s(/*first_output_index=*/1000);
    check(s.frontier() == 1000, "empty frontier == base");
    check(s.first_output_index() == 1000, "base recorded");

    // Block A: two outputs (global idx 1000, 1001), one key image spent.
    check(s.on_block_connected(connected(5, 1000, {rec(1), rec(2)}, {hash_byte(0xa1)})),
          "connect block A");
    check(s.frontier() == 1002, "frontier advanced by 2");
    check(s.output_count() == 2, "two outputs");

    // Resolve the two outputs by their absolute global index.
    std::vector<OutputRecord> got;
    check(s.resolve(0, {1000, 1001}, got) && got.size() == 2, "resolve two");
    check(got[0].pubkey == hash_byte(1) && got[1].pubkey == hash_byte(2),
          "resolved in index order");

    // Below the base and beyond the frontier both fail closed.
    check(!s.resolve(0, {999}, got), "below base fails");
    check(!s.resolve(0, {1002}, got), "beyond frontier fails");
    // A non-RCT amount is never resolvable here.
    check(!s.resolve(5, {1000}, got), "non-zero amount fails");

    // The spent view.
    check(s.is_spent(hash_byte(0xa1)), "key image a1 spent");
    check(!s.is_spent(hash_byte(0xb2)), "unseen key image not spent");

    // Block B: one output (idx 1002), one key image.
    check(s.on_block_connected(connected(6, 1002, {rec(3)}, {hash_byte(0xb2)})),
          "connect block B");
    check(s.frontier() == 1003 && s.is_spent(hash_byte(0xb2)), "B applied");

    // A stream that skipped a block (wrong first_output_index) is refused.
    check(!s.on_block_connected(connected(7, 9999, {rec(4)}, {})),
          "frontier cross-check refuses a gap");
    check(s.frontier() == 1003, "refused block did not mutate the set");

    // Reorg: disconnect B, then A. Outputs pop, key images un-spend.
    BlockTxEvent dB; dB.kind = BlockTxEvent::Kind::Disconnected; dB.height = 6;
    check(s.on_block_disconnected(dB), "disconnect B");
    check(s.frontier() == 1002 && !s.is_spent(hash_byte(0xb2)), "B rolled back");
    check(s.is_spent(hash_byte(0xa1)), "A's key image still spent after B rollback");

    BlockTxEvent dA; dA.kind = BlockTxEvent::Kind::Disconnected; dA.height = 5;
    check(s.on_block_disconnected(dA), "disconnect A");
    check(s.frontier() == 1000 && !s.is_spent(hash_byte(0xa1)), "A rolled back");
    check(s.output_count() == 0, "empty after full rollback");

    // A disconnect that does not match the top frame's height is refused.
    check(!s.on_block_disconnected(dA), "disconnect on empty refused");

    // A block that carries key images but no outputs still advances the spent
    // set without disturbing the numbering (a producer that did not capture).
    check(s.on_block_connected(connected(5, 0, {}, {hash_byte(0xc3)})),
          "connect key-image-only block");
    check(s.is_spent(hash_byte(0xc3)) && s.frontier() == 1000, "spent-only advance");
}

// ---------------------------------------------------------------------------
// PART B: the txpool admission seam over real mainnet transactions.
// ---------------------------------------------------------------------------

// A sparse ring source: absolute global index -> resolved (dest, mask). Also
// the on-chain spent-key-image view. Both surfaces, as ChainOutputSet is.
class FakeRingSource final : public IRingMemberSource, public ISpentKeyImageView {
public:
    std::map<std::uint64_t, OutputRecord> outs;
    std::vector<Hash>                     spent;
    bool                                  fail_all = false;   // simulate below-anchor

    bool resolve(std::uint64_t amount,
                 const std::vector<std::uint64_t>& abs,
                 std::vector<OutputRecord>& out) const override {
        if (fail_all || amount != 0) return false;
        out.clear();
        for (std::uint64_t off : abs) {
            auto it = outs.find(off);
            if (it == outs.end()) return false;
            out.push_back(it->second);
        }
        return true;
    }
    bool is_spent(const Hash& ki) const override {
        for (const Hash& s : spent) if (s == ki) return true;
        return false;
    }
};

// De-relativise a decoded input's key offsets (relative -> absolute).
static std::vector<std::uint64_t> to_abs(const std::vector<std::uint64_t>& rel) {
    std::vector<std::uint64_t> abs;
    abs.reserve(rel.size());
    std::uint64_t acc = 0;
    for (std::uint64_t r : rel) { acc += r; abs.push_back(acc); }
    return abs;
}

// Build a ring source that resolves one golden tx's rings to its real members.
// `rotate_members` scrambles the members within each input (still 16 valid
// points, but the wrong ones) to force a ring-signature mismatch.
static FakeRingSource source_for(const T::GoldenTx& gtx, const DecodedTx& d,
                                 bool rotate_members) {
    FakeRingSource src;
    for (std::size_t i = 0; i < d.key_offsets.size() && i < gtx.inputs.size(); ++i) {
        const std::vector<std::uint64_t> abs = to_abs(d.key_offsets[i]);
        const T::GoldenInput& gi = gtx.inputs[i];
        for (std::size_t j = 0; j < abs.size() && j < gi.members.size(); ++j) {
            const std::size_t src_j =
                rotate_members ? (j + 1) % gi.members.size() : j;
            OutputRecord o;
            o.pubkey      = hash_from_hex(gi.members[src_j].dest);
            o.commitment  = hash_from_hex(gi.members[src_j].mask);
            o.height      = 0;    // very old -> always spendable-age-clear
            o.unlock_time = 0;
            src.outs[abs[j]] = o;
        }
    }
    return src;
}

static PeerRef peer() { PeerRef p; p.peer_id = 7; p.addr = "test:0"; return p; }

// Set the pool synced and its tip high enough that height-0 members clear the
// spendable-age rule.
static void arm(RelayedTxPool& pool) {
    pool.set_synced(true);
    BlockTxEvent tip;
    tip.kind   = BlockTxEvent::Kind::Connected;
    tip.height = 4000000;   // above any golden member's height (all 0 here)
    pool.on_block_connected(tip);
}

static bool has(AdmissionEvidence e, AdmissionEvidence bit) {
    return (e & bit) == bit;
}

// Find the first golden tx that decodes cleanly, for the admission scenarios.
static const T::GoldenTx* first_decodable(DecodedTx& d) {
    for (const T::GoldenTx& tx : T::input_consensus_golden()) {
        std::vector<std::uint8_t> blob = from_hex(tx.full_hex);
        if (decode_relayed_tx(blob.data(), blob.size(), d) == TxDecodeStatus::Ok &&
            !d.clsags.empty())
            return &tx;
    }
    return nullptr;
}

static void test_admission() {
    using Reason = TxRelayVerdict::Reason;

    DecodedTx d;
    const T::GoldenTx* gtx = first_decodable(d);
    checkf(gtx != nullptr, "no decodable golden tx for admission tests");
    if (!gtx) return;
    std::vector<std::uint8_t> blob = from_hex(gtx->full_hex);

    // (1) Correct rings -> ACCEPTED with InputConsensus evidence.
    {
        RelayedTxPool pool;
        FakeRingSource src = source_for(*gtx, d, /*rotate=*/false);
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        auto v = pool.on_relayed(peer(), {blob}, true);
        checkf(v.size() == 1 && v[0].reason == Reason::Accepted,
               "correct rings: expected Accepted, got %s",
               v.empty() ? "none" : to_string(v[0].reason));
        if (!v.empty())
            check(has(v[0].evidence, AdmissionEvidence::InputConsensus),
                  "correct rings: InputConsensus evidence granted");
    }

    // (2) Key image already spent on chain -> KeyImageSpent (no drop). The tx is
    //     already mined, so its key image is genuinely spent -- no forgery.
    {
        RelayedTxPool pool;
        FakeRingSource src = source_for(*gtx, d, /*rotate=*/false);
        for (const Hash& ki : d.rct.key_images) src.spent.push_back(ki);
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        auto v = pool.on_relayed(peer(), {blob}, true);
        checkf(v.size() == 1 && v[0].reason == Reason::KeyImageSpent,
               "spent key image: expected KeyImageSpent, got %s",
               v.empty() ? "none" : to_string(v[0].reason));
        if (!v.empty()) check(!v[0].drop_offense, "KeyImageSpent is not a drop");
        check(pool.stats().rejected_key_image_spent == 1, "spent counter incremented");
    }

    // (3) Wrong ring members -> RingSigFail (drop). A forged/mismatched ring.
    {
        RelayedTxPool pool;
        FakeRingSource src = source_for(*gtx, d, /*rotate=*/true);
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        auto v = pool.on_relayed(peer(), {blob}, true);
        checkf(v.size() == 1 && v[0].reason == Reason::RingSigFail,
               "wrong members: expected RingSigFail, got %s",
               v.empty() ? "none" : to_string(v[0].reason));
        if (!v.empty()) check(v[0].drop_offense, "RingSigFail IS a drop offence");
        check(pool.stats().rejected_ring_sig == 1, "ring-sig counter incremented");
    }

    // (4) Unresolvable rings (below anchor / no daemon) -> admitted WITHOUT
    //     InputConsensus, counted unresolved_ring. Good-citizen, fail-closed.
    {
        RelayedTxPool pool;
        FakeRingSource src;
        src.fail_all = true;
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        auto v = pool.on_relayed(peer(), {blob}, true);
        checkf(v.size() == 1 && v[0].reason == Reason::Accepted,
               "unresolved rings: expected Accepted (non-input only), got %s",
               v.empty() ? "none" : to_string(v[0].reason));
        if (!v.empty())
            check(!has(v[0].evidence, AdmissionEvidence::InputConsensus),
                  "unresolved rings: InputConsensus NOT granted");
        check(pool.stats().unresolved_ring == 1, "unresolved counter incremented");
    }

    // (5) A ring member too young -> RingMemberLocked (no drop).
    {
        RelayedTxPool pool;
        FakeRingSource src = source_for(*gtx, d, /*rotate=*/false);
        // Make one member freshly mined relative to the tip we armed with.
        if (!src.outs.empty()) src.outs.begin()->second.height = 4000000;
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        auto v = pool.on_relayed(peer(), {blob}, true);
        checkf(v.size() == 1 && v[0].reason == Reason::RingMemberLocked,
               "young member: expected RingMemberLocked, got %s",
               v.empty() ? "none" : to_string(v[0].reason));
        if (!v.empty()) check(!v[0].drop_offense, "RingMemberLocked is not a drop");
    }

    // (6) With NO sources wired the leg is dormant: the same tx is admitted on
    //     non-input evidence only (the pre-input-consensus behaviour).
    {
        RelayedTxPool pool;
        arm(pool);
        auto v = pool.on_relayed(peer(), {blob}, true);
        checkf(v.size() == 1 && v[0].reason == Reason::Accepted,
               "no sources: expected Accepted, got %s",
               v.empty() ? "none" : to_string(v[0].reason));
        if (!v.empty())
            check(!has(v[0].evidence, AdmissionEvidence::InputConsensus),
                  "no sources: InputConsensus not granted (dormant leg)");
    }
}

int main() {
    test_output_set();
    test_admission();

    if (g_fail == 0) {
        std::fprintf(stderr, "output-set + admission KAT: ALL %d checks passed\n",
                     g_checks);
        return 0;
    }
    std::fprintf(stderr, "output-set + admission KAT: %d/%d checks FAILED\n",
                 g_fail, g_checks);
    return 1;
}
