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

#include "c2pool/v37/record_log.hpp"   // MMR-root parity cross-check

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
// PART A2: the AUTHENTICATED (MRR-Merkle/MMR) output + spent logs.
//   * coinbase commitment synthesis (zeroCommit) + global ordering,
//   * root parity against a c2pool::v37 RecordLog on the SET's OWN leaves,
//   * membership proof verifies through the shipped lane verifier, flip fails,
//   * reorg restores both roots BIT-EXACT,
//   * serialize/deserialize round-trip with root re-derivation.
// ---------------------------------------------------------------------------
static BlockTxEvent cb_connected(std::uint64_t height, std::uint64_t first_idx,
                                 std::vector<std::pair<std::uint64_t, Hash>> cb,
                                 std::vector<OutputRecord> outs,
                                 std::vector<Hash> kis) {
    BlockTxEvent e;
    e.kind                    = BlockTxEvent::Kind::Connected;
    e.height                  = height;
    e.first_output_index      = first_idx;
    e.coinbase_amount_pubkeys = std::move(cb);
    e.coinbase_unlock_time    = height + 60;
    e.outputs                 = std::move(outs);
    e.key_images              = std::move(kis);
    return e;
}

static void test_output_mmr() {
    ChainOutputSet s(/*first_output_index=*/0);

    // Block 1: a v2 coinbase paying 5 (idx 0), then one non-coinbase output
    // (idx 1). The coinbase commitment must be zeroCommit(5); ordering coinbase
    // FIRST. One key image spent.
    const Hash cb_pk = hash_byte(0x11);
    check(s.on_block_connected(
              cb_connected(1, 0, {{5, cb_pk}}, {rec(2, 1)}, {hash_byte(0xd1)})),
          "connect block 1 (coinbase + 1 out)");
    check(s.output_count() == 2 && s.frontier() == 2, "coinbase-first numbering");

    std::vector<OutputRecord> got;
    check(s.resolve(0, {0}, got) && got.size() == 1, "resolve coinbase output 0");
    check(got[0].pubkey == cb_pk, "coinbase output pubkey");
    check(got[0].commitment == R::zero_commit(5), "coinbase commitment == zeroCommit(5)");
    check(R::zero_commit(0) == R::generator_G(), "zeroCommit(0) == G");

    // Block 2: coinbase paying 5 (idx 2), no other outputs, one key image.
    check(s.on_block_connected(cb_connected(2, 2, {{5, hash_byte(0x22)}}, {}, {hash_byte(0xd2)})),
          "connect block 2");
    check(s.frontier() == 3, "frontier after block 2");

    const auto root_out_2 = s.output_root();
    const auto root_ki_2  = s.spent_root();
    check(s.output_leaf_count() == 2 && s.spent_leaf_count() == 2, "two leaves each");

    // Root parity: append the SET's OWN leaf hashes into a RecordLog and the
    // bagged roots must be byte-identical -- ONE MMR (the shipped lane's).
    {
        c2pool::v37n::recordlog::RecordLog rl_out, rl_ki;
        for (std::uint64_t i = 0; i < s.output_leaf_count(); ++i) {
            ChainOutputSet::bytes32 leaf{}; ::v37::Lane::MmrProof pr;
            check(s.prove_output_leaf(i, leaf, pr), "prove output leaf");
            check(ChainOutputSet::verify(s.output_root(), leaf, pr), "output proof verifies");
            rl_out.append_leaf(leaf);
        }
        for (std::uint64_t i = 0; i < s.spent_leaf_count(); ++i) {
            ChainOutputSet::bytes32 leaf{}; ::v37::Lane::MmrProof pr;
            check(s.prove_spent_leaf(i, leaf, pr), "prove spent leaf");
            check(ChainOutputSet::verify(s.spent_root(), leaf, pr), "spent proof verifies");
            rl_ki.append_leaf(leaf);
        }
        check(rl_out.root() == root_out_2, "output root == RecordLog root (same leaves)");
        check(rl_ki.root() == root_ki_2, "spent root == RecordLog root (same leaves)");
    }

    // A flipped leaf byte breaks the proof.
    {
        ChainOutputSet::bytes32 leaf{}; ::v37::Lane::MmrProof pr;
        check(s.prove_output_leaf(0, leaf, pr), "prove leaf 0");
        leaf[0] ^= 0x01;
        check(!ChainOutputSet::verify(s.output_root(), leaf, pr), "flipped leaf fails");
    }

    // Serialize / deserialize: roots, frontier and spent view survive, and the
    // peaks are re-derived from the leaves on load.
    {
        const std::string blob = s.serialize();
        auto back = ChainOutputSet::deserialize(blob);
        check(back != nullptr, "deserialize round-trips");
        if (back) {
            check(back->output_root() == root_out_2, "restored output root");
            check(back->spent_root()  == root_ki_2,  "restored spent root");
            check(back->frontier() == 3, "restored frontier");
            check(back->is_spent(hash_byte(0xd1)) && back->is_spent(hash_byte(0xd2)),
                  "restored spent set");
            std::vector<OutputRecord> g2;
            check(back->resolve(0, {0}, g2) && g2[0].commitment == R::zero_commit(5),
                  "restored coinbase commitment");
        }
        check(ChainOutputSet::deserialize(blob + "x") == nullptr, "trailing garbage rejected");
    }

    // Reorg: disconnect block 2, both roots must be BIT-EXACT what they were
    // after block 1 (the lane's reorg rule, applied to the output set).
    ChainOutputSet a(0);
    a.on_block_connected(cb_connected(1, 0, {{5, cb_pk}}, {rec(2, 1)}, {hash_byte(0xd1)}));
    const auto root_out_1 = a.output_root();
    const auto root_ki_1  = a.spent_root();
    a.on_block_connected(cb_connected(2, 2, {{5, hash_byte(0x22)}}, {}, {hash_byte(0xd2)}));
    BlockTxEvent d2; d2.kind = BlockTxEvent::Kind::Disconnected; d2.height = 2;
    check(a.on_block_disconnected(d2), "disconnect block 2");
    check(a.output_root() == root_out_1, "output root restored bit-exact after reorg");
    check(a.spent_root()  == root_ki_1,  "spent root restored bit-exact after reorg");
    check(a.frontier() == 2 && !a.is_spent(hash_byte(0xd2)), "reorg rolled back state");

    // The set digest is stable and non-zero once populated.
    check(!(s.set_digest() == ChainOutputSet::bytes32{}), "set digest non-zero");
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

// ---------------------------------------------------------------------------
// PART C: the SELECT-POLICY seam -- a resolvable ring is selectable (good
// citizen), an unresolved ring is NOT selectable by default (the SPV fix), and
// an explicit Include policy restores the pre-input-consensus behaviour.
// ---------------------------------------------------------------------------
static void test_select_policy() {
    DecodedTx d;
    const T::GoldenTx* gtx = first_decodable(d);
    checkf(gtx != nullptr, "no decodable golden tx for select-policy tests");
    if (!gtx) return;
    std::vector<std::uint8_t> blob = from_hex(gtx->full_hex);

    // (A) A RESOLVABLE ring (InputConsensus granted at admission) is SELECTABLE.
    {
        RelayedTxPool pool;
        FakeRingSource src = source_for(*gtx, d, /*rotate=*/false);
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        pool.on_relayed(peer(), {blob}, true);
        auto sel = pool.selectable_backlog();
        checkf(sel.size() == 1, "resolvable tx is selectable (good citizen), got %zu",
               sel.size());
        check(pool.stats().excluded_unresolved == 0, "nothing excluded when ring resolves");
    }

    // (B) An UNRESOLVED ring is NOT selectable under the default Exclude, and the
    //     exclusion is counted. THIS is the load-bearing close of the SPV
    //     critique: a tx whose ring we cannot verify is never mined.
    {
        RelayedTxPool pool;
        FakeRingSource src; src.fail_all = true;
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        pool.on_relayed(peer(), {blob}, true);      // admitted, ring_unresolved
        auto sel = pool.selectable_backlog();        // default policy = Exclude
        checkf(sel.empty(), "unresolved tx NOT selectable by default, got %zu", sel.size());
        check(pool.stats().excluded_unresolved >= 1, "excluded_unresolved counted");
    }

    // (C) Under an explicit Include policy the same unresolved tx IS selectable
    //     (mainnet pre-O-backfill behaviour -- operator ruling R2).
    {
        RelayedTxPool pool;
        FakeRingSource src; src.fail_all = true;
        pool.set_input_consensus_sources(&src, &src);
        arm(pool);
        pool.on_relayed(peer(), {blob}, true);
        TxpoolSelectPolicy incl;
        incl.required         = AdmissionEvidence::Structural;
        incl.min_peers        = 1;
        incl.unresolved_rings = UnresolvedRingPolicy::Include;
        auto sel = pool.selectable_backlog(incl);
        checkf(sel.size() == 1, "Include policy admits unresolved tx, got %zu", sel.size());
    }
}

// ---------------------------------------------------------------------------
// PART D: format-2 O-BACKFILL -- seed the historical set from an anchor-committed
// snapshot so a ring reaching BELOW the anchor's numbering base RESOLVES, its
// membership proves against the committed root, and a below-base double-spend is
// caught. Composes with PART B: PART B proves that ONCE an offset resolves to the
// authentic member the CLSAG verifies (Accepted+InputConsensus) and a WRONG
// member is RingSigFail; PART D proves the seed is what makes a below-base offset
// resolve to that authentic member in the first place, and does so only when the
// snapshot re-derives to the roots the anchor committed (fail-closed otherwise).
// ---------------------------------------------------------------------------
static BlockTxEvent blk(std::uint64_t height, std::uint64_t first_idx, const Hash& id,
                        std::vector<std::pair<std::uint64_t, Hash>> cb,
                        std::vector<OutputRecord> outs, std::vector<Hash> kis) {
    BlockTxEvent e;
    e.kind                    = BlockTxEvent::Kind::Connected;
    e.height                  = height;
    e.first_output_index      = first_idx;
    e.block_id                = id;
    e.coinbase_amount_pubkeys = std::move(cb);
    e.coinbase_unlock_time    = height + 60;
    e.outputs                 = std::move(outs);
    e.key_images              = std::move(kis);
    return e;
}

static AnchorBundle bundle_for(const ChainOutputSet& set, std::uint64_t height,
                               const Hash& tip_id) {
    AnchorBundle b;
    b.network                = "regtest";
    b.height                 = height;
    b.id                     = tip_id;
    b.rct_output_count       = set.frontier();
    b.output_set_base_height = 1;
    b.output_set_leaves      = set.output_leaf_count();
    b.output_set_root        = set.output_root();
    b.spent_set_leaves       = set.spent_leaf_count();
    b.spent_set_root         = set.spent_root();
    return b;
}

static void test_format2_seed() {
    // Build a from-genesis set: blocks 1..H, each a v2 coinbase; block 3 also
    // carries one non-coinbase output (the future "below-base ring member") and
    // spends one key image (the future "below-base double-spend"). All of this is
    // BELOW the anchor at height H.
    const std::uint64_t H = 8;
    const Hash member_pk = hash_byte(0x51);
    const Hash spent_ki_below = hash_byte(0xE1);
    OutputRecord member = rec(0x51, /*height=*/3);   // pubkey 0x51, commitment 0x51^0xff
    std::uint64_t member_index = 0;
    Hash tip_id{};

    ChainOutputSet built(0);
    for (std::uint64_t h = 1; h <= H; ++h) {
        const Hash bid = hash_byte(static_cast<std::uint8_t>(0x90 + h));
        const std::uint64_t before = built.frontier();
        std::vector<std::pair<std::uint64_t, Hash>> cb = {{7, hash_byte(static_cast<std::uint8_t>(0x40 + h))}};
        std::vector<OutputRecord> outs;
        std::vector<Hash> kis;
        if (h == 3) { outs.push_back(member); kis.push_back(spent_ki_below);
                      member_index = before + 1; }   // coinbase is `before`, member next
        check(built.on_block_connected(blk(h, before, bid, cb, outs, kis)),
              "PART D: connect pre-anchor block");
        tip_id = bid;
    }
    const std::uint64_t F = built.frontier();          // == rct_output_count
    check(member_index != 0 && member_index < F, "PART D: member is a below-anchor index");

    const std::string snapshot = built.serialize();
    const AnchorBundle bnd = bundle_for(built, H, tip_id);
    check(bnd.has_output_set(), "PART D: the anchor commits a set");

    // (0) WITHOUT the seed (format-1 behaviour): base == rct_output_count, empty
    //     set -> a below-base offset is UNRESOLVED and the spent view is blind.
    {
        ChainOutputSet node(0);
        check(node.reset_base(F), "PART D: reset base to rct_output_count");
        std::vector<OutputRecord> got;
        check(!node.resolve(0, {member_index}, got), "PART D: below-base UNRESOLVED before seed");
        check(!node.is_spent(spent_ki_below), "PART D: below-base key image invisible before seed");
    }

    // (1) WITH the seed: the below-base ring member RESOLVES to the AUTHENTIC
    //     record, its membership PROVES against the committed root, and the
    //     below-base key image is SPENT.
    {
        ChainOutputSet node(0);
        check(node.reset_base(F), "PART D: reset base before seed");
        std::string why;
        checkf(node.seed_from_snapshot(snapshot, bnd, why),
               "PART D: seed_from_snapshot accepts a matching snapshot: %s", why.c_str());
        check(node.first_output_index() == 0 && node.frontier() == F,
              "PART D: seeded base is 0 and frontier == rct_output_count");

        std::vector<OutputRecord> got;
        check(node.resolve(0, {member_index}, got) && got.size() == 1,
              "PART D (a): below-base ring member RESOLVES after seed");
        check(got.size() == 1 && got[0].pubkey == member_pk
                  && got[0].commitment == member.commitment,
              "PART D (a): resolves to the AUTHENTIC member (so a wrong member is RingSigFail, PART B)");
        check(node.verify_member(member_index),
              "PART D (a): membership proof verifies against the committed output root");
        check(!node.verify_member(F + 100), "PART D: an index beyond the frontier does not prove");

        check(node.is_spent(spent_ki_below),
              "PART D (c): below-base key image is SPENT from the seeded set (double-spend caught)");
        check(!node.is_spent(hash_byte(0xEE)), "PART D: an unseen key image is not spent");
    }

    // (2) FAIL-CLOSED. The anchor's committed roots -- not the blob -- are the
    //     trust, so every mismatch is refused and leaves the set empty.
    auto rejects = [&](const AnchorBundle& b, const std::string& blob, const char* what) {
        ChainOutputSet node(0);
        (void)node.reset_base(b.rct_output_count);
        std::string why;
        const bool ok = node.seed_from_snapshot(blob, b, why);
        checkf(!ok, "PART D fail-closed: %s is rejected", what);
        checkf(!ok && !why.empty(), "PART D fail-closed: %s says why", what);
        std::vector<OutputRecord> got;
        check(!node.resolve(0, {member_index}, got),
              "PART D fail-closed: a rejected seed leaves the set unresolved");
    };
    { AnchorBundle b = bnd; b.output_set_root[0] ^= 0x01; rejects(b, snapshot, "a flipped output root"); }
    { AnchorBundle b = bnd; b.spent_set_root[0] ^= 0x01;  rejects(b, snapshot, "a flipped spent root"); }
    { AnchorBundle b = bnd; b.rct_output_count += 1;      rejects(b, snapshot, "a wrong rct_output_count"); }
    { AnchorBundle b = bnd; b.output_set_leaves += 1;     rejects(b, snapshot, "a wrong output leaf count"); }
    { AnchorBundle b = bnd; b.id = hash_byte(0x01);       rejects(b, snapshot, "a wrong tip id"); }
    { AnchorBundle b = bnd; b.height += 1;                rejects(b, snapshot, "a wrong tip height"); }
    rejects(bnd, snapshot + "x", "a truncated/padded snapshot");
    // A format-1 bundle (no committed set) cannot be seeded against.
    { AnchorBundle b; b.height = H; b.id = tip_id; check(!b.has_output_set(), "PART D: format-1 has no set");
      ChainOutputSet node(0); std::string why;
      check(!node.seed_from_snapshot(snapshot, b, why), "PART D: refuse to seed against a format-1 anchor"); }

    // (3) Seeding is boot-only: a non-empty set refuses a seed.
    {
        ChainOutputSet node(0);
        node.on_block_connected(blk(1, 0, hash_byte(0x91), {{7, hash_byte(0x41)}}, {}, {}));
        std::string why;
        check(!node.seed_from_snapshot(snapshot, bnd, why), "PART D: a non-empty set refuses a seed");
    }
}

// ---------------------------------------------------------------------------
// PART E: the cross-language pin. Builds a fixed synthetic two-block set (no
// coinbase, so every commitment is explicit and no ed25519 is needed on either
// side) and asserts its roots equal the values the Python generator's --selftest
// computes with its ported MMR + leaf encoding. A drift between the two
// implementations of the leaf/MMR discipline is a RED test here.
// ---------------------------------------------------------------------------
static OutputRecord rec_full(std::uint8_t pk, std::uint8_t cm,
                             std::uint64_t unlock, std::uint64_t height) {
    OutputRecord o;
    o.pubkey      = hash_byte(pk);
    o.commitment  = hash_byte(cm);
    o.unlock_time = unlock;
    o.height      = height;
    return o;
}
static std::string hex32(const ChainOutputSet::bytes32& h) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(64);
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}
// The pinned roots, equal to tools/xmr-anchor-gen/xmr_anchor_gen.py --selftest.
static const char* PIN_OUTPUT_ROOT = "4f8d4835a2788d17bdb6c06048a9fa12395f9b0945993553703db8a4e929d293";
static const char* PIN_SPENT_ROOT  = "0fd7d87a83a87e7ccae7bb5bc8a6418f4dbf3f187c2bf29d3f1156426ce2af33";
static void test_selftest_pin() {
    ChainOutputSet s(0);
    s.on_block_connected(blk(1, 0, hash_byte(0x91), {},
        {rec_full(0x33, 0x44, 0, 1), rec_full(0x35, 0x46, 5, 1)}, {hash_byte(0xAA)}));
    s.on_block_connected(blk(2, 2, hash_byte(0x92), {},
        {rec_full(0x55, 0x66, 62, 2)}, {hash_byte(0xBB), hash_byte(0x0C)}));
    const std::string out_root = hex32(s.output_root());
    const std::string ki_root  = hex32(s.spent_root());
    std::fprintf(stderr, "PART E output_root %s\n", out_root.c_str());
    std::fprintf(stderr, "PART E spent_root  %s\n", ki_root.c_str());
    checkf(out_root == PIN_OUTPUT_ROOT,
           "PART E: output root pinned to the Python generator (%s)", out_root.c_str());
    checkf(ki_root == PIN_SPENT_ROOT,
           "PART E: spent root pinned to the Python generator (%s)", ki_root.c_str());
}

int main() {
    test_output_set();
    test_output_mmr();
    test_format2_seed();
    test_selftest_pin();
    test_admission();
    test_select_policy();

    if (g_fail == 0) {
        std::fprintf(stderr, "output-set + admission KAT: ALL %d checks passed\n",
                     g_checks);
        return 0;
    }
    std::fprintf(stderr, "output-set + admission KAT: %d/%d checks FAILED\n",
                 g_fail, g_checks);
    return 1;
}
