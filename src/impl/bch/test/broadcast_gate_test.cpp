// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// F3 tx-completeness broadcast gate + F2 mark-only-what-was-sent — BCH KATs.
//
// Both primitives are the ones send_shares()/broadcast_share() in
// src/impl/bch/node.cpp actually call, so these checks pin the shipped policy:
//
//   partition_backable()  — F3. send_shares must NOT write a share whose
//     referenced new-tx BYTES we do not hold: canonical p2pool disconnects on
//     "referenced unknown transaction" (p2p.py), which isolates us from the
//     sharechain and orphans our shares. Pre-fix, send_shares looked the tx up
//     and simply omitted it when absent (`if (it != m_known_txs.end())` with no
//     else), sending the share anyway.
//
//   broadcast_and_mark()  — F2. broadcast_share may add a hash to
//     m_shared_share_hashes only AFTER a peer accepted it. Pre-fix it marked the
//     whole chain-walk up front, so a batch that send_shares then abandoned (F3
//     skip, tracker try_to_lock miss, zero peers) was withheld FOREVER: the next
//     walk breaks on the first marked hash and nothing ever re-pushes it.
//
// Red-able: the walk-stranding block reproduces the pre-fix marking order beside
// the shipped one and asserts they differ; restoring mark-before-send reddens
// the shipped half. The gate block asserts a skip count of 1; deleting the gate
// reddens it.
//
// HARNESS: the bch test tree is plain int main()/assert (no GTest), so this TU
// exposes run_share_broadcast_gate_checks() and rides the already-allowlisted
// bch_embedded_block_broadcast_test executable — no build.yml --target allowlist
// change, no NOT_BUILT sentinel risk.
// Consensus surface: NONE. These primitives decide only WHETHER a share is put
// on the wire; share bytes, minting and payout are untouched.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <map>
#include <set>
#include <vector>

#include <core/uint256.hpp>
#include <impl/bch/known_txs_retention.hpp>

namespace {

int g_failures = 0;

void check(bool ok, const char* what)
{
    if (!ok) {
        ++g_failures;
        std::cerr << "  FAIL: " << what << "\n";
    }
}

uint256 h(const char* hex) { uint256 v; v.SetHex(hex); return v; }

// Stand-in for a share on the broadcast path: its hash plus the new-tx hashes
// it references. The gate is agnostic to everything else in a share.
struct FakeShare {
    uint256 hash;
    std::vector<uint256> new_txs;
};

std::vector<uint256> refs_of(FakeShare& s) { return s.new_txs; }

// A peer that accepts exactly the hashes send_shares would have written to it.
struct FakePeer { std::set<uint256> accepts; };

// The tip-first walk broadcast_share performs, verbatim in its essentials: it
// BREAKS on the first hash already in the de-dup set.
std::vector<uint256> walk(const std::vector<uint256>& chain_tip_first,
                          const std::set<uint256>& marked)
{
    std::vector<uint256> to_send;
    for (const auto& hash : chain_tip_first) {
        if (marked.count(hash))
            break;
        to_send.push_back(hash);
    }
    return to_send;
}

// The tip-first walk readvertise_best_share() performs (#885), verbatim in its
// essentials: it does NOT consult the de-dup set, so a head share already in
// m_shared_share_hashes is still re-pushed. It skips only peer-REJECTED hashes.
std::vector<uint256> readvertise_walk(const std::vector<uint256>& chain_tip_first,
                                      const std::set<uint256>& rejected)
{
    std::vector<uint256> to_send;
    for (const auto& hash : chain_tip_first) {
        if (rejected.count(hash))
            continue;   // never re-broadcast a peer-rejected share
        to_send.push_back(hash);
    }
    return to_send;
}

} // namespace

int run_share_broadcast_gate_checks()
{
    g_failures = 0;

    const uint256 S1 = h("11"), S2 = h("22"), S3 = h("33");
    const uint256 TA = h("aa"), TB = h("bb"), TC = h("cc");

    // -- F3: an unbacked share is removed; backable ones survive, in order ----
    {
        const std::set<uint256> held{TA, TB};   // TC bytes NOT held
        std::vector<FakeShare> batch{{S1, {TA}}, {S2, {TC}}, {S3, {TA, TB}}};

        const std::size_t skipped = bch::partition_backable(batch, held, refs_of);
        check(skipped == 1u, "F3 gate skips exactly the unbacked share");
        check(batch.size() == 2u, "F3 gate keeps the two backable shares");
        if (batch.size() == 2u) {
            check(batch[0].hash == S1, "F3 gate preserves batch order (S1)");
            check(batch[1].hash == S3, "F3 gate preserves batch order (S3)");
        }
    }

    // -- F3: a share referencing no new txs is trivially backable -------------
    {
        const std::set<uint256> held;   // hold nothing at all
        std::vector<FakeShare> batch{{S1, {}}};
        check(bch::partition_backable(batch, held, refs_of) == 0u,
              "F3 gate never withholds a share with no tx refs");
        check(batch.size() == 1u, "F3 gate keeps the no-refs share");
    }

    // -- F3: every share unbacked -> empty batch, so nothing is reported sent -
    {
        const std::set<uint256> held;
        std::vector<FakeShare> batch{{S1, {TA}}, {S2, {TB}}};
        check(bch::partition_backable(batch, held, refs_of) == 2u,
              "F3 gate skips a wholly-unbacked batch");
        check(batch.empty(), "F3 gate empties a wholly-unbacked batch");
    }

    // -- F2: a batch no peer accepted leaves the de-dup set untouched ---------
    {
        std::set<uint256> marked;
        std::map<uint64_t, FakePeer> peers{{1, {}}, {2, {}}};
        const std::size_t n = bch::broadcast_and_mark(
            marked, peers, std::vector<uint256>{S1, S2},
            [](FakePeer&) { return std::vector<uint256>{}; });
        check(n == 0u, "F2 reports nothing sent when no peer accepted");
        check(marked.empty(), "F2 marks nothing when no peer accepted");
    }

    // -- F2: zero peers -> nothing sent, therefore nothing marked -------------
    {
        std::set<uint256> marked;
        std::map<uint64_t, FakePeer> peers;
        check(bch::broadcast_and_mark(marked, peers, std::vector<uint256>{S1, S2},
                                      [](FakePeer&) {
                                          return std::vector<uint256>{};
                                      }) == 0u,
              "F2 reports nothing sent with zero peers");
        check(marked.empty(), "F2 marks nothing with zero peers");
    }

    // -- F2: exactly the union of what peers accepted is marked, no more ------
    {
        std::set<uint256> marked;
        std::map<uint64_t, FakePeer> peers{{1, {{S1}}}, {2, {{S1, S3}}}};
        const std::size_t n = bch::broadcast_and_mark(
            marked, peers, std::vector<uint256>{S1, S2, S3}, [](FakePeer& p) {
                return std::vector<uint256>(p.accepts.begin(), p.accepts.end());
            });
        check(n == 2u, "F2 counts the union of accepted hashes");
        check(marked.count(S1) == 1u, "F2 marks an accepted hash");
        check(marked.count(S3) == 1u, "F2 marks an accepted hash");
        check(marked.count(S2) == 0u, "F2 leaves a withheld share un-marked");
    }

    // -- The regression: mark-before-send strands the walk permanently --------
    // Round 1: TB is missing so S2 is withheld and no peer accepts anything.
    {
        const std::vector<uint256> chain{S2, S1};   // S2 is the tip
        std::map<uint64_t, FakePeer> one_peer{{1, {}}};

        // pre-fix ordering: mark the walk, THEN discover nothing was sent
        {
            std::set<uint256> marked;
            auto to_send = walk(chain, marked);
            check(to_send.size() == 2u, "pre-fix walk yields the full batch once");
            for (const auto& hash : to_send) marked.insert(hash);   // the bug
            bch::broadcast_and_mark(marked, one_peer, to_send,
                                    [](FakePeer&) { return std::vector<uint256>{}; });
            // Round 2, TB has since arrived — but the tip is marked, so nothing
            // is ever re-pushed. Silent, permanent share loss, no retry path.
            check(walk(chain, marked).empty(),
                  "pre-fix ordering strands the walk (documents the bug)");
        }

        // shipped ordering: mark only what a peer accepted
        {
            std::set<uint256> marked;
            auto offered = walk(chain, marked);
            check(offered.size() == 2u, "shipped walk yields the batch");
            bch::broadcast_and_mark(marked, one_peer, offered,
                                    [](FakePeer&) { return std::vector<uint256>{}; });
            check(marked.empty(), "shipped ordering marks nothing on an abandoned send");

            auto retry = walk(chain, marked);
            check(retry.size() == 2u, "shipped ordering re-offers the batch");
            if (!retry.empty())
                check(retry[0] == S2, "shipped retry still starts at the tip");

            // ...and once a peer accepts them they are marked exactly once.
            std::map<uint64_t, FakePeer> live{{1, {{S1, S2}}}};
            bch::broadcast_and_mark(marked, live, retry, [](FakePeer& p) {
                return std::vector<uint256>(p.accepts.begin(), p.accepts.end());
            });
            check(marked.size() == 2u, "shipped ordering marks after a real send");
            check(walk(chain, marked).empty(), "shipped ordering then de-dups");
        }
    }

    // -- #885: readvertise_best_share re-pushes a head share the de-dup set
    //          would otherwise mask, where broadcast_share's walk breaks --------
    // A peer that handshook while our verified chain was empty never called
    // download_shares(); it must be re-served the tip. But the tip's parents
    // were already accepted by an EARLIER peer, so they sit in m_shared_share_hashes.
    // broadcast_share's walk breaks on the first such hash and never reaches the
    // tip; readvertise_best_share ignores the de-dup set and re-pushes the window.
    {
        const std::vector<uint256> chain{S3, S2, S1};   // S3 is the tip
        const std::set<uint256> marked{S2, S1};         // parents already shared

        // broadcast_share delegate (pre-#885 readvertise_best): breaks at S2,
        // so the tip S3 is re-pushed but nothing behind it — and if the TIP
        // itself were already marked the walk would yield NOTHING.
        const std::set<uint256> marked_incl_tip{S3, S2, S1};
        check(walk(chain, marked_incl_tip).empty(),
              "#885 broadcast_share walk strands an all-marked head (documents the gap)");
        check(walk(chain, marked).size() == 1u,
              "#885 broadcast_share walk breaks on the first shared parent");

        // readvertise_best_share (the fix): de-dup set is ignored entirely, so
        // the full tip window is re-pushed regardless of prior sharing.
        const std::set<uint256> no_rejects;
        auto readv = readvertise_walk(chain, no_rejects);
        check(readv.size() == 3u,
              "#885 readvertise walk re-pushes the whole window ignoring the de-dup set");
        if (readv.size() == 3u) {
            check(readv[0] == S3, "#885 readvertise walk starts at the tip");
            check(readv[2] == S1, "#885 readvertise walk reaches the shared parents");
        }

        // ...but a peer-REJECTED share is still never re-broadcast.
        const std::set<uint256> rejected{S2};
        auto readv_rej = readvertise_walk(chain, rejected);
        check(readv_rej.size() == 2u,
              "#885 readvertise walk still skips a peer-rejected share");
        check(std::find(readv_rej.begin(), readv_rej.end(), S2) == readv_rej.end(),
              "#885 readvertise walk excludes the rejected hash");
    }

    if (g_failures == 0)
        std::cout << "share_broadcast_gate (F2/F3) KATs: ALL PASS\n";
    else
        std::cerr << "share_broadcast_gate (F2/F3) KATs: " << g_failures
                  << " FAILURE(S)\n";
    return g_failures;
}
