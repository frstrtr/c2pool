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

#include <cstddef>
#include <iostream>
#include <map>
#include <set>
#include <vector>

#include <core/uint256.hpp>
#include <impl/bch/known_txs_retention.hpp>
#include <impl/bch/share.hpp>          // real bch share variants + ShareType
#include <impl/bch/share_tx_refs.hpp>  // bch::new_tx_hashes SSOT (#905/#913)

// ---------------------------------------------------------------------------
// #880 COMPILE-TIME PIN of the send-side probe topology.
//
// The F3 gate is only as good as the member probe that feeds it. The historical
// defect was a probe on a member name NO share variant declares: `if constexpr`
// on a false `requires` is discarded silently — no warning, no error, no
// counter — so the gate collected an empty ref list for every share, every share
// was vacuously backable, and the gate no-op'd while every test stayed green.
//
// These static_asserts hold down the topology bch::new_tx_hashes depends on. If
// a share variant ever moves or renames the list, the build breaks HERE instead
// of the gate going quietly inert.
// ---------------------------------------------------------------------------
static_assert(!bch::has_flat_new_tx_hashes<bch::Share>,              "v17 must NOT expose a flat new-tx list");
static_assert(!bch::has_flat_new_tx_hashes<bch::NewShare>,           "v33 must NOT expose a flat new-tx list");
static_assert(!bch::has_flat_new_tx_hashes<bch::SegwitMiningShare>,  "v34 must NOT expose a flat new-tx list");
static_assert(!bch::has_flat_new_tx_hashes<bch::PaddingBugfixShare>, "v35 must NOT expose a flat new-tx list");
static_assert(!bch::has_flat_new_tx_hashes<bch::MergedMiningShare>,  "v36 must NOT expose a flat new-tx list");

static_assert(bch::has_nested_new_tx_hashes<bch::Share>,               "v17 must nest the list in m_tx_info");
static_assert(bch::has_nested_new_tx_hashes<bch::NewShare>,            "v33 must nest the list in m_tx_info");
static_assert(!bch::has_nested_new_tx_hashes<bch::SegwitMiningShare>,  "v34 carries no new-tx list");
static_assert(!bch::has_nested_new_tx_hashes<bch::PaddingBugfixShare>, "v35 carries no new-tx list");
static_assert(!bch::has_nested_new_tx_hashes<bch::MergedMiningShare>,  "v36 carries no new-tx list");

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

// The EXACT refs_of that src/impl/bch/node.cpp installs on partition_backable:
// route the variant through the bch::new_tx_hashes SSOT. Kept verbatim so the
// checks below drive the production probe rather than a stand-in.
std::vector<uint256> production_refs_of(bch::ShareType& share)
{
    std::vector<uint256> hashes;
    share.invoke([&](auto* obj) {
        if (const auto* new_txs = bch::new_tx_hashes(obj))
            hashes.assign(new_txs->begin(), new_txs->end());
    });
    return hashes;
}

// Heap-allocated real v17 share wrapped in the production variant. ShareVariants
// is non-owning (see sharechain/share.hpp destroy()), so callers free the raws.
bch::ShareType make_v17(std::vector<uint256> refs, std::vector<bch::Share*>& owned)
{
    auto* raw = new bch::Share();
    raw->m_tx_info.m_new_transaction_hashes = std::move(refs);
    owned.push_back(raw);
    bch::ShareType sv;
    sv = raw;
    return sv;
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

    // -----------------------------------------------------------------------
    // #880 REGRESSION: the F3 gate must be driven by the PRODUCTION probe.
    //
    // Everything above exercises partition_backable's MECHANICS through
    // FakeShare, which declares its ref list as a TOP-LEVEL member and hands it
    // over via a bespoke refs_of. That is precisely the shape that let the real
    // bug hide: production probed `requires { obj->m_new_transaction_hashes; }`,
    // which is FALSE for every BCH variant (v17/v33 nest the list inside
    // m_tx_info, v34+ carry none), so the gate saw empty refs, every share was
    // vacuously backable, and the gate withheld nothing — while a FakeShare KAT
    // and its negative control both stayed green.
    //
    // The block below builds REAL bch share variants and drives them through the
    // SAME bch::new_tx_hashes SSOT that node.cpp's partition_backable refs_of
    // uses. FAILS-BEFORE: revert bch::new_tx_hashes to the flat probe (or drop
    // the SSOT from node.cpp's refs_of) and the skip count collapses to 0.
    // -----------------------------------------------------------------------
    {
        // Accessor SSOT: a REAL v17/v33 share nests its hashes in m_tx_info and
        // the production probe must surface them. The dead flat probe returned
        // nullptr here, which is what emptied the gate.
        bch::Share s17;
        s17.m_tx_info.m_new_transaction_hashes = {TA, TC};
        const auto* refs17 = bch::new_tx_hashes(&s17);
        check(refs17 != nullptr, "v17 refs resolve through the production SSOT");
        check(refs17 != nullptr && refs17->size() == 2u,
              "v17 SSOT delivers every referenced hash");

        bch::NewShare s33;
        s33.m_tx_info.m_new_transaction_hashes = {TC};
        const auto* refs33 = bch::new_tx_hashes(&s33);
        check(refs33 != nullptr, "v33 refs resolve through the production SSOT");
        check(refs33 != nullptr && refs33->size() == 1u,
              "v33 SSOT delivers every referenced hash");

        // v34+ carry no list at all: nullptr, compiled out — not a silent skip.
        bch::SegwitMiningShare  v34;
        bch::PaddingBugfixShare v35;
        bch::MergedMiningShare  v36;
        check(bch::new_tx_hashes(&v34) == nullptr, "v34 carries no new-tx list");
        check(bch::new_tx_hashes(&v35) == nullptr, "v35 carries no new-tx list");
        check(bch::new_tx_hashes(&v36) == nullptr, "v36 carries no new-tx list");
    }

    {
        // The gate end-to-end on REAL share variants: a v17 share referencing a
        // tx whose bytes we do NOT hold must be withheld, and the backable ones
        // must survive in order. This is the assertion the dead probe made
        // impossible: pre-fix, skipped was pinned at 0 forever.
        std::vector<bch::Share*> owned;
        const std::set<uint256> held{TA, TB};   // TC bytes NOT held

        std::vector<bch::ShareType> batch;
        batch.push_back(make_v17({TA}, owned));       // backable
        batch.push_back(make_v17({TC}, owned));       // unheld TC -> withheld
        batch.push_back(make_v17({TA, TB}, owned));   // backable

        const std::size_t skipped =
            bch::partition_backable(batch, held, production_refs_of);

        check(skipped == 1u,
              "F3 gate withholds a REAL share whose tx bytes we lack "
              "(dead-probe regression pins this at 0)");
        check(batch.size() == 2u, "F3 gate keeps the two backable REAL shares");
        if (batch.size() == 2u) {
            check(production_refs_of(batch[0]).size() == 1u,
                  "F3 gate preserves REAL batch order (S1)");
            check(production_refs_of(batch[1]).size() == 2u,
                  "F3 gate preserves REAL batch order (S3)");
        }

        // A wholly-unbacked REAL batch empties, so send_shares reports nothing
        // sent and broadcast_share marks nothing.
        std::vector<bch::ShareType> all_unbacked;
        all_unbacked.push_back(make_v17({TC}, owned));
        check(bch::partition_backable(all_unbacked, held, production_refs_of) == 1u,
              "F3 gate skips a wholly-unbacked REAL batch");
        check(all_unbacked.empty(), "F3 gate empties a wholly-unbacked REAL batch");

        for (auto* raw : owned)
            delete raw;
    }

    if (g_failures == 0)
        std::cout << "share_broadcast_gate (F2/F3) KATs: ALL PASS\n";
    else
        std::cerr << "share_broadcast_gate (F2/F3) KATs: " << g_failures
                  << " FAILURE(S)\n";
    return g_failures;
}
