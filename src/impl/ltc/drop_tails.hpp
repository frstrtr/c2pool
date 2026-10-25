#pragma once

// drop_tails.hpp — the clean_tracker() Step 3 tail-dropping loop (node.cpp),
// extracted VERBATIM into a template so it can be driven by a KAT without a
// live node. Pure move: the iteration order, the QUALIFY / PRE diagnostics and
// the per-aftertail checks are byte-for-byte the loop that was inline in
// NodeImpl::clean_tracker(); only the member names became parameters
// (m_tracker.chain -> chain, m_tracker.verified -> verified,
// m_supersede_hint -> hint). One deliberate change since the move: the
// supersede exemption now compares tail_hash with hint.target_segment_last
// directly (see the comment in the loop).
//
// LOCKING: takes NO lock. The caller must hold the tracker mutex EXCLUSIVELY
// for the whole call — clean_tracker() calls it inside the same
// std::unique_lock scope the inline loop ran in, so the lock scope is
// unchanged.
//
// C++ implementation of the p2pool tail-dropping step (node.py:380-398).
// p2pool has NO best-chain protection — the 2*CHAIN_LENGTH+10 threshold
// ensures only shares far beyond the PPLNS window are removed.
//
// ChainT: the sharechain (production: ltc::ShareChain); VerifiedT: the
// borrowing verified view of the same shares; HintT: ltc::SupersedeHint
// (active + target_segment_last). Returns the number of shares dropped.

#include <core/log.hpp>
#include <core/uint256.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace ltc {

template <typename ChainT, typename VerifiedT, typename HintT>
int drop_tails(ChainT& chain, VerifiedT& verified, int32_t CL, const HintT& hint)
{
    int total_dropped = 0;
    for (int iter = 0; iter < 1000; ++iter)
    {
        std::vector<uint256> to_remove;
        auto tails_copy = chain.get_tails();
        for (auto& [tail_hash, head_hashes] : tails_copy)
        {
            // Restart-reorg: never drop the tail of the converging challenger
            // segment. An unrooted challenger needs its FULL ~2*CL depth to
            // reach CHAIN_LENGTH verified shares; trimming its bottom mid-
            // verification silently restarts convergence (looks like the
            // original stickiness). The exemption lifts once it verifies to
            // CHAIN_LENGTH and the hint deactivates, when normal drop-tails
            // resumes. Matched by segment id (the shared missing-parent):
            // get_tails() is keyed by that missing parent, so tail_hash IS the
            // segment id. (The old chain.contains(tail_hash) guard was always
            // false for exactly that reason, so the exemption never fired.)
            if (hint.active && tail_hash == hint.target_segment_last)
                continue;

            int32_t min_height = 0;  // default 0 → skip if no valid heads
            for (auto& hh : head_hashes) {
                if (!chain.contains(hh)) continue;
                auto h = chain.get_height(hh);
                if (min_height == 0 || h < min_height)
                    min_height = h;
            }
            if (min_height < 2 * CL + 10) continue;

            if (iter == 0) {
                LOG_WARNING << "[drop-tails-QUALIFY] tail=" << tail_hash.GetHex().substr(0,16)
                            << " min_height=" << min_height << " threshold=" << (2*CL+10)
                            << " n_heads=" << head_hashes.size()
                            << " chain_size=" << chain.size();
            }

            // p2pool node.py:386: to_remove.update(tracker.reverse.get(tail, set()))
            auto& rev = chain.get_reverse();
            auto rev_it = rev.find(tail_hash);
            if (rev_it != rev.end()) {
                for (const auto& child : rev_it->second)
                    to_remove.push_back(child);
            }
        }

        if (to_remove.empty()) break;

        // p2pool node.py:392-398
        size_t _drop_idx = 0;
        for (const auto& aftertail : to_remove)
        {
            try {
                // DIAG: contabo 2026-04-21 froze 40s inside
                // unordered_map::contains() on an aftertail at bucket 2332.
                // If we spin here again this is the last line flushed —
                // gives us the iter index, which aftertail triggered it,
                // and the queue size to correlate with the freeze.
                std::fprintf(stderr,
                    "[drop-tails-PRE] iter=%d drop_idx=%zu/%zu aftertail=%.16s "
                    "chain_size=%zu\n",
                    iter, _drop_idx, to_remove.size(),
                    aftertail.GetHex().c_str(),
                    chain.size());
                std::fflush(stderr);
                ++_drop_idx;

                if (!chain.contains(aftertail)) continue;
                // p2pool node.py:393: if items[aftertail].previous_hash not in tails: continue
                auto* idx = chain.get_index(aftertail);
                if (!idx) continue;
                if (!chain.get_tails().count(idx->tail)) {
                    continue;
                }
                if (verified.contains(aftertail))
                    verified.remove(aftertail, /*owns_data=*/false);
                chain.remove(aftertail);
                ++total_dropped;
            } catch (...) {}
        }
    }
    return total_dropped;
}

} // namespace ltc
