// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_recon_ring.hpp   (R-C rework-3, D7)
//
// The RECON candidate ring (this node's owed_digest history, the set of
// lane_commitments a peer's 0x03 root is matched against) with the coin height
// each state became current at, and the AGE BOUND on the historical root RECON
// may credit.
//
// WHY (rework-2 verify, D7): the ring holds EVERY state this ledger lived
// through (it must: an honest builder that is a few cursors behind commits an
// older state, and a restarted node must still match it). But "any state we
// ever lived through" also matches a forker that commits a state honest nodes
// left long ago: a fresh node seeded with the genesis owed-demo state built
// blocks committing the genesis-seed digest, the honest ring still held it, and
// the forker's block was CREDITED. Nothing honest ever commits a state that old:
// a builder whose finalize cursor lags the buried frontier by more than
// 2 * D_conf is lane-suspended (xmr_lane_suspend_state.hpp), so its committed
// state was superseded at most ~2 * D_conf heights before the block's builder
// cut. The bound below (4 * D_conf, a 2x margin) refuses anything older.
//
// DEFINITIONS (deterministic on converged ledgers; no wall clock, no wire):
//   since(i)        coin height at which ring state i became current. Post R-A
//                   the digest is D(c): it changes only at a FINALIZE of the
//                   block mined at h (-> since = h) or at a seed.
//   superseded(i)   since(i+1); the newest state is still current (+inf).
//   bcut(h)         h - 1 - D_conf: the finalize cursor an in-order builder
//                   stood at when it built the block at height h (R6).
//   age(i, h)       max(0, bcut(h) - superseded(i)). 0 for the live state.
// A matched candidate with age > max_root_age is REFUSED ("stale root"), never
// credited. An idle lane (no settlement for a long time) keeps age 0: the old
// state is still CURRENT, so a long-lived current root is never "stale".
//
// Consumer tree only; no consensus digest is defined or altered.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32

namespace c2pool::v37n::xmr::recon {

// The documented constant: a matched historical root older than
// kReconMaxRootAgeDconf * D_conf heights (relative to the block's builder cut)
// is never credited. 4 = 2x the lane-suspend lag bound (2 * D_conf).
inline constexpr std::uint64_t kReconMaxRootAgeDconf = 4;
inline constexpr std::uint64_t kSupersededNever = std::numeric_limits<std::uint64_t>::max();

inline std::uint64_t default_max_root_age(std::uint64_t d_conf) {
    return kReconMaxRootAgeDconf * (d_conf ? d_conf : 1);
}
inline std::uint64_t builder_cut(std::uint64_t h, std::uint64_t d_conf) {
    return h >= 1 + d_conf ? h - 1 - d_conf : 0;
}
inline std::uint64_t root_age(std::uint64_t superseded, std::uint64_t bcut) {
    return (superseded == kSupersededNever || superseded >= bcut) ? 0 : bcut - superseded;
}

class ReconRing {
public:
    struct Entry { ::v37::bytes32 digest{}; std::uint64_t since = 0; };

    explicit ReconRing(std::size_t cap = 4096) : m_cap(cap ? cap : 1) {}

    // A new state that became current at coin height `since`. De-duplicated
    // against the newest entry (the ledger-event observer and the per-tick
    // sampler both call this). Returns true when an entry was appended.
    bool push(const ::v37::bytes32& d, std::uint64_t since) {
        if (!m_e.empty() && m_e.back().digest == d) return false;
        m_e.push_back(Entry{d, since});
        while (m_e.size() > m_cap) m_e.pop_front();
        return true;
    }
    // Boot: the replayed history (oldest first) with its since heights.
    void seed(const std::vector<::v37::bytes32>& ds, const std::vector<std::uint64_t>& since) {
        for (std::size_t i = 0; i < ds.size(); ++i) push(ds[i], i < since.size() ? since[i] : 0);
    }

    std::size_t size() const { return m_e.size(); }
    bool empty() const { return m_e.empty(); }
    const Entry& back() const { return m_e.back(); }
    const std::deque<Entry>& entries() const { return m_e; }
    bool contains(const ::v37::bytes32& d) const {
        for (const auto& e : m_e) if (e.digest == d) return true;
        return false;
    }

    // The decode candidates, newest first: the LIVE digest at index 0 (still
    // current), then the ring newest -> oldest (the live digest skipped).
    // `superseded` is parallel to `cands`: the coin height at which that
    // candidate stopped being current (kSupersededNever for the live one). A
    // digest that occurs twice keeps its NEWEST occurrence first (the most
    // lenient age), which is the one decode_lane_coinbase matches.
    void candidates(const ::v37::bytes32& live, std::vector<::v37::bytes32>& cands,
                    std::vector<std::uint64_t>& superseded) const {
        cands.clear(); superseded.clear();
        cands.push_back(live); superseded.push_back(kSupersededNever);
        for (std::size_t k = m_e.size(); k-- > 0;) {
            if (m_e[k].digest == live) continue;
            cands.push_back(m_e[k].digest);
            superseded.push_back(k + 1 < m_e.size() ? m_e[k + 1].since : kSupersededNever);
        }
    }

private:
    std::size_t       m_cap;
    std::deque<Entry> m_e;
};

} // namespace c2pool::v37n::xmr::recon
