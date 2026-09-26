// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/relay/xmr_repair_replay.hpp   (REPAIR-HORIZON)
//
// The SCRATCH REPLAY of a relay repair (main_v37_xmr.cpp relay_view) and the
// SHADOW: the last winner-side order this node reconstructed.
//
// A repair served from a peer's vault horizon covers [a0, P) only; the replay
// needs the first a0 pushes of the WINNER-side order from somewhere else. Our
// own lane is the right prefix only while a0 is at or below the position where
// our order diverged from the winner's. Lane orders never re-converge (the
// lane digest is an append-only chain), so after a divergence d every later
// cross-side cut needs the winner order over [d, P) -- and once P - d exceeds
// the vault horizon no peer can serve it from our own prefix any more (the
// capstone would have held again ~3 h after its stall). The SHADOW closes
// that: every successful repair leaves its full push list [0, P) here, and the
// next repair may use shadow[0, a0) as its prefix when a0 <= that P -- so the
// winner-side order is CHAINED from repair to repair as long as consecutive
// cross-side cuts are less than a horizon apart. After a divergence every
// node's order is its own lineage, so up to kMaxShadows are kept (one per
// other node, most recently used first). Each base is tried in turn (own
// first, then each shadow; one whose digest at a0 is known to differ from the
// serving peer's is skipped) and a view is returned ONLY when the replay's
// digest at P equals the winner's spine: the same digest gate, the same fold.
// The digests of the shadow's last `keep` positions are what the relay's
// prefix probe accepts besides our own (XmrRelayNode::note_alt_digests).
// Node-local bookkeeping only: nothing here is on the wire or in consensus.
// ===========================================================================
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <memory>
#include <utility>
#include <vector>

#include <c2pool/v37/v37_engine.hpp>

namespace c2pool::v37n::xmr::relay {

class RepairReplayer {
public:
    using Push = std::pair<::v37::ScriptRef, std::uint64_t>;
    enum Base { kNone = 0, kFull = 1, kOwn = 2, kShadow = 3 };
    // Winner-side orders kept (most recently used first). Every node's order is
    // its own lineage after a divergence, so up to one shadow per other node.
    static constexpr std::size_t kMaxShadows = 4;

    explicit RepairReplayer(std::uint64_t keep_digests) : m_keep(keep_digests ? keep_digests : 1) {}

    // Replay base[0, a0) + served (the pushes of the served ids [a0, P)) for
    // our own order, then each shadow; the view at (P, spine) of the first that
    // reproduces the spine, or null. `want_a0` = the serving peer's digest at
    // a0 when its prefix probe returned one: a base whose own digest at a0 is
    // known and differs is skipped (`own_a0` = our lane digest at a0). On
    // success that push list becomes the most recent shadow (replacing the
    // shadow it extended, if it came from one).
    std::shared_ptr<const SettlementView> replay(std::uint32_t chain, const ::v37::LaneParams& lp,
                                                 std::uint64_t P, const bytes32& spine, std::uint64_t a0,
                                                 const std::vector<Push>& own, const std::vector<Push>& served,
                                                 Base* used = nullptr,
                                                 const std::optional<bytes32>& want_a0 = std::nullopt,
                                                 const std::optional<bytes32>& own_a0 = std::nullopt) {
        if (used) *used = kNone;
        const auto skip = [&](const std::optional<bytes32>& have) { return a0 && want_a0 && have && *have != *want_a0; };
        auto adopt = [&](std::vector<Push>&& all, std::map<std::uint64_t, bytes32>&& digs, int from) {
            if (from >= 0) m_sh.erase(m_sh.begin() + from);
            // the new order supersedes every shadow it extends (same digest at that shadow's end)
            for (auto it = m_sh.begin(); it != m_sh.end();) {
                const std::uint64_t L = it->pushes.size();
                auto a = digs.find(L); auto b = it->dig.find(L);
                if (L <= all.size() && a != digs.end() && b != it->dig.end() && a->second == b->second) it = m_sh.erase(it);
                else ++it;
            }
            m_sh.push_front(Shadow{std::move(all), std::move(digs)});
            while (m_sh.size() > kMaxShadows) m_sh.pop_back();
        };
        if (!skip(own_a0) && a0 <= own.size()) {
            std::vector<Push> all; std::map<std::uint64_t, bytes32> digs;
            if (auto rv = run(chain, lp, P, spine, own, a0, served, all, digs)) {
                adopt(std::move(all), std::move(digs), -1);
                if (used) *used = a0 == 0 ? kFull : kOwn;
                return rv;
            }
        }
        if (!a0) return nullptr;   // the served order IS the whole prefix: nothing else to try
        for (std::size_t i = 0; i < m_sh.size(); ++i) {
            const Shadow& sh = m_sh[i];
            if (a0 > sh.pushes.size()) continue;
            std::optional<bytes32> have;
            if (auto it = sh.dig.find(a0); it != sh.dig.end()) have = it->second;
            if (skip(have)) continue;
            std::vector<Push> all; std::map<std::uint64_t, bytes32> digs;
            if (auto rv = run(chain, lp, P, spine, sh.pushes, a0, served, all, digs)) {
                adopt(std::move(all), std::move(digs), static_cast<int>(i));
                if (used) *used = kShadow;
                return rv;
            }
        }
        return nullptr;
    }
    std::size_t shadows() const { return m_sh.size(); }
    // Every shadow's digests at its last `keep` positions (for the relay's probe).
    std::multimap<std::uint64_t, bytes32> shadow_digests() const {
        std::multimap<std::uint64_t, bytes32> out;
        for (const auto& sh : m_sh) for (const auto& [p, d] : sh.dig) out.emplace(p, d);
        return out;
    }

private:
    struct Shadow { std::vector<Push> pushes; std::map<std::uint64_t, bytes32> dig; };

    std::shared_ptr<const SettlementView> run(std::uint32_t chain, const ::v37::LaneParams& lp, std::uint64_t P,
                                              const bytes32& spine, const std::vector<Push>& base, std::uint64_t a0,
                                              const std::vector<Push>& served, std::vector<Push>& all,
                                              std::map<std::uint64_t, bytes32>& digs) const {
        V37Engine scratch;   // ring depth is irrelevant: P is the tip after exactly P replays
        scratch.start();
        scratch.submit_tracked(::v37::LaneRecord::add_lane(chain, lp)).get();
        all.reserve(static_cast<std::size_t>(a0) + served.size());
        auto push = [&](const Push& p) {
            ::v37::PayoutDescriptor d; d.pay = p.first;
            scratch.submit_tracked(::v37::LaneRecord::push(chain, d, p.second, 0)).get();
            all.push_back(p);
            const std::uint64_t pos = all.size();
            if (pos + m_keep >= P) {
                if (auto s = scratch.snapshot(chain)) digs[pos] = s->digest;
            }
        };
        for (std::uint64_t i = 0; i < a0; ++i) push(base[static_cast<std::size_t>(i)]);
        for (const auto& p : served) push(p);
        bool mism = false;
        auto rv = scratch.settlement_view_by_cut(chain, P, spine, &mism);
        scratch.stop();
        return rv;
    }

    std::uint64_t m_keep;
    std::deque<Shadow> m_sh;
};

} // namespace c2pool::v37n::xmr::relay
