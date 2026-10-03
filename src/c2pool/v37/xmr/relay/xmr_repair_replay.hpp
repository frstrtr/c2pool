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
//
// REPAIR-CHAIN (capstone attempt 4). Two corrections to the above:
// (1) the lane digest is a Merkle root over the lane STATE (v37_lane.hpp
//     digest()), not an append-only chain: two orders that differ locally
//     re-converge at the digest level once the differing buckets fold, so a
//     repair needs ANY base whose state at some q equals the winner's, not the
//     winner's order from 0. With a checkpoint step G (set_checkpoint_step) a
//     shadow also keeps its digest at every multiple of G, which is what the
//     relay's down-walk (XmrRelayNode deep_order) compares at q.
// (2) the shadows were IN MEMORY ONLY: every restart dropped them, and two of
//     the three attempt-4 holds were exactly that. enable_persist() writes them
//     to <settle_db>/lane<N>.shadow after every adopt (atomic tmp + rename,
//     sha256d trailer) and load() restores them at boot, before the relay
//     starts; a missing / torn / foreign file = zero shadows (RC5), loudly.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <map>
#include <optional>
#include <memory>
#include <utility>
#include <vector>

#include <unistd.h>

#include <c2pool/v37/v37_engine.hpp>
#include <sharechain/v37/v37_hash.hpp>

namespace c2pool::v37n::xmr::relay {

class RepairReplayer {
public:
    using Push = std::pair<::v37::ScriptRef, std::uint64_t>;
    enum Base { kNone = 0, kFull = 1, kOwn = 2, kShadow = 3 };
    // Winner-side orders kept (most recently used first). Every node's order is
    // its own lineage after a divergence, so up to one shadow per other node.
    static constexpr std::size_t kMaxShadows = 4;

    explicit RepairReplayer(std::uint64_t keep_digests) : m_keep(keep_digests ? keep_digests : 1) {}

    // ★ HOLD-ROUND-3 F3b: bound the shadows' RAM. A shadow is a whole push list
    // [0, P_end) because the scratch replay (run) starts at position 0 -- there
    // is no lane-state checkpoint to start from -- so a shadow cannot be
    // folded below a point and still serve as a BASE. Above the budget (total
    // pushes over every shadow; 0 = unbounded, the stagenet default) the
    // least recently used shadows are FOLDED TO THEIR DIGESTS: the probe
    // witness (shadow_digests / shadow_with_digest) and the DROPS record key
    // stay, the pushes go, and replay() skips them as a base -- the caller
    // then takes the whole-order fallback (F3a), bounded by the server's
    // retention. Folded shadows are not persisted (digests alone cannot be
    // reloaded as a base either). The daemon's mainnet default is 4 x R.
    void set_ram_budget(std::uint64_t max_pushes) { m_max_pushes = max_pushes; fold_over_budget(); }
    std::uint64_t ram_budget() const { return m_max_pushes; }
    std::uint64_t pushes_held() const { std::uint64_t n = 0; for (const auto& sh : m_sh) n += sh.pushes.size(); return n; }
    std::size_t shadows_folded() const { std::size_t n = 0; for (const auto& sh : m_sh) n += sh.folded ? 1 : 0; return n; }
    std::uint64_t folds() const { return m_folds; }
#define C2POOL_XMR_SHADOW_RAM_BUDGET 1

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
                                                 const std::optional<bytes32>& own_a0 = std::nullopt,
                                                 std::pair<std::uint64_t, bytes32>* shadow_end = nullptr) {
        if (used) *used = kNone;
        const auto skip = [&](const std::optional<bytes32>& have) { return a0 && want_a0 && have && *have != *want_a0; };
        auto adopt = [&](std::vector<Push>&& all, std::map<std::uint64_t, bytes32>&& digs, int from) {
            if (from >= 0) m_sh.erase(m_sh.begin() + from);
            // the new order supersedes every shadow it extends (same digest at that shadow's end)
            for (auto it = m_sh.begin(); it != m_sh.end();) {
                const std::uint64_t L = it->length;
                auto a = digs.find(L); auto b = it->dig.find(L);
                if (L <= all.size() && a != digs.end() && b != it->dig.end() && a->second == b->second) it = m_sh.erase(it);
                else ++it;
            }
            m_sh.push_front(Shadow{std::move(all), std::move(digs)});
            while (m_sh.size() > kMaxShadows) m_sh.pop_back();
            fold_over_budget();               // F3b: the RAM bound (LRU shadows -> digests only)
            if (!m_path.empty()) persist();   // REPAIR-CHAIN (F1): a restart keeps the chain
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
            if (sh.folded || a0 > sh.pushes.size()) continue;   // F3b: a digest-only witness is no base
            std::optional<bytes32> have;
            if (auto it = sh.dig.find(a0); it != sh.dig.end()) have = it->second;
            if (skip(have)) continue;
            std::vector<Push> all; std::map<std::uint64_t, bytes32> digs;
            if (auto rv = run(chain, lp, P, spine, sh.pushes, a0, served, all, digs)) {
                if (shadow_end) {   // ★ DROPS-CARRY-SUFFIX: WHICH shadow's [0, a0) reached the spine (its end)
                    const auto e = sh.dig.find(sh.pushes.size());
                    *shadow_end = {sh.pushes.size(), e == sh.dig.end() ? bytes32{} : e->second};
                }
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
    // ★ HOLD-ROUND-3 (F1): WHICH shadow the relay's prefix probe matched -- the
    // most recently used shadow whose recorded digest at `pos` is exactly `d`,
    // as (its length P_end, its digest at P_end) = the key of its DROPS record
    // ("P_end:digesthex", main_v37_xmr.cpp drops_records). nullopt = none: the
    // probe matched our own order, or nothing (attempt 8: node A's relay chose
    // C's lineage through this shadow and no line said so).
    std::optional<std::pair<std::uint64_t, bytes32>> shadow_with_digest(std::uint64_t pos, const bytes32& d) const {
        for (const auto& sh : m_sh) {
            const auto it = sh.dig.find(pos);
            if (it == sh.dig.end() || it->second != d) continue;
            const auto e = sh.dig.find(sh.length);
            return std::make_pair(sh.length, e == sh.dig.end() ? bytes32{} : e->second);
        }
        return std::nullopt;
    }
#define C2POOL_XMR_SHADOW_WITH_DIGEST 1

    // ── REPAIR-CHAIN ────────────────────────────────────────────────────────
    struct PersistStats {
        std::uint64_t writes = 0, write_fail = 0, bytes = 0;   // `bytes` = the last file's size
        std::uint64_t loaded = 0, load_bad = 0;                // shadows restored / files ignored
        std::string last_error;
    };
    void set_checkpoint_step(std::uint64_t g) { m_step = g; }
    // Persist the shadows to `path` after every adopt. `tag` = the relay's
    // lane_params_digest (a file of another lane geometry is ignored at load).
    void enable_persist(const std::string& path, std::uint32_t chain, const bytes32& tag,
                        std::uint64_t max_bytes = 256ull << 20) {
        m_path = path; m_chain = chain; m_tag = tag; m_max_bytes = max_bytes ? max_bytes : (256ull << 20);
    }
    const PersistStats& persist_stats() const { return m_ps; }
    const std::string& persist_path() const { return m_path; }
    // Every shadow's (length, digest at its end): the KAT compares them across a restart.
    std::vector<std::pair<std::uint64_t, bytes32>> shadow_ends() const {
        std::vector<std::pair<std::uint64_t, bytes32>> v;
        for (const auto& sh : m_sh) {
            auto it = sh.dig.find(sh.length);
            v.emplace_back(sh.length, it == sh.dig.end() ? bytes32{} : it->second);
        }
        return v;
    }

    // Write every UNFOLDED shadow (MRU first) to m_path: tmp + fsync + rename.
    // Above m_max_bytes only the most recent shadow is written. false = kept the old file.
    bool persist() {
        if (m_path.empty()) return false;
        std::vector<std::uint8_t> b;
        std::vector<const Shadow*> keep;   // F3b: a folded shadow (digests only) cannot be reloaded as a base
        for (const auto& sh : m_sh) if (!sh.folded) keep.push_back(&sh);
        std::size_t count = keep.size();
        for (int pass = 0; pass < 2; ++pass) {
            b.clear();
            b.insert(b.end(), kMagic, kMagic + 8);
            put(b, m_chain, 4); b.insert(b.end(), m_tag.begin(), m_tag.end());
            put(b, m_keep, 8); put(b, m_step, 8); put(b, count, 4);
            for (std::size_t i = 0; i < count; ++i) {
                const Shadow& sh = *keep[i];
                put(b, sh.pushes.size(), 8); put(b, sh.dig.size(), 8);
                for (const auto& [pos, d] : sh.dig) { put(b, pos, 8); b.insert(b.end(), d.begin(), d.end()); }
                for (const auto& [ref, w] : sh.pushes) {
                    b.push_back(static_cast<std::uint8_t>(ref.kind)); put(b, ref.payload.size(), 2);
                    b.insert(b.end(), ref.payload.begin(), ref.payload.end()); put(b, w, 8);
                }
            }
            if (b.size() + 32 <= m_max_bytes || count <= 1) break;
            count = 1;   // over the cap: the MRU shadow only
        }
        const bytes32 h = ::v37::sha256d(b);
        b.insert(b.end(), h.begin(), h.end());
        const std::string tmp = m_path + ".tmp";
        std::FILE* f = std::fopen(tmp.c_str(), "wb");
        bool ok = f && std::fwrite(b.data(), 1, b.size(), f) == b.size() && std::fflush(f) == 0 && ::fsync(::fileno(f)) == 0;
        if (f) ok = (std::fclose(f) == 0) && ok;
        ok = ok && std::rename(tmp.c_str(), m_path.c_str()) == 0;
        if (!ok) { ++m_ps.write_fail; m_ps.last_error = "cannot write " + m_path + ": " + std::strerror(errno); return false; }
        ++m_ps.writes; m_ps.bytes = b.size();
        return true;
    }

    // Restore the shadows from m_path (boot, before the relay starts). Any
    // mismatch (magic, chain, lane tag, bounds, trailer) = the file is ignored:
    // zero shadows, exactly RC5, with m_ps.last_error saying why. Returns the
    // number of shadows restored.
    std::size_t load() {
        if (m_path.empty()) return 0;
        std::FILE* f = std::fopen(m_path.c_str(), "rb");
        if (!f) return 0;   // no file yet: nothing to restore
        std::vector<std::uint8_t> b;
        std::uint8_t buf[65536];
        for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, f)) > 0;) b.insert(b.end(), buf, buf + n);
        std::fclose(f);
        auto bad = [&](const char* why) { ++m_ps.load_bad; m_ps.last_error = std::string(why) + " (" + m_path + " ignored: zero shadows)"; return std::size_t{0}; };
        if (b.size() < 8 + 4 + 32 + 8 + 8 + 4 + 32 || std::memcmp(b.data(), kMagic, 8) != 0) return bad("bad magic/size");
        const std::size_t body = b.size() - 32;
        if (::v37::sha256d(b.data(), body) != *reinterpret_cast<const bytes32*>(b.data() + body)) return bad("trailer hash mismatch (torn/corrupt)");
        std::size_t o = 8;
        auto get = [&](std::size_t n, std::uint64_t& v) {
            if (o + n > body) return false;
            v = 0; for (std::size_t i = n; i-- > 0;) v = (v << 8) | b[o + i];
            o += n; return true;
        };
        std::uint64_t chain = 0, keep = 0, step = 0, count = 0;
        if (!get(4, chain) || o + 32 > body) return bad("truncated header");
        bytes32 tag{}; std::memcpy(tag.data(), b.data() + o, 32); o += 32;
        if (!get(8, keep) || !get(8, step) || !get(4, count)) return bad("truncated header");
        if (chain != m_chain || tag != m_tag) return bad("another lane (chain / lane_params_digest differ)");
        if (count > kMaxShadows) return bad("too many shadows");
        std::deque<Shadow> sh;
        for (std::uint64_t i = 0; i < count; ++i) {
            Shadow s; std::uint64_t P = 0, nd = 0;
            if (!get(8, P) || !get(8, nd) || P > (1ull << 32) || nd > P + 1 || nd * 40 > body - o) return bad("bad shadow header");
            for (std::uint64_t k = 0; k < nd; ++k) {
                std::uint64_t pos = 0; bytes32 d{};
                if (!get(8, pos) || o + 32 > body || pos > P) return bad("bad digest record");
                std::memcpy(d.data(), b.data() + o, 32); o += 32;
                s.dig.emplace(pos, d);
            }
            if (!s.dig.count(P)) return bad("a shadow without its end digest");
            s.pushes.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(P, (body - o) / 11 + 1)));
            for (std::uint64_t k = 0; k < P; ++k) {
                std::uint64_t kind = 0, len = 0, w = 0;
                if (!get(1, kind) || !get(2, len) || len > 255 || o + len > body) return bad("bad push record");   // A2: 132-byte composite refs
                ::v37::ScriptRef ref; ref.kind = static_cast<::v37::ScriptKind>(kind);
                ref.payload.assign(b.begin() + static_cast<std::ptrdiff_t>(o), b.begin() + static_cast<std::ptrdiff_t>(o + len)); o += len;
                if (!get(8, w)) return bad("bad push record");
                s.pushes.emplace_back(std::move(ref), w);
            }
            s.length = P;
            sh.push_back(std::move(s));
        }
        if (o != body) return bad("trailing bytes");
        m_sh = std::move(sh);
        m_ps.loaded += m_sh.size();
        fold_over_budget();
        return m_sh.size();
    }

private:
    static constexpr std::uint8_t kMagic[8] = {'V', '3', '7', 'S', 'H', 'D', '1', 0};
    static void put(std::vector<std::uint8_t>& b, std::uint64_t v, int n) {
        for (int i = 0; i < n; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
    // length = P_end (== pushes.size() unless folded); folded = digests only (F3b)
    struct Shadow {
        std::vector<Push> pushes; std::map<std::uint64_t, bytes32> dig;
        std::uint64_t length = 0; bool folded = false;
        Shadow() = default;
        Shadow(std::vector<Push>&& p, std::map<std::uint64_t, bytes32>&& d) : pushes(std::move(p)), dig(std::move(d)), length(pushes.size()) {}
    };
    // F3b: fold the least recently used shadows to digests until the pushes held fit the budget
    void fold_over_budget() {
        if (!m_max_pushes) return;
        for (auto it = m_sh.rbegin(); it != m_sh.rend() && pushes_held() > m_max_pushes; ++it) {
            if (it->folded) continue;
            std::vector<Push>().swap(it->pushes);
            it->folded = true;
            ++m_folds;
        }
    }

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
            if (pos + m_keep >= P || (m_step && pos % m_step == 0)) {   // + REPAIR-CHAIN checkpoints
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
    std::uint64_t m_step = 0;          // REPAIR-CHAIN: checkpoint digest spacing (0 = RC5: last `keep` only)
    std::deque<Shadow> m_sh;
    std::string m_path;                // REPAIR-CHAIN (F1): "" = in memory only (RC5)
    std::uint32_t m_chain = 0;
    bytes32 m_tag{};
    std::uint64_t m_max_bytes = 256ull << 20;
    std::uint64_t m_max_pushes = 0;    // F3b: 0 = unbounded
    std::uint64_t m_folds = 0;
    PersistStats m_ps;
};

} // namespace c2pool::v37n::xmr::relay
