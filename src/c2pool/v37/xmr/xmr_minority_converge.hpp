// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_minority_converge.hpp   (D2: minority converges to
//                                                 majority, operator ruling D2 = A)
//
// The PURE pieces of the D2 track (docs/xmr-lane/d2-minority-converge.md):
//
//   * builder_key()      -- the per-builder datum under the PoW: the first 4
//                           bytes of the coinbase 0x02 extra-nonce payload >> 20
//                           (GAP-2 node-private base in [2^24, 2^31)). A PROXY:
//                           it defends the accidental case (one stuck/forked
//                           node cannot look like a majority), not a sybil.
//   * evaluate_run()     -- the minority-detection rule over the per-block
//                           observations, in chain order: M consecutive
//                           UNMATCHED foreign lane blocks from >= B_min distinct
//                           builders (own blocks and undecided ones skipped, a
//                           matched foreign block resets the run). One foreign
//                           block, or M from one builder, is NEVER a detection.
//   * refold()           -- the re-derivation: replay the settled prefix up to
//                           the fork point F into a scratch OwedLedger, then the
//                           synced node's sequence book(h + D_conf) -> FINALIZE(h)
//                           over the canonical lane blocks of the chain, each
//                           decoded under the SCRATCH candidate ring, the forced
//                           refuse set R skipped. Post R-A owed_digest is a pure
//                           function of the ordered FINALIZE sequence, so this is
//                           deterministic on (chain, event log, R).
//   * Marker             -- the phased adoption marker (<sidecar>.converge).
//
// Consumer tree only. No consensus digest, coinbase byte or golden is defined
// or altered here: the scratch uses the production OwedLedger on the same maps.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>   // OwedLedger
#include "xmr_settle_store.hpp"           // SettleEvent, SettleEvKind, Amounts
#include "xmr_recon_ring.hpp"             // ReconRing (the scratch candidate ring)

namespace c2pool::v37n::xmr::minority {

// ── builder key ─────────────────────────────────────────────────────────────
inline constexpr unsigned kBuilderShift = 20;
inline std::uint32_t builder_key(std::uint32_t extra_nonce) { return extra_nonce >> kBuilderShift; }

// ── observations and the run ────────────────────────────────────────────────
enum class Verdict : std::uint8_t { Matched = 0, Unmatched = 1, Undecided = 2 };
inline const char* verdict_name(Verdict v) {
    return v == Verdict::Matched ? "matched" : v == Verdict::Unmatched ? "unmatched" : "undecided";
}

struct Observation {
    std::uint64_t h = 0;
    std::string   bid, root;                 // root: the on-chain 0x03 root (hex), "" when unknown
    bool          own = false;               // mined by this node
    bool          has_builder = false;       // the 0x02 extra-nonce was parsed
    std::uint32_t builder = 0;               // builder_key(extra_nonce)
    Verdict       verdict = Verdict::Undecided;
    bool          has_matched_since = false; // matched: the since-height of the state it committed
    std::uint64_t matched_since = 0;
    std::uint64_t t = 0;                     // wall clock unix s (staleness only)
};

struct RunStatus {
    std::vector<Observation> run;                    // the current unmatched-foreign run, chain order
    std::size_t builders = 0;                        // distinct builder keys in it (parsed only)
    bool        detected = false;
    std::optional<Observation> last_matched_before;  // the last matched foreign obs before the run
    std::size_t trailing_matched = 0;                // matched foreign obs since the last unmatched one
    std::size_t trailing_matched_builders = 0;
    bool        trailing_clear = false;              // trailing_matched >= M from >= B_min builders
};

// `floor_h`: observations at or below it are ignored (consumed by an adoption).
inline RunStatus evaluate_run(std::vector<Observation> obs, std::size_t M, std::size_t B_min, std::uint64_t floor_h) {
    std::stable_sort(obs.begin(), obs.end(), [](const Observation& a, const Observation& b) { return a.h < b.h; });
    RunStatus st;
    std::set<std::uint32_t> run_b, trail_b;
    for (const auto& o : obs) {
        if (o.h <= floor_h || o.own || o.verdict == Verdict::Undecided) continue;
        if (o.verdict == Verdict::Unmatched) {
            st.run.push_back(o);
            if (o.has_builder) run_b.insert(o.builder);
            st.trailing_matched = 0; trail_b.clear();
        } else {
            st.last_matched_before = o;   // a matched obs always precedes the (reset) run
            st.run.clear(); run_b.clear();
            ++st.trailing_matched;
            if (o.has_builder) trail_b.insert(o.builder);
        }
    }
    st.builders = run_b.size();
    st.detected = M > 0 && st.run.size() >= M && st.builders >= std::max<std::size_t>(B_min, 1);
    st.trailing_matched_builders = trail_b.size();
    st.trailing_clear = M > 0 && st.trailing_matched >= M && st.trailing_matched_builders >= std::max<std::size_t>(B_min, 1);
    return st;
}

// ── the re-derivation ───────────────────────────────────────────────────────
enum class DecodeOutcome : std::uint8_t { Booked = 0, NotLane = 1, Refused = 2, Undecidable = 3 };

struct DecodeResult {
    DecodeOutcome outcome = DecodeOutcome::Undecidable;
    Amounts       credit, payout;            // Booked (empty when root_only: the caller reuses its maps)
    std::string   why;
    // the money shape of a refusal, exactly what the live refuse path records
    bool          payout_decoded = false;
    std::uint64_t unattributed_pico = 0, total_pico = 0;
    std::string   root_hex;
};
// cands/superseded: the scratch ring's candidates (live first), as ReconRing::
// candidates() produces them. root_only: the refold already holds this block's
// booked maps (it was booked in the log being re-derived) -- the decoder only
// has to say whether its 0x03 root matches the scratch ring (age-bounded).
using DecodeFn = std::function<DecodeResult(std::uint64_t h, const std::string& bid,
                                            const std::vector<::v37::bytes32>& cands,
                                            const std::vector<std::uint64_t>& superseded, bool root_only)>;

struct RefoldInput {
    ::v37::ChainId chain = 0;
    std::uint64_t  d_conf = 1;
    std::uint64_t  fork_h = 0;                     // F: every FINALIZE of a block mined at h <= F is kept
    std::uint64_t  cursor = 0;                     // c: the refold finalizes (F, c], books (F, c + 1 + D_conf]
    std::vector<SettleEvent> events;               // the persisted event log, seq order
    std::map<std::uint64_t, std::string> chain_blocks;   // canonical bid per height in (F, c + 1 + D_conf]
    std::set<std::string> refuse;                  // the forced refuse set R
};

struct RefusedBlock {
    std::uint64_t h = 0;
    std::string   bid;
    bool          forced = false;                  // in R (never decoded)
    bool          had_old = false;                 // it was booked in the log being re-derived
    Amounts       old_payout;                      // its booked payout map (liability per payee)
    DecodeResult  r;                               // the scratch decode (when not forced)
};
struct PendingOut { std::uint64_t h = 0; std::string bid; Amounts credit, payout; };

struct RefoldResult {
    bool          ok = false;
    bool          undecidable = false;
    std::string   why;
    std::vector<SettleEvent> events;               // the re-derived event log
    std::vector<std::pair<::v37::bytes32, std::uint64_t>> ring;   // (digest, since), oldest first
    std::map<std::string, std::uint64_t> booked;   // bid -> height, booked by the refold
    std::vector<RefusedBlock> refused;
    std::vector<PendingOut> pending;               // booked, not finalized at c
    ::v37::bytes32 digest{};
    std::uint64_t  since = 0, ledger_seq = 0;
    std::size_t    prefix_events = 0, reused_maps = 0, decoded = 0, finalized = 0;
};

inline RefoldResult refold(const RefoldInput& in, const DecodeFn& decode) {
    RefoldResult out;
    const std::uint64_t D = in.d_conf ? in.d_conf : 1;
    auto since_of_bin = [D](std::uint64_t bin) { return bin >= D ? bin - D : 0; };
    // (1) which bids settled at or below F; their LAST booked maps.
    std::map<std::string, std::uint64_t> fin_since;
    std::map<std::string, std::pair<Amounts, Amounts>> old_maps;
    for (const auto& e : in.events) {
        if (e.kind == SettleEvKind::Finalize) fin_since[e.bid] = since_of_bin(e.bin_height);
        else if (e.kind == SettleEvKind::Found) old_maps[e.bid] = {e.credit, e.payout};
    }
    OwedLedger L(in.chain);
    recon::ReconRing ring(4096);
    std::uint64_t since = 0;
    ring.push(L.owed_digest(), 0);
    out.ring.emplace_back(L.owed_digest(), 0);
    auto note_state = [&]() {
        const ::v37::bytes32 d = L.owed_digest();
        if (ring.push(d, since)) out.ring.emplace_back(d, since);
    };
    // (2) PREFIX: every event of a bid that settled at h <= F, original order.
    for (const auto& e : in.events) {
        const auto it = fin_since.find(e.bid);
        if (it == fin_since.end() || it->second > in.fork_h) continue;
        switch (e.kind) {
            case SettleEvKind::Found:    L.on_block_found(e.bid, e.credit, e.payout); break;
            case SettleEvKind::Finalize: since = since_of_bin(e.bin_height); L.on_block_finalized(e.bid, e.bin_height); break;
            case SettleEvKind::Orphan:   L.on_block_orphaned(e.bid, e.payout); break;
        }
        out.events.push_back(e);
        ++out.prefix_events;
        note_state();
    }
    // (3) REFOLD: book(h + D) -> FINALIZE(h), the synced node's order.
    const std::uint64_t top = in.cursor + 1 + D;
    std::map<std::uint64_t, std::string> pend;   // h -> bid
    std::map<std::string, std::pair<Amounts, Amounts>> maps;
    auto book = [&](std::uint64_t h) -> bool {
        if (h <= in.fork_h || h > top) return true;
        const auto cb = in.chain_blocks.find(h);
        if (cb == in.chain_blocks.end() || cb->second.empty()) return true;
        const std::string& bid = cb->second;
        const auto om = old_maps.find(bid);
        const bool had_old = om != old_maps.end();
        if (in.refuse.count(bid)) {
            RefusedBlock rb; rb.h = h; rb.bid = bid; rb.forced = true; rb.had_old = had_old;
            if (had_old) rb.old_payout = om->second.second;
            out.refused.push_back(std::move(rb));
            return true;
        }
        std::vector<::v37::bytes32> cands; std::vector<std::uint64_t> sup;
        ring.candidates(L.owed_digest(), cands, sup);
        DecodeResult r = decode(h, bid, cands, sup, had_old);
        ++out.decoded;
        switch (r.outcome) {
            case DecodeOutcome::Booked: {
                Amounts credit = r.credit, payout = r.payout;
                if (had_old) { credit = om->second.first; payout = om->second.second; ++out.reused_maps; }
                SettleEvent fe; fe.kind = SettleEvKind::Found; fe.bid = bid; fe.credit = credit; fe.payout = payout;
                L.on_block_found(bid, credit, payout);
                out.events.push_back(fe);
                pend[h] = bid; maps[bid] = {credit, payout}; out.booked[bid] = h;
                note_state();
                return true;
            }
            case DecodeOutcome::NotLane: return true;
            case DecodeOutcome::Refused: {
                RefusedBlock rb; rb.h = h; rb.bid = bid; rb.had_old = had_old; rb.r = r;
                if (had_old) rb.old_payout = om->second.second;
                out.refused.push_back(std::move(rb));
                return true;
            }
            case DecodeOutcome::Undecidable:
                out.undecidable = true;
                out.why = "h=" + std::to_string(h) + " bid=" + bid.substr(0, 12) + " undecidable: " + r.why;
                return false;
        }
        return true;
    };
    for (std::uint64_t h = in.fork_h + 1; h <= in.fork_h + 1 + D; ++h)
        if (!book(h)) return out;
    for (std::uint64_t h = in.fork_h + 1; h <= in.cursor; ++h) {
        if (const auto p = pend.find(h); p != pend.end()) {
            SettleEvent fz; fz.kind = SettleEvKind::Finalize; fz.bid = p->second; fz.bin_height = h + D;
            since = h;
            L.on_block_finalized(p->second, h + D);
            out.events.push_back(fz);
            ++out.finalized;
            note_state();
            pend.erase(p);
        }
        if (!book(h + 1 + D)) return out;
    }
    for (const auto& [h, bid] : pend) {
        const auto& m = maps[bid];
        out.pending.push_back(PendingOut{h, bid, m.first, m.second});
    }
    out.digest = L.owed_digest();
    out.since = since;
    out.ledger_seq = L.ledger_seq();
    out.ok = true;
    return out;
}

// Every run block (the majority's unmatched commitments) was booked by the
// refold: the re-derived lineage reproduces the majority's commitments.
inline std::size_t reproduced(const RefoldResult& r, const std::vector<Observation>& run) {
    std::size_t n = 0;
    for (const auto& o : run) if (r.booked.count(o.bid)) ++n;
    return n;
}

// ── the adoption marker (<sidecar>.converge) ────────────────────────────────
struct Marker {
    std::string   phase;          // proposed | applied | done
    std::uint64_t fork_h = 0, cursor = 0, new_seq = 0, new_events = 0, old_events = 0, floor_h = 0;
    std::string   new_digest_hex, utc, candidate;
    std::vector<std::string> forced, refused, released;
};
inline std::string join_(const std::vector<std::string>& v) {
    if (v.empty()) return "-";
    std::string s; for (const auto& x : v) { if (!s.empty()) s += ","; s += x; } return s;
}
inline std::vector<std::string> split_(const std::string& s) {
    std::vector<std::string> v; if (s == "-" || s.empty()) return v;
    std::size_t p = 0;
    while (p <= s.size()) {
        const std::size_t c = s.find(',', p);
        v.push_back(s.substr(p, c == std::string::npos ? std::string::npos : c - p));
        if (c == std::string::npos) break;
        p = c + 1;
    }
    return v;
}
inline std::string marker_str(const Marker& m) {
    std::ostringstream o;
    o << "phase " << m.phase << "\nfork_h " << m.fork_h << "\ncursor " << m.cursor << "\nnew_seq " << m.new_seq
      << "\nnew_events " << m.new_events << "\nold_events " << m.old_events << "\nfloor_h " << m.floor_h
      << "\nnew_digest " << (m.new_digest_hex.empty() ? "-" : m.new_digest_hex) << "\nutc " << (m.utc.empty() ? "-" : m.utc)
      << "\ncandidate " << (m.candidate.empty() ? "-" : m.candidate)
      << "\nforced " << join_(m.forced) << "\nrefused " << join_(m.refused) << "\nreleased " << join_(m.released) << "\n";
    return o.str();
}
inline bool marker_parse(const std::string& s, Marker& m) {
    std::istringstream in(s); std::string k, v; bool any = false;
    while (in >> k >> v) {
        any = true;
        try {
            if (k == "phase") m.phase = v;
            else if (k == "fork_h") m.fork_h = std::stoull(v);
            else if (k == "cursor") m.cursor = std::stoull(v);
            else if (k == "new_seq") m.new_seq = std::stoull(v);
            else if (k == "new_events") m.new_events = std::stoull(v);
            else if (k == "old_events") m.old_events = std::stoull(v);
            else if (k == "floor_h") m.floor_h = std::stoull(v);
            else if (k == "new_digest") m.new_digest_hex = v == "-" ? "" : v;
            else if (k == "utc") m.utc = v == "-" ? "" : v;
            else if (k == "candidate") m.candidate = v == "-" ? "" : v;
            else if (k == "forced") m.forced = split_(v);
            else if (k == "refused") m.refused = split_(v);
            else if (k == "released") m.released = split_(v);
        } catch (...) { return false; }
    }
    return any && !m.phase.empty();
}

// ── the observation codec (<sidecar>.mobs, append-only) ─────────────────────
//   "1 h bid root|- verdict(0/1/2) own(0/1) has_builder builder has_since since t"
inline std::string obs_line(const Observation& o) {
    std::ostringstream s;
    s << "1 " << o.h << ' ' << o.bid << ' ' << (o.root.empty() ? "-" : o.root) << ' ' << static_cast<int>(o.verdict) << ' '
      << (o.own ? 1 : 0) << ' ' << (o.has_builder ? 1 : 0) << ' ' << o.builder << ' ' << (o.has_matched_since ? 1 : 0) << ' '
      << o.matched_since << ' ' << o.t << '\n';
    return s.str();
}
inline bool obs_parse(const std::string& line, Observation& o) {
    std::istringstream is(line);
    std::string ver, root; unsigned long long h = 0, ms = 0, t = 0; int v = 0, own = 0, hb = 0, hs = 0; unsigned long b = 0;
    if (!(is >> ver >> h >> o.bid >> root >> v >> own >> hb >> b >> hs >> ms >> t) || ver != "1") return false;
    if (v < 0 || v > 2) return false;
    o.h = h; o.root = root == "-" ? "" : root; o.verdict = static_cast<Verdict>(v); o.own = own != 0;
    o.has_builder = hb != 0; o.builder = static_cast<std::uint32_t>(b); o.has_matched_since = hs != 0; o.matched_since = ms; o.t = t;
    return true;
}

} // namespace c2pool::v37n::xmr::minority
