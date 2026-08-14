// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// W5-A: FoldFeeSource — the adapter that lets the full-history UTXO fold
// (replay_utxo_fold.hpp, W3) price mempool-tx inputs the forward-built
// UTXOViewCache cannot know (coins created before the node's replay horizon),
// closing the DOMINANT dashd-only tx class behind the gbt-xcheck tx-merkle
// mismatches (20/34 across the 26-event diagnosis: ordinary fee-payers
// spending OLD confirmed coins → fee_known=false → excluded → embedded is a
// strict SUBSET of dashd → guard swaps to the dashd template).
//
// ── Trust model (reward-critical; every branch fails TOWARD EXCLUSION) ─────
//
// A fold answer may reach a fee computation ONLY while ALL of these hold:
//
//   1. GRADUATED: the fold proved byte-equality with dashd's own
//      `gettxoutsetinfo hash_serialized_2` at the pinned anchor
//      (ReplayUtxoFold::try_graduate → the durable 'G' record), AND the
//      operator RESTATED the expected anchor hash on the command line
//      (--embedded-utxo-fold-fees-expect) — a stale or foreign DB cannot
//      graduate on its own say-so. A wrong fee can OVERSTATE coinbasevalue =
//      an invalid found block = a lost block, so an unverified fold is
//      arithmetically unreachable from the fee path (the latch is the FIRST
//      statement of lookup()).
//   2. LIVE-CONTIGUOUS: the fold's cursor is within `tip_lag_max` (default 2)
//      of the last tip height this adapter was shown (note_tip). A fold still
//      catching up prices nothing — it could hold coins the chain has since
//      spent, admitting a tx dashd already dropped (superset ⇒ guard trip).
//   3. UNPOISONED / UNDISARMED: any fold refusal on the feed path (gap,
//      prev-hash linkage break = reorg tripwire, gate fail, store error)
//      latches the disarm. The latch clears ONLY by process restart — with
//      ChainLocks live, mainnet DASH reorgs are ~nonexistent, so the latch is
//      a rare-case backstop, not an availability cost.
//
// Even a WRONG-but-graduated answer is bounded: selection divergence is
// caught by the #1218 gbt-xcheck-txmerkle guard (serving refused / swapped to
// the dashd arm where present — never an invalid block from divergence
// alone); the graduation gate exists because fee VALUES additionally flow
// into coinbasevalue, which the tx-merkle guard does not cover.
//
// ── Threading ──────────────────────────────────────────────────────────────
// ReplayUtxoFold is single-thread by design (plain unordered_map overlay).
// This adapter owns the mutex: feed()/disconnect()/note_tip() run on the io
// thread; lookup() runs under Mempool::m_mutex from intake / recompute /
// selection. Lock order on the money path: Mempool::m_mutex →
// FoldFeeSource::m_mutex. The feed path takes m_mutex alone and never calls
// into Mempool — no cycle. The LevelDB point-get under the mempool lock is
// the same cost class as the existing UTXOViewCache base read.
//
// Constructed ONLY by the --embedded-utxo-fold-fees flag family in
// main_dash.cpp (DASH lane only). Absent the flag, nothing here exists and
// Mempool::m_fee_coin_lookup stays empty — production byte-identical.

#include "replay_utxo_fold.hpp"

#include <core/log.hpp>

#include <atomic>
#include <cctype>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>

namespace dash {
namespace coin {

class FoldFeeSource {
public:
    struct Options {
        // The operator's restatement of the anchor hash (hex, REQUIRED by the
        // wiring). Compared against the STORED graduation record AND against
        // the fold's compiled/injected gate_anchor_expect.
        std::string operator_expect;
        // Trust requires fold.best_height + tip_lag_max >= last noted tip.
        uint32_t tip_lag_max = 2;
    };

    /// `fold` must already be open()ed; not owned. The constructor attempts a
    /// TRUST RESTORE from the stored 'G' record (a restart with the cursor
    /// past the anchor can regain trust ONLY from a recorded PASS), and — the
    /// crash-window case — re-runs the gate when the cursor is parked exactly
    /// on the anchor with no record yet.
    FoldFeeSource(replay::ReplayUtxoFold& fold, Options opts)
        : m_fold(fold), m_opts(std::move(opts))
    {
        normalize_hex(m_opts.operator_expect);
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_fold.have_cursor()
            && m_fold.best_height() == gate_anchor_height_locked()
            && !m_fold.graduation().has_value()) {
            // Parked on the anchor, ungraduated (fresh arrival or a crash
            // between the PASS and the 'G' put): run the gate now — pure
            // re-measure, same verdict.
            try_graduate_locked();
        } else {
            restore_graduation_locked();
        }
    }
    FoldFeeSource(const FoldFeeSource&) = delete;
    FoldFeeSource& operator=(const FoldFeeSource&) = delete;

    // ── Feed side (io thread) ──────────────────────────────────────────────

    /// Hand one block to the fold. Used by BOTH lanes:
    ///   * the W2 bulk-replay lane (strictly in-order from the fold's own
    ///     cursor — catch-up AND steady-state tip-follow with
    ///     tip_exclusion=0);
    ///   * any opportunistic caller (idempotent ack below cursor, tolerated
    ///     gap above it — a gap only marks the fold behind, it is not an
    ///     error while another lane is still bridging).
    /// Returns false ONLY on a fold refusal (which also disarms trust) — the
    /// bulk lane then stops with the fold's own named cause.
    bool feed(uint32_t height, const uint256& hash, const BlockType& block)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (!m_fold.is_open()) return fail_locked("fold-not-open");
        if (m_fold.have_cursor() && height <= m_fold.best_height())
            return true;                        // idempotent redelivery ack
        // Above the fold's next expected height — including a LIVE TIP block
        // landing on an EMPTY store (cold start must begin at genesis, and
        // only the replay lane starts there). NOT a refusal: the replay lane
        // is (or will be) bridging the gap, and trust demands tip proximity,
        // so a genuinely-behind fold prices nothing meanwhile.
        const uint32_t next =
            m_fold.have_cursor() ? m_fold.resume_height() : 1;
        if (height > next) {
            if (!m_gap_noted) {
                m_gap_noted = true;
                LOG_INFO << "[FOLD-FEE] feed gap: got h=" << height
                         << " fold wants h=" << next
                         << " — fold behind, fee-pricing stays dark until the"
                            " replay lane bridges to the tip";
            }
            return true;
        }
        if (!m_fold.on_replay_block(height, hash, block))
            return fail_locked(m_fold.refusal());
        m_gap_noted = false;
        // THE GATE fires exactly as the cursor crosses the anchor.
        if (m_fold.best_height() == gate_anchor_height_locked()
            && !m_graduated.load(std::memory_order_relaxed)) {
            if (!try_graduate_locked() && m_fold.poisoned())
                return false;   // gate FAIL: poisoned + disarmed, stop the lane
        }
        recompute_trust_locked();
        return true;
    }

    /// Reorg support within the fold's undo window. Any failure disarms.
    bool disconnect(const BlockType& tip_block)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (!m_fold.disconnect_tip(tip_block))
            return fail_locked(m_fold.refusal());
        recompute_trust_locked();
        return true;
    }

    /// The chain-tip observation trust condition 2 compares against. Cheap;
    /// call per connected block / header tip advance.
    void note_tip(uint32_t tip_height)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (tip_height > m_tip_height) m_tip_height = tip_height;
        recompute_trust_locked();
    }

    // ── Lookup side (called under Mempool::m_mutex) ────────────────────────

    /// The Mempool::set_fee_coin_lookup target. Answers ONLY while trusted;
    /// missing, spent and immature-coinbase outpoints all answer false
    /// (fail-toward-exclusion — dashd would not pool an immature-coinbase
    /// spend, and admitting one would make embedded a SUPERSET ⇒ guard trip).
    bool lookup(const ::core::coin::Outpoint& op, ::core::coin::Coin& out) const
    {
        if (!m_trusted.load(std::memory_order_acquire)) return false;   // THE LATCH
        std::lock_guard<std::mutex> lk(m_mutex);
        ::core::coin::Coin c;
        if (!m_fold.get_coin(op, c)) return false;      // missing OR spent
        if (c.coinbase
            && !replay::ReplayUtxoFold::is_mature(c, m_fold.best_height() + 1))
            return false;
        out = c;
        return true;
    }

    // ── Introspection (wiring + soak logs) ─────────────────────────────────
    bool graduated() const { return m_graduated.load(std::memory_order_relaxed); }
    bool trusted()   const { return m_trusted.load(std::memory_order_relaxed); }
    bool disarmed()  const { return m_disarmed.load(std::memory_order_relaxed); }
    std::string disarm_cause() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_disarm_cause;
    }
    uint32_t fold_height() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_fold.have_cursor() ? m_fold.best_height() : 0;
    }

private:
    static void normalize_hex(std::string& s)
    {
        for (auto& c : s)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    uint32_t gate_anchor_height_locked() const
    {
        // The anchor the FOLD was constructed with (KAT-injectable there);
        // the adapter never carries a second copy that could drift.
        return m_fold.gate_anchor_height();
    }

    /// Disarm latch: named once, cleared only by restart.
    bool fail_locked(const std::string& why)
    {
        if (!m_disarmed.exchange(true, std::memory_order_relaxed)) {
            m_disarm_cause = why;
            LOG_ERROR << "[FOLD-FEE] DISARMED (until restart): " << why
                      << " — fee pricing reverts to the fee-unknown exclusion";
        }
        m_trusted.store(false, std::memory_order_release);
        return false;
    }

    /// Trust restore from the stored 'G' record (restart with cursor past the
    /// anchor). All four equalities required; any miss = never graduated.
    void restore_graduation_locked()
    {
        auto g = m_fold.graduation();
        if (!g) {
            if (m_fold.have_cursor()
                && m_fold.best_height() > gate_anchor_height_locked()) {
                LOG_WARNING << "[FOLD-FEE] store cursor h="
                            << m_fold.best_height()
                            << " is PAST the anchor h="
                            << gate_anchor_height_locked()
                            << " with NO graduation record — this store can"
                               " never graduate (re-fold, or supply a fresh"
                               " operator anchor)";
            }
            return;
        }
        if (g->anchor_height != gate_anchor_height_locked()) {
            LOG_WARNING << "[FOLD-FEE] stored graduation anchor h="
                        << g->anchor_height << " != configured h="
                        << gate_anchor_height_locked() << " — IGNORED";
            return;
        }
        const std::string measured = g->measured_hash.GetHex();
        if (measured != g->expected_hash.GetHex()
            || measured != m_opts.operator_expect) {
            LOG_WARNING << "[FOLD-FEE] stored graduation hash " << measured
                        << " does not match the operator-restated expect "
                        << m_opts.operator_expect << " — IGNORED (a foreign"
                           " or stale DB cannot graduate on its own say-so)";
            return;
        }
        m_graduated.store(true, std::memory_order_relaxed);
        LOG_INFO << "[FOLD-FEE] graduation RESTORED from record: anchor h="
                 << g->anchor_height << " hash=" << measured
                 << " coins=" << g->coins;
        recompute_trust_locked();
    }

    /// Run the gate (cursor must stand on the anchor). PASS → graduated=true;
    /// hash-mismatch FAIL → fold poisoned → disarm.
    bool try_graduate_locked()
    {
        // The operator's restatement must agree with the fold's own expected
        // anchor BEFORE we measure — refusing early keeps a mis-typed flag
        // from burning a multi-minute set scan and then "failing" the fold.
        if (m_opts.operator_expect != lowercase(m_fold.gate_anchor_expect())) {
            fail_locked("operator-expect mismatch: '" + m_opts.operator_expect +
                        "' vs fold anchor '" + m_fold.gate_anchor_expect() + "'");
            return false;
        }
        if (m_fold.try_graduate()) {
            m_graduated.store(true, std::memory_order_relaxed);
            recompute_trust_locked();
            return true;
        }
        if (m_fold.poisoned()) fail_locked(m_fold.refusal());
        return false;
    }

    static std::string lowercase(std::string s) { normalize_hex(s); return s; }

    void recompute_trust_locked()
    {
        const bool t = m_graduated.load(std::memory_order_relaxed)
            && !m_disarmed.load(std::memory_order_relaxed)
            && !m_fold.poisoned()
            && m_fold.have_cursor()
            && m_tip_height > 0
            && m_fold.best_height() + m_opts.tip_lag_max >= m_tip_height;
        const bool was = m_trusted.exchange(t, std::memory_order_release);
        if (t && !was) {
            LOG_INFO << "[FOLD-FEE] TRUSTED: graduated fold is live at h="
                     << m_fold.best_height() << " (tip h=" << m_tip_height
                     << ") — full-history fee pricing ACTIVE (backlog resolves"
                        " on the next block-connect recompute)";
        } else if (!t && was) {
            LOG_WARNING << "[FOLD-FEE] trust dropped: fold h="
                        << (m_fold.have_cursor() ? m_fold.best_height() : 0)
                        << " tip h=" << m_tip_height
                        << (m_disarmed.load(std::memory_order_relaxed)
                                ? " (disarmed: " + m_disarm_cause + ")"
                                : " (lag)");
        }
    }

    replay::ReplayUtxoFold& m_fold;   // not owned; single-thread core
    Options                 m_opts;
    mutable std::mutex      m_mutex;
    std::atomic<bool>       m_graduated{false};
    std::atomic<bool>       m_trusted{false};   // the ONLY bit lookup() consults first
    std::atomic<bool>       m_disarmed{false};
    std::string             m_disarm_cause;
    uint32_t                m_tip_height{0};
    bool                    m_gap_noted{false};
};

} // namespace coin
} // namespace dash
