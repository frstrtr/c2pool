// SPDX-License-Identifier: (see repository LICENSE)
// ---------------------------------------------------------------------------
// xmr_recon.hpp — RECON Phase-1 orchestrator: reconstruct-at-the-winner's-cut,
// then verify against the on-chain coinbase. The payout-side twin of the ruled
// variant-A credit side; 0 new wire bytes (uses only v0x02 fields).
//
// The single entry point evaluate(w, pending_now) is a drop-in for the
// FinalizeConnect peer-payout hook (PeerPayoutRecomputeFn): it returns an
// XmrPeerPayoutOutcome, so the receive seam's fold site is UNCHANGED for the
// authoritative payout leg — the map it books is now the RECONSTRUCTED one,
// verified against the winner's coinbase, instead of the cached-instant
// recompute (xmr_peer_payout_recompute.hpp) whose node-local finalize instant
// forked at the first settling block (the cursor-15 defect).
//
// THE RULE, in five steps:
//   (1) pick the ledger snapshot whose owed_digest == w.owed_digest_at_win
//       (the ring, newest-first, or the live ledger). none -> "no-state" (the
//       receiver is behind; the caller PARKs, bounded, then refuses).
//   (2) reconcile that snapshot's pending set to the winner's reservation
//       window (snap_cursor, H_b) from the descriptors this node holds.
//   (3) run the SAME K_fair caller (build_settlement_source ->
//       propose_coinbase) over the scratch ledger at the winner's budget.
//   (4) VERIFY the reconstructed map against the winner's ACTUAL on-chain
//       coinbase (canonical_coinbase_matches). mismatch -> "refuse-coinbase"
//       (fail-closed). bytes not held -> "no-state" (PARK).
//   (5) book exactly that map.
//
// Consumer-tree module: no consensus body, no owed_digest()/fold_eb edit. It is
// decoupled from FinalizeConnect (takes the pending set as a flat vector), so
// there is no include cycle.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "xmr_s1_fold.hpp"                   // XmrPeerWin, s1_hex32, settle::OwedLedger
#include "xmr_peer_payout_recompute.hpp"     // XmrPeerPayoutOutcome (the hook's return type)
#include "xmr_o2_settlement_source.hpp"      // XmrOwedSettlementSource
#include "xmr_recon_ring.hpp"                // XmrReconRing
#include "xmr_recon_verify.hpp"              // WinnerCoinbase(Fetcher), recon_verify_coinbase

namespace c2pool::v37n::xmr::o2 {

// A held descriptor's reservation footprint, flattened so RECON need not depend
// on FinalizeConnect::PendingRec (no include cycle). The daemon fills it from
// fc.pending(); a KAT fills it from its own pending map.
struct ReconReservation {
    std::string                 bid;
    std::uint64_t               height = 0;
    settle::OwedLedger::Amounts payout;   // what that block's coinbase settled
};

struct XmrReconStats {
    std::uint64_t asked         = 0;   // hook invocations for a settling win
    std::uint64_t verified      = 0;   // reconstructed AND coinbase-verified
    std::uint64_t no_state      = 0;   // no snapshot / block bytes not held (PARK)
    std::uint64_t refused_recon = 0;   // settlement source refused the scratch
    std::uint64_t refused_cb    = 0;   // coinbase mismatch (fail-closed)
};

class XmrRecon {
public:
    // recon_owed_map: run the K_fair caller over `scratch` at `reward`, filling
    // `out` (the owed map) and `src_out` (the source, whose inputs_at() the
    // coinbase verify rebuilds from). false + why on a settlement-source refusal.
    using ReconOwedMapFn = std::function<bool(
        const settle::OwedLedger& scratch, std::uint64_t reward,
        settle::OwedLedger::Amounts& out,
        std::unique_ptr<XmrOwedSettlementSource>& src_out, std::string& why)>;

    struct Deps {
        const XmrReconRing*                          ring = nullptr;
        std::function<const settle::OwedLedger&()>   live_ledger;   // cursor-now snapshot
        std::function<std::uint64_t()>               cursor_now;
        ReconOwedMapFn                               recon_owed_map;
        // OPTIONAL. When set, the reconstructed map is VERIFIED against the
        // winner's on-chain coinbase and a mismatch fail-closes; when unset,
        // RECON is reconstruction-only (the payout is the reconstructed map with
        // no coinbase cross-check — used only where block bytes are unreachable,
        // and called out as a gap).
        WinnerCoinbaseFetcher                        fetch_coinbase;
    };

    explicit XmrRecon(Deps d) : m_d(std::move(d)) {}

    const XmrReconStats& stats() const { return m_stats; }

    // The FinalizeConnect peer-payout hook. `w` is the peer's win as the v0x02
    // descriptor delivered it; `pending_now` is every block-winner descriptor
    // this node currently holds pending.
    XmrPeerPayoutOutcome evaluate(const XmrPeerWin& w,
                                  const std::vector<ReconReservation>& pending_now) {
        XmrPeerPayoutOutcome out;
        ++m_stats.asked;

        // (1) the snapshot whose owed_digest matches the winner's commitment.
        const settle::OwedLedger* snap = nullptr;
        std::uint64_t snap_cursor = 0;
        const std::uint64_t cur_now = m_d.cursor_now ? m_d.cursor_now() : 0;
        if (m_d.live_ledger) {
            const settle::OwedLedger& live = m_d.live_ledger();
            if (live.owed_digest() == w.owed_digest_at_win) { snap = &live; snap_cursor = cur_now; }
        }
        if (!snap && m_d.ring)
            snap = m_d.ring->find_by_digest(w.owed_digest_at_win, snap_cursor);
        if (!snap) {
            ++m_stats.no_state;
            out.ok = false; out.code = "no-state";
            out.refusal = "RECON no-state: no ledger snapshot carries the winner's "
                          "owed_digest_at_win " + s1_hex32(w.owed_digest_at_win).substr(0, 12) +
                          " (ring " + (m_d.ring ? std::to_string(m_d.ring->oldest_cursor()) + ".." +
                          std::to_string(m_d.ring->newest_cursor()) : std::string("<none>")) +
                          ", live cursor " + std::to_string(cur_now) + ") — behind, PARK";
            return out;
        }

        // (2) reconcile pending to the winner's reservation window (cursor, H_b).
        settle::OwedLedger scratch = *snap;
        std::size_t reserved = 0;
        for (const auto& r : pending_now) {
            const bool in_window = r.height > snap_cursor && r.height < w.h_b;
            if (in_window) {
                ++reserved;
                if (!scratch.is_pending(r.bid) && !scratch.is_settled(r.bid))
                    scratch.on_block_found(r.bid, {}, r.payout);
            } else if (scratch.is_pending(r.bid)) {
                scratch.on_block_orphaned(r.bid, {});
            }
        }

        // (3) the SAME K_fair over the scratch state at the winner's budget.
        settle::OwedLedger::Amounts map;
        std::unique_ptr<XmrOwedSettlementSource> src;
        std::string why;
        if (!m_d.recon_owed_map || !m_d.recon_owed_map(scratch, w.reward, map, src, why)) {
            ++m_stats.refused_recon;
            out.ok = false; out.code = "no-record";
            out.refusal = "RECON: settlement source refused the reconstructed scratch: " +
                          (why.empty() ? std::string("no map") : why);
            return out;
        }

        // (4) VERIFY against the winner's on-chain coinbase. The source is
        //     needed only for the verify (to rebuild the canonical coinbase);
        //     reconstruction-only mode books the map without it.
        if (m_d.fetch_coinbase) {
            if (!src) {
                ++m_stats.refused_recon;
                out.ok = false; out.code = "no-record";
                out.refusal = "RECON: reconstruction produced no settlement source to verify "
                              "the coinbase against";
                return out;
            }
            WinnerCoinbase wc; std::string fwhy;
            if (!m_d.fetch_coinbase(w.bid, wc, fwhy)) {
                ++m_stats.no_state;
                out.ok = false; out.code = "no-state";
                out.refusal = "RECON no-state: the winner's block bytes are not held yet (" +
                              (fwhy.empty() ? std::string("fetch declined") : fwhy) + ") — PARK";
                return out;
            }
            const ReconVerifyResult v = recon_verify_coinbase(*src, w, wc);
            if (!v.ok) {
                ++m_stats.refused_cb;
                out.ok = false; out.code = "refuse-coinbase";
                out.refusal = "RECON COINBASE MISMATCH " + s1_hex32(w.owed_digest_at_win).substr(0, 12) +
                              " idx=" + std::to_string(v.first_bad_index) + " (" + v.reason +
                              ") — the reconstructed map does not reproduce the winner's on-chain "
                              "coinbase; FAIL-CLOSED, nothing booked";
                return out;
            }
        }

        // (5) book exactly the reconstructed (and, when a fetcher is wired,
        //     coinbase-verified) map.
        std::uint64_t sum = 0;
        for (const auto& [k, v] : map) { (void)k; if (v > 0) sum += static_cast<std::uint64_t>(v); }
        out.ok = true;
        out.code = m_d.fetch_coinbase ? "recon-verified" : "recon-only";
        out.payout = std::move(map);
        out.sum = sum;
        (void)reserved;
        ++m_stats.verified;
        return out;
    }

private:
    Deps          m_d;
    XmrReconStats m_stats;
};

}  // namespace c2pool::v37n::xmr::o2
