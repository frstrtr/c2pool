// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// btc::coin::TipReconcileGate — pure decision logic for the B5b tip-reconcile
// poll that unwedges the HeaderChain sync-lag self-collision livelock.
//
// Livelock (observed on the vm130 G3b regtest rig 2026-08-16, tip pinned at
// 604 while bitcoind was at 605): after we submit a won block, bitcoind may
// connect it (or a competing same-height block) as its active tip WITHOUT
// re-announcing an inv/sendheaders over the P2P leg it learned the block from
// — Core does not reliably re-announce a block to the path it arrived on. Our
// initial getheaders sync then never re-fires, so HeaderChain stalls one block
// behind bitcoind's real tip, every new template re-mines the SAME height, and
// each won block returns submitblock "inconclusive" -> STALE forever.
//
// Fix: while ANY submitted block is still pending roundtrip confirmation,
// actively re-issue getheaders(locator = current tip) every kPollInterval so
// HeaderChain pulls the connected tip and either CONFIRMS the roundtrip or
// advances past it, unwedging template production. Gated on a pending submit
// (and a live, handshaked P2P leg) so an idle, caught-up node emits zero
// getheaders churn.
//
// This gate is the SSOT for both the shipped poll (src/c2pool/main_btc.cpp)
// and the tip_reconcile KAT (src/impl/btc/test/tip_reconcile_test.cpp) — the
// decision, and the 10s cadence, live in exactly one place so the test can
// never silently drift from production. Header-only, no I/O, no timers.
//
// It also owns the unknown-block resync decision (on_block_announce), the
// second HeaderChain stall shape: inv-only tip announcements after a reorg.
// ---------------------------------------------------------------------------
#ifndef C2POOL_IMPL_BTC_COIN_TIP_RECONCILE_GATE_HPP
#define C2POOL_IMPL_BTC_COIN_TIP_RECONCILE_GATE_HPP

#include <chrono>

namespace btc::coin {

class TipReconcileGate
{
public:
    // Re-poll cadence. Deliberately a named constant so the shipped timer and
    // the KAT reference the SAME interval — a drift here would silently desync
    // the test from production.
    static constexpr std::chrono::seconds kPollInterval{10};

    enum class Action {
        Poll,  // re-issue getheaders(locator = tip) on this tick
        Skip,  // nothing pending / P2P not ready -> stay quiet
    };

    // Decide whether this tick should re-issue the reconcile getheaders.
    // Mirrors the shipped guard exactly:
    //   have_pending_submit && p2p_up && handshake_complete
    static constexpr Action evaluate(bool have_pending_submit,
                                     bool p2p_up,
                                     bool handshake_complete) noexcept
    {
        return (have_pending_submit && p2p_up && handshake_complete)
                   ? Action::Poll
                   : Action::Skip;
    }

    // Locator selection: the current tip hash when we have a tip, else the
    // genesis hash (cold chain). Templated on the hash type to keep this
    // header free of uint256 / chain-params includes.
    template <class Hash>
    static Hash locator(bool have_tip,
                        const Hash& tip_hash,
                        const Hash& genesis_hash) noexcept
    {
        return have_tip ? tip_hash : genesis_hash;
    }

    // ── Unknown-block resync (header-stall fix) ──────────────────────────────
    // Second stall shape (observed on the .234 G3b testnet3 rig 2026-10-25,
    // HeaderChain pinned ~50k behind bitcoind for 5 days): once a < 2000
    // headers batch marks sync "caught up", the external-bitcoind arm relies on
    // bitcoind pushing new tips as headers (sendheaders). Core falls back to a
    // plain block INV whenever the announced block does not connect to the
    // best header it believes the peer has (reorg / min-diff storm / > 8 new
    // blocks). We then getdata the block, full_block finds its header unknown
    // and drops it -- and nothing ever re-issues getheaders, so every later
    // tip arrives as yet another unconnectable INV. Core's own PeerManager
    // answers an INV for an unknown block with getheaders(locator); do the
    // same. Throttled to one resync per kUnknownBlockResyncMinGap so a burst of
    // sibling INVs (the 288-wide regtest storm) costs one getheaders, not 288.
    static constexpr std::chrono::seconds kUnknownBlockResyncMinGap{2};

    // Decide whether an announced block should trigger a resync getheaders.
    //   header_known       : HeaderChain already has this block's header
    //   handshake_complete : P2P leg is up and handshaked
    //   resync_ever_sent   : a previous unknown-block resync was issued
    //   since_last_resync  : time since that previous resync (ignored if none)
    static constexpr Action on_block_announce(
        bool header_known,
        bool handshake_complete,
        bool resync_ever_sent,
        std::chrono::steady_clock::duration since_last_resync) noexcept
    {
        if (header_known || !handshake_complete)
            return Action::Skip;
        if (resync_ever_sent && since_last_resync < kUnknownBlockResyncMinGap)
            return Action::Skip;
        return Action::Poll;
    }
};

}  // namespace btc::coin

#endif  // C2POOL_IMPL_BTC_COIN_TIP_RECONCILE_GATE_HPP
