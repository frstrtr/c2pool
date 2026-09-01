// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bip110::coin::TipReconcileGate — pure decision logic for the B5b tip-reconcile
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
// ---------------------------------------------------------------------------
#ifndef C2POOL_IMPL_BTC_COIN_TIP_RECONCILE_GATE_HPP
#define C2POOL_IMPL_BTC_COIN_TIP_RECONCILE_GATE_HPP

#include <chrono>

namespace bip110::coin {

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
};

}  // namespace bip110::coin

#endif  // C2POOL_IMPL_BTC_COIN_TIP_RECONCILE_GATE_HPP
