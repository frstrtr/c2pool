// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 7 (S8 embedded_gbt live-wire, follow-on to #673):
/// the maintainer that POPULATES the node-held NodeCoinState off the
/// reception + think update path, replacing the set_tip-on-demand pattern
/// where a caller poked NodeCoinState::set_tip() directly.
///
/// #672 landed select_dash_work() as the branch point; #673 landed
/// NodeCoinState as the node-held bundle whose populated() flips the hot arm.
/// But #673 left publication to whoever calls set_tip() -- fine for the KAT,
/// wrong for a live node: the tip advances on the header/think path, the MN
/// list advances on the mnlistdiff reception path, and mempool txs arrive on
/// the relay path, all ASYNCHRONOUSLY. The bundle must only go live once the
/// prerequisites the embedded template needs are actually present, else the
/// selector would build a template against a stale/empty MN list.
///
/// CoinStateMaintainer is that ordering gate. It owns no state of its own
/// beyond readiness flags + the last tip params; it drives a NodeCoinState&
/// the node owns. The reception/think slices call the on_*() event methods;
/// the maintainer republishes (calls set_tip) only when BOTH the MN list has
/// been seeded AND a tip has arrived. Until then, and after any invalidating
/// event (reorg / MN-list gap), populated() stays false and select_work()
/// routes to the retained dashd getblocktemplate fallback.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only, no bitcoin_family / src/core
/// reach. The dashd RPC arm is NEVER removed -- it is the always-reachable
/// safety path and the [GBT-XCHECK] cross-check whenever the bundle is not live.

#include <impl/dash/coin/node_coin_state.hpp>    // NodeCoinState
#include <impl/dash/coin/mn_state_machine.hpp>   // MNState
#include <impl/dash/coin/block.hpp>            // BlockType
#include <impl/dash/coin/transaction.hpp>        // MutableTransaction

#include <core/uint256.hpp>

#include <cstdint>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// Drives a node-owned NodeCoinState from the async update events the running
/// node observes. Non-copyable (holds a reference to the node's holder). The
/// node constructs exactly one, wired to its NodeCoinState member; the
/// reception (mnlistdiff / mempool) and header/think (tip) slices call the
/// on_*() methods as their respective updates land.
class CoinStateMaintainer {
public:
    explicit CoinStateMaintainer(NodeCoinState& state) : m_state(state) {}
    CoinStateMaintainer(const CoinStateMaintainer&) = delete;
    CoinStateMaintainer& operator=(const CoinStateMaintainer&) = delete;

    /// Reception path (mnlistdiff): replace the masternode set the embedded
    /// coinbase pays. An EMPTY list is treated as a gap -- it cannot back a
    /// valid payee, so it clears MN-readiness and drops the bundle to fallback
    /// rather than publishing a template with no masternode payment.
    ///
    /// as_of_height (E2c): the chain height the snapshot is CURRENT AT
    /// (0 = unknown). Recorded so on_block_connected() can skip re-applying
    /// blocks the snapshot already reflects -- replaying a historical coinbase
    /// payment on top of an already-current lastPaidHeight set falsely
    /// re-bumps the front of the GetMNPayee queue when several MNs share one
    /// payoutAddress (live-observed: E2b's 288-block UTXO bootstrap replay
    /// scrambled the seeded queue and the embedded template projected the
    /// wrong payee).
    void on_mn_list_update(std::vector<std::pair<uint256, MNState>> mnstates,
                           uint32_t as_of_height = 0) {
        m_have_mn = !mnstates.empty();
        m_mn_snapshot_height = as_of_height;
        m_state.mnstates().load(std::move(mnstates));
        if (!m_have_mn)
            demote();
        else
            republish();
    }

    /// Reception path (mempool relay): fold a relayed tx into the local
    /// mempool. Mempool contents are OPTIONAL for viability -- an empty
    /// mempool yields a valid coinbase-only template -- so this never gates
    /// publication; it only enriches the next assembled template. Returns the
    /// mempool's accept verdict (false = rejected: bad utxo ref / already in).
    bool on_mempool_tx(const MutableTransaction& tx) {
        return m_state.mempool().add_tx(tx);
    }

    /// Header / think path: the chain tip advanced. Stash the params the
    /// embedded template needs and mark tip-readiness, then republish if the
    /// MN list is also ready. curtime/version left 0 defer to
    /// build_embedded_workdata()'s own SAFE-ADDITIVE defaults.
    void on_new_tip(uint32_t prev_height, const uint256& prev_hash,
                    uint32_t bits_for_next, uint32_t mtp_at_tip,
                    uint8_t address_version, uint8_t address_p2sh_version,
                    uint32_t curtime = 0, uint32_t version = 0) {
        m_prev_height          = prev_height;
        m_prev_hash            = prev_hash;
        m_bits_for_next        = bits_for_next;
        m_mtp_at_tip           = mtp_at_tip;
        m_address_version      = address_version;
        m_address_p2sh_version = address_p2sh_version;
        m_curtime              = curtime;
        m_version              = version;
        m_have_tip             = true;
        republish();
    }

    /// Header / think path (block connect): fold a newly-connected block's
    /// special txs into the DMN list incrementally, mirroring dashcore's
    /// RebuildListFromBlock (MnStateMachine::apply_block). This is the LIVE
    /// driver that keeps the masternode set the embedded coinbase pays current
    /// BETWEEN full mnlistdiff snapshots -- on_mn_list_update() stays the
    /// authoritative resync and is UNCHANGED. MN-readiness is refreshed from
    /// the post-apply list size: a block that empties the set (all collateral
    /// spent) drops the bundle to the dashd fallback rather than backing a
    /// template with a phantom payee. Returns apply_block's ApplyResult.
    MnStateMachine::ApplyResult
    on_block_connected(const dash::coin::BlockType& block, uint32_t height) {
        // E2c snapshot fence: blocks the payout-bearing snapshot already
        // reflects (height <= its as-of height) must NOT be re-folded -- the
        // snapshot's registrations/spends/lastPaid ARE those blocks' effects,
        // and re-attributing their coinbase payments corrupts the shared-
        // payoutAddress payee queue (see on_mn_list_update). The E2b UTXO
        // lane's own subscription to the same event is unaffected (it needs
        // every block for the UTXO view; it holds no MN state).
        if (m_mn_snapshot_height != 0 && height <= m_mn_snapshot_height) {
            MnStateMachine::ApplyResult r;
            r.total_after = m_state.mnstates().size();
            return r;
        }
        auto r    = m_state.mnstates().apply_block(block, height);
        m_have_mn = m_state.mnstates().size() != 0;
        if (!m_have_mn)
            demote();
        else
            republish();
        return r;
    }

    /// Reorg / MN-list gap / mempool flush: invalidate the live bundle so the
    /// next get_work falls back to dashd until a fresh tip rebuilds it. The
    /// stashed tip params are dropped -- a reorg means the old prev_hash is no
    /// longer the tip, so we must NOT auto-republish it; a subsequent
    /// on_new_tip() re-arms tip-readiness. The MN list (which survives a mere
    /// reorg) is left in place.
    void on_invalidate() {
        m_have_tip = false;
        demote();
    }

    /// True iff both prerequisites are met AND the holder is currently live.
    bool live() const { return m_state.populated(); }

private:
    // Publish only when both prerequisites are present; otherwise leave the
    // holder in whatever (un)published state it is in -- callers reach demote()
    // explicitly for the invalidating transitions.
    void republish() {
        if (m_have_tip && m_have_mn)
            m_state.set_tip(m_prev_height, m_prev_hash, m_bits_for_next,
                            m_mtp_at_tip, m_address_version, m_address_p2sh_version,
                            m_curtime, m_version);
    }

    void demote() {
        if (m_state.populated())
            m_state.invalidate();
    }

    NodeCoinState& m_state;

    bool m_have_mn{false};
    bool m_have_tip{false};

    // Height the last MN-set snapshot was current at (0 = none/unknown);
    // on_block_connected skips re-applying blocks at or below it.
    uint32_t m_mn_snapshot_height{0};

    // Last observed tip params, applied on republish().
    uint32_t m_prev_height{0};
    uint256  m_prev_hash;
    uint32_t m_bits_for_next{0};
    uint32_t m_mtp_at_tip{0};
    uint8_t  m_address_version{0};
    uint8_t  m_address_p2sh_version{0};
    uint32_t m_curtime{0};
    uint32_t m_version{0};
};

} // namespace coin
} // namespace dash
