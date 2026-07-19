// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 6 (S8 embedded_gbt live-wire, follow-on to #672):
/// the node-held embedded coin-state bundle that flips select_dash_work()'s
/// hot arm live.
///
/// #672 landed select_dash_work() (work_source.hpp) as the stable branch
/// point, but every caller still presents has_state=false, so 100% of the
/// running node's get_work path routes to the retained dashd
/// getblocktemplate fallback. This holder is the in-process coin-state the
/// DASH node maintains as mnlistdiff / mempool / header-tip updates arrive --
/// masternode list + mempool + header-tip params. make_embedded_work_inputs()
/// presents it as a viable() EmbeddedWorkInputs so select_dash_work() takes
/// the oracle-parity embedded path (build_embedded_workdata, pinned by
/// test_dash_embedded_gbt vs frstrtr/p2pool-dash getwork()).
///
/// STRICTLY single-coin: src/impl/dash/ only, no bitcoin_family / src/core
/// reach. The external-daemon (dashd RPC) arm is NEVER removed -- populated()
/// == false always routes there, and it remains the [GBT-XCHECK] cross-check.

#include <impl/dash/coin/work_source.hpp>        // EmbeddedWorkInputs, select_dash_work, WorkSelection
#include <impl/dash/coin/mn_state_machine.hpp>   // MnStateMachine
#include <impl/dash/coin/mempool.hpp>            // Mempool
#include <impl/dash/coin/rpc_data.hpp>           // DashWorkData

#include <core/uint256.hpp>

#include <cstdint>
#include <functional>

namespace dash {
namespace coin {

/// In-process coin-state the running node maintains for LOCAL template
/// assembly. Non-copyable: it owns a Mempool (itself non-copyable) and is
/// node-owned, never duplicated. The maintainer mutates mnstates()/mempool()
/// in place and calls set_tip() once the tip advances; get_work reads it
/// through select_work().
class NodeCoinState {
public:
    NodeCoinState() = default;
    NodeCoinState(const NodeCoinState&) = delete;
    NodeCoinState& operator=(const NodeCoinState&) = delete;

    // Mutable accessors for the maintainer (the reception / think slices seed
    // these from mnlistdiff + relayed mempool txs).
    MnStateMachine& mnstates() { return m_mnstates; }
    Mempool&        mempool()  { return m_mempool; }

    /// Record the header-tip parameters and mark the bundle live. Call after
    /// the tip advances AND the MN list + mempool are seeded; until then the
    /// selector must route to the dashd fallback. curtime/version left 0 use
    /// build_embedded_workdata()'s own SAFE-ADDITIVE defaults.
    void set_tip(uint32_t prev_height, const uint256& prev_hash,
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
        m_populated            = true;
    }

    /// Invalidate the bundle (reorg / mempool flush / MN list gap) so the next
    /// get_work falls back to dashd until the state is rebuilt.
    void invalidate() { m_populated = false; }

    bool populated() const { return m_populated; }

    /// Coinbase-maturity mining gate (E2b/#738) — the dash analog of the LTC
    /// EmbeddedCoinNode::set_utxo_ready_fn (main_ltc.cpp ~1785-1801). When
    /// set, embedded-template viability additionally requires the predicate
    /// (UtxoLane::mining_utxo_ready: blocks_connected >= 106) so templates
    /// cannot include txs spending immature coinbase outputs; until then
    /// has_state stays false and get_work routes to the retained dashd
    /// fallback. Unset (default) preserves the pre-E2b behaviour exactly.
    void set_utxo_ready_fn(std::function<bool()> fn) {
        m_utxo_ready_fn = std::move(fn);
    }

    /// Assemble the selector input. has_state is populated() gated by the
    /// optional UTXO-maturity predicate; the two required pointers are always
    /// non-null (members), so viable() reduces to that gate -- exactly the
    /// semantics work_source.hpp documents.
    EmbeddedWorkInputs make_embedded_work_inputs() const {
        EmbeddedWorkInputs e;
        e.has_state            = m_populated
                                 && (!m_utxo_ready_fn || m_utxo_ready_fn());
        e.prev_height          = m_prev_height;
        e.prev_hash            = m_prev_hash;
        e.mnstates             = &m_mnstates;
        e.mempool              = &m_mempool;
        e.bits_for_next        = m_bits_for_next;
        e.mtp_at_tip           = m_mtp_at_tip;
        e.address_version      = m_address_version;
        e.address_p2sh_version = m_address_p2sh_version;
        e.curtime              = m_curtime;
        e.version              = m_version;
        return e;
    }

    /// Live get_work entry point: prefer the locally-assembled embedded
    /// template when this bundle is populated, else the supplied dashd
    /// getblocktemplate fallback. Thin wrapper over select_dash_work() so the
    /// node call site is one line. dashd_fallback is REQUIRED -- it is the
    /// always-reachable safety path and the cross-check arm.
    WorkSelection select_work(
        const std::function<DashWorkData()>& dashd_fallback) const {
        return select_dash_work(make_embedded_work_inputs(), dashd_fallback);
    }

private:
    MnStateMachine m_mnstates;
    Mempool        m_mempool;
    std::function<bool()> m_utxo_ready_fn;   // optional UTXO maturity gate (E2b)
    uint32_t m_prev_height{0};
    uint256  m_prev_hash;
    uint32_t m_bits_for_next{0};
    uint32_t m_mtp_at_tip{0};
    uint8_t  m_address_version{0};
    uint8_t  m_address_p2sh_version{0};
    uint32_t m_curtime{0};
    uint32_t m_version{0};
    bool     m_populated{false};
};

} // namespace coin
} // namespace dash
