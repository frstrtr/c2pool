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
#include <impl/dash/coin/quorum_manager.hpp>     // QuorumManager (merkleRootQuorums source)
#include <impl/dash/coin/vendor/simplifiedmns.hpp> // vendor::CSimplifiedMNList (merkleRootMNList source)

#include <core/uint256.hpp>

#include <array>
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

    // ── SML / quorum consensus-commitment state (daemonless CCbTx) ────────
    // The deterministic MN list + LLMQ quorum set the CCbTx extra_payload
    // commits to. Populated by CoinStateMaintainer::on_mnlistdiff (apply_diff
    // + QuorumManager::apply) off the live coin-P2P mnlistdiff feed. These are
    // the merkleRootMNList / merkleRootQuorums sources build_embedded_workdata
    // needs to emit a MAINNET-VALID type-5 coinbase. In-memory only (no
    // SMLDb/QuorumDb persistence yet — a restart re-requests a cold-start
    // mnlistdiff(zero, tip), see main_dash.cpp handshake driver).
    vendor::CSimplifiedMNList& sml() { return m_sml; }
    QuorumManager&             qmgr() { return m_qmgr; }
    const vendor::CSimplifiedMNList& sml() const { return m_sml; }
    const QuorumManager&             qmgr() const { return m_qmgr; }

    /// Mark whether a valid SML is present (set by the maintainer after the
    /// first accepted mnlistdiff yields a non-empty list). When require_sml
    /// is enabled (the mainnet / DIP-0004 posture), viability additionally
    /// requires this — the embedded arm must NOT serve a template with an
    /// empty/absent CCbTx (that block would be consensus-invalid).
    void set_have_sml(bool v) { m_have_sml = v; }
    bool have_sml() const { return m_have_sml; }

    /// Seed the version-appropriate CCbTx fields the SML/quorum roots do not
    /// carry: the best-ChainLock height+signature and the DIP-0027 credit-pool
    /// balance. Sourced by the maintainer from the diff's embedded cbTx (the
    /// authoritative wire form as-of blockHash) and from new_chainlock events.
    void set_best_cl(int32_t height, const std::array<uint8_t, 96>& sig) {
        m_best_cl_height = height;
        m_best_cl_sig    = sig;
    }
    void set_credit_pool(int64_t balance) { m_credit_pool = balance; }
    int32_t best_cl_height() const { return m_best_cl_height; }
    int64_t credit_pool() const { return m_credit_pool; }

    /// Enable the SML-required viability gate. main_dash.cpp turns this on for
    /// the embedded coin-P2P arm so a template is only served once the CCbTx
    /// commitment inputs are present (review finding H3: no mid-sync half-built block).
    /// Default OFF preserves the pre-CCbTx KAT/testnet posture byte-for-byte.
    void set_require_sml(bool v) { m_require_sml = v; }

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
                                 && (!m_utxo_ready_fn || m_utxo_ready_fn())
                                 && (!m_require_sml || m_have_sml);
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
        // CCbTx seams: pass the SML + quorum set ONLY when present, so a
        // legacy/testnet-without-SML bundle still builds the pre-CCbTx template
        // (empty payload) byte-for-byte, while a live daemonless bundle emits
        // the real type-5 coinbase. build_embedded_workdata folds these into
        // build_embedded_cbtx (merkleRootMNList + merkleRootQuorums + bestCL* +
        // creditPool) when both pointers are non-null.
        if (m_have_sml) {
            e.sml              = &m_sml;
            e.qmgr             = &m_qmgr;
            e.best_cl_height   = m_best_cl_height;
            e.best_cl_sig      = m_best_cl_sig;
            e.credit_pool      = m_credit_pool;
        }
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
    vendor::CSimplifiedMNList m_sml;         // merkleRootMNList source (mnlistdiff-fed)
    QuorumManager  m_qmgr;                    // merkleRootQuorums source (quorum-tail-fed)
    int32_t  m_best_cl_height{0};             // best observed ChainLock height
    std::array<uint8_t, 96> m_best_cl_sig{};  // best observed ChainLock signature
    int64_t  m_credit_pool{0};                // DIP-0027 credit-pool balance (seeded from cbTx)
    bool     m_have_sml{false};               // a non-empty SML has been applied
    bool     m_require_sml{false};            // gate viability on have_sml (embedded arm)
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
