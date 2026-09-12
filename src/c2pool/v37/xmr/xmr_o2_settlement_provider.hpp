// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_o2_settlement_provider.hpp   (Track A2 / X9 OPTION B)
//
// THE OPTION-B TEMPLATE PROVIDER — the serve-side analogue of
// MonerodTemplateProvider (xmr_o2_template.hpp, option A), but the block bytes
// it serves and submits are the v37 K_fair SETTLEMENT coinbase, not monerod's
// single-output get_block_template.
//
// Flow, once per refresh (main thread):
//   monerod get_miner_data  ->  node::MinerData (major/height/prev_id/seed/
//                               difficulty/median_weight/already_generated_coins)
//        |                       + an (empty on regtest) tx backlog
//        v
//   build_settlement_source(scfg, XmrParentContext, OwedLedger, pay_of, hint)
//        |  (xmr_o2_settlement_fixture.hpp -> XmrOwedSettlementSource: projects
//        |   the W4 K_fair owed set into x6::CoinbaseInputs, fail-closed)
//        v
//   XmrBlockAssembler::build(AssemblyInputs{from_miner_data, backlog, settle})
//        |  (xmr_block_assembly.hpp: reward/payee-set fixpoint, weight-aware cap)
//        v
//   AssembledTemplate  ->  hashing_blob(en) served to miners
//                          materialize(en) -> BlockBytes -> submit_block payload
//
// The three consumer seams the O-2 serve path already speaks to option A are
// re-implemented over the AssembledTemplate so main_v37_xmr.cpp branches with a
// few lines and reuses the listener / RandomX gate / LiveBlockSubmitter /
// finalize-connect UNCHANGED:
//   * XmrSettlementTemplateProvider   — mirrors MonerodTemplateProvider's
//       refresh()/template_id()/current()/by_id()/last_error()/counters, plus
//       difficulty_by_id() for the exact 128-bit network gate and
//       candidate_by_id() for the submit path.
//   * SettlementStratumTemplateSource — strat::ITemplateSource over the snapshot
//       (get_job/rebuild_blob/max_extra_nonces). extra_nonce IS baked into the
//       miner_tx 0x02 tag, so distinct extra_nonce => distinct blob (real
//       per-worker search spaces, unlike option A's single blob).
//
// CONSENSUS STATUS: defines NO v37 consensus digest. It READS OwedLedger::
// owed_digest() (through the settlement source) and serialises it into the
// Monero coinbase tx_extra 0x03; the Monero block is validated by monerod
// (RandomX + HF13 exact-sum), not by any v37 rule. Single-pool FOUND->FINALIZE
// is safe pool-local. The two multi-node lane-consensus rulings (KFairSource,
// lane_commitment source + the canonical_coinbase_matches ACCEPT gate on peers)
// are surfaced as EXPLICIT config in XmrSettlementConfig and are NOT wired here
// as a peer-reject gate — that seam is handed to the operator.
//
// THREADING: refresh() = main thread (reads the ledger, pumps + reads the miner
// data source). current()/by_id()/difficulty_by_id()/candidate_by_id()/
// template_id() and the ITemplateSource methods are any-thread (mutex snapshot
// copy / shared_ptr to an immutable AssembledTemplate). A retained snapshot
// outlives every in-flight job that can still name its template_id.
//
// ---------------------------------------------------------------------------
// C4 REBIND (native-minimal Monero node, Wave 1). The flow line above that read
// "monerod get_miner_data -> node::MinerData" is now
//
//     IMinerDataSource::snapshot() -> node::MinerData
//
// and NOTHING BELOW IT CHANGED. The assembler, the X6 settlement source, the
// reward/payee fixpoint, the exact-sum residual sink, the owed_digest in
// tx_extra 0x03 and the retained-template ring are untouched: assemble() below
// is the same function it was, fed from a seam instead of from a socket. That
// is the point of the seam -- the K_fair coinbase shape cannot drift when the
// code that builds it did not move.
//
// Two sources implement the seam (src/impl/xmr/native/template/):
//   * MonerodMinerDataSource -- the get_miner_data RPC path, verbatim. Still
//     the default, still never removed.
//   * NativeMinerDataSource  -- the C2c chain index + the C3 relayed txpool. A
//     template built through it makes NO daemon call at all.
//
// The two constructors below are the only difference a caller sees. The legacy
// (IMonerodTransport&) one behaves exactly as before: it OWNS a
// MonerodMinerDataSource and pumps it once per refresh, which is the same one
// RPC per refresh the old body did, and it rebuilds on exactly the same
// condition — the parent tip moved. The daemon arm reports no backlog sequence
// (it is frozen at 0), so the epoch term added below cannot make the production
// path rebuild on anything the old path ignored. The native arm's backlog
// sequence is ADDITIVE and opt-in, off by default. The (IMinerDataSource&) one takes whichever
// arm the ArmResolver picked, plus an optional pump for arms that need one --
// the native arm does not, which is why its refresh costs no I/O at all.
// ===========================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/miner_data.hpp"          // IMinerDataSource / MinerDataEpoch (C4 seam)
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp" // MonerodMinerDataSource (the daemon arm)
#include "impl/xmr/node/monero_rpc.hpp"             // MoneroDaemonRpc::body_get_miner_data / parse_miner_data
#include "impl/xmr/node/monerod_transport.hpp"      // IMonerodTransport / RpcResponse
#include "impl/xmr/node/xmr_node_types.hpp"         // node::MinerData / TxBacklogEntry / Hash / Difficulty128
#include "impl/xmr/stratum/xmr_stratum.hpp"         // ITemplateSource / TemplateJob
#include "impl/xmr/template/xmr_block_assembly.hpp" // XmrBlockAssembler / AssembledTemplate / from_miner_data / from_backlog / BlockBytes
#include "xmr_o2_settlement_fixture.hpp"            // XmrSettlementConfig / XmrParentContext / XmrOwedFixture / build_settlement_source / assembly_settle_inputs
#include "xmr_live_submit.hpp"                       // submit::BlockCandidate

namespace c2pool::v37n::xmr::o2 {

namespace strat  = ::v37::xmr::stratum;
namespace asm_   = ::c2pool::xmr::assembly;
namespace node   = ::c2pool::xmr::node;
namespace native = ::c2pool::xmr::native;         // C4 seam: IMinerDataSource
namespace ntmpl  = ::c2pool::xmr::native::tmpl;   // C4 arms

// One immutable, refcounted settlement template snapshot the serve + submit side
// share. The AssembledTemplate is heap-owned and immutable after build(), so a
// listener thread may materialize()/hashing_blob() while the main thread builds
// the next one.
struct SettlementSnapshot {
    std::uint32_t                            template_id = 0;
    std::shared_ptr<const asm_::AssembledTemplate> tpl;   // the v37 whole-block builder result
    std::uint64_t                            height = 0;
    std::uint64_t                            difficulty = 0;       // network difficulty lo64
    std::uint64_t                            difficulty_top64 = 0; // hi64
    std::uint64_t                            reward = 0;           // Σ coinbase outputs (piconero)
    std::uint8_t                             major_version = 0;
    std::size_t                              nonce_offset = 0;
    node::Hash                               prev_id{};
    std::array<std::uint8_t, strat::HASH_SIZE> seed_hash{};
    std::size_t                              n_outputs = 0;
    std::size_t                              n_tx = 0;
    bool                                     valid = false;

    // --- C4: which arm produced this template, and under which epoch --------
    // Carried so the parity oracle can attribute a diff to an arm without
    // guessing, and so the status line can say what it is actually serving.
    // "monerod" | "native" (a literal owned by the source, never freed).
    const char*             source_name = "monerod";
    native::MinerDataEpoch  epoch{};
};

// ---------------------------------------------------------------------------
// XmrSettlementTemplateProvider — the option-B provider.
// ---------------------------------------------------------------------------
class XmrSettlementTemplateProvider {
public:
    // The refresh-time pump for a source that needs one (the daemon arm's
    // get_miner_data round trip). Empty for the native arm, which reads its
    // chain index and txpool directly.
    using RefreshPump = std::function<bool(std::string*)>;

    // OPTIONAL SHAPE GATE (M2). Called on a freshly assembled template BEFORE
    // it is retained, published or given a template_id. Returning false makes
    // the refresh fail with the gate's reason and leaves the PREVIOUS template
    // in place, so a shape regression parks the miners on the last good block
    // instead of handing them one that pays the wrong set.
    //
    // It exists because the seam this provider is bound through can be
    // rebound -- to the daemon, to the native node, later to something else --
    // and "the assembler is unchanged" is a claim about the code, while what
    // has to hold is a claim about the BYTES. See
    // xmr_settlement_coinbase_shape.hpp for the gate the daemon installs.
    using ShapeGate = std::function<bool(const asm_::AssembledTemplate&, std::string*)>;

    // --- C4 seam constructor -------------------------------------------------
    // `source` is whichever arm the ArmResolver picked. The provider does not
    // own it and does not choose it: an arm that stops being ready is the
    // resolver's problem, not the assembler's.
    XmrSettlementTemplateProvider(native::IMinerDataSource& source,
                                  XmrOwedFixture& ledger_owner,
                                  XmrSettlementConfig scfg,
                                  std::uint64_t share_diff,
                                  RefreshPump pump = {})
        : m_src(&source), m_pump(std::move(pump)), m_ledger(ledger_owner),
          m_scfg(std::move(scfg)), m_share_diff(share_diff) {}

    // --- legacy constructor, behaviour-identical -----------------------------
    // `ledger_owner` supplies the (possibly seeded, possibly empty) OwedLedger +
    // its pay_of resolver. `scfg` is the fail-closed lane-parameter surface
    // (residual sink REQUIRED + torsion-checked at build). `share_diff` mirrors
    // option A (0 => solo/network target).
    //
    // Owns a MonerodMinerDataSource over `transport` and pumps it once per
    // refresh: exactly the one get_miner_data per refresh this constructor
    // always did.
    XmrSettlementTemplateProvider(node::IMonerodTransport& transport,
                                  XmrOwedFixture& ledger_owner,
                                  XmrSettlementConfig scfg,
                                  std::uint64_t share_diff)
        : m_owned_src(std::make_unique<ntmpl::MonerodMinerDataSource>(transport)),
          m_ledger(ledger_owner), m_scfg(std::move(scfg)),
          m_share_diff(share_diff) {
        auto* daemon = static_cast<ntmpl::MonerodMinerDataSource*>(m_owned_src.get());
        m_src  = daemon;
        m_pump = [daemon](std::string* why) { return daemon->poll(why); };
    }

    // MAIN THREAD, before the first refresh(). Not settable while serving.
    void set_shape_gate(ShapeGate g) { m_shape_gate = std::move(g); }

    XmrSettlementTemplateProvider(const XmrSettlementTemplateProvider&) = delete;
    XmrSettlementTemplateProvider& operator=(const XmrSettlementTemplateProvider&) = delete;

    // MAIN THREAD. Pump the source (a no-op for the native arm), read one
    // MinerData snapshot, assemble a fresh v37 settlement template when the
    // epoch moved. Returns true when a valid template is cached (new or
    // unchanged); the human reason for a failure is kept in last_error().
    bool refresh() {
        if (!m_src) { set_error("no miner data source bound"); m_failures.fetch_add(1); return false; }

        if (m_pump) {
            std::string pump_why;
            if (!m_pump(&pump_why)) {
                set_error(pump_why.empty() ? "miner data source: no response" : pump_why);
                m_failures.fetch_add(1);
                return false;
            }
        }

        std::string src_why;
        std::optional<node::MinerData> got = m_src->snapshot(&src_why);
        if (!got) {
            set_error(src_why.empty() ? "miner data source: not ready" : src_why);
            m_failures.fetch_add(1);
            return false;
        }
        node::MinerData md = std::move(*got);
        if (!md.valid()) { set_error("miner data source: invalid miner_data"); m_failures.fetch_add(1); return false; }

        const native::MinerDataEpoch ep = m_src->epoch();
        node::Hash md_prev = md.prev_id;
        // EPOCH UNCHANGED => keep the existing template BYTE-FOR-BYTE. This is
        // load-bearing: XmrBlockAssembler stamps a fresh header timestamp on each
        // build, so re-assembling under the same id would change the bytes a
        // miner is already grinding (its shares would then miss on the daemon's
        // re-hash — "Low diff"). Only reassemble when the epoch moves.
        //
        // The epoch is (height, prev_id, backlog_seq). The first two ARE the old
        // tip rule, character for character. The third is C4's addition and is
        // an OPT-IN trigger that no arm reports unless it was configured to:
        //
        //   monerod arm  backlog_seq is frozen at 0 (xmr_monerod_miner_data.hpp).
        //                The conjunct below is 0 == 0 on every refresh, so THE
        //                DEFAULT/PRODUCTION PATH TAKES EXACTLY THE DECISION IT
        //                TOOK BEFORE THE SEAM EXISTED — a rebuild when, and only
        //                when, the parent tip moves.
        //   native arm   backlog_seq is frozen for the life of a tip under the
        //                default tip-only policy (backlog_refresh_s == 0), and
        //                moves under an unchanged tip only when an operator sets
        //                a non-zero refresh interval, which is a NEW JOB by
        //                explicit configuration rather than a silent restamp.
        //
        // Anything else would restamp the header timestamp under miners who are
        // already grinding the current bytes, and their in-flight shares would
        // miss on re-hash.
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (m_cur.valid && m_cur.height == md.height && m_cur.prev_id == md_prev
                && m_cur.epoch.backlog_seq == ep.backlog_seq) {
                m_last_error.clear();
                m_refreshes.fetch_add(1);
                return true;
            }
        }

        std::string why;
        SettlementSnapshot snap;
        if (!assemble(md, snap, why)) { set_error(why); m_failures.fetch_add(1); return false; }
        snap.source_name = m_src->name();
        snap.epoch       = ep;

        m_refreshes.fetch_add(1);
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last_error.clear();
        // The ARTEFACT the current template was built from. C6's P-TPL seam
        // compares what was SERVED against what the shadow arm would have said,
        // and an epoch tag alone cannot prove a served mismatch -- so the miner
        // data is kept here rather than re-read from the source later, by which
        // time the arm may have moved on. Kept beside m_cur (not inside the
        // snapshot) so that by_id()/current() stay cheap to copy.
        m_cur_miner = md;
        snap.template_id = ++m_id_counter;   // a real tip change => a fresh template + job
        m_changes.fetch_add(1);
        retain(snap);
        m_cur = std::move(snap);
        m_tid.store(m_cur.template_id, std::memory_order_release);
        return true;
    }

    // --- MonerodTemplateProvider-shaped surface (any thread) ----------------
    SettlementSnapshot current() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_cur;
    }
    bool by_id(std::uint32_t id, SettlementSnapshot& out) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_ring.find(id);
        if (it == m_ring.end() || !it->second.valid) return false;
        out = it->second;
        return true;
    }
    std::uint32_t template_id() const { return m_tid.load(std::memory_order_acquire); }
    std::string   last_error() const { std::lock_guard<std::mutex> lk(m_mtx); return m_last_error; }
    std::string   offset_note() const { return {}; }   // no derived-offset surprise: we own the layout
    std::uint64_t refreshes() const { return m_refreshes.load(); }
    std::uint64_t failures()  const { return m_failures.load(); }
    std::uint64_t changes()   const { return m_changes.load(); }

    // 128-bit network difficulty for a retained template — the exact gate input.
    bool difficulty_by_id(std::uint32_t id, std::uint64_t& lo, std::uint64_t& hi) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_ring.find(id);
        if (it == m_ring.end() || !it->second.valid) return false;
        lo = it->second.difficulty; hi = it->second.difficulty_top64;
        return true;
    }

    // The submit-path candidate for (template_id, extra_nonce). Materialises the
    // full block blob + the exact served hashing blob (both from the SAME
    // AssembledTemplate), plus every offset the submitter patches. false =>
    // template gone (stale) or a layout invariant failed.
    bool candidate_by_id(std::uint32_t id, std::uint32_t extra_nonce,
                         submit::BlockCandidate& out, std::string* why = nullptr) const {
        SettlementSnapshot snap;
        if (!by_id(id, snap) || !snap.tpl) { if (why) *why = "settlement template gone (stale)"; return false; }
        asm_::BlockBytes b;
        std::string me;
        if (!snap.tpl->materialize(extra_nonce, b, &me)) { if (why) *why = "materialize: " + me; return false; }
        out.template_id     = id;
        out.height          = snap.height;
        out.full_blob       = b.full_blob;
        out.hashing_blob    = b.hashing_blob;
        out.nonce_offset    = b.nonce_offset;
        out.reserved_offset = 0;                 // extra_nonce is BAKED into the miner_tx, not spliced
        out.reserved_size   = 0;
        out.prev_id         = snap.prev_id;
        out.expected_reward = snap.reward;
        out.major_version   = snap.major_version;
        return true;
    }

    // Fill a stratum job blob for (template_id, extra_nonce). Shared by get_job
    // (current id) and rebuild_blob (a specific id).
    bool fill_job(std::uint32_t id, std::uint32_t extra_nonce, strat::TemplateJob& out) const {
        SettlementSnapshot snap;
        if (!by_id(id, snap) || !snap.tpl) return false;
        out.blob                 = snap.tpl->hashing_blob(extra_nonce);
        out.nonce_offset         = snap.nonce_offset;
        out.template_id          = id;
        out.height               = snap.height;
        out.mainchain_target     = network_target(snap.difficulty, snap.difficulty_top64);
        out.lane_target          = m_share_diff
                                       ? std::max(target_from_diff(m_share_diff), out.mainchain_target)
                                       : out.mainchain_target;
        out.seed_hash            = snap.seed_hash;
        out.next_seed_hash       = std::nullopt;
        out.monero_major_version = snap.major_version;
        return !out.blob.empty();
    }

    std::uint32_t current_id() const { return m_tid.load(std::memory_order_acquire); }

    // The MinerData the CURRENT template was assembled from, or false when no
    // template has been built. This is the served artefact C6 judges; feeding
    // the oracle a fresh read of the source instead would compare the shadow
    // arm against something the miners were never handed.
    bool last_miner_data(node::MinerData& out) const {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (!m_cur.valid) return false;
        out = m_cur_miner;
        return true;
    }

    // --- C4: which arm is bound, for the status line and the parity oracle ---
    const char* source_name() const { return m_src ? m_src->name() : "none"; }
    native::MinerDataReadiness source_readiness() const {
        return m_src ? m_src->readiness() : native::MinerDataReadiness{};
    }
    native::MinerDataEpoch source_epoch() const {
        return m_src ? m_src->epoch() : native::MinerDataEpoch{};
    }
    // The body of a transaction the CURRENT source selected. C5's ARM A needs
    // this to answer a peer's fluffy missing-tx request; the daemon arm returns
    // nullptr, because with a daemon armed it is ARM B that delivers.
    const std::vector<std::uint8_t>* tx_body(const node::Hash& id) const {
        return m_src ? m_src->tx_body(id) : nullptr;
    }

    // 64-bit target helpers (identical rule to MonerodStratumTemplateSource).
    static std::uint64_t target_from_diff(std::uint64_t diff) {
        return diff ? (0xFFFFFFFFFFFFFFFFULL / diff) : 0xFFFFFFFFFFFFFFFFULL;
    }
    static std::uint64_t network_target(std::uint64_t lo, std::uint64_t hi) {
        if (hi) return 1;                       // a >2^64 difficulty: hardest u64 target; exact gate re-checks
        return target_from_diff(lo);
    }

private:
    static constexpr std::size_t RING = 6;      // retain a few templates so in-flight jobs resolve

    void set_error(std::string e) { std::lock_guard<std::mutex> lk(m_mtx); m_last_error = std::move(e); }

    // Add a new snapshot to the retain ring, evicting the oldest id beyond RING.
    void retain(const SettlementSnapshot& snap) {   // caller holds m_mtx
        m_ring[snap.template_id] = snap;
        m_order.push_back(snap.template_id);
        while (m_order.size() > RING) {
            const std::uint32_t old = m_order.front();
            m_order.pop_front();
            if (old != snap.template_id) m_ring.erase(old);
        }
    }

    // Turn one MinerData into a v37 settlement AssembledTemplate.
    bool assemble(const node::MinerData& md, SettlementSnapshot& snap, std::string& why) {
        // lane parameters that track the tip: major_version (CARROT fence key)
        // and chain_id (== ledger.chain()). Everything else is operator config.
        XmrSettlementConfig scfg = m_scfg;
        scfg.monero_major_version = md.major_version;
        scfg.chain_id             = m_ledger.ledger().chain();

        // The XMR miner-data view the assembler consumes. lane_target is stored
        // only (not used in block bytes); carry the network difficulty for tidiness.
        ::c2pool::xmr::difficulty_type lane_t; lane_t.lo = md.difficulty.lo; lane_t.hi = md.difficulty.hi;
        ::c2pool::xmr::XmrMinerData xmr_md = asm_::from_miner_data(md, lane_t);

        const std::uint64_t base_reward = asm_::xmr_base_reward(md.already_generated_coins);
        std::uint64_t fees = 0;
        for (const auto& t : md.tx_backlog) fees += t.fee;

        XmrParentContext parent = XmrParentContext::from_miner(xmr_md, base_reward, fees);

        std::string ss_why;
        std::unique_ptr<XmrOwedSettlementSource> src = build_settlement_source(
            scfg, parent, m_ledger.ledger(), m_ledger.pay_of(),
            /*reward_hint=*/base_reward + fees, &ss_why);
        if (!src) { why = "settlement source refused: " + ss_why; return false; }

        asm_::AssemblyInputs a;
        a.miner   = xmr_md;
        a.mempool = asm_::from_backlog(md.tx_backlog);       // empty on regtest => n_tx == 0
        a.settle  = assembly_settle_inputs(*src, /*weight_aware_cap=*/true);

        std::string as_why;
        std::unique_ptr<asm_::AssembledTemplate> tpl = asm_::XmrBlockAssembler::build(a, &as_why);
        if (!tpl) { why = "assembler refused: " + as_why; return false; }

        // A probe materialisation locks in the layout (nonce offset, blob sizes).
        asm_::BlockBytes probe;
        std::string pe;
        if (!tpl->materialize(0, probe, &pe)) { why = "probe materialize: " + pe; return false; }

        // The shape gate, on the assembled bytes, before anything is published.
        if (m_shape_gate) {
            std::string gw;
            if (!m_shape_gate(*tpl, &gw)) {
                why = "coinbase shape gate REFUSED: " + (gw.empty() ? std::string("no reason given") : gw);
                return false;
            }
        }

        snap.tpl              = std::shared_ptr<const asm_::AssembledTemplate>(tpl.release());
        snap.height           = snap.tpl->height();
        snap.difficulty       = md.difficulty.lo;
        snap.difficulty_top64 = md.difficulty.hi;
        snap.reward           = snap.tpl->reward();
        snap.major_version    = snap.tpl->major_version();
        snap.nonce_offset     = probe.nonce_offset;
        std::memcpy(snap.prev_id.data(), snap.tpl->prev_id().data(), 32);
        std::memcpy(snap.seed_hash.data(), md.seed_hash.data(), strat::HASH_SIZE);
        snap.n_outputs        = snap.tpl->outputs().size();
        snap.n_tx             = snap.tpl->n_tx();
        snap.valid            = true;
        why.clear();
        return true;
    }

    // The C4 seam. m_owned_src is non-null only for the legacy transport
    // constructor, which owns the daemon arm it built; m_src always points at
    // the arm in use, owned here or not.
    std::unique_ptr<native::IMinerDataSource> m_owned_src;
    native::IMinerDataSource*                 m_src = nullptr;
    RefreshPump                               m_pump;
    ShapeGate                                 m_shape_gate;

    XmrOwedFixture&          m_ledger;
    XmrSettlementConfig      m_scfg;
    std::uint64_t            m_share_diff;

    mutable std::mutex m_mtx;
    SettlementSnapshot m_cur;
    node::MinerData    m_cur_miner;                       // what m_cur was built from
    std::map<std::uint32_t, SettlementSnapshot> m_ring;   // retained by id
    std::deque<std::uint32_t> m_order;
    std::uint32_t m_id_counter = 0;
    std::string   m_last_error;
    std::atomic<std::uint32_t> m_tid{0};
    std::atomic<std::uint64_t> m_refreshes{0}, m_failures{0}, m_changes{0};
};

// ---------------------------------------------------------------------------
// SettlementStratumTemplateSource — strat::ITemplateSource over the provider.
// Serves the v37 settlement hashing blob per (template_id, extra_nonce).
// ---------------------------------------------------------------------------
class SettlementStratumTemplateSource final : public strat::ITemplateSource {
public:
    explicit SettlementStratumTemplateSource(const XmrSettlementTemplateProvider& provider)
        : m_provider(provider) {}

    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        const std::uint32_t id = m_provider.current_id();
        if (id == 0) return false;
        return m_provider.fill_job(id, extra_nonce, out);
    }
    bool rebuild_blob(std::uint32_t template_id, std::uint32_t extra_nonce,
                      strat::TemplateJob& out) override {
        return m_provider.fill_job(template_id, extra_nonce, out);   // false => Stale
    }
    // The miner_tx bakes a per-worker extra_nonce (distinct blob per worker),
    // unlike option A's single blob. Bound a broadcast batch generously.
    std::uint32_t max_extra_nonces() const override { return 65536; }

private:
    const XmrSettlementTemplateProvider& m_provider;
};

} // namespace c2pool::v37n::xmr::o2
