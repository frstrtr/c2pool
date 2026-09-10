// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp
//                        (Track A2 / X9 option B — the settlement SOURCE, the
//                         construction layer that FEEDS XmrOwedSettlementSource)
//
// XmrOwedSettlementSource (xmr_o2_settlement_source.hpp) is the IXmrSettlement-
// Source VALUE that the whole-block template calls into. This header is the
// piece that BUILDS it deterministically and fail-closed for the FOUND->
// FINALIZE proof: it owns the Option-B *config surface*, the hand-built
// XmrCoinbaseContext, and the fixture OwedLedger — the three things the survey
// (item E, "the settlement source feeding it") lists as still unwritten because
// the observe-side X9 daemon has no live XMR OwedLedger yet (Track A2 S-1
// emission, task #27).
//
// WHY A SEPARATE HEADER (not an edit to xmr_node_config.hpp / the source):
//   * xmr_node_config.hpp today carries only the Option-A payout_address knob.
//     Option B needs a residual-sink descriptor, h_min, output_cap, chain_id,
//     the KFairSource ruling and the lane_commitment source knob. Those are a
//     COHESIVE, fail-closed value struct (XmrSettlementConfig) — kept here so
//     the assemble step wires it into XmrNodeConfig with a one-line
//     `std::optional<XmrSettlementConfig> settlement;` add, rather than this
//     component editing the shared config header.
//   * XmrOwedSettlementSource::build() already does every byte of the seam
//     projection + X6 crypto. This header does NOT reimplement it — it produces
//     the XmrCoinbaseContext + the ledger it consumes, then forwards to it.
//
// WHAT THIS FEEDS (the consumer graph, all in src/impl/xmr + src/c2pool/v37/xmr):
//
//     XmrSettlementConfig + XmrParentContext + OwedLedger
//                 |  make_xmr_coinbase_context()      (fail-closed, no crypto)
//                 v
//           XmrCoinbaseContext ---- XmrOwedSettlementSource::build() ----> src
//                                        (r, R, P_i, view tags, MM leaf, order)
//                 |                              |
//                 |  assembly_settle_inputs(src) |  src->seam()
//                 v                              v
//        AssemblyInputs.settle  ------> XmrBlockAssembler::build() -> AssembledTemplate
//        (the K_fair owed set +          (reward/payee-set fixpoint; the assembler
//         lane params: the coinbase       re-runs X6 over these owed entries and
//         OUTPUTS the block pays)         emits the whole Monero block)
//
// So the miner_tx the pool assembles pays the v37 K_fair payees (oldest-owed-
// first EffectiveOwed ++ fixed ++ exact-sum residual sink), NOT a single miner
// output. On an EMPTY ledger the whole reward flows to the residual sink — the
// cleanest FOUND->FINALIZE proof shape (one coinbase output, no owed tail).
//
// CONSENSUS GATE (unchanged from the source header): this defines NO v37
// consensus digest. It only READS OwedLedger::owed_digest() and serialises it
// into the Monero coinbase's tx_extra 0x03; the Monero block is validated by
// monerod (RandomX + HF13 exact-sum), not by any v37 rule. The single-pool
// proof needs no operator tap. Two knobs are LANE consensus the moment Option B
// goes multi-node — `kfair` (which K_fair rule picks the payees) and
// `lc_source` (which value r and the MM root bind). Both were RULED by the
// operator on 2026-09-10 and are now PINNED, fail-closed, in
// validate_structural(): kfair == W4Propose (the one ratified K_fair rule,
// whitepaper E-1) and lc_source == StateRoot (the whitepaper §13
// StateCommitment Merkle root). This PR ships them as a DRAFT: the operator
// merges/activates, never a silent flip.
//
// FAIL-CLOSED (defence in depth over XmrOwedSettlementSource::build's own):
//   * residual_sink MUST be a well-formed XMR ref (kind XMR_STD/XMR_SUB, 64-B
//     payload) here, AND torsion-valid under the installed ed25519 point-check
//     backend at build() — no backend => build() refuses (BadSinkDescriptor).
//   * output_cap must leave room for fixed + the sink (>= fixed.size() + 1).
//   * ctx.chain_id must equal ledger.chain(); CARROT fence major_version <= 16.
//   * every fixed output must be a well-formed XMR ref.
//   None of these throw: every entry point returns std::nullopt / nullptr with
//   a human-readable *why, exactly as the rest of the O-2 consumer tree does.
// ===========================================================================
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/coin/xmr_crypto_types.hpp"        // Hash256, Bytes32
#include "impl/xmr/settle/xmr_coinbase.hpp"          // x6::FixedOutput, CoinbaseInputs
#include "impl/xmr/template/xmr_block_template.hpp"   // XmrMinerData (parent-context bridge)
#include "xmr_o2_settlement_source.hpp"              // XmrOwedSettlementSource, XmrCoinbaseContext, KFairSource

namespace c2pool::v37n::xmr::o2 {

// x6, OwedLedger, PayOfFn, AgeOfFn, KFairSource, XmrCoinbaseContext,
// XmrOwedSettlementSource, lane_commitment_from_owed_digest all come in from
// xmr_o2_settlement_source.hpp (same namespace).

// ---------------------------------------------------------------------------
// Which digest r and the MM root bind. A consensus ruling the moment Option B
// is multi-node (survey gate flag (2)); explicit here until tapped.
// ---------------------------------------------------------------------------
// RULED 2026-09-10 (multi-node): StateRoot. The other two are refused by
// validate_structural unless allow_nonruled_local_only is set for a
// single-pool experiment (never for a lane with peers).
// ---------------------------------------------------------------------------
enum class LaneCommitmentSource : std::uint8_t {
    OwedDigest = 0,   // ledger.owed_digest() — the §4.5 OWED commitment (pre-ruling default)
    Explicit   = 1,   // an operator-supplied bytes32 (lane digest / SettlementView::digest)
    StateRoot  = 2,   // RULED: the whitepaper §13 StateCommitment Merkle root
};

inline const char* to_string(LaneCommitmentSource s) {
    switch (s) {
        case LaneCommitmentSource::OwedDigest: return "owed-digest";
        case LaneCommitmentSource::Explicit:   return "explicit";
        case LaneCommitmentSource::StateRoot:  return "state-root";
    }
    return "?";
}

// Parse the --lane-commitment operator flag. Returns false on an unknown name.
inline bool parse_lane_commitment_source(const std::string& s, LaneCommitmentSource& out) {
    if (s == "state-root"  || s == "state_root")  { out = LaneCommitmentSource::StateRoot;  return true; }
    if (s == "owed-digest" || s == "owed_digest") { out = LaneCommitmentSource::OwedDigest; return true; }
    if (s == "explicit")                          { out = LaneCommitmentSource::Explicit;   return true; }
    return false;
}

// ---------------------------------------------------------------------------
// hex helpers (64-hex -> 32 bytes). Boundary-only; the canon never holds a
// printable string. Returns false on any non-hex char or a length != 64.
// ---------------------------------------------------------------------------
inline bool hex32(const std::string& s, std::array<std::uint8_t, 32>& out) {
    if (s.size() != 64) return false;
    auto nib = [](char c, int& v) -> bool {
        if (c >= '0' && c <= '9') { v = c - '0';        return true; }
        if (c >= 'a' && c <= 'f') { v = c - 'a' + 10;   return true; }
        if (c >= 'A' && c <= 'F') { v = c - 'A' + 10;   return true; }
        return false;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        int hi = 0, lo = 0;
        if (!nib(s[2 * i], hi) || !nib(s[2 * i + 1], lo)) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

// ---------------------------------------------------------------------------
// XmrSettlementConfig — the Option-B lane-parameter surface (consumer-tree).
// Every field is either a lane parameter (consensus once tapped) or a fence.
// Defaults are the safe pre-CARROT, XMR-dust-0 shape; the sink is REQUIRED.
// ---------------------------------------------------------------------------
struct XmrSettlementConfig {
    // --- lane identity + fence ---
    ::v37::ChainId chain_id = 0;                    // == OwedLedger::chain()
    std::uint8_t   monero_major_version =           // pre-CARROT fence (<= 16)
        ::v37::xmr::XMR_PRECARROT_MAX_MAJOR_VERSION;

    // --- owed-emission policy ---
    std::uint64_t  h_min      = ::v37::xmr::XMR_DUST;  // piconero floor per owed output (0 on XMR)
    std::uint32_t  output_cap = 0;                     // TOTAL outputs cap C. 0 => output_cap_ceiling
    std::uint32_t  output_cap_ceiling = 2700;          // used when output_cap == 0 (wire cap analogue)

    // --- the mandated residual sink (REQUIRED; torsion-checked at build) ---
    ::v37::ScriptRef residual_sink;                    // XMR_STD/XMR_SUB, 64-B payload
    ::v37::bytes32   residual_sink_identity{};         // its ledger identity_key (payout-map key)

    // --- mandated fixed outputs (dev / donation / finder), usually empty ---
    std::vector<x6::FixedOutput> fixed;

    // --- RULED 2026-09-10 (multi-node consensus): both values are now pinned.
    //     kfair     == W4Propose : the ONE ratified K_fair rule (E-1).
    //     lc_source == StateRoot : the coinbase commits the §13 state root.
    //     Any other combination is REFUSED by validate_structural unless
    //     allow_nonruled_local_only is set (single-pool experiments only —
    //     a node that sets it can never agree with a ruled peer).
    KFairSource          kfair     = KFairSource::W4Propose;
    LaneCommitmentSource lc_source = LaneCommitmentSource::StateRoot;
    ::v37::bytes32       lane_commitment_explicit{};   // used iff lc_source == Explicit
    bool                 allow_nonruled_local_only = false;

    // ---- sink constructors (payout-target bytes, never address strings) ----
    // Set the sink from raw 32-byte key material; also fills residual_sink_identity.
    void set_residual_sink_std(const std::array<std::uint8_t, 32>& spend_B,
                               const std::array<std::uint8_t, 32>& view_A) {
        residual_sink          = ::v37::xmr::make_xmr_std(spend_B, view_A);
        residual_sink_identity = ::v37::xmr::xmr_identity_key(residual_sink);
    }
    void set_residual_sink_sub(const std::array<std::uint8_t, 32>& sub_spend_D,
                               const std::array<std::uint8_t, 32>& main_view_A) {
        residual_sink          = ::v37::xmr::make_xmr_sub(sub_spend_D, main_view_A);
        residual_sink_identity = ::v37::xmr::xmr_identity_key(residual_sink);
    }
    // Set the sink from 64-hex spend + view keys (the operator test-wallet ref).
    // sub == true builds an XMR_SUB ref (sub-spend D_i, main view A). Returns
    // false (leaving the sink untouched) on any malformed hex.
    bool set_residual_sink_hex(const std::string& spend_hex,
                               const std::string& view_hex, bool sub = false) {
        std::array<std::uint8_t, 32> p0{}, p1{};
        if (!hex32(spend_hex, p0) || !hex32(view_hex, p1)) return false;
        if (sub) set_residual_sink_sub(p0, p1);
        else     set_residual_sink_std(p0, p1);
        return true;
    }

    // Concrete TOTAL-outputs cap to hand XmrOwedSettlementSource::build (which,
    // unlike XmrBlockAssembler, requires a concrete cap, not the 0 sentinel).
    std::uint32_t resolved_output_cap() const {
        return output_cap != 0 ? output_cap : output_cap_ceiling;
    }

    // Structural, backend-free validity (torsion is enforced at build()).
    // Returns false and fills *why on any refusal.
    bool validate_structural(std::string* why = nullptr) const {
        auto no = [&](const std::string& m) { if (why) *why = m; return false; };
        if (!::v37::xmr::xmr_precarrot_ok(monero_major_version))
            return no("XmrSettlementConfig: monero_major_version > pre-CARROT max (16)");
        if (!::v37::xmr::xmr_ref_well_formed(residual_sink))
            return no("XmrSettlementConfig: residual_sink is not a well-formed XMR ref "
                      "(need an XMR_STD/XMR_SUB 64-B payload — set --residual-sink-*)");
        for (const auto& f : fixed)
            if (!::v37::xmr::xmr_ref_well_formed(f.pay))
                return no("XmrSettlementConfig: a fixed output is not a well-formed XMR ref");
        const std::uint32_t cap = resolved_output_cap();
        if (cap < fixed.size() + 1)
            return no("XmrSettlementConfig: output_cap leaves no room for fixed + sink "
                      "(need >= fixed.size() + 1)");
        if (lc_source == LaneCommitmentSource::Explicit &&
            lane_commitment_explicit == ::v37::bytes32{})
            return no("XmrSettlementConfig: lc_source == Explicit but lane_commitment_explicit is zero");
        // ---- the two multi-node rulings, enforced before any crypto ----
        if (kfair != KFairSource::W4Propose)
            return no("RULED 2026-09-10: KFairSource must be W4Propose "
                      "(canonical K_fair propose_coinbase, whitepaper E-1); got " +
                      std::string(to_string(kfair)));
        if (lc_source != LaneCommitmentSource::StateRoot && !allow_nonruled_local_only)
            return no("RULED 2026-09-10: lane_commitment must be the §13 StateCommitment "
                      "state root (--lane-commitment state-root); got " +
                      std::string(to_string(lc_source)) +
                      " (set allow_nonruled_local_only only for a single-pool experiment)");
        if (why) why->clear();
        return true;
    }
};

// ---------------------------------------------------------------------------
// XmrParentContext — the mainchain-tip scalars the coinbase binds. In
// production these come from the node's get_miner_data / get_block_template;
// for the proof they are the regtest tip. base_reward is the consensus subsidy
// (get_base_reward(already_generated_coins)); fees is Σ selected tx fees. When
// this context also feeds XmrBlockAssembler, major/height/prev_id MUST equal
// AssemblyInputs.miner's (the assembler overwrites them and re-derives r from
// the miner values, so a mismatch would desync r).
// ---------------------------------------------------------------------------
struct XmrParentContext {
    std::uint8_t         monero_major_version = ::v37::xmr::XMR_PRECARROT_MAX_MAJOR_VERSION;
    std::uint64_t        height = 0;             // unlock = height + 60
    ::xmr::coin::Hash256 prev_id{};              // parent block id (bin origin)
    std::uint64_t        base_reward = 0;        // consensus subsidy, piconero
    std::uint64_t        fees = 0;               // Σ selected tx fees, piconero

    std::uint64_t budget() const { return base_reward + fees; }

    // prev_id from a 64-hex Monero block id.
    bool set_prev_id_hex(const std::string& hex) {
        std::array<std::uint8_t, 32> b{};
        if (!hex32(hex, b)) return false;
        std::copy(b.begin(), b.end(), prev_id.data());
        return true;
    }

    // Bridge from the template leg's XmrMinerData (major/height/prev_id). The
    // subsidy is NOT in XmrMinerData (it carries already_generated_coins), so
    // base_reward + fees are supplied by the caller (the provider computes the
    // subsidy with the template leg's xmr_base_reward()).
    static XmrParentContext from_miner(const ::c2pool::xmr::XmrMinerData& m,
                                       std::uint64_t base_reward,
                                       std::uint64_t fees) {
        XmrParentContext p;
        p.monero_major_version = m.major_version;
        p.height               = m.height;
        std::memcpy(p.prev_id.data(), m.prev_id.h, 32);
        p.base_reward          = base_reward;
        p.fees                 = fees;
        return p;
    }
};

// ---------------------------------------------------------------------------
// Resolve the lane commitment r and the MM root bind, per the config's ruling.
// ---------------------------------------------------------------------------
inline ::v37::bytes32 resolve_lane_commitment(const XmrSettlementConfig& cfg,
                                              const OwedLedger& ledger) {
    switch (cfg.lc_source) {
        case LaneCommitmentSource::OwedDigest: return lane_commitment_from_owed_digest(ledger);
        case LaneCommitmentSource::Explicit:   return cfg.lane_commitment_explicit;
        case LaneCommitmentSource::StateRoot:  return lane_commitment_from_state_root(ledger);
    }
    return lane_commitment_from_state_root(ledger);   // RULED default
}

// ---------------------------------------------------------------------------
// Assemble the XmrCoinbaseContext from config + tip + ledger. Structural,
// backend-free (torsion is enforced by XmrOwedSettlementSource::build). Returns
// std::nullopt + *why on any structural refusal or a chain-id mismatch.
// ---------------------------------------------------------------------------
inline std::optional<XmrCoinbaseContext>
make_xmr_coinbase_context(const XmrSettlementConfig& cfg,
                          const XmrParentContext& parent,
                          const OwedLedger& ledger,
                          std::string* why = nullptr) {
    auto no = [&](const std::string& m) -> std::optional<XmrCoinbaseContext> {
        if (why) *why = m; return std::nullopt;
    };
    if (!cfg.validate_structural(why)) return std::nullopt;
    if (cfg.chain_id != ledger.chain())
        return no("make_xmr_coinbase_context: cfg.chain_id != ledger.chain()");
    if (cfg.monero_major_version != parent.monero_major_version)
        return no("make_xmr_coinbase_context: cfg.monero_major_version != parent tip major_version "
                  "(r would desync from the assembler's miner-derived r)");

    XmrCoinbaseContext ctx;
    ctx.monero_major_version   = parent.monero_major_version;
    ctx.height                 = parent.height;
    ctx.prev_id                = parent.prev_id;
    ctx.base_reward            = parent.base_reward;
    ctx.fees                   = parent.fees;
    ctx.chain_id               = cfg.chain_id;
    ctx.lane_commitment        = resolve_lane_commitment(cfg, ledger);
    ctx.residual_sink          = cfg.residual_sink;
    ctx.residual_sink_identity = cfg.residual_sink_identity;
    ctx.fixed                  = cfg.fixed;
    ctx.h_min                  = cfg.h_min;
    ctx.output_cap             = cfg.resolved_output_cap();
    if (why) why->clear();
    return ctx;
}

// ---------------------------------------------------------------------------
// Build the settlement source for a template: make the context, then forward
// to XmrOwedSettlementSource::build (which projects the K_fair owed set, runs
// X6 once — r, R, P_i, view tags, MM leaf, canonical order — and fails closed
// on the CARROT fence / bad sink / cap / chain mismatch / derivation).
//
//   reward_hint : the exact-sum budget the owed set is chosen at. 0 =>
//                 parent.budget() (base_reward + fees) — the assembler's own
//                 first sizing-pass reward, so the snapshot matches pass 1.
//   age_of      : REQUIRED for KFairSource::X6Allocate, ignored for W4Propose.
//
// Returns nullptr + *why on refusal. The returned source is heap-owned (stable
// address, immutable after build) — the exact ownership the template's raw
// seam pointer needs.
// ---------------------------------------------------------------------------
inline std::unique_ptr<XmrOwedSettlementSource>
build_settlement_source(const XmrSettlementConfig& cfg,
                        const XmrParentContext& parent,
                        const OwedLedger& ledger,
                        const PayOfFn& pay_of,
                        std::uint64_t reward_hint,
                        std::string* why,
                        const AgeOfFn& age_of = {}) {
    std::optional<XmrCoinbaseContext> ctx = make_xmr_coinbase_context(cfg, parent, ledger, why);
    if (!ctx) return nullptr;
    const std::uint64_t hint = reward_hint != 0 ? reward_hint : parent.budget();
    return XmrOwedSettlementSource::build(ledger, pay_of, *ctx, hint, why, cfg.kfair, age_of);
}

// ---------------------------------------------------------------------------
// The x6::CoinbaseInputs to drop into AssemblyInputs.settle. `src->inputs()`
// carries the K_fair owed set + lane params (reward/extra_nonce NOT applied —
// the assembler overwrites them from AssemblyInputs.miner and the template's
// final reward, and iterates the count-invariance fixpoint over these owed
// entries). weight_aware_cap == true zeroes output_cap so the assembler
// resolves the weight-aware cap itself (recommended for real multi-payee
// blocks); false keeps the config's concrete cap.
// ---------------------------------------------------------------------------
inline x6::CoinbaseInputs assembly_settle_inputs(const XmrOwedSettlementSource& src,
                                                 bool weight_aware_cap = true) {
    x6::CoinbaseInputs in = src.inputs();
    if (weight_aware_cap) in.output_cap = 0;   // 0 => XmrBlockAssembler weight-aware default
    return in;
}

// ---------------------------------------------------------------------------
// The RULED per-reward re-projection callback for AssemblyInputs.reproject_owed
// (RULED 2026-09-10). Binding it makes the assembler re-derive the canonical
// K_fair owed rows — OwedLedger::propose_coinbase — at EVERY reward its
// count-invariance fixpoint visits, and at the RESOLVED (weight-aware) total
// output cap, so the payee set the block pays is the proposal at the reward the
// block actually pays. Both the daemon provider and the KATs bind THIS
// function, so there is exactly one wiring to review.
//
// The ledger is captured by POINTER (never by reference to a caller local): the
// callback is copied into the assembler's seam, which the AssembledTemplate
// owns for as long as that template is retained. `fixture` must therefore
// outlive every template built with the returned callback.
// ---------------------------------------------------------------------------
class XmrOwedFixture;   // defined below
inline ReprojectOwedFn make_reproject_owed(const XmrSettlementConfig& cfg,
                                           XmrOwedFixture& fixture);


// ===========================================================================
// XmrOwedFixture — the deterministic proof ledger (survey item E). The X9
// observe-side daemon has no live XMR OwedLedger yet, so the FOUND->FINALIZE
// proof is driven from a hand-built one:
//
//   * EMPTY (no seed)  => propose_coinbase returns no owed outs => the whole
//                         reward flows to the residual sink: a one-output
//                         coinbase, the cleanest proof shape.
//   * seed_owed(ref,a) => credits + FINALIZES `a` piconero to `ref`, so
//                         EffectiveOwed(ref) == a and it is armed: the coinbase
//                         then pays that payee (K_fair) with the sink absorbing
//                         the exact-sum residual — a real multi-payee proof.
//
// It also carries the payout resolver (identity_key -> ScriptRef) the source's
// pay_of needs. Everything is deterministic in the seeds' insertion order.
// ===========================================================================
class XmrOwedFixture {
public:
    // OWNING form (KATs, self-checks, single-shot experiments): the fixture
    // holds its own OwedLedger.
    explicit XmrOwedFixture(::v37::ChainId chain)
        : m_owned(std::in_place, chain), m_ledger(*m_owned) {}

    // NON-OWNING form — R-7 (2026-09-10), the ONE-LEDGER wiring. The live
    // daemon MUST hand the provider the SAME OwedLedger the finalize driver
    // writes (XmrNode::ledger(): store-backed, RecoveryDriver-replayed,
    // XmrFinalizeDriver-driven). Two disjoint ledgers — a settlement one the
    // coinbase pays from and a node one FINALIZE books into — is the split-brain
    // this ctor exists to kill: block N+1's propose_coinbase would never see
    // block N's pending payout deducted, so it would re-propose the SAME owed
    // row at its full EffectiveOwed on EVERY block (a no-double-pay violation of
    // whitepaper section 9 / OI-W4-5), while the node ledger's effective_owed
    // went negative by one reward per pending FOUND.
    // `external` must outlive this fixture and every template built from it.
    explicit XmrOwedFixture(OwedLedger& external) : m_ledger(external) {}

    // DURABLE non-owning form — F-1 (2026-09-10). Same wiring as above, but the
    // caller declares that `external` is backed by the settle-store write-ahead
    // log (XmrNode::ledger()). That single bit is what lets this fixture REFUSE
    // a non-durable in-memory seed instead of silently creating a credit leg the
    // store cannot replay (see seed_owed below). The live daemon uses THIS ctor;
    // KATs driving a bare in-memory OwedLedger use the plain one above.
    struct DurableLedger {};   // tag
    XmrOwedFixture(OwedLedger& external, DurableLedger)
        : m_ledger(external), m_durable(true) {}

    // Is this fixture's ledger the fixture's OWN in-memory one?
    bool owns_ledger() const { return m_owned.has_value(); }
    // Is it declared settle-store backed (so a direct ledger write is not durable)?
    bool durable_ledger() const { return m_durable; }

    // ── F-1 (2026-09-10): RESOLVER-ONLY LEARN ──────────────────────────────
    // Teach the pay_of resolver that identity_key(pay) is paid to `pay`, WITHOUT
    // touching the ledger. This is what the live daemon calls on EVERY boot: the
    // owed ROW is durable (settle-store WAL, replayed by RecoveryDriver) but this
    // key->ScriptRef map is in-memory and must be rebuilt each run, or a
    // recovered owed row would resolve to the RAW sentinel and be CARRIED
    // forever instead of paid. Idempotent by construction. Returns the key.
    ::v37::bytes32 learn_pay(const ::v37::ScriptRef& pay) {
        ::v37::bytes32 key = ::v37::xmr::xmr_identity_key(pay);
        m_paymap[key] = pay;
        return key;
    }
    ::v37::bytes32 learn_pay_std(const std::array<std::uint8_t, 32>& spend_B,
                                 const std::array<std::uint8_t, 32>& view_A) {
        return learn_pay(::v37::xmr::make_xmr_std(spend_B, view_A));
    }

    // Credit + finalize `amount` piconero owed to XMR ref `pay`. Its ledger key
    // is the canon identity_key(pay); the resolver learns pay for that key.
    // bin_height auto-increments so each seed arms at a distinct (older-first)
    // age — matching the K_fair oldest-owed-first order. Returns the key.
    //
    // ── F-1 FAIL-CLOSED (2026-09-10) ────────────────────────────────────────
    // This writes into the ledger DIRECTLY, which is fine for an in-memory
    // ledger (the OWNING form, and the plain non-owning form the KATs drive:
    // nothing there has to survive anything).
    // Against a SETTLE-STORE-BACKED ledger it is the F-1 defect: a direct write
    // is invisible to the write-ahead log, so RecoveryDriver cannot replay the
    // credit leg on the next boot — while the PAYOUT that drew on it, which DID
    // go through XmrFinalizeDriver's WAL, replays fine. finalW then lands at
    // -(amount paid): a NEGATIVE effective_owed row that survives the restart
    // (§9 no-double-pay / OI-W4-5), and re-passing the flag re-credits on top of
    // the recovered ledger, so the row is applied once per boot instead of once
    // ever. Silent, because this store's RecoveryDriver has no ledger_seq
    // cross-check to trip on the missing events.
    // So when the caller declared the ledger durable, this REFUSES: it learns
    // the payee for the resolver and returns the key, but moves NO owed. The
    // durable route is XmrFinalizeDriver::seed_owed_durable(), which is
    // replay-exact and restart-idempotent. Refusing in code, rather than
    // trusting a comment, is what keeps the defect from walking back in.
    ::v37::bytes32 seed_owed(const ::v37::ScriptRef& pay, std::uint64_t amount) {
        ::v37::bytes32 key = learn_pay(pay);
        if (m_durable) return key;   // F-1: never a non-durable write to a store-backed ledger
        const std::string bid = "fixture-seed-" + std::to_string(m_next_bid++);
        OwedLedger::Amounts credit; credit[key] = static_cast<long long>(amount);
        m_ledger.on_block_found(bid, credit, /*payout=*/{});
        m_ledger.on_block_finalized(bid, /*bin_height=*/m_next_age++);
        return key;
    }

    // Convenience: seed from raw key material.
    ::v37::bytes32 seed_owed_std(const std::array<std::uint8_t, 32>& spend_B,
                                 const std::array<std::uint8_t, 32>& view_A,
                                 std::uint64_t amount) {
        return seed_owed(::v37::xmr::make_xmr_std(spend_B, view_A), amount);
    }

    // The pay_of resolver bound to this fixture. A key with no learned ref maps
    // to a RAW sentinel — never paid, CARRIED by W4's canon rule (deterministic).
    PayOfFn pay_of() const {
        return [this](const ::v37::bytes32& k) -> ::v37::ScriptRef {
            auto it = m_paymap.find(k);
            if (it != m_paymap.end()) return it->second;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; raw.payload.clear();
            return raw;
        };
    }

    const OwedLedger& ledger() const { return m_ledger; }
    OwedLedger&       ledger()       { return m_ledger; }
    std::size_t       seeded() const { return m_paymap.size(); }

private:
    // Declaration order is load-bearing: m_owned is constructed before the
    // reference that binds to it.
    std::optional<OwedLedger>             m_owned;   // engaged only in the OWNING form
    OwedLedger&                           m_ledger;  // the ledger actually used
    std::map<::v37::bytes32, ::v37::ScriptRef> m_paymap;
    std::uint64_t                         m_next_bid = 0;
    std::uint64_t                         m_next_age = 1;   // 0 reserved / unarmed
    bool                                  m_durable = false; // F-1: settle-store backed
};

inline ReprojectOwedFn make_reproject_owed(const XmrSettlementConfig& cfg,
                                           XmrOwedFixture& fixture) {
    XmrOwedFixture*     fx      = &fixture;
    PayOfFn             pay_of  = fixture.pay_of();
    const std::uint64_t h_min   = cfg.h_min;
    const std::size_t   n_fixed = cfg.fixed.size();
    std::uint64_t       fixed_sum = 0;
    for (const auto& f : cfg.fixed) fixed_sum += f.amount;
    return [fx, pay_of, h_min, n_fixed, fixed_sum](std::uint64_t reward, std::uint32_t output_cap,
                                                    std::vector<x6::OwedEntry>& out, std::string* why) {
        return project_w4_owed(fx->ledger(), pay_of, h_min, n_fixed, fixed_sum,
                               reward, output_cap, out, nullptr, why);
    };
}

// ===========================================================================
// Structural self-check (no crypto backend needed). A KAT TU can call
// selftest::run() to prove the config/context plumbing holds; the crypto path
// (build_settlement_source succeeding) is exercised by the template KATs where
// the ref10 point-check backend is installed.
// ===========================================================================
namespace selftest {

// A structurally well-formed (but NOT torsion-valid) XMR ref: two ed25519
// basepoint encodings. Passes xmr_ref_well_formed; passes xmr_ref_valid ONLY
// with the ref10 backend installed. Good enough for the backend-free checks.
inline ::v37::ScriptRef sample_wellformed_ref() {
    std::array<std::uint8_t, 32> bp = ::v37::xmr::kat::TORSION_PASS_BASEPOINT;
    return ::v37::xmr::make_xmr_std(bp, bp);
}

inline bool run(std::string* why = nullptr) {
    auto fail = [&](const std::string& m) { if (why) *why = m; return false; };

    // (S1) A config with no sink is refused structurally.
    {
        XmrSettlementConfig cfg;
        cfg.chain_id = 7;
        std::string w;
        if (cfg.validate_structural(&w)) return fail("S1: empty-sink config accepted");
    }
    // (S2) A well-formed sink + room for it validates; a cap of 0 with a fixed
    //      output plus sink that overflows the ceiling is refused.
    XmrSettlementConfig cfg;
    cfg.chain_id           = 7;
    cfg.residual_sink      = sample_wellformed_ref();
    cfg.residual_sink_identity = ::v37::xmr::xmr_identity_key(cfg.residual_sink);
    {
        std::string w;
        if (!cfg.validate_structural(&w)) return fail("S2: well-formed sink config refused: " + w);
    }
    {
        XmrSettlementConfig bad = cfg;
        bad.output_cap = 1;                       // room for exactly 1 = the sink
        bad.fixed.push_back(x6::FixedOutput{sample_wellformed_ref(), 1, {}});
        std::string w;
        if (bad.validate_structural(&w)) return fail("S3: cap-too-small (fixed+sink) accepted");
    }
    // (S4) make_xmr_coinbase_context copies every field through and defaults the
    //      lane commitment to the RULED §13 StateCommitment state root.
    {
        XmrOwedFixture fx(7);
        XmrParentContext parent;
        parent.height = 100; parent.base_reward = 600000000000ULL; parent.fees = 0;
        std::string w;
        auto ctx = make_xmr_coinbase_context(cfg, parent, fx.ledger(), &w);
        if (!ctx) return fail("S4: context build refused: " + w);
        if (ctx->chain_id != 7)                       return fail("S4: chain_id not copied");
        if (ctx->output_cap != cfg.resolved_output_cap()) return fail("S4: output_cap not resolved");
        if (!(ctx->lane_commitment ==
              ::c2pool::v37n::coinbase::StateCommitment(fx.ledger(), fx.ledger().chain()).root()))
            return fail("S4: lane_commitment != §13 state root (RULED default source)");
        if (ctx->lane_commitment == ::v37::bytes32{})
            return fail("S4: §13 state root is zero (summary leaf must always exist)");
        if (!(ctx->residual_sink == cfg.residual_sink)) return fail("S4: sink not copied");
    }
    // (S5) chain-id mismatch between config and ledger is refused.
    {
        XmrOwedFixture fx(9);                         // ledger chain 9 != cfg.chain_id 7
        XmrParentContext parent; parent.height = 1;
        std::string w;
        if (make_xmr_coinbase_context(cfg, parent, fx.ledger(), &w))
            return fail("S5: chain-id mismatch accepted");
    }
    // (S6) fixture seeding: EffectiveOwed and the resolver track the seed set.
    {
        XmrOwedFixture fx(7);
        std::array<std::uint8_t, 32> b = ::v37::xmr::kat::STD_KAT.p0;
        std::array<std::uint8_t, 32> a = ::v37::xmr::kat::STD_KAT.p1;
        ::v37::bytes32 key = fx.seed_owed_std(b, a, 12345);
        if (fx.ledger().effective_owed(key) != 12345) return fail("S6: seeded EffectiveOwed wrong");
        PayOfFn po = fx.pay_of();
        if (!::v37::xmr::is_xmr_kind(po(key).kind))    return fail("S6: resolver lost the seeded ref");
        ::v37::bytes32 miss{}; miss[0] = 0xEE;
        if (::v37::xmr::is_xmr_kind(po(miss).kind))    return fail("S6: resolver invented a ref (must be RAW/carry)");
    }
    // (S7) resolve_lane_commitment(StateRoot) IS StateCommitment::root(), and it
    //      MOVES when one balance moves by a single piconero (the negative
    //      control the §13 binding rests on).
    {
        XmrOwedFixture fx(7);
        std::array<std::uint8_t, 32> b = ::v37::xmr::kat::STD_KAT.p0;
        std::array<std::uint8_t, 32> a = ::v37::xmr::kat::STD_KAT.p1;
        fx.seed_owed_std(b, a, 1000000);
        const ::v37::bytes32 want =
            ::c2pool::v37n::coinbase::StateCommitment(fx.ledger(), fx.ledger().chain()).root();
        if (!(resolve_lane_commitment(cfg, fx.ledger()) == want))
            return fail("S7: resolve_lane_commitment(StateRoot) != StateCommitment::root()");

        XmrOwedFixture fx2(7);
        fx2.seed_owed_std(b, a, 1000001);            // ONE piconero apart
        const ::v37::bytes32 other =
            ::c2pool::v37n::coinbase::StateCommitment(fx2.ledger(), fx2.ledger().chain()).root();
        if (want == other) return fail("S7: §13 root did not move for a 1-piconero balance change");

        XmrSettlementConfig od = cfg;
        od.lc_source = LaneCommitmentSource::OwedDigest;
        od.allow_nonruled_local_only = true;
        if (!(resolve_lane_commitment(od, fx.ledger()) == fx.ledger().owed_digest()))
            return fail("S7: the owed-digest escape hatch no longer resolves to owed_digest");
        if (resolve_lane_commitment(od, fx.ledger()) == want)
            return fail("S7: owed_digest == §13 root (the two bindings must differ)");
    }
    // (S8) the two RULED knobs are refused at config level, before any crypto.
    {
        XmrSettlementConfig bad = cfg;
        bad.kfair = KFairSource::X6Allocate;
        std::string w;
        if (bad.validate_structural(&w)) return fail("S8: X6Allocate accepted");
        if (w.find("RULED") == std::string::npos) return fail("S8: X6Allocate refusal does not name the ruling");

        XmrSettlementConfig bad2 = cfg;
        bad2.lc_source = LaneCommitmentSource::OwedDigest;
        if (bad2.validate_structural(&w)) return fail("S8: non-ruled lane_commitment accepted");
        if (w.find("RULED") == std::string::npos) return fail("S8: lane-commitment refusal does not name the ruling");

        bad2.allow_nonruled_local_only = true;       // single-pool experiment escape hatch
        if (!bad2.validate_structural(&w)) return fail("S8: local-only override still refused: " + w);

        LaneCommitmentSource p{};
        if (!parse_lane_commitment_source("state-root", p) || p != LaneCommitmentSource::StateRoot)
            return fail("S8: parse_lane_commitment_source(state-root)");
        if (parse_lane_commitment_source("nonsense", p))
            return fail("S8: parse_lane_commitment_source accepted an unknown name");
    }
    if (why) why->clear();
    return true;
}

} // namespace selftest

} // namespace c2pool::v37n::xmr::o2
