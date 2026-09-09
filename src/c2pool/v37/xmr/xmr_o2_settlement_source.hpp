// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_o2_settlement_source.hpp
//                        (Track A2 / X9 option B — the settlement seam impl)
//
// XmrOwedSettlementSource: the ONLY IXmrSettlementSource in the tree. It is
// the value that XmrBlockTemplate (impl/xmr/template, the p2pool block_template
// port) calls into so that the miner_tx the pool assembles is the v37 K_fair
// SETTLEMENT coinbase — outputs = oldest-owed-first EffectiveOwed payees from
// the W4 OwedLedger ++ mandated fixed outputs ++ the exact-sum residual sink —
// instead of monerod's single --payout-address output (option A, PR #1534).
//
// It is a PER-TEMPLATE VALUE SNAPSHOT, built on the main thread from
//   (OwedLedger, pay_of, XmrCoinbaseContext, reward_hint)
// with the X6 executor (impl/xmr/settle/xmr_coinbase) doing every byte of
// crypto/serialization. Nothing here defines a consensus digest; the header
// only CALLS OwedLedger::propose_coinbase / owed_digest and the X6 builder.
// It never touches src/sharechain/v37 (its descriptor_xmr header is a
// read-only value consumer, exactly as X6 uses it).
//
// WHERE THE K_FAIR SET COMES FROM — RULED 2026-09-10 (multi-node): W4Propose,
// and ONLY W4Propose. build() REFUSES any other source (fail-closed), and the
// projection lives in the free function project_w4_owed() below so the
// assembler can RE-PROJECT it at every reward its fixpoint visits — the block
// pays the proposal at the reward it ACTUALLY settles on, not at a stale hint.
//   * KFairSource::W4Propose (RULED): the owed output set and
//     order are OwedLedger::propose_coinbase (w4_settlement.hpp:565 — the
//     canonical (first_eligible ASC, key ASC) walk with take = min(owed,
//     budget) and CARRY on take < h_min). X6 is then a pure crypto/serialize
//     executor: it is fed owed := take_i, first_eligible := i (the proposal
//     index), h_min := 0, so allocate_exact_sum reproduces the proposal
//     byte-for-byte and appends the residual sink. This is the BTC W5 shape
//     ("the order is W4's and cannot drift", w5_coinbase.hpp:299-322).
//   * KFairSource::X6Allocate (REFUSED since the ruling; the enum value is
//     kept for one release so an old config fails LOUDLY instead of silently
//     changing meaning): owed := every
//     EffectiveOwed > 0 with first_eligible := age_of(key) and h_min := ctx.h_min;
//     X6's own sort + skip/break rule decides (mbp_wiring.hpp OwedCoinbaseBridge
//     shape). Kept ONLY so the operator ruling is a one-line flip.
//   The two can emit different output sets from the same ledger (X6 skips
//   owed < h_min and BREAKS on a sub-h_min final partial; W4 carries and
//   CONTINUES). Whichever is ruled becomes lane canon; the enum pins the choice
//   in the provider, not in this header's defaults alone.
//
// WHAT IS PRE-COMPUTED (and why it is safe to snapshot):
//   r = H_s(domain || major || chain_id || lane_commitment || prev_id || height)
//   depends on NEITHER the reward NOR the extra_nonce, so r, R = rG, every
//   one-time key P_i = H_s(8rA_i || i)G + B_i and view tag, and the MM leaf
//   keccak(MM_LEAF_DOMAIN || chain_id_le32 || lane_commitment) are fixed for
//   the template's lifetime. Only the AMOUNTS vary with the reward the template
//   settles on, and those are re-allocated deterministically in split_reward().
//
// LANE COMMITMENT — RULED 2026-09-10 (multi-node): ctx.lane_commitment is the
// whitepaper §13 StateCommitment Merkle root (lane_commitment_from_state_root
// below), NOT the narrower owed_digest. The §13 summary leaf already contains
// owed_digest, so the new binding strictly subsumes the old one. It also seeds
// the deterministic tx secret key r, so the whole coinbase moves — every pinned
// option-B byte golden had to be regenerated with this change.
//
// COUNT INVARIANCE (survey must_implement 3a — NOT solved here, by design):
//   XmrBlockTemplate::update() calls split_reward twice (dry run at
//   base + Σfees, then at the penalty-adjusted final reward) and assumes the
//   payee COUNT is reward-independent. X6's set is budget-dependent (the sink
//   exists iff residual > 0; a lower budget truncates the tail). This seam
//   keeps payees() FIXED at the reward_hint allocation and makes split_reward
//   return false whenever the allocation at `reward` has a different shape —
//   fail-closed (the template falls back to use_old_template(), which the
//   provider MUST detect via template_id/height). The fixpoint (re-allocate at
//   the final reward and iterate) belongs to the template-side patch / the
//   provider ring, which rebuilds THIS snapshot at reward_hint := final reward.
//   Do NOT "fix" it here by forcing the sink to always exist: that would alter
//   X6's allocation canon.
//
// PER-TEMPLATE SEAM CAPTURE (survey 3b): XmrBlockTemplate stores a raw
//   IXmrSettlementSource* and RE-QUERIES it at job/submit time, and its
//   OLD_TEMPLATES copies share that pointer. So this object is heap-owned
//   (build() returns a unique_ptr — stable address), immutable after build,
//   and the provider ring owns one per template_id for as long as that id can
//   be submitted. Never point a template at a snapshot that may be destroyed
//   or rebuilt underneath it.
//
// FAIL-CLOSED RULES:
//   * the residual sink (and every fixed output) MUST pass xmr_ref_valid —
//     torsion check under the installed ed25519 point-check backend. No backend
//     => nothing validates => build() refuses (BadSinkDescriptor). This is the
//     "REFUSE to serve B without --residual-sink-*" rule.
//   * a ledger key whose pay_of() ref is not a valid XMR ref is never paid and
//     never dropped ad hoc: it is CARRIED by W4's own rule (h_min_of ->
//     UINT64_MAX, the canon CARRY branch), so every node with the same ledger +
//     backend produces the same set. The count is surfaced for diagnostics.
//   * CARROT fence: major_version > 16 refuses (X6 CarrotFence), and
//     derive_output_key() refuses an hf_major that differs from the one r was
//     derived under.
//   * ctx.chain_id must equal ledger.chain(); mismatch refuses.
//
// THREADING: build() = main thread (reads the ledger). Every other method is
// const, touches no shared state, and is safe from the listener thread through
// the template's seam pointer.
// ===========================================================================
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>            // OwedLedger (merged; propose_coinbase, owed_digest)
#include <c2pool/v37/w5_coinbase.hpp>              // StateCommitment (the whitepaper §13 state root)
#include <sharechain/v37/v37_descriptor.hpp>        // ScriptRef, ScriptKind (read-only canon)
#include <sharechain/v37/v37_descriptor_xmr.hpp>    // xmr_ref_valid, is_xmr_kind, xmr_precarrot_ok
#include <sharechain/v37/v37_hash.hpp>              // bytes32

#include "impl/xmr/coin/xmr_crypto_types.hpp"       // Bytes32, PublicKey, SecretKey, Hash256
#include "impl/xmr/settle/xmr_coinbase.hpp"         // X6: CoinbaseInputs, build_coinbase, allocate_exact_sum, ...
#include "impl/xmr/template/xmr_block_template.hpp" // IXmrSettlementSource, XmrPayee, c2pool::xmr::hash

namespace c2pool::v37n::xmr::o2 {

namespace x6 = ::v37::xmr::settle;

using OwedLedger = ::c2pool::v37n::settle::OwedLedger;
using Amounts    = OwedLedger::Amounts;                    // std::map<bytes32, long long>
using TplHash    = ::c2pool::xmr::hash;                    // the template's 32-byte hash POD

// Resolve a canonical OWED key to its payout ScriptRef (the fold's identity
// view in production; a fixed resolver in the smoke). Same shape as
// btc_node.hpp:82 PayOfFn and mbp_wiring.hpp:96 PayOf.
using PayOfFn = std::function<::v37::ScriptRef(const ::v37::bytes32& key)>;
// K_fair age of a key (first_eligible). ONLY the X6Allocate path needs it;
// OwedLedger keeps m_first_eligible private, so the W4Propose path never asks.
using AgeOfFn = std::function<std::uint64_t(const ::v37::bytes32& key)>;

// ---------------------------------------------------------------------------
// 32-byte shims between the three hash spellings that meet at this seam:
//   c2pool::xmr::hash (template, uint8_t h[32])  <->  xmr::coin::Bytes32 (X6)
//   <->  ::v37::bytes32 (ledger keys / digests, std::array<uint8_t,32>).
// Plain memcpy; every one of them is a bare 32-byte little-endian string.
// ---------------------------------------------------------------------------
inline TplHash tpl_hash_from(const ::xmr::coin::Bytes32& b) {
    TplHash h; std::memcpy(h.h, b.data(), 32); return h;
}
inline TplHash tpl_hash_from(const ::v37::bytes32& b) {
    TplHash h; std::memcpy(h.h, b.data(), 32); return h;
}
inline ::xmr::coin::Hash256 hash256_from(const TplHash& h) {
    ::xmr::coin::Hash256 o{}; std::memcpy(o.data(), h.h, 32); return o;
}
inline ::xmr::coin::Hash256 hash256_from(const ::v37::bytes32& b) {
    ::xmr::coin::Hash256 o{}; std::memcpy(o.data(), b.data(), 32); return o;
}
inline ::v37::bytes32 bytes32_from(const ::xmr::coin::Bytes32& b) {
    ::v37::bytes32 o{}; std::memcpy(o.data(), b.data(), 32); return o;
}
inline ::v37::bytes32 bytes32_from(const TplHash& h) {
    ::v37::bytes32 o{}; std::memcpy(o.data(), h.h, 32); return o;
}

// ---------------------------------------------------------------------------
// Which implementation of "K_fair" picks the owed output set. See banner.
// ---------------------------------------------------------------------------
enum class KFairSource : std::uint8_t {
    W4Propose  = 0,   // OwedLedger::propose_coinbase decides; X6 executes (default)
    X6Allocate = 1,   // X6 allocate_exact_sum decides over effective_owed_all (needs AgeOf)
};

inline const char* to_string(KFairSource s) {
    switch (s) {
        case KFairSource::W4Propose:  return "w4-propose";
        case KFairSource::X6Allocate: return "x6-allocate";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// The consensus-derived context for ONE template (mirrors mbp_wiring.hpp:78-91
// CoinbaseContext field-for-field, minus the per-WORKER extra_nonce, which the
// template patches itself). Every field is a pure function of the mainchain
// tip + lane state / lane parameters, so the coinbase is byte-reproducible.
// ---------------------------------------------------------------------------
struct XmrCoinbaseContext {
    // --- CARROT fence key + Monero parent ---
    std::uint8_t          monero_major_version = 16;
    std::uint64_t         height = 0;                 // block height; unlock = height + 60
    ::xmr::coin::Hash256  prev_id{};                  // parent block id (bin origin)
    std::uint64_t         base_reward = 0;            // get_base_reward(already_generated_coins)
    std::uint64_t         fees = 0;                   // Σ selected tx fees (informational split)

    // --- lane context ---
    std::uint32_t         chain_id = 0;               // v37 ChainId of the XMR lane (== ledger.chain())
    ::v37::bytes32        lane_commitment{};          // r-seed + MM leaf (recommended: owed_digest())

    // --- lane parameters (consensus once tapped; explicit flags until then) ---
    ::v37::ScriptRef      residual_sink;              // mandated absorber, XMR ref (REQUIRED, torsion-checked)
    ::v37::bytes32        residual_sink_identity{};   // its ledger identity_key (payout-map key)
    std::vector<x6::FixedOutput> fixed;               // mandated dev/donation/finder outputs (optional)
    std::uint64_t         h_min = 0;                  // piconero floor per owed output (dust = 0 on XMR)
    std::uint32_t         output_cap = 0;             // TOTAL outputs cap C (weight_aware_output_cap(...))

    std::uint64_t budget() const { return base_reward + fees; }
};

// The lane_commitment source the survey recommends: the §4.5 OWED commitment
// over the finalized partition (public, const, deterministic). Superseded as
// the DEFAULT by the §13 state root below (operator ruling 2026-09-10); kept
// for single-pool experiments and for the golden-regeneration KAT.
inline ::v37::bytes32 lane_commitment_from_owed_digest(const OwedLedger& ledger) {
    return ledger.owed_digest();
}

// RULED 2026-09-10 (multi-node): the MM-root leaf in the coinbase tx_extra 0x03
// commits the FULL whitepaper §13 StateCommitment Merkle root — the SAME root
// w5_coinbase.hpp builds (summary leaf "V37S" || chain || ledger_seq ||
// num_balances || owed_digest, then per-key "V37E" || key || balance leaves,
// key ASC). STRICT SUBSUMPTION: the summary leaf already CONTAINS owed_digest,
// so committing the root strictly strengthens the previous owed_digest binding.
//
// We commit the ROOT VALUE the engine computes, never a re-derivation from
// pinned constants, so the binding is robust to any later change in what §13
// hashes — but note that such a change MOVES the root and is therefore
// lane-consensus-visible (needs an activation gate; see the PR's ruling R-3).
inline ::v37::bytes32 lane_commitment_from_state_root(const OwedLedger& ledger) {
    return ::c2pool::v37n::coinbase::StateCommitment(ledger, ledger.chain()).root();
}

// ---------------------------------------------------------------------------
// project_w4_owed — the ONE place the canonical K_fair owed set is computed.
//
// RULED 2026-09-10: KFairSource == W4Propose. The XMR coinbase selects payees
// by the ONE ratified K_fair rule — OwedLedger::propose_coinbase (oldest-owed-
// first: first_eligible ASC then identity ASC, whitepaper erratum E-1) — so
// every node derives the SAME output set from the same ledger. X6 is then a
// pure crypto/serialize + exact-sum sink executor: it is fed owed := take_i,
// first_eligible := i (the proposal index) and h_min := 0, which makes
// allocate_exact_sum reproduce the proposal byte-for-byte.
//
// This is a FREE function (not a build() private) because the assembler must
// RE-PROJECT at every reward its count-invariance fixpoint visits — the payee
// set has to be W4's proposal at the reward the block ACTUALLY pays, not at the
// first sizing hint. One body, one order, no second implementation.
//
//   h_min           : the owed floor W4 applies (XMR dust = 0 today).
//   n_fixed         : ctx.fixed.size() (mandated outputs, each takes a slot).
//   fixed_sum       : Σ fixed amounts (subtracted from the owed budget).
//   reward          : the exact-sum budget the set is chosen at.
//   total_output_cap: the RESOLVED total-output cap C (never the 0 sentinel).
//   out             : receives the projected x6::OwedEntry rows (cleared first).
//   unpayable       : optional count of keys CARRIED for an unpayable ref.
//   why             : filled on refusal.
// ---------------------------------------------------------------------------
inline bool project_w4_owed(const OwedLedger& ledger, const PayOfFn& pay_of,
                            std::uint64_t h_min, std::size_t n_fixed,
                            std::uint64_t fixed_sum, std::uint64_t reward,
                            std::uint32_t total_output_cap,
                            std::vector<x6::OwedEntry>& out,
                            std::size_t* unpayable = nullptr,
                            std::string* why = nullptr) {
    auto no = [&](const std::string& m) { if (why) *why = m; return false; };
    out.clear();
    if (!pay_of)                        return no("project_w4_owed: no pay_of resolver");
    if (reward == 0)                    return no("project_w4_owed: zero reward");
    if (total_output_cap < n_fixed + 1) return no("project_w4_owed: output_cap leaves no room for fixed + sink");
    if (fixed_sum > reward)             return no("project_w4_owed: Σfixed exceeds the reward");

    // A key whose ref is not a payable XMR ref is downgraded to a RAW sentinel;
    // W4's h_min_of(RAW) = UINT64_MAX then CARRIES it (canon branch,
    // deterministic across nodes with the same point-check backend).
    std::size_t carried = 0;
    auto payable_ref = [&](const ::v37::bytes32& k) -> ::v37::ScriptRef {
        ::v37::ScriptRef r = pay_of(k);
        if (!::v37::xmr::xmr_ref_valid(r)) {
            ++carried;
            ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; raw.payload.clear();
            return raw;
        }
        return r;
    };

    const unsigned cap_owed = static_cast<unsigned>(
        std::min<std::size_t>(static_cast<std::size_t>(total_output_cap) - n_fixed - 1,
                              std::numeric_limits<unsigned>::max()));
    // ── COUNT-INVARIANCE GUARD (2026-09-10) ─────────────────────────────────
    // The two layers that meet here use the SAME arithmetic with OPPOSITE
    // conventions for 0:
    //   * W4 canon reads slot_budget_C == 0 as UNBOUNDED output count
    //     (w4_settlement.hpp:580-583, symmetric with W5's max_payout_bytes==0);
    //   * X6 reads its own cap_owed == 0 as "no room for any owed output"
    //     (xmr_coinbase.cpp:113-114 + :135).
    // cap_owed == 0 <=> total_output_cap == n_fixed + 1: room for the mandated
    // outputs and the residual sink and NOTHING else. Forwarding that 0 to W4
    // would propose EVERY eligible key while X6 emits zero owed outputs — the
    // whole owed budget silently lands in the residual sink while the proposal
    // claims N rows. Reachable on ordinary FULL blocks, not a synthetic edge:
    // weight_aware_output_cap floors its result at 1 ("always room for at least
    // the residual sink", xmr_coinbase.cpp:430-433), so any block whose selected
    // txs fill the penalty-free zone resolves the cap to 1 == n_fixed + 1 under
    // the default empty `fixed` set.
    //
    // Disposition: CLEAR AND SUCCEED — emit ZERO owed rows and CARRY every key.
    //   (a) it matches X6's OWN legality boundary (BuildError::CapTooSmall is
    //       output_cap < fixed.size() + 1, xmr_coinbase.hpp:200 / .cpp:110-111),
    //       so the projection accepts exactly the templates X6 accepts;
    //   (b) a refusal here is PERMANENTLY fatal, not a retry signal: the outer
    //       pass loop dies (xmr_block_assembly.hpp:585-586) and the split_reward
    //       path asks for a rebuild at the same reward, whose weight-aware cap
    //       is the same deterministic function of the same inputs — it would
    //       refuse identically until max_passes is exhausted. The node would
    //       STOP SERVING every time its block is full: fail-STOPPED, not
    //       fail-closed;
    //   (c) it IS fail-closed where it matters: nothing is over-paid, no payee
    //       is short-changed. Every owed row is CARRIED with the SAME
    //       disposition as W4's own sub-h_min CARRY ("skip, first_eligible
    //       untouched -- no starvation, the entry keeps its age",
    //       w4_settlement.hpp:586-587), so the K_fair queue ages are undamaged
    //       and the next block with cap room pays them.
    // A named refusal would be right only if cap_owed == 0 could signal an
    // upstream sentinel leak. It cannot: total_output_cap == 0 is already
    // refused at the :273 guard above, and xmr_block_assembly.hpp:572-573
    // resolves the 0 sentinel before this hook is ever called.
    if (cap_owed == 0) {
        if (unpayable) *unpayable = 0;   // nothing was even walked
        if (why) why->clear();
        return true;                     // `out` was cleared at the top
    }

    const std::uint64_t owed_budget = reward - fixed_sum;
    auto h_min_of = [&](::v37::ScriptKind k) -> std::uint64_t {
        return ::v37::xmr::is_xmr_kind(k) ? h_min : std::numeric_limits<std::uint64_t>::max();
    };

    OwedLedger::Proposal prop = ledger.propose_coinbase(owed_budget, cap_owed,
                                                        payable_ref, h_min_of);
    out.reserve(prop.outs.size());
    for (std::size_t i = 0; i < prop.outs.size(); ++i) {
        x6::OwedEntry e;
        e.pay            = prop.outs[i].pay;
        e.owed           = prop.outs[i].amount;   // exactly the proposed take
        e.first_eligible = i;                     // proposal index == canonical order
        e.identity       = prop.outs[i].key;
        out.push_back(std::move(e));
    }
    if (unpayable) *unpayable = carried;
    if (why) why->clear();
    return true;
}

// The per-reward re-projection callback the assembler consumes. Structurally
// identical to XmrBlockAssembler's X6SettlementSource::ReprojectOwedFn (the
// impl tree must not include consumer headers, so the type is spelled twice —
// it is the SAME std::function specialisation, so they assign freely).
using ReprojectOwedFn =
    std::function<bool(std::uint64_t reward, std::uint32_t output_cap,
                       std::vector<x6::OwedEntry>& out, std::string* why)>;

// ===========================================================================
// XmrOwedSettlementSource
// ===========================================================================
class XmrOwedSettlementSource final : public ::c2pool::xmr::IXmrSettlementSource {
public:
    // Build the per-template snapshot. Returns nullptr and fills *why on any
    // refusal (fence, bad sink, cap, budget, derivation, chain mismatch).
    //   reward_hint : the exact-sum budget the owed set is chosen at (the
    //                 template's final reward once the fixpoint converges; the
    //                 provider's first guess is base_reward + Σ selected fees).
    //                 0 => ctx.budget().
    //   age_of      : REQUIRED for KFairSource::X6Allocate, ignored otherwise.
    static std::unique_ptr<XmrOwedSettlementSource>
    build(const OwedLedger& ledger, const PayOfFn& pay_of, const XmrCoinbaseContext& ctx,
          std::uint64_t reward_hint, std::string* why,
          KFairSource source = KFairSource::W4Propose, const AgeOfFn& age_of = {})
    {
        auto refuse = [&](const std::string& msg) -> std::unique_ptr<XmrOwedSettlementSource> {
            if (why) *why = msg;
            return nullptr;
        };
        if (reward_hint == 0) reward_hint = ctx.budget();

        // ---- fences / lane-parameter validity (fail-closed) ----
        if (!::v37::xmr::xmr_precarrot_ok(ctx.monero_major_version))
            return refuse(std::string("refused: ") + x6::to_string(x6::BuildError::CarrotFence));
        if (ctx.chain_id != ledger.chain())
            return refuse("refused: ctx.chain_id != ledger.chain()");
        if (!::v37::xmr::xmr_ref_valid(ctx.residual_sink))
            return refuse(std::string("refused: ") + x6::to_string(x6::BuildError::BadSinkDescriptor) +
                          " (need --residual-sink-* XMR ref AND the ed25519 point-check backend)");
        for (const auto& f : ctx.fixed) {
            if (!::v37::xmr::xmr_ref_valid(f.pay))
                return refuse("refused: a fixed output is not a valid XMR ref");
        }
        if (ctx.output_cap < ctx.fixed.size() + 1)
            return refuse(std::string("refused: ") + x6::to_string(x6::BuildError::CapTooSmall));
        if (reward_hint == 0)
            return refuse(std::string("refused: ") + x6::to_string(x6::BuildError::ZeroBudget));
        std::uint64_t fixed_sum = 0;
        for (const auto& f : ctx.fixed) {
            if (f.amount > reward_hint - fixed_sum)
                return refuse(std::string("refused: ") + x6::to_string(x6::BuildError::FixedExceedsBudget));
            fixed_sum += f.amount;
        }
        // RULED 2026-09-10 (multi-node consensus): the ONLY admissible K_fair
        // source is W4Propose — OwedLedger::propose_coinbase, the one ratified
        // rule (oldest-owed-first, whitepaper erratum E-1). X6Allocate would
        // let a node derive a DIFFERENT output set from the same ledger, so it
        // is refused here, fail-closed, rather than left silently selectable.
        if (source != KFairSource::W4Propose)
            return refuse("RULED 2026-09-10: KFairSource must be W4Propose "
                          "(canonical K_fair propose_coinbase, whitepaper E-1); "
                          "X6Allocate is refused for multi-node settlement");
        (void)age_of;   // W4Propose never asks the ledger for an age

        std::unique_ptr<XmrOwedSettlementSource> s(new XmrOwedSettlementSource());
        s->m_ctx         = ctx;
        s->m_source      = source;
        s->m_reward_hint = reward_hint;
        s->m_ledger_seq  = ledger.ledger_seq();
        s->m_owed_digest = ledger.owed_digest();

        // ---- the fixed part of the X6 inputs (reward / extra_nonce applied per query) ----
        x6::CoinbaseInputs& in = s->m_inputs;
        in.monero_major_version   = ctx.monero_major_version;
        in.height                 = ctx.height;
        in.prev_id                = ctx.prev_id;
        in.chain_id               = ctx.chain_id;
        in.lane_commitment        = ctx.lane_commitment;
        in.fixed                  = ctx.fixed;
        in.residual_sink          = ctx.residual_sink;
        in.residual_sink_identity = ctx.residual_sink_identity;
        in.output_cap             = ctx.output_cap;
        in.extra_nonce.clear();

        // The canonical K_fair projection — the SAME free function the
        // assembler's per-reward re-projection hook calls, so the set the block
        // pays is OwedLedger::propose_coinbase output at the block's reward.
        std::size_t unpayable = 0;
        std::string pw;
        if (!project_w4_owed(ledger, pay_of, ctx.h_min, ctx.fixed.size(), fixed_sum,
                             reward_hint, ctx.output_cap, in.owed, &unpayable, &pw))
            return refuse("refused: " + pw);
        // LOAD-BEARING 0 (do not "restore" ctx.h_min here). W4 has already
        // applied the owed floor while choosing the set, and each row's `owed`
        // IS its accepted take. Feeding X6 a NON-zero h_min would reintroduce a
        // two-conventions divergence of exactly the class the count-invariance
        // guard above closes: on a budget-truncated final partial W4 CARRYs and
        // KEEPS SCANNING (w4_settlement.hpp:586-587) while X6 BREAKs and stops
        // (xmr_coinbase.cpp:137-139), so X6 would emit a strict PREFIX of the
        // proposal and the residual sink would swallow the difference. The
        // FOUND payout map is read from the EMITTED outputs (Role::Owed), so it
        // stays correct either way — but the proposal/emission divergence would
        // silently under-pay carried payees. Keep it 0.
        in.h_min = 0;                                     // W4 already applied the floor
        s->m_unpayable = unpayable;

        // ---- run X6 once at reward_hint: fixes r, R, keys, view tags, MM leaf, ORDER ----
        s->m_built = x6::build_coinbase(s->inputs_at(reward_hint, {}));
        if (!s->m_built.ok)
            return refuse(std::string("refused: X6 build_coinbase: ") + s->m_built.detail);

        s->m_payees.reserve(s->m_built.outputs.size());
        for (const auto& o : s->m_built.outputs) {
            ::c2pool::xmr::XmrPayee p;
            std::memcpy(p.spend_public_key.h, o.pay.payload.data(),      32);   // B (or D_i)
            std::memcpy(p.view_public_key.h,  o.pay.payload.data() + 32, 32);   // A
            s->m_payees.push_back(p);
        }
        s->m_r    = tpl_hash_from(s->m_built.r);
        s->m_R    = tpl_hash_from(s->m_built.R);
        s->m_leaf = tpl_hash_from(s->m_built.mm_root);   // == mm_commitment_root(chain_id, lane_commitment)
        if (why) why->clear();
        return s;
    }

    // Non-copyable / non-movable on purpose: the template keeps a raw pointer.
    XmrOwedSettlementSource(const XmrOwedSettlementSource&) = delete;
    XmrOwedSettlementSource& operator=(const XmrOwedSettlementSource&) = delete;
    ~XmrOwedSettlementSource() override = default;

    // =====================================================================
    // IXmrSettlementSource (the template seam) — all pure, all const.
    // =====================================================================

    // X6 canonical order: [K_fair owed] ++ [fixed] ++ [sink?], fixed at reward_hint.
    [[nodiscard]] const std::vector<::c2pool::xmr::XmrPayee>& payees() const override {
        return m_payees;
    }

    [[nodiscard]] const TplHash& tx_secret_key() const override { return m_r; }
    [[nodiscard]] const TplHash& tx_public_key() const override { return m_R; }

    // P_i / view_tag_i were derived under r for the SAME major version; refuse
    // any other fork (fence) and any index outside the snapshot.
    [[nodiscard]] bool derive_output_key(std::size_t i, std::uint8_t hf_major,
                                         TplHash& out_eph_pubkey,
                                         std::uint8_t& out_view_tag) const override {
        if (!::v37::xmr::xmr_precarrot_ok(hf_major)) return false;        // CARROT fence
        if (hf_major != m_ctx.monero_major_version) return false;          // r was seeded with ctx.major
        if (i >= m_built.outputs.size()) return false;
        const x6::CoinbaseOutput& o = m_built.outputs[i];
        out_eph_pubkey = tpl_hash_from(o.one_time_key);
        out_view_tag   = o.view_tag.tag;
        return true;
    }

    // Exact-sum split at `reward` over the snapshot's owed/fixed/sink set.
    // true  => rewards[i] is the piconero amount of payees()[i], Σ == reward.
    // false => the allocation at `reward` has a different SHAPE (count / payee
    //          order) than payees() — fail closed; see the banner (3a).
    [[nodiscard]] bool split_reward(std::uint64_t reward,
                                    std::vector<std::uint64_t>& rewards) const override {
        x6::BuildError err = x6::BuildError::None;
        const std::vector<x6::CoinbaseOutput> outs = x6::allocate_exact_sum(inputs_at(reward, {}), &err);
        if (outs.empty() || err != x6::BuildError::None) return false;
        if (!same_shape(outs)) return false;
        rewards.resize(outs.size());
        std::uint64_t sum = 0;
        for (std::size_t i = 0; i < outs.size(); ++i) { rewards[i] = outs[i].amount; sum += outs[i].amount; }
        return sum == reward;   // X6 invariant; belt-and-braces
    }

    // Single v37 MM-tree leaf: keccak(MM_LEAF_DOMAIN || chain_id_le32 || lane_commitment).
    // extra_nonce-INDEPENDENT (the commitment binds the ledger, not the worker),
    // so a stale template_id can never patch a different root than was hashed.
    [[nodiscard]] TplHash commitment_leaf(std::uint32_t /*extra_nonce*/) const override {
        return m_leaf;
    }

    // depth 0 => the template emits [0x03][1+32][varint(0)][root], byte-equal
    // to X6 assemble_tx_extra's { varint(33) || 0x00 || root }.
    [[nodiscard]] std::uint64_t merkle_tree_data() const override { return 0; }

    // =====================================================================
    // Value accessors (provider ring / FOUND record / KATs / ACCEPT check)
    // =====================================================================

    // The seam pointer the template takes. Address is stable for this object's life.
    ::c2pool::xmr::IXmrSettlementSource* seam() { return this; }

    const XmrCoinbaseContext& context()      const { return m_ctx; }
    KFairSource               kfair_source() const { return m_source; }
    std::uint64_t             reward_hint()  const { return m_reward_hint; }
    // Ledger state this snapshot was cut at — part of the provider's REBUILD
    // KEY (prev_id, height, backlog, ledger_seq/owed_digest), since r and the
    // MM leaf depend on lane_commitment and the owed set on the ledger.
    std::uint64_t             ledger_seq()   const { return m_ledger_seq; }
    const ::v37::bytes32&     owed_digest()  const { return m_owed_digest; }
    // Ledger keys with EffectiveOwed > 0 that were CARRIED as unpayable.
    std::size_t               carried_unpayable() const { return m_unpayable; }

    // The full X6 result at reward_hint (empty extra_nonce => no 0x02 tag; use
    // build_at() for the template-equal tx_extra).
    const x6::BuiltCoinbase&  built() const { return m_built; }
    const x6::CoinbaseInputs& inputs() const { return m_inputs; }   // reward/extra_nonce NOT applied

    // X6 inputs at a given exact-sum budget and 0x02 extra-nonce payload.
    // X6 consumes only budget(); the (base_reward, fees) split is kept where
    // it is representable so audit trails keep the subsidy/fees distinction.
    x6::CoinbaseInputs inputs_at(std::uint64_t reward,
                                 const std::vector<unsigned char>& extra_nonce) const {
        x6::CoinbaseInputs in = m_inputs;
        if (reward >= m_ctx.base_reward) { in.base_reward = m_ctx.base_reward; in.fees = reward - m_ctx.base_reward; }
        else                             { in.base_reward = reward;            in.fees = 0; }
        in.extra_nonce = extra_nonce;
        return in;
    }

    // The 0x02 payload exactly as XmrBlockTemplate lays it out for extra_nonce
    // e: LE32(e) followed by zero padding up to the template's corrected size
    // (EXTRA_NONCE_SIZE + max_reward_amounts_weight - reward_amounts_weight).
    static std::vector<unsigned char> extra_nonce_bytes(std::uint32_t e, std::size_t padded_len) {
        std::vector<unsigned char> b(std::max<std::size_t>(padded_len, 4), 0);
        b[0] = static_cast<unsigned char>(e);       b[1] = static_cast<unsigned char>(e >> 8);
        b[2] = static_cast<unsigned char>(e >> 16); b[3] = static_cast<unsigned char>(e >> 24);
        return b;
    }

    // Full X6 rebuild at (reward, extra_nonce): the bytes a KAT compares against
    // the template's miner_tx slice, and what a peer's ACCEPT check (W3,
    // canonical_coinbase_matches) recomputes.
    x6::BuiltCoinbase build_at(std::uint64_t reward,
                               const std::vector<unsigned char>& extra_nonce) const {
        return x6::build_coinbase(inputs_at(reward, extra_nonce));
    }

    // Allocation at `reward` (amount / pay / identity / role), with the
    // snapshot's one-time keys + view tags attached when the shape matches.
    // Empty on an X6 allocation error.
    std::vector<x6::CoinbaseOutput> outputs_at(std::uint64_t reward, bool* shape_ok = nullptr) const {
        x6::BuildError err = x6::BuildError::None;
        std::vector<x6::CoinbaseOutput> outs = x6::allocate_exact_sum(inputs_at(reward, {}), &err);
        const bool ok = !outs.empty() && err == x6::BuildError::None && same_shape(outs);
        if (ok) {
            for (std::size_t i = 0; i < outs.size(); ++i) {
                outs[i].one_time_key = m_built.outputs[i].one_time_key;
                outs[i].view_tag     = m_built.outputs[i].view_tag;
            }
        }
        if (shape_ok) *shape_ok = ok;
        return outs;
    }
    bool shape_matches_at(std::uint64_t reward) const {
        bool ok = false; (void)outputs_at(reward, &ok); return ok;
    }
    std::size_t output_count_at(std::uint64_t reward) const {
        return outputs_at(reward).size();
    }

    // FOUND-record `payout` — R-7 (2026-09-10): the Role::Owed SUBSET ONLY,
    // { identity_key : piconero }, at the reward the template settled on
    // (XmrBlockTemplate::get_reward()). This is what OwedLedger::on_block_found
    // may be handed: the payout term is SUBTRACTED from finalW at FINALIZE
    // (w4_settlement.hpp:485-500) and is legal only for keys the ledger
    // CREDITED. A Fixed or Sink identity was never credited, so booking it
    // would drive that key's finalW permanently negative — they are EXCLUDED.
    // Duplicate owed identities SUM. Empty when the allocation at `reward`
    // fails or its shape does not match.
    //
    // NOTE for the live daemon: prefer the EMITTED outputs of the FINAL
    // AssembledTemplate (AssembledTemplate::outputs()) over this re-derivation.
    // They agree on the snapshot's own shape by construction (same_shape), but
    // the assembled template is the thing the block actually broadcast.
    Amounts owed_payout_map_at(std::uint64_t reward) const {
        Amounts m;
        bool ok = false;
        const std::vector<x6::CoinbaseOutput> outs = outputs_at(reward, &ok);
        if (!ok) return m;
        for (const auto& o : outs)
            if (o.role == x6::CoinbaseOutput::Role::Owed)
                m[o.identity] += static_cast<long long>(o.amount);
        return m;
    }
    Amounts owed_payout_map() const { return owed_payout_map_at(m_reward_hint); }

    // EVERY output the coinbase pays (owed ++ fixed ++ sink), for AUDIT /
    // exact-sum diagnostics only. NEVER a FOUND payout map — see above.
    Amounts all_outputs_map_at(std::uint64_t reward) const {
        Amounts m;
        bool ok = false;
        const std::vector<x6::CoinbaseOutput> outs = outputs_at(reward, &ok);
        if (!ok) return m;
        for (const auto& o : outs) m[o.identity] += static_cast<long long>(o.amount);
        return m;
    }

private:
    XmrOwedSettlementSource() = default;

    // Same count, same payee (pay + identity + role) at every index as the
    // snapshot's canonical order. Amounts are allowed to differ (that is the
    // whole point of re-splitting); nothing else is.
    bool same_shape(const std::vector<x6::CoinbaseOutput>& outs) const {
        if (outs.size() != m_built.outputs.size()) return false;
        for (std::size_t i = 0; i < outs.size(); ++i) {
            const x6::CoinbaseOutput& a = outs[i];
            const x6::CoinbaseOutput& b = m_built.outputs[i];
            if (a.role != b.role || a.identity != b.identity || !(a.pay == b.pay)) return false;
        }
        return true;
    }

    XmrCoinbaseContext   m_ctx;
    KFairSource          m_source = KFairSource::W4Propose;
    std::uint64_t        m_reward_hint = 0;
    std::uint64_t        m_ledger_seq = 0;
    ::v37::bytes32       m_owed_digest{};
    std::size_t          m_unpayable = 0;

    x6::CoinbaseInputs   m_inputs;     // fixed part; reward + extra_nonce applied per query
    x6::BuiltCoinbase    m_built;      // X6 at reward_hint: r, R, keys, view tags, mm_root, order

    std::vector<::c2pool::xmr::XmrPayee> m_payees;
    TplHash              m_r;
    TplHash              m_R;
    TplHash              m_leaf;
};

} // namespace c2pool::v37n::xmr::o2
