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
// WHERE THE K_FAIR SET COMES FROM (the survey's gate flag, ruling owed):
//   * KFairSource::W4Propose (DEFAULT, recommended): the owed output set and
//     order are OwedLedger::propose_coinbase (w4_settlement.hpp:565 — the
//     canonical (first_eligible ASC, key ASC) walk with take = min(owed,
//     budget) and CARRY on take < h_min). X6 is then a pure crypto/serialize
//     executor: it is fed owed := take_i, first_eligible := i (the proposal
//     index), h_min := 0, so allocate_exact_sum reproduces the proposal
//     byte-for-byte and appends the residual sink. This is the BTC W5 shape
//     ("the order is W4's and cannot drift", w5_coinbase.hpp:299-322).
//   * KFairSource::X6Allocate (alternative, needs AgeOf): owed := every
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
// over the finalized partition (public, const, deterministic). Whether this or
// the lane digest / SettlementView::digest goes into r and the MM root is a
// consensus ruling; the provider picks EXPLICITLY and passes it in ctx.
inline ::v37::bytes32 lane_commitment_from_owed_digest(const OwedLedger& ledger) {
    return ledger.owed_digest();
}

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
        if (source == KFairSource::X6Allocate && !age_of)
            return refuse("refused: KFairSource::X6Allocate needs an AgeOf resolver");

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

        // A key whose ref is not a payable XMR ref is downgraded to a RAW
        // sentinel; W4's h_min_of(RAW) = UINT64_MAX then CARRIES it (canon
        // branch, deterministic across nodes with the same backend).
        std::size_t unpayable = 0;
        auto payable_ref = [&](const ::v37::bytes32& k) -> ::v37::ScriptRef {
            ::v37::ScriptRef r = pay_of(k);
            if (!::v37::xmr::xmr_ref_valid(r)) {
                ++unpayable;
                ::v37::ScriptRef raw; raw.kind = ::v37::ScriptKind::RAW; raw.payload.clear();
                return raw;
            }
            return r;
        };

        const unsigned cap_owed = static_cast<unsigned>(
            std::min<std::size_t>(ctx.output_cap - ctx.fixed.size() - 1,
                                  std::numeric_limits<unsigned>::max()));

        if (source == KFairSource::W4Propose) {
            // W4 canon picks the set over budget - Σfixed with C = cap - fixed - sink.
            const std::uint64_t owed_budget = reward_hint - fixed_sum;
            auto h_min_of = [&](::v37::ScriptKind k) -> std::uint64_t {
                return ::v37::xmr::is_xmr_kind(k) ? ctx.h_min
                                                  : std::numeric_limits<std::uint64_t>::max();
            };
            OwedLedger::Proposal prop = ledger.propose_coinbase(owed_budget, cap_owed,
                                                                payable_ref, h_min_of);
            in.owed.reserve(prop.outs.size());
            for (std::size_t i = 0; i < prop.outs.size(); ++i) {
                x6::OwedEntry e;
                e.pay            = prop.outs[i].pay;
                e.owed           = prop.outs[i].amount;   // exactly the proposed take
                e.first_eligible = i;                     // proposal index == canonical order
                e.identity       = prop.outs[i].key;
                in.owed.push_back(std::move(e));
            }
            in.h_min = 0;                                 // W4 already applied the floor
        }
        else {
            // X6 decides: every EffectiveOwed > 0 with its real age; X6 sorts
            // (first_eligible ASC, identity ASC) and applies its own h_min rule.
            for (const auto& [k, owed] : ledger.effective_owed_all()) {
                if (owed <= 0) continue;
                ::v37::ScriptRef r = payable_ref(k);
                if (!::v37::xmr::is_xmr_kind(r.kind)) continue;   // unpayable => carry
                x6::OwedEntry e;
                e.pay            = r;
                e.owed           = static_cast<std::uint64_t>(owed);
                e.first_eligible = age_of(k);
                e.identity       = k;
                in.owed.push_back(std::move(e));
            }
            in.h_min = ctx.h_min;
        }
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

    // FOUND-record `payout`: { identity_key : piconero } over EVERY output the
    // coinbase actually pays (owed keys, fixed identities, the sink identity),
    // at the reward the template settled on (XmrBlockTemplate::get_reward()).
    // Duplicate identities (e.g. a sink that is also an owed key) SUM. Empty
    // when the allocation at `reward` fails or its shape does not match.
    Amounts payout_map_at(std::uint64_t reward) const {
        Amounts m;
        bool ok = false;
        const std::vector<x6::CoinbaseOutput> outs = outputs_at(reward, &ok);
        if (!ok) return m;
        for (const auto& o : outs) m[o.identity] += static_cast<long long>(o.amount);
        return m;
    }
    Amounts payout_map() const { return payout_map_at(m_reward_hint); }

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
