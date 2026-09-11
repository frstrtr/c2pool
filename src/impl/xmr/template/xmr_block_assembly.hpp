// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/template/xmr_block_assembly.hpp  --  X9 option B:
//                                                   WHOLE-BLOCK ASSEMBLY
//
// AUTHORED for c2pool (AGPL-3.0). NOT a port. This file is the glue that turns
// the two disconnected legs already in the tree into one producer of a FULL,
// SUBMITTABLE Monero block:
//
//   * the p2pool-derived whole-block template builder
//       XmrBlockTemplate  (xmr_block_template.{hpp,cpp}, GPL-3 via AGPLv3 s13)
//     which serialises  header || miner_tx || varint(n_tx) || 32*n tx hashes,
//     does the penalty-aware tx selection, the Keccak-midstate per-extra-nonce
//     coinbase re-hash, the tree_hash main branch and the 76..128 B RandomX
//     hashing blob -- but consumes its coinbase through the abstract seam
//       IXmrSettlementSource   (payees / r / R / P_i / split / MM leaf)
//     and its primitives through xmr_coin_primitives.hpp, which DECLARES
//     writeVarint / keccak / keccak_step / keccak_finish / umul128 / udiv128 /
//     parallel_run / seconds_since_epoch with NO bodies; and
//
//   * the X6 W5-XMR settlement executor
//       build_coinbase / allocate_exact_sum / derive_output / mm_commitment_root
//       (settle/xmr_coinbase.{hpp,cpp}, AGPL-3, KAT-pinned)
//     which is the CANON for what the coinbase pays (K_fair oldest-owed-first
//     EffectiveOwed payees ++ mandated fixed outputs ++ exact-sum residual sink,
//     HF13 no-burn), the deterministic tx key r and the 0x03 MM commitment.
//
// What this header adds (three seams, all impl-side; nothing under
// src/sharechain/v37 is touched and no consumer-tree header is included):
//
//   1. PRIMITIVE BODIES for xmr_coin_primitives.hpp, over the vendored
//      monero-project keccak.c / varint.h (BSD-3) -- compiled into exactly ONE
//      translation unit that defines XMR_BLOCK_ASSEMBLY_IMPLEMENT_PRIMITIVES
//      before including this header (see the bottom of the file).
//
//   2. X6SettlementSource : IXmrSettlementSource -- a per-template VALUE
//      snapshot built from X6 CoinbaseInputs. payees()/r/R/P_i/view tags/the
//      MM root are X6's own outputs, so "the X6 coinbase IS the block's
//      coinbase" holds by construction and is byte-proven by the self-check.
//      It also solves the p2pool COUNT-INVARIANCE assumption (the upstream
//      flow calls split_reward twice -- a sizing pass at base+sum(fees) and a
//      final pass at the penalty-adjusted reward -- and requires the same
//      miner_tx size): X6's payee SET varies with the budget, so the seam
//      accepts a reward only if X6's allocate_exact_sum at that reward yields
//      the SAME payee set (then adopts those canonical amounts, exact-sum for
//      that reward) and otherwise records the wanted reward and refuses, which
//      makes XmrBlockTemplate::update() fall back to its empty old template;
//      the assembler (3) then rebuilds the snapshot at the wanted reward and
//      iterates to a fixpoint. This keeps X6's allocation canon untouched (no
//      "sink always present" hack) and needs NO edit to the ported TU.
//
//   3. XmrBlockAssembler / AssembledTemplate -- the fixpoint driver + the
//      immutable per-build record. Every build owns its OWN seam snapshot and
//      its OWN XmrBlockTemplate (so the seam pointer the template stores can
//      never be re-queried for a stale template id after the ledger moved --
//      the OLD_TEMPLATES double-buffer sharing problem of the ported class is
//      side-stepped rather than patched), and exposes for one extra_nonce:
//         full_blob     = get_block_template_blob  (extra nonce + MM root
//                         patched, header nonce zero: the submit_block payload)
//         hashing_blob  = get_hashing_blob          (the RandomX input)
//      plus the X6 output list with FINAL amounts (the FOUND payout map) and
//      the final CoinbaseInputs (what a peer feeds canonical_coinbase_matches).
//
// Thread-safety: an AssembledTemplate is immutable after build(); all reads
// are const and touch no shared mutable state, so a listener thread may call
// materialize()/hashing_blob() concurrently while the main thread builds the
// next record. The provider (consumer tree) swaps records under its own lock.
//
// Consensus status: see the survey's gate flag. This header activates NO
// consensus rule by itself; lane parameters (residual sink, h_min, output cap,
// chain_id, the lane_commitment definition) arrive in CoinbaseInputs from the
// consumer and are REQUIRED (build fails closed without a valid sink).
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/template/xmr_block_template.hpp"   // XmrBlockTemplate, IXmrSettlementSource, XmrMinerData, XmrTxMempoolData
#include "impl/xmr/settle/xmr_coinbase.hpp"           // X6: CoinbaseInputs, build_coinbase, allocate_exact_sum, ...
#include "impl/xmr/coin/xmr_blob.hpp"                 // BlobWriter, tx_prefix_hash, coinbase_tx_hash, tree_root, branches
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"      // keccak256 (+ vendor/keccak.h under extern "C")
#include "impl/xmr/node/xmr_node_types.hpp"           // node::MinerData / TxBacklogEntry / Hash / Difficulty128

namespace c2pool::xmr::assembly {

using ::v37::xmr::settle::BuildError;
using ::v37::xmr::settle::BuiltCoinbase;
using ::v37::xmr::settle::CoinbaseInputs;
using ::v37::xmr::settle::CoinbaseOutput;
using ::v37::xmr::settle::ReceivedCoinbase;

// ===========================================================================
// Type shims: c2pool::xmr::hash (uint8_t[32], the p2pool-shaped template type)
// <-> xmr::coin::Bytes32 family (X1/X6) <-> node::Hash (std::array, X2 wire).
// All three are the same 32 little-endian bytes; memcpy is the whole adapter.
// ===========================================================================
inline hash to_hash(const ::xmr::coin::Bytes32& b) { hash h; std::memcpy(h.h, b.data(), HASH_SIZE); return h; }
inline hash to_hash(const node::Hash& a)            { hash h; std::memcpy(h.h, a.data(), HASH_SIZE); return h; }
inline ::xmr::coin::Hash256 to_hash256(const hash& h) { ::xmr::coin::Hash256 o; std::memcpy(o.data(), h.h, HASH_SIZE); return o; }
inline ::xmr::coin::Hash256 to_hash256(const node::Hash& a) { ::xmr::coin::Hash256 o; std::memcpy(o.data(), a.data(), HASH_SIZE); return o; }
inline node::Hash to_node_hash(const hash& h) { node::Hash a{}; std::memcpy(a.data(), h.h, HASH_SIZE); return a; }
inline node::Hash to_node_hash(const ::xmr::coin::Bytes32& b) { node::Hash a{}; std::memcpy(a.data(), b.data(), HASH_SIZE); return a; }
inline difficulty_type to_difficulty(const node::Difficulty128& d) { difficulty_type t; t.lo = d.lo; t.hi = d.hi; return t; }

// Monero base (subsidy) reward for the block AFTER `already_generated_coins`
// (cryptonote get_block_reward: (2^64-1 - A) >> 19, floored at the 0.6 XMR
// tail). Byte-for-byte the static helper inside xmr_block_template.cpp; it is
// re-stated here because the assembler must size the X6 budget BEFORE the
// template runs, and the self-check pins the two against each other via
// XmrBlockTemplate::get_reward().
inline std::uint64_t xmr_base_reward(std::uint64_t already_generated_coins) {
    const std::uint64_t r = ~already_generated_coins >> 19;
    return (r < BASE_BLOCK_REWARD) ? BASE_BLOCK_REWARD : r;
}

// Split a total coinbase budget back into X6's (base_reward, fees) pair given
// the consensus subsidy. Only the SUM feeds allocation and r-derivation, so the
// split is presentational: under a block-weight penalty the budget can drop
// below the subsidy, in which case base_reward := budget and fees := 0.
inline void set_budget(CoinbaseInputs& in, std::uint64_t subsidy, std::uint64_t budget) {
    if (budget >= subsidy) { in.base_reward = subsidy; in.fees = budget - subsidy; }
    else                   { in.base_reward = budget;  in.fees = 0; }
}

// --- X2 adapter values -> template inputs ------------------------------------
inline XmrMinerData from_miner_data(const node::MinerData& md, difficulty_type lane_target) {
    XmrMinerData d;
    d.major_version           = md.major_version;
    d.height                  = md.height;
    d.prev_id                 = to_hash(md.prev_id);
    d.already_generated_coins = md.already_generated_coins;
    d.median_weight           = md.median_weight;
    d.median_timestamp        = md.median_timestamp;
    d.difficulty              = to_difficulty(md.difficulty);
    d.seed_hash               = to_hash(md.seed_hash);
    d.lane_target             = lane_target;
    return d;
}
inline std::vector<XmrTxMempoolData> from_backlog(const std::vector<node::TxBacklogEntry>& backlog) {
    std::vector<XmrTxMempoolData> out;
    out.reserve(backlog.size());
    for (const auto& e : backlog) {
        XmrTxMempoolData t;
        t.id            = to_hash(e.id);
        t.weight        = e.weight ? e.weight : e.blob_size;
        t.fee           = e.fee;
        t.time_received = e.time_received;   // 0 from get_miner_data => passes the 5-s age gate
        out.push_back(t);
    }
    return out;
}

// LE32 extra nonce padded to `size` bytes -- the exact bytes the template
// writes into the 0x02 tag (EXTRA_NONCE_SIZE..EXTRA_NONCE_MAX_SIZE).
inline std::vector<unsigned char> extra_nonce_bytes(std::uint32_t extra_nonce, std::size_t size) {
    std::vector<unsigned char> v(size, 0);
    for (std::size_t i = 0; i < 4 && i < size; ++i) v[i] = static_cast<unsigned char>(extra_nonce >> (8 * i));
    return v;
}

// ===========================================================================
// X6SettlementSource -- the IXmrSettlementSource VALUE snapshot over X6.
//
// One instance per template build. Built from a complete CoinbaseInputs whose
// budget() is the reward HINT; build() runs X6 build_coinbase once, so the
// payee list, r, R, every P_i / view tag and the MM root are fixed for the life
// of the snapshot. split_reward() may ADOPT a different budget (see the header
// banner) but never a different payee set -- the keys do not depend on the
// amounts, which is why re-deriving is unnecessary and the template's two-pass
// flow stays sound.
//
// RULED 2026-09-10 (multi-node): when a `reproject_owed` callback is supplied,
// the OWED ROWS are re-derived from the canonical K_fair rule at every reward
// the template proposes, BEFORE X6 allocates. The same_set() gate is unchanged
// and still governs adoption -- a re-projection that changes the SET is
// refused, the reward is handed back, and the assembler rebuilds at it. So the
// block's payee set is OwedLedger::propose_coinbase output at the reward the
// block pays. With no callback the behaviour is byte-identical to before.
//
// Call protocol with XmrBlockTemplate::update() (upstream order, pinned to the
// p2pool commit named in xmr_block_template.hpp):
//   payees() ... merkle_tree_data() ... split_reward(base + sum(fees))   [1]
//   create_miner_tx(dry_run)  -> derive_output_key not called
//   [tx selection]            split_reward(final_reward)                 [2]
//   create_miner_tx(final)    -> derive_output_key(i) for every payee,
//                                tx_public_key()
//   calc_miner_tx_hash(0)     -> commitment_leaf(0)
//   (-3 path only: split_reward(r2) [3], dry-run, split_reward(final') [4])
// begin_update() resets the call counter; call [1] is the SIZING pass and
// returns the snapshot's canonical amounts (the sizing amounts only bound the
// amount-varint weight; p2pool's padded extra nonce absorbs any difference).
// Every later call is a REAL reward and goes through the same-set rule.
// ===========================================================================
class X6SettlementSource final : public IXmrSettlementSource {
public:
    // Build the snapshot. `in.budget()` is the reward hint. Returns nullptr and
    // fills *why (if given) when X6 refuses (CARROT fence, bad sink/payee ref,
    // fixed > budget, cap too small, derivation failure) -- fail closed.
    // Re-project the canonical K_fair owed rows at ONE reward and ONE resolved
    // total-output cap. Supplied by the consumer tree (the option-B provider
    // binds it to project_w4_owed over the live OwedLedger). EMPTY => the
    // pre-ruling frozen-rows behaviour, so a caller that does not set it (every
    // impl-only KAT) is byte-identical to the previous release.
    using ReprojectOwedFn =
        std::function<bool(std::uint64_t reward, std::uint32_t output_cap,
                           std::vector<::v37::xmr::settle::OwedEntry>& out, std::string* why)>;

    static std::unique_ptr<X6SettlementSource> build(const CoinbaseInputs& in,
                                                     std::uint64_t subsidy,
                                                     std::string* why,
                                                     ReprojectOwedFn reproject = {}) {
        std::unique_ptr<X6SettlementSource> s(new X6SettlementSource());
        s->m_in = in;
        s->m_reproject = std::move(reproject);
        s->m_in.extra_nonce = extra_nonce_bytes(0, EXTRA_NONCE_SIZE); // keys/amounts are nonce-independent
        s->m_subsidy = subsidy;
        s->m_cb = ::v37::xmr::settle::build_coinbase(s->m_in);
        if (!s->m_cb.ok) {
            if (why) *why = std::string("X6 build_coinbase refused: ") + s->m_cb.detail;
            return nullptr;
        }
        s->m_payees.clear();
        s->m_payees.reserve(s->m_cb.outputs.size());
        for (const auto& o : s->m_cb.outputs) {
            XmrPayee p;
            std::memcpy(p.spend_public_key.h, o.pay.payload.data(), HASH_SIZE);      // B (or D_i)
            std::memcpy(p.view_public_key.h,  o.pay.payload.data() + HASH_SIZE, HASH_SIZE); // A
            s->m_payees.push_back(p);
        }
        s->m_r    = to_hash(s->m_cb.r);
        s->m_R    = to_hash(s->m_cb.R);
        s->m_leaf = to_hash(s->m_cb.mm_root);
        return s;
    }

    // ---- IXmrSettlementSource ---------------------------------------------
    [[nodiscard]] const std::vector<XmrPayee>& payees() const override { return m_payees; }
    [[nodiscard]] const hash& tx_secret_key() const override { return m_r; }
    [[nodiscard]] const hash& tx_public_key() const override { return m_R; }

    [[nodiscard]] bool derive_output_key(std::size_t i, std::uint8_t hf_major,
                                         hash& out_eph_pubkey, std::uint8_t& out_view_tag) const override {
        // CARROT/FCMP++ fence: the template's fork must be the fork r was
        // derived under, and pre-CARROT. Otherwise the template refuses.
        if (!::v37::xmr::xmr_precarrot_ok(hf_major)) return false;
        if (hf_major != m_in.monero_major_version) return false;
        if (i >= m_cb.outputs.size()) return false;
        out_eph_pubkey = to_hash(m_cb.outputs[i].one_time_key);
        out_view_tag   = m_cb.outputs[i].view_tag.tag;
        return true;
    }

    [[nodiscard]] bool split_reward(std::uint64_t reward, std::vector<std::uint64_t>& rewards) const override {
        ++m_split_calls;
        if (m_split_calls == 1) {
            // sizing pass (upstream call [1]); amounts only bound varint weight
            fill_amounts(rewards);
            return true;
        }
        if (reward == m_in.budget()) { fill_amounts(rewards); return true; }

        // A different real reward. RULED 2026-09-10: the payee set must be the
        // canonical K_fair proposal AT THE REWARD THE BLOCK PAYS, so re-project
        // the owed rows first (when the consumer supplied the hook) and only
        // then ask X6 to allocate. Accept iff the allocation at that reward pays
        // the SAME ordered payee set; then adopt its amounts AND its rows.
        CoinbaseInputs probe = m_in;
        set_budget(probe, m_subsidy, reward);
        if (m_reproject) {
            std::string w;
            if (!m_reproject(reward, probe.output_cap, probe.owed, &w)) {
                m_wanted = reward;
                return false;   // fail closed: the assembler rebuilds at `reward`
            }
        }
        BuildError err = BuildError::None;
        std::vector<CoinbaseOutput> alt = ::v37::xmr::settle::allocate_exact_sum(probe, &err);
        if (alt.empty() || !same_set(alt)) {
            m_wanted = reward;
            return false;   // template falls back; the assembler rebuilds at `reward`
        }
        for (std::size_t i = 0; i < alt.size(); ++i) m_cb.outputs[i].amount = alt[i].amount;
        set_budget(m_in, m_subsidy, reward);
        // Carry the re-projected rows into the FINAL inputs so the FOUND record
        // and any peer's ACCEPT re-derivation (coinbase_inputs()) hold the
        // canonical set for the reward actually paid, not the sizing hint's.
        if (m_reproject) m_in.owed = std::move(probe.owed);
        m_cb.budget = reward;
        fill_amounts(rewards);
        return true;
    }

    // Single MM-tree leaf: root == leaf == X6 mm_commitment_root(chain_id,
    // lane_commitment); extra-nonce independent (the nonce lives in 0x02).
    [[nodiscard]] hash commitment_leaf(std::uint32_t /*extra_nonce*/) const override { return m_leaf; }
    // depth 0 => the template's 0x03 tag is  03 | 0x21 | 0x00 | root[32],
    // byte-identical to X6 assemble_tx_extra.
    [[nodiscard]] std::uint64_t merkle_tree_data() const override { return 0; }

    // ---- assembler protocol / read-back ------------------------------------
    void begin_update() const { m_split_calls = 0; m_wanted.reset(); }
    [[nodiscard]] std::uint64_t budget() const { return m_in.budget(); }
    [[nodiscard]] std::optional<std::uint64_t> wanted_reward() const { return m_wanted; }
    [[nodiscard]] unsigned split_calls() const { return m_split_calls; }

    // The FINAL inputs (budget adopted) and outputs (amounts adopted): what a
    // peer's canonical_coinbase_matches() must be fed.
    //
    // R-7 CORRECTION (2026-09-10): an earlier revision of this comment claimed
    // the FOUND payout map runs over ALL outputs (owed / fixed / sink). That is
    // WRONG under the W4 contract. OwedLedger's payout term is SUBTRACTED from
    // finalW at FINALIZE (w4_settlement.hpp:485-500) and is only ever legal for
    // keys that were CREDITED into finalW — the K_fair owed rows the coinbase
    // drew EffectiveOwed for. A Fixed or Sink identity was never credited, so
    // booking it would drive that key's finalW permanently negative. The FOUND
    // payout map is the Role::Owed SUBSET ONLY; consumers filter on
    // CoinbaseOutput::Role::Owed (see c2pool/v37/xmr/xmr_o2_finalize_connect.hpp
    // and main_v37_xmr.cpp's candidate lookup).
    // And read THIS vector — never a re-run of the W4 projection: X6's owed pass
    // can legitimately emit FEWER rows than W4 proposed (a budget-truncated
    // sub-h_min tail BREAKs here and the sink absorbs it, xmr_coinbase.cpp:
    // 135-139, while W4 CARRYs and keeps scanning, w4_settlement.hpp:586-587).
    [[nodiscard]] const CoinbaseInputs& inputs() const { return m_in; }
    [[nodiscard]] const std::vector<CoinbaseOutput>& outputs() const { return m_cb.outputs; }
    [[nodiscard]] const BuiltCoinbase& built() const { return m_cb; }
    [[nodiscard]] std::uint64_t subsidy() const { return m_subsidy; }

private:
    X6SettlementSource() = default;

    void fill_amounts(std::vector<std::uint64_t>& rewards) const {
        rewards.resize(m_cb.outputs.size());
        for (std::size_t i = 0; i < rewards.size(); ++i) rewards[i] = m_cb.outputs[i].amount;
    }
    bool same_set(const std::vector<CoinbaseOutput>& alt) const {
        if (alt.size() != m_cb.outputs.size()) return false;
        for (std::size_t i = 0; i < alt.size(); ++i) {
            const CoinbaseOutput& a = alt[i];
            const CoinbaseOutput& b = m_cb.outputs[i];
            if (a.role != b.role || !(a.pay == b.pay) || a.identity != b.identity) return false;
            if (a.amount == 0) return false;   // never emit a zero-amount output
        }
        return true;
    }

    ReprojectOwedFn        m_reproject;   // empty => frozen rows (pre-ruling behaviour)
    mutable CoinbaseInputs m_in;
    mutable BuiltCoinbase  m_cb;
    std::uint64_t          m_subsidy = 0;
    std::vector<XmrPayee>  m_payees;
    hash m_r, m_R, m_leaf;
    mutable unsigned                     m_split_calls = 0;
    mutable std::optional<std::uint64_t> m_wanted;
};

// ===========================================================================
// One materialised (template, extra_nonce) pair: the two blobs the submit path
// needs plus every offset a submitter or verifier patches / inspects.
// ===========================================================================
struct BlockBytes {
    std::uint32_t extra_nonce = 0;
    std::vector<std::uint8_t> full_blob;     // header(nonce=0) || miner_tx || varint(n_tx) || 32*n   -> submit_block (patch nonce first)
    std::vector<std::uint8_t> hashing_blob;  // header(nonce=0) || tree_root[32] || varint(n_tx+1)      -> RandomX input
    std::size_t nonce_offset = 0;            // 4-B header nonce, same offset in BOTH blobs (39 for v16 / 5-B timestamp varint)
    std::size_t miner_tx_offset = 0;         // == header size
    std::size_t extra_nonce_offset = 0;      // in full_blob: first byte of the 0x02 payload
    std::size_t extra_nonce_size = 0;        // 4..14 (padded)
    std::size_t merkle_root_offset = 0;      // in full_blob: the 32-B root inside the 0x03 tag
    std::size_t miner_tx_size = 0;           // incl. trailing rct_type byte
    ::xmr::coin::Hash256 merkle_root{};      // MM commitment root patched at merkle_root_offset (== X6 mm_root)
    ::xmr::coin::Hash256 tree_root{};        // tx tree root inside hashing_blob
    std::vector<::xmr::coin::Hash256> tx_hashes; // non-coinbase tx ids in the template's order (leaf 1..n)

    // The miner_tx PREFIX (everything but the rct_type byte): what X6
    // build_coinbase(...).prefix must equal for this extra_nonce.
    [[nodiscard]] std::vector<unsigned char> coinbase_prefix() const {
        return std::vector<unsigned char>(full_blob.begin() + static_cast<std::ptrdiff_t>(miner_tx_offset),
                                          full_blob.begin() + static_cast<std::ptrdiff_t>(miner_tx_offset + miner_tx_size - 1));
    }
};

// Monero block id = keccak256( varint(len(hashing_blob)) || hashing_blob ), with
// the nonce already patched into the blob (get_block_hash over the hashing blob).
inline ::xmr::coin::Hash256 block_id_of(const std::vector<std::uint8_t>& hashing_blob_with_nonce) {
    ::xmr::coin::BlobWriter w;
    w.put_varint(hashing_blob_with_nonce.size());
    w.put_bytes(hashing_blob_with_nonce.data(), hashing_blob_with_nonce.size());
    return ::xmr::coin::keccak256(w.bytes());
}

// Parse a serialised coinbase PREFIX (version .. tx_extra) into X6's
// ReceivedCoinbase for canonical_coinbase_matches(). Accepts the miner_tx as
// found in a block blob (the rct_type byte after the prefix is ignored). Returns
// false on any structural error. *consumed = prefix length on success.
inline bool parse_coinbase_prefix(const std::uint8_t* p, std::size_t n,
                                  ReceivedCoinbase& out, std::uint64_t* height_out = nullptr,
                                  std::size_t* consumed = nullptr) {
    const std::uint8_t* it = p;
    const std::uint8_t* end = p + n;
    auto rd = [&](std::uint64_t& v) -> bool { return tools::read_varint(it, end, v) > 0; };
    std::uint64_t version = 0, unlock = 0, vin = 0, height = 0, nout = 0, xlen = 0;
    if (!rd(version) || version != TX_VERSION) return false;
    if (!rd(unlock)) return false;
    if (!rd(vin) || vin != 1) return false;
    if (it >= end || *it++ != TXIN_GEN) return false;
    if (!rd(height)) return false;
    if (unlock != height + MINER_REWARD_UNLOCK_TIME) return false;
    if (!rd(nout)) return false;
    out.amounts.clear(); out.keys.clear(); out.view_tags.clear();
    for (std::uint64_t i = 0; i < nout; ++i) {
        std::uint64_t amt = 0;
        if (!rd(amt)) return false;
        if (it >= end || *it++ != TXOUT_TO_TAGGED_KEY) return false;
        if (static_cast<std::size_t>(end - it) < HASH_SIZE + 1) return false;
        ::xmr::coin::PublicKey k; std::memcpy(k.data(), it, HASH_SIZE); it += HASH_SIZE;
        ::xmr::coin::ViewTag vt; vt.tag = *it++;
        out.amounts.push_back(amt); out.keys.push_back(k); out.view_tags.push_back(vt);
    }
    if (!rd(xlen) || static_cast<std::size_t>(end - it) < xlen) return false;
    out.tx_extra.assign(it, it + xlen);
    it += xlen;
    // tx pubkey: tag 0x01 must be the first extra field (X6 layout)
    if (out.tx_extra.size() < 1 + HASH_SIZE || out.tx_extra[0] != TX_EXTRA_TAG_PUBKEY) return false;
    std::memcpy(out.R.data(), out.tx_extra.data() + 1, HASH_SIZE);
    if (height_out) *height_out = height;
    if (consumed) *consumed = static_cast<std::size_t>(it - p);
    return true;
}

// ===========================================================================
// AssembledTemplate -- the immutable per-build record (one ledger snapshot, one
// prev_id, one payee set, one XmrBlockTemplate). Owns the seam it was built
// over; the seam is declared FIRST so it outlives the template that points to it.
// ===========================================================================
class AssembledTemplate {
public:
    [[nodiscard]] std::uint64_t height() const { return m_tpl->get_height(); }
    [[nodiscard]] std::uint64_t reward() const { return m_tpl->get_reward(); }   // == seam().budget() == sum(outputs)
    [[nodiscard]] std::uint8_t  major_version() const { return m_major; }
    [[nodiscard]] const ::xmr::coin::Hash256& prev_id() const { return m_prev_id; }
    [[nodiscard]] const ::xmr::coin::Hash256& seed_hash() const { return m_seed_hash; }
    [[nodiscard]] difficulty_type lane_target() const { return m_tpl->get_lane_target(); }
    [[nodiscard]] std::size_t nonce_offset() const { return m_nonce_offset; }
    [[nodiscard]] std::size_t n_tx() const { return m_n_tx; }
    [[nodiscard]] int passes() const { return m_passes; }                        // fixpoint passes taken
    [[nodiscard]] std::uint64_t built_at() const { return m_tpl->last_updated(); }
    [[nodiscard]] const X6SettlementSource& seam() const { return *m_seam; }
    [[nodiscard]] const XmrBlockTemplate& tpl() const { return *m_tpl; }

    // FOUND record material: what the coinbase actually pays, by identity.
    [[nodiscard]] const std::vector<CoinbaseOutput>& outputs() const { return m_seam->outputs(); }
    [[nodiscard]] const CoinbaseInputs& coinbase_inputs() const { return m_seam->inputs(); }

    // RandomX hashing blob for one extra nonce (76..128 B). Header nonce zero.
    [[nodiscard]] std::vector<std::uint8_t> hashing_blob(std::uint32_t extra_nonce,
                                                         std::size_t* nonce_offset = nullptr) const {
        std::uint8_t buf[HASHING_BLOB_MAX_SIZE];
        std::uint64_t h = 0; difficulty_type t; hash seed; std::size_t no = 0; std::uint32_t tid = 0;
        const std::uint32_t n = m_tpl->get_hashing_blob(extra_nonce, buf, h, t, seed, no, tid);
        if (nonce_offset) *nonce_offset = no;
        return std::vector<std::uint8_t>(buf, buf + n);
    }

    // Both blobs + offsets for one extra nonce. Returns false only if the
    // template's own invariants fail (header prefix disagreement / layout).
    [[nodiscard]] bool materialize(std::uint32_t extra_nonce, BlockBytes& out, std::string* why = nullptr) const {
        out = BlockBytes{};
        out.extra_nonce = extra_nonce;
        hash root;
        out.full_blob = m_tpl->get_block_template_blob(m_internal_tid, extra_nonce,
                                                       out.nonce_offset, out.extra_nonce_offset,
                                                       out.merkle_root_offset, root);
        out.merkle_root = to_hash256(root);
        out.miner_tx_offset = out.nonce_offset + NONCE_SIZE;
        out.miner_tx_size   = m_miner_tx_size;
        out.extra_nonce_size = m_extra_nonce_size;
        out.tx_hashes = m_tx_hashes;

        std::size_t no2 = 0;
        out.hashing_blob = hashing_blob(extra_nonce, &no2);
        if (no2 != out.nonce_offset || out.hashing_blob.size() < HASHING_BLOB_MIN_SIZE ||
            out.hashing_blob.size() > HASHING_BLOB_MAX_SIZE) {
            if (why) *why = "assembled hashing blob out of range / nonce offset mismatch";
            return false;
        }
        // validate_candidate() invariant: both blobs share the header through the nonce.
        if (out.full_blob.size() < out.miner_tx_offset ||
            std::memcmp(out.full_blob.data(), out.hashing_blob.data(), out.miner_tx_offset) != 0) {
            if (why) *why = "full_blob / hashing_blob header prefix disagree";
            return false;
        }
        if (out.merkle_root_offset + HASH_SIZE + 1 != out.miner_tx_offset + out.miner_tx_size) {
            if (why) *why = "miner_tx layout: MM root is not the last prefix field";
            return false;
        }
        std::memcpy(out.tree_root.data(), out.hashing_blob.data() + out.miner_tx_offset, HASH_SIZE);
        return true;
    }

private:
    friend class XmrBlockAssembler;
    AssembledTemplate() = default;

    std::unique_ptr<X6SettlementSource> m_seam;   // FIRST: must outlive m_tpl
    std::unique_ptr<XmrBlockTemplate>   m_tpl;
    std::uint32_t m_internal_tid = 0;             // the template's own id (1 for a fresh object)
    std::uint8_t  m_major = 0;
    ::xmr::coin::Hash256 m_prev_id{};
    ::xmr::coin::Hash256 m_seed_hash{};
    std::size_t m_nonce_offset = 0;
    std::size_t m_miner_tx_size = 0;
    std::size_t m_extra_nonce_size = 0;
    std::size_t m_n_tx = 0;
    std::vector<::xmr::coin::Hash256> m_tx_hashes;
    int m_passes = 0;
};

// ===========================================================================
// XmrBlockAssembler -- build one AssembledTemplate from miner data + backlog +
// the lane's X6 context, iterating the reward/payee-set fixpoint.
// ===========================================================================
struct AssemblyInputs {
    XmrMinerData                  miner;      // from_miner_data()
    std::vector<XmrTxMempoolData> mempool;    // from_backlog()
    // Lane context: owed / fixed / residual_sink(+identity) / chain_id /
    // lane_commitment / h_min / output_cap. monero_major_version, height,
    // prev_id, base_reward, fees and extra_nonce are OVERWRITTEN from `miner`
    // and the template's final reward. output_cap == 0 => weight-aware default.
    CoinbaseInputs                settle;
    std::uint32_t                 wire_cap = 2700;   // output cap ceiling when output_cap == 0
    int                           max_passes = 6;    // fixpoint bound (fail closed beyond)

    // RULED 2026-09-10 (multi-node): re-derive the canonical K_fair owed rows at
    // EVERY reward the fixpoint visits, so the block's payee set is
    // OwedLedger::propose_coinbase output at the reward the block ACTUALLY pays.
    // The consumer tree binds this to project_w4_owed over the live ledger; it
    // is handed `in.output_cap`, i.e. the RESOLVED weight-aware cap, which also
    // closes the cap disagreement between the W4 proposal (cut at the config's
    // cap) and X6's allocation (cut at the weight-aware cap).
    // EMPTY => frozen rows, byte-identical to the pre-ruling assembler; every
    // impl-only KAT below leaves it empty on purpose.
    X6SettlementSource::ReprojectOwedFn reproject_owed;
};

class XmrBlockAssembler {
public:
    static std::unique_ptr<AssembledTemplate> build(const AssemblyInputs& a, std::string* why) {
        auto fail = [&](const std::string& s) -> std::unique_ptr<AssembledTemplate> { if (why) *why = s; return nullptr; };

        if (a.miner.height == 0) return fail("miner data: height 0");
        // CARROT fence FIRST: the v37 lane's governing pre-CARROT rule
        // (output-key derivation is pre-CARROT). It is checked before the
        // template's own HARDFORK_SUPPORTED_VERSION pin so the refusal names the
        // lane fence that actually governs (both are pinned at 16 today).
        if (!::v37::xmr::xmr_precarrot_ok(a.miner.major_version))
            return fail("CARROT_FENCE: major_version " + std::to_string(a.miner.major_version) +
                        " > pre-CARROT max " + std::to_string(::v37::xmr::XMR_PRECARROT_MAX_MAJOR_VERSION));
        if (a.miner.major_version > HARDFORK_SUPPORTED_VERSION)
            return fail("template refuses major_version " + std::to_string(a.miner.major_version) +
                        " > HARDFORK_SUPPORTED_VERSION " + std::to_string(HARDFORK_SUPPORTED_VERSION));

        const std::uint64_t subsidy = xmr_base_reward(a.miner.already_generated_coins);
        std::uint64_t fees_all = 0, weight_all = 0;
        for (const auto& t : a.mempool) { fees_all += t.fee; weight_all += t.weight; }

        CoinbaseInputs base = a.settle;
        base.monero_major_version = a.miner.major_version;
        base.height  = a.miner.height;
        base.prev_id = to_hash256(a.miner.prev_id);
        if (base.output_cap == 0)
            base.output_cap = ::v37::xmr::settle::weight_aware_output_cap(a.miner.median_weight, weight_all, a.wire_cap);

        std::uint64_t hint = subsidy + fees_all;   // == the template's sizing-pass reward
        std::vector<std::uint64_t> tried;
        std::string sub;

        for (int pass = 1; pass <= a.max_passes; ++pass) {
            CoinbaseInputs in = base;
            set_budget(in, subsidy, hint);
            // RULED: the owed rows are the canonical K_fair proposal AT THIS
            // reward and at the RESOLVED (weight-aware) cap — fail closed.
            if (a.reproject_owed &&
                !a.reproject_owed(hint, in.output_cap, in.owed, &sub))
                return fail("pass " + std::to_string(pass) + ": reproject_owed refused: " + sub);

            std::unique_ptr<X6SettlementSource> seam =
                X6SettlementSource::build(in, subsidy, &sub, a.reproject_owed);
            if (!seam) return fail("pass " + std::to_string(pass) + ": " + sub);

            std::unique_ptr<XmrBlockTemplate> tpl(new XmrBlockTemplate(seam.get()));
            seam->begin_update();
            tpl->update(a.miner, a.mempool);

            const bool ok = tpl->last_updated() != 0 && tpl->get_height() == a.miner.height && tpl->get_reward() != 0;
            if (ok) {
                if (tpl->get_reward() != seam->budget())
                    return fail("internal: template reward " + std::to_string(tpl->get_reward()) +
                                " != adopted budget " + std::to_string(seam->budget()));
                std::uint64_t sum = 0;
                for (const auto& o : seam->outputs()) sum += o.amount;
                if (sum != tpl->get_reward())
                    return fail("internal: sum(outputs) != reward (exact-sum violated)");

                std::unique_ptr<AssembledTemplate> rec(new AssembledTemplate());
                rec->m_seam = std::move(seam);
                rec->m_tpl  = std::move(tpl);
                rec->m_major = a.miner.major_version;
                rec->m_prev_id = to_hash256(a.miner.prev_id);
                rec->m_seed_hash = to_hash256(a.miner.seed_hash);
                rec->m_passes = pass;
                if (!finish_layout(*rec, why)) return nullptr;
                return rec;
            }

            const std::optional<std::uint64_t> w = seam->wanted_reward();
            if (!w) return fail("pass " + std::to_string(pass) + ": template refused (no reward requested; "
                                "split calls=" + std::to_string(seam->split_calls()) + ")");
            tried.push_back(hint);
            if (std::find(tried.begin(), tried.end(), *w) != tried.end())
                return fail("pass " + std::to_string(pass) + ": reward/payee-set fixpoint cycle at " + std::to_string(*w));
            hint = *w;
        }
        return fail("no reward/payee-set fixpoint within " + std::to_string(a.max_passes) + " passes");
    }

private:
    // Derive the layout constants from a probe materialisation at extra_nonce 0
    // and parse the tx-hash list off the template blob.
    static bool finish_layout(AssembledTemplate& rec, std::string* why) {
        // internal template id: read it back rather than assume 1
        {
            std::uint8_t buf[HASHING_BLOB_MAX_SIZE];
            std::uint64_t h = 0; difficulty_type t; hash seed; std::size_t no = 0; std::uint32_t tid = 0;
            const std::uint32_t n = rec.m_tpl->get_hashing_blob(0, buf, h, t, seed, no, tid);
            if (tid == 0 || n < HASHING_BLOB_MIN_SIZE || n > HASHING_BLOB_MAX_SIZE) {
                if (why) *why = "internal: probe hashing blob invalid";
                return false;
            }
            rec.m_internal_tid = tid;
            rec.m_nonce_offset = no;
            // trailing varint = n_tx + 1
            const std::uint8_t* it = buf + no + NONCE_SIZE + HASH_SIZE;
            const std::uint8_t* bend = buf + n;   // named lvalue: read_varint deduces one InputIt for both ends
            std::uint64_t cnt = 0;
            if (tools::read_varint(it, bend, cnt) <= 0 || cnt == 0 || it != bend) {
                if (why) *why = "internal: probe hashing blob tx count varint";
                return false;
            }
            rec.m_n_tx = static_cast<std::size_t>(cnt - 1);
        }
        std::size_t no = 0, eo = 0, ro = 0; hash root;
        const std::vector<std::uint8_t> full = rec.m_tpl->get_block_template_blob(rec.m_internal_tid, 0, no, eo, ro, root);
        const std::size_t header = no + NONCE_SIZE;
        // 0x02 tag layout: 02 | varint(len) | payload ; len < 0x80 so one byte
        if (eo < 2 || eo > full.size() || full[eo - 2] != TX_EXTRA_NONCE) {
            if (why) *why = "internal: extra-nonce tag layout";
            return false;
        }
        rec.m_extra_nonce_size = full[eo - 1];
        if (rec.m_extra_nonce_size < EXTRA_NONCE_SIZE || rec.m_extra_nonce_size > EXTRA_NONCE_MAX_SIZE) {
            if (why) *why = "internal: extra-nonce size out of range";
            return false;
        }
        // miner_tx ends right after the MM root + the rct_type byte
        const std::size_t tx_end = ro + HASH_SIZE + 1;
        if (tx_end > full.size() || full[tx_end - 1] != 0) {
            if (why) *why = "internal: rct_type byte";
            return false;
        }
        rec.m_miner_tx_size = tx_end - header;
        // varint(n_tx) || 32*n
        const std::uint8_t* it = full.data() + tx_end;
        const std::uint8_t* fend = full.data() + full.size();   // named lvalue for read_varint deduction
        std::uint64_t n = 0;
        if (tools::read_varint(it, fend, n) <= 0 || n != rec.m_n_tx ||
            static_cast<std::size_t>(fend - it) != n * HASH_SIZE) {
            if (why) *why = "internal: tx-hash list layout";
            return false;
        }
        rec.m_tx_hashes.resize(static_cast<std::size_t>(n));
        for (std::size_t i = 0; i < n; ++i) std::memcpy(rec.m_tx_hashes[i].data(), it + i * HASH_SIZE, HASH_SIZE);
        return true;
    }
};

// ===========================================================================
// SELF-CHECK (the KATs that prove "X6's coinbase IS the block's coinbase").
// Header-only so a KAT executable is a 3-line TU; returns true iff every check
// passes, appending a line per check to `log`.
// ===========================================================================
namespace kat {

inline void hex_into(std::string& s, const void* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    const auto* b = static_cast<const unsigned char*>(p);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
}
inline std::array<std::uint8_t, 32> unhex32(const char* h) {
    std::array<std::uint8_t, 32> o{};
    auto nib = [](char c) -> int { return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0; };
    for (std::size_t i = 0; i < 32; ++i) o[i] = static_cast<std::uint8_t>((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
    return o;
}

struct Checker {
    std::string& log; int pass = 0, fail = 0;
    explicit Checker(std::string& l) : log(l) {}
    bool operator()(bool ok, const std::string& what) {
        log += ok ? "  [PASS] " : "  [FAIL] "; log += what; log += '\n';
        if (ok) ++pass; else ++fail;
        return ok;
    }
};

// Real ed25519 points from the OFFICIAL monero-project tests/crypto/tests.txt
// vectors (same ones xmr_coinbase_kat.cpp uses): B = derive_public_key base,
// A = generate_key_derivation pub. Canonical on-curve points => ECDH works.
inline ::v37::ScriptRef std_ref() {
    return ::v37::xmr::make_xmr_std(unhex32("6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39"),
                                    unhex32("fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984"));
}
inline ::v37::bytes32 id_of(unsigned char seed) {
    ::v37::bytes32 b{}; for (int i = 0; i < 32; ++i) b[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(seed + i); return b;
}
inline hash hash_of(unsigned char seed) { hash h; for (std::size_t i = 0; i < HASH_SIZE; ++i) h.h[i] = static_cast<std::uint8_t>(seed * 7 + i); return h; }

inline CoinbaseInputs lane_ctx() {
    CoinbaseInputs in;
    in.chain_id = 0x0000ABCD;
    in.lane_commitment = id_of(0x11);
    in.residual_sink = std_ref();
    in.residual_sink_identity = id_of(0x99);
    in.h_min = 0;
    in.output_cap = 2700;
    return in;
}
inline XmrMinerData miner(std::uint64_t height, std::uint64_t median_weight, std::uint64_t agc, std::uint8_t major = 16) {
    XmrMinerData d;
    d.major_version = major; d.height = height; d.prev_id = hash_of(0x31);
    d.already_generated_coins = agc; d.median_weight = median_weight; d.median_timestamp = 1700000000;
    d.difficulty.lo = 1000; d.seed_hash = hash_of(0x53); d.lane_target.lo = 0xFFFFFFFFFFFFFFFFull;
    return d;
}
inline std::vector<XmrTxMempoolData> txs(std::size_t n, std::uint64_t weight, std::uint64_t fee) {
    std::vector<XmrTxMempoolData> v;
    for (std::size_t i = 0; i < n; ++i) { XmrTxMempoolData t; t.id = hash_of(static_cast<unsigned char>(0x80 + i)); t.weight = weight; t.fee = fee; v.push_back(t); }
    return v;
}

// (a)+(b)+(c)+(d) for one template and one extra nonce.
inline bool check_template(Checker& C, const AssembledTemplate& t, std::uint32_t en, const std::string& tag) {
    BlockBytes b; std::string why;
    if (!C(t.materialize(en, b, &why), tag + " materialize(en=" + std::to_string(en) + ") " + why)) return false;

    // (a) miner_tx prefix == X6 build_coinbase(final inputs, extra_nonce padded).prefix
    CoinbaseInputs ref = t.coinbase_inputs();
    ref.extra_nonce = extra_nonce_bytes(en, b.extra_nonce_size);
    const BuiltCoinbase cb = ::v37::xmr::settle::build_coinbase(ref);
    const std::vector<unsigned char> got = b.coinbase_prefix();
    bool ok = C(cb.ok && got == cb.prefix, tag + " (a) template miner_tx prefix == X6 build_coinbase().prefix");
    ok &= C(b.merkle_root == cb.mm_root, tag + " (a') patched MM root == X6 mm_root");
    ok &= C(std::memcmp(got.data() + (got.size() - HASH_SIZE), cb.mm_root.data(), HASH_SIZE) == 0, tag + " (a'') MM root is the last prefix field");
    std::uint64_t sum = 0; for (const auto& o : t.outputs()) sum += o.amount;
    ok &= C(sum == t.reward() && sum == cb.budget, tag + " exact-sum: sum(outputs) == template reward == X6 budget");

    // (b)+(c) tree root == tree_root([X6 coinbase_tx_hash] ++ template tx ids); branch verifies
    std::vector<::xmr::coin::Hash256> leaves; leaves.push_back(cb.coinbase_tx_hash);
    for (const auto& h : b.tx_hashes) leaves.push_back(h);
    const ::xmr::coin::Hash256 root = ::xmr::coin::tree_root(leaves);
    ok &= C(root == b.tree_root, tag + " (b)(c) hashing-blob tree root == tree_root([X6 leaf0] ++ tx ids), n_tx=" + std::to_string(b.tx_hashes.size()));
    ::xmr::coin::TreeBranch br;
    ok &= C(::xmr::coin::make_coinbase_branch(leaves, br) && ::xmr::coin::verify_branch(cb.coinbase_tx_hash, br, b.tree_root),
            tag + " (c') coinbase branch verifies against the served root");

    // (d) both blobs share the header; block id computes; extra nonce bytes patched
    ok &= C(b.nonce_offset == 39 || b.nonce_offset == 38 || b.nonce_offset == 40, tag + " (d) nonce offset " + std::to_string(b.nonce_offset));
    ok &= C(std::memcmp(b.full_blob.data(), b.hashing_blob.data(), b.nonce_offset + NONCE_SIZE) == 0, tag + " (d') header prefix agrees (validate_candidate invariant)");
    ok &= C(std::memcmp(b.full_blob.data() + b.extra_nonce_offset, ref.extra_nonce.data(), b.extra_nonce_size) == 0, tag + " (d'') extra nonce bytes patched at extra_nonce_offset");
    ok &= C(b.hashing_blob.size() >= HASHING_BLOB_MIN_SIZE && b.hashing_blob.size() <= HASHING_BLOB_MAX_SIZE, tag + " hashing blob size " + std::to_string(b.hashing_blob.size()));
    std::vector<std::uint8_t> hb = b.hashing_blob; hb[b.nonce_offset] = 0x2A;
    const ::xmr::coin::Hash256 bid = block_id_of(hb);
    ok &= C(!(bid == ::xmr::coin::Hash256{}), tag + " block id computes");

    // (e) the served prefix re-parses and canonical_coinbase_matches() == true (the W3 ACCEPT check)
    ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    ok &= C(parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, rc, &h, &used) && used == got.size() && h == t.height(),
            tag + " (e) miner_tx prefix parses (height " + std::to_string(h) + ")");
    const auto m = ::v37::xmr::settle::canonical_coinbase_matches(ref, rc);
    ok &= C(m.matches, tag + " (e') canonical_coinbase_matches(final inputs, parsed) == true " + m.reason);
    // negative control: a different lane_commitment must NOT match (R and the MM root move)
    CoinbaseInputs bad = ref; bad.lane_commitment = id_of(0x22);
    ok &= C(!::v37::xmr::settle::canonical_coinbase_matches(bad, rc).matches, tag + " (e'') negative: other lane_commitment does not match");
    return ok;
}

inline bool selfcheck(std::string& log) {
    Checker C(log);

    // ---- K0: primitive bodies vs the vendored reference ----------------------
    {
        for (std::uint64_t v : {0ull, 1ull, 127ull, 128ull, 300ull, 16383ull, 16384ull, 600000000000ull, 35184372088831ull, 0xFFFFFFFFFFFFFFFFull}) {
            std::vector<std::uint8_t> a; writeVarint(v, a);
            ::xmr::coin::BlobWriter w; w.put_varint(v);
            C(a == w.bytes(), "K0 writeVarint(" + std::to_string(v) + ") == tools::write_varint");
        }
        std::vector<std::uint8_t> buf(300);
        for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<std::uint8_t>((i * 131 + 7) & 0xff);
        hash md; keccak(buf.data(), buf.size(), md.h);
        C(to_hash256(md) == ::xmr::coin::keccak256(buf), "K0 keccak() one-shot == cn_fast_hash");
        bool all = true; int n_fast = 0;
        for (std::size_t len = 0; len <= buf.size(); ++len) {
            const ::xmr::coin::Hash256 want = ::xmr::coin::keccak256(buf.data(), len);
            for (std::size_t N = 0; N <= len; N += KeccakParams::HASH_DATA_AREA) {   // every block-aligned midstate split
                std::array<std::uint64_t, 25> st{};
                keccak_step(buf.data(), static_cast<int>(N), st);
                keccak_finish(buf.data() + N, static_cast<int>(len - N), st);
                ::xmr::coin::Hash256 got; std::memcpy(got.data(), st.data(), HASH_SIZE);
                if (!(got == want)) all = false; else ++n_fast;
            }
        }
        C(all, "K0 keccak_step/keccak_finish raw-state midstate == cn_fast_hash for every (len, split), " + std::to_string(n_fast) + " cases");
        std::uint64_t hi = 0;
        const std::uint64_t lo = umul128(0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull, &hi);
        C(lo == 1 && hi == 0xFFFFFFFFFFFFFFFEull, "K0 umul128(2^64-1, 2^64-1)");
        std::uint64_t rem = 0;
        const std::uint64_t q = udiv128(0x0000000000000001ull, 0x0000000000000005ull, 7, &rem);   // (2^64+5)/7
        C(q == 2635249153387078803ull && rem == 0, "K0 udiv128((2^64+5), 7)");
        C(xmr_base_reward(0) == 35184372088831ull, "K0 base reward at agc=0 == 2^45-1 pn (regtest first blocks)");
        C(xmr_base_reward(~0ull) == BASE_BLOCK_REWARD, "K0 base reward floor == 0.6 XMR tail");
        C(seconds_since_epoch() > 1600000000ull, "K0 seconds_since_epoch");
    }

    // ---- K1: regtest-like: empty mempool, nothing owed -> sink-only coinbase --
    {
        AssemblyInputs a; a.miner = miner(1, 300000, 0); a.settle = lane_ctx();
        std::string why;
        auto t = XmrBlockAssembler::build(a, &why);
        if (C(t != nullptr, "K1 build (sink-only) " + why)) {
            C(t->passes() == 1, "K1 converged in 1 pass");
            C(t->reward() == 35184372088831ull, "K1 reward == monerod expected_reward at agc=0 (" + std::to_string(t->reward()) + ")");
            C(t->outputs().size() == 1 && t->outputs()[0].role == CoinbaseOutput::Role::Sink, "K1 single sink output");
            C(t->n_tx() == 0, "K1 n_tx == 0");
            for (std::uint32_t en : {0u, 1u, 0xFFFFFFFFu}) check_template(C, *t, en, "K1");
            // per-extra-nonce distinctness: distinct coinbase => distinct tree root
            BlockBytes b0, b1; std::string w;
            C(t->materialize(0, b0, &w) && t->materialize(1, b1, &w) && !(b0.tree_root == b1.tree_root) && b0.full_blob.size() == b1.full_blob.size(),
              "K1 extra_nonce 0 vs 1 => different tree root, same blob size");
            // get_hashing_blobs (parallel_run) matches get_hashing_blob
            std::vector<std::uint8_t> blobs; std::uint64_t h; difficulty_type dt; hash sh; std::size_t no; std::uint32_t tid;
            const std::uint32_t bs = t->tpl().get_hashing_blobs(5, 4, blobs, h, dt, sh, no, tid);
            bool same = bs >= HASHING_BLOB_MIN_SIZE && blobs.size() == static_cast<std::size_t>(bs) * 4;
            for (std::uint32_t i = 0; same && i < 4; ++i) {
                const std::vector<std::uint8_t> one = t->hashing_blob(5 + i);
                same = one.size() == bs && std::memcmp(one.data(), blobs.data() + static_cast<std::size_t>(i) * bs, bs) == 0;
            }
            C(same, "K1 get_hashing_blobs(5,4) via parallel_run == 4x get_hashing_blob");
        }
    }

    // ---- K2: 6 owed + 1 fixed + sink, 5 txs below median (fast midstate path) --
    {
        AssemblyInputs a; a.miner = miner(3000000, 300000, 18000000000000000000ull); a.settle = lane_ctx();
        a.mempool = txs(5, 2000, 30000000);
        for (unsigned char i = 0; i < 6; ++i) {
            ::v37::xmr::settle::OwedEntry e; e.pay = std_ref(); e.owed = 1000000000ull * (i + 1); e.first_eligible = 100 + (5 - i); e.identity = id_of(static_cast<unsigned char>(0x40 + i));
            a.settle.owed.push_back(e);
        }
        ::v37::xmr::settle::FixedOutput f; f.pay = std_ref(); f.amount = 5000000ull; f.identity = id_of(0x77); a.settle.fixed.push_back(f);
        std::string why;
        auto t = XmrBlockAssembler::build(a, &why);
        if (C(t != nullptr, "K2 build (6 owed + fixed + sink, 5 txs) " + why)) {
            C(t->passes() == 1, "K2 converged in 1 pass (below median: final == sizing reward)");
            C(t->reward() == xmr_base_reward(a.miner.already_generated_coins) + 5 * 30000000ull, "K2 reward == subsidy + all fees");
            C(t->outputs().size() == 8, "K2 8 outputs (6 owed + fixed + sink), extra-nonce offset past one Keccak block => midstate fast path");
            C(t->n_tx() == 5, "K2 n_tx == 5");
            // K_fair order: oldest first_eligible first => identity 0x45 (fe=100) ... 0x40 (fe=105)
            C(t->outputs()[0].identity == id_of(0x45) && t->outputs()[5].identity == id_of(0x40), "K2 K_fair oldest-owed-first order preserved through the template");
            for (std::uint32_t en : {0u, 1u, 0xFFFFFFFFu}) check_template(C, *t, en, "K2");
        }
    }

    // ---- K3: penalty zone, payee set CHANGES with the final reward -> fixpoint --
    {
        // median 2000, 10 txs of 500 B / 1e9 fee: the greedy keeps 3 (penalty-free),
        // sizing reward = subsidy + 10e9, final = subsidy + 3e9.
        AssemblyInputs a; a.miner = miner(3000000, 2000, 18000000000000000000ull); a.settle = lane_ctx();
        a.mempool = txs(10, 500, 1000000000ull);
        const std::uint64_t subsidy = xmr_base_reward(a.miner.already_generated_coins);
        ::v37::xmr::settle::OwedEntry A; A.pay = std_ref(); A.owed = subsidy + 5000000000ull; A.first_eligible = 1; A.identity = id_of(0x41);
        ::v37::xmr::settle::OwedEntry B; B.pay = std_ref(); B.owed = 100000000000ull;         B.first_eligible = 2; B.identity = id_of(0x42);
        a.settle.owed = {A, B};
        std::string why;
        auto t = XmrBlockAssembler::build(a, &why);
        if (C(t != nullptr, "K3 build (penalty zone, set changes) " + why)) {
            C(t->passes() == 2, "K3 converged in 2 passes (rebuilt at the wanted reward), passes=" + std::to_string(t->passes()));
            C(t->reward() == subsidy + 3000000000ull, "K3 final reward == subsidy + 3 fees (" + std::to_string(t->reward()) + ")");
            C(t->outputs().size() == 1 && t->outputs()[0].identity == id_of(0x41) && t->outputs()[0].amount == t->reward(),
              "K3 coinbase pays only A (B and the sink vanished at the final reward)");
            C(t->n_tx() == 3, "K3 3 txs selected");
            for (std::uint32_t en : {0u, 7u}) check_template(C, *t, en, "K3");
        }
    }

    // ---- K4: penalty zone, SAME set at the final reward -> adopted in pass 1 --
    {
        AssemblyInputs a; a.miner = miner(3000000, 2000, 18000000000000000000ull); a.settle = lane_ctx();
        a.mempool = txs(10, 500, 1000000000ull);
        const std::uint64_t subsidy = xmr_base_reward(a.miner.already_generated_coins);
        ::v37::xmr::settle::OwedEntry A; A.pay = std_ref(); A.owed = 1000000000ull; A.first_eligible = 1; A.identity = id_of(0x41);
        a.settle.owed = {A};
        std::string why;
        auto t = XmrBlockAssembler::build(a, &why);
        if (C(t != nullptr, "K4 build (penalty zone, same set) " + why)) {
            C(t->passes() == 1, "K4 adopted the final reward in pass 1 (same payee set)");
            C(t->reward() == subsidy + 3000000000ull && t->reward() < subsidy + 10000000000ull, "K4 final reward below the sizing reward");
            C(t->outputs().size() == 2 && t->outputs()[1].role == CoinbaseOutput::Role::Sink &&
              t->outputs()[0].amount + t->outputs()[1].amount == t->reward(), "K4 owed + sink, exact-sum at the ADOPTED reward");
            for (std::uint32_t en : {0u, 0xFFFFFFFFu}) check_template(C, *t, en, "K4");
        }
    }

    // ---- K5/K6: fail-closed ---------------------------------------------------
    {
        AssemblyInputs a; a.miner = miner(1, 300000, 0, 17); a.settle = lane_ctx();
        std::string why;
        C(XmrBlockAssembler::build(a, &why) == nullptr && why.find("CARROT") != std::string::npos, "K5 major_version 17 refused (CARROT fence): " + why);
        AssemblyInputs b; b.miner = miner(1, 300000, 0); b.settle = lane_ctx(); b.settle.residual_sink = ::v37::ScriptRef{};
        C(XmrBlockAssembler::build(b, &why) == nullptr && why.find("residual_sink") != std::string::npos, "K6 missing residual sink refused: " + why);
        AssemblyInputs c; c.miner = miner(1, 300000, 0); c.settle = lane_ctx(); c.settle.output_cap = 1;
        ::v37::xmr::settle::FixedOutput f; f.pay = std_ref(); f.amount = 1; f.identity = id_of(0x77); c.settle.fixed.push_back(f);
        C(XmrBlockAssembler::build(c, &why) == nullptr, "K6' output_cap too small for fixed + sink refused: " + why);
    }

    log += "summary: " + std::to_string(C.pass) + " passed, " + std::to_string(C.fail) + " failed\n";
    return C.fail == 0;
}

} // namespace kat
} // namespace c2pool::xmr::assembly

// ===========================================================================
// PRIMITIVE BODIES for xmr_coin_primitives.hpp  --  compile in EXACTLY ONE TU:
//
//     #define XMR_BLOCK_ASSEMBLY_IMPLEMENT_PRIMITIVES
//     #include "impl/xmr/template/xmr_block_assembly.hpp"
//
// Byte-identity with monero-project keccak.c (vendored, BSD-3): the one-shot
// keccak() IS the vendored function; keccak_step/keccak_finish are the raw
// 25-lane state form of keccak_update/keccak_finish (same 136-B rate, same
// 0x01 ... 0x80 Keccak padding -- NOT SHA3's 0x06 -- same keccakf(24)), which
// the ported template needs because it caches std::array<uint64_t,25> and
// patches the tail in place. The self-check (K0) pins them against
// cn_fast_hash for every (length, split) pair. The digest is the first 4 lanes
// in host order; the template memcpy's them, as p2pool does (LE hosts).
// ===========================================================================
#ifdef XMR_BLOCK_ASSEMBLY_IMPLEMENT_PRIMITIVES
namespace c2pool::xmr {

void writeVarint(std::uint64_t value, std::vector<std::uint8_t>& out) {
    ::xmr::coin::BlobWriter w;                       // tools::write_varint (vendored varint.h)
    w.put_varint(value);
    out.insert(out.end(), w.bytes().begin(), w.bytes().end());
}

void keccak(const std::uint8_t* in, std::size_t inlen, std::uint8_t* md, int mdlen) {
    ::keccak(in, inlen, md, mdlen);                  // vendor/keccak.c (extern "C")
}

namespace {
inline std::uint64_t load_le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    return v;
}
inline void absorb_block(const std::uint8_t* block, std::array<std::uint64_t, 25>& st) {
    for (int i = 0; i < KeccakParams::HASH_DATA_AREA / 8; ++i) st[static_cast<std::size_t>(i)] ^= load_le64(block + 8 * i);
    ::keccakf(st.data(), KECCAK_ROUNDS);
}
} // namespace

void keccak_step(const std::uint8_t* in, int inlen, std::array<std::uint64_t, 25>& state) {
    for (; inlen >= KeccakParams::HASH_DATA_AREA; inlen -= KeccakParams::HASH_DATA_AREA, in += KeccakParams::HASH_DATA_AREA)
        absorb_block(in, state);
    // a non-multiple is a caller error (the template always steps whole blocks)
}

void keccak_finish(const std::uint8_t* in, int inlen, std::array<std::uint64_t, 25>& state) {
    for (; inlen >= KeccakParams::HASH_DATA_AREA; inlen -= KeccakParams::HASH_DATA_AREA, in += KeccakParams::HASH_DATA_AREA)
        absorb_block(in, state);
    std::uint8_t temp[KeccakParams::HASH_DATA_AREA];
    std::memset(temp, 0, sizeof(temp));
    if (inlen > 0) std::memcpy(temp, in, static_cast<std::size_t>(inlen));
    temp[inlen] = 1;                                  // Keccak (pre-SHA3) padding start
    temp[KeccakParams::HASH_DATA_AREA - 1] |= 0x80;   // final bit
    absorb_block(temp, state);
    // digest = state[0..3] (little-endian lanes); the caller memcpy's 32 bytes
}

std::uint64_t umul128(std::uint64_t a, std::uint64_t b, std::uint64_t* hi) {
    const unsigned __int128 p = static_cast<unsigned __int128>(a) * b;
    *hi = static_cast<std::uint64_t>(p >> 64);
    return static_cast<std::uint64_t>(p);
}

std::uint64_t udiv128(std::uint64_t numhi, std::uint64_t numlo, std::uint64_t den, std::uint64_t* rem) {
    const unsigned __int128 n = (static_cast<unsigned __int128>(numhi) << 64) | numlo;
    const unsigned __int128 q = n / den;                 // caller guarantees numhi < den (quotient fits)
    *rem = static_cast<std::uint64_t>(n % den);
    return static_cast<std::uint64_t>(q);
}

// Serial fan-out: the template's only user (get_hashing_blobs) shares an atomic
// counter and loops until it is exhausted, so one synchronous call covers every
// blob. A thread-pool variant can replace this body without touching callers.
void parallel_run(const std::function<void()>& f, bool /*wait*/) { f(); }

std::uint64_t seconds_since_epoch() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace c2pool::xmr
#endif // XMR_BLOCK_ASSEMBLY_IMPLEMENT_PRIMITIVES

// ===========================================================================
// KAT driver: define XMR_BLOCK_ASSEMBLY_SELFCHECK_MAIN in a TU that also
// compiles xmr_block_template.cpp, settle/xmr_coinbase.cpp, the primitives TU
// and links xmr_coin. Nonzero exit on any failure (build.yml test lane shape).
// ===========================================================================
#ifdef XMR_BLOCK_ASSEMBLY_SELFCHECK_MAIN
#include <cstdio>
int main() {
    std::string log;
    const bool ok = c2pool::xmr::assembly::kat::selfcheck(log);
    std::fputs("xmr_block_assembly_kat (X9 option B: whole-block assembly over X6)\n", stdout);
    std::fputs(log.c_str(), stdout);
    std::fputs(ok ? "RESULT: GREEN\n" : "RESULT: RED\n", stdout);
    return ok ? 0 : 1;
}
#endif
