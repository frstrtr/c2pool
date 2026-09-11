// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp   (M2)
//
// THE SHAPE GATE. One function that reads an assembled option-B template's
// BLOCK BYTES back and says whether what they actually pay is still the K_fair
// settlement coinbase.
//
// Why it reads BYTES and not the builder's bookkeeping. M2 rebinds the miner
// data the assembler is fed -- from monerod's get_miner_data to the native
// chain index. Nothing below the seam moved, and the C4 KATs pin that. But the
// claim a rebind has to survive is not "the assembler file is unchanged"; it is
// "the block a miner is handed still pays the owed ledger". A check that asks
// the seam what it meant to pay cannot fail when the seam is the thing that is
// wrong. So every number below is re-read from `full_blob` through
// parse_coinbase_prefix() -- the same parser a PEER uses on a block it did not
// build -- and then judged against the canonical rebuild.
//
// The five properties, in the order they are judged:
//
//   1. PARSES.       The miner_tx prefix inside full_blob is a well-formed
//                    v2 coinbase for this height (unlock == height + 60).
//   2. CANONICAL.    canonical_coinbase_matches(final inputs, parsed) -- the
//                    W3 every-node ACCEPT check. This is the strongest single
//                    statement available: it rebuilds the whole coinbase from
//                    the CoinbaseInputs and byte-compares R, every amount,
//                    every one-time key, every view tag and the tx_extra.
//   3. EXACT SUM.    Sum of the amounts AS PARSED == base_reward + fees ==
//                    the template's reward. Post-HF13 a Monero coinbase that
//                    pays anything else is a consensus failure; there is no
//                    burn-the-remainder escape hatch.
//   4. K_FAIR ORDER. The owed outputs appear oldest-owed-first (first_eligible
//                    ascending, identity as the tiebreak) and the mandated
//                    residual sink is the LAST output.
//   5. OWED DIGEST.  The 0x03 merge-mining tag carries
//                    mm_commitment_root(chain_id, owed_digest) for the digest
//                    of the ledger this template claims to settle -- checked
//                    against the tag's own bytes at the tail of tx_extra, not
//                    against BlockBytes::merkle_root, which is a value the
//                    builder handed us.
//
// A failure is never a warning: the caller refuses to serve. That is the whole
// point of putting it on the M2 path rather than only in a KAT.
//
// Header-only, consumer tree, no consensus digest, no src/sharechain/v37 touch.
// ===========================================================================
#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "impl/xmr/settle/xmr_coinbase.hpp"          // CoinbaseInputs / canonical_coinbase_matches / mm_commitment_root
#include "impl/xmr/template/xmr_block_assembly.hpp"  // AssembledTemplate / BlockBytes / parse_coinbase_prefix

namespace c2pool::v37n::xmr::o2 {

namespace asm_  = ::c2pool::xmr::assembly;
namespace set_  = ::v37::xmr::settle;

// The tail of an X6 tx_extra: 03 | 0x21 | 0x00 | root[32].
// (tag, length = depth-varint + 32, depth 0 for a single-leaf tree, the root.)
inline constexpr std::size_t MM_TAG_BYTES   = 35;
inline constexpr std::uint8_t MM_TAG        = 0x03;
inline constexpr std::uint8_t MM_TAG_LENGTH = 0x21;   // 1 + 32
inline constexpr std::uint8_t MM_TAG_DEPTH  = 0x00;

struct KFairCoinbaseShape {
    bool        ok = false;
    std::string why;                  // first failing property, human readable

    // --- what the bytes say -------------------------------------------------
    std::uint64_t height        = 0;
    std::uint64_t sum_outputs   = 0;  // summed from the PARSED amounts
    std::size_t   n_outputs     = 0;  // parsed vout count
    std::size_t   n_owed        = 0;  // outputs whose role is Owed
    std::size_t   n_fixed       = 0;
    std::size_t   n_sink        = 0;

    // --- what it was supposed to be -----------------------------------------
    std::uint64_t base_reward   = 0;
    std::uint64_t fees          = 0;
    std::uint64_t budget        = 0;  // base_reward + fees
    std::uint32_t chain_id      = 0;
    ::v37::bytes32 owed_digest{};     // the digest the caller says it settles
    ::xmr::coin::Hash256 mm_root{};   // the root the tx_extra actually carries

    // --- the five properties -------------------------------------------------
    bool parses          = false;
    bool canonical       = false;
    bool exact_sum       = false;
    bool kfair_order     = false;
    bool sink_last       = false;
    bool owed_digest_bound = false;

    std::string describe() const {
        std::string s = "outputs=" + std::to_string(n_outputs)
                      + " (owed=" + std::to_string(n_owed)
                      + " fixed=" + std::to_string(n_fixed)
                      + " sink=" + std::to_string(n_sink) + ")"
                      + " sum=" + std::to_string(sum_outputs)
                      + " budget=" + std::to_string(budget)
                      + " (base=" + std::to_string(base_reward)
                      + "+fees=" + std::to_string(fees) + ")";
        s += ok ? " K_FAIR-SHAPE=OK" : (" K_FAIR-SHAPE=REFUSED: " + why);
        return s;
    }
};

// ---------------------------------------------------------------------------
// inspect_kfair_coinbase -- read the assembled block's coinbase back and judge.
//
// `expect_owed_digest` is the digest of the ledger the CALLER believes it is
// settling (OwedLedger::owed_digest()). Passing the value the template itself
// carries would make property 5 vacuous, so the caller must supply it from the
// ledger side of the seam.
// ---------------------------------------------------------------------------
inline KFairCoinbaseShape inspect_kfair_coinbase(const asm_::AssembledTemplate& tpl,
                                                 const ::v37::bytes32& expect_owed_digest,
                                                 std::uint32_t extra_nonce = 0) {
    KFairCoinbaseShape s;

    asm_::BlockBytes b;
    std::string mwhy;
    if (!tpl.materialize(extra_nonce, b, &mwhy)) { s.why = "materialize: " + mwhy; return s; }

    // The FINAL inputs: budget adopted, amounts adopted. This is exactly what a
    // peer is fed for the ACCEPT check, with the padded nonce for this job.
    set_::CoinbaseInputs ref = tpl.coinbase_inputs();
    ref.extra_nonce = asm_::extra_nonce_bytes(extra_nonce, b.extra_nonce_size);

    s.height      = tpl.height();
    s.base_reward = ref.base_reward;
    s.fees        = ref.fees;
    s.budget      = ref.budget();
    s.chain_id    = ref.chain_id;
    s.owed_digest = expect_owed_digest;

    // --- 1. PARSES ----------------------------------------------------------
    set_::ReceivedCoinbase got;
    std::uint64_t parsed_height = 0;
    std::size_t   used = 0;
    if (!asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size,
                                     got, &parsed_height, &used)) {
        s.why = "miner_tx prefix does not parse";
        return s;
    }
    if (parsed_height != tpl.height()) {
        s.why = "miner_tx txin_gen height " + std::to_string(parsed_height)
              + " != template height " + std::to_string(tpl.height());
        return s;
    }
    if (used != b.miner_tx_size - 1) {   // the trailing rct_type byte is not prefix
        s.why = "miner_tx prefix length " + std::to_string(used)
              + " != miner_tx size - 1 (" + std::to_string(b.miner_tx_size - 1) + ")";
        return s;
    }
    s.parses    = true;
    s.n_outputs = got.amounts.size();

    // --- 2. CANONICAL -------------------------------------------------------
    const set_::MatchResult m = set_::canonical_coinbase_matches(ref, got);
    if (!m.matches) {
        s.why = "canonical_coinbase_matches: " + m.reason
              + " (index " + std::to_string(m.first_bad_index) + ")";
        return s;
    }
    s.canonical = true;

    // --- 3. EXACT SUM (summed from the PARSED amounts) ----------------------
    for (std::uint64_t a : got.amounts) s.sum_outputs += a;
    if (s.sum_outputs != s.budget || s.sum_outputs != tpl.reward()) {
        s.why = "exact-sum: parsed " + std::to_string(s.sum_outputs)
              + " != budget " + std::to_string(s.budget)
              + " / template reward " + std::to_string(tpl.reward());
        return s;
    }
    s.exact_sum = true;

    // --- 4. K_FAIR ORDER + the sink last ------------------------------------
    const std::vector<set_::CoinbaseOutput>& outs = tpl.outputs();
    if (outs.size() != got.amounts.size()) {
        s.why = "output count: seam " + std::to_string(outs.size())
              + " != parsed " + std::to_string(got.amounts.size());
        return s;
    }
    std::map<::v37::bytes32, std::uint64_t> age_of;
    for (const set_::OwedEntry& e : ref.owed) age_of[e.identity] = e.first_eligible;

    bool          have_prev = false;
    std::uint64_t prev_age  = 0;
    ::v37::bytes32 prev_identity{};
    for (std::size_t i = 0; i < outs.size(); ++i) {
        switch (outs[i].role) {
            case set_::CoinbaseOutput::Role::Owed: {
                ++s.n_owed;
                auto it = age_of.find(outs[i].identity);
                if (it == age_of.end()) {
                    s.why = "owed output " + std::to_string(i) + " is not in the eligible owed set";
                    return s;
                }
                const std::uint64_t age = it->second;
                if (have_prev) {
                    const bool ordered = (age > prev_age)
                                      || (age == prev_age && !(outs[i].identity < prev_identity));
                    if (!ordered) {
                        s.why = "K_fair order broken at output " + std::to_string(i)
                              + " (first_eligible " + std::to_string(age)
                              + " after " + std::to_string(prev_age) + ")";
                        return s;
                    }
                }
                have_prev     = true;
                prev_age      = age;
                prev_identity = outs[i].identity;
                break;
            }
            case set_::CoinbaseOutput::Role::Fixed: ++s.n_fixed; break;
            case set_::CoinbaseOutput::Role::Sink:  ++s.n_sink;  break;
        }
    }
    if (s.n_sink != 1) {
        s.why = "residual sink outputs = " + std::to_string(s.n_sink) + " (exactly one is mandated)";
        return s;
    }
    if (outs.back().role != set_::CoinbaseOutput::Role::Sink) {
        s.why = "the residual sink is not the last output";
        return s;
    }
    if (!(outs.back().identity == ref.residual_sink_identity)) {
        s.why = "the last output is not the configured residual sink identity";
        return s;
    }
    s.kfair_order = true;
    s.sink_last   = true;

    // --- 5. OWED DIGEST under the 0x03 tag ----------------------------------
    // Read the tag out of the tx_extra AS PARSED. BlockBytes::merkle_root is
    // the builder's own answer and is deliberately not what is compared.
    if (got.tx_extra.size() < MM_TAG_BYTES) { s.why = "tx_extra too short for the 0x03 tag"; return s; }
    const unsigned char* tag = got.tx_extra.data() + got.tx_extra.size() - MM_TAG_BYTES;
    if (tag[0] != MM_TAG || tag[1] != MM_TAG_LENGTH || tag[2] != MM_TAG_DEPTH) {
        s.why = "tx_extra tail is not the single-leaf merge-mining tag 03 21 00";
        return s;
    }
    std::memcpy(s.mm_root.data(), tag + 3, 32);

    if (!(ref.lane_commitment == expect_owed_digest)) {
        s.why = "lane_commitment in the template != the ledger's owed_digest";
        return s;
    }
    const ::xmr::coin::Hash256 want = set_::mm_commitment_root(ref.chain_id, expect_owed_digest);
    if (!(s.mm_root == want)) {
        s.why = "tx_extra 0x03 root != mm_commitment_root(chain_id, owed_digest)";
        return s;
    }
    s.owed_digest_bound = true;

    s.ok = true;
    return s;
}

} // namespace c2pool::v37n::xmr::o2
