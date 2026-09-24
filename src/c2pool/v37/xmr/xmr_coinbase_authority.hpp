// SPDX-License-Identifier: AGPL-3.0-or-later
//
// COINBASE-AUTHORITY BOOKING (RECON, operator ruling 'read from block').
// The winner's ON-CHAIN coinbase is the settlement authority: map every output
// back to the owed-key it pays via deterministic r (docs/xmr-lane/w5-xmr-coinbase-rule.md
// s1/s3). No wire bytes -- the block is on the Monero chain both nodes follow.
// The K_fair recompute is a cross-check only (see xmr_recon_verify).
//
//   1. parse the block blob (native consensus parser) -> prev_id, major, miner_tx span
//   2. parse the coinbase prefix -> R, amounts[], keys[], view_tags[], tx_extra
//   3. tx_extra tail 03 21 00 root[32]: match against candidate lane_commitments
//      (this node's owed_digest history ring) -> lane_commitment
//   4. r = derive_tx_secret_key(major, height, prev_id, chain_id, lane_commitment); r*G == R
//   5. every vout i: find the payee ref whose derive_output(r, ref, i) == keys[i]
//      -> identity; fail-closed if any output is unmapped
//   6. payout[identity] += amount   (the residual sink is coverage-only, NOT a ledger
//      deduction -- D1: excluded from payout, tallied in sink_total)

#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_descriptor_xmr.hpp>
#include <sharechain/v37/v37_hash.hpp>
#include "impl/xmr/coin/xmr_derivation.hpp"                 // xmr::coin::secret_key_to_public_key
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"    // parse_block
#include "impl/xmr/settle/xmr_coinbase.hpp"                 // derive_tx_secret_key / derive_output / mm_commitment_root
#include "impl/xmr/template/xmr_block_assembly.hpp"         // parse_coinbase_prefix
#include "xmr_credit_cut.hpp"                               // recon(A+B credit): the on-chain credit cut
#include "xmr_fee_model.hpp"                                // fee model: donation marker rule (REFUSE-IF-ABSENT)

namespace c2pool::v37n::xmr::authority {

struct CoinbaseBooking {
    bool          ok = false;
    bool          is_lane = false;      // carries a 03-21-00 tag whose root matched a candidate digest
    std::string   why;
    std::uint64_t height = 0;
    std::uint8_t  major = 0;
    std::uint64_t total = 0;            // Σ vout amounts (== base_reward + fees, exact-sum)
    std::size_t   n_outputs = 0;
    long long     sink_total = 0;       // D1: sink amount is NOT a ledger deduction
    std::size_t   digest_index = 0;     // which candidate matched (0 = newest)
    ::v37::bytes32 lane_commitment{};
    // R-C majority-shaped halt: the raw on-chain 0x03 root, set as soon as the
    // 03-21-00 tail is read -- BEFORE the candidate match. On a lane-root-unknown
    // block (no candidate matched, so lane_commitment is empty) this is the only
    // stable builder/ledger-state fingerprint available (the payout identities are
    // undecodable without the matched lane_commitment). The receiver uses distinct
    // on-chain roots across a consecutive-unmatched run as the "distinct payees"
    // proxy so a single stuck/forked builder cannot halt the honest majority.
    ::xmr::coin::Hash256 onchain_root{};
    bool           has_onchain_root = false;
    // D2 (minority converges to majority): the first 4 bytes (LE) of the 0x02
    // extra-nonce payload -- the stratum extra_nonce the block was mined under
    // (builder_key = >> 20 under GAP-2). Read with the root, before the match.
    bool           has_extra_nonce = false;
    std::uint32_t  extra_nonce = 0;
    std::map<::v37::bytes32, long long> payout;   // identity -> piconero, the on-chain truth
    // fee model: the per-vout identity + amount (canonical order), so the
    // donation-marker rule (xmr_fee_model.hpp apply_donation_rule) can locate
    // the marker / sink tail and re-book the donation's owed outputs.
    std::vector<::v37::bytes32> out_identity;
    std::vector<std::uint64_t>  out_amount;
    // R-C rework-2 (F-MONEY, M2): when an output maps to NO known payee the block
    // stays fail-closed for booking (ok == false, unchanged), but the MAPPED
    // outputs are kept in `payout` (flag payout_partial) and the unmapped sum is
    // reported, so a refusing node can still debit what it CAN attribute and
    // put the rest in node-local suspense. Before, payout was cleared.
    bool           payout_partial = false;
    std::uint64_t  unmapped_total = 0;
    std::size_t    unmapped_outputs = 0;
    // recon(A+B credit): the ON-CHAIN CREDIT CUT (0x02 tail), if the coinbase carries one.
    bool           has_credit_cut = false;
    credit::CreditCut credit_cut;
    // fee model: the donation owed_in commitment (0x02 tail "V37D"), if any.
    // Read by decode_lane_coinbase_fee only; gate OFF coinbases carry none.
    std::optional<std::uint64_t> donation_owed_in;
};

// candidates: newest first. keys: every identity this node can resolve via pay_of.
template <class PayOf>
inline CoinbaseBooking decode_lane_coinbase(const std::vector<std::uint8_t>& blob,
                                                std::uint32_t chain_id,
                                                const std::vector<::v37::bytes32>& candidates,
                                                const std::vector<::v37::bytes32>& keys,
                                                const ::v37::ScriptRef& sink_ref,
                                                const ::v37::bytes32& sink_identity,
                                                PayOf&& pay_of) {
    namespace cons = ::c2pool::xmr::native;
    namespace set_ = ::v37::xmr::settle;
    CoinbaseBooking b;

    cons::ParsedBlock pb;
    const cons::BlockParseStatus st = cons::parse_block(blob.data(), blob.size(), pb);
    if (st != cons::BlockParseStatus::Ok && st != cons::BlockParseStatus::TxCountMismatch) {
        b.why = std::string("block does not parse: ") + cons::to_string(st); return b;
    }
    set_::ReceivedCoinbase got;
    std::uint64_t height = 0; std::size_t used = 0;
    if (!::c2pool::xmr::assembly::parse_coinbase_prefix(blob.data() + pb.miner_tx_offset,
                                                         pb.miner_tx_size, got, &height, &used)) {
        b.why = "miner_tx prefix does not parse"; return b;
    }
    b.height = height;
    b.major  = static_cast<std::uint8_t>(pb.header.major_version);
    b.n_outputs = got.amounts.size();
    for (std::uint64_t a : got.amounts) b.total += a;

    // --- the 0x03 tag -> lane_commitment (from this node's own digest history) ---
    if (got.tx_extra.size() < 35) { b.why = "not-lane: tx_extra too short for 03 tag"; return b; }
    const unsigned char* tag = got.tx_extra.data() + got.tx_extra.size() - 35;
    if (tag[0] != 0x03 || tag[1] != 0x21 || tag[2] != 0x00) { b.why = "not-lane: no 03 21 00 tail"; return b; }
    ::xmr::coin::Hash256 root; std::memcpy(root.data(), tag + 3, 32);
    b.onchain_root = root; b.has_onchain_root = true;   // R-C: fingerprint available even when no candidate matches
    if (const auto en = credit::extra_nonce_field(got.tx_extra); en && en->size() >= 4) {   // D2: the builder datum
        b.has_extra_nonce = true;
        b.extra_nonce = static_cast<std::uint32_t>((*en)[0]) | (static_cast<std::uint32_t>((*en)[1]) << 8) |
                        (static_cast<std::uint32_t>((*en)[2]) << 16) | (static_cast<std::uint32_t>((*en)[3]) << 24);
    }
    bool matched = false;
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        if (set_::mm_commitment_root(chain_id, candidates[i]) == root) {
            b.lane_commitment = candidates[i]; b.digest_index = i; matched = true; break;
        }
    }
    // R5: a 03-21-00 tail whose root matches NO candidate is NOT "not-lane" (a
    // stranger's block, memoized and never re-attempted). It is "lane-root-unknown":
    // another lane, or OUR ring does not (yet) hold the ledger state the winner built
    // on -- a receiver one ledger event behind the winner sees exactly this and must
    // RETRY as its ring advances (FinalizeConnect keeps it in the bounded retry set,
    // which also holds the R4 finalize gate); it must never be memoize-dropped.
    if (!matched) { b.why = "lane-root-unknown: 03 root matches none of " + std::to_string(candidates.size()) + " candidate digests (other lane, or this node's ledger history does not (yet) contain the winner's build digest -- retried as the ring advances)"; return b; }
    b.is_lane = true;
    if (const auto cc = credit::parse_from_tx_extra(got.tx_extra)) { b.has_credit_cut = true; b.credit_cut = *cc; }   // recon(A+B credit)
    b.donation_owed_in = fee::parse_donation_owed(got.tx_extra);   // fee model (used by the gate-ON booking only)

    // --- r and R ---
    set_::CoinbaseInputs in;
    in.monero_major_version = b.major;
    in.height   = height;
    std::memcpy(in.prev_id.data(), pb.header.prev_id.data(), 32);
    in.chain_id = chain_id;
    in.lane_commitment = b.lane_commitment;
    ::xmr::coin::SecretKey r;
    if (!set_::derive_tx_secret_key(in, r)) { b.why = "derive_tx_secret_key refused (CARROT fence?)"; return b; }
    ::xmr::coin::PublicKey R;
    if (!::xmr::coin::secret_key_to_public_key(r, R)) { b.why = "r*G failed"; return b; }
    if (!(R == got.R)) { b.why = "r*G != tx_extra R: lane_commitment/prev_id/height mismatch"; return b; }

    // --- map every output to a payee identity (fail-closed) ---
    std::vector<std::pair<::v37::bytes32, ::v37::ScriptRef>> refs;
    refs.emplace_back(sink_identity, sink_ref);
    for (const auto& k : keys) {
        ::v37::ScriptRef ref = pay_of(k);
        if (::v37::xmr::is_xmr_kind(ref.kind)) refs.emplace_back(k, ref);
    }
    for (std::size_t i = 0; i < got.keys.size(); ++i) {
        bool found = false;
        for (const auto& [id, ref] : refs) {
            ::xmr::coin::PublicKey P; ::xmr::coin::ViewTag vt;
            if (!set_::derive_output(r, ref, i, P, vt)) continue;
            if (P == got.keys[i] && vt.tag == got.view_tags[i].tag) {
                b.out_identity.push_back(id); b.out_amount.push_back(got.amounts[i]);
                if (id == sink_identity) b.sink_total += static_cast<long long>(got.amounts[i]); // D1: never deduct the sink from a ledger key
                else b.payout[id] += static_cast<long long>(got.amounts[i]);
                found = true; break;
            }
        }
        if (!found) {
            ++b.unmapped_outputs; b.unmapped_total += got.amounts[i];
            if (b.why.empty()) b.why = "output " + std::to_string(i) + " maps to no known payee (fail-closed)";
        }
    }
    if (b.unmapped_outputs) { b.payout_partial = true; return b; }   // fail-closed for booking; mapped part kept for the debit
    b.ok = true;
    return b;
}

// ---------------------------------------------------------------------------
// fee model (xmr_fee_model.hpp): the every-node REFUSE-IF-ABSENT booking rule.
// The residual sink IS the donation address, so every vout to it was tallied
// as coverage above; this locates the ONE mandatory donation output (last,
// >= 1 piconero; the donation's K_fair payout + the V36 marker + the folded
// residual, rulings S1 + 09-23), refusing the coinbase when it is absent,
// when an earlier output also pays the donation, or when the owed_in tail is
// missing, and books min(owed_in, amount - 1) of it as the donation's payout
// (give-author credit settled, an owed deduction); the rest stays coverage.
// Only a FeeModelGate-ON node calls this; gate OFF books with
// decode_lane_coinbase() against its configured sink, exactly as master.
// ---------------------------------------------------------------------------
template <class PayOf>
inline CoinbaseBooking decode_lane_coinbase_fee(const std::vector<std::uint8_t>& blob,
                                                std::uint32_t chain_id,
                                                const std::vector<::v37::bytes32>& candidates,
                                                const std::vector<::v37::bytes32>& keys,
                                                PayOf&& pay_of) {
    namespace fee = ::c2pool::v37n::xmr::fee;
    CoinbaseBooking b = decode_lane_coinbase(blob, chain_id, candidates, keys, fee::donation_ref(),
                                             fee::donation_identity(), std::forward<PayOf>(pay_of));
    if (!b.ok) return b;
    std::string w;
    if (!fee::apply_donation_rule(b.out_identity, b.out_amount, fee::donation_identity(), b.donation_owed_in,
                                  b.payout, b.sink_total, &w)) {
        b.ok = false;
        b.why = "donation-refused: " + w + " (the lane coinbase must carry the mandatory donation output)";
        b.payout.clear();
    }
    return b;
}

} // namespace c2pool::v37n::xmr::authority
