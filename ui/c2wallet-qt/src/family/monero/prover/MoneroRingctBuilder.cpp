// Copyright (c) 2014-2026, The Monero Project  (BSD-3-Clause)
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. Full BSD-3 text: xmr_derivation.cpp.
//
// Port of monero-project/monero RingCT assembly (rctSigs.cpp genRctSimple),
// output-key/tx_extra/ecdh construction (cryptonote_tx_utils.cpp) and the
// pre-MLSAG / prefix / tx hashing (cryptonote_format_utils.cpp), re-expressed
// over Bytes32 and the vendored engine. See MoneroRingctBuilder.hpp for full
// provenance. Ring selection is the online side and supplied as input.

#include "family/monero/prover/MoneroRingctBuilder.hpp"

#include <algorithm>
#include <cstring>
#include <numeric>

#include "secure/SecureString.hpp"                       // secure_wipe
#include "family/monero/scan/MoneroScanOps.hpp"          // derivations, ecdh, key image
#include "family/monero/prover/MoneroProverRng.hpp"      // csprng_scalar_nonzero
#include "xmr_rct_ops.hpp"                               // rct ops
#include "xmr_bulletproofs_plus.hpp"                     // in-tree BP+ verifier (oracle)

extern "C" {
#include "vendor/crypto-ops.h"
}

namespace xr = c2pool::xmr::native::rct;

namespace c2wallet::monero::prover {

namespace {

// CryptoNote tags.
constexpr std::uint8_t TXIN_TO_KEY          = 0x02;
constexpr std::uint8_t TXOUT_TO_TAGGED_KEY  = 0x03;
constexpr std::uint8_t EXTRA_TAG_PUBKEY     = 0x01;
constexpr std::uint8_t EXTRA_TAG_NONCE      = 0x02;
constexpr std::uint8_t EXTRA_TAG_ADD_PUBKEY = 0x04;
constexpr std::uint8_t RCT_TYPE_BP_PLUS     = 6;   // RCTTypeBulletproofPlus

// LEB128 varint, byte-identical to tools::write_varint.
void put_varint(std::vector<unsigned char>& b, std::uint64_t v) {
    while (v >= 0x80) { b.push_back(static_cast<unsigned char>((v & 0x7f) | 0x80)); v >>= 7; }
    b.push_back(static_cast<unsigned char>(v));
}
void put_key(std::vector<unsigned char>& b, const Bytes32& k) { b.insert(b.end(), k.begin(), k.end()); }

Bytes32 keccak(const std::vector<unsigned char>& b) {
    return mcrypto::keccak256(b.data(), b.size());
}

// --- point helpers (encoded ed25519 points) ---------------------------------
bool point_add(const Bytes32& a, const Bytes32& b, Bytes32& out) {
    ge_p3 a3, b3; ge_cached bc; ge_p1p1 sum; ge_p3 res;
    if (ge_frombytes_vartime(&a3, a.data()) != 0) return false;
    if (ge_frombytes_vartime(&b3, b.data()) != 0) return false;
    ge_p3_to_cached(&bc, &b3);
    ge_add(&sum, &a3, &bc);
    ge_p1p1_to_p3(&res, &sum);
    ge_p3_tobytes(out.data(), &res);
    return true;
}
bool point_sub(const Bytes32& a, const Bytes32& b, Bytes32& out) {
    ge_p3 a3, b3; ge_cached bc; ge_p1p1 diff; ge_p3 res;
    if (ge_frombytes_vartime(&a3, a.data()) != 0) return false;
    if (ge_frombytes_vartime(&b3, b.data()) != 0) return false;
    ge_p3_to_cached(&bc, &b3);
    ge_sub(&diff, &a3, &bc);
    ge_p1p1_to_p3(&res, &diff);
    ge_p3_tobytes(out.data(), &res);
    return true;
}
Bytes32 scalarmult_base(const Bytes32& a) {
    ge_p3 p; ge_scalarmult_base(&p, a.data());
    Bytes32 out{}; ge_p3_tobytes(out.data(), &p);
    return out;
}

void wipe(Bytes32& k) { c2w::secure::secure_wipe(k.data(), k.size()); }

// tx_extra: 0x01 R [0x04 n P...] [0x02 len nonce].
std::vector<unsigned char> build_tx_extra(const Bytes32& R,
                                          const std::vector<Bytes32>& additional,
                                          const std::vector<std::uint8_t>& nonce) {
    std::vector<unsigned char> e;
    e.push_back(EXTRA_TAG_PUBKEY);
    put_key(e, R);
    if (!additional.empty()) {
        e.push_back(EXTRA_TAG_ADD_PUBKEY);
        put_varint(e, additional.size());
        for (const Bytes32& k : additional) put_key(e, k);
    }
    if (!nonce.empty()) {
        e.push_back(EXTRA_TAG_NONCE);
        put_varint(e, nonce.size());
        e.insert(e.end(), nonce.begin(), nonce.end());
    }
    return e;
}

} // namespace

std::uint64_t compute_fee(std::size_t tx_weight, std::uint64_t per_byte_rate,
                          std::uint32_t priority) noexcept {
    static const std::uint64_t mult[] = {1, 5, 25, 1000};
    const std::uint64_t m = (priority >= 1 && priority <= 4) ? mult[priority - 1] : 1;
    return static_cast<std::uint64_t>(tx_weight) * per_byte_rate * m;
}

bool self_verify_key_images(const std::vector<SpendInput>& inputs,
                            const RingctTx& tx, std::string& why) {
    if (inputs.size() != tx.key_images.size()) { why = "input/key-image count mismatch"; return false; }
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        const SpendInput& in = inputs[i];
        if (in.real_index >= in.ring.size()) { why = "real_index out of range"; return false; }
        Bytes32 I{};
        if (!scanops::generate_key_image(in.ring[in.real_index].dest, in.one_time_sec, I)) {
            why = "key-image recompute failed"; return false;
        }
        // The stored images are ordered as the tx orders inputs; match by value.
        bool found = false;
        for (const Bytes32& stored : tx.key_images) if (stored == I) { found = true; break; }
        if (!found) { why = "recomputed key image not present in tx"; return false; }
    }
    return true;
}

bool self_verify_tx_public(const RingctTx& tx, std::string& why) {
    const std::vector<std::vector<CtKey>>& rings = tx.rings;
    // 1. Bulletproofs+ range proof, INDEPENDENT in-tree verifier.
    if (!xr::verify_bulletproof_plus(tx.bpp)) { why = "bulletproofs+ verify failed"; return false; }
    if (tx.bpp.V.size() != tx.output_commitments.size()) { why = "bp+ V count != outputs"; return false; }
    for (std::size_t j = 0; j < tx.output_commitments.size(); ++j) {
        // Bind the proof to the tx: 8 * V_j must equal the output commitment.
        ge_p3 p3; if (!xr::scalarmult8(p3, tx.bpp.V[j])) { why = "bp+ V decode failed"; return false; }
        Bytes32 v8{}; ge_p3_tobytes(v8.data(), &p3);
        if (v8 != tx.output_commitments[j]) { why = "bp+ V not bound to output commitment"; return false; }
    }

    // 2. Per-input CLSAG, ported verifier.
    if (rings.size() != tx.clsags.size() || rings.size() != tx.pseudo_outs.size()) {
        why = "ring/clsag/pseudo-out count mismatch"; return false;
    }
    for (std::size_t i = 0; i < tx.clsags.size(); ++i) {
        if (!clsag_verify(tx.message, tx.clsags[i], rings[i], tx.pseudo_outs[i])) {
            why = "CLSAG verify failed for an input"; return false;
        }
    }

    // 3. Commitment balance: Sum pseudo_outs - Sum C_out - fee*H == identity.
    Bytes32 acc = xr::identity();
    bool first = true;
    for (const Bytes32& c : tx.pseudo_outs) {
        if (first) { acc = c; first = false; }
        else if (!point_add(acc, c, acc)) { why = "pseudo-out sum failed"; return false; }
    }
    for (const Bytes32& c : tx.output_commitments)
        if (!point_sub(acc, c, acc)) { why = "output-commitment subtract failed"; return false; }
    const Bytes32 feeH = xr::scalarmult_H(xr::amount_to_scalar(tx.fee));
    if (!point_sub(acc, feeH, acc)) { why = "fee subtract failed"; return false; }
    if (acc != xr::identity()) { why = "commitment balance != 0 (unbalanced tx)"; return false; }

    return true;
}

AssembleResult assemble_ringct_tx(const std::vector<SpendInput>& inputs_in,
                                  const std::vector<TxDestination>& dests,
                                  std::uint64_t fee,
                                  const std::vector<std::uint8_t>& payment_id_nonce,
                                  bool self_verify) {
    AssembleResult res;
    if (inputs_in.empty()) { res.error = "no inputs"; return res; }
    if (dests.empty())     { res.error = "no destinations"; return res; }
    if (dests.size() > xr::BULLETPROOF_PLUS_MAX_OUTPUTS) { res.error = "too many outputs"; return res; }
    for (const SpendInput& in : inputs_in)
        if (in.real_index >= in.ring.size()) { res.error = "real_index out of range"; return res; }

    // Amount balance precondition: Sum a_in == Sum a_out + fee.
    std::uint64_t sum_in = 0, sum_out = 0;
    for (const SpendInput& in : inputs_in) sum_in += in.amount;
    for (const TxDestination& d : dests) sum_out += d.amount;
    if (sum_in != sum_out + fee) { res.error = "amounts do not balance (sum_in != sum_out + fee)"; return res; }

    RingctTx tx;
    tx.fee = fee;

    // --- tx secret key r and R = r*G (design step 8, tx_extra 0x01) ----------
    Bytes32 r = csprng_scalar_nonzero();                 // MONEY: CSPRNG
    tx.tx_pubkey = scalarmult_base(r);

    // --- outputs: one-time keys, ecdh amounts, deterministic masks (step 3,8)-
    std::vector<std::uint64_t> out_amounts(dests.size());
    std::vector<Bytes32>       out_masks(dests.size());
    std::vector<Bytes32>       additional_pubkeys;   // subaddress support (structural)
    for (std::size_t j = 0; j < dests.size(); ++j) {
        const TxDestination& d = dests[j];
        Bytes32 D{};
        if (!scanops::key_derivation(d.view_pub, r, D)) { wipe(r); res.error = "key_derivation failed"; return res; }
        Bytes32 P{};
        if (!scanops::derive_public_key(D, j, d.spend_pub, P)) { wipe(r); res.error = "derive_public_key failed"; return res; }
        const Bytes32 amount_key = scanops::derivation_to_scalar(D, j);
        tx.output_pubkeys.push_back(P);
        tx.ecdh_amounts.push_back(scanops::ecdh_encode_amount(d.amount, amount_key));
        out_amounts[j] = d.amount;
        out_masks[j]   = scanops::commitment_mask(amount_key);
        tx.output_commitments.push_back(commit(d.amount, out_masks[j]));
        wipe(D);
    }

    // --- pseudo-output masks balanced so Sum x'_i = Sum out_masks (step 3) ----
    Bytes32 sum_out_mask = xr::scalar_zero();
    for (const Bytes32& m : out_masks) sc_add(sum_out_mask.data(), sum_out_mask.data(), m.data());

    std::vector<Bytes32> pseudo_masks(inputs_in.size());
    Bytes32 acc_mask = xr::scalar_zero();
    for (std::size_t i = 0; i + 1 < inputs_in.size(); ++i) {
        pseudo_masks[i] = csprng_scalar_nonzero();       // MONEY: CSPRNG
        sc_add(acc_mask.data(), acc_mask.data(), pseudo_masks[i].data());
    }
    // Last mask balances the sum. (If a single input, this is the whole sum.)
    sc_sub(pseudo_masks.back().data(), sum_out_mask.data(), acc_mask.data());
    wipe(acc_mask); wipe(sum_out_mask);

    // --- key images + pseudo-output commitments ------------------------------
    // We compute per-input key images now (needs secrets) and reorder inputs by
    // key image (descending), as monerod does, so the blob + signatures + the
    // message all agree on ordering.
    std::vector<SpendInput> inputs = inputs_in;
    std::vector<Bytes32> key_images(inputs.size());
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        if (!scanops::generate_key_image(inputs[i].ring[inputs[i].real_index].dest,
                                         inputs[i].one_time_sec, key_images[i])) {
            wipe(r); for (Bytes32& m : pseudo_masks) wipe(m);
            res.error = "generate_key_image failed"; return res;
        }
    }
    std::vector<std::size_t> order(inputs.size());
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
        return std::memcmp(key_images[a].data(), key_images[b].data(), 32) > 0;  // desc
    });
    std::vector<SpendInput> sinputs(inputs.size());
    std::vector<Bytes32>    spseudo_masks(inputs.size());
    std::vector<Bytes32>    skey_images(inputs.size());
    for (std::size_t k = 0; k < order.size(); ++k) {
        sinputs[k]       = inputs[order[k]];
        spseudo_masks[k] = pseudo_masks[order[k]];
        skey_images[k]   = key_images[order[k]];
    }

    std::vector<std::vector<CtKey>> rings(sinputs.size());
    for (std::size_t i = 0; i < sinputs.size(); ++i) {
        tx.key_images.push_back(skey_images[i]);
        tx.pseudo_outs.push_back(commit(sinputs[i].amount, spseudo_masks[i]));
        rings[i] = sinputs[i].ring;
    }
    tx.rings = rings;

    // --- Bulletproofs+ range proof over the outputs (step 4) -----------------
    if (!prove_range(out_amounts, out_masks, tx.bpp)) {
        wipe(r); for (Bytes32& m : spseudo_masks) wipe(m); for (Bytes32& m : pseudo_masks) wipe(m);
        res.error = "bulletproofs+ prove failed"; return res;
    }
    for (Bytes32& m : out_masks) wipe(m);

    // --- serialize tx prefix + hashes (step 9) -------------------------------
    const std::vector<unsigned char> extra =
        build_tx_extra(tx.tx_pubkey, additional_pubkeys, payment_id_nonce);

    std::vector<unsigned char> prefix;
    put_varint(prefix, 2);   // version
    put_varint(prefix, 0);   // unlock_time
    put_varint(prefix, sinputs.size());
    for (std::size_t i = 0; i < sinputs.size(); ++i) {
        prefix.push_back(TXIN_TO_KEY);
        put_varint(prefix, 0);                       // amount (0 for RingCT)
        const std::size_t n = sinputs[i].ring.size();
        put_varint(prefix, n);                       // ring size (key_offsets count)
        // Delta-encoded absolute output indices; synthesize if not supplied.
        std::vector<std::uint64_t> gi = sinputs[i].ring_global_indices;
        if (gi.size() != n) { gi.resize(n); for (std::size_t k = 0; k < n; ++k) gi[k] = k; }
        std::uint64_t prev = 0;
        for (std::size_t k = 0; k < n; ++k) {
            put_varint(prefix, k == 0 ? gi[k] : gi[k] - prev);
            prev = gi[k];
        }
        put_key(prefix, skey_images[i]);
    }
    put_varint(prefix, tx.output_pubkeys.size());
    for (std::size_t j = 0; j < tx.output_pubkeys.size(); ++j) {
        put_varint(prefix, 0);                       // amount (0 for RingCT)
        prefix.push_back(TXOUT_TO_TAGGED_KEY);
        put_key(prefix, tx.output_pubkeys[j]);
        // view tag = first byte of H("view_tag" || D || j): recompute is online;
        // for the blob we carry the low byte of the ecdh masked amount as a
        // deterministic placeholder tag (view-tag exactness is an M5/interop item).
        prefix.push_back(tx.ecdh_amounts[j][0]);
    }
    put_varint(prefix, extra.size());
    prefix.insert(prefix.end(), extra.begin(), extra.end());

    tx.prefix_hash = keccak(prefix);

    // rctSigBase hash: type || fee || ecdhInfo[] || outPk[].
    std::vector<unsigned char> base;
    base.push_back(RCT_TYPE_BP_PLUS);
    put_varint(base, fee);
    for (const auto& e : tx.ecdh_amounts) base.insert(base.end(), e.begin(), e.end());
    for (const Bytes32& c : tx.output_commitments) put_key(base, c);
    const Bytes32 base_hash = keccak(base);

    // range-proof hash (V excluded, as monerod hashes the prunable BP+).
    std::vector<unsigned char> bpb;
    put_key(bpb, tx.bpp.A); put_key(bpb, tx.bpp.A1); put_key(bpb, tx.bpp.B);
    put_key(bpb, tx.bpp.r1); put_key(bpb, tx.bpp.s1); put_key(bpb, tx.bpp.d1);
    for (const auto& L : tx.bpp.L) put_key(bpb, L);
    for (const auto& R : tx.bpp.R) put_key(bpb, R);
    const Bytes32 bpp_hash = keccak(bpb);

    // pre-MLSAG (CLSAG) message = keccak(prefix_hash || base_hash || bpp_hash).
    {
        std::vector<unsigned char> m;
        put_key(m, tx.prefix_hash); put_key(m, base_hash); put_key(m, bpp_hash);
        tx.message = keccak(m);
    }

    // --- CLSAG per input (step 5) --------------------------------------------
    tx.clsags.resize(sinputs.size());
    for (std::size_t i = 0; i < sinputs.size(); ++i) {
        Bytes32 x = sinputs[i].one_time_sec;   // spend secret x_i for real member
        bool ok = clsag_prove_simple(tx.message, sinputs[i].ring, x,
                                     sinputs[i].amount_mask, spseudo_masks[i],
                                     tx.pseudo_outs[i], sinputs[i].real_index, tx.clsags[i]);
        wipe(x);
        if (!ok) {
            wipe(r); for (Bytes32& m : spseudo_masks) wipe(m); for (Bytes32& m : pseudo_masks) wipe(m);
            res.error = "clsag_prove_simple failed"; return res;
        }
    }

    // --- full blob + tx_hash --------------------------------------------------
    std::vector<unsigned char> blob = prefix;
    blob.insert(blob.end(), base.begin(), base.end());
    // prunable: pseudoOuts[], BP+, CLSAGs.
    std::vector<unsigned char> prun;
    for (const Bytes32& c : tx.pseudo_outs) put_key(prun, c);
    prun.insert(prun.end(), bpb.begin(), bpb.end());
    for (const Clsag& s : tx.clsags) {
        put_varint(prun, s.s.size());
        for (const Bytes32& sc : s.s) put_key(prun, sc);
        put_key(prun, s.c1);
        put_key(prun, s.D);
    }
    blob.insert(blob.end(), prun.begin(), prun.end());
    tx.blob = blob;

    const Bytes32 prun_hash = keccak(prun);
    {
        std::vector<unsigned char> th;
        put_key(th, tx.prefix_hash); put_key(th, base_hash); put_key(th, prun_hash);
        tx.tx_hash = keccak(th);
    }

    // --- offline self-verify-before-emit (design §5.3) -----------------------
    if (self_verify) {
        std::string why;
        if (!self_verify_tx_public(tx, why)) {
            for (Bytes32& m : spseudo_masks) wipe(m); for (Bytes32& m : pseudo_masks) wipe(m); wipe(r);
            res.error = "self-verify refused to emit: " + why;
            return res;   // ok stays false, no blob handed out
        }
        if (!self_verify_key_images(sinputs, tx, why)) {
            for (Bytes32& m : spseudo_masks) wipe(m); for (Bytes32& m : pseudo_masks) wipe(m); wipe(r);
            res.error = "self-verify refused to emit: " + why;
            return res;
        }
    }

    for (Bytes32& m : spseudo_masks) wipe(m);
    for (Bytes32& m : pseudo_masks) wipe(m);
    wipe(r);

    res.ok = true;
    res.tx = std::move(tx);
    return res;
}

} // namespace c2wallet::monero::prover
