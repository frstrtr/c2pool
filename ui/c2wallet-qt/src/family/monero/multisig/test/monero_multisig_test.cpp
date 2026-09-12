// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// Known-answer tests for the Family B (Monero) M4-X-MMS money path: N/M
// multisig key exchange, MMS round-message import/export, and COOPERATIVE
// (partial) CLSAG signing over the M4-X RingCT prover (design §4.2).
//
//   *** EXPERIMENTAL feature under test *** -- see MoneroMultisig.hpp.
//
// Money-correctness oracles, all non-circular:
//
//  [K] KEY EXCHANGE -> SHARED ADDRESS. 2-of-2 and 2-of-3 key exchange yields a
//      single shared multisig spend public key on which every participant
//      agrees, and whose secret is the sum of the exchanged shares
//      (cross-derived: spend_pub == (Sum of all subset secrets)*G). For 2-of-3,
//      no single participant holds every subset secret, but any two do.
//
//  [M] MMS MESSAGE ROUND-TRIP. Every round message (Round1, Round2, sign nonce,
//      sign response) survives export -> import unchanged, incl. via hex.
//
//  [S] COOPERATIVE SIGN -> COMBINED TX SELF-VERIFIES. M cosigners each produce a
//      partial; the combined CLSAG verifies under the UNCHANGED in-tree/M3-X
//      verifier clsag_verify, the key image equals the single-key reference,
//      and the surrounding tx legs (BP+ range proof over the output, commitment
//      balance) also verify -- so the whole combined tx self-verifies.
//
//  [N] THRESHOLD + TAMPER. M-1 cosigners canNOT produce a valid signature; a
//      withheld partial and a tampered partial are both rejected by verify.
//
//  [R] CSPRNG. Two signings of the same input produce distinct published
//      scalars (fresh nonces); both verify. (The nm/grep proof that no multisig
//      object references random_scalar_nonzero / mt19937 is a build-step check.)
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"
#include "family/monero/addr/MoneroAddress.hpp"
#include "family/monero/scan/MoneroScanOps.hpp"
#include "family/monero/prover/MoneroClsag.hpp"
#include "family/monero/prover/MoneroBulletproofsPlus.hpp"
#include "family/monero/prover/MoneroProverRng.hpp"
#include "family/monero/multisig/MoneroMultisig.hpp"
#include "family/monero/multisig/MoneroMultisigSign.hpp"
#include "family/monero/multisig/MoneroMmsMessage.hpp"
#include "xmr_bulletproofs_plus.hpp"
#include "xmr_rct_ops.hpp"

extern "C" {
#include "vendor/crypto-ops.h"
}

using namespace c2wallet::monero;
namespace ms = c2wallet::monero::multisig;
namespace xr = c2pool::xmr::native::rct;

namespace {

int g_failures = 0;
int g_checks = 0;
void check(bool cond, const std::string& what) {
    ++g_checks;
    std::printf(cond ? "  ok   : %s\n" : "  FAIL : %s\n", what.c_str());
    if (!cond) ++g_failures;
}

Bytes32 scalar_of(const char* label) {
    return mcrypto::reduce32(mcrypto::keccak256(
        reinterpret_cast<const std::uint8_t*>(label), std::strlen(label)));
}

// Deterministic base secrets so the KATs are reproducible (the CSPRNG path is
// exercised separately in [R] and generate_base_secrets()).
ms::BaseSecrets base_of(const char* seed) {
    ms::BaseSecrets b;
    b.spend_sec = scalar_of((std::string(seed) + "-spend").c_str());
    b.view_sec  = mcrypto::hash_to_scalar(b.spend_sec.data(), b.spend_sec.size());
    return b;
}

// Run a full key exchange for M-of-N with the given base secrets; return each
// participant's finalized setup (index -> SetupResult).
std::vector<ms::SetupResult> run_kex(const ms::MultisigConfig& cfg,
                                     const std::vector<ms::BaseSecrets>& bases) {
    std::vector<ms::KexRound1> r1;
    for (std::uint32_t i = 0; i < cfg.total; ++i) r1.push_back(ms::make_round1(i, bases[i]));

    std::vector<ms::KexRound2> r2;
    if (ms::kex_rounds(cfg) >= 2) {
        for (std::uint32_t i = 0; i < cfg.total; ++i) {
            ms::SignerShares dummy;
            r2.push_back(ms::make_round2(i, bases[i], r1, dummy));
        }
    }
    std::vector<ms::SetupResult> out;
    for (std::uint32_t i = 0; i < cfg.total; ++i)
        out.push_back(ms::finalize(cfg, i, bases[i], r1, r2));
    return out;
}

// Gather the UNIQUE subset secrets across all signers and sum them: the full
// multisig spend secret (test scaffold only; no single party computes this).
Bytes32 reconstruct_spend_secret(const std::vector<ms::SetupResult>& setups) {
    std::vector<std::vector<std::uint32_t>> seen;
    Bytes32 acc{};
    for (const ms::SetupResult& s : setups) {
        for (std::size_t k = 0; k < s.shares.spend_key_shares.size(); ++k) {
            const std::vector<std::uint32_t>& sub = s.shares.shares_subset[k];
            if (std::find(seen.begin(), seen.end(), sub) != seen.end()) continue;
            seen.push_back(sub);
            sc_add(acc.data(), acc.data(), s.shares.spend_key_shares[k].data());
        }
    }
    return acc;
}

// ── [K] key exchange -> shared address ──────────────────────────────────────
void test_kex() {
    std::printf("[K] multisig key exchange -> shared multisig address\n");

    // 2-of-2.
    {
        ms::MultisigConfig cfg{2, 2, Network::Mainnet};
        check(ms::config_supported(cfg) && ms::kex_rounds(cfg) == 1, "2-of-2 supported, 1 kex round");
        std::vector<ms::BaseSecrets> bases = { base_of("A"), base_of("B") };
        std::vector<ms::SetupResult> s = run_kex(cfg, bases);
        check(s[0].ok && s[1].ok, "2-of-2 finalize ok for both");
        check(s[0].info.spend_pub == s[1].info.spend_pub, "both agree on multisig spend pub");
        check(s[0].info.view_sec == s[1].info.view_sec, "both agree on common view secret");
        check(s[0].info.address.spend_pub == s[0].info.spend_pub, "address carries the multisig spend pub");

        Bytes32 x = reconstruct_spend_secret(s), Ks{};
        mcrypto::secret_to_public(x, Ks);
        check(Ks == s[0].info.spend_pub, "spend_pub == (sum of shares)*G (cross-derive)");

        std::string enc = address_encode(s[0].info.address);
        MoneroAddress dec; std::string err;
        check(address_decode(enc, dec, err) && dec.spend_pub == Ks,
              "multisig address encodes + decodes round-trip");
    }

    // 2-of-3.
    {
        ms::MultisigConfig cfg{2, 3, Network::Mainnet};
        check(ms::config_supported(cfg) && ms::kex_rounds(cfg) == 2, "2-of-3 supported, 2 kex rounds");
        std::vector<ms::BaseSecrets> bases = { base_of("P0"), base_of("P1"), base_of("P2") };
        std::vector<ms::SetupResult> s = run_kex(cfg, bases);
        check(s[0].ok && s[1].ok && s[2].ok, "2-of-3 finalize ok for all three");
        check(s[0].info.spend_pub == s[1].info.spend_pub &&
              s[1].info.spend_pub == s[2].info.spend_pub, "all three agree on multisig spend pub");
        Bytes32 x = reconstruct_spend_secret(s), Ks{};
        mcrypto::secret_to_public(x, Ks);
        check(Ks == s[0].info.spend_pub, "2-of-3 spend_pub == (sum of 3 subset secrets)*G");
        // Each participant holds exactly 2 of the 3 pairwise subsets; none holds all 3.
        check(s[0].shares.spend_key_shares.size() == 2 &&
              s[1].shares.spend_key_shares.size() == 2 &&
              s[2].shares.spend_key_shares.size() == 2, "each of 3 holds 2 subset secrets (none holds all 3)");
    }

    // Unsupported shape refused (documented follow-on: subset size >= 3).
    {
        ms::MultisigConfig cfg{2, 4, Network::Mainnet};   // subset size 3
        check(!ms::config_supported(cfg), "2-of-4 (subset size 3) reported unsupported (deferred)");
        std::vector<ms::BaseSecrets> bases(4);
        ms::SetupResult r = ms::finalize(cfg, 0, bases[0], {}, {});
        check(!r.ok, "finalize refuses an unsupported shape");
    }
}

// ── [M] MMS message round-trip ──────────────────────────────────────────────
void test_mms_roundtrip() {
    std::printf("[M] MMS round-message export/import round-trip\n");
    ms::MultisigConfig cfg{2, 3, Network::Mainnet};
    std::vector<ms::BaseSecrets> bases = { base_of("P0"), base_of("P1"), base_of("P2") };

    ms::KexRound1 r1 = ms::make_round1(1, bases[1]);
    ms::MmsMessage m1 = ms::to_mms(r1);
    std::vector<std::uint8_t> blob = ms::mms_serialize(m1);
    ms::MmsMessage back; ms::KexRound1 r1b;
    check(ms::mms_deserialize(blob.data(), blob.size(), back) && ms::from_mms(back, r1b), "Round1 deserialize ok");
    check(r1b.signer_index == r1.signer_index && r1b.spend_pub_share == r1.spend_pub_share &&
          r1b.view_sec_share == r1.view_sec_share, "Round1 fields survive round-trip");

    std::vector<ms::KexRound1> all1 = { ms::make_round1(0, bases[0]), r1, ms::make_round1(2, bases[2]) };
    ms::SignerShares dummy;
    ms::KexRound2 r2 = ms::make_round2(1, bases[1], all1, dummy);
    ms::MmsMessage hexm; ms::KexRound2 r2b;
    check(ms::mms_from_hex(ms::mms_to_hex(ms::to_mms(r2)), hexm) && ms::from_mms(hexm, r2b), "Round2 hex round-trip ok");
    check(r2b.partner_index == r2.partner_index && r2b.subset_pub == r2.subset_pub, "Round2 fields survive hex round-trip");

    ms::PartialNonce pn; pn.signer_index = 2; pn.alpha_G = scalar_of("aG"); pn.alpha_H = scalar_of("aH"); pn.partial_ki = scalar_of("ki");
    ms::MmsMessage nm; ms::PartialNonce pnb;
    check(ms::mms_deserialize(ms::mms_serialize(ms::to_mms(pn, 1)).data(), ms::mms_serialize(ms::to_mms(pn, 1)).size(), nm) &&
          ms::from_mms(nm, pnb), "SignNonce deserialize ok");
    check(pnb.alpha_G == pn.alpha_G && pnb.alpha_H == pn.alpha_H && pnb.partial_ki == pn.partial_ki, "SignNonce fields round-trip");

    Bytes32 resp = scalar_of("resp");
    ms::MmsMessage rm; std::uint32_t si = 99; Bytes32 rb{};
    check(ms::mms_deserialize(ms::mms_serialize(ms::response_to_mms(1, resp, 2)).data(),
          ms::mms_serialize(ms::response_to_mms(1, resp, 2)).size(), rm) &&
          ms::response_from_mms(rm, si, rb), "SignResponse deserialize ok");
    check(si == 1 && rb == resp, "SignResponse fields round-trip");

    // Corrupt magic / trailing garbage rejected.
    blob[0] ^= 0xff;
    ms::MmsMessage junk;
    check(!ms::mms_deserialize(blob.data(), blob.size(), junk), "bad magic rejected");
}

// Orchestrate a cooperative CLSAG signing. `quorum` are the signing indices.
// Options let the negative tests withhold or tamper a partial. Returns the
// combined CLSAG and (out) the aggregated key image.
struct SignOpts { bool withhold_last{false}; bool tamper_last{false}; };
bool cooperative_sign(const ms::SigningSession& sess,
                      const std::vector<ms::SetupResult>& setups,
                      const std::vector<std::uint32_t>& quorum,
                      const Bytes32& z,
                      const SignOpts& opt,
                      prover::Clsag& out) {
    const std::uint32_t coordinator = quorum.front();

    // Precompute each signer's assigned shares for this quorum.
    std::vector<std::vector<Bytes32>> assigned(quorum.size());
    for (std::size_t j = 0; j < quorum.size(); ++j)
        assigned[j] = ms::assigned_shares(setups[quorum[j]].shares, quorum);

    // Round 1: each signer's nonce commitments + partial key image.
    std::vector<ms::CosignerNonce> nonces(quorum.size());
    std::vector<ms::PartialNonce>  pns;
    for (std::size_t j = 0; j < quorum.size(); ++j) {
        ms::PartialNonce pn;
        if (!ms::cosigner_round1(sess, quorum[j], assigned[j], nullptr, pn, nonces[j])) return false;
        pns.push_back(pn);
    }

    // Coordinator combine round 1.
    ms::Round1Combined r1;
    if (!ms::coordinator_combine_round1(sess, pns, z, r1)) return false;

    // Round 2: each signer's partial response (coordinator carries z).
    std::vector<Bytes32> responses;
    for (std::size_t j = 0; j < quorum.size(); ++j) {
        const bool is_coord = (quorum[j] == coordinator);
        Bytes32 resp = ms::cosigner_round2(r1.c_at_l, r1.mu_P, r1.mu_C, assigned[j],
                                           nullptr, is_coord ? &z : nullptr, nonces[j]);
        if (opt.tamper_last && j + 1 == quorum.size()) resp[0] ^= 0x01;
        responses.push_back(resp);
    }
    if (opt.withhold_last && !responses.empty()) responses.pop_back();

    return ms::coordinator_combine_round2(sess, r1, responses, out);
}

// Build a self-verifying single-input/single-output RingCT context whose spend
// key is the multisig key. All masks are chosen here so the balance holds and
// the commitment-to-zero scalar z is known to the coordinator.
struct TxCtx {
    ms::SigningSession sess;
    Bytes32 z{};                 // c_a - c_out
    Bytes32 out_commit{};        // C_out
    Bytes32 pseudo_commit{};     // pseudo-output (== Cout in session)
    std::uint64_t fee{0};
    prover::BulletproofPlus bpp; // range proof over the output
    Bytes32 amount_mask{};       // c_a
    std::uint64_t amount_in{0};
};
bool build_tx_ctx(const Bytes32& Ks, std::uint64_t amount_in, std::uint64_t amount_out,
                  std::size_t ring_n, std::size_t real_index, TxCtx& ctx) {
    ctx.amount_in = amount_in;
    ctx.fee = amount_in - amount_out;
    ctx.amount_mask = scalar_of("ms-c_a");           // input commitment mask c_a

    // Balance for 1-in/1-out: pseudo = commit(a_in, c_out), out = commit(a_out, z_out),
    // fee*H. Need pseudo - out - fee*H = 0 -> with fee=a_in-a_out, choose c_out=z_out.
    Bytes32 z_out = prover::csprng_scalar_nonzero();
    ctx.out_commit    = prover::commit(amount_out, z_out);
    ctx.pseudo_commit = prover::commit(amount_in, z_out);   // c_out = z_out
    sc_sub(ctx.z.data(), ctx.amount_mask.data(), z_out.data());  // z = c_a - c_out

    // Range proof over the single output.
    std::vector<std::uint64_t> amts = { amount_out };
    std::vector<Bytes32> masks = { z_out };
    if (!prover::prove_range(amts, masks, ctx.bpp)) return false;

    // Ring: real member is (K_s, C_a); decoys arbitrary.
    std::vector<prover::CtKey> ring(ring_n);
    for (std::size_t i = 0; i < ring_n; ++i) {
        if (i == real_index) {
            ring[i].dest = Ks;
            ring[i].mask = prover::commit(amount_in, ctx.amount_mask);
        } else {
            char lbl[64];
            std::snprintf(lbl, sizeof(lbl), "ms-decoy-d-%zu", i);
            Bytes32 ds = scalar_of(lbl);
            mcrypto::secret_to_public(ds, ring[i].dest);
            std::snprintf(lbl, sizeof(lbl), "ms-decoy-m-%zu", i);
            ring[i].mask = prover::commit(1000 + i, scalar_of(lbl));
        }
    }
    Bytes32 message = mcrypto::keccak256(
        reinterpret_cast<const std::uint8_t*>("ms-pre-mlsag"), 12);
    return ms::make_signing_session(message, ring, real_index, ctx.pseudo_commit, ctx.sess);
}

// Independent balance check: pseudo - out - fee*H == identity.
bool balance_ok(const TxCtx& ctx) {
    Bytes32 feeH = xr::scalarmult_H(xr::amount_to_scalar(ctx.fee));
    Bytes32 sum{}; bool ok = true;
    // pseudo - out
    Bytes32 negout{};
    // compute (pseudo - out) - feeH via point ops in MoneroCrypto
    Bytes32 diff{};
    // diff = pseudo - out
    {
        ge_p3 a3, b3; ge_cached bc; ge_p1p1 d; ge_p3 r;
        if (ge_frombytes_vartime(&a3, ctx.pseudo_commit.data()) != 0) return false;
        if (ge_frombytes_vartime(&b3, ctx.out_commit.data()) != 0) return false;
        ge_p3_to_cached(&bc, &b3); ge_sub(&d, &a3, &bc); ge_p1p1_to_p3(&r, &d);
        ge_p3_tobytes(diff.data(), &r);
    }
    // sum = diff - feeH
    {
        ge_p3 a3, b3; ge_cached bc; ge_p1p1 d; ge_p3 r;
        if (ge_frombytes_vartime(&a3, diff.data()) != 0) return false;
        if (ge_frombytes_vartime(&b3, feeH.data()) != 0) return false;
        ge_p3_to_cached(&bc, &b3); ge_sub(&d, &a3, &bc); ge_p1p1_to_p3(&r, &d);
        ge_p3_tobytes(sum.data(), &r);
    }
    (void)negout; (void)ok;
    return sum == xr::identity();
}

// ── [S]/[N] cooperative sign for one M-of-N configuration ───────────────────
void test_coop_sign(const ms::MultisigConfig& cfg,
                    const std::vector<ms::BaseSecrets>& bases,
                    const std::vector<std::uint32_t>& quorum,
                    const char* label) {
    std::printf("[S] cooperative sign %s (quorum size %zu)\n", label, quorum.size());
    std::vector<ms::SetupResult> setups = run_kex(cfg, bases);
    Bytes32 x = reconstruct_spend_secret(setups);
    Bytes32 Ks = setups[0].info.spend_pub;

    TxCtx ctx;
    if (!build_tx_ctx(Ks, 5000000000ULL, 4990000000ULL, 11, 4, ctx)) { check(false, "build_tx_ctx"); return; }

    // Reference single-key key image + a single-sig CLSAG (the oracle).
    Bytes32 ref_I{};
    check(scanops::generate_key_image(Ks, x, ref_I), "reference key image computed from reconstructed x");

    // Cooperative signature.
    prover::Clsag sig;
    check(cooperative_sign(ctx.sess, setups, quorum, ctx.z, SignOpts{}, sig), "cooperative sign completes");
    check(sig.I == ref_I, "combined key image == single-key reference (Sum of partial images)");
    check(prover::clsag_verify(ctx.sess.message, sig, ctx.sess.ring, ctx.sess.Cout),
          "combined CLSAG VERIFIES under the unchanged in-tree verifier");

    // The rest of the tx self-verifies: BP+ range proof + commitment balance.
    check(xr::verify_bulletproof_plus(ctx.bpp), "output range proof (BP+) verifies");
    ge_p3 p3; xr::scalarmult8(p3, ctx.bpp.V[0]); Bytes32 v8{}; ge_p3_tobytes(v8.data(), &p3);
    check(v8 == ctx.out_commit, "8*V == output commitment (BP+ binds the output)");
    check(balance_ok(ctx), "commitment balance pseudo - out - fee*H == 0");

    // [N] withhold a partial -> reject.
    {
        prover::Clsag bad;
        check(cooperative_sign(ctx.sess, setups, quorum, ctx.z, SignOpts{true, false}, bad),
              "combine still returns with a withheld partial");
        check(!prover::clsag_verify(ctx.sess.message, bad, ctx.sess.ring, ctx.sess.Cout),
              "withheld partial -> combined signature REJECTED");
    }
    // [N] tamper a partial -> reject.
    {
        prover::Clsag bad;
        cooperative_sign(ctx.sess, setups, quorum, ctx.z, SignOpts{false, true}, bad);
        check(!prover::clsag_verify(ctx.sess.message, bad, ctx.sess.ring, ctx.sess.Cout),
              "tampered partial -> combined signature REJECTED");
    }
    // [N] M-1 signers cannot sign: drop the last quorum member entirely.
    if (quorum.size() >= 2) {
        std::vector<std::uint32_t> short_quorum(quorum.begin(), quorum.end() - 1);
        prover::Clsag bad;
        cooperative_sign(ctx.sess, setups, short_quorum, ctx.z, SignOpts{}, bad);
        check(!prover::clsag_verify(ctx.sess.message, bad, ctx.sess.ring, ctx.sess.Cout),
              "M-1 cosigners canNOT produce a valid signature");
    }
}

// ── [R] CSPRNG: fresh nonces across signings ────────────────────────────────
void test_csprng() {
    std::printf("[R] fresh CSPRNG nonces across signings\n");
    ms::MultisigConfig cfg{2, 2, Network::Mainnet};
    std::vector<ms::BaseSecrets> bases = { base_of("R0"), base_of("R1") };
    std::vector<ms::SetupResult> setups = run_kex(cfg, bases);
    Bytes32 Ks = setups[0].info.spend_pub;
    TxCtx ctx;
    build_tx_ctx(Ks, 2000000000ULL, 1990000000ULL, 11, 3, ctx);
    std::vector<std::uint32_t> quorum = {0, 1};

    prover::Clsag a, b;
    cooperative_sign(ctx.sess, setups, quorum, ctx.z, SignOpts{}, a);
    cooperative_sign(ctx.sess, setups, quorum, ctx.z, SignOpts{}, b);
    check(prover::clsag_verify(ctx.sess.message, a, ctx.sess.ring, ctx.sess.Cout) &&
          prover::clsag_verify(ctx.sess.message, b, ctx.sess.ring, ctx.sess.Cout), "both signings verify");
    check(a.c1 != b.c1, "CLSAG anchor c1 differs across signings (fresh nonces)");
    bool any_diff = false;
    for (std::size_t i = 0; i < a.s.size(); ++i) if (a.s[i] != b.s[i]) any_diff = true;
    check(any_diff, "published scalars differ across signings (distinct nonces)");
    check(a.I == b.I, "key image identical across signings (deterministic)");

    // generate_base_secrets draws distinct CSPRNG keys.
    ms::BaseSecrets g1 = ms::generate_base_secrets(), g2 = ms::generate_base_secrets();
    check(g1.spend_sec != g2.spend_sec, "generate_base_secrets yields distinct CSPRNG spend keys");
}

} // namespace

int main() {
    std::printf("=== c2wallet-qt Family B (Monero) M4-X-MMS KATs: multisig key-exchange + cooperative sign ===\n");
    test_kex();
    test_mms_roundtrip();
    {
        ms::MultisigConfig cfg22{2, 2, Network::Mainnet};
        test_coop_sign(cfg22, { base_of("S0"), base_of("S1") }, {0, 1}, "2-of-2");
        ms::MultisigConfig cfg23{2, 3, Network::Mainnet};
        std::vector<ms::BaseSecrets> b3 = { base_of("T0"), base_of("T1"), base_of("T2") };
        test_coop_sign(cfg23, b3, {0, 1}, "2-of-3 quorum {0,1}");
        test_coop_sign(cfg23, b3, {0, 2}, "2-of-3 quorum {0,2}");
        test_coop_sign(cfg23, b3, {1, 2}, "2-of-3 quorum {1,2}");
    }
    test_csprng();
    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
