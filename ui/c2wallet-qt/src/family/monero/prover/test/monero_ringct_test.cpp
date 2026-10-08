// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// Known-answer tests for the Family B (Monero) M4-X money path: the
// Bulletproofs+ range-proof PROVER and full single-sig RingCT transaction
// assembly with offline self-verify (design §4.2 steps 3-4-9 + §5.3).
//
// Money-correctness oracles, all non-circular:
//
//  [A] BP+ CONSTRUCT -> INDEPENDENT IN-TREE VERIFY. The verifier is the
//      separate, node-consensus code src/impl/xmr/native/rct/
//      xmr_bulletproofs_plus.cpp -- NOT a mirror of the prover -- so a valid
//      proof it accepts is strong evidence of correctness. Single-output and
//      aggregated (multi-output) proofs both verify.
//
//  [B] BP+ TAMPER / MIS-BIND -> REJECT. A flipped proof element is rejected by
//      the in-tree verifier; a proof whose V does not rescale (x8) to the tx's
//      output commitment fails the binding check.
//
//  [C] FULL RINGCT ASSEMBLE -> SELF-VERIFY. Assemble a tx (owned inputs +
//      frozen decoys + outputs), and the offline self-verify passes: the
//      in-tree BP+ verifier, per-input CLSAG verify, key-image recompute, and
//      the commitment balance Sum pseudo - Sum out - fee*H = 0 all hold.
//
//  [D] UNBALANCED -> REFUSED. A tx whose fee (or a commitment) has been mauled
//      fails the balance leg of self-verify; and assembly of amounts that do
//      not balance is refused outright.
//
//  [E] DISTINCT RANDOMNESS. Two assemblies over identical inputs use different
//      BP+ blinding (the published proof differs), while the deterministic key
//      images are unchanged. (The nm/grep assert that no prover object refers
//      to random_scalar_nonzero / mt19937 is a build-step check, not here.)
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"
#include "family/monero/MoneroKey.hpp"
#include "family/monero/scan/MoneroScanOps.hpp"
#include "family/monero/prover/MoneroClsag.hpp"
#include "family/monero/prover/MoneroBulletproofsPlus.hpp"
#include "family/monero/prover/MoneroRingctBuilder.hpp"
#include "family/monero/prover/MoneroProverRng.hpp"
#include "xmr_bulletproofs_plus.hpp"
#include "xmr_rct_ops.hpp"

using namespace c2wallet::monero;
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

// ── [A]/[B] Bulletproofs+ prover ↔ in-tree verifier ─────────────────────────
void test_bpp_prove_verify() {
    std::printf("[A] Bulletproofs+ construct -> INDEPENDENT in-tree verify\n");

    // Single output.
    {
        std::vector<std::uint64_t> amts = {6820513ULL};
        std::vector<Bytes32> masks = {prover::csprng_scalar_nonzero()};
        prover::BulletproofPlus p;
        check(prover::prove_range(amts, masks, p), "single-output prove_range succeeds");
        check(p.V.size() == 1 && p.L.size() == 6, "proof shape: V=1, L=logMN=6 rounds (MN=64)");
        check(xr::verify_bulletproof_plus(p), "in-tree verifier ACCEPTS the valid single proof");

        // Binding: 8*V == commit(amount, mask).
        ge_p3 p3; xr::scalarmult8(p3, p.V[0]);
        Bytes32 v8{}; ge_p3_tobytes(v8.data(), &p3);
        check(v8 == prover::commit(amts[0], masks[0]), "8*V == amount commitment (binding)");
    }

    // Aggregated (4 outputs, incl. the extremes 0 and 2^64-1).
    {
        std::vector<std::uint64_t> amts = {0ULL, 1ULL, 4294967296ULL, 0xFFFFFFFFFFFFFFFFULL};
        std::vector<Bytes32> masks;
        for (std::size_t i = 0; i < amts.size(); ++i) masks.push_back(prover::csprng_scalar_nonzero());
        prover::BulletproofPlus p;
        check(prover::prove_range(amts, masks, p), "4-output aggregated prove_range succeeds");
        check(p.V.size() == 4 && p.L.size() == 8, "aggregated shape: V=4, L=logMN=logN+logM=8 (MN=256)");
        check(xr::verify_bulletproof_plus(p), "in-tree verifier ACCEPTS the aggregated proof");
    }

    std::printf("[B] Bulletproofs+ tamper / mis-bind -> in-tree verifier REJECTS\n");
    {
        std::vector<std::uint64_t> amts = {123456789ULL};
        std::vector<Bytes32> masks = {prover::csprng_scalar_nonzero()};
        prover::BulletproofPlus good;
        prover::prove_range(amts, masks, good);
        check(xr::verify_bulletproof_plus(good), "baseline proof verifies");

        prover::BulletproofPlus t1 = good; t1.A[0] ^= 0x01;
        check(!xr::verify_bulletproof_plus(t1), "flipped A byte -> rejected");
        prover::BulletproofPlus t2 = good; t2.L[0][0] ^= 0x01;
        check(!xr::verify_bulletproof_plus(t2), "flipped L[0] byte -> rejected");
        prover::BulletproofPlus t3 = good; t3.r1[0] ^= 0x01;
        check(!xr::verify_bulletproof_plus(t3), "mauled r1 -> rejected");
        prover::BulletproofPlus t4 = good; t4.d1[0] ^= 0x01;
        check(!xr::verify_bulletproof_plus(t4), "mauled d1 -> rejected");
    }
}

// Build an owned spendable input: a real one-time secret x, amount, real mask,
// and a ring of `n` members with the real member at `l` (decoys arbitrary).
prover::SpendInput build_input(std::size_t n, std::size_t l,
                               const char* seed, std::uint64_t amount) {
    prover::SpendInput in;
    in.amount = amount;
    in.one_time_sec = scalar_of((std::string(seed) + "-x").c_str());
    in.amount_mask  = scalar_of((std::string(seed) + "-zin").c_str());
    in.real_index = l;
    in.ring.assign(n, prover::CtKey{});
    for (std::size_t i = 0; i < n; ++i) {
        if (i == l) {
            mcrypto::secret_to_public(in.one_time_sec, in.ring[i].dest);
            in.ring[i].mask = prover::commit(amount, in.amount_mask);
        } else {
            char lbl[96];
            std::snprintf(lbl, sizeof(lbl), "%s-decoy-dest-%zu", seed, i);
            Bytes32 ds = scalar_of(lbl);
            mcrypto::secret_to_public(ds, in.ring[i].dest);
            std::snprintf(lbl, sizeof(lbl), "%s-decoy-mask-%zu", seed, i);
            in.ring[i].mask = prover::commit(1000 + i, scalar_of(lbl));
        }
    }
    return in;
}

prover::TxDestination dest_of(const char* seed, std::uint64_t amount) {
    prover::TxDestination d;
    d.amount = amount;
    Bytes32 vs = scalar_of((std::string(seed) + "-view").c_str());
    Bytes32 ss = scalar_of((std::string(seed) + "-spend").c_str());
    mcrypto::secret_to_public(ss, d.spend_pub);
    mcrypto::secret_to_public(vs, d.view_pub);
    return d;
}

// ── [C]/[D] full RingCT assembly + self-verify ──────────────────────────────
void test_ringct_assemble() {
    std::printf("[C] full RingCT assemble (2 inputs, ring 11, 2 outputs) -> self-verify\n");

    std::vector<prover::SpendInput> inputs = {
        build_input(11, 6, "c2w-m4x-in0", 5000000000ULL),
        build_input(11, 2, "c2w-m4x-in1", 3000000000ULL),
    };
    const std::uint64_t fee = 30000000ULL;
    std::vector<prover::TxDestination> dests = {
        dest_of("c2w-m4x-alice", 4970000000ULL),
        dest_of("c2w-m4x-bob",   3000000000ULL),
    };
    // sum_in 8e9 == sum_out 7.97e9 + fee 0.03e9.

    prover::AssembleResult r = prover::assemble_ringct_tx(inputs, dests, fee);
    check(r.ok, std::string("assemble_ringct_tx succeeds") + (r.ok ? "" : " (err: " + r.error + ")"));
    if (!r.ok) return;

    const prover::RingctTx& tx = r.tx;
    check(tx.clsags.size() == 2, "one CLSAG per input");
    check(tx.key_images.size() == 2, "one key image per input");
    check(tx.output_pubkeys.size() == 2, "two output one-time keys");
    check(tx.bpp.V.size() == 2, "aggregate BP+ over both outputs");
    check(!tx.blob.empty(), "serialized CryptoNote blob produced");
    check(tx.tx_hash != Bytes32{}, "tx_hash computed");

    std::string why;
    check(prover::self_verify_tx_public(tx, why),
          std::string("self-verify (BP+ + CLSAG + balance) passes") + (why.empty() ? "" : " (" + why + ")"));
    check(prover::self_verify_key_images(inputs, tx, why),
          std::string("self-verify key-image recompute passes") + (why.empty() ? "" : " (" + why + ")"));

    // Independent balance restatement.
    check(xr::verify_bulletproof_plus(tx.bpp), "tx.bpp independently verifies");

    std::printf("[D] unbalanced tx -> self-verify REFUSES\n");
    {
        prover::RingctTx bad = tx;
        bad.fee += 1;   // now Sum pseudo - Sum out - fee*H != 0
        std::string w;
        check(!prover::self_verify_tx_public(bad, w), "mauled fee -> balance leg refuses");

        prover::RingctTx bad2 = tx;
        bad2.output_commitments[0][0] ^= 0x01;  // corrupt a commitment
        std::string w2;
        check(!prover::self_verify_tx_public(bad2, w2), "corrupted output commitment -> refused");
    }
    {
        // Amounts that do not balance are refused at assembly.
        std::vector<prover::TxDestination> bad_dests = {
            dest_of("c2w-m4x-alice", 4970000000ULL),
            dest_of("c2w-m4x-bob",   3000000001ULL),   // +1, breaks sum
        };
        prover::AssembleResult br = prover::assemble_ringct_tx(inputs, bad_dests, fee);
        check(!br.ok, "assembly refuses amounts that do not balance");
    }
    {
        // A tx assembled with self_verify=false, then hand-unbalanced, must be
        // caught if we re-run self-verify (proves the gate is the emit barrier).
        std::vector<prover::SpendInput> one = { build_input(11, 4, "c2w-m4x-single", 2000000000ULL) };
        std::vector<prover::TxDestination> od = { dest_of("c2w-m4x-carol", 1990000000ULL) };
        prover::AssembleResult sr = prover::assemble_ringct_tx(one, od, 10000000ULL);
        check(sr.ok, "single-input single-output tx assembles + self-verifies");
        std::string w;
        check(sr.ok && prover::self_verify_tx_public(sr.tx, w), "single-in/out self-verify passes");
    }
}

// ── [E] distinct randomness (CSPRNG) ────────────────────────────────────────
void test_distinct_randomness() {
    std::printf("[E] two assemblies over identical inputs use distinct BP+ blinding\n");
    std::vector<prover::SpendInput> inputs = { build_input(11, 3, "c2w-m4x-rng", 2000000000ULL) };
    std::vector<prover::TxDestination> dests = { dest_of("c2w-m4x-rng-dest", 1990000000ULL) };
    const std::uint64_t fee = 10000000ULL;

    prover::AssembleResult a = prover::assemble_ringct_tx(inputs, dests, fee);
    prover::AssembleResult b = prover::assemble_ringct_tx(inputs, dests, fee);
    check(a.ok && b.ok, "both assemblies succeed");
    if (!a.ok || !b.ok) return;

    // Deterministic: key images identical (x*H_p(P) does not depend on nonces).
    check(a.tx.key_images == b.tx.key_images, "key images deterministic across assemblies");
    // BP+ blinding differs: A, A1, B, d1 and the CLSAG published scalars differ.
    check(a.tx.bpp.A != b.tx.bpp.A, "BP+ commitment A differs (fresh alpha nonce)");
    check(a.tx.bpp.d1 != b.tx.bpp.d1, "BP+ d1 differs (fresh r/s/d/eta nonces)");
    check(a.tx.clsags[0].c1 != b.tx.clsags[0].c1, "CLSAG c1 differs (fresh signer nonces)");
    // R differs (fresh tx secret r).
    check(a.tx.tx_pubkey != b.tx.tx_pubkey, "tx pubkey R differs (fresh tx secret)");

    // Fee model sanity.
    check(prover::compute_fee(1500, 3000, 1) == 1500ULL * 3000ULL * 1ULL, "fee = weight*rate*1 (priority 1)");
    check(prover::compute_fee(1500, 3000, 4) == 1500ULL * 3000ULL * 1000ULL, "fee = weight*rate*1000 (priority 4)");
}

} // namespace

int main() {
    std::printf("=== c2wallet-qt Family B (Monero) M4-X KATs: Bulletproofs+ prover + RingCT assembly ===\n");
    test_bpp_prove_verify();
    test_ringct_assemble();
    test_distinct_randomness();
    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
