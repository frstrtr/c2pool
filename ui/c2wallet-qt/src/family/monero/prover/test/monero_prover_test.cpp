// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// Known-answer tests for the Family B (Monero) prover: key-image export and
// the CLSAG signer (design §4.2 steps 5-6).
//
// Money-correctness oracles, all non-circular:
//
//  [A] KEY-IMAGE BYTE ANCHOR -- I = x*H_p(P) pinned byte-for-byte to
//      monero-project/monero tests/crypto/tests.txt generate_key_image, and
//      confirmed to lie in the prime-order subgroup (monerod's key-image
//      domain check, the one CLSAG-adjacent check c2pool DOES have in-tree).
//
//  [B] KEY-IMAGE EXPORT ROUND-TRIP -- construct an owned output, export the
//      {I, ring-signature} artifact a full wallet hands the online side, and
//      verify it; tampering with the image or the signature must be rejected.
//
//  [C] VIEW-ONLY SPLIT -- a view-only wallet (no spend secret) cannot export a
//      key image at all. Structural, carried over from the M2-X scanner.
//
//  [D] CLSAG CONSTRUCT -> VERIFY -- the strong harness design §4.2 calls for:
//      build a CLSAG signature over a ring (real member + decoys) and verify
//      it with the ported verifier; the key image inside it matches x*H_p(P)
//      and is in the subgroup.
//
//  [E] CLSAG TAMPER -> REJECT -- wrong message, a corrupted ring member, a
//      mauled signature scalar, an unbalanced pseudo-output, and signing with
//      the wrong secret all make the verifier reject.
//
// There is no in-tree CLSAG verifier (verifying CLSAG needs the chain's ring
// members), so the oracle is the ported verifier, exactly as §4.2 specifies.
// Bulletproofs+ and full RingCT tx assembly are M4-X and are not exercised here.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>
#include <string>

#include "family/monero/MoneroCrypto.hpp"
#include "family/monero/MoneroKey.hpp"
#include "family/monero/scan/MoneroScanOps.hpp"
#include "family/monero/scan/MoneroScanner.hpp"
#include "family/monero/prover/MoneroClsag.hpp"
#include "family/monero/prover/MoneroKeyImage.hpp"
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

void eq_hex(const Bytes32& got, const std::string& want, const std::string& what) {
    std::string g = bytes32_to_hex(got);
    ++g_checks;
    if (g == want) {
        std::printf("  ok   : %s\n", what.c_str());
    } else {
        std::printf("  FAIL : %s\n         got : %s\n         want: %s\n",
                    what.c_str(), g.c_str(), want.c_str());
        ++g_failures;
    }
}

Bytes32 hx(const char* h) { Bytes32 b{}; hex_to_bytes32(h, b); return b; }

// A deterministic canonical scalar from a label (reduced mod l).
Bytes32 scalar_of(const char* label) {
    return mcrypto::reduce32(mcrypto::keccak256(
        reinterpret_cast<const std::uint8_t*>(label), std::strlen(label)));
}

// monero-rs/monero-rs doctest recipient keypair (same as the M2-X scan KAT).
const char* RS_VIEW  = "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07";
const char* RS_SPEND = "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907";

MoneroKeys full_account() {
    MoneroKeys k;
    k.has_spend_priv = true;
    k.spend_priv = hx(RS_SPEND);
    k.view_priv  = hx(RS_VIEW);
    mcrypto::secret_to_public(k.spend_priv, k.spend_pub);
    mcrypto::secret_to_public(k.view_priv,  k.view_pub);
    return k;
}

// ── [A] key-image byte anchor: monero tests/crypto/tests.txt ────────────────
void test_key_image_anchor() {
    std::printf("[A] key-image byte anchor -- monero tests/crypto/tests.txt generate_key_image\n");
    // generate_key_image <pub> <sec> <image>
    Bytes32 I{};
    bool ok = scanops::generate_key_image(
        hx("e46b60ebfe610b8ba761032018471e5719bb77ea1cd945475c4a4abe7224bfd0"),
        hx("981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f"), I);
    check(ok, "generate_key_image returns true");
    eq_hex(I, "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887",
           "I = x*H_p(P) byte-exact to monero vector");
    check(xr::in_main_subgroup(I), "key image is in the prime-order subgroup (domain check)");
}

// Build a coherent owned output paying the account's primary address, scan it,
// and return the ExportedOutput plus the one-time secret x for cross-checks.
struct BuiltOutput {
    ExportedOutput exp;
    Bytes32        one_time_pub{};
    Bytes32        one_time_sec{};   // x_i (for KAT cross-checks only)
    std::uint64_t  amount{0};
};

BuiltOutput build_owned_output(const MoneroKeys& acc, const char* r_label,
                               std::uint64_t amount, std::size_t i) {
    BuiltOutput b;
    Bytes32 r = scalar_of(r_label);
    Bytes32 R{}; mcrypto::secret_to_public(r, R);
    Bytes32 D{}; scanops::key_derivation(acc.view_pub, r, D);
    Bytes32 P{}; scanops::derive_public_key(D, i, acc.spend_pub, P);
    b.one_time_pub = P;
    b.one_time_sec = scanops::derive_secret_key(D, i, acc.spend_priv);
    b.amount = amount;
    b.exp.one_time_pub = P;
    b.exp.tx_pubkey    = R;
    b.exp.output_index = i;
    b.exp.subaddr      = SubaddressIndex{0, 0};
    b.exp.amount       = amount;
    return b;
}

// ── [B] key-image export round-trip ─────────────────────────────────────────
void test_key_image_export_roundtrip() {
    std::printf("[B] key-image export {I, ring-sig} -> verify; tamper -> reject\n");
    MoneroKeys acc = full_account();
    BuiltOutput b = build_owned_output(acc, "c2w-m3x-ki-export-r", 3141592653589ULL, 0);

    std::vector<ExportedOutput> outs{b.exp};
    prover::KeyImageExportResult r = prover::export_key_images(acc, outs);
    check(r.ok, "full wallet exports key images");
    check(r.images.size() == 1, "one key image exported");
    if (!r.images.empty()) {
        const prover::ExportedKeyImage& e = r.images[0];
        // Cross-check the exported image against the independent recipe.
        Bytes32 I_expect{}; scanops::generate_key_image(b.one_time_pub, b.one_time_sec, I_expect);
        eq_hex(e.image, bytes32_to_hex(I_expect), "exported I == x*H_p(P)");
        check(prover::check_exported_key_image(e), "ring signature over {P} verifies");

        // Tamper 1: flip a bit of the image -> reject.
        prover::ExportedKeyImage bad_img = e;
        bad_img.image[0] ^= 0x01;
        check(!prover::check_exported_key_image(bad_img), "flipped image -> rejected");

        // Tamper 2: maul the signature -> reject.
        prover::ExportedKeyImage bad_sig = e;
        bad_sig.signature[0] ^= 0x01;
        check(!prover::check_exported_key_image(bad_sig), "mauled signature -> rejected");

        // Tamper 3: wrong output pubkey -> reject.
        prover::ExportedKeyImage bad_pub = e;
        bad_pub.one_time_pub[0] ^= 0x01;
        check(!prover::check_exported_key_image(bad_pub), "wrong one-time pubkey -> rejected");
    }
}

// ── [C] view-only split ─────────────────────────────────────────────────────
void test_view_only_cannot_export() {
    std::printf("[C] view-only wallet cannot produce a key image (structural)\n");
    MoneroKeys acc = full_account();
    BuiltOutput b = build_owned_output(acc, "c2w-m3x-ki-vo-r", 42000000ULL, 0);

    // A view-only import: public spend key + private view key, no spend secret.
    KeyImportResult vo = keys_view_only(bytes32_to_hex(acc.spend_pub),
                                        bytes32_to_hex(acc.view_priv));
    check(vo.ok, "view-only import succeeds");
    check(!vo.keys.can_sign(), "view-only wallet reports can_sign()==false");

    std::vector<ExportedOutput> outs{b.exp};
    prover::KeyImageExportResult r = prover::export_key_images(vo.keys, outs);
    check(!r.ok, "view-only export_key_images refuses");
    check(!r.error.empty(), "refusal carries an explanation");

    // And the M2-X scanner agrees the split is structural.
    MoneroScanner vo_scan(vo.keys);
    check(!vo_scan.can_produce_key_images(), "view-only scanner cannot produce key images");
    MoneroScanner full_scan(acc);
    check(full_scan.can_produce_key_images(), "full-wallet scanner can produce key images");
}

// Build a CLSAG ring of `n` members with the real member at index `l`.
// Real member: P=p*G, C=commit(amount, c_a). pseudoOut Cout=commit(amount, c_out).
void build_ring(std::size_t n, std::size_t l, const Bytes32& p, std::uint64_t amount,
                const Bytes32& c_a, const Bytes32& c_out,
                std::vector<prover::CtKey>& ring, Bytes32& Cout) {
    ring.assign(n, prover::CtKey{});
    Cout = prover::commit(amount, c_out);
    for (std::size_t i = 0; i < n; ++i) {
        if (i == l) {
            mcrypto::secret_to_public(p, ring[i].dest);      // P = p*G
            ring[i].mask = prover::commit(amount, c_a);      // C = commit(a, c_a)
        } else {
            char lbl[64];
            std::snprintf(lbl, sizeof(lbl), "c2w-m3x-decoy-dest-%zu", i);
            Bytes32 ds = scalar_of(lbl);
            mcrypto::secret_to_public(ds, ring[i].dest);
            std::snprintf(lbl, sizeof(lbl), "c2w-m3x-decoy-mask-%zu", i);
            Bytes32 dm = scalar_of(lbl);
            ring[i].mask = prover::commit(1000 + i, dm);     // arbitrary decoy commitment
        }
    }
}

// ── [D] CLSAG construct -> verify ───────────────────────────────────────────
void test_clsag_roundtrip() {
    std::printf("[D] CLSAG construct -> in-tree-ported verify (ring size 11)\n");
    const std::size_t n = 11, l = 6;
    const std::uint64_t amount = 2718281828ULL;
    const Bytes32 p     = scalar_of("c2w-m3x-clsag-onetime-secret");
    const Bytes32 c_a   = scalar_of("c2w-m3x-clsag-real-mask");
    const Bytes32 c_out = scalar_of("c2w-m3x-clsag-pseudo-mask");
    const Bytes32 msg   = mcrypto::keccak256(
        reinterpret_cast<const std::uint8_t*>("c2w-m3x tx signing message"), 26);

    std::vector<prover::CtKey> ring; Bytes32 Cout{};
    build_ring(n, l, p, amount, c_a, c_out, ring, Cout);

    prover::Clsag sig;
    bool signed_ok = prover::clsag_prove_simple(msg, ring, p, c_a, c_out, Cout, l, sig);
    check(signed_ok, "clsag_prove_simple succeeds");
    check(sig.s.size() == n, "signature has one scalar per ring member");

    check(prover::clsag_verify(msg, sig, ring, Cout), "CLSAG verifies (construct->verify)");

    // The key image in the signature is exactly x*H_p(P) and in the subgroup.
    Bytes32 I_expect{}; scanops::generate_key_image(ring[l].dest, p, I_expect);
    eq_hex(sig.I, bytes32_to_hex(I_expect), "sig.I == p*H_p(P_l)");
    check(xr::in_main_subgroup(sig.I), "sig.I is in the prime-order subgroup");
}

// ── [E] CLSAG tamper -> reject ──────────────────────────────────────────────
void test_clsag_tamper() {
    std::printf("[E] CLSAG tamper -> verifier rejects\n");
    const std::size_t n = 8, l = 3;
    const std::uint64_t amount = 999999ULL;
    const Bytes32 p     = scalar_of("c2w-m3x-clsag2-onetime-secret");
    const Bytes32 c_a   = scalar_of("c2w-m3x-clsag2-real-mask");
    const Bytes32 c_out = scalar_of("c2w-m3x-clsag2-pseudo-mask");
    const Bytes32 msg   = mcrypto::keccak256(
        reinterpret_cast<const std::uint8_t*>("c2w-m3x message two"), 19);

    std::vector<prover::CtKey> ring; Bytes32 Cout{};
    build_ring(n, l, p, amount, c_a, c_out, ring, Cout);

    prover::Clsag sig;
    check(prover::clsag_prove_simple(msg, ring, p, c_a, c_out, Cout, l, sig),
          "baseline signature produced");
    check(prover::clsag_verify(msg, sig, ring, Cout), "baseline verifies");

    // T1: wrong message.
    Bytes32 wrong_msg = msg; wrong_msg[0] ^= 0x01;
    check(!prover::clsag_verify(wrong_msg, sig, ring, Cout), "wrong message -> rejected");

    // T2: corrupted ring member (swap a decoy dest for another point).
    {
        std::vector<prover::CtKey> bad_ring = ring;
        mcrypto::secret_to_public(scalar_of("c2w-m3x-intruder"), bad_ring[0].dest);
        check(!prover::clsag_verify(msg, sig, bad_ring, Cout), "wrong ring member -> rejected");
    }

    // T3: mauled signature scalar.
    {
        prover::Clsag bad = sig;
        bad.s[0][0] ^= 0x01;
        check(!prover::clsag_verify(msg, bad, ring, Cout), "mauled s[0] -> rejected");
    }

    // T4: unbalanced pseudo-output (commits to a different amount).
    {
        Bytes32 bad_Cout = prover::commit(amount + 1, c_out);
        prover::Clsag s2;
        // Signing with a mismatched pseudo-output: C[l] != z*G, so verify must fail.
        prover::clsag_prove_simple(msg, ring, p, c_a, c_out, bad_Cout, l, s2);
        check(!prover::clsag_verify(msg, s2, ring, bad_Cout), "unbalanced pseudo-output -> rejected");
    }

    // T5: signing with the wrong one-time secret (does not match P[l]).
    {
        Bytes32 wrong_p = scalar_of("c2w-m3x-not-the-secret");
        prover::Clsag s3;
        prover::clsag_prove_simple(msg, ring, wrong_p, c_a, c_out, Cout, l, s3);
        check(!prover::clsag_verify(msg, s3, ring, Cout), "wrong one-time secret -> rejected");
    }
}

} // namespace

int main() {
    std::printf("=== c2wallet-qt Family B (Monero) prover KATs: key image + CLSAG ===\n");
    test_key_image_anchor();
    test_key_image_export_roundtrip();
    test_view_only_cannot_export();
    test_clsag_roundtrip();
    test_clsag_tamper();
    std::printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
