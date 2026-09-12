// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// Known-answer tests for the Family B (Monero) output-scanning path (§4.2).
//
// TWO layers of pinning, both non-circular:
//
//  (1) PRIMITIVE ANCHORS -- every operation §4.2 needs is pinned byte-for-byte
//      to monero-project/monero  tests/crypto/tests.txt (the daemon's own crypto
//      KAT corpus):
//        A1 generate_key_derivation   D = 8*sec*pub
//        A2 derive_public_key         P = H_s(D||i)*G + base            (x2)
//        A3 derive_view_tag           first byte of H("view_tag"||D||i)
//        A4 derive_secret_key         x = H_s(D||i) + base_sec          (the one-time secret)
//        A5 generate_key_image        I = x * H_p(P)
//
//  (2) COHERENT SCAN VECTOR -- an end-to-end sender->scanner round-trip whose
//      RECIPIENT key pair (k_v, k_s) is the published monero-rs doctest keypair
//      (monero-rs/monero-rs src/blockdata/transaction.rs). The sender path
//      (D = 8*r*A, P = H_s(D||i)*G+K_s, ecdh amount encode) and the scanner path
//      (D = 8*k_v*R, ownership via the subaddress table, ecdh amount decode) are
//      INDEPENDENT computations that must agree because r*A == k_v*R. This proves
//      ownership detection, amount decrypt, subaddress detection, and the
//      view-only / full-wallet key-image split.
//
// The scanner does not sign and touches no network; this is the read path.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>
#include <string>

#include "family/monero/MoneroCrypto.hpp"
#include "family/monero/MoneroKey.hpp"
#include "family/monero/addr/MoneroAddress.hpp"
#include "family/monero/scan/MoneroScanOps.hpp"
#include "family/monero/scan/MoneroScanner.hpp"

using namespace c2wallet::monero;

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

// ── (1) primitive anchors: monero-project tests/crypto/tests.txt ────────────

void test_primitive_anchors() {
    std::printf("[A] primitive anchors -- monero-project tests/crypto/tests.txt\n");

    // A1 generate_key_derivation <pub> <sec> true <derivation>
    Bytes32 D{};
    bool ok = scanops::key_derivation(
        hx("fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984"),
        hx("eb2bd1cf0c5e074f9dbf38ebbc99c316f54e21803048c687a3bb359f7a713b02"), D);
    check(ok, "A1 generate_key_derivation returns true");
    eq_hex(D, "4e0bd2c41325a1b89a9f7413d4d05e0a5a4936f241dccc3c7d0c539ffe00ef67",
           "A1 D = 8*sec*pub");

    // A2 derive_public_key <derivation> <index> <base> true <result>
    Bytes32 P{};
    scanops::derive_public_key(
        hx("ca780b065e48091d910de90bcab2411db3d1a845e6d95cfd556af4138504c737"),
        217407,
        hx("6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39"), P);
    eq_hex(P, "d48008aff5f27d8fcdc2a3bf814ed3505530f598075f3bf7e868fea696b109f6",
           "A2a derive_public_key (index 217407)");
    scanops::derive_public_key(
        hx("13bb0039172efee53059c7a973dc5f6f3c0a07611ebb0f5609cd833d5d25846c"),
        1,
        hx("5ca5429e836cd4172b7427ca8dc639f39c299f1b8e0d00f9d3f9a5bb2e49251a"), P);
    eq_hex(P, "52e0a76a5785d12737dba717fd6c90e0e7d7a1a6c758543758abe578793c7a52",
           "A2b derive_public_key (index 1)");

    // A3 derive_view_tag <derivation> 0 <tag>
    std::uint8_t vt = scanops::view_tag(
        hx("0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97"), 0);
    check(vt == 0x76, "A3 derive_view_tag first byte == 0x76");

    // A4 derive_secret_key <derivation> 66 <base_sec> <result>  (the one-time secret x)
    Bytes32 x = scanops::derive_secret_key(
        hx("0fc47054f355ced4d67de73bfa12e4c78ff19089548fffa7d07a674741860f97"), 66,
        hx("5619c62aa4ad787274b1071598b6ecacf4f9dacca2fd11b0c80741b744400500"));
    eq_hex(x, "55297d64b0c0556d5583ce0e30c2024ccce90c93d16bdeb4e40fce7afff87803",
           "A4 derive_secret_key x = H_s(D||i)+k_s");

    // A5 generate_key_image <pub> <sec> <image>
    Bytes32 I{};
    ok = scanops::generate_key_image(
        hx("e46b60ebfe610b8ba761032018471e5719bb77ea1cd945475c4a4abe7224bfd0"),
        hx("981d477fb18897fa1f784c89721a9d600bf283f06b89cb018a077f41dcefef0f"), I);
    check(ok, "A5 generate_key_image returns true");
    eq_hex(I, "a637203ec41eab772532d30420eac80612fce8e44f1758bc7e2cb1bdda815887",
           "A5 I = x * H_p(P)");
}

// ── (2) coherent scan vector: monero-rs recipient keypair ───────────────────

// monero-rs/monero-rs src/blockdata/transaction.rs doctest keypair.
const char* RS_VIEW  = "bcfdda53205318e1c14fa0ddca1a45df363bb427972981d0249d0f4652a7df07";
const char* RS_SPEND = "e5f4301d32f3bdaef814a835a18aaaa24b13cc76cf01a832a7852faf9322e907";

// Build a full account (spend+view) from the raw scalars.
MoneroKeys full_account() {
    MoneroKeys k;
    k.has_spend_priv = true;
    k.spend_priv = hx(RS_SPEND);
    k.view_priv  = hx(RS_VIEW);
    mcrypto::secret_to_public(k.spend_priv, k.spend_pub);
    mcrypto::secret_to_public(k.view_priv,  k.view_pub);
    return k;
}

// A deterministic, canonical tx secret r for the constructed vector.
Bytes32 tx_secret() {
    const char* seed = "c2wallet-qt-m2x-scan-kat-tx-secret";
    return mcrypto::reduce32(
        mcrypto::keccak256(reinterpret_cast<const std::uint8_t*>(seed),
                           std::strlen(seed)));
}

void test_scan_standard_owned_and_amount() {
    std::printf("[B] construct->scan: standard-address owned output + amount\n");
    MoneroKeys acc = full_account();

    // --- SENDER (independent path): craft one output paying acc's primary addr.
    Bytes32 r = tx_secret();
    Bytes32 R{};  mcrypto::secret_to_public(r, R);             // R = r*G (tx pubkey)
    Bytes32 D_send{};
    scanops::key_derivation(acc.view_pub, r, D_send);          // D = 8*r*A
    const std::size_t i = 0;
    Bytes32 P{};
    scanops::derive_public_key(D_send, i, acc.spend_pub, P);   // P = H_s(D||i)*G + K_s
    const std::uint64_t sent = 3141592653589ULL;               // piconero
    Bytes32 shared_send = scanops::derivation_to_scalar(D_send, i);
    auto ecdh = scanops::ecdh_encode_amount(sent, shared_send);
    std::uint8_t vt = scanops::view_tag(D_send, i);

    std::printf("       vector R  = %s\n", bytes32_to_hex(R).c_str());
    std::printf("       vector P0 = %s\n", bytes32_to_hex(P).c_str());
    std::printf("       vector amt= %llu piconero\n", (unsigned long long)sent);

    TxToScan tx;
    tx.tx_pubkeys.push_back(R);
    EnoteToScan e; e.one_time_pub = P; e.has_view_tag = true; e.view_tag = vt;
    e.is_rct = true; e.ecdh_amount = ecdh;
    tx.outputs.push_back(e);

    // --- SCANNER (full wallet).
    MoneroScanner full(acc);
    ScanResult r1 = full.scan_transaction(tx);
    check(r1.owned.size() == 1, "standard output detected as owned");
    if (!r1.owned.empty()) {
        const OwnedOutput& o = r1.owned[0];
        check(o.subaddr == (SubaddressIndex{0, 0}), "detected at primary index (0,0)");
        check(o.amount == sent, "amount decrypted correctly (two Keccak + xor)");
        check(o.has_key_image, "full wallet computed a key image");
        // The key image must equal the authoritative recipe I = x*H_p(P) with
        // x = H_s(D||i)+k_s -- recompute independently here.
        Bytes32 x = scanops::derive_secret_key(D_send, i, acc.spend_priv);
        Bytes32 I_expect{}; scanops::generate_key_image(P, x, I_expect);
        eq_hex(o.key_image, bytes32_to_hex(I_expect), "key image matches x*H_p(P)");
        // And x*G must reproduce the one-time public key.
        Bytes32 xG{}; mcrypto::secret_to_public(x, xG);
        check(xG == P, "x*G reproduces P (one-time secret is consistent)");
    }
    check(full.balance() == sent, "balance == sum of owned amounts");
}

void test_view_tag_and_non_owned() {
    std::printf("[C] view-tag fast-reject + non-owned output not detected\n");
    MoneroKeys acc = full_account();
    Bytes32 r = tx_secret();
    Bytes32 R{};  mcrypto::secret_to_public(r, R);
    Bytes32 D_send{}; scanops::key_derivation(acc.view_pub, r, D_send);
    Bytes32 P{}; scanops::derive_public_key(D_send, 0, acc.spend_pub, P);

    // Corrupt the view tag -> must be fast-rejected, not owned.
    {
        TxToScan tx; tx.tx_pubkeys.push_back(R);
        EnoteToScan e; e.one_time_pub = P; e.has_view_tag = true;
        e.view_tag = static_cast<std::uint8_t>(scanops::view_tag(D_send, 0) ^ 0xff);
        e.is_rct = true;
        tx.outputs.push_back(e);
        MoneroScanner s(acc);
        ScanResult res = s.scan_transaction(tx);
        check(res.owned.empty(), "wrong view tag -> not owned");
        check(res.view_tag_rejected == 1, "view-tag mismatch counted as fast-reject");
    }

    // An output paying a DIFFERENT account must not be detected as ours.
    {
        MoneroKeys other = full_account();
        // Flip the spend key to a different (still canonical) scalar.
        other.spend_priv = mcrypto::reduce32(
            scanops::commitment_mask(acc.spend_priv)); // arbitrary distinct scalar
        mcrypto::secret_to_public(other.spend_priv, other.spend_pub);
        Bytes32 Po{}; scanops::derive_public_key(D_send, 0, other.spend_pub, Po);
        check(!(Po == P), "different account yields a different one-time key");

        TxToScan tx; tx.tx_pubkeys.push_back(R);
        EnoteToScan e; e.one_time_pub = Po; e.has_view_tag = false; e.is_rct = true;
        tx.outputs.push_back(e);
        MoneroScanner s(acc);
        ScanResult res = s.scan_transaction(tx);
        check(res.owned.empty(), "non-owned output not detected");
    }
}

void test_subaddress_scan() {
    std::printf("[D] subaddress-received output detected via the precomputed table\n");
    MoneroKeys acc = full_account();
    const std::uint32_t major = 1, minor = 3;

    // Recipient subaddress (1,3): S = K_s + m*G, V = k_v*S.
    SubaddressResult sub = derive_subaddress(acc.view_priv, acc.spend_pub, major, minor);
    check(sub.ok, "subaddress (1,3) derives");

    // SENDER to a subaddress: additional tx pubkey R_i = r * S ; D = 8*r*V.
    Bytes32 r = tx_secret();
    Bytes32 Ri{}; mcrypto::point_scalarmult(r, sub.sub_spend_pub, Ri);
    Bytes32 D_send{}; scanops::key_derivation(sub.sub_view_pub, r, D_send);
    const std::size_t i = 0;
    Bytes32 P{}; scanops::derive_public_key(D_send, i, sub.sub_spend_pub, P);
    const std::uint64_t sent = 777000000ULL;
    Bytes32 shared = scanops::derivation_to_scalar(D_send, i);
    auto ecdh = scanops::ecdh_encode_amount(sent, shared);

    TxToScan tx;
    tx.tx_pubkeys.push_back(Ri);            // main slot (unused once additional present)
    tx.additional_pubkeys.push_back(Ri);    // per-output additional key
    EnoteToScan e; e.one_time_pub = P; e.has_view_tag = true;
    e.view_tag = scanops::view_tag(D_send, i); e.is_rct = true; e.ecdh_amount = ecdh;
    tx.outputs.push_back(e);

    // A scanner whose table does NOT cover (1,3) must miss it...
    MoneroScanner narrow(acc);   // default table (1,1) = primary only
    check(narrow.scan_transaction(tx).owned.empty(), "primary-only table misses subaddress");

    // ...and one built over a grid covering (1,3) detects it.
    MoneroScanner wide(acc);
    wide.build_subaddress_table(2, 4);   // major 0..1, minor 0..3
    ScanResult res = wide.scan_transaction(tx);
    check(res.owned.size() == 1, "subaddress output detected via table");
    if (!res.owned.empty()) {
        check(res.owned[0].subaddr == (SubaddressIndex{major, minor}),
              "detected at the correct (major,minor)");
        check(res.owned[0].amount == sent, "subaddress amount decrypted");
        check(res.owned[0].has_key_image, "subaddress key image computed (full wallet)");
        // Subaddress one-time secret x = H_s(D||i)+k_s+m ; verify x*G == P.
        Bytes32 x = scanops::derive_secret_key(D_send, i, acc.spend_priv);
        x = mcrypto::scalar_add(x, sub.m);
        Bytes32 xG{}; mcrypto::secret_to_public(x, xG);
        check(xG == P, "subaddress x = H_s(D||i)+k_s+m reproduces P");
    }
}

void test_view_only_cannot_make_key_image() {
    std::printf("[E] view-only split: ownership+amount YES, key image NO\n");
    MoneroKeys acc = full_account();
    Bytes32 r = tx_secret();
    Bytes32 R{}; mcrypto::secret_to_public(r, R);
    Bytes32 D_send{}; scanops::key_derivation(acc.view_pub, r, D_send);
    Bytes32 P{}; scanops::derive_public_key(D_send, 0, acc.spend_pub, P);
    const std::uint64_t sent = 42000000ULL;
    auto ecdh = scanops::ecdh_encode_amount(sent, scanops::derivation_to_scalar(D_send, 0));

    TxToScan tx; tx.tx_pubkeys.push_back(R);
    EnoteToScan e; e.one_time_pub = P; e.has_view_tag = true;
    e.view_tag = scanops::view_tag(D_send, 0); e.is_rct = true; e.ecdh_amount = ecdh;
    tx.outputs.push_back(e);

    // View-only account: private view key + PUBLIC spend key, no spend secret.
    MoneroKeys vo;
    vo.has_spend_priv = false;
    vo.view_priv = acc.view_priv;
    vo.spend_pub = acc.spend_pub;
    vo.view_pub  = acc.view_pub;

    MoneroScanner view_only(vo);
    check(!view_only.can_produce_key_images(), "view-only reports it cannot make key images");
    ScanResult res = view_only.scan_transaction(tx);
    check(res.owned.size() == 1, "view-only detects ownership");
    if (!res.owned.empty()) {
        check(res.owned[0].amount == sent, "view-only decrypts the amount");
        check(!res.owned[0].has_key_image, "view-only produced NO key image (air-gap split)");
        check(res.owned[0].key_image == Bytes32{}, "view-only key image is empty");
    }
    // The export-outputs artifact carries no secrets and no key image.
    auto exp = view_only.export_outputs();
    check(exp.size() == 1, "export-outputs artifact has the owned output");
    if (!exp.empty()) {
        check(exp[0].one_time_pub == P, "exported P_i matches");
        check(exp[0].amount == sent, "exported amount matches");
    }

    // The SAME tx scanned by the full wallet DOES yield a key image -- the offline
    // side of the split. Prove the two differ exactly in the key-image field.
    MoneroScanner full(acc);
    ScanResult fr = full.scan_transaction(tx);
    check(!fr.owned.empty() && fr.owned[0].has_key_image,
          "full wallet computes the key image for the identical output");
}

void test_ecdh_roundtrip() {
    std::printf("[F] ecdh amount encode/decode is an exact inverse\n");
    Bytes32 shared = tx_secret();
    for (std::uint64_t a : {0ULL, 1ULL, 12345678ULL, 0xFFFFFFFFFFFFFFFFULL}) {
        auto enc = scanops::ecdh_encode_amount(a, shared);
        std::uint64_t dec = scanops::ecdh_decode_amount(enc, shared);
        check(dec == a, "decode(encode(a)) == a");
    }
    // A wrong shared secret must not recover the amount.
    auto enc = scanops::ecdh_encode_amount(999ULL, shared);
    Bytes32 wrong = scanops::commitment_mask(shared);
    check(scanops::ecdh_decode_amount(enc, wrong) != 999ULL, "wrong shared secret fails to decode");
}

} // namespace

int main() {
    std::printf("=== c2wallet-qt Family B (Monero) output-scanning KATs ===\n\n");
    test_primitive_anchors();
    test_scan_standard_owned_and_amount();
    test_view_tag_and_non_owned();
    test_subaddress_scan();
    test_view_only_cannot_make_key_image();
    test_ecdh_roundtrip();
    std::printf("\n=== %d checks, %d failures ===\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
