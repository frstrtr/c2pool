// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_coinbase_kat.cpp  --  X6 KAT: OWED -> miner_tx executor
//                                             (Family B: Monero / RandomX lane)
//
// Known-Answer Tests for the W5-XMR coinbase settlement executor
// (../settle/xmr_coinbase.{hpp,cpp}). This is the consensus-adjacent leg: it
// turns a finality-gated OWED ledger for one Monero parent into the canonical
// miner_tx every v37 node re-derives byte-for-byte. A wrong derivation pays the
// wrong wallet; a wrong sum is an HF13 CONSENSUS FAILURE (Bitcoin's burn-the-
// remainder is invalid on Monero). So each property below is consensus-critical
// and pinned here against REAL Monero crypto (the ../coin xmr_coin library:
// vendored ed25519 ge_*, keccak) and OFFICIAL monero-project vectors.
//
// Cases (each reported PASS/FAIL, nonzero exit on any failure):
//   1. deterministic-r reproducibility  -- same inputs => same r, same R, same
//      P_i set; a changed lane_commitment or prev_id => a different r (so a
//      different owed set / Monero parent forces a fresh coinbase, p2pool style).
//   2. R = r*G                          -- build.R == secret_key_to_public_key(r),
//      AND secret_key_to_public_key anchored to an OFFICIAL monero generate_keys
//      (sec,pub) vector.
//   3. stealth key vs known Monero vector -- generate_key_derivation and
//      derive_public_key byte-match monero-project tests/crypto/tests.txt, and
//      the coinbase's per-vout one-time keys reproduce independently by the same
//      ECDH recipe P_i = derive_public_key(8 r A, i, B).
//   4. exact-sum, no burn               -- Sum(vout) == base_reward + fees to the
//      piconero across surplus/deficit/fixed shapes, residual sink included.
//   5. weight-aware output cap          -- wire cap binds; penalty headroom binds;
//      floor of 1 (always room for the sink).
//   6. CARROT fence                     -- major_version 17 => CarrotFence error,
//      NO coinbase built, and derive_tx_secret_key refuses; 16 builds.
//
// VECTOR PROVENANCE: the input->output crypto vectors are the OFFICIAL Monero
// consensus test vectors from monero-project tests/crypto/tests.txt
// (generate_key_derivation / derive_public_key / generate_keys). Each is cited
// inline. No third-party code is copied into this file.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Executor under test (settle leg) + its coin-layer + descriptor consumers.
#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "impl/xmr/coin/xmr_derivation.hpp"   // generate_key_derivation / derive_* / r*G

using namespace v37::xmr::settle;

namespace {

int g_fail = 0;
#define CHECK(cond, ...) do { \
    bool _ok = (cond); \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    if (!_ok) ++g_fail; \
} while (0)

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> o; o.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}
std::string hex(const unsigned char* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
template <class T> T key_from_hex(const std::string& h) {
    T t{}; auto v = unhex(h);
    std::memcpy(t.data(), v.data(), v.size() < 32 ? v.size() : 32);
    return t;
}
template <class T> std::string hx(const T& t) { return hex(t.data(), 32); }

// ---- OFFICIAL monero-project tests/crypto/tests.txt vectors ---------------
// generate_key_derivation <pub A> <sec r> true <derivation D>   (D = 8*r*A)
const char* kA_hex = "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984";
const char* kr_hex = "eb2bd1cf0c5e074f9dbf38ebbc99c316f54e21803048c687a3bb359f7a713b02";
const char* kD_hex = "4e0bd2c41325a1b89a9f7413d4d05e0a5a4936f241dccc3c7d0c539ffe00ef67";
// derive_public_key <derivation D> <output_index i> <base B> true <derived P>
const char* kDPK_D_hex = "ca780b065e48091d910de90bcab2411db3d1a845e6d95cfd556af4138504c737";
const std::uint64_t kDPK_i = 217407;
const char* kDPK_B_hex = "6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39";
const char* kDPK_P_hex = "d48008aff5f27d8fcdc2a3bf814ed3505530f598075f3bf7e868fea696b109f6";
// generate_keys <pub> <sec>   (pub = sec*G): anchors secret_key_to_public_key.
const char* kGK_pub_hex = "0cf20fe6862d94989e57543c21cd35c9d834364db7701b8d55f63137b1abac35";
const char* kGK_sec_hex = "8639002c6f8b39c3430786b91f12ad1527cbd3a39ea07c4e730707e777655004";

// Two REAL Monero public keys, reused as the (spend B, view A) of every payout
// target so the executor's ECDH derivation runs against on-curve points. B is
// the tests.txt derive_public_key `base`; A is its generate_key_derivation
// `pub` -- both are canonical ed25519 points (they appear as valid inputs in
// the official vectors), which is all derive_output needs.
::xmr::coin::PublicKey g_B;   // spend
::xmr::coin::PublicKey g_A;   // view

// Build an XMR_STD payout ref (B || A) with a distinct identity byte.
::v37::ScriptRef xmr_ref(unsigned char id_seed) {
    ::v37::ScriptRef r;
    r.kind = ::v37::xmr::XMR_STD;
    r.payload.resize(64);
    std::memcpy(r.payload.data(),      g_B.data(), 32);
    std::memcpy(r.payload.data() + 32, g_A.data(), 32);
    // identity byte only tweaks the K_fair tiebreak / provenance, not the point.
    (void)id_seed;
    return r;
}
::v37::bytes32 id_of(unsigned char seed) {
    ::v37::bytes32 b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<unsigned char>(seed + i);
    return b;
}
std::uint64_t sum_amounts(const std::vector<CoinbaseOutput>& v) {
    std::uint64_t s = 0; for (auto& o : v) s += o.amount; return s;
}

CoinbaseInputs base_inputs() {
    CoinbaseInputs in;
    in.monero_major_version = 16;                 // pre-CARROT
    in.height = 3000000;
    in.prev_id = key_from_hex<::xmr::coin::Hash256>(
        "b6d9b2c9a4d0d0e1f2a3b4c5d6e7f80912233445566778899aabbccddeeff001");
    in.base_reward = 600000000000ull;             // 0.6 XMR tail (piconero)
    in.fees = 12345678ull;
    in.chain_id = 0x0000ABCD;
    in.lane_commitment = id_of(0x11);             // owed_digest stand-in
    in.residual_sink = xmr_ref(0x99);
    in.residual_sink_identity = id_of(0x99);
    in.h_min = 0;
    in.output_cap = 2700;
    in.extra_nonce = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0}; // 14-B padded nonce
    return in;
}

// The independent ECDH recomputation of a single coinbase output key + view tag
// (the "every node re-derives" side of the ACCEPT check), done here straight
// from the primitives so it cannot share a bug with derive_output().
bool recompute_output(const ::xmr::coin::SecretKey& r, std::size_t i,
                      ::xmr::coin::PublicKey& P, ::xmr::coin::ViewTag& vt) {
    ::xmr::coin::KeyDerivation D{};
    if (!::xmr::coin::generate_key_derivation(g_A, r, D)) return false; // D = 8 r A
    if (!::xmr::coin::derive_public_key(D, i, g_B, P)) return false;    // P = H_s(D||i)G + B
    ::xmr::coin::derive_view_tag(D, i, vt);
    return true;
}

} // namespace

int main() {
    std::printf("=== xmr_coinbase_kat (X6: OWED -> canonical miner_tx) ===\n");

    g_A = key_from_hex<::xmr::coin::PublicKey>(kDPK_B_hex); // reuse two real points
    g_B = key_from_hex<::xmr::coin::PublicKey>(kA_hex);
    // (any two canonical points work; label-agnostic -- both are on-curve.)

    // -----------------------------------------------------------------------
    // Case 1: deterministic-r reproducibility.
    // -----------------------------------------------------------------------
    std::printf("== 1. deterministic-r reproducibility ==\n");
    {
        CoinbaseInputs in = base_inputs();
        in.owed = { {xmr_ref(1), 200000000000ull, 1, id_of(1)},
                    {xmr_ref(2), 150000000000ull, 2, id_of(2)} };
        BuiltCoinbase b1 = build_coinbase(in);
        BuiltCoinbase b2 = build_coinbase(in);
        CHECK(b1.ok && b2.ok, "both builds ok");
        CHECK(b1.r == b2.r, "same inputs -> same tx secret r (%s)", hx(b1.r).c_str());
        CHECK(b1.R == b2.R, "same inputs -> same tx pubkey R (%s)", hx(b1.R).c_str());
        bool same_set = (b1.outputs.size() == b2.outputs.size());
        for (std::size_t i = 0; same_set && i < b1.outputs.size(); ++i)
            same_set = (b1.outputs[i].one_time_key == b2.outputs[i].one_time_key) &&
                       (b1.outputs[i].amount == b2.outputs[i].amount) &&
                       (b1.outputs[i].view_tag.tag == b2.outputs[i].view_tag.tag);
        CHECK(same_set, "same inputs -> identical P_i / amount / view_tag set");
        CHECK(b1.prefix == b2.prefix, "same inputs -> byte-identical tx prefix");

        // sensitivity: a different owed_digest (lane_commitment) must move r.
        CoinbaseInputs in2 = in; in2.lane_commitment = id_of(0x22);
        BuiltCoinbase b3 = build_coinbase(in2);
        CHECK(b3.ok && b3.r != b1.r, "changed lane_commitment -> different r");
        // sensitivity: a different Monero parent (prev_id) must move r.
        CoinbaseInputs in3 = in; in3.prev_id.data()[0] ^= 0xff;
        BuiltCoinbase b4 = build_coinbase(in3);
        CHECK(b4.ok && b4.r != b1.r, "changed prev_id -> different r");
        // sensitivity: a different height must move r.
        CoinbaseInputs in4 = in; in4.height = in.height + 1;
        BuiltCoinbase b5 = build_coinbase(in4);
        CHECK(b5.ok && b5.r != b1.r, "changed height -> different r");
    }

    // -----------------------------------------------------------------------
    // Case 2: R = r*G (and secret_key_to_public_key anchored to a real vector).
    // -----------------------------------------------------------------------
    std::printf("== 2. R = r*G ==\n");
    {
        // Anchor secret_key_to_public_key to the OFFICIAL generate_keys vector.
        ::xmr::coin::SecretKey sec = key_from_hex<::xmr::coin::SecretKey>(kGK_sec_hex);
        ::xmr::coin::PublicKey pub{};
        bool ok = ::xmr::coin::secret_key_to_public_key(sec, pub);
        CHECK(ok && hx(pub) == std::string(kGK_pub_hex),
              "secret_key_to_public_key(sec) == pub (monero generate_keys vector) -> %s",
              hx(pub).c_str());

        // The executor's R is exactly r*G for its deterministic r.
        CoinbaseInputs in = base_inputs();
        in.owed = { {xmr_ref(1), 100000000000ull, 1, id_of(1)} };
        BuiltCoinbase b = build_coinbase(in);
        CHECK(b.ok, "build ok");
        ::xmr::coin::SecretKey r{};
        CHECK(derive_tx_secret_key(in, r), "derive_tx_secret_key ok (fence passed)");
        CHECK(r == b.r, "build.r == derive_tx_secret_key(in)");
        ::xmr::coin::PublicKey R_check{};
        CHECK(::xmr::coin::secret_key_to_public_key(r, R_check) && R_check == b.R,
              "R == r*G (%s)", hx(b.R).c_str());
    }

    // -----------------------------------------------------------------------
    // Case 3: one derived stealth key against a known Monero vector, and the
    //         coinbase's own P_i reproduce by the same recipe.
    // -----------------------------------------------------------------------
    std::printf("== 3. stealth key vs known Monero vector ==\n");
    {
        // (a) generate_key_derivation official vector.
        ::xmr::coin::PublicKey A = key_from_hex<::xmr::coin::PublicKey>(kA_hex);
        ::xmr::coin::SecretKey r = key_from_hex<::xmr::coin::SecretKey>(kr_hex);
        ::xmr::coin::KeyDerivation D{};
        bool okd = ::xmr::coin::generate_key_derivation(A, r, D);
        CHECK(okd && hx(D) == std::string(kD_hex),
              "generate_key_derivation(A,r) == D (monero vector) -> %s", hx(D).c_str());

        // (b) derive_public_key official vector -> a real stealth one-time key.
        ::xmr::coin::KeyDerivation D2 = key_from_hex<::xmr::coin::KeyDerivation>(kDPK_D_hex);
        ::xmr::coin::PublicKey B = key_from_hex<::xmr::coin::PublicKey>(kDPK_B_hex);
        ::xmr::coin::PublicKey P{};
        bool okp = ::xmr::coin::derive_public_key(D2, static_cast<std::size_t>(kDPK_i), B, P);
        CHECK(okp && hx(P) == std::string(kDPK_P_hex),
              "derive_public_key(D,i,B) == P (monero vector) -> %s", hx(P).c_str());

        // (c) coinbase-path consistency: each built P_i reproduces from scratch.
        CoinbaseInputs in = base_inputs();
        in.owed = { {xmr_ref(1), 200000000000ull, 1, id_of(1)},
                    {xmr_ref(2), 150000000000ull, 2, id_of(2)},
                    {xmr_ref(3),  50000000000ull, 3, id_of(3)} };
        BuiltCoinbase b = build_coinbase(in);
        CHECK(b.ok, "build ok");
        bool all_match = true;
        for (std::size_t i = 0; i < b.outputs.size(); ++i) {
            ::xmr::coin::PublicKey Pi{}; ::xmr::coin::ViewTag vti{};
            if (!recompute_output(b.r, i, Pi, vti)) { all_match = false; break; }
            if (!(Pi == b.outputs[i].one_time_key) ||
                vti.tag != b.outputs[i].view_tag.tag) { all_match = false; break; }
        }
        CHECK(all_match, "every coinbase P_i / view_tag reproduces by 8rA ECDH recipe");
        // vout keys are distinct across indices (the output_index really binds).
        bool distinct = true;
        for (std::size_t i = 0; i < b.outputs.size(); ++i)
            for (std::size_t j = i + 1; j < b.outputs.size(); ++j)
                if (b.outputs[i].one_time_key == b.outputs[j].one_time_key) distinct = false;
        CHECK(distinct, "per-vout one-time keys are distinct (index-bound)");

        // ACCEPT round-trip: rebuild matches; a wrong-wallet tamper is caught.
        ReceivedCoinbase got; got.R = b.R;
        for (auto& o : b.outputs) { got.amounts.push_back(o.amount);
                                    got.keys.push_back(o.one_time_key);
                                    got.view_tags.push_back(o.view_tag); }
        got.tx_extra = b.tx_extra;
        MatchResult m = canonical_coinbase_matches(in, got);
        CHECK(m.matches && m.first_bad_index == -1, "ACCEPT: identical coinbase matches");
        ReceivedCoinbase bad = got; bad.keys[0].data()[3] ^= 0xff;
        MatchResult mb = canonical_coinbase_matches(in, bad);
        CHECK(!mb.matches && mb.first_bad_index == 0,
              "ACCEPT: wrong wallet at index 0 rejected");
    }

    // -----------------------------------------------------------------------
    // Case 4: exact-sum, no burn (Sum(vout) == base_reward + fees).
    // -----------------------------------------------------------------------
    std::printf("== 4. exact-sum, no burn (HF13) ==\n");
    {
        // surplus -> owed paid in full + residual sink absorbs the rest.
        CoinbaseInputs in = base_inputs();  // budget = 600000000000 + 12345678
        in.owed = { {xmr_ref(1), 200000000000ull, 1, id_of(1)},
                    {xmr_ref(2), 150000000000ull, 2, id_of(2)} };
        BuiltCoinbase b = build_coinbase(in);
        CHECK(b.ok, "surplus: build ok");
        CHECK(sum_amounts(b.outputs) == in.budget(),
              "surplus: Sum(vout)=%llu == base_reward+fees=%llu",
              (unsigned long long)sum_amounts(b.outputs), (unsigned long long)in.budget());
        CHECK(b.outputs.back().role == CoinbaseOutput::Role::Sink,
              "surplus: last output is the residual sink");
        CHECK(b.outputs.back().amount ==
                  in.budget() - 200000000000ull - 150000000000ull,
              "surplus: sink carries exactly the unallocated remainder");

        // deficit -> last owed partial, NO sink, still exact-sum.
        CoinbaseInputs in2 = base_inputs(); in2.base_reward = 1000; in2.fees = 0;
        in2.owed = { {xmr_ref(1), 600, 1, id_of(1)}, {xmr_ref(2), 700, 2, id_of(2)} };
        BuiltCoinbase b2 = build_coinbase(in2);
        CHECK(b2.ok && sum_amounts(b2.outputs) == 1000,
              "deficit: exact-sum == 1000 (%llu)", (unsigned long long)sum_amounts(b2.outputs));
        CHECK(b2.outputs.size() == 2 &&
                  b2.outputs.back().role == CoinbaseOutput::Role::Owed,
              "deficit: partial last owed, no sink");

        // fixed dev output deducted first; owed|fixed|sink order; exact-sum.
        CoinbaseInputs in3 = base_inputs(); in3.base_reward = 1000; in3.fees = 0;
        in3.fixed = { {xmr_ref(0x50), 50, id_of(0x50)} };
        in3.owed  = { {xmr_ref(1), 200, 1, id_of(1)} };
        BuiltCoinbase b3 = build_coinbase(in3);
        CHECK(b3.ok && sum_amounts(b3.outputs) == 1000, "fixed: exact-sum == 1000");
        CHECK(b3.outputs.size() == 3 &&
                  b3.outputs[0].role == CoinbaseOutput::Role::Owed &&
                  b3.outputs[1].role == CoinbaseOutput::Role::Fixed &&
                  b3.outputs[2].role == CoinbaseOutput::Role::Sink,
              "fixed: owed|fixed|sink order");

        // no owed, no fixed -> whole budget to the sink (never burned).
        CoinbaseInputs in4 = base_inputs(); in4.base_reward = 1000; in4.fees = 0;
        BuiltCoinbase b4 = build_coinbase(in4);
        CHECK(b4.ok && b4.outputs.size() == 1 &&
                  b4.outputs[0].role == CoinbaseOutput::Role::Sink &&
                  b4.outputs[0].amount == 1000,
              "empty ledger: full reward to sink, nothing burned");
    }

    // -----------------------------------------------------------------------
    // Case 5: weight-aware output cap.
    // -----------------------------------------------------------------------
    std::printf("== 5. weight-aware output cap ==\n");
    {
        CHECK(weight_aware_output_cap(300000, 0, 2700) == 2700, "wire cap binds below headroom");
        CHECK(weight_aware_output_cap(300000, 0, 10) == 10, "small wire cap binds");
        CHECK(weight_aware_output_cap(0, 1000000, 2700) == 1, "floor 1 (always room for sink)");
        // penalty headroom binds when the wire cap is generous.
        std::uint32_t c = weight_aware_output_cap(300000, 0, 100000);
        CHECK(c > 1 && c < 100000, "penalty headroom binds when wire cap is large (C=%u)", c);
        // a bigger median (more headroom) never lowers the cap.
        CHECK(weight_aware_output_cap(600000, 0, 100000) >=
              weight_aware_output_cap(300000, 0, 100000), "cap monotonic in median");
    }

    // -----------------------------------------------------------------------
    // Case 6: CARROT / FCMP++ fence.
    // -----------------------------------------------------------------------
    std::printf("== 6. CARROT fence (major > %u) ==\n",
                (unsigned)W5_PRECARROT_MAX_MAJOR_VERSION);
    {
        CoinbaseInputs in = base_inputs();
        in.owed = { {xmr_ref(1), 200000000000ull, 1, id_of(1)} };

        in.monero_major_version = 16;
        BuiltCoinbase b16 = build_coinbase(in);
        CHECK(b16.ok && b16.error == BuildError::None, "v16 builds a coinbase");

        in.monero_major_version = 17;
        BuiltCoinbase b17 = build_coinbase(in);
        CHECK(!b17.ok && b17.error == BuildError::CarrotFence,
              "v17 REFUSED with CarrotFence (%s)", to_string(b17.error));
        CHECK(b17.outputs.empty(), "v17: no coinbase outputs produced");

        // the fence also trips at the secret-key derivation boundary.
        ::xmr::coin::SecretKey r{};
        CHECK(!derive_tx_secret_key(in, r), "v17: derive_tx_secret_key refuses");

        // boundary is exact: 16 ok, 17 fenced (W5_PRECARROT_MAX == descriptor).
        CHECK(W5_PRECARROT_MAX_MAJOR_VERSION == 16, "fence pinned at pre-CARROT max = 16");
    }

    std::printf("%s (%d failure%s)\n", g_fail ? "X6 COINBASE KAT FAILED" : "X6 COINBASE KAT OK",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
