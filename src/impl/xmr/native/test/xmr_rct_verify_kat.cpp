// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_rct_verify_kat.cpp
//
// The R-VAL evidence KAT: does `Structural | NonInputConsensus` actually mean
// what the ruling says it means?
//
// The oracle is real Monero: every transaction here was captured from a live
// stagenet daemon (xmr_tx_weight_golden.hpp) and every one of them was accepted
// by a real monerod and mined into a real block. So:
//
//   POSITIVE -- each real Bulletproof+ transaction decodes, its identity
//   reproduces the daemon's own tx_hash, its weight reproduces the daemon's own
//   weight, and its commitment balance, range proofs and key-image domain all
//   verify. Reproducing the id is not decoration: the id is the triple hash
//   over the three byte spans, so it only comes out right if the decoder split
//   prefix / rct base / prunable exactly where monerod splits them, which is
//   the same split the proof and the commitments are read out of.
//
//   NON-VACUOUS -- mutating what the checks are supposed to catch makes them
//   fail, and each mutation is aimed at a DIFFERENT check: a changed output
//   commitment and a changed fee and a changed pseudo-output all break the
//   balance equation; a changed proof element breaks the range proof; a
//   torsion key image breaks the domain check; an unreduced scalar is refused
//   before any arithmetic. Without this half the positive half would pass just
//   as well against a verifier that returned Ok unconditionally.
//
//   FAIL-CLOSED -- the seven real rct-type-5 (CLSAG / Bulletproof, pre-HF15)
//   transactions in the same corpus are REFUSED as an unsupported type rather
//   than guessed at.
//
// What this KAT deliberately does NOT assert: that a double spend is caught. It
// is not, by ruling; see the txpool KAT for what the pool does about that.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/rct/xmr_bulletproofs_plus.hpp"
#include "impl/xmr/native/rct/xmr_multiexp.hpp"
#include "impl/xmr/native/rct/xmr_rct_ops.hpp"
#include "impl/xmr/native/rct/xmr_rct_verify.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"
#include "xmr_tx_weight_golden.hpp"

using namespace c2pool::xmr::native;
namespace R = c2pool::xmr::native::rct;
namespace G = c2pool::xmr::native::golden;

static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 20) std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 20) {
            va_list ap;
            va_start(ap, fmt);
            std::vfprintf(stderr, fmt, ap);
            va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

static std::vector<std::uint8_t> from_hex(const char* hex) {
    std::vector<std::uint8_t> out;
    const std::size_t n = std::strlen(hex);
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

static std::string to_hex(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : h) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 0xf]);
    }
    return s;
}

// A point of order 8 on ed25519 -- a valid encoding, decodable, and outside the
// prime-order subgroup. Exactly the shape the key-image domain check exists to
// refuse (monerod: check_tx_inputs_keyimages_domain).
static const R::Key TORSION_POINT = {{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
                                      0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
                                      0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
                                      0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}};

// ---------------------------------------------------------------------------
// The curve helpers themselves, before anything trusts them
// ---------------------------------------------------------------------------
// The two published generator constants (monero-project src/ringct/rctTypes.h
// and the ed25519 base point). They are pinned here as literals so that a
// vendored table swapped underneath us is a KAT failure and not a silent change
// of the curve everything else is denominated in.
static const R::Key PUBLISHED_G = {{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}};
static const R::Key PUBLISHED_H = {{0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf,
                                    0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
                                    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9,
                                    0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94}};

static void test_primitives() {
    // The generators are the two constants Monero publishes. G is DERIVED here
    // (a base-point multiplication by one) rather than copied, so this also
    // says the vendored scalar-base path agrees with the published encoding.
    check(R::generator_G() == PUBLISHED_G, "G is the published ed25519 base point");
    check(R::generator_H() == PUBLISHED_H, "H is Monero's published value generator");

    // hash_to_p3 is what derives all 2048 Bulletproof+ generators, so what
    // matters about it is that it lands in the prime-order subgroup and is
    // deterministic. Whether it reproduces H is NOT a property of it: H predates
    // this map and is a published constant, not a recomputable one. The real
    // oracle for this function is further down -- real range proofs only verify
    // if all 2048 derived generators came out exactly right.
    ge_p3 a_p3{}, a_again{}, b_p3{};
    R::hash_to_p3(a_p3, R::generator_G());
    R::hash_to_p3(a_again, R::generator_G());
    R::hash_to_p3(b_p3, R::generator_H());
    check(R::point_encode(a_p3) == R::point_encode(a_again), "hash_to_p3 is deterministic");
    check(R::point_encode(a_p3) != R::point_encode(b_p3),
          "hash_to_p3 separates distinct inputs");
    check(R::in_main_subgroup(R::point_encode(a_p3)),
          "hash_to_p3 lands in the prime-order subgroup (the cofactor is cleared)");

    // Both generators are in the prime-order subgroup; the torsion point is not.
    check(R::in_main_subgroup(R::generator_G()), "G is in the prime-order subgroup");
    check(R::in_main_subgroup(R::generator_H()), "H is in the prime-order subgroup");
    check(!R::in_main_subgroup(TORSION_POINT),
          "the order-8 test point is NOT in the prime-order subgroup (the domain "
          "check has something to catch)");

    // Scalar inversion, single and batched, against each other.
    const R::Key a = R::hash_to_scalar("c2pool-rct-kat-a", 16);
    const R::Key b = R::hash_to_scalar("c2pool-rct-kat-b", 16);
    check(R::sc_mul_k(a, R::scalar_invert(a)) == R::scalar_one(), "a * a^-1 == 1");
    R::KeyV batch{a, b};
    check(R::scalar_batch_invert(batch), "batch inversion of two nonzero scalars succeeds");
    check(batch[0] == R::scalar_invert(a) && batch[1] == R::scalar_invert(b),
          "batch inversion agrees with single inversion");
    R::KeyV with_zero{a, R::scalar_zero()};
    check(!R::scalar_batch_invert(with_zero), "batch inversion refuses a zero element");

    // Multi-scalar multiplication against the same sum computed one point at a
    // time: 3*G + 5*H must equal G+G+G + H+H+H+H+H.
    ge_p3 G_p3{}, H_p3{};
    check(R::point_decode(G_p3, R::generator_G()), "G decodes");
    check(R::point_decode(H_p3, R::generator_H()), "H decodes");
    R::Key three = R::scalar_zero(); three[0] = 3;
    R::Key five  = R::scalar_zero(); five[0]  = 5;
    const R::Key by_multiexp = R::multiexp({{three, G_p3}, {five, H_p3}});
    R::KeyV terms;
    for (int i = 0; i < 3; ++i) terms.push_back(R::generator_G());
    for (int i = 0; i < 5; ++i) terms.push_back(R::generator_H());
    R::Key by_addition{};
    check(R::add_keys(terms, by_addition), "repeated addition of G and H succeeds");
    check(by_multiexp == by_addition, "multiexp(3G + 5H) == G+G+G+H+H+H+H+H");

    // A zero scalar contributes nothing, and an empty sum is the identity.
    check(R::multiexp({{R::scalar_zero(), G_p3}}) == R::identity(),
          "a zero-scalar term contributes the identity");
    check(R::multiexp({}) == R::identity(), "an empty multiexp is the identity");

    // The commitment arithmetic the balance check is made of: fee*H computed by
    // scalarmult_H equals fee*H computed as a generic scalar multiplication.
    const R::Key fee_scalar = R::amount_to_scalar(1234567890123ull);
    R::Key       generic{};
    check(R::scalarmult_key(generic, R::generator_H(), fee_scalar), "generic a*H succeeds");
    check(generic == R::scalarmult_H(fee_scalar), "scalarmult_H agrees with the generic path");
}

// ---------------------------------------------------------------------------
// The real transactions
// ---------------------------------------------------------------------------
struct RealTx {
    std::vector<std::uint8_t> blob;
    const char*               id_hex = nullptr;
    std::uint32_t             weight = 0;
};

static std::vector<RealTx> bulletproof_plus_corpus() {
    std::vector<RealTx> out;
    for (std::size_t i = 0; i < G::FULL_TX_COUNT; ++i) {
        const G::GoldenFullTx& g = G::FULL_TXS[i];
        RealTx t;
        t.blob   = from_hex(g.full_hex);
        t.id_hex = g.id_hex;
        t.weight = g.weight;
        DecodedTx d;
        if (decode_relayed_tx(t.blob, d) == TxDecodeStatus::Ok) out.push_back(std::move(t));
    }
    return out;
}

static void test_real_transactions() {
    std::size_t bpp = 0, unsupported = 0;
    std::vector<const R::BulletproofPlus*> batch;
    std::vector<DecodedTx>                 decoded;
    decoded.reserve(G::FULL_TX_COUNT);

    for (std::size_t i = 0; i < G::FULL_TX_COUNT; ++i) {
        const G::GoldenFullTx& g = G::FULL_TXS[i];
        const std::vector<std::uint8_t> blob = from_hex(g.full_hex);

        DecodedTx d;
        const TxDecodeStatus st = decode_relayed_tx(blob, d);
        if (st == TxDecodeStatus::UnsupportedRctType) {
            ++unsupported;
            continue;   // a pre-HF15 rct type: refused by the scope fence
        }
        checkf(st == TxDecodeStatus::Ok, "tx %s decodes (got %s)", g.id_hex, to_string(st));
        if (st != TxDecodeStatus::Ok) continue;
        ++bpp;

        // Identity and weight against the daemon's own numbers.
        checkf(to_hex(d.id) == std::string(g.id_hex),
               "tx id reproduces monerod's tx_hash: got %s want %s", to_hex(d.id).c_str(),
               g.id_hex);
        checkf(d.w.weight == g.weight, "tx %s weight %llu == monerod %u", g.id_hex,
               static_cast<unsigned long long>(d.w.weight), g.weight);
        checkf(d.prefix_size + d.base_size + d.prunable_size == blob.size(),
               "tx %s byte spans cover the blob exactly", g.id_hex);
        checkf(d.rct.outPk.size() == d.w.n_outputs, "tx %s has one commitment per output",
               g.id_hex);
        checkf(d.rct.pseudoOuts.size() == d.w.n_inputs,
               "tx %s has one pseudo-output per input", g.id_hex);
        checkf(d.rct.key_images.size() == d.w.n_inputs, "tx %s has one key image per input",
               g.id_hex);
        checkf(d.rct.bpp.size() == 1, "tx %s carries exactly one Bulletproof+ proof",
               g.id_hex);
        checkf(R::bulletproof_plus_max_amounts(d.rct.bpp[0]) >= d.w.n_outputs,
               "tx %s proof shape covers its output count", g.id_hex);

        // The evidence itself.
        R::RctNonInput in = d.rct;
        const R::RctVerifyStatus vs = R::verify_non_input_consensus(in);
        checkf(vs == R::RctVerifyStatus::Ok,
               "tx %s passes non-input consensus (got %s)", g.id_hex, R::to_string(vs));

        decoded.push_back(std::move(d));
    }

    checkf(bpp >= 5, "the corpus carries at least five Bulletproof+ transactions (%zu)", bpp);
    checkf(unsupported >= 1,
           "the corpus carries pre-HF15 rct types, and they are refused (%zu)", unsupported);

    // Batch verification over every real proof at once, which is the path a
    // busy pool actually takes and which mixes proof sizes (2, 3 and 4 output
    // aggregates have different round counts).
    std::vector<R::RctNonInput> ins;
    ins.reserve(decoded.size());
    for (DecodedTx& d : decoded) {
        R::RctNonInput in = d.rct;
        in.bpp[0].V.resize(in.outPk.size());
        for (std::size_t i = 0; i < in.outPk.size(); ++i)
            check(R::scalarmult_key(in.bpp[0].V[i], in.outPk[i], R::inv_eight()),
                  "V is rebuilt from the output commitments");
        ins.push_back(std::move(in));
    }
    for (const R::RctNonInput& in : ins) batch.push_back(&in.bpp[0]);
    check(R::verify_bulletproofs_plus(batch),
          "every real proof verifies in ONE batch");
}

// ---------------------------------------------------------------------------
// Non-vacuity: each mutation must break the check it is aimed at
// ---------------------------------------------------------------------------
static void test_mutations() {
    const std::vector<RealTx> corpus = bulletproof_plus_corpus();
    check(!corpus.empty(), "there is at least one Bulletproof+ transaction to mutate");
    if (corpus.empty()) return;

    for (std::size_t n = 0; n < corpus.size() && n < 2; ++n) {
        const RealTx& t = corpus[n];

        // -- a changed OUTPUT COMMITMENT breaks the balance equation ---------
        {
            DecodedTx d;
            check(decode_relayed_tx(t.blob, d) == TxDecodeStatus::Ok, "control decode");
            R::RctNonInput in = d.rct;
            in.outPk[0] = R::generator_H();   // a valid point, the wrong one
            const R::RctVerifyStatus vs = R::verify_non_input_consensus(in);
            checkf(vs == R::RctVerifyStatus::SumMismatch,
                   "a substituted output commitment fails the balance check (got %s)",
                   R::to_string(vs));
        }

        // -- a changed FEE breaks the balance equation ------------------------
        // The fee is plaintext and enters the equation as fee*H, so claiming a
        // different fee for the same commitments is exactly a value forgery.
        {
            DecodedTx d;
            check(decode_relayed_tx(t.blob, d) == TxDecodeStatus::Ok, "control decode");
            R::RctNonInput in = d.rct;
            in.fee += 1;
            const R::RctVerifyStatus vs = R::verify_non_input_consensus(in);
            checkf(vs == R::RctVerifyStatus::SumMismatch,
                   "a fee that does not match the commitments is refused (got %s)",
                   R::to_string(vs));
        }

        // -- a changed PSEUDO-OUTPUT breaks the balance equation --------------
        {
            DecodedTx d;
            check(decode_relayed_tx(t.blob, d) == TxDecodeStatus::Ok, "control decode");
            R::RctNonInput in = d.rct;
            in.pseudoOuts[0] = R::generator_H();
            const R::RctVerifyStatus vs = R::verify_non_input_consensus(in);
            checkf(vs == R::RctVerifyStatus::SumMismatch,
                   "a substituted pseudo-output fails the balance check (got %s)",
                   R::to_string(vs));
        }

        // -- a TORSION key image fails the domain check -----------------------
        {
            DecodedTx d;
            check(decode_relayed_tx(t.blob, d) == TxDecodeStatus::Ok, "control decode");
            R::RctNonInput in = d.rct;
            in.key_images[0] = TORSION_POINT;
            const R::RctVerifyStatus vs = R::verify_non_input_consensus(in);
            checkf(vs == R::RctVerifyStatus::KeyImageDomain,
                   "a key image outside the prime-order subgroup is refused (got %s)",
                   R::to_string(vs));
        }

        // -- a changed PROOF ELEMENT fails the range proof ---------------------
        // The blob is mutated here, not the decoded struct, so this also proves
        // the proof bytes are read from where the decoder says they are.
        {
            std::vector<std::uint8_t> blob = t.blob;
            DecodedTx probe;
            check(decode_relayed_tx(blob, probe) == TxDecodeStatus::Ok, "control decode");
            const std::size_t a_off = probe.prefix_size + probe.base_size + 1;   // past nbp
            blob[a_off + 7] ^= 0x40;

            DecodedTx d;
            const TxDecodeStatus st = decode_relayed_tx(blob, d);
            checkf(st == TxDecodeStatus::Ok, "a tampered proof still DECODES (got %s)",
                   to_string(st));
            if (st == TxDecodeStatus::Ok) {
                R::RctNonInput in = d.rct;
                const R::RctVerifyStatus vs = R::verify_non_input_consensus(in);
                checkf(vs == R::RctVerifyStatus::RangeProofFail,
                       "a tampered range proof fails verification (got %s)",
                       R::to_string(vs));
            }
        }

        // -- an UNREDUCED scalar is refused before the arithmetic --------------
        {
            DecodedTx d;
            check(decode_relayed_tx(t.blob, d) == TxDecodeStatus::Ok, "control decode");
            R::RctNonInput in = d.rct;
            in.bpp[0].d1.fill(0xff);
            const R::RctVerifyStatus vs = R::verify_non_input_consensus(in);
            checkf(vs == R::RctVerifyStatus::RangeProofFail,
                   "an unreduced proof scalar is refused (got %s)", R::to_string(vs));
        }

        // -- SHAPE mismatches --------------------------------------------------
        {
            DecodedTx d;
            check(decode_relayed_tx(t.blob, d) == TxDecodeStatus::Ok, "control decode");
            R::RctNonInput in = d.rct;
            in.bpp[0].L.pop_back();   // a proof too short for its commitments
            check(R::verify_non_input_consensus(in) == R::RctVerifyStatus::ShapeMismatch,
                  "a proof whose round count cannot cover the outputs is refused");

            R::RctNonInput in2 = d.rct;
            in2.pseudoOuts.pop_back();
            check(R::verify_non_input_consensus(in2) == R::RctVerifyStatus::ShapeMismatch,
                  "a pseudo-output count that disagrees with the inputs is refused");

            R::RctNonInput in3 = d.rct;
            in3.rct_type = 5;
            check(R::verify_non_input_consensus(in3) == R::RctVerifyStatus::UnsupportedType,
                  "a non-Bulletproof+ rct type is refused rather than guessed at");
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder refusals on the wire shape
// ---------------------------------------------------------------------------
static void test_decoder_refusals() {
    const std::vector<RealTx> corpus = bulletproof_plus_corpus();
    if (corpus.empty()) return;
    const std::vector<std::uint8_t>& good = corpus[0].blob;

    DecodedTx d;
    check(decode_relayed_tx(nullptr, 0, d) != TxDecodeStatus::Ok, "an empty blob is refused");

    std::vector<std::uint8_t> truncated(good.begin(), good.end() - 1);
    check(decode_relayed_tx(truncated, d) != TxDecodeStatus::Ok,
          "a blob one byte short is refused");

    std::vector<std::uint8_t> extended = good;
    extended.push_back(0x00);
    check(decode_relayed_tx(extended, d) != TxDecodeStatus::Ok,
          "a blob with a trailing byte is refused");

    // The proof-count field is consensus shape: exactly one aggregate proof.
    DecodedTx probe;
    check(decode_relayed_tx(good, probe) == TxDecodeStatus::Ok, "control decode");
    std::vector<std::uint8_t> two_proofs = good;
    two_proofs[probe.prefix_size + probe.base_size] = 0x02;
    check(decode_relayed_tx(two_proofs, d) == TxDecodeStatus::ProofShape,
          "a prunable part claiming two aggregate proofs is refused");
}

int main() {
    std::printf("xmr_rct_verify_kat: corpus from monerod %s (%s) at tip %llu\n",
                G::MONEROD_VERSION, G::NETWORK,
                static_cast<unsigned long long>(G::CAPTURE_TIP));
    test_primitives();
    test_real_transactions();
    test_mutations();
    test_decoder_refusals();
    std::printf("xmr_rct_verify_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
