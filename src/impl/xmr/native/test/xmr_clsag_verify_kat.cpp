// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_clsag_verify_kat.cpp
//
// The INPUT-consensus signature KAT: does verify_clsag actually verify the
// CLSAG ring signature -- the check that decides a REAL, owned input was spent,
// the one thing that separates a daemonless node that mines what the network
// will accept from an SPV-mining relay that trusts the sender?
//
// The oracle is real Monero MAINNET. Every transaction in
// xmr_input_consensus_golden.hpp was captured from a monerod: the transaction
// blob is public chain data, and the (public key, commitment) of every ring
// member of every input was resolved by the same daemon's get_outs. Each of
// these transactions was accepted by a real monerod and mined into a real
// block -- so its ring signatures are, by construction, valid.
//
//   POSITIVE / PARITY -- each real Bulletproof+ transaction decodes with OUR
//   decoder; its identity reproduces the daemon's own tx_hash (so we split the
//   prefix / rct base / prunable byte-for-byte where monerod does, which is
//   also where the CLSAG message's two leading hashes come from); its non-input
//   consensus verifies; and then, taking ONLY the resolved ring members from
//   the golden, our clsag_message() + verify_clsag() accept every input's ring
//   signature. This is the reproducible monerod-parity claim, committed: rerun
//   the generator against any monerod and the goldens regenerate.
//
//   NON-VACUOUS -- mutating each thing the signature is supposed to bind makes
//   verify_clsag fail, and each mutation is aimed at a DIFFERENT branch: a
//   flipped signature scalar, a swapped ring-member key, a swapped ring-member
//   commitment, a wrong pseudo-output, a flipped message bit -> SigMismatch; an
//   unreduced c1 -> BadScalar; D := identity -> BadAuxKeyImage; I := identity
//   -> BadKeyImage; a ring one member short -> ShapeMismatch. Without this half
//   the positive half would pass against a verifier that returned Ok always.
//
// A real monerod rejects the same forged transactions (m_invalid_input); the
// generator's --replay path documents how to reproduce that verdict against any
// restricted public v0.18 node. What is committed here is our verifier's own
// verdict on real signatures and on mutations of them, third-party checkable.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/rct/xmr_clsag_verify.hpp"
#include "impl/xmr/native/rct/xmr_rct_ops.hpp"
#include "impl/xmr/native/rct/xmr_rct_verify.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"
#include "xmr_input_consensus_golden.hpp"

using namespace c2pool::xmr::native;
namespace R = c2pool::xmr::native::rct;
namespace T = c2pool::xmr::native::test;

static int g_checks = 0;
static int g_fail   = 0;

static void check(bool cond, const char* what) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 30) std::fprintf(stderr, "FAIL: %s\n", what);
    }
}

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 30) {
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

static R::Key key_from_hex(const char* hex) {
    R::Key k{};
    std::vector<std::uint8_t> b = from_hex(hex);
    for (std::size_t i = 0; i < 32 && i < b.size(); ++i) k[i] = b[i];
    return k;
}

// Build the resolved ring for one input from the golden's (dest, mask) pairs.
static std::vector<R::CtKey> ring_of(const T::GoldenInput& gi) {
    std::vector<R::CtKey> ring;
    ring.reserve(gi.members.size());
    for (const T::GoldenMember& m : gi.members)
        ring.push_back(R::CtKey{key_from_hex(m.dest), key_from_hex(m.mask)});
    return ring;
}

// ---------------------------------------------------------------------------
// POSITIVE + PARITY: real mainnet signatures verify, and our tx_hash matches.
// ---------------------------------------------------------------------------
static void test_positive() {
    const std::vector<T::GoldenTx>& g = T::input_consensus_golden();
    checkf(!g.empty(), "golden corpus is empty (generator not run?)");

    std::size_t verified_inputs = 0;
    for (const T::GoldenTx& tx : g) {
        std::vector<std::uint8_t> blob = from_hex(tx.full_hex);

        DecodedTx d;
        const TxDecodeStatus st = decode_relayed_tx(blob.data(), blob.size(), d);
        checkf(st == TxDecodeStatus::Ok, "decode failed for %s", tx.id);
        if (st != TxDecodeStatus::Ok) continue;

        // PARITY: our identity reproduces monerod's tx_hash byte-for-byte.
        const R::Key want_id = key_from_hex(tx.id);
        checkf(std::memcmp(d.id.data(), want_id.data(), 32) == 0,
               "tx_hash mismatch for %s (decoder split disagrees with monerod)",
               tx.id);

        // These are real, mined transactions: non-input consensus must pass.
        checkf(rct::verify_non_input_consensus(d.rct) == rct::RctVerifyStatus::Ok,
               "non-input consensus failed for %s", tx.id);

        checkf(d.clsags.size() == tx.inputs.size(),
               "input count mismatch for %s (%zu decoded vs %zu golden)",
               tx.id, d.clsags.size(), tx.inputs.size());
        if (d.clsags.size() != tx.inputs.size()) continue;
        checkf(!d.rct.bpp.empty(), "no bulletproof for %s", tx.id);
        if (d.rct.bpp.empty()) continue;

        const R::Key msg = R::clsag_message(d.h_prefix, d.h_base, d.rct.bpp[0]);
        for (std::size_t i = 0; i < d.clsags.size(); ++i) {
            // Sanity: the golden's key image matches the one we decoded, so the
            // members really belong to this input.
            const R::Key gki = key_from_hex(tx.inputs[i].k_image);
            checkf(std::memcmp(d.clsags[i].I.data(), gki.data(), 32) == 0,
                   "key image mismatch for %s input %zu", tx.id, i);

            const std::vector<R::CtKey> ring = ring_of(tx.inputs[i]);
            const R::ClsagStatus s =
                R::verify_clsag(msg, d.clsags[i], ring, d.rct.pseudoOuts[i]);
            checkf(s == R::ClsagStatus::Ok,
                   "verify_clsag rejected a REAL signature for %s input %zu: %s",
                   tx.id, i, R::to_string(s));
            if (s == R::ClsagStatus::Ok) ++verified_inputs;
        }
    }
    std::fprintf(stderr, "positive: %zu real mainnet ring signatures verified\n",
                 verified_inputs);
    checkf(verified_inputs > 0, "no ring signature was verified");
}

// ---------------------------------------------------------------------------
// NON-VACUOUS: each mutation trips a different branch of the verifier.
// ---------------------------------------------------------------------------
static void test_mutations() {
    const std::vector<T::GoldenTx>& g = T::input_consensus_golden();

    // Find the first transaction that decodes and has a first input to mutate.
    for (const T::GoldenTx& tx : g) {
        std::vector<std::uint8_t> blob = from_hex(tx.full_hex);
        DecodedTx d;
        if (decode_relayed_tx(blob.data(), blob.size(), d) != TxDecodeStatus::Ok) continue;
        if (d.clsags.empty() || d.rct.bpp.empty() || tx.inputs.empty()) continue;
        if (d.clsags[0].s.empty()) continue;

        const R::Key msg = R::clsag_message(d.h_prefix, d.h_base, d.rct.bpp[0]);
        const std::vector<R::CtKey> ring = ring_of(tx.inputs[0]);
        const R::Key pout = d.rct.pseudoOuts[0];

        // Baseline: the untouched signature verifies.
        check(R::verify_clsag(msg, d.clsags[0], ring, pout) == R::ClsagStatus::Ok,
              "mutation baseline: untouched signature must verify");

        // 1) Flip a byte of s[0] -> the ring equation no longer closes.
        {
            R::Clsag m = d.clsags[0];
            m.s[0][0] ^= 0x01;
            check(R::verify_clsag(msg, m, ring, pout) == R::ClsagStatus::SigMismatch,
                  "flipped s[0] must be SigMismatch");
        }
        // 2) Swap a ring member's destination key.
        if (ring.size() >= 2) {
            std::vector<R::CtKey> r = ring;
            std::swap(r[0].dest, r[1].dest);
            check(R::verify_clsag(msg, d.clsags[0], r, pout) == R::ClsagStatus::SigMismatch,
                  "swapped member dest must be SigMismatch");
        }
        // 3) Replace a ring member's commitment (mask) with another member's.
        if (ring.size() >= 2) {
            std::vector<R::CtKey> r = ring;
            r[0].mask = r[1].mask;
            check(R::verify_clsag(msg, d.clsags[0], r, pout) == R::ClsagStatus::SigMismatch,
                  "swapped member mask must be SigMismatch");
        }
        // 4) Wrong pseudo-output: use a different, still-valid point (another
        //    ring member's commitment) so we reach the equation, not BadPoint.
        {
            const R::Key wrong = ring[0].mask;
            if (std::memcmp(wrong.data(), pout.data(), 32) != 0)
                check(R::verify_clsag(msg, d.clsags[0], ring, wrong) ==
                          R::ClsagStatus::SigMismatch,
                      "wrong pseudo_out must be SigMismatch");
        }
        // 5) Flip a bit of the message (the pre-MLSAG hash).
        {
            R::Key m = msg;
            m[0] ^= 0x80;
            check(R::verify_clsag(m, d.clsags[0], ring, pout) == R::ClsagStatus::SigMismatch,
                  "flipped message must be SigMismatch");
        }
        // 6) c1 unreduced (all 0xff is > l) -> refused before arithmetic.
        {
            R::Clsag m = d.clsags[0];
            for (auto& b : m.c1) b = 0xff;
            check(R::verify_clsag(msg, m, ring, pout) == R::ClsagStatus::BadScalar,
                  "unreduced c1 must be BadScalar");
        }
        // 7) An unreduced signature scalar is also refused before arithmetic.
        {
            R::Clsag m = d.clsags[0];
            for (auto& b : m.s[0]) b = 0xff;
            check(R::verify_clsag(msg, m, ring, pout) == R::ClsagStatus::BadScalar,
                  "unreduced s[0] must be BadScalar");
        }
        // 8) D := identity -> 8*D is identity -> BadAuxKeyImage.
        {
            R::Clsag m = d.clsags[0];
            m.D = R::identity();
            check(R::verify_clsag(msg, m, ring, pout) == R::ClsagStatus::BadAuxKeyImage,
                  "D := identity must be BadAuxKeyImage");
        }
        // 9) I := identity -> BadKeyImage (rejected up front).
        {
            R::Clsag m = d.clsags[0];
            m.I = R::identity();
            check(R::verify_clsag(msg, m, ring, pout) == R::ClsagStatus::BadKeyImage,
                  "I := identity must be BadKeyImage");
        }
        // 10) A ring one member short -> shape mismatch (|ring| != |s|).
        if (ring.size() >= 2) {
            std::vector<R::CtKey> r = ring;
            r.pop_back();
            check(R::verify_clsag(msg, d.clsags[0], r, pout) == R::ClsagStatus::ShapeMismatch,
                  "ring one member short must be ShapeMismatch");
        }

        return;   // one transaction exercised every branch; done.
    }
    check(false, "no decodable transaction with an input to mutate");
}

int main() {
    test_positive();
    test_mutations();

    if (g_fail == 0) {
        std::fprintf(stderr, "CLSAG verify KAT: ALL %d checks passed\n", g_checks);
        return 0;
    }
    std::fprintf(stderr, "CLSAG verify KAT: %d/%d checks FAILED\n", g_fail, g_checks);
    return 1;
}
