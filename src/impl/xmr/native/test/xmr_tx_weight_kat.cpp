// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_tx_weight_kat.cpp
//
// The consensus tx-weight golden, over real Monero transactions captured from a
// live stagenet daemon (see xmr_tx_weight_golden.hpp for the capture metadata).
//
// Four levels of assertion, weakest to strongest:
//
//   A. STRUCTURE -- every pruned blob parses, and the parser's own view of the
//      byte spans adds up to the blob it was handed.
//   B. PRUNABLE RECONSTRUCTION -- for every transaction, the prunable length
//      predicted from structure alone equals the prunable bytes that actually
//      exist. This is the number a node syncing with prune=true (D-4) can never
//      measure and must therefore get right by construction.
//   C. WEIGHT -- computed weight equals full blob size plus the bulletproof
//      clawback, for every transaction and for the shapes the clawback is
//      non-zero on.
//   D. THE INDEPENDENT PIN -- for every captured block, the coinbase weight
//      plus the weight of every transaction in it equals the block_weight the
//      DAEMON reports. That number is not computed anywhere in this repository,
//      so it is what makes this a golden rather than a self-portrait. For the
//      blocks that carry exactly one transaction it pins that transaction's
//      weight exactly.
//
// Plus the arithmetic edge cases (padded output counts, the clawback knee at
// three outputs) and the fail-closed behaviour on rct types whose prunable
// shape is not pinned.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/consensus/xmr_tx_weight.hpp"
#include "xmr_tx_weight_golden.hpp"

using namespace c2pool::xmr::native;
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

static bool from_hex(const char* hex, std::vector<std::uint8_t>& out) {
    const std::size_t n = std::strlen(hex);
    if (n % 2) return false;
    out.clear();
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < n; i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Arithmetic edge cases, independent of the capture.
// ---------------------------------------------------------------------------
static void test_arithmetic() {
    check(n_padded_outputs_for(1) == 1, "one output pads to one");
    check(n_padded_outputs_for(2) == 2, "two outputs pad to two");
    check(n_padded_outputs_for(3) == 4, "three outputs pad to four");
    check(n_padded_outputs_for(4) == 4, "four outputs pad to four");
    check(n_padded_outputs_for(5) == 8, "five outputs pad to eight");
    check(n_padded_outputs_for(16) == 16, "sixteen outputs pad to sixteen");

    check(bp_nlr_for(2) == 7,  "two padded outputs give seven rounds");
    check(bp_nlr_for(4) == 8,  "four padded outputs give eight rounds");
    check(bp_nlr_for(8) == 9,  "eight padded outputs give nine rounds");

    // The knee: one and two outputs carry no clawback, three do.
    check(bulletproof_clawback(RCT_TYPE_BULLETPROOF_PLUS, 1) == 0, "no clawback at one output");
    check(bulletproof_clawback(RCT_TYPE_BULLETPROOF_PLUS, 2) == 0, "no clawback at two outputs");
    check(bulletproof_clawback(RCT_TYPE_BULLETPROOF_PLUS, 3) == 460,
          "the clawback knee at three outputs, bulletproof plus");
    check(bulletproof_clawback(RCT_TYPE_BULLETPROOF_PLUS, 4) == 460,
          "three and four outputs share the padded count");
    check(bulletproof_clawback(RCT_TYPE_BULLETPROOF_PLUS, 5) == 1433,
          "five outputs pad to eight");
    check(bulletproof_clawback(RCT_TYPE_CLSAG, 3) == 537,
          "the pre-plus proof is larger, so its clawback differs");

    // Types that carry no bulletproof never claw back.
    check(bulletproof_clawback(RCT_TYPE_NULL, 8) == 0,   "coinbase never claws back");
    check(bulletproof_clawback(RCT_TYPE_SIMPLE, 8) == 0, "pre-bulletproof never claws back");

    // A version-1 transaction weighs exactly its blob.
    check(transaction_weight(1234, 1, RCT_TYPE_NULL, 8) == 1234,
          "a version 1 transaction weighs its blob size");

    // Fail-closed on a shape whose prunable layout is not pinned.
    std::size_t sz = 0;
    check(predicted_prunable_size(RCT_TYPE_BULLETPROOF, 2, 11, 2, sz)
              == TxParseStatus::UnsupportedRctType,
          "an unpinned rct type refuses to predict rather than guess");
    check(predicted_prunable_size(RCT_TYPE_NULL, 1, 0, 1, sz) == TxParseStatus::Ok && sz == 0,
          "a coinbase has no prunable part");
}

// ---------------------------------------------------------------------------
// A, B, C: every captured transaction.
// ---------------------------------------------------------------------------
static std::vector<std::uint64_t> g_weights;   // computed weight per TXS index

static void test_transactions() {
    g_weights.assign(G::TX_COUNT, 0);

    std::size_t coinbases = 0, clsag = 0, bpp = 0, with_clawback = 0;

    for (std::size_t i = 0; i < G::TX_COUNT; ++i) {
        const G::GoldenTx& g = G::TXS[i];

        std::vector<std::uint8_t> pruned;
        checkf(from_hex(g.pruned_hex, pruned), "tx %s: pruned hex decodes", g.id_hex);

        TxWeightInfo info;
        const TxParseStatus st = parse_tx_pruned(pruned, info);
        checkf(st == TxParseStatus::Ok, "tx %s: pruned parse -> %s", g.id_hex, to_string(st));
        if (st != TxParseStatus::Ok) continue;

        // A. structure
        checkf(info.pruned_size == pruned.size(),
               "tx %s: parsed spans (%zu) cover the pruned blob (%zu)",
               g.id_hex, info.pruned_size, pruned.size());
        checkf(info.rct_type == g.rct_type, "tx %s: rct type %u vs %u",
               g.id_hex, unsigned(info.rct_type), unsigned(g.rct_type));
        checkf(info.n_inputs == g.n_inputs, "tx %s: input count", g.id_hex);
        checkf(info.n_outputs == g.n_outputs, "tx %s: output count", g.id_hex);
        if (g.ring_size) {
            checkf(!info.ring_sizes.empty() && info.ring_sizes.front() == g.ring_size,
                   "tx %s: ring size", g.id_hex);
            checkf(info.key_images.size() == g.n_inputs,
                   "tx %s: one key image per input", g.id_hex);
        } else {
            checkf(info.is_coinbase, "tx %s: no ring means a coinbase", g.id_hex);
            checkf(info.key_images.empty(), "tx %s: a coinbase spends nothing", g.id_hex);
        }

        // B. prunable reconstruction
        checkf(info.prunable_predicted, "tx %s: the pruned path predicts", g.id_hex);
        checkf(info.prunable_size == g.prunable_size,
               "tx %s: predicted prunable %zu vs actual %u",
               g.id_hex, info.prunable_size, g.prunable_size);
        checkf(info.blob_size == g.full_size,
               "tx %s: reconstructed blob size %zu vs actual %u",
               g.id_hex, info.blob_size, g.full_size);

        // C. weight
        checkf(info.weight == g.weight, "tx %s: weight %llu vs golden %u",
               g.id_hex, static_cast<unsigned long long>(info.weight), g.weight);
        checkf(info.weight >= info.blob_size,
               "tx %s: weight never falls below the blob size", g.id_hex);
        checkf(info.clawback == static_cast<std::uint64_t>(g.weight) - g.full_size,
               "tx %s: clawback accounts for the whole difference", g.id_hex);

        g_weights[i] = info.weight;

        if (info.is_coinbase) ++coinbases;
        if (g.rct_type == RCT_TYPE_CLSAG) ++clsag;
        if (g.rct_type == RCT_TYPE_BULLETPROOF_PLUS) ++bpp;
        if (info.clawback) ++with_clawback;
    }

    // The corpus must actually cover the shapes that matter, or a green run
    // proves nothing.
    checkf(G::TX_COUNT - coinbases >= 200,
           "corpus carries at least 200 non-coinbase transactions (has %zu)",
           G::TX_COUNT - coinbases);
    check(clsag > 0, "corpus covers CLSAG transactions");
    check(bpp > 0,   "corpus covers bulletproof-plus transactions");
    check(coinbases > 0, "corpus covers coinbase transactions");
    checkf(with_clawback > 0, "corpus covers the non-zero clawback shapes (%zu)", with_clawback);

    std::printf("  transactions: %zu total, %zu coinbase, %zu CLSAG, %zu BP+, %zu with clawback\n",
                G::TX_COUNT, coinbases, clsag, bpp, with_clawback);
}

// ---------------------------------------------------------------------------
// D: the independent pin.
// ---------------------------------------------------------------------------
static void test_block_weight_sums() {
    std::size_t single = 0;
    for (std::size_t b = 0; b < G::BLOCK_COUNT; ++b) {
        const G::GoldenBlock& blk = G::BLOCKS[b];
        std::uint64_t sum = g_weights[blk.miner_index];
        for (std::uint32_t k = 0; k < blk.tx_count; ++k)
            sum += g_weights[blk.tx_begin + k];

        checkf(sum == blk.block_weight,
               "block %llu: computed weight %llu vs monerod %u",
               static_cast<unsigned long long>(blk.height),
               static_cast<unsigned long long>(sum), blk.block_weight);

        if (blk.tx_count == 1) ++single;
    }
    checkf(single > 0,
           "corpus carries single-transaction blocks, which pin one weight exactly (%zu)",
           single);
    std::printf("  blocks: %zu checked against monerod block_weight, %zu of them single-tx\n",
                G::BLOCK_COUNT, single);
}

// ---------------------------------------------------------------------------
// The full-blob path, where the prunable part is measured rather than predicted.
// ---------------------------------------------------------------------------
static void test_full_blobs() {
    for (std::size_t i = 0; i < G::FULL_TX_COUNT; ++i) {
        const G::GoldenFullTx& g = G::FULL_TXS[i];
        std::vector<std::uint8_t> blob;
        checkf(from_hex(g.full_hex, blob), "full tx %s: hex decodes", g.id_hex);

        TxWeightInfo info;
        const TxParseStatus st = parse_tx_full(blob, info);
        checkf(st == TxParseStatus::Ok, "full tx %s: parse -> %s", g.id_hex, to_string(st));
        if (st != TxParseStatus::Ok) continue;

        checkf(!info.prunable_predicted, "full tx %s: the full path measures", g.id_hex);
        checkf(info.blob_size == blob.size(), "full tx %s: blob size invariant", g.id_hex);
        checkf(info.weight == g.weight, "full tx %s: weight %llu vs golden %u",
               g.id_hex, static_cast<unsigned long long>(info.weight), g.weight);

        // The two paths must agree: predicting the prunable length from the
        // pruned prefix must give back exactly what the full blob measured.
        std::vector<std::uint8_t> pruned(blob.begin(),
                                         blob.begin() + static_cast<long>(info.pruned_size));
        TxWeightInfo from_pruned;
        const TxParseStatus st2 = parse_tx_pruned(pruned, from_pruned);
        checkf(st2 == TxParseStatus::Ok, "full tx %s: its own prefix re-parses", g.id_hex);
        if (st2 == TxParseStatus::Ok)
            checkf(from_pruned.weight == info.weight,
                   "full tx %s: pruned and full paths agree (%llu vs %llu)", g.id_hex,
                   static_cast<unsigned long long>(from_pruned.weight),
                   static_cast<unsigned long long>(info.weight));
    }
    std::printf("  full blobs: %zu parsed on both paths\n", G::FULL_TX_COUNT);
}

// ---------------------------------------------------------------------------
// Truncation and corruption must be refused, never guessed at.
// ---------------------------------------------------------------------------
static void put_varint(std::vector<std::uint8_t>& v, std::uint64_t x) {
    while (x >= 0x80) { v.push_back(static_cast<std::uint8_t>(x) | 0x80u); x >>= 7; }
    v.push_back(static_cast<std::uint8_t>(x));
}

// A minimal but well-formed one-in one-out bulletproof-plus transaction, so a
// single field can be corrupted at a time.
static std::vector<std::uint8_t> synth_tx(std::uint64_t version,
                                          std::uint8_t  in_tag,
                                          std::uint8_t  out_tag,
                                          std::uint64_t n_in,
                                          std::uint64_t n_out,
                                          std::uint64_t extra_len_claim,
                                          std::size_t   extra_actual) {
    std::vector<std::uint8_t> v;
    put_varint(v, version);
    put_varint(v, 0);                 // unlock_time
    put_varint(v, n_in);
    for (std::uint64_t i = 0; i < n_in; ++i) {
        v.push_back(in_tag);
        put_varint(v, 0);             // amount
        put_varint(v, 16);            // ring size
        for (int k = 0; k < 16; ++k) put_varint(v, 1);
        v.insert(v.end(), 32, 0x55);  // key image
    }
    put_varint(v, n_out);
    for (std::uint64_t i = 0; i < n_out; ++i) {
        put_varint(v, 0);             // amount
        v.push_back(out_tag);
        v.insert(v.end(), 32, 0x66);  // one-time key
        if (out_tag == TX_OUT_TO_TAGGED_KEY) v.push_back(0x77);
    }
    put_varint(v, extra_len_claim);
    v.insert(v.end(), extra_actual, 0x00);
    if (version >= 2) {
        v.push_back(RCT_TYPE_BULLETPROOF_PLUS);
        put_varint(v, 30000);         // fee
        v.insert(v.end(), 8 * n_out, 0x01);   // ecdhInfo
        v.insert(v.end(), 32 * n_out, 0x02);  // outPk
    }
    return v;
}

static void test_rejects() {
    TxWeightInfo info;

    // The baseline must parse, or the negative cases prove nothing.
    const auto good = synth_tx(2, TX_IN_TO_KEY, TX_OUT_TO_TAGGED_KEY, 1, 2, 44, 44);
    check(parse_tx_pruned(good, info) == TxParseStatus::Ok,
          "the synthetic baseline transaction parses");
    check(info.n_inputs == 1 && info.n_outputs == 2 && info.extra_size == 44,
          "the synthetic baseline has the expected shape");

    // Every proper prefix of a valid blob must be refused.
    std::size_t refused = 0;
    for (std::size_t n = 0; n < good.size(); ++n) {
        std::vector<std::uint8_t> cut(good.begin(), good.begin() + static_cast<long>(n));
        TxWeightInfo cut_info;
        if (parse_tx_pruned(cut, cut_info) != TxParseStatus::Ok) ++refused;
    }
    checkf(refused == good.size(), "every truncation is refused (%zu of %zu)",
           refused, good.size());

    // Trailing garbage on the pruned path is a reject, not a shrug.
    std::vector<std::uint8_t> extended = good;
    extended.push_back(0xAA);
    check(parse_tx_pruned(extended, info) == TxParseStatus::TrailingBytes,
          "trailing bytes on a pruned blob are refused");

    // Version, tag and count errors, one at a time.
    check(parse_tx_pruned(synth_tx(0, TX_IN_TO_KEY, TX_OUT_TO_TAGGED_KEY, 1, 2, 0, 0), info)
              == TxParseStatus::UnsupportedVersion,
          "version 0 is refused");
    check(parse_tx_pruned(synth_tx(3, TX_IN_TO_KEY, TX_OUT_TO_TAGGED_KEY, 1, 2, 0, 0), info)
              == TxParseStatus::UnsupportedVersion,
          "a version beyond 2 is refused");
    check(parse_tx_pruned(synth_tx(2, 0x7E, TX_OUT_TO_TAGGED_KEY, 1, 2, 0, 0), info)
              == TxParseStatus::Malformed,
          "an unknown input tag is refused");
    check(parse_tx_pruned(synth_tx(2, TX_IN_TO_KEY, 0x05, 1, 2, 0, 0), info)
              == TxParseStatus::Malformed,
          "an unknown output tag is refused");
    check(parse_tx_pruned(synth_tx(2, TX_IN_TO_KEY, TX_OUT_TO_TAGGED_KEY, 0, 2, 0, 0), info)
              != TxParseStatus::Ok,
          "a transaction with no inputs is refused");
    check(parse_tx_pruned(synth_tx(2, TX_IN_TO_KEY, TX_OUT_TO_TAGGED_KEY, 1, 0, 0, 0), info)
              != TxParseStatus::Ok,
          "a transaction with no outputs is refused");

    // A tx_extra length the sender never backs with bytes must not make us
    // reserve anything: the count check refuses it against the bytes left.
    check(parse_tx_pruned(synth_tx(2, TX_IN_TO_KEY, TX_OUT_TO_TAGGED_KEY, 1, 2, 1u << 19, 4), info)
              == TxParseStatus::Truncated,
          "an over-claimed tx_extra length is refused against the bytes actually present");

    // A coinbase input may not appear beside a spend input.
    std::vector<std::uint8_t> mixed;
    put_varint(mixed, 2);
    put_varint(mixed, 0);
    put_varint(mixed, 2);            // two inputs
    mixed.push_back(TX_IN_GEN);      // the first of which is a coinbase input
    put_varint(mixed, 100);
    check(parse_tx_pruned(mixed, info) == TxParseStatus::Malformed,
          "a coinbase input may only be the single input of a coinbase");
}

int main() {
    std::printf("xmr_tx_weight_kat: golden from monerod %s (%s) at tip %llu\n",
                G::MONEROD_VERSION, G::NETWORK,
                static_cast<unsigned long long>(G::CAPTURE_TIP));
    test_arithmetic();
    test_transactions();
    test_block_weight_sums();
    test_full_blobs();
    test_rejects();
    std::printf("xmr_tx_weight_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
