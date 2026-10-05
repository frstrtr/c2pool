// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_coinbase_outputs_limit_kat.cpp
//
// MONERO'S TRANSACTION COUNT CEILINGS, AND NOTHING TIGHTER.
//
// The native parser (consensus/xmr_tx_weight.hpp) used to cap every
// transaction at 4096 outputs, 4096 inputs, 512 ring members per input and
// 1 MiB of tx_extra, and the block parser runs it on the coinbase. Monero
// allows (monero-project master f6a591c, cryptonote_basic.h:56-60):
//
//   MAX_COINBASE_VOUT_COUNT     = 100000000 / 32 = 3,125,000  (coinbase)
//   MAX_NON_COINBASE_VOUT_COUNT = 1000000 / 32   =    31,250
//   MAX_VIN_COUNT               = 1000000 / 32   =    31,250
//   MAX_TOTAL_KEY_OFFSETS       = 1000000 / 32   =    31,250  (sum over inputs,
//                                                    refused once reached)
//   tx_extra                    : no ceiling beyond the bytes present
//
// so a valid Monero block whose coinbase had more than 4096 outputs was refused
// by the native node, which then stopped following Monero. From the FCMP++ fork
// (fcmp++-stage: HF_VERSION_REJECT_MANY_MINER_OUTPUTS = 17) Monero adds a
// miner-tx rule, vout.size() <= FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS = 10,000,
// judged in prevalidate_miner_transaction; here it is judged in
// ConsensusState::connect, keyed on the block's major version.
//
// WHAT RUNS (integer-only, deterministic, synthetic blobs).
//   A. The ceilings and the version-keyed miner-output bound, at their edges.
//   B. A v16 block whose coinbase has 5,000 outputs (and one with 4,097):
//      parses, evaluates, and CONNECTS on a fresh mainnet state with an exact
//      coinbase amount.
//   C. A v16 block whose coinbase has exactly 3,125,000 outputs parses and its
//      coinbase fields read back; the parse allocates nothing from the count.
//   D. Above the ceilings: count-only mutations refused with CountTooLarge,
//      and a count AT the ceiling with too few bytes refused as Truncated.
//   E. A truncated buffer with a huge count is refused without a large
//      allocation (block parser, coinbase field reader, txpool decoder).
//   F. The v17 miner-output rule at connect time.
//   G. Non-coinbase, inputs, key offsets, extra: Monero's bounds, both sides.
//
// Fails on the pre-fix tree: B, C, F and G are refused there, and E's coinbase
// field reader reserves from the count. (The file does not compile there
// either: the Monero-named constants are new.)
// ---------------------------------------------------------------------------
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_block_eval.hpp"
#include "impl/xmr/native/chain/xmr_consensus_state.hpp"
#include "impl/xmr/native/consensus/xmr_blob_reader.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/consensus/xmr_tx_weight.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"

using namespace c2pool::xmr::native;

// ---------------------------------------------------------------------------
// Allocation tracker. Every non-aligned operator new / delete is replaced (all
// of the family, so a sanitizer runtime never sees a split pair); while armed,
// the size of every request is recorded. "No large allocation" below means the
// largest single request stayed under a stated bound.
// ---------------------------------------------------------------------------
namespace alloc_track {
std::atomic<bool>        armed{false};
std::atomic<std::size_t> peak{0};
std::atomic<std::size_t> total{0};

inline void note(std::size_t n) noexcept {
    if (!armed.load(std::memory_order_relaxed)) return;
    total.fetch_add(n, std::memory_order_relaxed);
    std::size_t p = peak.load(std::memory_order_relaxed);
    while (n > p && !peak.compare_exchange_weak(p, n, std::memory_order_relaxed)) {}
}
inline void arm() noexcept {
    peak.store(0);
    total.store(0);
    armed.store(true);
}
inline void disarm() noexcept { armed.store(false); }
} // namespace alloc_track

static void* tracked_malloc(std::size_t n) noexcept {
    alloc_track::note(n);
    return std::malloc(n ? n : 1);
}
void* operator new(std::size_t n) {
    if (void* p = tracked_malloc(n)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t n) {
    if (void* p = tracked_malloc(n)) return p;
    throw std::bad_alloc();
}
void* operator new(std::size_t n, const std::nothrow_t&) noexcept { return tracked_malloc(n); }
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept { return tracked_malloc(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }

// ---------------------------------------------------------------------------
static int g_checks = 0;
static int g_fail   = 0;

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 40) {
            va_list ap;
            va_start(ap, fmt);
            std::fputs("FAIL: ", stderr);
            std::vfprintf(stderr, fmt, ap);
            va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

using Bytes = std::vector<std::uint8_t>;

static void put_varint(Bytes& b, std::uint64_t v) { blob_write_varint(b, v); }

// A deterministic 32-byte value. The parser does not check points.
static void put_key(Bytes& b, std::uint64_t seed) {
    std::uint64_t x = seed * 0x9E3779B97F4A7C15ull + 0x632BE59BD9B4E019ull;
    for (int i = 0; i < 32; ++i) {
        x ^= x >> 29; x *= 0xBF58476D1CE4E5B9ull; x ^= x >> 32;
        b.push_back(static_cast<std::uint8_t>(x));
    }
}

// The varint length of v.
static std::size_t varint_len(std::uint64_t v) {
    std::size_t n = 1;
    while (v >= 0x80) { v >>= 7; ++n; }
    return n;
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

// A version-2 coinbase (miner tx) with `declared` outputs in its count and the
// first `present` of them written out (tagged keys, the v15+ shape). When
// `complete`, the extra (a tx pubkey) and the rct NULL byte follow; when not,
// the bytes stop after the last written output.
struct CoinbaseSpec {
    std::uint64_t height   = 1;
    std::uint64_t declared = 0;
    std::uint64_t present  = 0;
    bool          complete = true;
    // amount of output i; default 1 piconero
    std::uint64_t base_amount = 1;
    std::uint64_t first_extra = 0;   // added to output 0
};

// Appends the coinbase to `b` (in place: the 3,125,000-output block is ~110 MB
// and is never copied).
static void append_coinbase(Bytes& b, const CoinbaseSpec& s) {
    b.reserve(b.size() + static_cast<std::size_t>(s.present) * 41 + 64);
    put_varint(b, 2);                       // version
    put_varint(b, s.height + 60);           // unlock_time
    put_varint(b, 1);                       // vin count
    b.push_back(TX_IN_GEN);
    put_varint(b, s.height);
    put_varint(b, s.declared);              // vout count
    for (std::uint64_t i = 0; i < s.present; ++i) {
        put_varint(b, s.base_amount + (i == 0 ? s.first_extra : 0));
        b.push_back(TX_OUT_TO_TAGGED_KEY);
        put_key(b, i);
        b.push_back(static_cast<std::uint8_t>(i));   // view tag
    }
    if (s.complete) {
        put_varint(b, 33);                  // extra: tx pubkey
        b.push_back(0x01);
        put_key(b, 0xC0FFEE);
        b.push_back(RCT_TYPE_NULL);
    }
}

static Bytes coinbase_tx(const CoinbaseSpec& s) {
    Bytes b;
    append_coinbase(b, s);
    return b;
}

static Bytes block_header(std::uint64_t major, std::uint64_t timestamp = 1) {
    Bytes b;
    put_varint(b, major);
    put_varint(b, major);                   // minor >= major from v8
    put_varint(b, timestamp);
    for (int i = 0; i < 32; ++i) b.push_back(0);   // prev_id
    for (int i = 0; i < 4; ++i) b.push_back(0);    // nonce
    return b;
}

static Bytes block_blob(std::uint64_t major, const Bytes& miner_tx, bool with_tx_count = true) {
    Bytes b = block_header(major);
    b.reserve(b.size() + miner_tx.size() + 1);
    b.insert(b.end(), miner_tx.begin(), miner_tx.end());
    if (with_tx_count) put_varint(b, 0);    // no other transactions
    return b;
}

static Bytes block_blob(std::uint64_t major, const CoinbaseSpec& s) {
    Bytes b = block_header(major);
    append_coinbase(b, s);
    put_varint(b, 0);
    return b;
}

// A version-1 non-coinbase: one txin_to_key per entry of `rings` (that many
// key offsets each), `n_out` txout_to_key outputs of 1 piconero, `extra_len`
// zero bytes of extra, then the ring signatures (64 bytes per ring member).
// `declared_out` overrides the output count written (0 = n_out); with
// `stop_after_count`, the bytes stop right after the output count.
static Bytes tx_v1(const std::vector<std::uint64_t>& rings, std::uint64_t n_out,
                   std::uint64_t extra_len = 0, std::uint64_t declared_out = 0,
                   bool stop_after_count = false) {
    Bytes b;
    put_varint(b, 1);                       // version
    put_varint(b, 0);                       // unlock_time
    put_varint(b, rings.size());
    std::uint64_t ring_sum = 0;
    for (std::size_t i = 0; i < rings.size(); ++i) {
        b.push_back(TX_IN_TO_KEY);
        put_varint(b, 1000000000000ull);    // amount (clear in v1)
        put_varint(b, rings[i]);
        for (std::uint64_t k = 0; k < rings[i]; ++k) put_varint(b, 1);
        put_key(b, 0x10000000ull + i);      // key image
        ring_sum += rings[i];
    }
    put_varint(b, declared_out ? declared_out : n_out);
    if (stop_after_count) return b;
    for (std::uint64_t i = 0; i < n_out; ++i) {
        put_varint(b, 1);
        b.push_back(TX_OUT_TO_KEY);
        put_key(b, 0x20000000ull + i);
    }
    put_varint(b, extra_len);
    b.insert(b.end(), static_cast<std::size_t>(extra_len), std::uint8_t{0});
    b.insert(b.end(), static_cast<std::size_t>(ring_sum * 64), std::uint8_t{0});
    return b;
}

// A version-2 BulletproofPlus transaction with one input of `ring` members and
// two outputs, complete unless `truncate_at` (bytes kept) is non-zero. With
// rct_type_override, the rct type byte is replaced (for the unknown-format
// peek) and the bytes stop right after it.
static Bytes tx_bpp(std::uint64_t ring, std::uint64_t n_out = 2, std::size_t truncate_at = 0,
                    int rct_type_override = -1) {
    Bytes b;
    put_varint(b, 2);
    put_varint(b, 0);
    put_varint(b, 1);
    b.push_back(TX_IN_TO_KEY);
    put_varint(b, 0);
    put_varint(b, ring);
    for (std::uint64_t k = 0; k < ring; ++k) put_varint(b, 1);
    put_key(b, 0xAAAA);                     // key image
    put_varint(b, n_out);
    for (std::uint64_t i = 0; i < n_out; ++i) {
        put_varint(b, 0);
        b.push_back(TX_OUT_TO_TAGGED_KEY);
        put_key(b, 0xB000 + i);
        b.push_back(0x5A);
    }
    put_varint(b, 0);                       // extra
    if (rct_type_override >= 0) {
        b.push_back(static_cast<std::uint8_t>(rct_type_override));
        return b;
    }
    b.push_back(RCT_TYPE_BULLETPROOF_PLUS);
    put_varint(b, 30000);                   // fee
    b.insert(b.end(), static_cast<std::size_t>(8 * n_out), std::uint8_t{0x11});   // ecdhInfo
    for (std::uint64_t i = 0; i < n_out; ++i) put_key(b, 0xC000 + i);             // outPk
    // prunable: one proof, A A1 B r1 s1 d1, L[7], R[7], CLSAG, pseudoOut
    put_varint(b, 1);
    for (int i = 0; i < 6; ++i) put_key(b, 0xD000 + i);
    const std::uint64_t nlr = bp_nlr_for(n_padded_outputs_for(static_cast<std::size_t>(n_out)));
    put_varint(b, nlr);
    for (std::uint64_t i = 0; i < nlr; ++i) put_key(b, 0xE000 + i);
    put_varint(b, nlr);
    for (std::uint64_t i = 0; i < nlr; ++i) put_key(b, 0xF000 + i);
    for (std::uint64_t k = 0; k < ring; ++k) put_key(b, 0x100000 + k);   // s[ring]
    put_key(b, 0x200000);                   // c1
    put_key(b, 0x200001);                   // D
    put_key(b, 0x200002);                   // pseudoOut
    if (truncate_at && truncate_at < b.size()) b.resize(truncate_at);
    return b;
}

// The reader error the prefix parser stops on (None when it parses).
static BlobError prefix_error(const Bytes& tx, TxParseStatus* st_out = nullptr) {
    BlobReader r(tx.data(), tx.size());
    TxWeightInfo info;
    const TxParseStatus st = detail::parse_tx_prefix(r, info);
    if (st_out) *st_out = st;
    return r.error();
}

// ---------------------------------------------------------------------------
// A. The ceilings at their edges.
// ---------------------------------------------------------------------------
static void test_a_ceilings() {
    checkf(MAX_COINBASE_VOUT_COUNT == 3125000, "A: MAX_COINBASE_VOUT_COUNT is 100000000 / 32");
    checkf(MAX_NON_COINBASE_VOUT_COUNT == 31250, "A: MAX_NON_COINBASE_VOUT_COUNT is 1000000 / 32");
    checkf(MAX_VIN_COUNT == 31250, "A: MAX_VIN_COUNT is 1000000 / 32");
    checkf(MAX_TOTAL_KEY_OFFSETS == 31250, "A: MAX_TOTAL_KEY_OFFSETS is 1000000 / 32");
    checkf(max_vout_count(true) == 3125000, "A: the coinbase vout ceiling");
    checkf(max_vout_count(false) == 31250, "A: the non-coinbase vout ceiling");

    checkf(HF_VERSION_REJECT_MANY_MINER_OUTPUTS == 17, "A: HF_VERSION_REJECT_MANY_MINER_OUTPUTS");
    checkf(FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS == 10000, "A: FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS");
    for (std::uint64_t v = 1; v <= 16; ++v)
        checkf(max_miner_tx_outputs(v) == 3125000, "A: v%llu miner-output bound is the parse ceiling",
               static_cast<unsigned long long>(v));
    checkf(max_miner_tx_outputs(17) == 10000, "A: v17 miner-output bound");
    checkf(max_miner_tx_outputs(18) == 10000, "A: v18 miner-output bound");
    checkf(miner_tx_output_count_ok(16, 3125000), "A: v16 3,125,000 ok");
    checkf(!miner_tx_output_count_ok(16, 3125001), "A: v16 3,125,001 refused");
    checkf(miner_tx_output_count_ok(16, 10001), "A: v16 10,001 ok");
    checkf(miner_tx_output_count_ok(17, 10000), "A: v17 10,000 ok");
    checkf(!miner_tx_output_count_ok(17, 10001), "A: v17 10,001 refused");
}

// ---------------------------------------------------------------------------
// B. 5,000 and 4,097 coinbase outputs at v16: parse, evaluate, connect.
// ---------------------------------------------------------------------------
static bool build_connectable(std::uint64_t n_out, Bytes& blob_out, std::uint64_t& base_out) {
    const std::uint64_t base = emission_base_reward(0, 16);
    CoinbaseSpec s;
    s.height      = 1;
    s.declared    = n_out;
    s.present     = n_out;
    s.base_amount = base / n_out;
    s.first_extra = base % n_out;
    blob_out = block_blob(16, s);
    base_out = base;
    return varint_len(s.base_amount) == varint_len(s.base_amount + s.first_extra);
}

static EvaluatedBlock g_ev5000;   // reused by F
static bool           g_ev5000_ok = false;

static void test_b_connect(std::uint64_t n_out) {
    Bytes blob;
    std::uint64_t base = 0;
    const unsigned long long n = static_cast<unsigned long long>(n_out);
    checkf(build_connectable(n_out, blob, base), "B[%llu]: every amount has one varint length", n);

    ParsedBlock pb;
    const BlockParseStatus ps = parse_block(blob, pb);
    checkf(ps == BlockParseStatus::Ok, "B[%llu]: parse_block is Ok (got %s)", n, to_string(ps));
    if (ps != BlockParseStatus::Ok) return;
    checkf(pb.miner_tx.is_coinbase, "B[%llu]: the miner tx is a coinbase", n);
    checkf(pb.miner_tx.n_outputs == n_out, "B[%llu]: n_outputs read back", n);
    checkf(pb.miner_tx.weight == pb.miner_tx_size, "B[%llu]: coinbase weight is its size", n);

    CoinbaseFields cb;
    checkf(parse_coinbase_fields(blob.data(), pb, cb, /*capture=*/true),
           "B[%llu]: coinbase fields read back", n);
    checkf(cb.n_outputs == n_out && cb.outputs.size() == n_out, "B[%llu]: all outputs captured", n);
    checkf(cb.output_sum == base, "B[%llu]: the outputs pay exactly the base reward", n);
    checkf(cb.height == 1, "B[%llu]: coinbase height", n);

    BlockEntry e;
    e.block_blob = blob;
    EvaluatedBlock ev;
    std::string why;
    const EvalStatus es = evaluate_block(e, ev, why);
    checkf(es == EvalStatus::Ok, "B[%llu]: evaluate_block is Ok (got %s: %s)", n, to_string(es), why.c_str());
    if (es != EvalStatus::Ok) return;
    checkf(ev.input.bodies_complete, "B[%llu]: no bodies needed", n);
    checkf(ev.input.block_weight == pb.miner_tx_size, "B[%llu]: block weight is the coinbase", n);
    checkf(ev.input.block_weight <= 300000, "B[%llu]: the block sits in the penalty-free zone", n);

    ConsensusState st(XmrNet::Mainnet);
    st.seed_empty(0);
    ChainRow row;
    ConnectUndo undo;
    const ConnectStatus cs = st.connect(ev.input, /*now=*/0, row, undo, why);
    checkf(cs == ConnectStatus::Ok, "B[%llu]: connect is Ok (got %s: %s)", n, to_string(cs), why.c_str());
    checkf(st.height() == 1, "B[%llu]: the tip moved to height 1", n);
    checkf(row.reward == base, "B[%llu]: the row records the reward", n);

    if (n_out == 5000) {
        g_ev5000    = ev;
        g_ev5000_ok = (cs == ConnectStatus::Ok);
    }
}

// ---------------------------------------------------------------------------
// C. Exactly 3,125,000 coinbase outputs at v16.
// ---------------------------------------------------------------------------
static void test_c_exact_ceiling() {
    CoinbaseSpec s;
    s.height   = 1;
    s.declared = MAX_COINBASE_VOUT_COUNT;
    s.present  = MAX_COINBASE_VOUT_COUNT;
    Bytes blob = block_blob(16, s);
    checkf(blob.size() > 100000000, "C: the blob carries 3,125,000 outputs (%zu bytes)", blob.size());

    ParsedBlock pb;
    alloc_track::arm();
    const BlockParseStatus ps = parse_block(blob, pb);
    alloc_track::disarm();
    checkf(ps == BlockParseStatus::Ok, "C: parse_block is Ok at exactly 3,125,000 (got %s)", to_string(ps));
    checkf(pb.miner_tx.n_outputs == MAX_COINBASE_VOUT_COUNT, "C: n_outputs read back");
    checkf(alloc_track::peak.load() < 4096,
           "C: parsing 3,125,000 outputs allocated nothing from the count (largest request %zu)",
           alloc_track::peak.load());

    CoinbaseFields cb;
    alloc_track::arm();
    const bool ok = parse_coinbase_fields(blob.data(), pb, cb, /*capture=*/false);
    alloc_track::disarm();
    checkf(ok, "C: coinbase fields read back");
    checkf(cb.n_outputs == MAX_COINBASE_VOUT_COUNT, "C: coinbase n_outputs");
    checkf(cb.output_sum == MAX_COINBASE_VOUT_COUNT, "C: coinbase output sum (1 each)");
    checkf(alloc_track::total.load() == 0, "C: reading the fields without capture allocates nothing");
}

// ---------------------------------------------------------------------------
// D. Above the ceilings, by count-only mutation.
// ---------------------------------------------------------------------------
static void test_d_above() {
    // Coinbase: the count is checked before the bytes.
    {
        CoinbaseSpec s;
        s.declared = MAX_COINBASE_VOUT_COUNT + 1;
        s.present  = 4;
        const Bytes cb = coinbase_tx(s);
        TxParseStatus st{};
        checkf(prefix_error(cb, &st) == BlobError::CountTooLarge,
               "D: a coinbase count of 3,125,001 is above the ceiling");
        checkf(st != TxParseStatus::Ok, "D: and the prefix is refused");
        ParsedBlock pb;
        checkf(parse_block(block_blob(16, cb), pb) == BlockParseStatus::BadMinerTx,
               "D: a block with a 3,125,001-output coinbase is refused");
    }
    {
        // AT the ceiling with too few bytes: passes the ceiling, fails the
        // bytes-present floor. This pins the ceiling as inclusive.
        CoinbaseSpec s;
        s.declared = MAX_COINBASE_VOUT_COUNT;
        s.present  = 4;
        checkf(prefix_error(coinbase_tx(s)) == BlobError::Truncated,
               "D: a coinbase count of exactly 3,125,000 passes the ceiling (refused only as truncated)");
    }
    {
        CoinbaseSpec s;
        s.declared = ~std::uint64_t{0};
        s.present  = 0;
        checkf(prefix_error(coinbase_tx(s)) == BlobError::CountTooLarge,
               "D: a coinbase count of 2^64-1 is above the ceiling");
    }
    // Non-coinbase: 31,250.
    checkf(prefix_error(tx_v1({1}, 0, 0, MAX_NON_COINBASE_VOUT_COUNT + 1, true)) == BlobError::CountTooLarge,
           "D: a non-coinbase count of 31,251 is above the ceiling");
    checkf(prefix_error(tx_v1({1}, 0, 0, MAX_NON_COINBASE_VOUT_COUNT, true)) == BlobError::Truncated,
           "D: a non-coinbase count of exactly 31,250 passes the ceiling");
    checkf(prefix_error(tx_v1({1}, 0, 0, 40000, true)) == BlobError::CountTooLarge,
           "D: a non-coinbase never gets the coinbase ceiling");
    // Inputs: 31,250.
    {
        Bytes b;
        put_varint(b, 1);
        put_varint(b, 0);
        put_varint(b, MAX_VIN_COUNT + 1);
        checkf(prefix_error(b) == BlobError::CountTooLarge, "D: an input count of 31,251 is above the ceiling");
        Bytes c;
        put_varint(c, 1);
        put_varint(c, 0);
        put_varint(c, MAX_VIN_COUNT);
        checkf(prefix_error(c) == BlobError::Truncated, "D: an input count of exactly 31,250 passes the ceiling");
    }
}

// ---------------------------------------------------------------------------
// E. A truncated buffer with a huge count: refused, no large allocation.
// ---------------------------------------------------------------------------
static void test_e_truncated_no_alloc() {
    for (std::uint64_t declared : {MAX_COINBASE_VOUT_COUNT, std::uint64_t{1} << 62}) {
        const unsigned long long d = static_cast<unsigned long long>(declared);
        CoinbaseSpec s;
        s.declared = declared;
        s.present  = 2;
        s.complete = false;
        const Bytes cb = coinbase_tx(s);
        const Bytes blob = block_blob(16, cb, /*with_tx_count=*/false);

        ParsedBlock pb;
        alloc_track::arm();
        const BlockParseStatus ps = parse_block(blob, pb);
        alloc_track::disarm();
        checkf(ps == BlockParseStatus::BadMinerTx, "E[%llu]: the truncated block is refused (%s)", d, to_string(ps));
        checkf(alloc_track::peak.load() < 4096, "E[%llu]: parse_block made no large allocation (largest %zu)",
               d, alloc_track::peak.load());

        // The coinbase field reader on a span parse_block never accepted: it
        // must refuse it, not reserve from the count (125 MB at 3,125,000,
        // a length_error at 2^62).
        ParsedBlock fake;
        fake.miner_tx_offset = blob.size() - cb.size();
        fake.miner_tx_size   = cb.size();
        CoinbaseFields f;
        bool ok = true, threw = false;
        alloc_track::arm();
        try {
            ok = parse_coinbase_fields(blob.data(), fake, f, /*capture=*/true);
        } catch (const std::exception&) {
            threw = true;
        }
        alloc_track::disarm();
        checkf(!threw, "E[%llu]: the coinbase field reader does not throw", d);
        checkf(!ok, "E[%llu]: the coinbase field reader refuses the truncated span", d);
        checkf(alloc_track::peak.load() < 4096,
               "E[%llu]: the coinbase field reader reserved nothing from the count (largest %zu)",
               d, alloc_track::peak.load());
    }

    // The txpool decoder sizes each CLSAG only once its bytes are present. A
    // ring of 31,249 (the largest one input may have) whose prunable part is
    // cut short must be refused before a 31,249-scalar vector is allocated.
    {
        const std::uint64_t ring = MAX_TOTAL_KEY_OFFSETS - 1;
        Bytes full = tx_bpp(ring);
        const std::size_t keep = full.size() - static_cast<std::size_t>(ring) * 32 / 2;
        Bytes cut = tx_bpp(ring, 2, keep);
        DecodedTx d;
        alloc_track::arm();
        const TxDecodeStatus ds = decode_relayed_tx(cut, d);
        alloc_track::disarm();
        checkf(ds == TxDecodeStatus::PrunableMalformed,
               "E: a truncated ring-31,249 transaction is refused as PrunableMalformed (got %s)", to_string(ds));
        checkf(alloc_track::peak.load() < static_cast<std::size_t>(ring) * 32,
               "E: the decoder did not size the CLSAG before its bytes were present (largest %zu)",
               alloc_track::peak.load());
    }
}

// ---------------------------------------------------------------------------
// F. The v17 miner-output rule, judged at connect time by major version.
// ---------------------------------------------------------------------------
static ConnectStatus connect_with(std::uint64_t major, std::uint64_t n_outputs, std::string& why) {
    BlockConnectInput in = g_ev5000.input;
    in.parsed.header.major_version = major;
    in.parsed.header.minor_version = major;
    in.parsed.miner_tx.n_outputs   = static_cast<std::size_t>(n_outputs);
    ConsensusState st(XmrNet::Mainnet);
    st.seed_empty(0);
    ChainRow row;
    ConnectUndo undo;
    return st.connect(in, /*now=*/0, row, undo, why);
}

static void test_f_v17_rule() {
    checkf(g_ev5000_ok, "F: the 5,000-output block from B connects (prerequisite)");
    if (!g_ev5000_ok) return;
    std::string why;

    checkf(connect_with(16, 10001, why) == ConnectStatus::Ok,
           "F: v16 has no miner-output rule below the parse ceiling (%s)", why.c_str());
    checkf(connect_with(16, MAX_COINBASE_VOUT_COUNT, why) == ConnectStatus::Ok,
           "F: v16 at the parse ceiling (%s)", why.c_str());
    checkf(connect_with(17, 10000, why) == ConnectStatus::Ok,
           "F: v17 at FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS connects (%s)", why.c_str());
    const ConnectStatus s17 = connect_with(17, 10001, why);
    checkf(s17 == ConnectStatus::BadCoinbase, "F: v17 with 10,001 miner outputs is refused (got %s)", to_string(s17));
    checkf(why.find("10001 outputs") != std::string::npos, "F: and the reason names the count (%s)", why.c_str());
    checkf(connect_with(18, 10001, why) == ConnectStatus::BadCoinbase, "F: the rule holds above v17");

    // The parse ceiling does not move with the version (as in Monero, where
    // the v17 rule is a validation rule, not a parse rule).
    CoinbaseSpec s;
    s.declared = 10001;
    s.present  = 10001;
    ParsedBlock pb;
    checkf(parse_block(block_blob(17, s), pb) == BlockParseStatus::Ok,
           "F: a v17-header block with 10,001 coinbase outputs still parses");
}

// ---------------------------------------------------------------------------
// G. Non-coinbase outputs, inputs, key offsets, extra.
// ---------------------------------------------------------------------------
static void expect_tx_ok(const Bytes& tx, const char* what) {
    TxWeightInfo full, pruned;
    const TxParseStatus a = parse_tx_full(tx, full);
    const TxParseStatus b = parse_tx_pruned(tx, pruned);   // v1: measures the signatures exactly
    checkf(a == TxParseStatus::Ok, "G: %s: parse_tx_full is Ok (got %s)", what, to_string(a));
    checkf(b == TxParseStatus::Ok, "G: %s: parse_tx_pruned is Ok (got %s)", what, to_string(b));
}

static void test_g_other_bounds() {
    expect_tx_ok(tx_v1({1}, 4097), "4,097 non-coinbase outputs");
    expect_tx_ok(tx_v1({1}, MAX_NON_COINBASE_VOUT_COUNT), "31,250 non-coinbase outputs");

    expect_tx_ok(tx_v1(std::vector<std::uint64_t>(4097, 1), 2), "4,097 inputs");

    expect_tx_ok(tx_v1({513}, 2), "one ring of 513");
    expect_tx_ok(tx_v1({MAX_TOTAL_KEY_OFFSETS - 1}, 2), "one ring of 31,249");
    checkf(prefix_error(tx_v1({MAX_TOTAL_KEY_OFFSETS}, 2)) == BlobError::CountTooLarge,
           "G: one ring of 31,250 is refused (the total reached MAX_TOTAL_KEY_OFFSETS)");
    expect_tx_ok(tx_v1({20000, 11249}, 2), "rings 20,000 + 11,249");
    checkf(prefix_error(tx_v1({20000, 11250}, 2)) == BlobError::CountTooLarge,
           "G: rings 20,000 + 11,250 are refused (the total reached MAX_TOTAL_KEY_OFFSETS)");

    expect_tx_ok(tx_v1({1}, 2, (1u << 20) + 1), "1 MiB + 1 of tx_extra");

    // The txpool decoder follows the same bounds: a ring above the old 512
    // decodes (the txpool's ring-size POLICY then judges it), and the
    // unknown-format peek reads past more than 4,096 outputs.
    {
        DecodedTx d;
        const TxDecodeStatus ds = decode_relayed_tx(tx_bpp(600), d);
        checkf(ds == TxDecodeStatus::Ok, "G: a BP+ transaction with a ring of 600 decodes (got %s)", to_string(ds));
        checkf(d.clsags.size() == 1 && d.clsags[0].s.size() == 600, "G: and its CLSAG has 600 scalars");
    }
    checkf(tx_format_above_implemented(tx_bpp(16, 5000, 0, /*rct_type=*/7)),
           "G: an rct-type-7 transaction with 5,000 outputs is recognised as above the implemented format");
}

int main() {
    test_a_ceilings();
    test_b_connect(4097);
    test_b_connect(5000);
    test_c_exact_ceiling();
    test_d_above();
    test_e_truncated_no_alloc();
    test_f_v17_rule();
    test_g_other_bounds();

    std::printf("xmr_native_coinbase_outputs_limit_kat: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
