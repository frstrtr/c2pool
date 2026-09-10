// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_blob_reader_fuzz_kat.cpp
//
// BlobReader unit checks plus a DETERMINISTIC fuzz pass.
//
// Deterministic on purpose: a fixed-seed PRNG and a fixed corpus mean a failure
// here reproduces exactly, on any host, forever. This is a KAT that happens to
// generate its inputs, not a random search that happens to run in CI.
//
// Three passes:
//
//   1. UNIT -- the bounds, poisoning, varint canonicality and depth rules, each
//      asserted directly.
//   2. STRUCTURED FUZZ -- random byte strings driven through a recursive walker
//      that uses the depth guard the way a real decoder would. The invariants
//      checked on every single step are the ones that make the reader safe:
//      the cursor never passes the end, a failed read never advances it, and a
//      poisoned reader stays poisoned.
//   3. CORPUS FUZZ -- real transaction blobs from the weight golden, mutated
//      (bit flips, truncations, insertions, deletions, splices) and fed to the
//      transaction parser. A mutant must either be refused or parse to a
//      SELF-CONSISTENT result; it may never do anything else.
//
// This target is also the one to run under the sanitizer leg: the invariants
// below catch a logic error, and ASan/UBSan catch anything that gets past them.
// ---------------------------------------------------------------------------

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/consensus/xmr_blob_reader.hpp"
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

// --- deterministic PRNG (xorshift64*) ---------------------------------------
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    std::uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 0x2545F4914F6CDD1Dull;
    }
    std::uint32_t below(std::uint32_t n) { return n ? static_cast<std::uint32_t>(next() % n) : 0; }
};

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
// 1. Unit checks
// ---------------------------------------------------------------------------
static void test_bounds_and_poison() {
    const std::uint8_t buf[] = {0x01, 0x02, 0x03, 0x04};
    BlobReader r(buf, sizeof(buf));

    check(r.ok() && r.size() == 4 && r.offset() == 0, "a fresh reader is clean");

    std::uint8_t b = 0;
    check(r.read_byte(b) && b == 0x01, "first byte reads");
    check(r.offset() == 1, "the cursor advanced by one");

    std::uint32_t u = 0;
    check(!r.read_u32_le(u), "a read past the end fails");
    check(r.offset() == 1, "a failed read did not move the cursor");
    check(!r.ok() && r.error() == BlobError::Truncated, "the reader is poisoned and says why");

    // Poison is sticky: nothing succeeds afterwards, whatever is asked.
    check(!r.read_byte(b), "a poisoned reader refuses further reads");
    check(!r.skip(0), "a poisoned reader refuses even a zero-length skip");
    std::uint64_t v = 0;
    check(!r.read_varint(v), "a poisoned reader refuses varints");
    check(r.offset() == 1, "and never moves again");

    // An empty reader is legal and immediately at the end.
    BlobReader empty(nullptr, 0);
    check(empty.ok() && empty.eof() && empty.remaining() == 0, "an empty reader is well defined");
    check(!empty.read_byte(b), "an empty reader has nothing to read");

    // A null pointer with a non-zero length is treated as empty, not as memory.
    BlobReader lying(nullptr, 1024);
    check(lying.size() == 0, "a null buffer has no size whatever the caller claims");
}

static void test_varint() {
    struct Case { const char* name; std::vector<std::uint8_t> bytes;
                  bool ok; std::uint64_t value; BlobError err; };

    const std::vector<Case> cases = {
        { "zero",        {0x00},                                       true,  0, BlobError::None },
        { "one byte",    {0x7F},                                       true,  127, BlobError::None },
        { "two bytes",   {0x80, 0x01},                                 true,  128, BlobError::None },
        { "max uint64",  {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x01},
                          true, 0xFFFFFFFFFFFFFFFFull, BlobError::None },
        { "overflow",    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x02},
                          false, 0, BlobError::VarintOverflow },
        { "non-canonical", {0x80, 0x00},                               false, 0, BlobError::VarintNonCanonical },
        { "truncated",   {0x80},                                       false, 0, BlobError::Truncated },
        { "empty",       {},                                           false, 0, BlobError::Truncated },
    };

    for (const Case& c : cases) {
        BlobReader r(c.bytes.data(), c.bytes.size());
        std::uint64_t v = 0;
        const bool got = r.read_varint(v);
        check(got == c.ok, (std::string("varint ") + c.name + ": accepted as expected").c_str());
        if (c.ok) {
            check(v == c.value, (std::string("varint ") + c.name + ": value").c_str());
            check(r.eof(), (std::string("varint ") + c.name + ": consumed exactly").c_str());
        } else {
            check(r.error() == c.err, (std::string("varint ") + c.name + ": error kind").c_str());
            check(r.offset() == 0, (std::string("varint ") + c.name + ": cursor rewound").c_str());
        }
    }

    // A ten-byte encoding is the longest legal one; an eleventh continuation
    // byte can only be an overflow.
    const std::uint8_t eleven[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x01};
    BlobReader r(eleven, sizeof(eleven));
    std::uint64_t v = 0;
    check(!r.read_varint(v) && r.error() == BlobError::VarintOverflow,
          "an eleven-byte varint overflows");
}

static void test_count_and_depth() {
    // A count the caller's bound forbids.
    const std::uint8_t big[] = {0xFF, 0x7F};   // 16383
    BlobReader r(big, sizeof(big));
    std::uint64_t n = 0;
    check(!r.read_count(n, 100) && r.error() == BlobError::CountTooLarge,
          "a count above the caller's bound is refused");

    // A count the bound allows but the remaining bytes cannot back.
    const std::uint8_t modest[] = {0x40, 0x01, 0x02};   // 64, then 2 bytes left
    BlobReader r2(modest, sizeof(modest));
    check(!r2.read_count(n, 4096, 32) && r2.error() == BlobError::Truncated,
          "a count that outruns the bytes present is refused before allocating");

    // A count that is affordable.
    const std::uint8_t small[] = {0x02, 0x01, 0x02};   // 2, then 2 bytes left
    BlobReader r3(small, sizeof(small));
    check(r3.read_count(n, 4096, 1) && n == 2,
          "an affordable count is accepted");

    // Depth: eight nested guards are fine, the ninth is not.
    const std::uint8_t one[] = {0x00};
    BlobReader r4(one, sizeof(one));
    {
        std::vector<BlobReader::DepthGuard*> guards;
        for (std::size_t i = 0; i < BLOB_MAX_DEPTH; ++i) {
            auto* g = new BlobReader::DepthGuard(r4);
            check(g->entered(), "nesting within the cap is allowed");
            guards.push_back(g);
        }
        check(r4.depth() == BLOB_MAX_DEPTH, "depth counts the open guards");
        {
            BlobReader::DepthGuard too_deep(r4);
            check(!too_deep.entered(), "the guard past the cap does not enter");
            check(r4.error() == BlobError::DepthExceeded, "and poisons the reader");
        }
        for (auto it = guards.rbegin(); it != guards.rend(); ++it) delete *it;
    }
    check(r4.depth() == 0, "every guard released its level");
}

// ---------------------------------------------------------------------------
// 2. Structured fuzz over random bytes
// ---------------------------------------------------------------------------
// Violations are recorded rather than asserted per step: the walk runs millions
// of steps, and a check per step would drown the report.
static const char* g_violation    = nullptr;
static std::size_t g_max_depth_seen = 0;

static void violate(const char* what) {
    if (!g_violation) g_violation = what;
}

// Walks a random byte string the way a nested decoder would, checking the
// reader's invariants at every step.
static void walk(BlobReader& r, Rng& rng, std::size_t& steps) {
    BlobReader::DepthGuard g(r);
    if (!g.entered()) return;
    if (r.depth() > g_max_depth_seen) g_max_depth_seen = r.depth();
    if (r.depth() > BLOB_MAX_DEPTH) { violate("depth exceeded the cap"); return; }

    while (r.ok() && steps < 4096) {
        ++steps;
        const std::size_t before_off = r.offset();
        const std::uint32_t choice = rng.below(6);

        if (choice == 5) {
            walk(r, rng, steps);            // recurse: where a depth bug shows up
        } else {
            bool read_ok = false;
            switch (choice) {
                case 0: { std::uint8_t b;  read_ok = r.read_byte(b); break; }
                case 1: { std::uint64_t v; read_ok = r.read_varint(v); break; }
                case 2: { std::array<std::uint8_t, 32> k; read_ok = r.read_key(k); break; }
                case 3: { std::uint32_t u; read_ok = r.read_u32_le(u); break; }
                default:{ std::uint64_t n; read_ok = r.read_count(n, BLOB_MAX_ELEMENTS, 1); break; }
            }
            if (!read_ok) {
                if (r.offset() != before_off) violate("a failed read moved the cursor");
                if (r.ok())                   violate("a failed read left the reader clean");
            }
        }

        if (r.offset() > r.size()) { violate("the cursor passed the end"); return; }
        if (!r.ok()) break;
    }
}

static void test_structured_fuzz() {
    Rng rng(0xC2900137ull);
    std::size_t total_steps = 0;
    std::size_t poisoned = 0;

    const int ITERATIONS = 4000;
    for (int i = 0; i < ITERATIONS; ++i) {
        std::vector<std::uint8_t> buf(rng.below(512));
        for (auto& b : buf) b = static_cast<std::uint8_t>(rng.next());

        BlobReader r(buf.data(), buf.size());
        std::size_t steps = 0;
        walk(r, rng, steps);
        total_steps += steps;
        if (!r.ok()) ++poisoned;

        if (r.offset() > r.size()) violate("post-walk cursor invariant");
        if (r.depth() != 0)        violate("post-walk depth invariant");
    }

    check(g_violation == nullptr,
          g_violation ? g_violation : "structured fuzz found no invariant violation");
    check(poisoned > 0, "random input does poison the reader, so the pass is meaningful");
    check(g_max_depth_seen == BLOB_MAX_DEPTH,
          "the walk actually reached the nesting cap");
    std::printf("  structured fuzz: %d iterations, %zu reader steps, %zu poisoned, max depth %zu\n",
                ITERATIONS, total_steps, poisoned, g_max_depth_seen);
}

// ---------------------------------------------------------------------------
// 3. Corpus mutation fuzz through the transaction parser
// ---------------------------------------------------------------------------
static void mutate(std::vector<std::uint8_t>& b, Rng& rng) {
    if (b.empty()) return;
    switch (rng.below(6)) {
        case 0:   // bit flip
            b[rng.below(static_cast<std::uint32_t>(b.size()))] ^=
                    static_cast<std::uint8_t>(1u << rng.below(8));
            break;
        case 1:   // byte overwrite
            b[rng.below(static_cast<std::uint32_t>(b.size()))] =
                    static_cast<std::uint8_t>(rng.next());
            break;
        case 2:   // truncate
            b.resize(rng.below(static_cast<std::uint32_t>(b.size())));
            break;
        case 3: { // insert
            const std::size_t at = rng.below(static_cast<std::uint32_t>(b.size()) + 1);
            b.insert(b.begin() + static_cast<long>(at),
                     static_cast<std::uint8_t>(rng.next()));
            break;
        }
        case 4: { // delete
            const std::size_t at = rng.below(static_cast<std::uint32_t>(b.size()));
            b.erase(b.begin() + static_cast<long>(at));
            break;
        }
        default: { // splice a run of noise over the middle
            const std::size_t at = rng.below(static_cast<std::uint32_t>(b.size()));
            const std::size_t n  = rng.below(16) + 1;
            for (std::size_t i = 0; i < n && at + i < b.size(); ++i)
                b[at + i] = static_cast<std::uint8_t>(rng.next());
            break;
        }
    }
}

static void test_corpus_fuzz() {
    Rng rng(0x5EED0BADull);

    std::size_t parsed = 0, refused = 0, seeds = 0;
    const std::size_t MUTANTS_PER_SEED = 24;

    for (std::size_t i = 0; i < G::TX_COUNT; ++i) {
        std::vector<std::uint8_t> seed;
        if (!from_hex(G::TXS[i].pruned_hex, seed) || seed.empty()) continue;
        ++seeds;

        for (std::size_t m = 0; m < MUTANTS_PER_SEED; ++m) {
            std::vector<std::uint8_t> mutant = seed;
            const std::uint32_t rounds = rng.below(3) + 1;
            for (std::uint32_t k = 0; k < rounds; ++k) mutate(mutant, rng);

            TxWeightInfo info;
            const TxParseStatus st = parse_tx_pruned(mutant, info);
            if (st != TxParseStatus::Ok) { ++refused; continue; }
            ++parsed;

            // A mutant that parses must still be internally consistent: the
            // parser is allowed to accept a different valid transaction, never
            // to produce a result that contradicts itself.
            if (info.pruned_size != mutant.size()) {
                check(false, "an accepted mutant consumed exactly its pruned bytes");
                return;
            }
            if (info.blob_size != info.pruned_size + info.prunable_size) {
                check(false, "an accepted mutant has consistent byte spans");
                return;
            }
            if (info.weight < info.blob_size) {
                check(false, "an accepted mutant has weight at least its blob size");
                return;
            }
            if (info.ring_sizes.size() != info.key_images.size()) {
                check(false, "an accepted mutant has one ring per key image");
                return;
            }
            if (!info.is_coinbase && info.ring_sizes.size() != info.n_inputs) {
                check(false, "an accepted mutant has one ring per input");
                return;
            }
        }

        // The full-blob path over the same seed, so both entry points are fuzzed.
        for (std::size_t m = 0; m < 4; ++m) {
            std::vector<std::uint8_t> mutant = seed;
            mutate(mutant, rng);
            TxWeightInfo info;
            if (parse_tx_full(mutant, info) == TxParseStatus::Ok) {
                if (info.blob_size != mutant.size()) {
                    check(false, "an accepted full-blob mutant measures its own blob");
                    return;
                }
            }
        }
    }

    check(seeds >= 200, "the corpus supplied enough seeds to be worth fuzzing");
    check(refused > 0, "mutation does produce rejects, so the pass is meaningful");
    check(true, "corpus fuzz completed without an invariant violation");
    std::printf("  corpus fuzz: %zu seeds, %zu mutants parsed, %zu refused\n",
                seeds, parsed, refused);
}

int main() {
    test_bounds_and_poison();
    test_varint();
    test_count_and_depth();
    test_structured_fuzz();
    test_corpus_fuzz();
    std::printf("xmr_blob_reader_fuzz_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
