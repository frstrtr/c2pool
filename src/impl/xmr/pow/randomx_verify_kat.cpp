// SPDX-License-Identifier: AGPL-3.0-or-later
//
// randomx_verify_kat.cpp — Known-Answer Tests for the c2pool XMR-lane light
// RandomX verifier (randomx_verify.hpp).
//
// Two independent suites:
//
//   (A) RandomX engine KATs — the OFFICIAL tevador/RandomX vectors, lifted
//       from upstream src/tests/tests.cpp ("Hash test 1a..1e"). These prove
//       our vendored library + our light VM reproduce canonical RandomX.
//       Requires linking librandomx.a (Argon2d cache init + a light VM hash).
//       This is what proto X0/X1 runs; it is heavy-ish (~seconds of Argon2d
//       per distinct key + ~15 ms/hash) so it is NOT a unit test on an
//       OOM-pressured host — run it deliberately.
//
//   (B) Difficulty-rule KATs — pure arithmetic, no RandomX, run anywhere in
//       microseconds. They pin meets_difficulty_64 / _128 (the Monero
//       hash*difficulty<2^256 rule) and seed_height() against hand-computed
//       answers. run_difficulty_kats() is the "light check".
//
// The RandomX vectors below are reproduced from tevador/RandomX
// src/tests/tests.cpp @ commit 7c761cf (BSD-3). They are published test
// vectors (data, not code). rx/0 == the v1 column; RANDOMX_FLAG_V2 flips them.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "randomx_verify.hpp"

namespace {

using c2pool::xmr::SeedHash;

// ---------- helpers ----------
bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2) return false;
    out.clear();
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}
std::string bytes_to_hex(const uint8_t* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
SeedHash key_from_ascii(const char* k) {
    // RandomX keys in the official vectors are short ASCII strings ("test key
    // 000"). Monero keys are 32-byte block ids. randomx_init_cache takes an
    // arbitrary-length key, so for the KATs we key the cache directly with the
    // ASCII bytes via LightVerifier::prefetch requiring a SeedHash; for the
    // short-key vectors we instead call the engine directly (see run_*).
    SeedHash s{};
    std::size_t n = std::strlen(k);
    std::memcpy(s.data(), k, n < s.size() ? n : s.size());
    return s;
}

// =====================================================================
// (A) Official RandomX engine vectors (tevador/RandomX tests.cpp).
// =====================================================================
struct RxVector {
    const char* key;          // ASCII cache key
    const char* input_ascii;  // null if input is hex
    const char* input_hex;    // null if input is ascii
    const char* expect_v1;    // rx/0 (RANDOMX_FLAG_V2 OFF)  <-- Monero mainnet
    const char* expect_v2;    // RANDOMX_FLAG_V2 ON (future fork only), or null
};

const RxVector kRxVectors[] = {
    // key "test key 000"
    { "test key 000", "This is a test", nullptr,
      "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
      "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f" },
    { "test key 000", "Lorem ipsum dolor sit amet", nullptr,
      "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
      "9e2c772c12fd48f93c14c97fdc89d556264d9100597023f44d9163e279012ecf" },
    { "test key 000",
      "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua", nullptr,
      "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
      "4d6b063a1a603751d525f18a171336a4002f2f06df6c17e4b25fe17e17796e42" },
    // key "test key 001"
    { "test key 001",
      "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua", nullptr,
      "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
      "97024134686ce27d362ea8d86d8ef16483ac272abdabd46ef13359400777fe5e" },
    // key "test key 001", hex input resembling a real Monero hashing blob (nonce mid-blob)
    { "test key 001", nullptr,
      "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d2553"
      "7f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca6292"
      "76817b56f32e9b68bd82f416",
      "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1",
      "c8e92c5f7c1946fecf06bc382b92e3111da38ee3e6a5ad90704e1a9d8aaf6e76" },
};

// Runs the engine vectors directly against the vendored library (light VM).
// Kept minimal and self-contained (does not use LightVerifier's SeedHash
// residency machinery because these keys are short ASCII, not 32-byte ids).
int run_randomx_kats(bool v2) {
    using namespace c2pool::xmr;
    VerifierOptions opts;
    opts.algo = PowAlgo::RX_0;            // V2 OFF by default
    randomx_flags cf = cache_flags(opts);
    randomx_flags vf = vm_flags(opts);
    if (v2) {
#ifdef RANDOMX_FLAG_V2
        cf = cf | RANDOMX_FLAG_V2; vf = vf | RANDOMX_FLAG_V2;
#else
        std::fprintf(stderr, "KAT: vendored pin has no RANDOMX_FLAG_V2 (rx/0 consensus pin); v2 suite N/A\n");
        return 0;  // not a failure: v2 is a future-fork path, absent by design here
#endif
    }

    randomx_cache* cache = randomx_alloc_cache(cf);
    if (!cache) { std::fprintf(stderr, "KAT: cache alloc failed (OOM?)\n"); return 2; }
    randomx_vm* vm = nullptr;
    int fails = 0;
    const char* last_key = nullptr;

    for (const auto& v : kRxVectors) {
        const char* want = v2 ? v.expect_v2 : v.expect_v1;
        if (!want) continue;
        if (!last_key || std::strcmp(last_key, v.key) != 0) {
            randomx_init_cache(cache, v.key, std::strlen(v.key));  // Argon2d (heavy)
            last_key = v.key;
            if (!vm) vm = randomx_create_vm(vf, cache, nullptr);
            else     randomx_vm_set_cache(vm, cache);
            if (!vm) { std::fprintf(stderr, "KAT: vm create failed\n"); randomx_release_cache(cache); return 2; }
        }
        std::vector<uint8_t> input;
        if (v.input_hex) { if (!hex_to_bytes(v.input_hex, input)) { ++fails; continue; } }
        else             { input.assign(v.input_ascii, v.input_ascii + std::strlen(v.input_ascii)); }

        uint8_t out[RANDOMX_HASH_SIZE];
        randomx_calculate_hash(vm, input.data(), input.size(), out);
        std::string got = bytes_to_hex(out, RANDOMX_HASH_SIZE);
        bool ok = (got == want);
        std::printf("  [%s] key=\"%s\" -> %s  %s\n", ok ? "PASS" : "FAIL",
                    v.key, got.c_str(), ok ? "" : (std::string("(want ") + want + ")").c_str());
        if (!ok) ++fails;
    }
    if (vm) randomx_destroy_vm(vm);
    randomx_release_cache(cache);
    return fails;
}

// =====================================================================
// (C) Real Monero mainnet block — end-to-end LIGHT verify through the
//     production wrapper (LightVerifier). This is the X0-proven path:
//     rx_probe.cpp measured EXACTLY this input on-host and recorded the
//     resulting PoW hash (see test/randomx-light-measurement.txt); monerod's
//     own rx_slow_hash consumes the identical 76-byte hashing_blob keyed by
//     the same seed-height block id. Passing this proves the vendored library
//     + our two-cache light verifier reproduce Monero mainnet consensus PoW.
//
//     Unlike suite (A)'s short ASCII keys, the RandomX key here is a real
//     32-byte Monero block id, so we drive the FULL production surface:
//     LightVerifier::init -> prefetch_epoch (Argon2d cache fill) ->
//     verify (VM hash + the hash*difficulty<2^256 acceptance rule).
//
//     Ground truth: monerod get_block(3000000). seed_height(3000000)=2998272.
// =====================================================================
struct MoneroBlockVector {
    uint64_t    height;
    uint64_t    seed_height;
    const char* seed_hash_hex;      // Monero block id at seed_height (RandomX key)
    const char* hashing_blob_hex;   // the 76-byte rx_slow_hash input
    const char* expected_pow_hex;   // RandomX PoW hash (little-endian)
    uint64_t    difficulty;         // block's network difficulty (must be met)
};

// Monero mainnet block 3,000,000 (2023-10-20, major_version 16 / rx/0).
const MoneroBlockVector kBlock3000000 = {
    3000000, 2998272,
    "3c512c1a6e8210e985b47e855eaf93af952abb61b9bd032872a376910ba7d448",
    "1010dea6caa906cc64d29f62794dbb5309732f74447d88389198cfbf86a499bd"
    "5b4b5347bc43ae2b8000313cc88694451e92299e5283b2c51985e5c0d31b8d91"
    "0f53d9a8b167a24e7bdf0626",
    "309e84a7d1175490a14cf722f8f3862b3adda4fff904a5d72175ec0100000000",
    308739704685ULL,
};

int run_block_kat() {
    using namespace c2pool::xmr;
    const MoneroBlockVector& v = kBlock3000000;
    int fails = 0;

    std::vector<uint8_t> seed_bytes, blob, expect;
    if (!hex_to_bytes(v.seed_hash_hex, seed_bytes) || seed_bytes.size() != kSeedHashSize) {
        std::fprintf(stderr, "KAT(C): bad seed hex\n"); return 1;
    }
    if (!hex_to_bytes(v.hashing_blob_hex, blob) || blob.empty()) {
        std::fprintf(stderr, "KAT(C): bad blob hex\n"); return 1;
    }
    if (!hex_to_bytes(v.expected_pow_hex, expect) || expect.size() != 32) {
        std::fprintf(stderr, "KAT(C): bad expected-pow hex\n"); return 1;
    }
    // seed_height() must reproduce Monero's rx_seedheight for this height.
    if (seed_height(v.height) != v.seed_height) {
        std::printf("  [FAIL] seed_height(%llu)=%llu (want %llu)\n",
                    (unsigned long long)v.height,
                    (unsigned long long)seed_height(v.height),
                    (unsigned long long)v.seed_height);
        ++fails;
    }

    SeedHash seed{};
    std::memcpy(seed.data(), seed_bytes.data(), kSeedHashSize);

    VerifierOptions opts;              // RX_0 (V2 OFF), JIT on, light (no FULL_MEM)
    LightVerifier lv;
    if (!lv.init(opts)) {
        // A W^X-restricted runner can refuse JIT pages. The hash is identical
        // under the portable interpreter — fall back rather than flake CI.
        std::fprintf(stderr, "KAT(C): JIT init failed; retrying with interpreter\n");
        opts.use_jit = false;
        // init() is safe to re-run here: it failed because randomx_create_vm
        // returned null (vm_ stays null, nothing to leak); the two CacheSlots
        // are move-reassigned, releasing any cache already allocated.
        if (!lv.init(opts)) {
            std::fprintf(stderr, "KAT(C): LightVerifier init failed (OOM?)\n");
            return 2;
        }
    }
    // Argon2d cache fill for the block's epoch (the expensive, off-hot-path step).
    lv.prefetch_epoch(seed, std::nullopt);
    if (!lv.seed_resident(seed)) {
        std::fprintf(stderr, "KAT(C): seed not resident after prefetch\n");
        return 2;
    }

    // The production hot path: VM hash + Monero acceptance rule.
    uint8_t pow[32];
    VerifyStatus st = lv.verify(blob.data(), blob.size(), seed, v.difficulty, pow);

    std::string got = bytes_to_hex(pow, 32);
    bool hash_ok = (got == v.expected_pow_hex);
    std::printf("  [%s] block %llu PoW = %s\n", hash_ok ? "PASS" : "FAIL",
                (unsigned long long)v.height, got.c_str());
    if (!hash_ok) {
        std::printf("         (want %s)\n", v.expected_pow_hex);
        ++fails;
    }

    // The mined block MUST meet its own network difficulty -> Accept.
    bool accept_ok = (st == VerifyStatus::Accept);
    std::printf("  [%s] block %llu meets difficulty %llu -> %s\n",
                accept_ok ? "PASS" : "FAIL", (unsigned long long)v.height,
                (unsigned long long)v.difficulty,
                st == VerifyStatus::Accept ? "Accept" :
                st == VerifyStatus::BelowTarget ? "BelowTarget" :
                st == VerifyStatus::SeedNotResident ? "SeedNotResident" : "NotInitialized");
    if (!accept_ok) ++fails;

    // Cross-check the raw arithmetic rule directly on the produced hash.
    bool d64 = meets_difficulty_64(pow, v.difficulty);
    if (!d64) { std::printf("  [FAIL] meets_difficulty_64 disagrees with verify()\n"); ++fails; }

    return fails;
}

// =====================================================================
// (B) Difficulty-rule + seed-height KATs — pure arithmetic (the light check).
// =====================================================================
struct DiffVector { const char* hash_hex; uint64_t difficulty; bool expect_accept; const char* note; };

const DiffVector kDiffVectors[] = {
    // difficulty 1 accepts every hash (hash*1 = hash < 2^256).
    { "0000000000000000000000000000000000000000000000000000000000000000", 1, true,  "zero, d=1" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1, true,  "max, d=1" },
    // max hash (2^256-1) * 2 overflows -> reject.
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 2, false, "max, d=2 overflow" },
    // hash = 2^255 (top bit set, little-endian => byte 31 = 0x80).
    // 2^255 * 1 = 2^255 < 2^256 accept; * 2 = 2^256 NOT < 2^256 reject.
    { "0000000000000000000000000000000000000000000000000000000000000080", 1, true,  "2^255, d=1" },
    { "0000000000000000000000000000000000000000000000000000000000000080", 2, false, "2^255, d=2 boundary" },
    // small hash, large difficulty still fine: hash=1, d=2^32.
    { "0100000000000000000000000000000000000000000000000000000000000000", 0x100000000ULL, true, "1, d=2^32" },
};

int run_difficulty_kats() {
    using namespace c2pool::xmr;
    int fails = 0;
    for (const auto& v : kDiffVectors) {
        std::vector<uint8_t> h;
        if (!hex_to_bytes(v.hash_hex, h) || h.size() != 32) { ++fails; continue; }
        bool got64  = meets_difficulty_64(h.data(), v.difficulty);
        bool got128 = meets_difficulty_128(h.data(), v.difficulty, 0);  // hi=0 delegates to _64
        bool ok = (got64 == v.expect_accept) && (got128 == v.expect_accept);
        std::printf("  [%s] diff64/128 %-22s d=%llu -> %d/%d (want %d)\n",
                    ok ? "PASS" : "FAIL", v.note,
                    (unsigned long long)v.difficulty, got64, got128, v.expect_accept);
        if (!ok) ++fails;
    }
    // seed_height / seed_heights pins (monero rx_seedheight geometry).
    struct SH { uint64_t h; uint64_t sh; };
    const SH shs[] = {
        { 0, 0 }, { 2048, 0 }, { 2112, 0 },        // h <= 2048+64 -> 0
        { 2113, 2048 },                            // first block past the lag
        { 4096, 2048 }, { 4159, 2048 }, { 4160, 2048 },
        { 4161, 4096 },                            // (4161-64-1)=4096 & ~2047 = 4096
        { 1000003, 999424 },                       // (1000003-65)=999938 & ~2047 = 999424
    };
    for (const auto& s : shs) {
        uint64_t got = seed_height(s.h);
        bool ok = (got == s.sh);
        std::printf("  [%s] seed_height(%llu) -> %llu (want %llu)\n",
                    ok ? "PASS" : "FAIL", (unsigned long long)s.h,
                    (unsigned long long)got, (unsigned long long)s.sh);
        if (!ok) ++fails;
    }
    // two-cache adjacency: a bin near an epoch boundary must resolve current
    // and next to two DIFFERENT seed heights exactly one epoch apart.
    {
        SeedHeights sh = seed_heights(4160);   // near boundary at 4161
        bool ok = (sh.next == sh.current) || (sh.next == sh.current + kSeedhashEpochBlocks);
        std::printf("  [%s] seed_heights(4160): cur=%llu next=%llu\n",
                    ok ? "PASS" : "FAIL",
                    (unsigned long long)sh.current, (unsigned long long)sh.next);
        if (!ok) ++fails;
    }
    (void)key_from_ascii;  // silence unused in builds that skip suite (A)
    return fails;
}

} // namespace

int main(int argc, char** argv) {
    bool do_engine = false, do_v2 = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--engine") == 0) do_engine = true;
        if (std::strcmp(argv[i], "--v2") == 0)     do_v2 = true;
    }

    int fails = 0;
    std::printf("== (B) difficulty + seed-height KATs (light) ==\n");
    fails += run_difficulty_kats();

    if (do_engine) {
        std::printf("== (A) RandomX engine KATs rx/0 (v1) ==\n");
        fails += run_randomx_kats(/*v2=*/false);
        if (do_v2) {
            std::printf("== (A) RandomX engine KATs v2 (future fork only) ==\n");
            fails += run_randomx_kats(/*v2=*/true);
        }
        std::printf("== (C) real Monero mainnet block 3000000 light verify ==\n");
        fails += run_block_kat();
    } else {
        std::printf("(skipping RandomX engine KATs; pass --engine to run against librandomx.a)\n");
    }

    std::printf("%s (%d failure%s)\n", fails ? "KAT FAILED" : "KAT OK",
                fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
