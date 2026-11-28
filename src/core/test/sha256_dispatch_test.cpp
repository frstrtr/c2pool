// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KATs for the SHA-256 implementation choice every node binary makes at
// startup (core::init_sha256, core/sha256_init.hpp, over btclibs'
// SHA256AutoDetect / SHA256SelfTest).
//
//   1. Every implementation the CPU running the test offers (each
//      sha256_implementation mask) passes SHA256SelfTest and gives the
//      standard vectors: FIPS 180-2 "", "abc", the 448- and 896-bit messages,
//      one million 'a'; sha256d of 64 zero bytes; the BTC and LTC genesis
//      header hashes (sha256d of the 80-byte header).
//   2. Byte equality with the scalar implementation over random inputs:
//      SHA-256 of messages of 0..4096 bytes written in random pieces (the
//      buffer path and the multi-block Transform), sha256d (64- and 80-byte
//      headers included), and SHA256D64 for 1..64 blocks (2-, 4- and 8-way).
//   3. The kill-switch: C2POOL_SHA256=standard installs the scalar one, also
//      read through the real environment.
//   4. The self-check: a failing self-test puts the scalar implementation
//      back, logs an error and does not abort; hashes stay correct.
//   5. Bounds (Linux): no implementation reads or writes a byte outside the
//      buffers it is given. Inputs and outputs sit against PROT_NONE pages
//      (mmap/mprotect), so a stray access faults in any build, sanitized or
//      not: SHA-256 (CSHA256 Write/Finalize) of 0..256 bytes and 1 MiB
//      (+0..63), sha256d (Hash) of 0..256 bytes and 1 MiB, SHA256D64 over
//      1..8 blocks, at unaligned starts; every digest equals the scalar one.
//
// The scalar implementation is what a process runs before SHA256AutoDetect;
// each case below puts it back when it ends.

#include <gtest/gtest.h>

#include <core/hash.hpp>
#include <core/sha256_init.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/sha256.h>
#include <btclibs/util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace {

using sha256_implementation::UseImplementation;

const UseImplementation kMasks[] = {
    sha256_implementation::STANDARD,
    sha256_implementation::USE_SSE4,
    sha256_implementation::USE_SSE4_AND_AVX2,
    sha256_implementation::USE_SSE4_AND_SHANI,
    sha256_implementation::USE_ALL,
};

struct Sha256Dispatch : ::testing::Test {
    void TearDown() override { SHA256AutoDetect(sha256_implementation::STANDARD); }
};

std::string sha256_hex(const std::string& msg)
{
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(msg.data()), msg.size()).Finalize(out);
    return HexStr(std::span<const unsigned char>(out, sizeof(out)));
}

// SHA-256 of `msg` written in pieces cut at `cuts` (ascending offsets).
std::array<unsigned char, 32> sha256_pieces(const std::vector<unsigned char>& msg,
                                            const std::vector<size_t>& cuts)
{
    CSHA256 h;
    size_t at = 0;
    for (size_t c : cuts) {
        h.Write(msg.data() + at, c - at);
        at = c;
    }
    h.Write(msg.data() + at, msg.size() - at);
    std::array<unsigned char, 32> out{};
    h.Finalize(out.data());
    return out;
}

std::vector<unsigned char> header_bytes(const std::string& hex)
{
    auto b = ParseHex(hex);
    EXPECT_EQ(b.size(), 80u);
    return b;
}

// The inputs of the byte-equality case and what the scalar implementation
// makes of them.
struct Corpus {
    std::vector<std::vector<unsigned char>> msgs;
    std::vector<std::vector<size_t>> cuts;
    std::vector<unsigned char> d64_in;   // 64 blocks of 64 bytes

    Corpus()
    {
        std::mt19937 rng(20261127u);
        std::vector<size_t> lens;
        for (size_t n = 0; n <= 200; ++n) lens.push_back(n);
        for (size_t n : {255u, 256u, 257u, 511u, 512u, 513u, 1000u, 1023u, 1024u, 4095u, 4096u})
            lens.push_back(n);
        for (int i = 0; i < 64; ++i) lens.push_back(rng() % 4097);
        for (size_t n : lens) {
            std::vector<unsigned char> m(n);
            for (auto& b : m) b = static_cast<unsigned char>(rng());
            std::vector<size_t> c;
            const size_t pieces = n ? rng() % 4 : 0;
            for (size_t i = 0; i < pieces; ++i) c.push_back(rng() % (n + 1));
            std::sort(c.begin(), c.end());
            msgs.push_back(std::move(m));
            cuts.push_back(std::move(c));
        }
        d64_in.resize(64 * 64);
        for (auto& b : d64_in) b = static_cast<unsigned char>(rng());
    }
};

struct Results {
    std::vector<std::array<unsigned char, 32>> sha;
    std::vector<uint256> sha256d;
    std::vector<std::vector<unsigned char>> d64;   // [blocks-1] -> blocks*32 bytes
};

Results run_corpus(const Corpus& c)
{
    Results r;
    for (size_t i = 0; i < c.msgs.size(); ++i) {
        r.sha.push_back(sha256_pieces(c.msgs[i], c.cuts[i]));
        r.sha256d.push_back(Hash(std::span<const unsigned char>(c.msgs[i].data(), c.msgs[i].size())));
    }
    for (size_t blocks = 1; blocks <= 64; ++blocks) {
        std::vector<unsigned char> out(blocks * 32);
        SHA256D64(out.data(), c.d64_in.data(), blocks);
        r.d64.push_back(std::move(out));
    }
    return r;
}

} // namespace

TEST_F(Sha256Dispatch, EveryImplementationPassesSelfTestAndStandardVectors)
{
    const std::string million_a(1000000, 'a');
    for (auto mask : kMasks) {
        const std::string name = SHA256AutoDetect(mask);
        SCOPED_TRACE("mask " + std::to_string(int(mask)) + " -> " + name);
        std::cout << "[KAT] mask " << int(mask) << " -> " << name << "\n";
        EXPECT_TRUE(SHA256SelfTest());

        EXPECT_EQ(sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        EXPECT_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        EXPECT_EQ(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        EXPECT_EQ(sha256_hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                             "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
                  "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
        EXPECT_EQ(sha256_hex(million_a), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

        // sha256d of 64 zero bytes: the merkle-node form, through Hash() and SHA256D64.
        const std::vector<unsigned char> zero64(64, 0);
        const uint256 zd = Hash(std::span<const unsigned char>(zero64.data(), zero64.size()));
        EXPECT_EQ(HexStr(std::span<const unsigned char>(zd.data(), 32)),
                  "e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9");
        unsigned char d64[32];
        SHA256D64(d64, zero64.data(), 1);
        EXPECT_EQ(HexStr(std::span<const unsigned char>(d64, 32)),
                  "e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9");

        // Genesis headers (80 bytes): the block hash is sha256d of the header.
        const auto btc = header_bytes(
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b2"
            "7ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
        EXPECT_EQ(Hash(std::span<const unsigned char>(btc.data(), btc.size())).GetHex(),
                  "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        const auto ltc = header_bytes(
            "010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7"
            "faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97b9aa8e4ef0ff0f1ecd513f7c");
        EXPECT_EQ(Hash(std::span<const unsigned char>(ltc.data(), ltc.size())).GetHex(),
                  "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2");
    }
}

TEST_F(Sha256Dispatch, DetectedImplementationsAreByteIdenticalToScalar)
{
    const Corpus corpus;
    ASSERT_EQ(SHA256AutoDetect(sha256_implementation::STANDARD), "standard");
    const Results scalar = run_corpus(corpus);

    for (auto mask : kMasks) {
        const std::string name = SHA256AutoDetect(mask);
        SCOPED_TRACE("mask " + std::to_string(int(mask)) + " -> " + name);
        const Results got = run_corpus(corpus);
        ASSERT_EQ(got.sha.size(), scalar.sha.size());
        for (size_t i = 0; i < scalar.sha.size(); ++i) {
            EXPECT_EQ(got.sha[i], scalar.sha[i]) << "SHA-256 of " << corpus.msgs[i].size() << " bytes";
            EXPECT_EQ(got.sha256d[i], scalar.sha256d[i]) << "sha256d of " << corpus.msgs[i].size() << " bytes";
        }
        for (size_t b = 0; b < scalar.d64.size(); ++b)
            EXPECT_EQ(got.d64[b], scalar.d64[b]) << "SHA256D64 over " << (b + 1) << " blocks";
    }

    // SHA256D64 equals sha256d of each 64-byte block (scalar Hash()).
    SHA256AutoDetect(sha256_implementation::USE_ALL);
    std::vector<unsigned char> all(64 * 32);
    SHA256D64(all.data(), corpus.d64_in.data(), 64);
    SHA256AutoDetect(sha256_implementation::STANDARD);
    for (size_t b = 0; b < 64; ++b) {
        const uint256 h = Hash(std::span<const unsigned char>(corpus.d64_in.data() + 64 * b, 64));
        EXPECT_EQ(std::vector<unsigned char>(all.begin() + 32 * b, all.begin() + 32 * (b + 1)),
                  std::vector<unsigned char>(h.data(), h.data() + 32)) << "block " << b;
    }
}

TEST_F(Sha256Dispatch, InitAutoDetectsAndLogsOneLine)
{
    const std::string expect = SHA256AutoDetect(sha256_implementation::USE_ALL);
    SHA256AutoDetect(sha256_implementation::STANDARD);

    std::ostringstream log;
    const core::Sha256Init r = core::init_sha256_with(nullptr, log);
    std::cout << "[KAT] " << log.str();
    EXPECT_EQ(r.implementation, expect);
    EXPECT_EQ(r.detected, expect);
    EXPECT_FALSE(r.forced_standard);
    EXPECT_FALSE(r.self_test_failed);
    EXPECT_FALSE(r.standard_self_test_failed);
    EXPECT_EQ(log.str(), "[init] sha256: using " + expect + "\n");
    EXPECT_TRUE(SHA256SelfTest());

    // "auto" and "" are the default; any other value is named and ignored.
    std::ostringstream log_auto;
    EXPECT_EQ(core::init_sha256_with("auto", log_auto).implementation, expect);
    EXPECT_EQ(log_auto.str(), "[init] sha256: using " + expect + "\n");
    std::ostringstream log_bad;
    const auto bad = core::init_sha256_with("sse4", log_bad);
    EXPECT_EQ(bad.implementation, expect);
    EXPECT_FALSE(bad.forced_standard);
    EXPECT_NE(log_bad.str().find("ignoring C2POOL_SHA256=sse4"), std::string::npos) << log_bad.str();
}

TEST_F(Sha256Dispatch, KillSwitchForcesStandard)
{
    const std::string detected = SHA256AutoDetect(sha256_implementation::USE_ALL);
    std::ostringstream log;
    const core::Sha256Init r = core::init_sha256_with("standard", log);
    std::cout << "[KAT] " << log.str();
    EXPECT_TRUE(r.forced_standard);
    EXPECT_EQ(r.implementation, "standard");
    EXPECT_EQ(r.detected, "standard");
    EXPECT_FALSE(r.self_test_failed);
    EXPECT_EQ(log.str(), "[init] sha256: using standard (C2POOL_SHA256=standard)\n");
    EXPECT_TRUE(SHA256SelfTest());
    // The switch ran with the auto-detected implementation installed (above)
    // and installed the scalar one in its place.
    std::cout << "[KAT] auto would be " << detected << "; kill-switch gives " << r.implementation << "\n";
    EXPECT_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

#ifndef _WIN32
    // The same through the process environment, as a node reads it.
    ASSERT_EQ(setenv(core::kSha256EnvVar, "standard", 1), 0);
    std::ostringstream env_log;
    const core::Sha256Init e = core::init_sha256(env_log);
    unsetenv(core::kSha256EnvVar);
    EXPECT_TRUE(e.forced_standard);
    EXPECT_EQ(e.implementation, "standard");
    EXPECT_EQ(env_log.str(), "[init] sha256: using standard (C2POOL_SHA256=standard)\n");

    std::ostringstream unset_log;
    EXPECT_EQ(core::init_sha256(unset_log).implementation, detected);
#endif
}

namespace {
int g_self_test_calls = 0;
bool fail_first_self_test()
{
    return ++g_self_test_calls > 1;
}
bool always_fail_self_test()
{
    ++g_self_test_calls;
    return false;
}
} // namespace

TEST_F(Sha256Dispatch, FailedSelfTestFallsBackToStandardWithoutAborting)
{
    const std::string detected = SHA256AutoDetect(sha256_implementation::USE_ALL);
    SHA256AutoDetect(sha256_implementation::STANDARD);

    g_self_test_calls = 0;
    std::ostringstream log;
    const core::Sha256Init r = core::init_sha256_with(nullptr, log, &fail_first_self_test);
    std::cout << "[KAT] " << log.str();
    EXPECT_EQ(r.detected, detected);
    EXPECT_EQ(r.implementation, "standard");
    if (detected != "standard") {
        // The detected implementation failed: scalar put back, then re-tested.
        EXPECT_EQ(g_self_test_calls, 2);
        EXPECT_TRUE(r.self_test_failed);
        EXPECT_FALSE(r.standard_self_test_failed);
        EXPECT_EQ(log.str(),
                  "[init] ERROR sha256: self-test failed for " + detected + "; falling back to standard\n"
                  "[init] sha256: using standard (self-test fallback)\n");
    } else {
        // A CPU without an optimized implementation: nothing to fall back from.
        EXPECT_EQ(g_self_test_calls, 1);
        EXPECT_FALSE(r.self_test_failed);
        EXPECT_TRUE(r.standard_self_test_failed);
    }
    // The real self-test passes on what is installed, and hashes are right.
    EXPECT_TRUE(SHA256SelfTest());
    EXPECT_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Even a self-test that never passes returns (no abort) on the scalar one.
    g_self_test_calls = 0;
    std::ostringstream log2;
    const core::Sha256Init r2 = core::init_sha256_with(nullptr, log2, &always_fail_self_test);
    EXPECT_EQ(r2.implementation, "standard");
    EXPECT_TRUE(r2.standard_self_test_failed);
    EXPECT_EQ(r2.self_test_failed, detected != "standard");
    EXPECT_NE(log2.str().find("[init] ERROR sha256: self-test failed for standard"), std::string::npos)
        << log2.str();
    EXPECT_EQ(sha256_hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#ifdef __linux__
namespace {

// Bytes [lo(), hi()) of an anonymous mapping between two PROT_NONE pages:
// touching the byte before lo() or the byte at hi() raises SIGSEGV.
class GuardedBuffer {
public:
    explicit GuardedBuffer(size_t min_size)
    {
        const long ps = sysconf(_SC_PAGESIZE);
        page_ = ps > 0 ? static_cast<size_t>(ps) : 4096;
        span_ = (min_size + page_ - 1) / page_ * page_;
        total_ = span_ + 2 * page_;
        void* m = mmap(nullptr, total_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) return;
        map_ = static_cast<unsigned char*>(m);
        ok_ = mprotect(map_, page_, PROT_NONE) == 0 &&
              mprotect(map_ + page_ + span_, page_, PROT_NONE) == 0;
    }
    ~GuardedBuffer()
    {
        if (map_) munmap(map_, total_);
    }
    GuardedBuffer(const GuardedBuffer&) = delete;
    GuardedBuffer& operator=(const GuardedBuffer&) = delete;

    bool ok() const { return ok_; }
    unsigned char* lo() const { return map_ + page_; }
    unsigned char* hi() const { return map_ + page_ + span_; }

private:
    size_t page_ = 0;
    size_t span_ = 0;
    size_t total_ = 0;
    unsigned char* map_ = nullptr;
    bool ok_ = false;
};

using Digest = std::array<unsigned char, 32>;

// Fill of the SHA256D64 output buffer around the output.
constexpr unsigned char kSentinel = 0xa5;

Digest sha256_of(const unsigned char* p, size_t n)
{
    Digest d{};
    CSHA256().Write(p, n).Finalize(d.data());
    return d;
}

Digest digest_of(const uint256& h)
{
    Digest d{};
    std::copy(h.data(), h.data() + 32, d.begin());
    return d;
}

} // namespace

// Every mask, against guard pages:
//   - low: the message starts at lo() + o, o = 0..63 (o = 0: its first byte
//     follows a PROT_NONE page), lengths 0..256 and 1 MiB;
//   - high: the message ends at hi() (its last byte precedes a PROT_NONE
//     page), lengths 0..256 and 1 MiB + k, k = 0..63, so its start falls on
//     every offset mod 64; for 0..256 also written in two pieces cut at
//     c = 0..63, which puts the chunk Transform reads from the caller's
//     buffer at every offset mod 64, ending at hi();
//   - sha256d (Hash) of every message of 0..256 bytes above, and of the
//     1 MiB one at lo() and ending at hi();
//   - SHA256D64 over 1..8 blocks (1-, 2-, 4- and 8-way), input ending at one
//     guard page and output ending at another, then both at lo() + o; the
//     output is exactly 32 bytes per block (sentinel bytes around it intact).
// A message of length n is the first n bytes of one random stream.
TEST_F(Sha256Dispatch, NoImplementationTouchesBytesOutsideItsBuffers)
{
    constexpr size_t kMiB = size_t{1} << 20;
    constexpr size_t kOffsets = 64;
    constexpr size_t kSmall = 256;
    constexpr size_t kMaxD64 = 8;

    std::vector<unsigned char> stream(kMiB + kOffsets);
    std::mt19937 rng(20261128u);
    for (auto& b : stream) b = static_cast<unsigned char>(rng());

    // Scalar references, indexed by length: 0..256, then 1 MiB + k at
    // kSmall + 1 + k.
    ASSERT_EQ(SHA256AutoDetect(sha256_implementation::STANDARD), "standard");
    std::vector<size_t> lens;
    std::vector<Digest> ref_sha, ref_d;
    for (size_t n = 0; n <= kSmall; ++n) {
        lens.push_back(n);
        ref_sha.push_back(sha256_of(stream.data(), n));
        ref_d.push_back(digest_of(Hash(std::span<const unsigned char>(stream.data(), n))));
    }
    {
        CSHA256 sha;
        sha.Write(stream.data(), kMiB);
        CHash256 sha_d;
        sha_d.Write(std::span<const unsigned char>(stream.data(), kMiB));
        for (size_t k = 0; k < kOffsets; ++k) {
            lens.push_back(kMiB + k);
            CSHA256 s = sha;
            Digest d{};
            s.Write(stream.data() + kMiB, k).Finalize(d.data());
            ref_sha.push_back(d);
            CHash256 h = sha_d;
            h.Write(std::span<const unsigned char>(stream.data() + kMiB, k)).Finalize(std::span<unsigned char>(d.data(), 32));
            ref_d.push_back(d);
        }
    }
    std::vector<unsigned char> ref_d64(kMaxD64 * 32);
    for (size_t b = 0; b < kMaxD64; ++b) {
        const uint256 h = Hash(std::span<const unsigned char>(stream.data() + 64 * b, 64));
        std::copy(h.data(), h.data() + 32, ref_d64.begin() + 32 * b);
    }

    GuardedBuffer msg(kMiB + kOffsets);
    GuardedBuffer d64_in(kMaxD64 * 64 + kOffsets);
    GuardedBuffer d64_out(kMaxD64 * 32 + kOffsets);
    ASSERT_TRUE(msg.ok() && d64_in.ok() && d64_out.ok());

    std::vector<std::string> names;
    for (auto mask : kMasks) {
        names.push_back(SHA256AutoDetect(mask));
        std::cout << "[KAT] guard pages: mask " << int(mask) << " -> " << names.back() << "\n";
    }
    std::cout << std::flush;

    size_t bad = 0;
    size_t checks = 0;
    auto report = [&](size_t m, const char* what, size_t n, size_t at) {
        if (++bad <= 10)
            ADD_FAILURE() << what << " differs from scalar: mask " << int(kMasks[m]) << " (" << names[m]
                          << "), " << n << " bytes, offset " << at;
    };
    auto check = [&](size_t m, size_t i, const unsigned char* p, const char* where, size_t at, bool sha256d) {
        const size_t n = lens[i];
        ++checks;
        if (sha256_of(p, n) != ref_sha[i]) report(m, where, n, at);
        if (!sha256d) return;
        ++checks;
        if (digest_of(Hash(std::span<const unsigned char>(p, n))) != ref_d[i]) report(m, "sha256d", n, at);
    };

    // low: start at lo() + o.
    for (size_t o = 0; o < kOffsets; ++o) {
        unsigned char* p = msg.lo() + o;
        std::copy(stream.begin(), stream.begin() + kMiB, p);
        for (size_t m = 0; m < std::size(kMasks); ++m) {
            SHA256AutoDetect(kMasks[m]);
            for (size_t i = 0; i <= kSmall; ++i) check(m, i, p, "SHA-256 (low)", o, true);
            check(m, kSmall + 1, p, "SHA-256 (low)", o, o == 0);   // 1 MiB
        }
    }

    // high: end at hi().
    for (size_t i = 0; i < lens.size(); ++i) {
        const size_t n = lens[i];
        unsigned char* p = msg.hi() - n;
        std::copy(stream.begin(), stream.begin() + n, p);
        for (size_t m = 0; m < std::size(kMasks); ++m) {
            SHA256AutoDetect(kMasks[m]);
            check(m, i, p, "SHA-256 (high)", (kOffsets - n % kOffsets) % kOffsets, n <= kSmall || n == kMiB);
            if (n > kSmall) continue;
            for (size_t c = 0; c < kOffsets && c <= n; ++c) {
                Digest d{};
                CSHA256().Write(p, c).Write(p + c, n - c).Finalize(d.data());
                ++checks;
                if (d != ref_sha[i]) report(m, "SHA-256 (high, two pieces)", n, c);
            }
        }
    }

    // SHA256D64: input and output at the high guard pages, then at lo() + o.
    auto d64 = [&](size_t m, size_t blocks, unsigned char* in, unsigned char* out, size_t at) {
        std::copy(stream.begin(), stream.begin() + 64 * blocks, in);
        std::fill(d64_out.lo(), d64_out.hi(), kSentinel);
        SHA256D64(out, in, blocks);
        ++checks;
        if (!std::equal(out, out + 32 * blocks, ref_d64.begin())) report(m, "SHA256D64", 64 * blocks, at);
        const bool before = std::all_of(d64_out.lo(), out, [](unsigned char x) { return x == kSentinel; });
        const bool after = std::all_of(out + 32 * blocks, d64_out.hi(), [](unsigned char x) { return x == kSentinel; });
        if (!before || !after) report(m, "SHA256D64 output bounds", 64 * blocks, at);
    };
    for (size_t m = 0; m < std::size(kMasks); ++m) {
        SHA256AutoDetect(kMasks[m]);
        for (size_t blocks = 1; blocks <= kMaxD64; ++blocks) {
            d64(m, blocks, d64_in.hi() - 64 * blocks, d64_out.hi() - 32 * blocks, 0);
            for (size_t o = 0; o < kOffsets; ++o)
                d64(m, blocks, d64_in.lo() + o, d64_out.lo() + o, o);
        }
    }

    std::cout << "[KAT] guard pages: " << checks << " checks, " << bad << " mismatches\n";
    EXPECT_EQ(bad, 0u);
}
#endif // __linux__
