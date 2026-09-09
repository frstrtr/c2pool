// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_template_primitives_kat.cpp  --  X9 option-B KAT:
// the whole-block template's primitive seam (xmr_coin_primitives.cpp)
//
// Pins every body behind template/xmr_coin_primitives.hpp against an
// INDEPENDENT oracle, then drives the real XmrBlockTemplate (the p2pool port
// that no target compiled until this wave) and recomputes what it emitted
// through the lane's OWN serializer/hash path (xmr::coin, X1):
//
//   1. writeVarint(vector)  == header byte_sink form == tools::get_varint_data
//                           == BlobWriter::put_varint   (canonical LEB128 vectors)
//   2. keccak (one-shot)    == xmr::coin::keccak256 (cn_fast_hash) incl. the
//                              published Keccak("") constant and the REAL Monero
//                              block-3,000,000 miner-tx-hash triple
//   3. keccak_step+finish   == keccak(head||tail) for EVERY block-aligned split
//                              and tails {0,1,135,136,137,271,272,288} bytes
//                              (the template's fast path hands tails up to 288 B),
//                              and == the KECCAK_CTX KeccakMidstate path
//   4. keccak_custom        == keccak over a patched byte stream (template use)
//   5. umul128              == vendored int-util.h mul128 (independent schoolbook)
//      udiv128              == hand-computed reward-math vector + reconstruction
//   6. parallel_run(wait)   partitions a counter-driven job and joins
//   7. seconds_since_epoch  agrees with std::chrono
//   8. adapters             round-trip hash/Bytes32/std::array and difficulty
//   9. IN-SITU: XmrBlockTemplate with a stub IXmrSettlementSource for payee
//      counts that exercise the keccak_custom SLOW path (extra-nonce offset <
//      136) and the keccak_step/keccak_finish midstate FAST path (offset >= 136,
//      incl. a >136-B tail): for extra_nonce in {0, 1, 0xFFFFFFFF}
//        (a) the miner_tx prefix sliced out of get_block_template_blob() is
//            byte-identical to xmr::coin::write_coinbase_prefix_head + tx_extra
//            (the two serializers agree),
//        (b) tree_root([coinbase_tx_hash(tx_prefix_hash(prefix))] ++ backlog ids)
//            recomputed through xmr::coin == the 32-B root inside get_hashing_blob(),
//        (c) block id keccak(varint(len)||hashing_blob) agrees on both paths,
//        (d) get_hashing_blobs (parallel_run in situ) == per-blob get_hashing_blob,
//        (e) an old template_id keeps resolving after a further update().
//
// Own harness (nonzero exit on any failure), STL + xmr_template + xmr_coin
// only: NO RandomX, monerod, libsodium or boost. Runs on both build.yml legs.
// ---------------------------------------------------------------------------
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "xmr_coin_primitives.hpp"
#include "xmr_coin_adapters.hpp"
#include "xmr_block_template.hpp"

#include "xmr_crypto_types.hpp"      // Hash256 / PublicKey / ViewTag
#include "xmr_keccak_midstate.hpp"   // keccak256() == cn_fast_hash, KeccakMidstate
#include "xmr_blob.hpp"              // BlobWriter, write_coinbase_prefix_head, tx hashes, tree_root
#include "vendor/varint.h"           // tools::get_varint_data

extern "C" {
#include "vendor/int-util.h"         // mul128 (independent schoolbook oracle)
}

namespace cx = c2pool::xmr;
using xmr::coin::Hash256;

namespace {

int g_fail = 0;
#define CHECK(cond, ...) do { \
    bool _ok = (cond); \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    if (!_ok) ++g_fail; \
} while (0)

std::string hex(const uint8_t* b, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
std::string hex(const std::vector<uint8_t>& v) { return hex(v.data(), v.size()); }
std::string hx(const cx::hash& h) { return hex(h.h, 32); }
std::string hx(const Hash256& h) { return hex(h.data(), 32); }

std::vector<uint8_t> unhex(const std::string& h) {
    std::vector<uint8_t> o;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}

// deterministic pseudo-random bytes (xorshift64*), no <random> dependency
struct Prng {
    uint64_t s;
    explicit Prng(uint64_t seed) : s(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next() { s ^= s >> 12; s ^= s << 25; s ^= s >> 27; return s * 0x2545F4914F6CDD1DULL; }
    void fill(std::vector<uint8_t>& v) { for (auto& b : v) b = static_cast<uint8_t>(next() >> 56); }
};

cx::hash keccak_str(const std::string& tag, uint64_t i = 0) {
    std::vector<uint8_t> in(tag.begin(), tag.end());
    for (int k = 0; k < 8; ++k) in.push_back(static_cast<uint8_t>(i >> (8 * k)));
    cx::hash h;
    cx::keccak(in.data(), in.size(), h.h, 32);
    return h;
}

bool eq32(const uint8_t* a, const uint8_t* b) { return std::memcmp(a, b, 32) == 0; }

// =====================================================================
void kat_varint() {
    std::printf("== 1. writeVarint (vector) == byte_sink form == tools::write_varint == BlobWriter ==\n");

    struct V { uint64_t v; const char* hexv; } canon[] = {
        {0, "00"}, {1, "01"}, {127, "7f"}, {128, "8001"}, {255, "ff01"}, {300, "ac02"},
        {16383, "ff7f"}, {16384, "808001"}, {0xFFFFFFFFULL, "ffffffff0f"},
        // 0.6 XMR tail reward. The literal here was a hand-written constant and
        // was WRONG: LEB128(600000000000) is 80 e0 a5 96 bb 11 (600000000000 =
        // 0x8BA43B7400; septets from the LSB are 0x00,0x60,0x25,0x16,0x3B,0x11).
        // The old "80a094a58b11" decodes to 587146268672. The implementation was
        // always right — xmr_block_assembly_kat's K0 already pins
        // writeVarint(600000000000) against the vendored tools::write_varint —
        // but this KAT was never in the CI target list, so the bad golden went
        // unseen until the option-B KATs were wired into build.yml.
        {600000000000ULL, "80e0a596bb11"},
        {(1ULL << 56) - 1, "ffffffffffffff7f"},                   // MAX_OUTPUT_VALUE
        {UINT64_MAX, "ffffffffffffffffff01"},
    };
    for (const V& c : canon) {
        std::vector<uint8_t> a; cx::writeVarint(c.v, a);
        std::vector<uint8_t> b; cx::writeVarint(c.v, [&b](uint8_t x) { b.push_back(x); });
        std::string t = tools::get_varint_data(c.v);
        xmr::coin::BlobWriter w; w.put_varint(c.v);
        const bool ok = hex(a) == c.hexv && a == b &&
                        std::vector<uint8_t>(t.begin(), t.end()) == a && w.bytes() == a;
        CHECK(ok, "varint(%llu) = %s (canon %s)", static_cast<unsigned long long>(c.v), hex(a).c_str(), c.hexv);
    }

    // sweep: every 7-bit boundary +-1 and a pseudo-random set
    Prng rng(1);
    bool sweep_ok = true;
    std::vector<uint64_t> vals;
    for (int s = 0; s < 64; s += 7) { vals.push_back(1ULL << s); vals.push_back((1ULL << s) - 1); vals.push_back((1ULL << s) + 1); }
    for (int i = 0; i < 2000; ++i) vals.push_back(rng.next() >> (rng.next() % 64));
    for (uint64_t v : vals) {
        std::vector<uint8_t> a; cx::writeVarint(v, a);
        std::vector<uint8_t> b; cx::writeVarint(v, [&b](uint8_t x) { b.push_back(x); });
        xmr::coin::BlobWriter w; w.put_varint(v);
        if (a != b || w.bytes() != a || a.size() != tools::get_varint_byte_size(v)) { sweep_ok = false; break; }
    }
    CHECK(sweep_ok, "varint sweep (%zu values): vector == byte_sink == BlobWriter, size == get_varint_byte_size", vals.size());
}

// =====================================================================
void kat_keccak_oneshot() {
    std::printf("== 2. keccak (one-shot) == xmr::coin::keccak256 / cn_fast_hash ==\n");

    cx::hash e; cx::keccak(nullptr, 0, e.h, 32);
    CHECK(hx(e) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          "keccak(\"\") = %s (published original-Keccak-256 constant)", hx(e).c_str());

    // REAL Monero mainnet block 3,000,000: miner_tx_hash == keccak(H_prefix||H_rct_base||H_prunable)
    std::vector<uint8_t> triple;
    for (const char* p : {"18b7efb2ab347082fc161ff480b0554dbf94de87251e676d8b67d7f5d9173b24",
                          "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
                          "0000000000000000000000000000000000000000000000000000000000000000"}) {
        auto v = unhex(p); triple.insert(triple.end(), v.begin(), v.end());
    }
    cx::hash th; cx::keccak(triple.data(), triple.size(), th.h, 32);
    CHECK(hx(th) == "7f88a52afdab303ddb9d444cb5b53adb5a12c63a82e898a9d2db9f76dd1127f6",
          "keccak(96-B triple) = %s (real blk 3,000,000 miner_tx_hash)", hx(th).c_str());

    // H(rct_base = 0x00) is the constant the template hard-codes (known_second_hash)
    uint8_t zero = 0; cx::hash rb; cx::keccak(&zero, 1, rb.h, 32);
    static const uint8_t known_second_hash[32] = {188,54,120,158,122,30,40,20,54,70,66,41,130,143,129,125,
                                                  102,18,247,180,119,214,101,145,255,150,169,224,100,188,201,138};
    CHECK(eq32(rb.h, known_second_hash), "keccak(0x00) == template known_second_hash (RCTTypeNull base)");

    Prng rng(2);
    bool ok = true;
    for (size_t len : {size_t(1), size_t(55), size_t(135), size_t(136), size_t(137), size_t(271), size_t(272), size_t(273), size_t(1000), size_t(4096)}) {
        std::vector<uint8_t> m(len); rng.fill(m);
        cx::hash a; cx::keccak(m.data(), m.size(), a.h, 32);
        Hash256 b = xmr::coin::keccak256(m.data(), m.size());
        if (!eq32(a.h, b.data())) { ok = false; std::printf("    mismatch at len %zu\n", len); }
    }
    CHECK(ok, "keccak == keccak256 for lengths {1,55,135,136,137,271,272,273,1000,4096}");
}

// =====================================================================
void kat_keccak_midstate() {
    std::printf("== 3. keccak_step + keccak_finish == keccak(head||tail), every split ==\n");

    constexpr int R = cx::KeccakParams::HASH_DATA_AREA;
    Prng rng(3);
    std::vector<uint8_t> msg(6 * R + 300); rng.fill(msg);

    const int tails[] = {0, 1, 7, 8, 9, 63, 64, 65, 134, 135, 136, 137, 200, 271, 272, 273, 287, 288};
    size_t cases = 0; bool ok = true;
    for (int N = 0; N + 288 <= static_cast<int>(msg.size()); N += R) {
        for (int tl : tails) {
            const int L = N + tl;
            // oracle: vendored one-shot
            cx::hash want; cx::keccak(msg.data(), static_cast<size_t>(L), want.h, 32);
            // raw-state path (what the template caches / resumes)
            std::array<uint64_t, 25> st{};
            cx::keccak_step(msg.data(), N, st);
            cx::keccak_finish(msg.data() + N, tl, st);
            uint8_t got[32]; std::memcpy(got, st.data(), 32);
            // KECCAK_CTX path (xmr_keccak_midstate.hpp) -- same split
            xmr::coin::KeccakMidstate ms;
            ms.absorb(msg.data(), static_cast<size_t>(N));
            ms.absorb(msg.data() + N, static_cast<size_t>(tl));
            Hash256 ctx = ms.finalize_copy();
            ++cases;
            if (!eq32(got, want.h) || !eq32(ctx.data(), want.h)) {
                ok = false;
                std::printf("    mismatch N=%d tail=%d: raw=%s ctx=%s want=%s\n", N, tl,
                            hex(got, 32).c_str(), hx(ctx).c_str(), hx(want).c_str());
            }
        }
    }
    CHECK(ok, "raw-state step/finish == one-shot == KECCAK_CTX for %zu (split, tail) cases", cases);

    // step with inlen=0 is a no-op; finish on an untouched state == keccak(tail)
    {
        std::array<uint64_t, 25> st{};
        cx::keccak_step(msg.data(), 0, st);
        bool zero = true; for (uint64_t w : st) zero = zero && (w == 0);
        cx::keccak_finish(msg.data(), 100, st);
        cx::hash want; cx::keccak(msg.data(), 100, want.h, 32);
        CHECK(zero && eq32(reinterpret_cast<const uint8_t*>(st.data()), want.h),
              "keccak_step(0 bytes) is a no-op; keccak_finish alone == keccak(tail)");
    }

    // resume-many-tails from ONE stepped state (the template copies the cached
    // state per extra_nonce and finishes each copy independently)
    {
        std::array<uint64_t, 25> base{};
        cx::keccak_step(msg.data(), 2 * R, base);
        bool ok2 = true;
        for (uint32_t en = 0; en < 16; ++en) {
            std::vector<uint8_t> tail(msg.begin() + 2 * R, msg.begin() + 2 * R + 150);
            std::memcpy(tail.data() + 40, &en, 4);          // "patch the extra nonce"
            std::vector<uint8_t> full(msg.begin(), msg.begin() + 2 * R);
            full.insert(full.end(), tail.begin(), tail.end());
            cx::hash want; cx::keccak(full.data(), full.size(), want.h, 32);
            std::array<uint64_t, 25> st = base;
            cx::keccak_finish(tail.data(), static_cast<int>(tail.size()), st);
            if (!eq32(reinterpret_cast<const uint8_t*>(st.data()), want.h)) ok2 = false;
        }
        CHECK(ok2, "one cached midstate resumed for 16 patched tails (per-extra-nonce pattern)");
    }
}

// =====================================================================
void kat_keccak_custom() {
    std::printf("== 4. keccak_custom (byte_at stream, patched regions) == keccak ==\n");
    Prng rng(4);
    std::vector<uint8_t> data(300); rng.fill(data);
    const size_t en_off = 120, root_off = 160;
    const uint8_t en[4] = {0xde, 0xad, 0xbe, 0xef};
    cx::hash root = keccak_str("root");
    std::vector<uint8_t> patched = data;
    std::memcpy(patched.data() + en_off, en, 4);
    std::memcpy(patched.data() + root_off, root.h, 32);
    cx::hash want; cx::keccak(patched.data(), patched.size(), want.h, 32);
    cx::hash got;
    cx::keccak_custom([&](int off) -> uint8_t {
        uint32_t k = static_cast<uint32_t>(off - static_cast<int>(en_off));
        if (k < 4) return en[k];
        k = static_cast<uint32_t>(off - static_cast<int>(root_off));
        if (k < 32) return root.h[k];
        return data[static_cast<size_t>(off)];
    }, static_cast<int>(data.size()), got.h, 32);
    CHECK(eq32(got.h, want.h), "keccak_custom over patched stream == keccak(patched bytes)");
}

// =====================================================================
void kat_mul_div_128() {
    std::printf("== 5. umul128 / udiv128 ==\n");

    struct M { uint64_t a, b, lo, hi; } mv[] = {
        {0, 0, 0, 0}, {1, 1, 1, 0}, {UINT64_MAX, 1, UINT64_MAX, 0},
        {1ULL << 32, 1ULL << 32, 0, 1},
        {UINT64_MAX, UINT64_MAX, 1, UINT64_MAX - 1},
        {600000000000ULL, 87500000000ULL, 0x07dc231427d00000ULL, 0xb1eULL},   // reward-math numerator
    };
    for (const M& m : mv) {
        uint64_t hi = 0; const uint64_t lo = cx::umul128(m.a, m.b, &hi);
        uint64_t vhi = 0; const uint64_t vlo = mul128(m.a, m.b, &vhi);   // vendored int-util.h
        CHECK(lo == m.lo && hi == m.hi && vlo == lo && vhi == hi,
              "umul128(%llu, %llu) = (hi %llx, lo %llx) == vendored mul128",
              static_cast<unsigned long long>(m.a), static_cast<unsigned long long>(m.b),
              static_cast<unsigned long long>(hi), static_cast<unsigned long long>(lo));
    }
    Prng rng(5); bool ok = true;
    for (int i = 0; i < 20000 && ok; ++i) {
        const uint64_t a = rng.next(), b = rng.next();
        uint64_t hi, vhi; const uint64_t lo = cx::umul128(a, b, &hi); const uint64_t vlo = mul128(a, b, &vhi);
        ok = (lo == vlo && hi == vhi);
    }
    CHECK(ok, "umul128 == vendored mul128 on 20000 pseudo-random pairs");

    // get_block_reward vector: base 0.6 XMR, median 300000, weight 350000
    //   reward = base*(2m-w)*w / m^2 = 5.25e22 / 9e10 = 583333333333 rem 30000000000
    {
        uint64_t rem = 0;
        const uint64_t q = cx::udiv128(0xb1eULL, 0x07dc231427d00000ULL, 90000000000ULL, &rem);
        CHECK(q == 583333333333ULL && rem == 30000000000ULL,
              "udiv128(reward numerator, median^2) = %llu rem %llu (hand-computed 583333333333 r 30000000000)",
              static_cast<unsigned long long>(q), static_cast<unsigned long long>(rem));
    }
    {
        uint64_t rem = 0;
        const uint64_t q = cx::udiv128(1, 0, 1ULL << 32, &rem);
        CHECK(q == (1ULL << 32) && rem == 0, "udiv128(2^64, 2^32) = 2^32 rem 0");
        const uint64_t q2 = cx::udiv128(0, 100, 7, &rem);
        CHECK(q2 == 14 && rem == 2, "udiv128(100, 7) = 14 rem 2");
    }
    // reconstruction sweep with numhi < den (the divq precondition)
    bool rok = true;
    for (int i = 0; i < 20000 && rok; ++i) {
        const uint64_t den = rng.next() | 1;
        const uint64_t hi = rng.next() % den;
        const uint64_t lo = rng.next();
        uint64_t rem = 0;
        const uint64_t q = cx::udiv128(hi, lo, den, &rem);
        uint64_t phi = 0; const uint64_t plo = cx::umul128(q, den, &phi);
        // (q*den) + rem must equal (hi:lo) with rem < den
        const uint64_t slo = plo + rem;
        const uint64_t shi = phi + (slo < plo ? 1 : 0);
        rok = (rem < den) && (slo == lo) && (shi == hi);
    }
    CHECK(rok, "udiv128 reconstruction q*den+rem == (hi:lo), rem < den, on 20000 pseudo-random triples");
}

// =====================================================================
void kat_parallel_run_and_clock() {
    std::printf("== 6/7. parallel_run(wait=true) partitions work; seconds_since_epoch ==\n");
    constexpr uint32_t N = 100000;
    std::atomic<uint32_t> counter{0};
    std::atomic<uint64_t> sum{0};
    std::atomic<int> copies{0};
    cx::parallel_run([&]() {
        ++copies;
        uint64_t local = 0;
        for (;;) {
            const uint32_t i = counter.fetch_add(1);
            if (i >= N) break;
            local += i;
        }
        sum += local;
    }, true);
    const uint64_t want = static_cast<uint64_t>(N) * (N - 1) / 2;
    CHECK(sum.load() == want && copies.load() >= 1,
          "counter-partitioned sum over %d copies = %llu (want %llu); returned after join",
          copies.load(), static_cast<unsigned long long>(sum.load()), static_cast<unsigned long long>(want));

    const uint64_t s = cx::seconds_since_epoch();
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    CHECK(s > 1700000000ULL && (now >= static_cast<long long>(s)) && (now - static_cast<long long>(s)) <= 2,
          "seconds_since_epoch = %llu (chrono %lld)", static_cast<unsigned long long>(s), static_cast<long long>(now));
}

// =====================================================================
void kat_adapters() {
    std::printf("== 8. type adapters ==\n");
    cx::hash h = keccak_str("adapter");
    Hash256 h256 = cx::from_hash<Hash256>(h);
    xmr::coin::PublicKey pk = cx::from_hash<xmr::coin::PublicKey>(h);
    std::array<uint8_t, 32> arr = cx::from_hash<std::array<uint8_t, 32>>(h);
    CHECK(eq32(h256.data(), h.h) && eq32(pk.data(), h.h) && eq32(arr.data(), h.h),
          "from_hash -> Hash256 / PublicKey / std::array<uint8_t,32> byte-identical");
    CHECK(cx::to_hash(h256) == h && cx::to_hash(pk) == h && cx::to_hash(arr) == h && cx::to_hash(h.h) == h,
          "to_hash round-trips all three spellings");
    struct D128 { uint64_t lo = 0, hi = 0; } d{0x1234, 0x5678};
    cx::difficulty_type t = cx::to_difficulty(d);
    D128 back = cx::from_difficulty<D128>(t);
    CHECK(t.lo == 0x1234 && t.hi == 0x5678 && back.lo == d.lo && back.hi == d.hi &&
          cx::to_difficulty(7).lo == 7 && cx::to_difficulty(7).hi == 0,
          "difficulty {lo,hi} round-trips");
}

// =====================================================================
// 9. IN-SITU: the real XmrBlockTemplate over a stub settlement seam.
// =====================================================================
struct StubSeam final : cx::IXmrSettlementSource {
    std::vector<cx::XmrPayee> ps;
    cx::hash r, R;
    explicit StubSeam(size_t n) {
        for (size_t i = 0; i < n; ++i) {
            cx::XmrPayee p;
            p.spend_public_key = keccak_str("B", i);
            p.view_public_key  = keccak_str("A", i);
            ps.push_back(p);
        }
        r = keccak_str("r"); R = keccak_str("R");
    }
    const std::vector<cx::XmrPayee>& payees() const override { return ps; }
    const cx::hash& tx_secret_key() const override { return r; }
    const cx::hash& tx_public_key() const override { return R; }
    bool derive_output_key(size_t i, uint8_t hf, cx::hash& out, uint8_t& vt) const override {
        if (hf > cx::HARDFORK_SUPPORTED_VERSION) return false;   // CARROT fence shape
        out = keccak_str("P", i);
        vt = static_cast<uint8_t>(i * 7 + 1);
        return true;
    }
    bool split_reward(uint64_t reward, std::vector<uint64_t>& rewards) const override {
        const size_t n = ps.size();
        if (n == 0) return false;
        rewards.assign(n, reward / n);
        rewards[n - 1] += reward - (reward / n) * n;            // exact sum
        return true;
    }
    cx::hash commitment_leaf(uint32_t en) const override { return keccak_str("leaf", en); }
    uint64_t merkle_tree_data() const override { return 0; }
};

// parse a CryptoNote varint at p (bounded)
uint64_t read_varint(const std::vector<uint8_t>& b, size_t& pos) {
    uint64_t v = 0; int shift = 0;
    while (pos < b.size()) {
        const uint8_t x = b[pos++];
        v |= static_cast<uint64_t>(x & 0x7f) << shift;
        if (!(x & 0x80)) break;
        shift += 7;
    }
    return v;
}

void kat_template_in_situ(size_t n_payees, size_t n_backlog) {
    std::printf("== 9. XmrBlockTemplate in situ: %zu payees, %zu backlog txs ==\n", n_payees, n_backlog);

    StubSeam seam(n_payees);
    cx::XmrBlockTemplate t(&seam);

    cx::XmrMinerData md;
    md.major_version = cx::HARDFORK_SUPPORTED_VERSION;
    md.height = 3000000;
    md.prev_id = keccak_str("prev", n_payees);
    md.already_generated_coins = UINT64_MAX - 1000;   // ~agc >> 19 == 0 -> tail emission 0.6 XMR
    md.median_weight = 300000;
    md.median_timestamp = 1700000000;
    md.difficulty.lo = 1000; md.difficulty.hi = 0;
    md.seed_hash = keccak_str("seed");
    md.lane_target.lo = 1ULL << 40; md.lane_target.hi = 0;

    std::vector<cx::XmrTxMempoolData> pool;
    uint64_t fees = 0;
    for (size_t i = 0; i < n_backlog; ++i) {
        cx::XmrTxMempoolData tx;
        tx.id = keccak_str("txid", i);
        tx.weight = 1500 + i;
        tx.fee = 30000000 + i;         // 0.00003 XMR-ish, < HIGH_FEE_VALUE
        tx.time_received = 0;          // passes the 5-s age gate
        pool.push_back(tx);
        fees += tx.fee;
    }

    t.update(md, pool);

    const uint64_t reward = t.get_reward();
    CHECK(t.get_height() == md.height && reward == cx::BASE_BLOCK_REWARD + fees,
          "update(): height %llu, reward %llu == base 0.6 XMR + fees %llu (below-median, all txs taken)",
          static_cast<unsigned long long>(t.get_height()), static_cast<unsigned long long>(reward),
          static_cast<unsigned long long>(fees));

    std::vector<uint64_t> amounts;
    CHECK(seam.split_reward(reward, amounts) && amounts.size() == n_payees, "stub split_reward at final reward");

    uint8_t hb[cx::HASHING_BLOB_MAX_SIZE];
    uint64_t h = 0; cx::difficulty_type lt; cx::hash seed; size_t nonce_off = 0; uint32_t tid = 0;
    const uint32_t hb_len = t.get_hashing_blob(0, hb, h, lt, seed, nonce_off, tid);
    CHECK(hb_len == 76 && nonce_off == 39 && tid == 1 && h == md.height && lt.lo == md.lane_target.lo && seed == md.seed_hash,
          "get_hashing_blob(0): %u B, nonce_offset %zu, template_id %u", hb_len, nonce_off, tid);

    const size_t header_len = nonce_off + cx::NONCE_SIZE;   // 43 for v16 + 5-B timestamp

    for (uint32_t en : {0u, 1u, 0xFFFFFFFFu}) {
        size_t no = 0, eno = 0, mro = 0; cx::hash mroot;
        std::vector<uint8_t> blob = t.get_block_template_blob(tid, en, no, eno, mro, mroot);

        // ---- carve the block: header || miner_tx(prefix || rct_type) || varint(n_tx) || ids ----
        const size_t prefix_end = mro + 32;                    // MM tag is the last tx_extra field
        bool layout_ok = no == nonce_off && blob.size() > prefix_end + 1 &&
                         std::memcmp(blob.data(), hb, header_len) == 0 &&
                         blob[prefix_end] == 0 /* rct_type RCTTypeNull */;
        const std::vector<uint8_t> prefix(blob.begin() + header_len, blob.begin() + prefix_end);
        size_t pos = prefix_end + 1;
        const uint64_t n_tx = read_varint(blob, pos);
        std::vector<Hash256> leaves(1);
        for (uint64_t i = 0; i < n_tx && pos + 32 <= blob.size(); ++i, pos += 32) {
            Hash256 id; std::memcpy(id.data(), blob.data() + pos, 32);
            leaves.push_back(id);
        }
        layout_ok = layout_ok && (n_tx == n_backlog) && (pos == blob.size());
        CHECK(layout_ok, "en=%08x: blob %zu B = header(%zu) || miner_tx || varint(%llu) || ids; offsets nonce %zu extra %zu root %zu",
              en, blob.size(), header_len, static_cast<unsigned long long>(n_tx), no, eno, mro);

        // ---- (a) two serializers agree: rebuild the prefix through xmr::coin ----
        {
            std::vector<xmr::coin::PublicKey> keys(n_payees);
            std::vector<xmr::coin::ViewTag> vts(n_payees);
            for (size_t i = 0; i < n_payees; ++i) {
                cx::hash P; uint8_t vt = 0;
                (void)seam.derive_output_key(i, md.major_version, P, vt);
                keys[i] = cx::from_hash<xmr::coin::PublicKey>(P);
                vts[i].tag = vt;
            }
            std::vector<uint8_t> want = xmr::coin::write_coinbase_prefix_head(
                md.height, amounts.data(), keys.data(), vts.data(), n_payees);
            // tx_extra exactly as X6 assemble_tx_extra / the template emit it:
            //   0x01 R[32] | 0x02 varint(len) nonce[len] | 0x03 (1+32) varint(0) root[32]
            const size_t en_len = blob[eno - 1];               // the template's corrected size (<= 14, 1-byte varint)
            xmr::coin::BlobWriter x;
            x.put_byte(xmr::coin::TX_EXTRA_TAG_PUBKEY);
            x.put_bytes(seam.R.h, 32);
            x.put_byte(xmr::coin::TX_EXTRA_TAG_NONCE);
            x.put_varint(en_len);
            x.put_u32_le(en);
            for (size_t i = 4; i < en_len; ++i) x.put_byte(0);
            x.put_byte(xmr::coin::TX_EXTRA_TAG_MERGE_MINING);
            x.put_byte(static_cast<uint8_t>(1 + 32));
            x.put_varint(0);                                   // merkle_tree_data() == 0
            const cx::hash leaf = seam.commitment_leaf(en);
            x.put_bytes(leaf.h, 32);
            xmr::coin::BlobWriter w;
            w.put_bytes(want.data(), want.size());
            w.put_varint(x.size());
            w.put_bytes(x.bytes().data(), x.size());
            CHECK(w.bytes() == prefix && mroot == leaf && en_len == cx::EXTRA_NONCE_SIZE,
                  "en=%08x: (a) template miner_tx prefix (%zu B) == xmr::coin write_coinbase_prefix_head + tx_extra; extra_nonce len %zu",
                  en, prefix.size(), en_len);
        }

        // ---- (b) coinbase hash + tree root recomputed through xmr::coin == root in the hashing blob ----
        {
            leaves[0] = xmr::coin::coinbase_tx_hash(xmr::coin::tx_prefix_hash(prefix));
            const Hash256 root = xmr::coin::tree_root(leaves);
            uint8_t hbe[cx::HASHING_BLOB_MAX_SIZE];
            uint64_t h2; cx::difficulty_type lt2; cx::hash s2; size_t no2; uint32_t tid2;
            const uint32_t len2 = t.get_hashing_blob(en, hbe, h2, lt2, s2, no2, tid2);
            const bool root_ok = len2 == hb_len && eq32(hbe + header_len, root.data()) &&
                                 std::memcmp(hbe, blob.data(), header_len) == 0 &&
                                 hbe[header_len + 32] == static_cast<uint8_t>(n_backlog + 1);
            // which Keccak path did calc_miner_tx_hash take for this layout?
            const size_t en_off_in_tx = eno - header_len;
            const size_t N = (en_off_in_tx / 136) * 136;
            const size_t tail = prefix.size() - N;
            CHECK(root_ok, "en=%08x: (b) tree_root([coinbase_tx_hash(prefix)] ++ %zu ids) == hashing-blob root %s  [%s path: midstate N=%zu, tail=%zu B]",
                  en, leaves.size() - 1, hx(root).c_str(),
                  N ? "keccak_step/finish FAST" : "keccak_custom SLOW", N, tail);

            // (c) block id = keccak(varint(len) || hashing_blob): primitives vs xmr::coin agree
            std::vector<uint8_t> pre; cx::writeVarint(len2, pre); pre.insert(pre.end(), hbe, hbe + len2);
            cx::hash bid; cx::keccak(pre.data(), pre.size(), bid.h, 32);
            Hash256 bid2 = xmr::coin::keccak256(pre.data(), pre.size());
            CHECK(eq32(bid.h, bid2.data()), "en=%08x: (c) block id keccak(varint(%u)||blob) = %s on both paths", en, len2, hx(bid).c_str());
        }
    }

    // ---- (d) get_hashing_blobs (parallel_run in situ) == per-blob get_hashing_blob ----
    {
        std::vector<uint8_t> blobs;
        uint64_t h3; cx::difficulty_type lt3; cx::hash s3; size_t no3; uint32_t tid3;
        const uint32_t sz = t.get_hashing_blobs(1000, 64, blobs, h3, lt3, s3, no3, tid3);
        bool ok = (sz == hb_len) && (blobs.size() == static_cast<size_t>(sz) * 64);
        for (uint32_t i = 0; ok && i < 64; ++i) {
            uint8_t one[cx::HASHING_BLOB_MAX_SIZE];
            uint64_t hh; cx::difficulty_type ll; cx::hash ss; size_t nn; uint32_t tt;
            const uint32_t l1 = t.get_hashing_blob(1000 + i, one, hh, ll, ss, nn, tt);
            ok = (l1 == sz) && std::memcmp(one, blobs.data() + static_cast<size_t>(i) * sz, sz) == 0;
        }
        // distinct extra nonces => distinct roots (disjoint search spaces)
        bool distinct = ok && std::memcmp(blobs.data() + header_len, blobs.data() + sz + header_len, 32) != 0;
        CHECK(ok && distinct, "(d) get_hashing_blobs(1000, 64) == 64 x get_hashing_blob; roots differ per extra_nonce");
    }

    // ---- (e) old template id keeps resolving after a further update() ----
    {
        cx::XmrMinerData md2 = md;
        md2.height = md.height + 1;
        md2.prev_id = keccak_str("prev2", n_payees);
        t.update(md2, pool);
        size_t a, b, c; cx::hash m1, m2;
        std::vector<uint8_t> old_blob = t.get_block_template_blob(tid, 5, a, b, c, m1);
        std::vector<uint8_t> new_blob = t.get_block_template_blob(tid + 1, 5, a, b, c, m2);
        const bool ok = old_blob.size() > 39 && new_blob.size() > 39 &&
                        std::memcmp(old_blob.data() + 7, md.prev_id.h, 32) == 0 &&
                        std::memcmp(new_blob.data() + 7, md2.prev_id.h, 32) == 0 &&
                        t.get_height() == md2.height;
        CHECK(ok, "(e) template_id %u still resolves (prev %s...) after update() to id %u", tid, hx(md.prev_id).substr(0, 16).c_str(), tid + 1);
    }
}

} // namespace

int main() {
    std::printf("xmr_template_primitives_kat: X9 option-B coin-primitives seam\n");
    kat_varint();
    kat_keccak_oneshot();
    kat_keccak_midstate();
    kat_keccak_custom();
    kat_mul_div_128();
    kat_parallel_run_and_clock();
    kat_adapters();
    // payee counts chosen so calc_miner_tx_hash takes: 1,2 -> SLOW (keccak_custom);
    // 4 -> FAST (N=136, tail < 136); 9 -> FAST with a >136-B tail (whole block
    // absorbed inside keccak_finish); 12 -> FAST N=272. 0/3 backlog txs cover a
    // single-leaf tree and a 4-leaf tree_hash main branch.
    kat_template_in_situ(1, 0);
    kat_template_in_situ(2, 3);
    kat_template_in_situ(4, 3);
    kat_template_in_situ(9, 3);
    kat_template_in_situ(12, 7);
    std::printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "ALL PASS", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
