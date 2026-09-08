// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/template/xmr_coin_primitives.cpp
//
// AUTHORED for c2pool (not ported). Bodies for the consumer-side seam declared
// in xmr_coin_primitives.hpp -- the surface the p2pool-derived whole-block
// template builder (xmr_block_template.cpp) consumes -- layered over the X1
// `xmr_coin` library so the template emits bytes that are IDENTICAL to the
// lane's authored serializer (xmr_blob.hpp) and to monerod:
//
//   writeVarint      -> the VENDORED tools::write_varint (vendor/varint.h, BSD-3),
//                       exactly what BlobWriter::put_varint uses. Same codec,
//                       same bytes, for both serializers.
//   keccak           -> the VENDORED monero-project keccak() (vendor/keccak.c,
//                       Saarinen baseline). Identical signature; a plain forward.
//   keccak_step /    -> AUTHORED over the vendored keccakf(st, 24): the raw
//   keccak_finish       25-lane sponge form the template caches per miner-tx
//                       prefix (m_minerTxKeccakState). Absorbs whole 136-B
//                       blocks as little-endian u64 lanes; finish pads with the
//                       ORIGINAL Keccak rule monerod uses (0x01 ... | 0x80),
//                       NOT the SHA-3 0x06 domain byte. For every split point:
//                         step(head); finish(tail)  ==  keccak(head || tail)
//                       and the digest is lanes 0..3 of the state (the template
//                       memcpy()s state.data(); LE host asserted below).
//   umul128/udiv128  -> unsigned __int128 (same semantics as x86-64 mul/divq
//                       that p2pool uses; vendor/int-util.h mul128 agrees).
//   parallel_run     -> std::thread fan-out (the "thread pool in the real tree").
//   seconds_since_epoch -> std::chrono system_clock.
//
// Nothing here touches consensus digests; it is byte plumbing under the seam.
// The XMR-lane KAT (test/xmr_template_primitives_kat.cpp) pins every body
// against the vendored one-shot oracle across all split points and then drives
// the real XmrBlockTemplate through BOTH Keccak paths (keccak_custom slow path
// and the keccak_step/keccak_finish midstate fast path), recomputing the
// coinbase hash + tree root independently through xmr::coin.
// ---------------------------------------------------------------------------

#include "xmr_coin_primitives.hpp"

#include <algorithm>
#include <bit>
#include <cassert>
#include <chrono>
#include <cstring>
#include <exception>
#include <thread>
#include <vector>

extern "C" {
#include "vendor/keccak.h"   // ::keccak(in, inlen, md, mdlen), ::keccakf(st, rounds), KECCAK_ROUNDS
}
#include "vendor/varint.h"   // tools::write_varint (BSD-3, vendored)

// The template reads the digest with memcpy(dst, state.data(), 32), i.e. it
// takes lanes 0..3 in HOST byte order. That equals memcpy_swap64le() (what the
// vendored keccak() emits) only on a little-endian host. p2pool has the same
// assumption; make it explicit instead of silent.
static_assert(std::endian::native == std::endian::little,
              "xmr_coin_primitives: keccak_step/keccak_finish state export assumes a little-endian host");

namespace c2pool::xmr {

namespace {

constexpr int kRate      = KeccakParams::HASH_DATA_AREA;   // 136 B for Keccak-256
constexpr int kRateWords = kRate / 8;                        // 17 lanes
static_assert(kRate == 136 && kRateWords == 17, "Keccak-256 rate must be 136 bytes");

inline uint64_t load_le64(const uint8_t* p) noexcept {
    uint64_t v;
    std::memcpy(&v, p, sizeof(v));   // LE host (asserted above) => this IS the LE lane
    return v;
}

// XOR one full rate-sized block into the sponge and permute. Mirrors the block
// loop of the vendored keccak() / KECCAK_PROCESS_BLOCK byte-for-byte.
inline void absorb_block(const uint8_t* block, std::array<uint64_t, 25>& st) noexcept {
    for (int i = 0; i < kRateWords; ++i) {
        st[static_cast<size_t>(i)] ^= load_le64(block + 8 * i);
    }
    ::keccakf(st.data(), KECCAK_ROUNDS);
}

} // namespace

// ---- CryptoNote varint --------------------------------------------------------
// Same codec object BlobWriter::put_varint drives (tools::write_varint over a
// char* cursor), so the template's varints and xmr_blob's are the same bytes.
void writeVarint(uint64_t value, std::vector<uint8_t>& out)
{
    char tmp[(sizeof(uint64_t) * 8 + 6) / 7];   // max 10 bytes for a u64
    char* end = tmp;
    tools::write_varint(end, value);
    out.insert(out.end(), reinterpret_cast<const uint8_t*>(tmp),
               reinterpret_cast<const uint8_t*>(end));
}

// ---- Keccak-256 one-shot (vendored) ------------------------------------------
void keccak(const uint8_t* in, size_t inlen, uint8_t* md, int mdlen)
{
    ::keccak(in, inlen, md, mdlen);   // monero-project keccak.c, unmodified
}

// ---- Keccak midstate: raw 25-lane state form ---------------------------------
// Contract (header): `inlen` is a whole multiple of HASH_DATA_AREA. Trailing
// bytes short of a block are NOT absorbed (they belong to keccak_finish); the
// template always passes (offset / 136) * 136, so the assert documents the
// contract rather than guarding a live path.
void keccak_step(const uint8_t* in, int inlen, std::array<uint64_t, 25>& state)
{
    assert(inlen >= 0 && (inlen % kRate) == 0 && "keccak_step: inlen must be a multiple of 136");
    for (; inlen >= kRate; inlen -= kRate, in += kRate) {
        absorb_block(in, state);
    }
}

// Absorb the tail into an already-stepped state, pad, permute. The tail may be
// LONGER than one block: the template's fast path hands up to sizeof(tx_buf)
// (288 B) here (calc_miner_tx_hash), so any whole blocks are absorbed first,
// exactly as the one-shot loop would have. Padding is the original-Keccak
// 0x01 ... 0x80 rule of monerod's keccak.c (the two bytes coincide into 0x81
// when the tail is 135 B). The 32-byte digest is state[0..3].
void keccak_finish(const uint8_t* in, int inlen, std::array<uint64_t, 25>& state)
{
    assert(inlen >= 0 && "keccak_finish: negative length");
    for (; inlen >= kRate; inlen -= kRate, in += kRate) {
        absorb_block(in, state);
    }

    uint8_t temp[kRate];
    std::memset(temp, 0, sizeof(temp));
    if (inlen > 0) std::memcpy(temp, in, static_cast<size_t>(inlen));
    temp[inlen]     = 0x01;   // Keccak (pre-SHA3) domain/padding start
    temp[kRate - 1] |= 0x80;  // final bit of the rate block
    absorb_block(temp, state);
}

// ---- 128-bit multiply / divide ------------------------------------------------
uint64_t umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
    const unsigned __int128 p = static_cast<unsigned __int128>(a) * b;
    *hi = static_cast<uint64_t>(p >> 64);
    return static_cast<uint64_t>(p);
}

// Precondition (as with x86-64 `divq`, which p2pool emits inline): den != 0 and
// numhi < den so the quotient fits 64 bits. The template's only caller
// (get_block_reward) satisfies both: den = median^2 > 0 and the numerator is
// base_reward * (2m - w) * w <= base_reward * m^2. A zero divisor is turned
// into a saturated quotient instead of a SIGFPE so a malformed miner_data
// cannot take the daemon down; the reward it yields is nonsense that monerod
// rejects, never a consensus value.
uint64_t udiv128(uint64_t numhi, uint64_t numlo, uint64_t den, uint64_t* rem)
{
    assert(den != 0 && "udiv128: zero divisor");
    if (den == 0) {
        if (rem) *rem = numlo;
        return ~0ULL;
    }
    const unsigned __int128 n = (static_cast<unsigned __int128>(numhi) << 64) | numlo;
    assert(numhi < den && "udiv128: quotient does not fit 64 bits");
    if (rem) *rem = static_cast<uint64_t>(n % den);
    return static_cast<uint64_t>(n / den);   // truncates like divq's overflow would NOT: caller's precondition
}

// ---- fan-out helper ------------------------------------------------------------
// Runs `f` on hardware_concurrency() threads (the calling thread takes one
// share when waiting). Copies of `f` divide the work themselves (the template
// uses a shared atomic counter). If a thread cannot be spawned the remaining
// work is simply run on the calling thread -- correct, only slower.
void parallel_run(const std::function<void()>& f, bool wait)
{
    unsigned n = std::thread::hardware_concurrency();
    if (n == 0) n = 1;
    n = std::min<unsigned>(n, 64);

    if (!wait) {
        for (unsigned i = 0; i < n; ++i) {
            try { std::thread(f).detach(); }
            catch (const std::exception&) { f(); }
        }
        return;
    }

    std::vector<std::thread> pool;
    pool.reserve(n > 1 ? n - 1 : 0);
    for (unsigned i = 1; i < n; ++i) {
        try { pool.emplace_back(f); }
        catch (const std::exception&) { break; }   // fall back: this thread finishes the rest
    }
    f();
    for (std::thread& t : pool) t.join();
}

// ---- wall clock ---------------------------------------------------------------
uint64_t seconds_since_epoch()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

} // namespace c2pool::xmr
