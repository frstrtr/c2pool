// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/coin/xmr_keccak_midstate.hpp  --  Keccak-256 with state export
//
// AUTHORED for c2pool (not ported). Thin C++ wrapper over the vendored
// monero-project Keccak (vendor/keccak.{h,c}, Saarinen baseline) that adds the
// one capability the XMR-lane coinbase-opening receipt needs and that monerod
// never exposes as a public API: SNAPSHOT / RESUME of the sponge at an
// arbitrary absorption boundary ("midstate").
//
// Why this is exact, not an approximation:
//   * monero-project's cn_fast_hash() == keccak1600(in,len) (one-shot).
//   * keccak.c's incremental keccak_init/keccak_update/keccak_finish use the
//     IDENTICAL rate (KECCAK_BLOCKLEN = 136), padding (0x01 start byte,
//     0x80 final bit) and keccakf(24) as keccak1600 (verified against
//     keccak.c @ monero-project 3d3920d7). Therefore, for any split point,
//         init; update(head); update(tail); finish   ==   keccak1600(head||tail)
//     and KECCAK_CTX fully captures the state between the two update() calls.
//   * A snapshot is thus a byte-exact, resumable image of the sponge; nothing
//     about the split boundary needs to be block-aligned.
//
// The coinbase-opening receipt carries: snapshot(prefix bytes up to the
// tx_extra section) + the tx_extra bytes. The verifier RESUMEs the snapshot,
// absorbs tx_extra, finalizes -> H(prefix) = the tx-prefix hash, then folds in
// H(rct_base) and the null H(prunable) for the RCTTypeNull coinbase to get the
// leaf-0 tx hash (see xmr_blob.hpp) without ever holding the whole miner_tx.
//
// [X0-KAT / U3, scoping S7] The exact split boundary and this snapshot's
// byte-identity against monerod's keccak.c MUST be pinned by the X0 KAT
// (mainnet-block coinbase-opening vector) before this is trusted in consensus.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "xmr_crypto_types.hpp"

extern "C" {
#include "vendor/keccak.h"     // KECCAK_CTX, keccak_init/update/finish
// Forward-declare ONLY cn_fast_hash rather than pulling all of vendor/hash-ops.h:
// that header leaks the RX_BLOCK_VERSION macro and global rx_seedheight/tree_hash
// decls, which collide with the lane's typed constants under `using namespace`.
// Signature matches hash-ops.h exactly (BSD-3): void cn_fast_hash(const void*, size_t, char*).
void cn_fast_hash(const void* data, std::size_t length, char* hash);
}

namespace xmr::coin {

// A byte-exact, resumable image of the Keccak sponge after absorbing some
// prefix of the input. Wraps monero-project's KECCAK_CTX; MUST be captured
// before finalization.
class KeccakMidstate {
public:
    KeccakMidstate() { keccak_init(&ctx_); }

    // Absorb more input into the running sponge (may be called repeatedly).
    void absorb(const void* data, std::size_t len) {
        if (finalized_) throw std::logic_error("KeccakMidstate: absorb after finalize");
        keccak_update(&ctx_, static_cast<const uint8_t*>(data), len);
    }
    void absorb(const std::vector<unsigned char>& v) { absorb(v.data(), v.size()); }

    // Finalize a COPY (pad + squeeze) and return the 32-byte Keccak-256 digest.
    // Leaves *this* resumable so the same head can be reused for many tails.
    Hash256 finalize_copy() const {
        KECCAK_CTX tmp = ctx_;                 // trivially-copyable snapshot
        Hash256 out;
        keccak_finish(&tmp, out.data());
        return out;
    }

    // ---- Wire form of the midstate (the receipt's coinbase-opening head) ----
    // Canonical minimal encoding:  rest(1B, 0..135) || partial[rest] || H[200B]
    // where H is the 25-lane sponge as 25 little-endian u64 and `partial` is the
    // not-yet-absorbed bytes of the current block. Fixed 201 B when the caller
    // split on a 136-byte block boundary (rest == 0); up to 336 B otherwise.
    std::vector<unsigned char> serialize() const {
        if (finalized_) throw std::logic_error("KeccakMidstate: serialize after finalize");
        const std::size_t rest = ctx_.rest;   // pre-finalize: real byte count
        if (rest >= 136) throw std::logic_error("KeccakMidstate: rest out of range");
        std::vector<unsigned char> out;
        out.reserve(1 + rest + 200);
        out.push_back(static_cast<unsigned char>(rest));
        const auto* msg = reinterpret_cast<const unsigned char*>(ctx_.message);
        out.insert(out.end(), msg, msg + rest);
        for (int i = 0; i < 25; ++i) {         // sponge lanes, little-endian
            uint64_t w = ctx_.hash[i];
            for (int b = 0; b < 8; ++b) out.push_back(static_cast<unsigned char>(w >> (8 * b)));
        }
        return out;
    }

    static KeccakMidstate deserialize(const unsigned char* p, std::size_t len) {
        if (len < 1) throw std::runtime_error("KeccakMidstate: short buffer");
        const std::size_t rest = p[0];
        if (rest >= 136) throw std::runtime_error("KeccakMidstate: bad rest");
        if (len != 1 + rest + 200) throw std::runtime_error("KeccakMidstate: bad length");
        KeccakMidstate m;
        keccak_init(&m.ctx_);
        const unsigned char* q = p + 1;
        auto* msg = reinterpret_cast<unsigned char*>(m.ctx_.message);
        for (std::size_t i = 0; i < rest; ++i) msg[i] = q[i];
        q += rest;
        for (int i = 0; i < 25; ++i) {
            uint64_t w = 0;
            for (int b = 0; b < 8; ++b) w |= static_cast<uint64_t>(q[b]) << (8 * b);
            m.ctx_.hash[i] = w;
            q += 8;
        }
        m.ctx_.rest = rest;
        return m;
    }
    static KeccakMidstate deserialize(const std::vector<unsigned char>& v) {
        return deserialize(v.data(), v.size());
    }

private:
    KECCAK_CTX ctx_{};
    bool finalized_ = false;
};

// One-shot Keccak-256 == monero-project cn_fast_hash(data,len). Provided so the
// lane never needs monerod's crypto.h just to hash a blob. NOTE: keccak.c's
// keccak1600() squeezes the FULL 200-byte sponge state, so it must NOT be
// written into a 32-byte buffer; cn_fast_hash() is the 32-byte-output wrapper
// (union hash_state internally, copies out HASH_SIZE) and is what we expose.
inline Hash256 keccak256(const void* data, std::size_t len) {
    Hash256 out;
    cn_fast_hash(data, len, reinterpret_cast<char*>(out.data()));
    return out;
}
inline Hash256 keccak256(const std::vector<unsigned char>& v) {
    return keccak256(v.data(), v.size());
}

} // namespace xmr::coin
