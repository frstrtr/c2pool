// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/cross-impl-goldens/xmr_goldens_compute.hpp
//   Single source of the XMR-lane golden RECOMPUTATION, shared by the generator
//   (gen_xmr_goldens.cpp, which prints the values) and the load-bearing KAT
//   (xmr_goldens_kat.cpp, which byte-compares them to the committed golden
//   header). Both call compute_xmr_goldens(); the golden header holds the frozen
//   expected values. A change to any merged primitive shifts what this function
//   returns, so the KAT's compare against the frozen header goes red — that is
//   the whole point of the gate.
//
// Links the REAL merged primitives only (xmr_coin: keccak/cn_fast_hash, ed25519
// ge_*/sc_*, the boost-free check_hash, the extracted CryptoNote derivation)
// plus the header-only wire codec + receipt structs. No RandomX/libsodium/boost.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "xmr_crypto_types.hpp"
#include "xmr_derivation.hpp"       // generate_key_derivation/derive_public_key/secret_key_to_public_key
#include "xmr_keccak_midstate.hpp"  // keccak256 / KeccakMidstate
#include "xmr_blob.hpp"             // BlobWriter / TX_EXTRA_TAG_PUBKEY
#include "xmr_check_hash.hpp"       // boost-free check_hash (lane hot path)
#include "xmr_receipt.hpp"          // MoneroReceipt / HashingBlob / ...
#include "xmr_carrier_wire.hpp"     // encode_carrier / CarrierMessage

namespace xmr_goldens {

using ::xmr::coin::Bytes32;
using ::xmr::coin::PublicKey;
using ::xmr::coin::SecretKey;
using ::xmr::coin::KeyDerivation;
using ::xmr::coin::EcScalar;
using ::xmr::coin::Hash256;
using ::xmr::coin::ViewTag;

// ---- hex helpers ----------------------------------------------------------
inline std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> o; o.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}
inline std::string hex(const unsigned char* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
template <class T> inline T from_hex(const std::string& h) {
    T t{}; auto v = unhex(h);
    std::memcpy(t.data(), v.data(), v.size() < 32 ? v.size() : 32);
    return t;
}
template <class T> inline std::string hx(const T& t) { return hex(t.data(), 32); }
inline std::array<std::uint8_t, 32> to_arr(const Hash256& h) {
    std::array<std::uint8_t, 32> a{}; std::memcpy(a.data(), h.data(), 32); return a;
}

// ===========================================================================
//  Pinned inputs (documented in gen_xmr_goldens.cpp / the golden header)
// ===========================================================================

// G2: OFFICIAL monero tests/crypto/tests.txt consensus vectors.
inline constexpr char kA_hex[] = "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984";
inline constexpr char kr_hex[] = "eb2bd1cf0c5e074f9dbf38ebbc99c316f54e21803048c687a3bb359f7a713b02";
inline constexpr char kB_hex[] = "6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39";

// G3: pinned CoinbaseInputs tuple (consensus-shaped literals).
inline constexpr char   TXKEY_DOMAIN[]   = "c2pool-v37-xmr-txkey-v1";
inline constexpr char   MM_LEAF_DOMAIN[] = "c2pool-v37-xmr-mm-leaf-v1";
inline constexpr std::uint8_t  G3_MAJOR   = 16;
inline constexpr std::uint32_t G3_CHAINID = 0x37584d52u;   // "7XMR"
inline constexpr std::uint64_t G3_HEIGHT  = 3000000;
inline constexpr char G3_LANE_HEX[] = "1111111111111111111111111111111111111111111111111111111111111111";
inline constexpr char G3_PREV_HEX[] = "b3b5c0e6f2a1d4c7e8091a2b3c4d5e6f70819a2b3c4d5e6f7081920a1b2c3d4e5";

// ---- byte-exact reproductions of settle/xmr_coinbase.cpp helpers ----------
inline SecretKey derive_tx_secret_key_g3() {
    ::xmr::coin::BlobWriter w;
    w.put_bytes(TXKEY_DOMAIN, sizeof(TXKEY_DOMAIN) - 1);
    w.put_byte(G3_MAJOR);
    w.put_u32_le(G3_CHAINID);
    Bytes32 lane = from_hex<Bytes32>(G3_LANE_HEX);
    Bytes32 prev = from_hex<Bytes32>(G3_PREV_HEX);
    w.put_bytes(lane.data(), 32);
    w.put_key(prev);
    w.put_varint(G3_HEIGHT);
    EcScalar s; ::xmr::coin::hash_to_scalar(w.bytes().data(), w.size(), s);
    SecretKey r; std::memcpy(r.data(), s.data(), 32);
    return r;
}
inline Hash256 mm_commitment_root_g3() {
    unsigned char cid[4] = {
        (unsigned char)(G3_CHAINID & 0xff), (unsigned char)((G3_CHAINID >> 8) & 0xff),
        (unsigned char)((G3_CHAINID >> 16) & 0xff), (unsigned char)((G3_CHAINID >> 24) & 0xff) };
    Bytes32 lane = from_hex<Bytes32>(G3_LANE_HEX);
    ::xmr::coin::KeccakMidstate m;
    m.absorb(MM_LEAF_DOMAIN, sizeof(MM_LEAF_DOMAIN) - 1);
    m.absorb(cid, 4);
    m.absorb(lane.data(), 32);
    return m.finalize_copy();
}

// ---- G5 pinned receipts (deterministic construction) ----------------------
inline v37::xmr::MoneroReceipt make_receipt(unsigned char seed, const PublicKey& R) {
    using namespace v37::xmr;
    MoneroReceipt r;
    r.hashing_blob.bytes.resize(76);
    for (std::size_t i = 0; i < r.hashing_blob.bytes.size(); ++i)
        r.hashing_blob.bytes[i] = (unsigned char)(seed + i);
    r.seed_ref.policy = SeedRefPolicy::DerivedFromBin;
    for (std::size_t i = 0; i < r.coinbase_opening.midstate.size(); ++i)
        r.coinbase_opening.midstate[i] = (unsigned char)((seed * 3 + i) & 0xff);
    r.coinbase_opening.prefix_tail = { 0xde, 0xad, 0xbe, 0xef, seed };
    r.coinbase_opening.tx_extra.clear();
    r.coinbase_opening.tx_extra.push_back(::xmr::coin::TX_EXTRA_TAG_PUBKEY);
    r.coinbase_opening.tx_extra.insert(r.coinbase_opening.tx_extra.end(), R.data(), R.data() + 32);
    r.tree_branch.path.push_back(to_arr(::xmr::coin::keccak256(std::string("leaf-0-sibling").data(), 14)));
    r.tree_branch.path.push_back(to_arr(::xmr::coin::keccak256(std::string("leaf-1-sibling").data(), 14)));
    r.tree_branch.depth = (unsigned char)r.tree_branch.path.size();
    std::string tag = "c2pool-xmr-golden-info-" + std::to_string(seed);
    r.info_digest = to_arr(::xmr::coin::keccak256(tag.data(), tag.size()));
    return r;
}

// ---- G1 difficulty boundary vectors (from ../xmr_difficulty_kat.cpp) -------
struct DiffVec { const char* h; std::uint64_t lo, hi; };
inline const DiffVec kDiffVecs[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",1,0},
    {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",1,0},
    {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",2,0},
    {"0000000000000000000000000000000000000000000000000000000000000080",1,0},
    {"0000000000000000000000000000000000000000000000000000000000000080",2,0},
    {"0100000000000000000000000000000000000000000000000000000000000000",0x100000000ULL,0},
    {"0100000000000000000000000000000000000000000000000000000000000000",0,1},
    {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",0,1},
    {"ffffffffffffffff000000000000000000000000000000000000000000000000",0,1},
    {"ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000",0,1}, // 2^192-1
    {"0000000000000000000000000000000000000000000000000100000000000000",0,1},
};
inline std::string g1_difficulty_bits() {
    std::string bits;
    for (std::size_t i = 0; i < sizeof(kDiffVecs)/sizeof(kDiffVecs[0]); ++i) {
        std::string hh(kDiffVecs[i].h);
        auto hb = unhex(hh);
        unsigned char h[32]; std::memset(h, 0, 32);
        std::memcpy(h, hb.data(), hb.size() < 32 ? hb.size() : 32);
        bits.push_back(::xmr::coin::check_hash(h, kDiffVecs[i].lo, kDiffVecs[i].hi) ? '1' : '0');
    }
    return bits;
}

// ===========================================================================
//  The recomputed golden bundle.
// ===========================================================================
struct XmrGoldens {
    std::string g1_bits;
    std::string g2_D, g2_P0; unsigned g2_vt0;
    std::string g3_r, g3_R, g3_mm_root, g3_Pcb;
    std::string g4_cheap_id, g4_info_digest; std::size_t g4_wire_size;
    std::size_t g5_len; std::string g5_digest, g5_bytes;
};

inline XmrGoldens compute_xmr_goldens() {
    XmrGoldens g;

    PublicKey A = from_hex<PublicKey>(kA_hex);
    SecretKey r_g2 = from_hex<SecretKey>(kr_hex);
    PublicKey B = from_hex<PublicKey>(kB_hex);

    // G1
    g.g1_bits = g1_difficulty_bits();

    // G2
    KeyDerivation D{}; ::xmr::coin::generate_key_derivation(A, r_g2, D);
    PublicKey P0{}; ::xmr::coin::derive_public_key(D, 0, B, P0);
    ViewTag vt0{}; ::xmr::coin::derive_view_tag(D, 0, vt0);
    g.g2_D = hx(D); g.g2_P0 = hx(P0); g.g2_vt0 = vt0.tag;

    // G3
    SecretKey r_g3 = derive_tx_secret_key_g3();
    PublicKey R_g3{}; ::xmr::coin::secret_key_to_public_key(r_g3, R_g3);
    Hash256 mm_root = mm_commitment_root_g3();
    KeyDerivation D_cb{}; ::xmr::coin::generate_key_derivation(A, r_g3, D_cb);
    PublicKey P_cb{}; ::xmr::coin::derive_public_key(D_cb, 0, B, P_cb);
    g.g3_r = hx(r_g3); g.g3_R = hx(R_g3); g.g3_mm_root = hx(mm_root); g.g3_Pcb = hx(P_cb);

    // G4 + G5
    v37::xmr::MoneroReceipt rcA = make_receipt(0x10, R_g3);
    v37::xmr::MoneroReceipt rcB = make_receipt(0x40, R_g3);
    Hash256 cheap_id_A = ::xmr::coin::keccak256(rcA.hashing_blob.bytes);
    g.g4_cheap_id = hx(cheap_id_A);
    g.g4_wire_size = rcA.wire_size();
    g.g4_info_digest = hex(rcA.info_digest.data(), 32);

    v37::xmr::wire::CarrierMessage cm;
    cm.chain_id = G3_CHAINID;
    cm.carrier = rcA;
    cm.receipts.push_back(rcB);
    std::vector<unsigned char> cb = v37::xmr::wire::encode_carrier(cm);
    g.g5_len = cb.size();
    g.g5_digest = hx(::xmr::coin::keccak256(cb));
    g.g5_bytes = hex(cb.data(), cb.size());
    return g;
}

} // namespace xmr_goldens
