/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// xmr_provenance.hpp — machine-readable provenance table for the XMR lane
// (Family B). This is the single in-tree source of truth that PROVENANCE.md
// and the NOTICE file are generated against / checked against. A CI provenance
// gate can assert that every vendored/ported file under src/impl/xmr/ appears
// here with a pinned upstream commit, and that no "fresh" file carries an
// upstream copyright line. Header-only, no dependencies, constexpr.

#ifndef C2POOL_IMPL_XMR_XMR_PROVENANCE_HPP
#define C2POOL_IMPL_XMR_XMR_PROVENANCE_HPP

#include <cstddef>
#include <string_view>
#include <array>

namespace c2pool::xmr::provenance {

using std::string_view;

// SPDX-style licence identifiers used across the XMR lane.
enum class License {
    BSD_3_Clause,   // permissive: RandomX, Monero-core crypto/epee
    GPL_3_0_only,   // copyleft: p2pool-derived monero-plumbing
    AGPL_3_0,       // the c2pool whole-work licence (fresh files)
};

// What we did to the upstream bytes.
enum class Disposition {
    Verbatim,       // copied unchanged (BSD notice retained)
    Adapted,        // derivative work (upstream notice retained + provenance)
    CleanRoom,      // authored fresh; listed here only to record NON-porting
};

struct Upstream {
    string_view repo;         // "tevador/RandomX"
    string_view pin_tag;      // release we pin to, "" if untagged
    string_view pin_sha;      // full 40-char commit, read on read_date
    string_view read_date;    // ISO date the pin/headers were read
    License      license;
};

// Upstreams, pinned as read on 2026-09-05. At vendor time, re-pin pin_sha to
// the exact commit checked out (prefer the release tag) and update read_date.
inline constexpr Upstream kRandomX{
    "tevador/RandomX", "v1.2.3",
    "7c761cf007c758056dcb6eb438a32f780f81bdbd", "2026-09-05",
    License::BSD_3_Clause};
inline constexpr Upstream kMonero{
    "monero-project/monero", "v0.18.5.1",
    "3d3920d7487b5df7ac388b6b8577fd04d505885f", "2026-09-05",
    License::BSD_3_Clause};
inline constexpr Upstream kP2pool{
    "SChernykh/p2pool", "v4.18",
    "128643114f9bea55bfdb95462eaeffa2e3f666bd", "2026-09-05",
    License::GPL_3_0_only};

// Which upstream (if any) a manifest row derives from. A value-typed tag
// rather than a `const Upstream*` pointer: the provenance gate's invariants
// are checked in a `static_assert`, i.e. under manifestly-constant evaluation,
// and once -fsanitize=undefined is enabled GCC's constexpr evaluator refuses
// to fold ANY comparison of a static-storage object's address -- not just
// `&kManifest[i] == &kP2pool` cross-object identity, but even `ptr == nullptr`
// against an address-of expression -- reporting e.g. "'(&kRandomX == 0)' is
// not a constant expression". An enum equality comparison carries the exact
// same information (which upstream, or none) and folds fine under every
// sanitizer combination, so it replaces the pointer for identity purposes.
enum class UpstreamId {
    None,       // authored fresh for c2pool; no upstream
    RandomX,
    Monero,
    P2pool,
};

// Resolve a tag to its pinned Upstream record (nullptr for None). Returning
// the address of a static-storage object is fine under constexpr+UBSan; it is
// only COMPARING such addresses that GCC's UBSan-instrumented constant
// evaluator rejects (see UpstreamId above).
constexpr const Upstream* upstream_of(UpstreamId id) {
    switch (id) {
        case UpstreamId::RandomX: return &kRandomX;
        case UpstreamId::Monero:  return &kMonero;
        case UpstreamId::P2pool:  return &kP2pool;
        case UpstreamId::None:    return nullptr;
    }
    return nullptr;
}

struct Entry {
    string_view      dst;          // path under src/impl/xmr/ (or vendor/)
    UpstreamId       upstream_id;  // None => authored fresh for c2pool
    string_view      src;          // upstream path ("" if fresh)
    Disposition      disp;
    License          license;      // licence THIS file ships under
    string_view      note;         // what/why (symbols, what was cut)
};

// The porting plan, one row per file. `upstream_id==None` rows are fresh AGPL
// files recorded here ONLY to pin the boundary of what we deliberately did NOT
// port from p2pool's pool-model.
inline constexpr std::array<Entry, 14> kManifest{{
    // ---- BSD-3: RandomX (verbatim vendor of the hasher library) ----
    {"vendor/randomx/", UpstreamId::RandomX, "src/ (whole library)", Disposition::Verbatim,
     License::BSD_3_Clause,
     "randomx_alloc_cache/init_cache/create_vm/calculate_hash; light (cache-only, "
     "256 MiB) verify path only; dataset optional. Vendor unmodified as a subtree."},

    // ---- BSD-3: Monero-core crypto primitives (verbatim/adapted) ----
    {"vendor/monero-crypto/crypto-ops.c", UpstreamId::Monero, "src/crypto/crypto-ops.c",
     Disposition::Verbatim, License::BSD_3_Clause,
     "ed25519 group ops: ge_scalarmult/ge_p3_tobytes/sc_reduce32 backing "
     "one-time output-key + view-tag derivation (get_eph_public_key)."},
    {"vendor/monero-crypto/keccak.c", UpstreamId::Monero, "src/crypto/keccak.c",
     Disposition::Verbatim, License::BSD_3_Clause,
     "Keccak-256 sponge (Saarinen baseline; retain the mjos author line). "
     "Needs a midstate-export shim for the coinbase-opening KAT (added as a "
     "SEPARATE fresh file, not by editing this one)."},
    {"vendor/monero-crypto/tree-hash.c", UpstreamId::Monero, "src/crypto/tree-hash.c",
     Disposition::Verbatim, License::BSD_3_Clause,
     "tree_hash / tree_branch: miner_tx is leaf 0; O(log n) inclusion proof."},
    {"vendor/monero-crypto/hash-ops.h", UpstreamId::Monero, "src/crypto/hash-ops.h",
     Disposition::Verbatim, License::BSD_3_Clause, "cn_fast_hash / hash decls."},
    {"vendor/monero-epee/varint.h", UpstreamId::Monero,
     "contrib/epee/include/storages/portable_storage.h (+ int-util.h varint)",
     Disposition::Adapted, License::BSD_3_Clause,
     "CryptoNote varint read/write + blob (de)serialization for the hashing "
     "blob and miner_tx prefix. epee copyright: Andrey N. Sabelnikov 2006-2013."},

    // ---- GPL-3: p2pool MONERO-PLUMBING (adapted; pool-model stripped) ----
    {"src/impl/xmr/pow/randomx_hasher.cpp", UpstreamId::P2pool, "src/pow_hash.cpp",
     Disposition::Adapted, License::GPL_3_0_only,
     "RandomX integration PATTERN: two-cache epoch handling (m_cache[2], "
     "64-block seed lag), light/dataset select, seed rotation. NOT the sidechain."},
    {"src/impl/xmr/coinbase/det_tx_key.cpp", UpstreamId::P2pool, "src/block_template.cpp",
     Disposition::Adapted, License::GPL_3_0_only,
     "Deterministic tx secret key: seed=keccak(\"tx_key_seed\"||main||side); "
     "r=generate_keys_deterministic; R=r*G in tx_extra 0x01; every node re-"
     "derives+byte-compares outputs. PPLNS get_shares()/split_reward NOT taken."},
    {"src/impl/xmr/coinbase/template_build.cpp", UpstreamId::P2pool, "src/block_template.cpp",
     Disposition::Adapted, License::GPL_3_0_only,
     "Whole-block miner_tx assembly: txout_to_tagged_key, extra-nonce padding "
     "(4->14 B weight-invariant), tree root -> 76-B hashing blob. PPLNS payout "
     "list REPLACED by the v37 K_fair caller."},
    {"src/impl/xmr/rpc/monerod_adapter.cpp", UpstreamId::P2pool,
     "src/p2pool.cpp + src/zmq_reader.cpp + src/json_rpc_request.cpp",
     Disposition::Adapted, License::GPL_3_0_only,
     "monerod glue: get_miner_data/submit_block/calc_pow/get_fee_estimate JSON-RPC "
     "+ ZMQ json-full-chain_main/miner_data/minimal-txpool_add subscribe."},
    {"src/impl/xmr/stratum/cryptonote_stratum.cpp", UpstreamId::P2pool, "src/stratum_server.cpp",
     Disposition::Adapted, License::GPL_3_0_only,
     "CryptoNote/XMRig stratum dialect: login/job/submit, 76-B blob job, nonce "
     "at offset 39, seed_hash/next_seed_hash, algo rx/0; per-worker extranonce."},

    // ---- AGPL-3: authored fresh for c2pool (NOT ported) ----
    {"src/impl/xmr/receipt/xmr_receipt.hpp", UpstreamId::None, "", Disposition::CleanRoom,
     License::AGPL_3_0,
     "Family-B receipt envelope (~600-660 B): hashing_blob, seed_ref, coinbase_"
     "opening, tree_branch, info_digest. v37-original; no p2pool ancestor."},
    {"src/impl/xmr/settle/k_fair_xmr.cpp", UpstreamId::None, "", Disposition::CleanRoom,
     License::AGPL_3_0,
     "v37 OWED-ledger K_fair split + exact-sum residual-sink rule. Clean-room: "
     "we do NOT lift p2pool split_reward(); PPLNS/uncles are the pool-model."},
    {"src/impl/xmr/coinbase/keccak_midstate.c", UpstreamId::None, "", Disposition::CleanRoom,
     License::AGPL_3_0,
     "Midstate-export shim over vendored keccak.c for the coinbase-opening KAT. "
     "Fresh file so the vendored keccak.c stays byte-identical to upstream."},
}};

// ---- compile-time invariants the provenance gate enforces ----

// (1) Every ported/vendored row names an upstream and a non-empty pin.
constexpr bool ported_rows_are_pinned() {
    for (const auto& e : kManifest) {
        const bool fresh = (e.upstream_id == UpstreamId::None);
        if (fresh) {
            if (e.license != License::AGPL_3_0) return false;      // fresh => AGPL
            if (e.disp != Disposition::CleanRoom) return false;
        } else {
            const Upstream* up = upstream_of(e.upstream_id);
            if (up->pin_sha.size() != 40) return false;             // full SHA pin
            if (e.src.empty()) return false;                       // named source
            if (e.disp == Disposition::CleanRoom) return false;    // ported != cleanroom
        }
    }
    return true;
}

// (2) A ported file never silently upgrades to a more-permissive licence than
//     its upstream: p2pool-derived rows must ship GPL-3.0-only (copyleft kept).
constexpr bool copyleft_preserved() {
    for (const auto& e : kManifest)
        if (e.upstream_id == UpstreamId::P2pool && e.license != License::GPL_3_0_only)
            return false;
    return true;
}

// (3) The whole distributable is conveyed under AGPL-3.0; GPL-3.0-only parts are
//     permitted in the combination by AGPLv3 §13 / GPLv3 §13. BSD-3 is permissive
//     and compatible. This predicate documents the only three licences allowed.
constexpr bool licence_set_closed() {
    for (const auto& e : kManifest)
        switch (e.license) {
            case License::BSD_3_Clause:
            case License::GPL_3_0_only:
            case License::AGPL_3_0: break;
            default: return false;
        }
    return true;
}

static_assert(ported_rows_are_pinned(), "provenance: unpinned/mis-typed row");
static_assert(copyleft_preserved(),     "provenance: p2pool copyleft dropped");
static_assert(licence_set_closed(),     "provenance: unexpected licence in lane");

} // namespace c2pool::xmr::provenance

#endif // C2POOL_IMPL_XMR_XMR_PROVENANCE_HPP
