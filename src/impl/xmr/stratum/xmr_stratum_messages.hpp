#pragma once
/*
 * xmr_stratum_messages.hpp — wire message schemas for the V37 Monero/RandomX
 * stratum front-end (Family B: XMR lane). CryptoNote / xmrig "JSON stratum"
 * dialect: login / job / submit. This is NOT the v36 Bitcoin stratum
 * (mining.subscribe / mining.notify / mining.submit) — it is a separate,
 * self-contained component, as the scoping note requires
 * (v37-monero-randomx-lane-scoping.md §5, row "Stratum").
 *
 * This file is part of c2pool (frstrtr/c2pool).
 * Copyright (c) 2026 The c2pool developers.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details. You should have received a copy of the GNU Affero General Public
 * License along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * ---------------------------------------------------------------------------
 * PROVENANCE (PATTERNS ported, not code copied)
 *
 *   The wire dialect below reproduces, field for field, the JSON that
 *   SChernykh/p2pool @ master (read 2026-09-05) emits and parses in
 *   src/stratum_server.cpp (GPL-3.0). Adapted symbols:
 *       - login OK response .......... StratumServer::on_login()        L340-346
 *       - job notification ........... StratumServer::on_blobs_ready()  L941-946
 *       - submit request parse ....... StratumClient::process_submit()  L1547-1619
 *       - submit result / errors ..... on_after_share_found()           L1220-1241
 *   p2pool GPL-3.0 combines lawfully into this AGPL-3.0 work under AGPLv3 §13.
 *   This header is FRESH c2pool code that re-expresses the byte-level schema;
 *   see PROVENANCE.md for the line-by-line map and the divergences.
 *
 *   DIVERGENCE FROM p2pool (deliberate):
 *     (a) `next_seed_hash` is added to the job (p2pool omits it; the xmrig
 *         protocol and monerod get_block_template both carry it — RandomX
 *         clients use it to pre-init the cache/dataset for the coming epoch so
 *         the 2048-block seed rotation is hitless; scoping §1.1, §4).
 *     (b) NO p2pool pool-model fields (sidechain id, PPLNS, uncles). A v37
 *         accepted share becomes a work-receipt/carrier in the RDWR model, not
 *         a p2pool sidechain block — that seam lives in IShareSink, not here.
 * ---------------------------------------------------------------------------
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace v37 {
namespace xmr {
namespace stratum {

// --- fixed sizes (CryptoNote / RandomX) -------------------------------------
inline constexpr std::size_t HASH_SIZE = 32;                 // Keccak / RandomX out
inline constexpr std::size_t NONCE_SIZE = sizeof(std::uint32_t); // 4-byte header nonce

// The Monero block *hashing blob* the miner hashes is
//   varint(major) varint(minor) varint(timestamp) prev_id[32] nonce[4]
//   || tree_root[32] || varint(n_tx)                    (scoping §2.5, §4)
// For the current mainnet regime (major=v16 => 1 byte, minor => 1 byte,
// timestamp => 5-byte varint for any realistic epoch) the header prefix is
// 1+1+5 = 7 bytes, so the 4-byte little-endian nonce sits at offset 39. The
// "get-block-hashing-blob" prefix + 32-byte root + 1-byte varint(n_tx) for a
// typical block is ~76 B (scoping §2.5). The nonce offset is NEVER hardcoded
// on the hot path: the template source returns it (see ITemplateSource); 39 is
// only the sanity value asserted for pre-CARROT v16 headers.
inline constexpr std::size_t EXPECTED_NONCE_OFFSET_V16 = 39;
inline constexpr std::size_t HASHING_BLOB_TYPICAL_SIZE = 76;   // scoping §2.5
inline constexpr std::size_t HASHING_BLOB_MAX_SIZE = 128;      // generous cap

// The RandomX variant string Monero uses (rx_slow_hash, no key-tweak variant).
inline constexpr std::string_view ALGO = "rx/0";

// p2pool util.h: send the 4-byte "compact" target for large targets (low diff)
// and the full 8-byte target for small targets (high diff). Value pinned to
// p2pool's TARGET_4_BYTES_LIMIT (verify against upstream src/util.h before
// landing — open question OQ-S5). 2^32.
inline constexpr std::uint64_t TARGET_4_BYTES_LIMIT = 0x1'0000'0000ULL;

// --- login string ("login" field of the login request) ---------------------
// xmrig sends the wallet address (base58 "4.."/"8..") optionally suffixed with
//   +<difficulty>        request a fixed custom difficulty
//   .<worker>  or  /<worker> or the traditional "addr.worker"
// p2pool parses this with get_custom_diff()/get_custom_user() (util.cpp). Here
// the parsed form is explicit so the descriptor boundary (descriptor-kinds
// leg: base58 -> XMR_STD/XMR_SUB payout target) is a clean hand-off.
struct LoginString {
    std::string address;                 // raw base58, decoded downstream
    std::optional<std::uint64_t> custom_diff;
    std::string worker;                  // "" if absent
};

// --- a fully-resolved job, ready to serialize to the wire -------------------
// Everything the miner needs to hash and to submit back. Produced by the
// stratum server from ITemplateSource output; consumed by build_login_ok /
// build_job_notify.
struct JobNotify {
    std::vector<std::uint8_t> blob;      // the hashing blob (per-client, extra_nonce baked in)
    std::uint32_t job_id = 0;            // per-connection job id (hex on the wire)
    std::uint64_t target = 0;            // 64-bit target (encode_target picks 4/8 bytes)
    std::uint64_t height = 0;            // Monero mainchain height of this template
    std::array<std::uint8_t, HASH_SIZE> seed_hash{};
    std::optional<std::array<std::uint8_t, HASH_SIZE>> next_seed_hash; // divergence (a)
    std::size_t nonce_offset = EXPECTED_NONCE_OFFSET_V16; // where the 4-byte nonce lives
};

// --- parsed submit request --------------------------------------------------
// The three hex fields of a "submit" params object, already decoded. p2pool
// decodes these inline in on_submit(); here decoding is a pure function
// (StratumDialect::parse_submit) so it is unit-testable without a socket.
struct ParsedSubmit {
    std::uint32_t job_id = 0;            // from params.job_id (hex)
    std::uint32_t nonce = 0;             // from params.nonce (8 hex chars, little-endian bytes)
    std::array<std::uint8_t, HASH_SIZE> result{}; // from params.result (64 hex chars, big-endian)
    std::string rpc_id;                  // params.id (the login session id echo)
};

// The raw string fields the transport (rapidjson, as in p2pool
// process_submit) hands to the dialect. Keeping tokenization in the transport
// mirrors p2pool's doc.ParseInsitu(); the dialect never sees a socket.
struct SubmitFields {
    std::string rpc_id;                  // params.id
    std::string job_id;                  // params.job_id
    std::string nonce;                   // params.nonce
    std::string result;                  // params.result
};

// --- error taxonomy (maps 1:1 to p2pool's on_after_share_found messages) ----
enum class SubmitError {
    None,
    Stale,          // "Stale share"        (template rolled / job aged out)
    InvalidJobId,   // "Invalid job id"
    CouldNotCheck,  // "Couldn't check PoW"
    LowDiff,        // "Low diff share"
    InvalidPoW,     // "Invalid PoW"        (recomputed hash != claimed / fails target)
    Banned,         // "Banned"
    SubmitFailed,   // "Submit failed"
    MalformedField, // parse-level rejection (bad hex / length)
};

std::string_view submit_error_message(SubmitError e) noexcept;

} // namespace stratum
} // namespace xmr
} // namespace v37
