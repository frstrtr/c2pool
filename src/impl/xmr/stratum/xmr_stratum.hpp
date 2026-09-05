#pragma once
/*
 * xmr_stratum.hpp — session + server skeleton for the V37 Monero/RandomX
 * stratum front-end (Family B: XMR lane), plus the three seams that keep the
 * miner-facing dialect cleanly separated from (1) block-template construction,
 * (2) RandomX PoW verification, and (3) the v37 work-receipt / settlement
 * model. This front-end MUST NOT touch src/sharechain/v37 consensus digest
 * code, and it is entirely separate from the v36 Bitcoin stratum.
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
 *   Design mirror of SChernykh/p2pool @ master src/stratum_server.h/.cpp
 *   (GPL-3.0, read 2026-09-05), combined lawfully into AGPL-3.0 under §13:
 *     - per-connection job ring (JOBS_SIZE=4) ..... StratumClient::m_jobs
 *     - atomic per-server extra_nonce counter ..... StratumServer::m_extraNonce
 *     - SavedJob{job_id, extra_nonce, template_id, target} .. StratumClient::SavedJob
 *     - two-stage submit: fast mainchain check + background recompute
 *                                                   .. on_submit + on_share_found
 *   DROPPED (p2pool pool-model, deliberately NOT ported): sidechain, PPLNS
 *   window, uncles, auto-diff heuristics kept only as an optional hook, and all
 *   libuv/TCPServer glue (transport is the host's; see ITransport).
 * ---------------------------------------------------------------------------
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "xmr_stratum_messages.hpp"

namespace v37 {
namespace xmr {
namespace stratum {

// ===========================================================================
// SEAM 1 — block-template source (built by the template-builder leg).
// Mirrors p2pool BlockTemplate::get_hashing_blob(extra_nonce, ...). The
// stratum server owns the per-client extra_nonce; the template source bakes it
// into the miner_tx tx_extra 0x02 nonce (scoping §3.4) and returns the exact
// per-client hashing blob plus everything needed to serialize a job and, later,
// to rebuild the identical blob at submit time.
// ===========================================================================
struct TemplateJob {
    std::vector<std::uint8_t> blob;                 // hashing blob, extra_nonce baked in
    std::size_t nonce_offset = EXPECTED_NONCE_OFFSET_V16;
    std::uint32_t template_id = 0;                  // identifies the template snapshot
    std::uint64_t height = 0;                        // Monero mainchain height
    std::uint64_t mainchain_target = 0;              // difficulty->target for a real block
    std::uint64_t lane_target = 0;                   // v37 lane min-difficulty target
    std::array<std::uint8_t, HASH_SIZE> seed_hash{};
    std::optional<std::array<std::uint8_t, HASH_SIZE>> next_seed_hash;
    std::uint8_t monero_major_version = 0;           // for the CARROT fence
};

class ITemplateSource {
public:
    virtual ~ITemplateSource() = default;

    // Produce a fresh per-client job blob for a given extra_nonce. Returns
    // false if no template is available yet (client should wait for on_job()).
    virtual bool get_job(std::uint32_t extra_nonce, TemplateJob& out) = 0;

    // Rebuild the byte-identical blob for a previously-issued (template_id,
    // extra_nonce). Used by the submit path to recompute the PoW. Returns false
    // if the template is gone (=> Stale). Mirrors p2pool's get_hashing_blob
    // overload taking template_id in on_share_found (L1071).
    virtual bool rebuild_blob(std::uint32_t template_id, std::uint32_t extra_nonce,
                              TemplateJob& out) = 0;

    // How many distinct extra_nonce values this template can serve (p2pool
    // BlobsData::m_numClientsExpected). Bounds a single broadcast batch.
    virtual std::uint32_t max_extra_nonces() const = 0;
};

// ===========================================================================
// SEAM 2 — RandomX PoW verifier (randomx-vendor leg wires the real engine).
// Light-mode (cache-only, 256 MiB) verification is sufficient and is the
// default here (scoping §1.2, §1.3, §2.4). Mirrors p2pool
// RandomX_Hasher::calculate / p2pool::calculate_hash (pow_hash.cpp), including
// the two-cache epoch straddle handled inside the implementation.
// ===========================================================================
class IPowVerifier {
public:
    virtual ~IPowVerifier() = default;

    // Compute the RandomX hash of `blob` for the epoch keyed by `seed_hash`.
    // `height` selects the seed epoch (seed_height() formula, scoping §1.1).
    // Returns false only on an operational failure (VM alloc / seed miss) =>
    // SubmitError::CouldNotCheck. force_light asks for the cache-only path
    // (p2pool re-hashes in forced light mode to detect unstable hardware,
    // L1095). NEVER trust a client-reported result — always recompute.
    virtual bool randomx_hash(const std::uint8_t* blob, std::size_t blob_size,
                              std::uint64_t height,
                              const std::array<std::uint8_t, HASH_SIZE>& seed_hash,
                              std::array<std::uint8_t, HASH_SIZE>& out_hash,
                              bool force_light = false) = 0;

    // True iff `hash` meets `target` under Monero's rule (hash * diff < 2^256,
    // equivalently the top-64-bit LE word of the hash <= target). Provided so
    // the check is in one audited place. Mirrors difficulty_type::check_pow.
    virtual bool meets_target(const std::array<std::uint8_t, HASH_SIZE>& hash,
                              std::uint64_t target) const = 0;
};

// ===========================================================================
// SEAM 3 — accepted-share sink (the v37 RDWR / work-receipt model). This is
// where the XMR lane DIVERGES from p2pool: an accepted share does not extend a
// p2pool sidechain — it (a) if it clears the Monero network target, submits a
// real block (p2pool submit_block_async, L431); and (b) is handed to the v37
// lane as a work-receipt candidate for the shared spine / OWED ledger
// (scoping §5, §17). No PPLNS, no uncles.
// ===========================================================================
struct AcceptedShare {
    std::uint32_t template_id = 0;
    std::uint32_t extra_nonce = 0;
    std::uint32_t nonce = 0;
    std::array<std::uint8_t, HASH_SIZE> pow_hash{};
    std::uint64_t achieved_target = 0;   // the hash's own target (for the estimator, scoping §2.4)
    std::uint64_t height = 0;
    bool is_network_block = false;       // cleared the Monero mainchain target
    std::string worker;                  // from the login string
    std::string address;                 // raw base58; descriptor boundary downstream
};

class IShareSink {
public:
    virtual ~IShareSink() = default;
    // Called once per accepted share (already PoW-verified and target-checked).
    virtual void on_accepted_share(const AcceptedShare& share) = 0;
    // Called when a share also clears the Monero network target; submit the
    // full block via monerod (monerod-adapter leg). Mirrors submit_block_async.
    virtual void submit_network_block(std::uint32_t template_id,
                                      std::uint32_t nonce,
                                      std::uint32_t extra_nonce) = 0;
};

// ===========================================================================
// Minimal transport seam — one write per response line. The host adapts this
// to libuv/TCPServer (p2pool) or any socket layer. The dialect and session
// logic never touch a socket directly.
// ===========================================================================
class ITransport {
public:
    virtual ~ITransport() = default;
    // Send one framed JSON line (already newline-terminated) to one client.
    virtual bool send_line(std::uint64_t client_id, std::string_view line) = 0;
    virtual void close(std::uint64_t client_id) = 0;
};

// ===========================================================================
// Per-connection session state. Mirrors StratumClient's mining fields (drops
// the raw read buffers / libuv bits, which belong to the transport).
// ===========================================================================
class XmrStratumSession {
public:
    enum : std::size_t { JOBS_RING = 4 };   // p2pool JOBS_SIZE

    struct SavedJob {                        // p2pool StratumClient::SavedJob
        std::uint32_t job_id = 0;
        std::uint32_t extra_nonce = 0;
        std::uint32_t template_id = 0;
        std::uint64_t target = 0;
    };

    explicit XmrStratumSession(std::uint64_t client_id) : m_clientId(client_id) {}

    std::uint64_t client_id() const { return m_clientId; }
    bool logged_in() const { return m_rpcId != 0; }
    std::uint32_t rpc_id() const { return m_rpcId; }
    void set_rpc_id(std::uint32_t v) { m_rpcId = v; }

    // Allocate the next per-connection job id and record its SavedJob. Returns
    // the new job id. Ring-indexed by job_id % JOBS_RING (p2pool L316/L918).
    std::uint32_t remember_job(std::uint32_t extra_nonce, std::uint32_t template_id,
                               std::uint64_t target);

    // Look up a SavedJob by wire job id; false if it aged out of the ring.
    bool find_job(std::uint32_t job_id, SavedJob& out) const;

    const LoginString& login() const { return m_login; }
    void set_login(LoginString v) { m_login = std::move(v); }

private:
    std::uint64_t m_clientId;
    std::uint32_t m_rpcId = 0;             // 0 == not logged in
    std::uint32_t m_perConnectionJobId = 0;
    std::array<SavedJob, JOBS_RING> m_jobs{};
    LoginString m_login;
};

// ===========================================================================
// StratumDialect — pure, transport-free functions: build responses, parse
// requests. Everything here is unit-testable with no socket and no engine.
// ===========================================================================
struct StratumDialect {
    // hex helpers (Monero/xmrig conventions) --------------------------------
    static std::string to_hex(const std::uint8_t* data, std::size_t n);
    static bool from_hex_byte(char hi, char lo, std::uint8_t& out) noexcept;

    // Encode the 64-bit target as p2pool does: 4-byte compact for large
    // targets (>= TARGET_4_BYTES_LIMIT), full 8-byte otherwise; bytes emitted
    // little-endian (p2pool on_login L332-337 / on_blobs_ready L933-938).
    static std::string encode_target(std::uint64_t target);

    // responses (byte-for-byte the xmrig/p2pool dialect) --------------------
    static std::string build_login_ok(std::uint32_t req_id, std::uint32_t rpc_id,
                                       const JobNotify& job);
    static std::string build_job_notify(const JobNotify& job);
    static std::string build_status_ok(std::uint32_t req_id);       // submit accepted
    static std::string build_error(std::uint32_t req_id, std::string_view message);

    // requests --------------------------------------------------------------
    // Split the xmrig "login" string into address / custom-diff / worker.
    static LoginString parse_login_string(std::string_view login);

    // Decode + validate the three submit fields. On success fills `out` and
    // returns SubmitError::None; otherwise returns the specific failure and
    // leaves `out` unspecified. Reproduces p2pool on_submit L361-395 decoding:
    //   job_id  = big-endian hex nibble accumulate, must be non-zero
    //   nonce   = exactly 8 hex chars, bytes read little-endian into a u32
    //   result  = exactly 64 hex chars, 32 bytes big-endian as-is
    static SubmitError parse_submit(const SubmitFields& in, ParsedSubmit& out) noexcept;
};

// ===========================================================================
// XmrStratumServer — the front-end skeleton. Holds the seams and the global
// extra_nonce counter; drives login / job-broadcast / submit. Concurrency,
// timers, bans and hashrate accounting are the host's (hooks noted inline).
// ===========================================================================
class XmrStratumServer {
public:
    XmrStratumServer(ITemplateSource& templates, IPowVerifier& verifier,
                     IShareSink& sink, ITransport& transport)
        : m_templates(templates), m_verifier(verifier),
          m_sink(sink), m_transport(transport) {}

    // Handle a parsed "login" request: allocate extra_nonce + rpc_id, build the
    // first job, reply with build_login_ok. Returns false to drop the client.
    bool handle_login(XmrStratumSession& s, std::uint32_t req_id,
                      std::string_view login);

    // Handle a parsed "submit" request. Two-stage, mirroring p2pool: (1) fast
    // synchronous field/job checks + optional network-block fast path; (2) the
    // authoritative RandomX recompute + target check via the seams; then reply
    // OK or the specific error. Returns false to drop the client.
    bool handle_submit(XmrStratumSession& s, std::uint32_t req_id,
                       const SubmitFields& fields);

    // Broadcast a fresh template to all logged-in sessions (p2pool on_block ->
    // on_blobs_ready). The host supplies the live session list; each gets a
    // distinct extra_nonce from get_next_extra_nonce().
    void broadcast_job(XmrStratumSession& s);

    std::uint32_t get_next_extra_nonce() { return m_extraNonce.fetch_add(1); }

private:
    // Fill a JobNotify from a TemplateJob + a session's job bookkeeping.
    bool make_job(XmrStratumSession& s, std::uint32_t extra_nonce, JobNotify& out);

    ITemplateSource& m_templates;
    IPowVerifier& m_verifier;
    IShareSink& m_sink;
    ITransport& m_transport;
    std::atomic<std::uint32_t> m_extraNonce{0};
};

} // namespace stratum
} // namespace xmr
} // namespace v37
