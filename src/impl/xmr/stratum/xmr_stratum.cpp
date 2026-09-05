/*
 * xmr_stratum.cpp — skeleton implementation of the V37 Monero/RandomX stratum
 * front-end (Family B: XMR lane). Pure logic only: JSON (de)serialization for
 * the CryptoNote/xmrig login/job/submit dialect, the per-connection job ring,
 * and the two-stage submit pipeline driven through the ITemplateSource /
 * IPowVerifier / IShareSink / ITransport seams. No sockets, no libuv, no
 * RandomX engine, no v37 consensus digest code are referenced here.
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
 * PROVENANCE: the wire bytes and the submit/login control flow re-express
 * SChernykh/p2pool @ master src/stratum_server.cpp (GPL-3.0, read 2026-09-05),
 * combinable into AGPL-3.0 under §13. Line references are in PROVENANCE.md.
 * p2pool's pool model (sidechain/PPLNS/uncles) is NOT reproduced.
 */

#include "xmr_stratum.hpp"

#include <algorithm>
#include <random>
#include <string>

namespace v37 {
namespace xmr {
namespace stratum {

// ---------------------------------------------------------------------------
// constants pinned to p2pool util.h (verify exact values before landing —
// OQ-S5). MAX_TARGET is the easiest possible target (diff 1).
// ---------------------------------------------------------------------------
static constexpr std::uint64_t MAX_TARGET = 0xFFFFFFFFFFFFFFFFULL;

static std::uint64_t target_from_diff(std::uint64_t diff) noexcept {
    return diff ? (MAX_TARGET / diff) : MAX_TARGET;
}

// Achieved-target proxy for the sub-threshold estimator (scoping §2.4): the
// last 8 bytes of the RandomX hash as a little-endian u64. The estimator
// refines this; here it is only carried on the accepted share.
static std::uint64_t hash_top_word_le(const std::array<std::uint8_t, HASH_SIZE>& h) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<std::uint64_t>(h[HASH_SIZE - 8 + i]) << (8 * i);
    return v;
}

std::string_view submit_error_message(SubmitError e) noexcept {
    switch (e) {
        case SubmitError::None:           return "OK";
        case SubmitError::Stale:          return "Stale share";
        case SubmitError::InvalidJobId:   return "Invalid job id";
        case SubmitError::CouldNotCheck:  return "Couldn't check PoW";
        case SubmitError::LowDiff:        return "Low diff share";
        case SubmitError::InvalidPoW:     return "Invalid PoW";
        case SubmitError::Banned:         return "Banned";
        case SubmitError::SubmitFailed:   return "Submit failed";
        case SubmitError::MalformedField: return "Malformed request";
    }
    return "Unknown error";
}

// ===========================================================================
// StratumDialect
// ===========================================================================
static char nibble(std::uint8_t v) noexcept { return "0123456789abcdef"[v & 0xf]; }

std::string StratumDialect::to_hex(const std::uint8_t* data, std::size_t n) {
    std::string out;
    out.resize(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out[i * 2 + 0] = nibble(data[i] >> 4);
        out[i * 2 + 1] = nibble(data[i] & 0xf);
    }
    return out;
}

bool StratumDialect::from_hex_byte(char hi, char lo, std::uint8_t& out) noexcept {
    auto v = [](char c, std::uint8_t& d) -> bool {
        if (c >= '0' && c <= '9') { d = static_cast<std::uint8_t>(c - '0'); return true; }
        if (c >= 'a' && c <= 'f') { d = static_cast<std::uint8_t>(c - 'a' + 10); return true; }
        if (c >= 'A' && c <= 'F') { d = static_cast<std::uint8_t>(c - 'A' + 10); return true; }
        return false;
    };
    std::uint8_t h, l;
    if (!v(hi, h) || !v(lo, l)) return false;
    out = static_cast<std::uint8_t>((h << 4) | l);
    return true;
}

// 8-hex-digit fixed-width lower hex for a u32 (mirrors p2pool log::Hex<u32>).
static std::string u32_hex(std::uint32_t v) {
    std::uint8_t b[4] = {
        static_cast<std::uint8_t>(v >> 24), static_cast<std::uint8_t>(v >> 16),
        static_cast<std::uint8_t>(v >> 8),  static_cast<std::uint8_t>(v),
    };
    return StratumDialect::to_hex(b, 4);
}

std::string StratumDialect::encode_target(std::uint64_t target) {
    // little-endian bytes of the 64-bit target
    std::uint8_t b[8];
    for (int i = 0; i < 8; ++i) b[i] = static_cast<std::uint8_t>(target >> (8 * i));
    // Large target (low diff) => 4-byte compact = the HIGH 4 bytes (skip low 4),
    // exactly p2pool's `m_data += sizeof(uint32_t)` on a little-endian buffer.
    if (target >= TARGET_4_BYTES_LIMIT) return to_hex(b + 4, 4);
    return to_hex(b, 8);
}

// Serialize the shared "job" object body (without surrounding braces). Used by
// both build_login_ok (nested under result.job) and build_job_notify.
static std::string job_object(const JobNotify& j) {
    std::string s;
    s.reserve(256 + j.blob.size() * 2);
    s += "\"blob\":\"";
    s += StratumDialect::to_hex(j.blob.data(), j.blob.size());
    s += "\",\"job_id\":\"";
    s += u32_hex(j.job_id);
    s += "\",\"target\":\"";
    s += StratumDialect::encode_target(j.target);
    s += "\",\"algo\":\"";
    s += ALGO;
    s += "\",\"height\":";
    s += std::to_string(j.height);
    s += ",\"seed_hash\":\"";
    s += StratumDialect::to_hex(j.seed_hash.data(), j.seed_hash.size());
    s += "\"";
    if (j.next_seed_hash) {          // divergence (a): help RandomX pre-init the next epoch
        s += ",\"next_seed_hash\":\"";
        s += StratumDialect::to_hex(j.next_seed_hash->data(), j.next_seed_hash->size());
        s += "\"";
    }
    return s;
}

std::string StratumDialect::build_login_ok(std::uint32_t req_id, std::uint32_t rpc_id,
                                           const JobNotify& job) {
    std::string s;
    s += "{\"id\":";
    s += std::to_string(req_id);
    s += ",\"jsonrpc\":\"2.0\",\"result\":{\"id\":\"";
    s += u32_hex(rpc_id);
    s += "\",\"job\":{";
    s += job_object(job);
    s += "},\"extensions\":[\"algo\"],\"status\":\"OK\"}}\n";
    return s;
}

std::string StratumDialect::build_job_notify(const JobNotify& job) {
    std::string s = "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{";
    s += job_object(job);
    s += "}}\n";
    return s;
}

std::string StratumDialect::build_status_ok(std::uint32_t req_id) {
    std::string s = "{\"id\":";
    s += std::to_string(req_id);
    s += ",\"jsonrpc\":\"2.0\",\"error\":null,\"result\":{\"status\":\"OK\"}}\n";
    return s;
}

std::string StratumDialect::build_error(std::uint32_t req_id, std::string_view message) {
    std::string esc;                      // minimal JSON-string escaping
    esc.reserve(message.size());
    for (char c : message) {
        if (c == '"' || c == '\\') esc += '\\';
        esc += c;
    }
    std::string s = "{\"id\":";
    s += std::to_string(req_id);
    s += ",\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"";
    s += esc;
    s += "\"}}\n";
    return s;
}

LoginString StratumDialect::parse_login_string(std::string_view login) {
    // xmrig: <address>[+<diff>][.<worker> | /<worker>]. The '+' diff suffix and
    // the worker suffix can co-occur; order in the wild is address+diff.worker.
    LoginString out;
    std::string_view rest = login;

    // worker: split on the first '.' or (fallback) first '/'
    std::size_t wpos = rest.find('.');
    if (wpos == std::string_view::npos) wpos = rest.find('/');
    if (wpos != std::string_view::npos) {
        out.worker = std::string(rest.substr(wpos + 1));
        rest = rest.substr(0, wpos);
    }

    // custom diff: trailing "+<decimal>"
    std::size_t dpos = rest.find('+');
    if (dpos != std::string_view::npos) {
        std::string_view d = rest.substr(dpos + 1);
        std::uint64_t v = 0;
        bool ok = !d.empty();
        for (char c : d) {
            if (c < '0' || c > '9') { ok = false; break; }
            v = v * 10 + static_cast<std::uint64_t>(c - '0');
        }
        if (ok) out.custom_diff = v;
        rest = rest.substr(0, dpos);
    }

    out.address = std::string(rest);
    return out;
}

SubmitError StratumDialect::parse_submit(const SubmitFields& in, ParsedSubmit& out) noexcept {
    out.rpc_id = in.rpc_id;

    // job_id: hex, big-endian nibble accumulate, must be non-zero (p2pool L361-373)
    std::uint32_t job_id = 0;
    if (in.job_id.empty()) return SubmitError::MalformedField;
    for (char c : in.job_id) {
        std::uint8_t d;
        // decode a single nibble by reusing from_hex_byte with a '0' high half
        if (!from_hex_byte('0', c, d)) return SubmitError::MalformedField;
        job_id = (job_id << 4) + d;
    }
    if (job_id == 0) return SubmitError::InvalidJobId;
    out.job_id = job_id;

    // nonce: exactly 8 hex chars, bytes read little-endian into a u32 (L375-384)
    if (in.nonce.size() != NONCE_SIZE * 2) return SubmitError::MalformedField;
    std::uint32_t nonce = 0;
    for (int i = static_cast<int>(NONCE_SIZE) - 1; i >= 0; --i) {
        std::uint8_t b;
        if (!from_hex_byte(in.nonce[i * 2 + 0], in.nonce[i * 2 + 1], b))
            return SubmitError::MalformedField;
        nonce = (nonce << 8) | b;
    }
    out.nonce = nonce;

    // result: exactly 64 hex chars, 32 bytes big-endian as-is (L386-395)
    if (in.result.size() != HASH_SIZE * 2) return SubmitError::MalformedField;
    for (std::size_t i = 0; i < HASH_SIZE; ++i) {
        std::uint8_t b;
        if (!from_hex_byte(in.result[i * 2 + 0], in.result[i * 2 + 1], b))
            return SubmitError::MalformedField;
        out.result[i] = b;
    }
    return SubmitError::None;
}

// ===========================================================================
// XmrStratumSession
// ===========================================================================
std::uint32_t XmrStratumSession::remember_job(std::uint32_t extra_nonce,
                                              std::uint32_t template_id,
                                              std::uint64_t target) {
    const std::uint32_t job_id = ++m_perConnectionJobId;
    SavedJob& sj = m_jobs[job_id % JOBS_RING];
    sj.job_id = job_id;
    sj.extra_nonce = extra_nonce;
    sj.template_id = template_id;
    sj.target = target;
    return job_id;
}

bool XmrStratumSession::find_job(std::uint32_t job_id, SavedJob& out) const {
    if (job_id == 0) return false;
    const SavedJob& sj = m_jobs[job_id % JOBS_RING];
    if (sj.job_id != job_id) return false;   // aged out of the 4-deep ring
    out = sj;
    return true;
}

// ===========================================================================
// XmrStratumServer
// ===========================================================================
// Skeleton RNG for rpc_id. Production must use the server's seeded, locked RNG
// (p2pool StratumServer::get_random32 under m_rngLock); a thread-local here
// keeps the skeleton self-contained.
static std::uint32_t skeleton_random32() {
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uint32_t v;
    do { v = static_cast<std::uint32_t>(rng()); } while (v == 0);
    return v;
}

bool XmrStratumServer::make_job(XmrStratumSession& s, std::uint32_t extra_nonce,
                                JobNotify& out) {
    TemplateJob tj;
    if (!m_templates.get_job(extra_nonce, tj)) return false;

    // Job target = easiest of {lane min, custom diff}, capped (p2pool on_login
    // L293-305). The much-harder mainchain target is used only at submit time
    // to detect a real network block; including it via max() would not change
    // the (easier) job target.
    std::uint64_t target = tj.lane_target ? tj.lane_target : MAX_TARGET;
    if (s.login().custom_diff)
        target = std::max(target, target_from_diff(*s.login().custom_diff));
    target = std::min(target, MAX_TARGET);

    const std::uint32_t job_id = s.remember_job(extra_nonce, tj.template_id, target);

    out.blob = std::move(tj.blob);
    out.job_id = job_id;
    out.target = target;
    out.height = tj.height;
    out.seed_hash = tj.seed_hash;
    out.next_seed_hash = tj.next_seed_hash;
    out.nonce_offset = tj.nonce_offset;
    return true;
}

bool XmrStratumServer::handle_login(XmrStratumSession& s, std::uint32_t req_id,
                                    std::string_view login) {
    if (s.logged_in()) {
        // duplicate login on one connection — p2pool drops it (L275-278)
        return false;
    }
    s.set_login(StratumDialect::parse_login_string(login));

    const std::uint32_t extra_nonce = get_next_extra_nonce();
    JobNotify job;
    if (!make_job(s, extra_nonce, job)) {
        // No template yet — reply with an error but keep the connection; the
        // next broadcast_job() will feed it.
        m_transport.send_line(s.client_id(),
                              StratumDialect::build_error(req_id, "No job available"));
        return true;
    }

    const std::uint32_t rpc_id = skeleton_random32();
    if (!m_transport.send_line(s.client_id(),
                               StratumDialect::build_login_ok(req_id, rpc_id, job))) {
        return false;
    }
    s.set_rpc_id(rpc_id);
    return true;
}

bool XmrStratumServer::handle_submit(XmrStratumSession& s, std::uint32_t req_id,
                                     const SubmitFields& fields) {
    ParsedSubmit ps;
    const SubmitError perr = StratumDialect::parse_submit(fields, ps);
    if (perr == SubmitError::MalformedField) {
        // parse-level garbage — drop the connection (p2pool returns false)
        return false;
    }
    if (perr == SubmitError::InvalidJobId) {
        return m_transport.send_line(
            s.client_id(),
            StratumDialect::build_error(req_id, submit_error_message(perr)));
    }

    XmrStratumSession::SavedJob sj;
    if (!s.find_job(ps.job_id, sj)) {
        return m_transport.send_line(
            s.client_id(),
            StratumDialect::build_error(req_id,
                                        submit_error_message(SubmitError::InvalidJobId)));
    }

    // Rebuild the byte-identical blob for (template_id, extra_nonce). If the
    // template is gone the share is stale.
    TemplateJob tj;
    if (!m_templates.rebuild_blob(sj.template_id, sj.extra_nonce, tj)) {
        return m_transport.send_line(
            s.client_id(),
            StratumDialect::build_error(req_id,
                                        submit_error_message(SubmitError::Stale)));
    }

    // Insert the 4-byte header nonce (little-endian) at the template's nonce
    // offset (=39 for v16 headers). Bounds-check defensively.
    if (tj.nonce_offset + NONCE_SIZE > tj.blob.size()) {
        return m_transport.send_line(
            s.client_id(),
            StratumDialect::build_error(req_id,
                                        submit_error_message(SubmitError::CouldNotCheck)));
    }
    for (std::size_t i = 0; i < NONCE_SIZE; ++i)
        tj.blob[tj.nonce_offset + i] = static_cast<std::uint8_t>(ps.nonce >> (8 * i));

    // AUTHORITATIVE check: recompute the RandomX hash ourselves. The client's
    // `result` is never trusted for PoW (only cross-checked for logging).
    std::array<std::uint8_t, HASH_SIZE> pow_hash{};
    if (!m_verifier.randomx_hash(tj.blob.data(), tj.blob.size(), tj.height,
                                 tj.seed_hash, pow_hash)) {
        return m_transport.send_line(
            s.client_id(),
            StratumDialect::build_error(req_id,
                                        submit_error_message(SubmitError::CouldNotCheck)));
    }

    // (1) does it clear the Monero network target? -> real block
    const bool network_block =
        tj.mainchain_target && m_verifier.meets_target(pow_hash, tj.mainchain_target);
    if (network_block) {
        m_sink.submit_network_block(sj.template_id, ps.nonce, sj.extra_nonce);
    }

    // (2) does it clear the job (lane) target? -> accepted share, else low diff
    if (!m_verifier.meets_target(pow_hash, sj.target)) {
        return m_transport.send_line(
            s.client_id(),
            StratumDialect::build_error(req_id,
                                        submit_error_message(SubmitError::LowDiff)));
    }

    AcceptedShare acc;
    acc.template_id = sj.template_id;
    acc.extra_nonce = sj.extra_nonce;
    acc.nonce = ps.nonce;
    acc.pow_hash = pow_hash;
    acc.achieved_target = hash_top_word_le(pow_hash);
    acc.height = tj.height;
    acc.is_network_block = network_block;
    acc.worker = s.login().worker;
    acc.address = s.login().address;
    m_sink.on_accepted_share(acc);

    return m_transport.send_line(s.client_id(), StratumDialect::build_status_ok(req_id));
}

void XmrStratumServer::broadcast_job(XmrStratumSession& s) {
    if (!s.logged_in()) return;   // on_login() will send the first job
    JobNotify job;
    if (!make_job(s, get_next_extra_nonce(), job)) return;
    m_transport.send_line(s.client_id(), StratumDialect::build_job_notify(job));
}

} // namespace stratum
} // namespace xmr
} // namespace v37
