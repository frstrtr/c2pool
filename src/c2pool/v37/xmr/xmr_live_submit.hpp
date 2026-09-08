// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_live_submit.hpp   (Track A2 / Milestone A — X9 O-2,
//                                            wire (3): LIVE SUBMIT)
//
// THE LIVE-SUBMIT COMPONENT. Given a block candidate (the monerod block-template
// bytes the stratum front-end served) and the winning header nonce, it
//
//   1. ASSEMBLES the full Monero block blob — the FULL blocktemplate_blob with
//      the 4-byte little-endian nonce patched at the header nonce offset (and,
//      when the template reserved tx_extra space, the per-client extra_nonce
//      patched at reserved_offset);
//   2. SUBMITS it to monerod over the X2 seam (IMonerodTransport::rpc_post with
//      the KAT-pinned MoneroDaemonRpc::body_submit_block body);
//   3. RETURNS ACCEPTANCE — monerod's status, plus the BLOCK ID the finalize
//      driver must be handed. The id is resolved from three sources, in order:
//        (a) result.block_id in monerod's submit_block response (authoritative;
//            the tree's MoneroDaemonRpc::parse_submit_block does NOT read it, so
//            this header carries its own parser — no existing file is edited);
//        (b) a LOCAL computation keccak256(varint(len) ‖ hashing_blob_with_nonce)
//            — the CryptoNote object-hash framing monerod applies to the hashing
//            blob (get_block_hash == get_object_hash(get_block_hashing_blob)),
//            over the vendored keccak in xmr_coin;
//        (c) get_block_header_by_height(H) whose prev_hash matches the template's
//            prev_id (a cross-check of (a)/(b) and the fallback for a monerod
//            that returns no block_id).
//      Any disagreement between the sources is recorded loudly (id_mismatch /
//      HeaderCheck::Mismatch) but never silently papered over: the bid handed
//      on is monerod's own when it gave one, because XmrNode's is_canonical
//      predicate compares against index().by_height(H).id — monerod's view.
//
// HONEST SCOPE (option A, per the O-2 survey): the bytes submitted are monerod's
// get_block_template block (single coinbase to the template wallet address)
// with the nonce patched — a genuine, monerod-validated, accepted block end to
// end, but NOT the v37 K_fair settlement coinbase. Option B (XmrBlockTemplate +
// X6 executor over an implemented xmr_coin_primitives seam) slots in behind the
// same BlockCandidate: full_blob := get_block_template_blob(...), hashing_blob
// := get_hashing_blob(...). Nothing in this header depends on which option
// produced the bytes.
//
// FAIL-CLOSED: SubmitPolicy::network_submit_enabled defaults to FALSE. The
// assembler must set it from (RandomX compiled in && cfg.randomx_enabled &&
// verifier ready). A stratum front-end that "structurally checks only" must
// never reach monerod with an unverified block (xmr_node_config.hpp:104-107).
//
// THREADING (O-2 contract, survey §E): submit() runs on the STRATUM LISTENER
// thread. It uses only the transport (LiveMonerodTransport opens a fresh socket
// per call, so it is safe alongside the main loop's pump_poll) and its own
// state. It NEVER touches MonerodAdapter / MainchainIndex / XmrFinalizeDriver.
// A found block crosses to the main thread through FoundBlockQueue (mutex),
// where the main loop calls XmrNode::on_network_block_won(). The transport
// must complete rpc_post synchronously (LiveMonerodTransport and
// MockMonerodTransport both do); an asynchronous transport is detected and
// reported as an error rather than mis-read as a rejection.
//
// CONSUMER-TREE ONLY. Defines NO consensus digest. Uses ONLY: the X2 seam
// (IMonerodTransport / RpcResponse / MoneroDaemonRpc body builders +
// parse_block_header / ChainMainBlock / Hash), minijson, xmr_coin's BlobWriter
// (monerod-identical varint) + keccak256, and the X5 IShareSink / AcceptedShare
// seam. Header-only; the only link dependencies are xmr_node (monero_rpc.cpp)
// and xmr_coin (vendored keccak), both already linked by c2pool-v37-xmr.
// ===========================================================================
#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"              // ::xmr::coin::BlobWriter (vendored varint)
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"   // ::xmr::coin::keccak256 (vendored cn_fast_hash)
#include "impl/xmr/node/minijson.hpp"              // parse / hex_to_hash / hash_to_hex
#include "impl/xmr/node/monero_rpc.hpp"            // MoneroDaemonRpc::body_* / parse_block_header
#include "impl/xmr/node/monerod_transport.hpp"     // IMonerodTransport / RpcResponse
#include "impl/xmr/node/xmr_node_types.hpp"        // Hash / ChainMainBlock / is_zero
#include "impl/xmr/stratum/xmr_stratum.hpp"        // IShareSink / AcceptedShare / NONCE_SIZE

namespace c2pool::v37n::xmr::submit {

using Hash = ::c2pool::xmr::node::Hash;
using ::c2pool::xmr::node::ChainMainBlock;
using ::c2pool::xmr::node::IMonerodTransport;
using ::c2pool::xmr::node::MoneroDaemonRpc;
using ::c2pool::xmr::node::RpcResponse;
namespace mj    = ::c2pool::xmr::node::minijson;
namespace strat = ::v37::xmr::stratum;

// ---------------------------------------------------------------------------
// small byte helpers (local; no dependency on xmr_stratum.cpp's StratumDialect)
// ---------------------------------------------------------------------------
inline std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0xf]);
    }
    return s;
}
inline std::string to_hex(const std::vector<std::uint8_t>& v) { return to_hex(v.data(), v.size()); }

inline bool from_hex(const std::string& hex, std::vector<std::uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

// Overflow-safe "[off, off+4) lies inside blob".
inline bool u32_fits(const std::vector<std::uint8_t>& blob, std::size_t off) noexcept {
    return off <= blob.size() && blob.size() - off >= strat::NONCE_SIZE;
}

// Patch a 4-byte little-endian u32 at `off`. False if it does not fit.
inline bool patch_u32_le(std::vector<std::uint8_t>& blob, std::size_t off, std::uint32_t v) noexcept {
    if (!u32_fits(blob, off)) return false;
    for (std::size_t i = 0; i < strat::NONCE_SIZE; ++i)
        blob[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
    return true;
}

// ===========================================================================
// BlockCandidate — what the template layer hands the submitter for ONE
// (template_id, extra_nonce). Option A fills it straight from get_block_template
// (+ the served hashing blob); option B from XmrBlockTemplate. The header bytes
// [0, nonce_offset) of full_blob and hashing_blob MUST agree — both start with
// the same block header (varint major ‖ varint minor ‖ varint ts ‖ prev[32]) —
// and validate_candidate() enforces it, so a mismatched pair can never be
// submitted under the wrong id.
// ===========================================================================
struct BlockCandidate {
    std::uint32_t template_id = 0;
    std::uint64_t height = 0;                 // Monero height of the block

    // blocktemplate_blob: header ‖ miner_tx ‖ varint(n_tx_hashes) ‖ 32·n. This is
    // what is SUBMITTED (with the nonce patched).
    std::vector<std::uint8_t> full_blob;

    // blockhashing_blob AS SERVED to the miner for (template_id, extra_nonce):
    // header ‖ tree_root[32] ‖ varint(n_tx+1) — the exact RandomX input before
    // the nonce. Optional (empty => no local block-id computation); when the
    // template baked an extra_nonce into the miner_tx this must be the blob
    // rebuilt for THAT extra_nonce (ITemplateSource::rebuild_blob's contract).
    std::vector<std::uint8_t> hashing_blob;

    std::size_t nonce_offset = strat::EXPECTED_NONCE_OFFSET_V16;   // 39 for v16 headers

    // Optional extra_nonce splice inside the miner_tx of full_blob (monerod
    // get_block_template reserve_size ≥ 4 → reserved_offset). 0/0 = not used;
    // the single-template solo demo leaves this unset.
    std::size_t reserved_offset = 0;
    std::size_t reserved_size   = 0;

    Hash          prev_id{};                  // template prev_hash (zero = unknown)
    std::uint64_t expected_reward = 0;        // piconero (get_block_template.expected_reward)
    std::uint8_t  major_version = 0;          // template major_version (diagnostic)
};

// Validate a candidate BEFORE any bytes are touched. Returns "" when sane.
inline std::string validate_candidate(const BlockCandidate& c) {
    if (c.height == 0) return "candidate: height is 0";
    if (c.full_blob.empty()) return "candidate: empty full_blob";
    if (!u32_fits(c.full_blob, c.nonce_offset))
        return "candidate: nonce_offset " + std::to_string(c.nonce_offset) +
               " past full_blob end (" + std::to_string(c.full_blob.size()) + ")";
    if (!c.hashing_blob.empty()) {
        if (!u32_fits(c.hashing_blob, c.nonce_offset))
            return "candidate: nonce_offset past hashing_blob end";
        // Both blobs share the header up to (and including) the nonce field.
        if (std::memcmp(c.full_blob.data(), c.hashing_blob.data(), c.nonce_offset) != 0)
            return "candidate: hashing_blob / full_blob header prefix disagree "
                   "(wrong template pairing?)";
    }
    if (c.reserved_size != 0) {
        if (c.reserved_size < strat::NONCE_SIZE)
            return "candidate: reserved_size < 4 cannot carry an extra_nonce";
        if (c.reserved_offset > c.full_blob.size() ||
            c.full_blob.size() - c.reserved_offset < c.reserved_size)
            return "candidate: reserved region past full_blob end";
        if (c.reserved_offset < c.nonce_offset + strat::NONCE_SIZE)
            return "candidate: reserved region overlaps the block header";
    }
    return {};
}

// ---------------------------------------------------------------------------
// ASSEMBLY (pure). Precondition: validate_candidate(c).empty().
// ---------------------------------------------------------------------------

// The block blob to submit: full_blob with the winning nonce (and, when the
// template reserved space, the extra_nonce) patched in little-endian.
inline std::vector<std::uint8_t> assemble_block_blob(const BlockCandidate& c,
                                                     std::uint32_t nonce,
                                                     std::uint32_t extra_nonce) {
    std::vector<std::uint8_t> blob = c.full_blob;
    patch_u32_le(blob, c.nonce_offset, nonce);
    if (c.reserved_size >= strat::NONCE_SIZE)
        patch_u32_le(blob, c.reserved_offset, extra_nonce);
    return blob;
}

// The exact RandomX input that won: served hashing blob with the nonce patched.
inline std::vector<std::uint8_t> hashing_blob_with_nonce(const BlockCandidate& c,
                                                         std::uint32_t nonce) {
    std::vector<std::uint8_t> blob = c.hashing_blob;
    patch_u32_le(blob, c.nonce_offset, nonce);
    return blob;
}

// Monero block id of a hashing blob: keccak256(varint(len) ‖ hashing_blob).
// monerod: get_block_hash(b) == get_object_hash(get_block_hashing_blob(b)), and
// get_object_hash serialises the blobdata (varint length-prefixed) before
// cn_fast_hash. The varint is xmr_coin's vendored tools::write_varint, so the
// framing is byte-identical to monerod's. (Pinned by the O-2 self-check against
// the Monero mainnet genesis block id.)
inline Hash block_id_of_hashing_blob(const std::vector<std::uint8_t>& hashing_blob) {
    ::xmr::coin::BlobWriter w;
    w.put_varint(static_cast<std::uint64_t>(hashing_blob.size()));
    w.put_bytes(hashing_blob.data(), hashing_blob.size());
    const ::xmr::coin::Hash256 h = ::xmr::coin::keccak256(w.bytes());
    Hash out{};
    std::memcpy(out.data(), h.data(), out.size());
    return out;
}

// ===========================================================================
// submit_block response — parsed INCLUDING result.block_id (the tree's
// MoneroDaemonRpc::parse_submit_block reads status only; monero_rpc.cpp:156-169).
// Shapes handled:
//   {"result":{"status":"OK","block_id":"<64 hex>",...}}        accepted
//   {"result":{"status":"<anything else>"}}                      rejected
//   {"error":{"code":-7,"message":"Block not accepted"}}         rejected (rpc)
//   {"error":{"code":-6,"message":"Wrong block blob"}}           rejected (rpc)
// ===========================================================================
struct SubmitAck {
    bool        accepted = false;
    std::string status;          // result.status ("OK" on success)
    std::string error;           // "rpc: <message>" / "json: ..." when not accepted
    long        rpc_code = 0;    // error.code when an rpc error was returned
    std::optional<Hash> block_id;  // result.block_id, when monerod supplied it
};

inline SubmitAck parse_submit_block_ack(const char* p, std::size_t n) {
    SubmitAck out;
    mj::Value root;
    if (!mj::parse(p, n, root)) { out.error = "json: parse failed"; return out; }
    const mj::Value& r = root["result"];
    if (r.is_object()) {
        out.status   = r["status"].as_string();
        out.accepted = (out.status == "OK");
        const std::string bid = r["block_id"].as_string();
        Hash h{};
        if (!bid.empty() && mj::hex_to_hash(bid, h)) out.block_id = h;
        if (!out.accepted) out.error = "rpc: status " + (out.status.empty() ? "<empty>" : out.status);
        return out;
    }
    const mj::Value& e = root["error"];
    if (e.is_object()) {
        out.error    = "rpc: " + e["message"].as_string();
        out.rpc_code = std::strtol(e["code"].as_string().c_str(), nullptr, 10);
    } else {
        out.error = "json: no result";
    }
    return out;
}
inline SubmitAck parse_submit_block_ack(const std::vector<char>& body) {
    return parse_submit_block_ack(body.data(), body.size());
}

// ===========================================================================
// Outcome of one submit — everything the assembler / the log / the FOUND event
// needs. `block_id` is the bid to hand to XmrNode::on_network_block_won (via
// mj::hash_to_hex, lowercase — the same encoding XmrNode::hex_of produces).
// ===========================================================================
enum class IdSource : std::uint8_t { None = 0, Monerod = 1, Local = 2, Header = 3 };
enum class HeaderCheck : std::uint8_t { NotRun = 0, Confirmed = 1, Mismatch = 2, Error = 3 };

inline const char* to_string(IdSource s) {
    switch (s) {
        case IdSource::None:    return "none";
        case IdSource::Monerod: return "monerod";
        case IdSource::Local:   return "local";
        case IdSource::Header:  return "header";
    }
    return "none";
}
inline const char* to_string(HeaderCheck c) {
    switch (c) {
        case HeaderCheck::NotRun:    return "not-run";
        case HeaderCheck::Confirmed: return "confirmed";
        case HeaderCheck::Mismatch:  return "MISMATCH";
        case HeaderCheck::Error:     return "error";
    }
    return "not-run";
}

struct SubmitOutcome {
    bool        accepted = false;       // monerod returned status "OK"
    bool        refused  = false;       // never posted (policy / malformed candidate)
    std::string status;                 // monerod result.status
    std::string error;                  // refusal / transport / rpc text
    long        rpc_code = 0;

    std::uint64_t height = 0;
    std::uint32_t template_id = 0;
    std::uint32_t nonce = 0;
    std::uint32_t extra_nonce = 0;

    Hash        block_id{};             // the bid for the finalize driver (zero if unknown)
    IdSource    id_source = IdSource::None;
    std::optional<Hash> monerod_block_id;   // (a) result.block_id
    std::optional<Hash> local_block_id;     // (b) keccak(varint ‖ hashing_blob)
    std::optional<Hash> header_block_id;    // (c) get_block_header_by_height(H).hash
    bool        id_mismatch = false;        // (a) and (b) both present and differ
    HeaderCheck header_check = HeaderCheck::NotRun;

    std::string block_blob_hex;         // exactly what was posted (diagnostic)
    double      rpc_ms = 0.0;           // submit_block round-trip

    std::string block_id_hex() const { return mj::hash_to_hex(block_id); }
    bool has_block_id() const { return id_source != IdSource::None; }
};

// ===========================================================================
// SubmitPolicy — fail-closed knobs. The assembler flips network_submit_enabled
// ON only when the RandomX verifier is live (compiled in + --randomx + init ok).
// ===========================================================================
struct SubmitPolicy {
    bool network_submit_enabled = false;   // FAIL-CLOSED default
    bool compute_local_id       = true;    // (b) when a hashing blob is supplied
    bool confirm_with_header    = true;    // (c) one get_block_header_by_height after OK
};

// ===========================================================================
// LiveBlockSubmitter — assemble + submit + resolve the block id.
// One instance; submit() is called from the listener thread. Counters are
// atomics so the main loop can print them; last_error()/last_outcome() are
// mutex-guarded copies.
// ===========================================================================
class LiveBlockSubmitter {
public:
    LiveBlockSubmitter(IMonerodTransport& transport, SubmitPolicy policy = {})
        : m_tx(transport), m_policy(policy), m_enabled(policy.network_submit_enabled) {}

    LiveBlockSubmitter(const LiveBlockSubmitter&) = delete;
    LiveBlockSubmitter& operator=(const LiveBlockSubmitter&) = delete;

    // Flip the fail-closed gate (main thread, before the listener starts, or
    // any time — it is atomic).
    void enable_network_submit(bool on) { m_enabled.store(on); }
    bool network_submit_enabled() const { return m_enabled.load(); }
    const SubmitPolicy& policy() const { return m_policy; }

    // THE ENTRY POINT. Listener thread. Blocking for one (or two) RPC round
    // trips on a fresh socket each.
    SubmitOutcome submit(const BlockCandidate& c, std::uint32_t nonce, std::uint32_t extra_nonce) {
        SubmitOutcome o;
        o.height = c.height;
        o.template_id = c.template_id;
        o.nonce = nonce;
        o.extra_nonce = extra_nonce;
        m_calls.fetch_add(1);

        // 0) fail-closed gate + candidate sanity, BEFORE any bytes are assembled.
        if (!m_enabled.load()) {
            o.refused = true;
            o.error = "submit refused: network submit disabled (fail-closed — RandomX "
                      "verify not live / --randomx not given)";
            return finish(o, &m_refused);
        }
        if (std::string v = validate_candidate(c); !v.empty()) {
            o.refused = true;
            o.error = "submit refused: " + v;
            return finish(o, &m_refused);
        }

        // 1) assemble the block bytes (+ the local id, if we can).
        const std::vector<std::uint8_t> blob = assemble_block_blob(c, nonce, extra_nonce);
        o.block_blob_hex = to_hex(blob);
        if (m_policy.compute_local_id && !c.hashing_blob.empty())
            o.local_block_id = block_id_of_hashing_blob(hashing_blob_with_nonce(c, nonce));

        // 2) submit_block — the KAT-pinned body, over the X2 seam.
        const auto t0 = std::chrono::steady_clock::now();
        SubmitAck ack;
        bool done = false;
        m_tx.rpc_post(MoneroDaemonRpc::body_submit_block(o.block_blob_hex),
                      [&](const RpcResponse& r) {
                          done = true;
                          if (!r.ok()) { ack.error = "transport: " + r.error; return; }
                          ack = parse_submit_block_ack(r.body);
                      });
        o.rpc_ms = std::chrono::duration<double, std::milli>(
                       std::chrono::steady_clock::now() - t0).count();
        if (!done) {
            o.error = "submit: transport did not complete synchronously "
                      "(LiveBlockSubmitter requires a blocking IMonerodTransport)";
            return finish(o, &m_transport_errors);
        }
        o.status   = ack.status;
        o.rpc_code = ack.rpc_code;
        if (!ack.accepted) {
            o.error = ack.error.empty() ? "submit rejected" : ack.error;
            return finish(o, ack.error.rfind("transport:", 0) == 0 ? &m_transport_errors : &m_rejected);
        }

        // 3) ACCEPTED. Resolve the block id: monerod > local > header.
        o.accepted = true;
        m_ok.fetch_add(1);
        o.monerod_block_id = ack.block_id;
        if (o.monerod_block_id) {
            o.block_id = *o.monerod_block_id;
            o.id_source = IdSource::Monerod;
            if (o.local_block_id && *o.local_block_id != *o.monerod_block_id) {
                o.id_mismatch = true;
                m_id_mismatches.fetch_add(1);
            }
        } else if (o.local_block_id) {
            o.block_id = *o.local_block_id;
            o.id_source = IdSource::Local;
        }

        // 4) Cross-check / fallback via the settled header at H.
        if (m_policy.confirm_with_header) confirm_with_header(c, o);

        if (!o.has_block_id()) {
            o.error = "accepted, but block id UNKNOWN (monerod gave no block_id, no "
                      "hashing_blob for a local id, header lookup " +
                      std::string(to_string(o.header_check)) + ")";
            m_unattributable.fetch_add(1);
        }
        return finish(o, nullptr);
    }

    // --- diagnostics (never consensus) --------------------------------------
    std::size_t calls()            const { return m_calls.load(); }
    std::size_t ok()               const { return m_ok.load(); }
    std::size_t rejected()         const { return m_rejected.load(); }
    std::size_t refused()          const { return m_refused.load(); }
    std::size_t transport_errors() const { return m_transport_errors.load(); }
    std::size_t id_mismatches()    const { return m_id_mismatches.load(); }
    std::size_t unattributable()   const { return m_unattributable.load(); }

    std::string last_error() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_last.error;
    }
    SubmitOutcome last_outcome() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_last;
    }

private:
    SubmitOutcome& finish(SubmitOutcome& o, std::atomic<std::size_t>* bump) {
        if (bump) bump->fetch_add(1);
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last = o;
        return o;
    }

    // (c) get_block_header_by_height(H): confirm the id we hold, or adopt the
    // header's id when we hold none and its prev_hash matches the template's
    // prev_id (so a competing block at H cannot be mistaken for ours).
    void confirm_with_header(const BlockCandidate& c, SubmitOutcome& o) {
        std::optional<ChainMainBlock> hdr;
        std::string err;
        bool done = false;
        m_tx.rpc_post(MoneroDaemonRpc::body_get_block_header_by_height(c.height),
                      [&](const RpcResponse& r) {
                          done = true;
                          if (!r.ok()) { err = r.error; return; }
                          hdr = MoneroDaemonRpc::parse_block_header(r.body);
                          if (!hdr) err = "get_block_header_by_height: parse failed";
                      });
        if (!done || !hdr) { o.header_check = HeaderCheck::Error; return; }
        o.header_block_id = hdr->id;
        const bool prev_ok = ::c2pool::xmr::node::is_zero(c.prev_id) || hdr->prev_id == c.prev_id;
        if (o.has_block_id()) {
            o.header_check = (hdr->id == o.block_id) ? HeaderCheck::Confirmed : HeaderCheck::Mismatch;
            if (o.header_check == HeaderCheck::Mismatch) m_id_mismatches.fetch_add(1);
            return;
        }
        if (prev_ok) {
            o.block_id = hdr->id;
            o.id_source = IdSource::Header;
            o.header_check = HeaderCheck::Confirmed;
        } else {
            o.header_check = HeaderCheck::Mismatch;   // another block sits at H
        }
    }

    IMonerodTransport&        m_tx;
    SubmitPolicy              m_policy;
    std::atomic<bool>         m_enabled;
    std::atomic<std::size_t>  m_calls{0}, m_ok{0}, m_rejected{0}, m_refused{0},
                              m_transport_errors{0}, m_id_mismatches{0}, m_unattributable{0};
    mutable std::mutex        m_mtx;
    SubmitOutcome             m_last;
};

// ===========================================================================
// FoundBlockEvent / FoundBlockQueue — the listener→main hand-off for an
// ACCEPTED block. Carries everything wire (4) needs: height + block_id (for
// XmrNode::on_network_block_won), reward (for the credit/payout amounts),
// prev_id, and attribution for the log. Worker/address are filled in a beat
// later by on_accepted_share (see LiveSubmitShareSink) via annotate().
// ===========================================================================
struct FoundBlockEvent {
    std::uint64_t height = 0;
    Hash          block_id{};
    Hash          prev_id{};
    std::uint64_t reward = 0;            // piconero (template expected_reward)
    std::uint32_t template_id = 0;
    std::uint32_t nonce = 0;
    std::uint32_t extra_nonce = 0;
    std::string   worker;                // from the login string (may be empty)
    std::string   address;               // raw base58 login address (may be empty)
    IdSource      id_source = IdSource::None;
    bool          id_mismatch = false;
    HeaderCheck   header_check = HeaderCheck::NotRun;
    double        rpc_ms = 0.0;
    std::chrono::steady_clock::time_point at{};

    std::string block_id_hex() const { return mj::hash_to_hex(block_id); }
};

class FoundBlockQueue {
public:
    void push(FoundBlockEvent e) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_q.push_back(std::move(e));
        m_pushed.fetch_add(1);
    }
    bool pop(FoundBlockEvent& out) {
        std::lock_guard<std::mutex> lk(m_mtx);
        if (m_q.empty()) return false;
        out = std::move(m_q.front());
        m_q.pop_front();
        return true;
    }
    // Attach worker/address to a queued event (no-op if already drained —
    // attribution is diagnostic only, never settlement-bearing).
    void annotate(std::uint32_t template_id, std::uint32_t nonce, std::uint32_t extra_nonce,
                  const std::string& worker, const std::string& address) {
        std::lock_guard<std::mutex> lk(m_mtx);
        for (auto it = m_q.rbegin(); it != m_q.rend(); ++it) {
            if (it->template_id == template_id && it->nonce == nonce &&
                it->extra_nonce == extra_nonce) {
                it->worker = worker;
                it->address = address;
                return;
            }
        }
    }
    std::size_t size() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_q.size();
    }
    std::size_t pushed() const { return m_pushed.load(); }

private:
    mutable std::mutex         m_mtx;
    std::deque<FoundBlockEvent> m_q;
    std::atomic<std::size_t>   m_pushed{0};
};

// ===========================================================================
// LiveSubmitShareSink — the X5 IShareSink that plugs LiveBlockSubmitter into
// XmrStratumServer. handle_submit (xmr_stratum.cpp:402-406) calls
// submit_network_block(template_id, nonce, extra_nonce) BEFORE the lane-target
// check and BEFORE on_accepted_share (:426), so:
//   * submit_network_block: look the candidate up (CandidateLookup — the
//     assembler binds it to the template provider's full blob + the template
//     source's rebuild_blob hashing blob), submit, and on OK push a
//     FoundBlockEvent;
//   * on_accepted_share (is_network_block): annotate that event with the
//     worker/address (same triple, same thread, moments later).
// ===========================================================================
class LiveSubmitShareSink final : public strat::IShareSink {
public:
    // Fill `out` for (template_id, extra_nonce); false => template gone (stale).
    using CandidateLookup =
        std::function<bool(std::uint32_t template_id, std::uint32_t extra_nonce, BlockCandidate& out)>;

    LiveSubmitShareSink(LiveBlockSubmitter& submitter, FoundBlockQueue& found, CandidateLookup lookup)
        : m_submitter(submitter), m_found(found), m_lookup(std::move(lookup)) {}

    void on_accepted_share(const strat::AcceptedShare& s) override {
        m_accepted.fetch_add(1);
        if (s.is_network_block)
            m_found.annotate(s.template_id, s.nonce, s.extra_nonce, s.worker, s.address);
    }

    void submit_network_block(std::uint32_t template_id, std::uint32_t nonce,
                              std::uint32_t extra_nonce) override {
        BlockCandidate c;
        if (!m_lookup || !m_lookup(template_id, extra_nonce, c)) {
            m_stale.fetch_add(1);
            set_error("submit: template " + std::to_string(template_id) + " gone (stale)");
            return;
        }
        const SubmitOutcome o = m_submitter.submit(c, nonce, extra_nonce);
        if (!o.accepted) { set_error(o.error); return; }
        if (!o.has_block_id()) {
            // Accepted by monerod but we cannot name it: NEVER hand a zero bid to
            // the finalize driver (is_canonical would orphan it at maturity).
            set_error(o.error);
            return;
        }
        FoundBlockEvent ev;
        ev.height       = o.height;
        ev.block_id     = o.block_id;
        ev.prev_id      = c.prev_id;
        ev.reward       = c.expected_reward;
        ev.template_id  = template_id;
        ev.nonce        = nonce;
        ev.extra_nonce  = extra_nonce;
        ev.id_source    = o.id_source;
        ev.id_mismatch  = o.id_mismatch;
        ev.header_check = o.header_check;
        ev.rpc_ms       = o.rpc_ms;
        ev.at           = std::chrono::steady_clock::now();
        m_found.push(std::move(ev));
        set_error({});
    }

    // --- diagnostics ------------------------------------------------------
    std::size_t accepted_shares() const { return m_accepted.load(); }
    std::size_t stale_lookups()   const { return m_stale.load(); }
    std::string last_error() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_last_error;
    }

private:
    void set_error(std::string e) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last_error = std::move(e);
    }

    LiveBlockSubmitter&      m_submitter;
    FoundBlockQueue&         m_found;
    CandidateLookup          m_lookup;
    std::atomic<std::size_t> m_accepted{0}, m_stale{0};
    mutable std::mutex       m_mtx;
    std::string              m_last_error;
};

// ===========================================================================
// Main-thread helper for wire (4): the credit/payout maps for an option-A
// block. Recommended (survey §4): credit == payout == {identity_key : reward}
// so finalW nets to 0 and the FOUND/FINALIZE trail is amount-honest. Templated
// on the ledger's Amounts (std::map<::v37::bytes32, long long>; bytes32 ==
// std::array<uint8_t,32>) so this header never pulls the engine. Pass
// reward == 0 to get the degenerate {} (the ledger still registers the block).
// ===========================================================================
template <class AmountsT>
AmountsT single_key_amounts(const std::array<std::uint8_t, 32>& identity_key,
                            std::uint64_t reward_piconero) {
    AmountsT a;
    if (reward_piconero != 0)
        a[identity_key] = static_cast<long long>(reward_piconero);
    return a;
}

// One-line log rendering of a FOUND event (main thread).
inline std::string describe(const FoundBlockEvent& e) {
    std::string s = "FOUND h=" + std::to_string(e.height) + " bid=" + e.block_id_hex().substr(0, 16) +
                    "… id-source=" + to_string(e.id_source) +
                    " header=" + to_string(e.header_check) +
                    (e.id_mismatch ? " ID-MISMATCH(monerod!=local)" : "") +
                    " reward=" + std::to_string(e.reward) + "pico" +
                    " tid=" + std::to_string(e.template_id) +
                    " nonce=0x" + to_hex(reinterpret_cast<const std::uint8_t*>(&e.nonce), 4);
    if (!e.worker.empty() || !e.address.empty())
        s += " worker=" + (e.worker.empty() ? std::string("-") : e.worker) +
             " addr=" + (e.address.size() > 12 ? e.address.substr(0, 12) + "…" : e.address);
    return s;
}

} // namespace c2pool::v37n::xmr::submit
