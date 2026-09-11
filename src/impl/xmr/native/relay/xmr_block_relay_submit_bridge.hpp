// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/relay/xmr_block_relay_submit_bridge.hpp
//
// The adapter between C5 and the two things it must not include:
//
//   * submit::BlockCandidate, the found-block value the stratum/template layer
//     already produces (src/c2pool/v37/xmr/xmr_live_submit.hpp), and
//   * submit::LiveBlockSubmitter, the monerod submit_block client that is
//     ARM B.
//
// contracts/relay.hpp says why the interface takes BlockRelayRequest instead:
// dragging the live transport into contracts/ would put an RPC client behind
// every consumer of the contract family. This header is where that adaptation
// lives, and it is the ONLY file in C5 that includes the live-submit surface.
//
// The plan writes C5's entry point as relay(BlockCandidate&, nonce,
// extra_nonce). CandidateBlockRelay below IS that entry point.
//
// SCOPE FENCE: src/impl/xmr/ plus the one existing src/c2pool/v37/xmr/ header
// it adapts; src/sharechain/v37 is not touched.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "c2pool/v37/xmr/xmr_live_submit.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"

namespace c2pool::xmr::native::relay {

// ---------------------------------------------------------------------------
// BlockCandidate -> BlockRelayRequest
//
// `block_blob` is the ASSEMBLED blob (nonce, and extra_nonce where the template
// reserved room, patched in) -- the exact bytes ARM B posts to submit_block and
// ARM A puts in the 2008 frame. One set of bytes for both arms is the point:
// the two arms can never disagree about what our block was.
//
// `block_id` is filled from the served hashing blob when the candidate carries
// one; that is the id the O-2 RandomX gate verified. When it is absent the
// field stays zero and the relay derives the id from the blob itself -- and the
// attestation gate then has nothing to compare against, which is exactly why
// relay_candidate() below refuses that combination.
// ---------------------------------------------------------------------------
inline BlockRelayRequest to_relay_request(const submit::BlockCandidate& c,
                                          std::uint32_t nonce,
                                          std::uint32_t extra_nonce) {
    BlockRelayRequest r;
    r.block_blob  = submit::assemble_block_blob(c, nonce, extra_nonce);
    r.height      = c.height;
    r.nonce       = nonce;
    r.extra_nonce = extra_nonce;
    if (!c.hashing_blob.empty())
        r.block_id = submit::block_id_of_hashing_blob(submit::hashing_blob_with_nonce(c, nonce));
    return r;
}

// ---------------------------------------------------------------------------
// ARM B as a DaemonSubmitSink.
//
// The submitter wants a BlockCandidate, and the relay only has the request, so
// the sink builds a candidate whose full_blob is the ALREADY ASSEMBLED blob.
// That is safe because assembly is idempotent: patching the same nonce back
// over itself changes nothing, and reserved_size = 0 means the extra_nonce
// patch is skipped entirely (it is already in the bytes). nonce_offset comes
// from the blob's own header length rather than a constant, so a future header
// layout cannot silently shift it.
//
// What is lost by not carrying the original candidate: hashing_blob, hence the
// submitter's LOCAL block id (source (b)). monerod's own result.block_id and
// the get_block_header_by_height confirmation are unaffected, and the relay has
// already computed the id from the blob. Callers that want all three sources
// use CandidateBlockRelay, which keeps the candidate.
// ---------------------------------------------------------------------------
inline DaemonSubmitSink make_daemon_sink(submit::LiveBlockSubmitter& submitter) {
    return [&submitter](const BlockRelayRequest& req) -> DaemonArmResult {
        DaemonArmResult out;
        out.armed = true;

        ParsedBlock pb;
        if (parse_block(req.block_blob, pb) != BlockParseStatus::Ok ||
            pb.header_size < 4) {
            out.rejected = true;
            out.status   = "daemon arm: the assembled blob does not parse";
            return out;
        }

        submit::BlockCandidate c;
        c.height        = req.height;
        c.full_blob     = req.block_blob;
        c.nonce_offset  = pb.header_size - 4;   // the u32 nonce ends the header
        c.reserved_size = 0;                    // extra_nonce is already in place
        c.major_version = static_cast<std::uint8_t>(pb.header.major_version);

        const submit::SubmitOutcome o = submitter.submit(c, req.nonce, req.extra_nonce);
        out.accepted = o.accepted;
        out.rejected = !o.accepted;
        out.status   = o.accepted ? o.status
                                  : (o.error.empty() ? o.status : o.error);
        out.rpc_ms   = o.rpc_ms;
        if (o.has_block_id()) out.block_id = o.block_id;
        return out;
    };
}

// A sink that keeps the ORIGINAL candidate, for the found-block path where the
// hashing blob exists and all three id sources are wanted. One block, one sink.
inline DaemonSubmitSink make_daemon_sink(submit::LiveBlockSubmitter& submitter,
                                         const submit::BlockCandidate& c) {
    return [&submitter, c](const BlockRelayRequest& req) -> DaemonArmResult {
        DaemonArmResult out;
        out.armed = true;
        const submit::SubmitOutcome o = submitter.submit(c, req.nonce, req.extra_nonce);
        out.accepted = o.accepted;
        out.rejected = !o.accepted;
        out.status   = o.accepted ? o.status
                                  : (o.error.empty() ? o.status : o.error);
        out.rpc_ms   = o.rpc_ms;
        if (o.has_block_id()) out.block_id = o.block_id;
        return out;
    };
}

// ---------------------------------------------------------------------------
// The plan's C5 entry point: relay(candidate, nonce, extra_nonce).
//
// `pow_accepted` is the O-2 gate's answer for THESE bytes
// (verify_network_block(...) == NetworkVerdict::Accept). It is passed in rather
// than recomputed because RandomX has already been paid for once on this path
// and paying twice would double the latency of the one thing that must be fast.
// The relay still refuses everything it is not told to accept, and the
// attestation ties the acceptance to a specific block id.
// ---------------------------------------------------------------------------
class CandidateBlockRelay {
public:
    explicit CandidateBlockRelay(LevinBlockRelay& core) : m_core(core) {}

    BlockRelayVerdict relay(const submit::BlockCandidate& c,
                            std::uint32_t nonce,
                            std::uint32_t extra_nonce,
                            bool          pow_accepted) {
        const BlockRelayRequest req = to_relay_request(c, nonce, extra_nonce);

        // No hashing blob means no verified id to attest to. Refuse rather than
        // relay on trust: an unattested push is exactly the failure this
        // component exists to make impossible.
        const bool attestable = pow_accepted && !all_zero(req.block_id);
        return m_core.relay_with_gate(req, attestable ? pow_attestation(req.block_id)
                                                      : PowGate{});
    }

private:
    static bool all_zero(const Hash& h) noexcept {
        for (const std::uint8_t b : h)
            if (b != 0) return false;
        return true;
    }

    LevinBlockRelay& m_core;
};

} // namespace c2pool::xmr::native::relay
