// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/relay/xmr_block_relay.hpp
//
// Wave 1, component C5: the DUAL-ARM found-block relay.
//
// One block we found -- from the C4 native template, or reconstructed from a
// block-share another c2pool node broadcast -- goes out over two arms:
//
//   ARM A  levin P2P, NOTIFY_NEW_FLUFFY_BLOCK (2008), written to EVERY
//          handshaked peer in state_normal through C1c's IBroadcastPort. This
//          is the DAEMONLESS-PRIMARY arm: with no monerod in the picture it is
//          the only way the block reaches Monero, a missed relay is a lost
//          block with no retry, and the share that paid for it is already
//          spent. So it is redundant on purpose (the DASH
//          submit_block_p2p_raw policy: write to everyone, duplicates are a
//          non-event, a miss is a loss).
//   ARM B  monerod submit_block, ON DEMAND: it fires only when a daemon is
//          actually configured. It is the backup, not the gate.
//
// THE FRAME IS SELF-CONTAINED. monerod relays a block it accepted as a fluffy
// block with `txs` EMPTY, because its peers already hold the transactions in
// their own pools and can fill the gaps with one REQUEST_FLUFFY_MISSING_TX
// (2009) round trip. We do the opposite by default: our 2008 carries the block
// blob AND every transaction body, so a receiving peer can validate and connect
// the block without asking us anything. The bytes are cheap (a stagenet or
// mainnet block is single-digit KB); the round trip is not, because it is a
// round trip on the one message that must not be missed, against a peer that
// has never heard of us and may drop us mid-exchange. `include_all_tx_bodies`
// can be turned off to mirror monerod exactly, and the 2009 responder below
// stays wired either way (a peer may still ask; we always answer from the
// retained book).
//
// WHAT MAY REACH relay(). Only a block that passed the exact 128-bit RandomX
// target check. The contracts header states that as a caller precondition;
// this component ALSO enforces it, fail-closed, through PowGate:
//
//   * no gate installed                       -> nothing is relayed, ever
//   * gate says anything but Accept           -> nothing is relayed
//   * gate is an attestation for block id X   -> only X can be relayed
//
// The attestation form (pow_attestation()) is what the found-block path uses:
// the O-2 verifier has already spent its ~25 ms on these exact bytes, and
// re-running RandomX here would double that on the hottest possible path. What
// the attestation still buys is the thing the plain precondition does not: the
// id the gate SAW is compared against the id of the bytes about to go out, so
// a wiring bug that hands relay() a different block cannot slip past.
//
// NEVER A SILENT DROP. A verdict that reached nobody carries `why` and is
// logged at error level. Zero peers with no daemon arm is a loud failure, not a
// shrug -- the August DASH a=0 lesson, where a broadcast path that had stopped
// firing looked exactly like a broadcast path with nothing to send.
//
// FAIL-LOUD ON A PARTIAL BLOCK (DASH reconstruct_won_block): if any transaction
// in the block has no body we can produce, ARM A is SUPPRESSED -- an incomplete
// self-contained frame is worse than no frame, because the peer that cannot
// complete the block drops and bans the identity that sent it. ARM B still
// fires: monerod has its own pool and needs no bodies from us.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// src/sharechain/v37 is not touched. Header-only, STL plus the native
// consensus and levin headers (xmr_coin for keccak/tree-root); no socket, no
// RPC client, no thread of its own.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/consensus/xmr_tx_weight.hpp"
#include "impl/xmr/native/contracts/broadcast.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/native/contracts/relay.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/levin_codec.hpp"
#include "impl/xmr/native/p2p/levin_messages.hpp"

namespace c2pool::xmr::native::relay {

// ---------------------------------------------------------------------------
// The RandomX gate, as this component sees it.
//
// Mirrors NetworkVerdict from src/c2pool/v37/xmr/xmr_o2_randomx_verify.hpp
// without including it: that header pulls the RandomX runtime, and C5 must stay
// buildable (and testable) with RandomX compiled out. The production wiring
// binds one closure over the live O2RandomXVerifier; the KAT binds a fake.
// ---------------------------------------------------------------------------
enum class PowVerdict : std::uint8_t {
    Accept = 0,          // hash * difficulty < 2^256, exact 128-bit rule
    BelowTarget,         // a forged or stale block: THEIR fault
    SeedNotResident,     // we could not key a VM for the seed: OUR fault
    Unavailable,         // no verifier at all: OUR fault, and fail-closed
    Malformed,           // the bytes could not be hashed
};

inline const char* to_string(PowVerdict v) noexcept {
    switch (v) {
        case PowVerdict::Accept:          return "Accept";
        case PowVerdict::BelowTarget:     return "BelowTarget";
        case PowVerdict::SeedNotResident: return "SeedNotResident";
        case PowVerdict::Unavailable:     return "Unavailable";
        case PowVerdict::Malformed:       return "Malformed";
    }
    return "?";
}

// True when the verdict says the BLOCK is bad (as opposed to saying that WE
// could not judge it). Only these justify banning whoever sent it to us.
inline constexpr bool pow_blames_the_block(PowVerdict v) noexcept {
    return v == PowVerdict::BelowTarget || v == PowVerdict::Malformed;
}

// `hashing_blob` is recomputed from the exact bytes about to be relayed, never
// taken from the caller: that is the whole point of the second check.
using PowGate = std::function<PowVerdict(const BlockRelayRequest& req,
                                         const std::vector<std::uint8_t>& hashing_blob)>;

// The attestation gate: the caller already ran the exact 128-bit check and is
// naming the block id it verified. Anything else is Unavailable, so a mis-wired
// caller relays nothing rather than relaying the wrong block.
inline PowGate pow_attestation(const Hash& verified_id) {
    return [verified_id](const BlockRelayRequest& req,
                         const std::vector<std::uint8_t>&) -> PowVerdict {
        return req.block_id == verified_id ? PowVerdict::Accept : PowVerdict::Unavailable;
    };
}

// ---------------------------------------------------------------------------
// ARM B, projected. The concrete monerod submitter lives in
// src/c2pool/v37/xmr/xmr_live_submit.hpp and speaks BlockCandidate over an
// IMonerodTransport; xmr_block_relay_submit_bridge.hpp adapts it into this
// closure so the core relay never sees the transport.
//
// An UNSET sink is not a failure: it is "no daemon configured", which is the
// daemonless posture and must be reported as `armed == false`, never as a
// rejection. The distinction matters downstream -- C6 counts a daemon that
// REJECTED our block as a parity failure and no daemon at all as a void sample.
// ---------------------------------------------------------------------------
struct DaemonArmResult {
    bool          armed    = false;   // a daemon was configured and was asked
    bool          accepted = false;   // monerod returned status OK
    bool          rejected = false;   // monerod was asked and said no
    std::string   status;             // result.status, or the transport error
    Hash          block_id{};         // monerod's own id, when it reports one
    double        rpc_ms = 0.0;
};

using DaemonSubmitSink = std::function<DaemonArmResult(const BlockRelayRequest&)>;

// Diagnostics. `error == true` is the never-silent-drop channel and must reach
// the operator's log at ERROR.
using RelayLog = std::function<void(bool error, const std::string& line)>;

// Injectable clock (seconds), so the retention window is testable without
// sleeping. Defaults to the system clock.
using RelayClock = std::function<std::uint64_t()>;

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// The daemonless-primary posture this component defaults to: BOTH arms fire,
// P2P first, and the daemon never gates the P2P push.
//
// ArmOrder::DaemonFirst is the plan's M0..M4 posture (monerod validates for
// free before our P2P identity is behind the block) and is implemented in full
// below; it is a configuration, not the default, because the daemon is the
// thing this whole native-node track exists to remove.
inline RelayPolicy self_contained_policy() noexcept {
    RelayPolicy p;
    p.order                 = ArmOrder::Parallel;
    p.include_all_tx_bodies = true;   // no 2009 round trip for our own blocks
    p.serve_missing_tx      = true;   // answer anyway: a peer may still ask
    p.confirm_timeout_s     = 120;
    return p;
}

struct RelayConfig {
    RelayPolicy   policy = self_contained_policy();

    // Re-hash every body against the id the block blob commits to before it
    // goes on the wire. Cheap next to what a bad relay costs (a ban at every
    // peer that received it), and it is the only check that can catch a body
    // source handing back the right number of wrong blobs.
    bool          verify_tx_bodies = true;

    // Hand the block to our own chain index (D-14 PREFER-OWN) so the tip moves
    // without waiting to hear our own block back from a peer.
    bool          submit_to_own_index = true;

    // The retained book: how long, and how many, blocks we can still answer a
    // 2009 for. One hour matches the DASH won-block book.
    std::uint32_t retain_seconds = 3600;
    std::size_t   max_retained   = 64;
};

// ---------------------------------------------------------------------------
// Why a relay was refused before any arm fired. Every one of these means the
// bytes never touched the network.
// ---------------------------------------------------------------------------
enum class RelayReject : std::uint8_t {
    None = 0,
    EmptyBlob,
    Unparseable,
    IdMismatch,          // the blob does not hash to the id the caller named
    TxListMismatch,      // the caller's tx list is not the blob's tx list
    NonceMismatch,       // the winning nonce is not patched into the blob
    HeightMismatch,      // the coinbase height is not the caller's height
    PowNotAccepted,      // THE gate: no attestation, or not Accept
};

inline const char* to_string(RelayReject r) noexcept {
    switch (r) {
        case RelayReject::None:           return "None";
        case RelayReject::EmptyBlob:      return "EmptyBlob";
        case RelayReject::Unparseable:    return "Unparseable";
        case RelayReject::IdMismatch:     return "IdMismatch";
        case RelayReject::TxListMismatch: return "TxListMismatch";
        case RelayReject::NonceMismatch:  return "NonceMismatch";
        case RelayReject::HeightMismatch: return "HeightMismatch";
        case RelayReject::PowNotAccepted: return "PowNotAccepted";
    }
    return "?";
}

struct RelayStats {
    std::uint64_t relays_attempted     = 0;
    std::uint64_t relays_refused       = 0;   // never reached an arm
    std::uint64_t pow_refused          = 0;
    std::uint64_t structural_refused   = 0;
    std::uint64_t partial_block        = 0;   // ARM A suppressed, bodies missing
    std::uint64_t reached_nobody       = 0;   // the loud failure
    std::uint64_t p2p_frames_written   = 0;
    std::uint64_t p2p_peers_written    = 0;
    std::uint64_t daemon_accepted      = 0;
    std::uint64_t daemon_rejected      = 0;
    std::uint64_t missing_tx_served    = 0;
    std::uint64_t missing_tx_declined  = 0;
};

// ---------------------------------------------------------------------------
// LevinBlockRelay
// ---------------------------------------------------------------------------
class LevinBlockRelay final : public IBlockRelay {
public:
    LevinBlockRelay(IBroadcastPort&        port,
                    DaemonSubmitSink       daemon,
                    const IMinerDataSource* bodies,
                    IChainView*            chain,
                    RelayConfig            cfg = RelayConfig{},
                    RelayLog               log = RelayLog{})
        : m_port(port),
          m_daemon(std::move(daemon)),
          m_bodies(bodies),
          m_chain(chain),
          m_cfg(cfg),
          m_log(std::move(log)) {
        if (m_cfg.policy.serve_missing_tx) {
            m_port.set_fluffy_missing_handler(
                [this](const PeerRef&, const Hash& block_id, std::uint64_t,
                       const std::vector<std::uint64_t>& idx,
                       std::vector<std::uint8_t>& reply) {
                    return this->on_request_fluffy_missing_tx(block_id, idx, reply);
                });
        }
    }

    // The gate. Nothing is relayed until this is set (fail-closed).
    void set_pow_gate(PowGate g)          { m_pow    = std::move(g); }
    void set_clock(RelayClock c)          { m_clock  = std::move(c); }
    void set_daemon_sink(DaemonSubmitSink s) { m_daemon = std::move(s); }

    const RelayConfig& config() const noexcept { return m_cfg; }
    RelayStats         stats()  const { std::lock_guard<std::mutex> lk(m_mx); return m_stats; }
    RelayReject        last_reject() const noexcept { return m_last_reject; }

    // -----------------------------------------------------------------------
    // The one entry point. Returns a verdict that ALWAYS explains itself.
    // -----------------------------------------------------------------------
    BlockRelayVerdict relay(const BlockRelayRequest& req) override {
        return relay_with_gate(req, m_pow);
    }

    // The same path under a ONE-SHOT gate. This is what the found-block caller
    // uses: it has just verified these exact bytes and passes an attestation
    // naming the id it verified, without disturbing the relay's standing gate
    // (two found blocks on two threads must not overwrite each other's).
    BlockRelayVerdict relay_with_gate(const BlockRelayRequest& req, const PowGate& gate) {
        BlockRelayVerdict v;
        v.block_id = req.block_id;
        m_last_reject = RelayReject::None;
        {
            std::lock_guard<std::mutex> lk(m_mx);
            ++m_stats.relays_attempted;
        }

        // --- 1. structural: the bytes must be a block, and the block the
        //        caller thinks it is ----------------------------------------
        ParsedBlock   pb;
        BlockIdentity ident;
        if (req.block_blob.empty())
            return refuse(v, RelayReject::EmptyBlob, "empty block blob");

        const BlockParseStatus st = parse_and_identify(req.block_blob, pb, ident);
        if (st != BlockParseStatus::Ok)
            return refuse(v, RelayReject::Unparseable,
                          std::string("block blob does not parse: ") + native::to_string(st));

        if (!is_zero(req.block_id) && ident.id != req.block_id)
            return refuse(v, RelayReject::IdMismatch,
                          "block blob hashes to " + hex(ident.id) + ", caller named " +
                              hex(req.block_id));
        v.block_id = ident.id;

        if (!req.tx_hashes.empty() && req.tx_hashes != pb.tx_hashes)
            return refuse(v, RelayReject::TxListMismatch,
                          "caller tx list disagrees with the blob's tx list");

        // The blob is what goes on the wire, so the winning nonce must be IN
        // it. A blob still carrying the template's nonce is a block nobody can
        // verify and everybody will ban us for.
        if (pb.header.nonce != req.nonce)
            return refuse(v, RelayReject::NonceMismatch,
                          "blob carries nonce " + std::to_string(pb.header.nonce) +
                              ", the winning nonce is " + std::to_string(req.nonce));

        CoinbaseFields cb;
        const bool cb_ok = parse_coinbase_fields(req.block_blob.data(), pb, cb);
        if (req.height != 0 && cb_ok && cb.height != req.height)
            return refuse(v, RelayReject::HeightMismatch,
                          "coinbase height " + std::to_string(cb.height) +
                              " is not the caller's height " + std::to_string(req.height));
        const std::uint64_t height = req.height != 0 ? req.height : cb.height;

        // --- 2. THE GATE -------------------------------------------------
        const PowVerdict pv = gate ? gate(req, ident.hashing_blob) : PowVerdict::Unavailable;
        if (pv != PowVerdict::Accept) {
            {
                std::lock_guard<std::mutex> lk(m_mx);
                ++m_stats.pow_refused;
            }
            return refuse(v, RelayReject::PowNotAccepted,
                          std::string("randomx gate: ") + to_string(pv), /*structural=*/false);
        }

        // --- 3. bodies ----------------------------------------------------
        std::vector<TxBlobEntry> bodies;
        std::string              body_why;
        const bool bodies_complete = collect_bodies(pb.tx_hashes, bodies, body_why);

        bool        p2p_suppressed = false;
        std::string p2p_why;
        if (!bodies_complete && m_cfg.policy.include_all_tx_bodies) {
            // Rule 5, fail-loud: never emit a partial self-contained block.
            p2p_suppressed = true;
            p2p_why        = "incomplete block: " + body_why;
            std::lock_guard<std::mutex> lk(m_mx);
            ++m_stats.partial_block;
        }

        // --- 4. the 2008 frame --------------------------------------------
        std::vector<std::uint8_t> frame;
        if (!p2p_suppressed) {
            std::string why;
            if (!build_fluffy_frame(req.block_blob,
                                    m_cfg.policy.include_all_tx_bodies ? bodies
                                                                       : std::vector<TxBlobEntry>{},
                                    height + 1u,   // rule 6: OUR height after this block
                                    frame, why)) {
                p2p_suppressed = true;
                p2p_why        = "2008 encode failed: " + why;
            }
        }

        // --- 5. the arms ---------------------------------------------------
        const bool daemon_wired = static_cast<bool>(m_daemon);
        switch (m_cfg.policy.order) {
            case ArmOrder::DaemonFirst: {
                fire_daemon(req, v);
                // The plan's rule 2: a daemon that said no means the block
                // never touches P2P -- monerod just told us it is invalid.
                if (v.daemon_rejected) {
                    p2p_suppressed = true;
                    if (p2p_why.empty()) p2p_why = "daemon arm rejected the block";
                } else {
                    fire_p2p(frame, v, p2p_suppressed);
                }
                break;
            }
            case ArmOrder::Parallel: {
                // Daemonless-primary: P2P first, always, and the daemon is the
                // on-demand backup behind it.
                fire_p2p(frame, v, p2p_suppressed);
                fire_daemon(req, v);
                break;
            }
            case ArmOrder::P2pOnly: {
                fire_p2p(frame, v, p2p_suppressed);
                break;
            }
        }

        // --- 6. the book, for 2009 and for dedup ---------------------------
        retain(v.block_id, height, req.block_blob, pb.tx_hashes, bodies);

        // --- 7. our own tip (PREFER-OWN) -----------------------------------
        if (m_cfg.submit_to_own_index && m_chain) {
            BlockEntry be;
            be.block_blob = req.block_blob;
            be.txs        = bodies;
            be.pruned     = false;
            std::string why;
            if (!m_chain->submit_own_block(be, why))
                say(false, "own index refused our block " + hex(v.block_id) + ": " + why);
        }

        // --- 8. never a silent drop ----------------------------------------
        if (!v.reached_network()) {
            std::lock_guard<std::mutex> lk(m_mx);
            ++m_stats.reached_nobody;
        }
        if (!v.reached_network()) {
            v.why = "block " + hex(v.block_id) + " at height " + std::to_string(height) +
                    " reached NO peer and no accepting daemon";
            if (!p2p_why.empty()) v.why += " (" + p2p_why + ")";
            if (!daemon_wired)    v.why += " (no daemon arm configured)";
            say(true, "RELAY FAILED: " + v.why);
        } else {
            if (!p2p_why.empty())
                say(true, "relay: P2P arm suppressed for " + hex(v.block_id) + ": " + p2p_why);
            if (v.p2p_peers_sent == 0 && m_cfg.policy.order != ArmOrder::DaemonFirst)
                say(true, "relay: block " + hex(v.block_id) +
                              " went out on the daemon arm only, zero P2P peers");
            say(false, "relay: block " + hex(v.block_id) + " h=" + std::to_string(height) +
                           " peers=" + std::to_string(v.p2p_peers_sent) +
                           " daemon=" + (v.daemon_armed ? (v.daemon_accepted ? "accepted"
                                                                            : "rejected")
                                                        : "none") +
                           " first=" + (v.landed_first.empty() ? "-" : v.landed_first));
        }
        if (!v.reached_network()) {
            std::lock_guard<std::mutex> lk(m_mx);
            ++m_stats.relays_refused;
        }
        return v;
    }

    // -----------------------------------------------------------------------
    // 2009: a peer is missing transactions from a block we pushed. The reply is
    // another 2008 carrying exactly the requested bodies, in the requested
    // order -- monerod's own answer shape.
    // -----------------------------------------------------------------------
    bool on_request_fluffy_missing_tx(const Hash&                       block_id,
                                      const std::vector<std::uint64_t>& tx_indices,
                                      std::vector<std::uint8_t>&        reply_frame) override {
        reply_frame.clear();
        if (!m_cfg.policy.serve_missing_tx) return decline();

        std::vector<std::uint8_t> blob;
        std::vector<TxBlobEntry>  wanted;
        std::uint64_t             height = 0;
        {
            std::lock_guard<std::mutex> lk(m_mx);
            expire_locked();
            const Retained* r = find_locked(block_id);
            if (!r) return decline_locked();
            if (tx_indices.empty()) return decline_locked();
            if (r->bodies.size() != r->tx_hashes.size()) return decline_locked();

            wanted.reserve(tx_indices.size());
            for (const std::uint64_t i : tx_indices) {
                if (i >= r->bodies.size()) return decline_locked();
                TxBlobEntry e;
                e.blob   = r->bodies[static_cast<std::size_t>(i)].blob;
                e.pruned = false;
                wanted.push_back(std::move(e));
            }
            blob   = r->block_blob;
            height = r->height;
        }

        std::string why;
        if (!build_fluffy_frame(blob, wanted, height + 1u, reply_frame, why)) {
            say(true, "2009: could not encode the reply for " + hex(block_id) + ": " + why);
            reply_frame.clear();
            return decline();
        }
        std::lock_guard<std::mutex> lk(m_mx);
        ++m_stats.missing_tx_served;
        return true;
    }

    // Did we announce this block? (dedup for the c2pool-side redundant
    // broadcast; DASH WonBlockRelay::knows.)
    bool knows(const Hash& block_id) const {
        std::lock_guard<std::mutex> lk(m_mx);
        return find_locked(block_id) != nullptr;
    }

    std::size_t retained_count() const {
        std::lock_guard<std::mutex> lk(m_mx);
        return m_book.size();
    }

private:
    struct Retained {
        Hash                      id{};
        std::uint64_t             height = 0;
        std::vector<std::uint8_t> block_blob;
        std::vector<Hash>         tx_hashes;
        std::vector<TxBlobEntry>  bodies;
        std::uint64_t             at = 0;
    };

    // --- helpers -----------------------------------------------------------
    static bool is_zero(const Hash& h) noexcept {
        for (const std::uint8_t b : h)
            if (b != 0) return false;
        return true;
    }

    static std::string hex(const Hash& h) {
        static const char* kD = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (const std::uint8_t b : h) {
            s.push_back(kD[b >> 4]);
            s.push_back(kD[b & 0x0f]);
        }
        return s;
    }

    std::uint64_t now() const { return m_clock ? m_clock() : wall_seconds(); }

    static std::uint64_t wall_seconds() {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    void say(bool error, const std::string& line) const {
        if (m_log) m_log(error, line);
    }

    BlockRelayVerdict& refuse(BlockRelayVerdict& v, RelayReject r, const std::string& why,
                              bool structural = true) {
        m_last_reject = r;
        v.why         = why;
        {
            std::lock_guard<std::mutex> lk(m_mx);
            ++m_stats.relays_refused;
            if (structural) ++m_stats.structural_refused;
        }
        say(true, std::string("RELAY REFUSED (") + to_string(r) + "): " + why);
        return v;
    }

    bool decline() {
        std::lock_guard<std::mutex> lk(m_mx);
        ++m_stats.missing_tx_declined;
        return false;
    }
    bool decline_locked() {   // caller holds m_mx
        ++m_stats.missing_tx_declined;
        return false;
    }

    // Bodies for every transaction the block commits to, in block order. False
    // when even one is missing or does not hash to the id it is filed under.
    bool collect_bodies(const std::vector<Hash>&  tx_hashes,
                        std::vector<TxBlobEntry>& out,
                        std::string&              why) const {
        out.clear();
        if (tx_hashes.empty()) return true;
        if (!m_bodies) {
            why = "no transaction body source is wired";
            return false;
        }
        out.reserve(tx_hashes.size());
        for (const Hash& id : tx_hashes) {
            const std::vector<std::uint8_t>* b = m_bodies->tx_body(id);
            if (!b || b->empty()) {
                why = "no body for tx " + hex(id);
                out.clear();
                return false;
            }
            if (m_cfg.verify_tx_bodies) {
                TxWeightInfo info;
                if (parse_tx_full(*b, info) != TxParseStatus::Ok) {
                    why = "body for tx " + hex(id) + " does not parse";
                    out.clear();
                    return false;
                }
                if (tx_hash_full(b->data(), b->size(), info) != id) {
                    why = "body filed under tx " + hex(id) + " hashes to something else";
                    out.clear();
                    return false;
                }
            }
            TxBlobEntry e;
            e.blob   = *b;
            e.pruned = false;
            out.push_back(std::move(e));
        }
        return true;
    }

    static bool build_fluffy_frame(const std::vector<std::uint8_t>& block_blob,
                                   const std::vector<TxBlobEntry>&  txs,
                                   std::uint64_t                    our_height,
                                   std::vector<std::uint8_t>&       frame,
                                   std::string&                     why) {
        levin::NewBlock m;
        m.b.block_blob                = block_blob;
        m.b.txs                       = txs;
        m.b.pruned                    = false;   // fluffy bodies are always full
        m.b.block_weight_claimed_hint = 0;       // a hint we do not need to send
        m.current_blockchain_height   = our_height;

        std::vector<std::uint8_t> body;
        levin::MessageError       err = levin::MessageError::None;
        if (!levin::encode_new_fluffy_block(m, body, err)) {
            why = levin::to_string(err);
            return false;
        }
        frame = levin::make_notify(levin::CMD_NEW_FLUFFY_BLOCK, body);
        return true;
    }

    void fire_p2p(const std::vector<std::uint8_t>& frame, BlockRelayVerdict& v,
                  bool suppressed) {
        if (suppressed || frame.empty()) return;
        const std::size_t n = m_port.broadcast_notify(levin::CMD_NEW_FLUFFY_BLOCK, frame);
        v.p2p_peers_sent    = n;
        {
            std::lock_guard<std::mutex> lk(m_mx);
            ++m_stats.p2p_frames_written;
            m_stats.p2p_peers_written += static_cast<std::uint64_t>(n);
        }
        if (n > 0 && v.landed_first.empty()) v.landed_first = "p2p";
    }

    void fire_daemon(const BlockRelayRequest& req, BlockRelayVerdict& v) {
        if (!m_daemon) return;   // no daemon configured: armed stays false
        const DaemonArmResult r = m_daemon(req);
        v.daemon_armed    = r.armed;
        v.daemon_accepted = r.accepted;
        v.daemon_rejected = r.rejected;
        {
            std::lock_guard<std::mutex> lk(m_mx);
            if (r.accepted) ++m_stats.daemon_accepted;
            if (r.rejected) ++m_stats.daemon_rejected;
        }
        if (r.rejected)
            say(true, "daemon arm REJECTED block " + hex(v.block_id) + ": " + r.status);
        if (r.accepted && v.landed_first.empty()) v.landed_first = "daemon";
    }

    void retain(const Hash& id, std::uint64_t height,
                const std::vector<std::uint8_t>& blob,
                const std::vector<Hash>&         tx_hashes,
                const std::vector<TxBlobEntry>&  bodies) {
        std::lock_guard<std::mutex> lk(m_mx);
        expire_locked();
        for (Retained& r : m_book) {
            if (r.id == id) { r.at = now(); return; }
        }
        Retained r;
        r.id         = id;
        r.height     = height;
        r.block_blob = blob;
        r.tx_hashes  = tx_hashes;
        r.bodies     = bodies;
        r.at         = now();
        m_book.push_back(std::move(r));
        while (m_book.size() > m_cfg.max_retained) m_book.pop_front();
    }

    void expire_locked() {
        const std::uint64_t t = now();
        while (!m_book.empty() &&
               t >= m_book.front().at &&
               t - m_book.front().at > m_cfg.retain_seconds)
            m_book.pop_front();
    }

    const Retained* find_locked(const Hash& id) const {
        for (const Retained& r : m_book)
            if (r.id == id) return &r;
        return nullptr;
    }

    IBroadcastPort&         m_port;
    DaemonSubmitSink        m_daemon;
    const IMinerDataSource* m_bodies = nullptr;
    IChainView*             m_chain  = nullptr;
    RelayConfig             m_cfg;
    RelayLog                m_log;
    PowGate                 m_pow;
    RelayClock              m_clock;

    mutable std::mutex   m_mx;
    std::deque<Retained> m_book;
    RelayStats           m_stats;
    RelayReject          m_last_reject = RelayReject::None;
};

} // namespace c2pool::xmr::native::relay
