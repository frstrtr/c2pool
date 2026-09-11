// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_p2p_block_publisher.hpp   (M3)
//
// THE LAST DAEMON CALL ON THE FIND PATH, REMOVED.
//
// LiveSubmitShareSink is the X5 IShareSink that turns a winning share into a
// Monero block: look the candidate up, POST submit_block to monerod, and on OK
// push a FoundBlockEvent for the finalize driver. Everything about that is
// right except the middle step, which is an RPC to the thing this track exists
// to remove.
//
// P2pBlockPublisher is the same sink with a different middle: the assembled
// block goes out over levin as a 2008 NOTIFY_NEW_FLUFFY_BLOCK to every
// handshaked peer, through C5's LevinBlockRelay (ArmOrder::P2pOnly, bodies
// included so no peer needs a 2009 round trip to validate it), and the relay's
// PREFER-OWN submit_to_own_index hands the block to our own chain index so our
// tip moves without waiting to hear our own block back from somebody else.
//
// WHAT COUNTS AS SUCCESS, AND WHY IT IS A WEAKER CLAIM THAN monerod's "OK".
// submit_block is an ADJUDICATION: monerod validated the block and told us so.
// A 2008 write is a DELIVERY: bytes reached N peers, and no peer answers an
// unsolicited block notification. So the honest success condition here is
// BlockRelayVerdict::reached_network() -- at least one peer took the frame --
// and the block id is ours, computed from the hashing blob the RandomX gate
// just verified (IdSource::Local), never a daemon's. header_check stays NotRun
// for the same reason: nothing confirmed the height for us.
//
// That weakness is real and is not hidden. What backs the block instead is the
// chain: if the network rejected it, the native index never sees it reach
// D_conf burial on the best chain, the canonical test fails at maturity, and
// the settlement is disposed as an orphan rather than finalized. The daemon's
// synchronous yes is traded for the chain's asynchronous one, which is the
// trade a daemonless node is FOR.
//
// FAIL-CLOSED, three ways:
//   * enable_network_relay() defaults FALSE, exactly like LiveBlockSubmitter's
//     network_submit_enabled -- a build with no RandomX relays nothing;
//   * a candidate with no hashing blob has no verified id to attest to, and
//     CandidateBlockRelay refuses an unattested push rather than trusting us;
//   * a verdict that reached nobody pushes NO FoundBlockEvent. A block nobody
//     received must never enter the settlement ledger as found.
//
// THREADING: submit_network_block runs on the stratum listener thread. The
// peer pool's IBroadcastPort is documented as called from exactly that thread
// (xmr_peer_pool.hpp), and it posts onto the io thread internally.
//
// SCOPE FENCE: consumer tree plus the C5 bridge under src/impl/xmr/native/.
// No consensus digest; src/sharechain/v37 untouched.
// ===========================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>

#include "impl/xmr/native/relay/xmr_block_relay_submit_bridge.hpp"
#include "impl/xmr/stratum/xmr_stratum.hpp"
#include "xmr_live_submit.hpp"

namespace c2pool::v37n::xmr::o2 {

namespace strat  = ::v37::xmr::stratum;
namespace sub    = ::c2pool::v37n::xmr::submit;
namespace nrelay = ::c2pool::xmr::native::relay;

class P2pBlockPublisher final : public strat::IShareSink {
public:
    using CandidateLookup = sub::LiveSubmitShareSink::CandidateLookup;

    P2pBlockPublisher(nrelay::LevinBlockRelay& relay, sub::FoundBlockQueue& found,
                      CandidateLookup lookup)
        : m_relay(relay), m_found(found), m_lookup(std::move(lookup)) {}

    // The RandomX fail-closed gate, mirroring LiveBlockSubmitter's. OFF until
    // the verifier is live, so a build that cannot check proof of work can
    // never put a block on somebody else's wire.
    void enable_network_relay(bool on) { m_enabled.store(on); }
    bool network_relay_enabled() const { return m_enabled.load(); }

    void on_accepted_share(const strat::AcceptedShare& s) override {
        m_accepted.fetch_add(1);
        if (s.is_network_block)
            m_found.annotate(s.template_id, s.nonce, s.extra_nonce, s.worker, s.address);
    }

    void submit_network_block(std::uint32_t template_id, std::uint32_t nonce,
                              std::uint32_t extra_nonce) override {
        m_calls.fetch_add(1);

        sub::BlockCandidate c;
        if (!m_lookup || !m_lookup(template_id, extra_nonce, c)) {
            m_stale.fetch_add(1);
            set_error("relay: template " + std::to_string(template_id) + " gone (stale)");
            return;
        }
        if (!m_enabled.load()) {
            m_refused.fetch_add(1);
            set_error("relay: REFUSED (network relay disabled, fail-closed)");
            return;
        }
        if (const std::string bad = sub::validate_candidate(c); !bad.empty()) {
            m_refused.fetch_add(1);
            set_error("relay: REFUSED (" + bad + ")");
            return;
        }
        if (c.hashing_blob.empty()) {
            // No served hashing blob means no id the RandomX gate can be said
            // to have verified. C5 would refuse the unattested push anyway;
            // refusing here names the actual cause.
            m_refused.fetch_add(1);
            set_error("relay: REFUSED (no hashing blob -> no verified block id to attest)");
            return;
        }

        // The exact 128-bit network gate ran in front of this sink, on these
        // bytes, moments ago -- that is the ONLY way this method is reached.
        // pow_accepted=true is that fact, and the attestation still ties it to
        // one block id, so a wiring bug that hands us different bytes is caught.
        nrelay::CandidateBlockRelay bridge(m_relay);
        const ::c2pool::xmr::native::BlockRelayVerdict v =
            bridge.relay(c, nonce, extra_nonce, /*pow_accepted=*/true);

        if (!v.reached_network()) {
            m_failed.fetch_add(1);
            set_error("relay: block reached NO peer: " +
                      (v.why.empty() ? std::string("(no reason given)") : v.why));
            return;
        }

        m_relayed.fetch_add(1);
        m_peers.fetch_add(static_cast<std::uint64_t>(v.p2p_peers_sent));

        sub::FoundBlockEvent ev;
        ev.height       = c.height;
        ev.block_id     = v.block_id;          // ours, off the bytes we relayed
        ev.prev_id      = c.prev_id;
        ev.reward       = c.expected_reward;
        ev.template_id  = template_id;
        ev.nonce        = nonce;
        ev.extra_nonce  = extra_nonce;
        ev.id_source    = sub::IdSource::Local;
        ev.id_mismatch  = false;
        ev.header_check = sub::HeaderCheck::NotRun;   // no daemon confirmed it
        ev.rpc_ms       = 0.0;                        // and none was called
        ev.at           = std::chrono::steady_clock::now();
        m_found.push(std::move(ev));
        set_error({});
    }

    // --- diagnostics ---------------------------------------------------------
    std::uint64_t calls()    const { return m_calls.load(); }
    std::uint64_t relayed()  const { return m_relayed.load(); }
    std::uint64_t peers()    const { return m_peers.load(); }
    std::uint64_t refused()  const { return m_refused.load(); }
    std::uint64_t failed()   const { return m_failed.load(); }
    std::uint64_t stale()    const { return m_stale.load(); }
    std::size_t   accepted_shares() const { return m_accepted.load(); }
    std::string   last_error() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_last_error;
    }

private:
    void set_error(std::string e) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last_error = std::move(e);
    }

    nrelay::LevinBlockRelay& m_relay;
    sub::FoundBlockQueue&    m_found;
    CandidateLookup          m_lookup;
    std::atomic<bool>        m_enabled{false};
    std::atomic<std::uint64_t> m_calls{0}, m_relayed{0}, m_peers{0},
                               m_refused{0}, m_failed{0}, m_stale{0};
    std::atomic<std::size_t>   m_accepted{0};
    mutable std::mutex         m_mtx;
    std::string                m_last_error;
};

} // namespace c2pool::v37n::xmr::o2
