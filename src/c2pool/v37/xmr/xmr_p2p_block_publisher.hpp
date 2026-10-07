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
// REACHED NOBODY IS NOT THE END OF THE BLOCK (parked re-announce). A find at
// a moment with no reachable peer (every monerod restarting, every link just
// re-dialled) used to be counted and dropped: the block sat on our own index
// and nobody was ever told about it. Now it is PARKED, and tick() re-announces
// it from the relay's retained book on a bounded backoff (2, 4, 8, 16, 30,
// 30 ... s; at most RetryPolicy::max_attempts frames, and never past
// RetryPolicy::window_ms -- two block times -- after the find). The first
// re-announce that reaches a peer pushes THE FoundBlockEvent, exactly once;
// a block our own best chain no longer carries (the height was lost) is
// dropped at once, and one that runs out of attempts or window is ABANDONED,
// both at ERROR and counted. Nothing here books a block that reached nobody:
// FOUND still means "a peer received it" (or --native-solo).
//
// THREADING: submit_network_block runs on the stratum listener thread. The
// peer pool's IBroadcastPort is documented as called from exactly that thread
// (xmr_peer_pool.hpp), and it posts onto the io thread internally.
//
// SCOPE FENCE: consumer tree plus the C5 bridge under src/impl/xmr/native/.
// No consensus digest; src/sharechain/v37 untouched.
// ===========================================================================
#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

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

    // The bounded re-announce of a block whose first push reached no peer.
    struct RetryPolicy {
        std::uint64_t window_ms        = 240'000;   // 2 x DIFFICULTY_TARGET_V2
        std::uint32_t max_attempts     = 10;        // re-announce frames per block
        std::uint64_t first_backoff_ms = 2'000;     // doubles per attempt ...
        std::uint64_t max_backoff_ms   = 30'000;    // ... up to this
        std::size_t   max_parked       = 8;         // oldest is abandoned beyond it
    };
    // Monotonic milliseconds; injectable so the KAT walks the window without
    // sleeping.
    using Clock = std::function<std::uint64_t()>;
    // error == true lines are the never-silent-drop channel.
    using Log   = std::function<void(bool error, const std::string& line)>;

    P2pBlockPublisher(nrelay::LevinBlockRelay& relay, sub::FoundBlockQueue& found,
                      CandidateLookup lookup)
        : m_relay(relay), m_found(found), m_lookup(std::move(lookup)) {}

    // The RandomX fail-closed gate, mirroring LiveBlockSubmitter's. OFF until
    // the verifier is live, so a build that cannot check proof of work can
    // never put a block on somebody else's wire.
    void enable_network_relay(bool on) { m_enabled.store(on); }
    void set_retry_policy(RetryPolicy p) { std::lock_guard<std::mutex> lk(m_park_mx); m_retry = p; }
    void set_clock(Clock c)              { m_clock = std::move(c); }
    void set_log(Log l)                  { m_log = std::move(l); }
    bool network_relay_enabled() const { return m_enabled.load(); }

    // SOLO MODE (--native-solo), OFF by default.
    //
    // The success condition below is reached_network(): at least one peer took
    // the frame. On a solo node there are no peers and no daemon BY
    // CONSTRUCTION, so that condition can never be met, and a real, valid,
    // RandomX-gated block would be dropped on the floor -- the node would mine
    // its own chain forever and book nothing.
    //
    // With this on, a block that reached nobody but that OUR OWN CHAIN INDEX
    // accepted (RelayConfig::submit_to_own_index, the D-14 PREFER-OWN push)
    // still enters the settlement ledger as found. That is a genuinely weaker
    // claim than monerod's "OK" or a peer's receipt, and it is counted and
    // labelled separately everywhere so it cannot be read as the stronger one:
    // solo_landed() is its own counter, and the FoundBlockEvent carries
    // HeaderCheck::NotRun exactly as the relayed path does.
    //
    // It is sound for the case it is for: on a private chain WE are the
    // network, the index validated the block on the way in (parse, id, PoW at
    // the template's difficulty, connect checks), and the canonical test that
    // settlement matures against is that same index -- so a block the index did
    // not take never finalizes, solo or not. It is not sound anywhere else,
    // which is why it is a flag and not a fallback.
    void enable_solo_own_index(bool on) { m_solo.store(on); }
    bool solo_own_index_enabled() const { return m_solo.load(); }

    void on_accepted_share(const strat::AcceptedShare& s) override {
        m_accepted.fetch_add(1);
        if (!s.is_network_block) return;
        m_found.annotate(s.template_id, s.nonce, s.extra_nonce, s.worker, s.address);
        // A parked block's event is not queued yet; it carries the attribution
        // with it when (if) it is released.
        std::lock_guard<std::mutex> lk(m_park_mx);
        for (Parked& p : m_parked) {
            if (p.ev.template_id == s.template_id && p.ev.nonce == s.nonce &&
                p.ev.extra_nonce == s.extra_nonce) {
                p.ev.worker  = s.worker;
                p.ev.address = s.address;
            }
        }
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

        bool solo_landing = false;
        if (!v.reached_network()) {
            // The solo opt-in, and ONLY it, rescues a block nobody received.
            if (!(m_solo.load() && v.landed_own_chain())) {
                m_failed.fetch_add(1);
                const std::string why =
                    v.why.empty() ? std::string("(no reason given)") : v.why;
                // PARK, don't drop: a block the relay accepted and retained (it
                // passed every gate; only the wire was empty) gets the bounded
                // re-announce. A refused block is not retained and is not
                // parked -- there is nothing valid to re-announce. Solo has no
                // peers by construction and keeps its own rule.
                if (!m_solo.load() && m_relay.knows(v.block_id) && park(std::move(ev))) {
                    set_error("relay: block reached NO peer -- PARKED for bounded re-announce: " +
                              why);
                    say(true, "PARKED block " + hex_of(v.block_id) + " h=" +
                                  std::to_string(c.height) +
                                  ": reached no peer; re-announcing for up to " +
                                  std::to_string(retry_policy().window_ms / 1000) + " s / " +
                                  std::to_string(retry_policy().max_attempts) + " attempts");
                    return;
                }
                // Not retained means the relay REFUSED it before any arm fired
                // (an invalid own block -- a tx already mined in the chain it
                // extends, a spent key image, a duplicate -- or a structural
                // fault): not relayed, not parked, not adopted, not booked.
                // Said out loud, never only in the status line.
                say(true, "FOUND block " + hex_of(v.block_id) + " h=" + std::to_string(c.height) +
                              " DROPPED (not relayed, not adopted, not booked): " + why);
                set_error("relay: block reached NO peer: " + why);
                return;
            }
            solo_landing = true;
            m_solo_landed.fetch_add(1);
            set_error("relay: SOLO — block reached no peer and no daemon; our own chain index "
                      "accepted it (this is a weaker claim than a peer receipt, and is only "
                      "honoured because --native-solo was asked for)");
        }

        if (!solo_landing) m_relayed.fetch_add(1);
        m_peers.fetch_add(static_cast<std::uint64_t>(v.p2p_peers_sent));
        unpark(v.block_id);   // a re-submission that got through supersedes a parked copy
        push_found(std::move(ev));
        // A solo landing keeps its explanation: clearing it here would leave the
        // status line claiming a clean relay for a block that reached nobody.
        if (!solo_landing) set_error({});
    }

    // --- the bounded re-announce (main loop thread) --------------------------
    // Cheap when nothing is parked. A due entry is taken OUT of the parked set
    // before it is worked on and goes back only if it is still undelivered,
    // so no two paths can deliver the same block.
    void tick() { tick_at(now_ms()); }

    void tick_at(std::uint64_t now) {
        std::vector<Parked> due;
        RetryPolicy pol;
        {
            std::lock_guard<std::mutex> lk(m_park_mx);
            pol = m_retry;
            for (auto it = m_parked.begin(); it != m_parked.end();) {
                if (now >= it->next_at) { due.push_back(std::move(*it)); it = m_parked.erase(it); }
                else ++it;
            }
        }
        for (Parked& p : due) {
            const std::string id = hex_of(p.ev.block_id);
            const std::string h  = std::to_string(p.ev.height);
            const std::uint64_t age = now >= p.t0 ? now - p.t0 : 0;
            // (i) Our own best chain carries a different block at this height
            //     (or never took ours): re-announcing a loser helps nobody.
            if (m_relay.own_chain_disowns(p.ev.block_id)) {
                m_orphaned_unreached.fetch_add(1);
                set_error("relay: parked block " + id + " DROPPED -- no longer on our own best "
                          "chain (the height was lost before any peer received it)");
                say(true, "RELAY DROPPED block " + id + " h=" + h + " after " +
                              std::to_string(p.attempts) + " re-announce(s) / " +
                              std::to_string(age / 1000) + " s: it is not on our own best chain");
                continue;
            }
            // (ii) One more frame, from the retained bytes.
            std::size_t n = 0;
            (void)m_relay.renotify(p.ev.block_id, &n);
            ++p.attempts;
            if (n > 0) {
                // (iii) THE delivery: the one FoundBlockEvent for this block.
                m_late_reached.fetch_add(1);
                m_relayed.fetch_add(1);
                m_peers.fetch_add(static_cast<std::uint64_t>(n));
                say(false, "LATE RELAY block " + id + " h=" + h + " reached " +
                               std::to_string(n) + " peer(s) on re-announce " +
                               std::to_string(p.attempts) + ", " + std::to_string(age / 1000) +
                               " s after the find");
                push_found(std::move(p.ev));
                set_error({});
                continue;
            }
            const bool retained = m_relay.knows(p.ev.block_id);
            if (!retained || p.attempts >= pol.max_attempts || age >= pol.window_ms) {
                m_abandoned.fetch_add(1);
                const bool own = !m_relay.own_chain_disowns(p.ev.block_id);
                const std::string msg =
                    "RELAY ABANDONED block " + id + " h=" + h + " after " +
                    std::to_string(p.attempts) + " re-announce(s) / " +
                    std::to_string(age / 1000) + " s" +
                    (retained ? "" : " (no longer retained)") +
                    " -- it " + (own ? "IS" : "is NOT") +
                    " on our own best chain; no peer received it, so it is not booked as found";
                set_error("relay: " + msg);
                say(true, msg);
                continue;
            }
            const std::uint32_t k = std::min<std::uint32_t>(p.attempts, 20);
            std::uint64_t backoff = pol.first_backoff_ms << k;
            if (backoff > pol.max_backoff_ms || backoff == 0) backoff = pol.max_backoff_ms;
            p.next_at = now + backoff;
            if (pol.window_ms > age && p.next_at > p.t0 + pol.window_ms)
                p.next_at = p.t0 + pol.window_ms;   // the last try lands on the window edge
            std::lock_guard<std::mutex> lk(m_park_mx);
            m_parked.push_back(std::move(p));
        }
    }

    // --- diagnostics ---------------------------------------------------------
    std::uint64_t calls()    const { return m_calls.load(); }
    // The parked re-announce. parked() is the number waiting right now; the
    // other three are how each parked block ended.
    std::size_t   parked() const { std::lock_guard<std::mutex> lk(m_park_mx); return m_parked.size(); }
    std::uint64_t parked_total()       const { return m_parked_total.load(); }
    // D2: was this own block ever PARKED (published while no relay peer took
    // it)? The minority re-derivation's first candidate refuse set. Thread-safe.
    bool was_parked(const std::string& bid_hex) const {
        std::lock_guard<std::mutex> lk(m_park_mx);
        return m_parked_ever.count(bid_hex) != 0;
    }
    std::uint64_t late_reached()       const { return m_late_reached.load(); }
    std::uint64_t abandoned()          const { return m_abandoned.load(); }
    std::uint64_t orphaned_unreached() const { return m_orphaned_unreached.load(); }
    std::uint64_t duplicate_found()    const { return m_dup_found.load(); }
    std::uint64_t relayed()  const { return m_relayed.load(); }
    // Blocks booked on the strength of our own chain index alone (solo mode).
    // Kept OUT of relayed() so the two can never be added up by accident.
    std::uint64_t solo_landed() const { return m_solo_landed.load(); }
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
    struct Parked {
        sub::FoundBlockEvent ev;
        std::uint64_t        t0       = 0;
        std::uint64_t        next_at  = 0;
        std::uint32_t        attempts = 0;
    };

    void set_error(std::string e) {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_last_error = std::move(e);
    }

    void say(bool error, const std::string& line) const {
        if (m_log) m_log(error, line);
    }

    std::uint64_t now_ms() const {
        if (m_clock) return m_clock();
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    RetryPolicy retry_policy() const {
        std::lock_guard<std::mutex> lk(m_park_mx);
        return m_retry;
    }

    // False when the block is already parked (a repeated submit of the same
    // block is not a second block).
    bool park(sub::FoundBlockEvent ev) {
        const std::uint64_t now = now_ms();
        std::lock_guard<std::mutex> lk(m_park_mx);
        for (const Parked& p : m_parked)
            if (p.ev.block_id == ev.block_id) return true;
        if (m_retry.max_parked == 0) return false;
        while (m_parked.size() >= m_retry.max_parked) {
            m_abandoned.fetch_add(1);
            say(true, "RELAY ABANDONED block " + hex_of(m_parked.front().ev.block_id) +
                          ": the parked set is full (" + std::to_string(m_retry.max_parked) +
                          ") and it is the oldest");
            m_parked.pop_front();
        }
        m_parked_ever.insert(hex_of(ev.block_id));   // D2: isolation mark (was_parked)
        Parked p;
        p.ev      = std::move(ev);
        p.t0      = now;
        p.next_at = now + m_retry.first_backoff_ms;
        m_parked.push_back(std::move(p));
        m_parked_total.fetch_add(1);
        return true;
    }

    void unpark(const sub::Hash& id) {
        std::lock_guard<std::mutex> lk(m_park_mx);
        m_parked.erase(std::remove_if(m_parked.begin(), m_parked.end(),
                                      [&](const Parked& p) { return p.ev.block_id == id; }),
                       m_parked.end());
    }

    // EXACTLY ONCE per block id, whichever path delivers it.
    void push_found(sub::FoundBlockEvent ev) {
        {
            std::lock_guard<std::mutex> lk(m_park_mx);
            if (std::find(m_delivered.begin(), m_delivered.end(), ev.block_id) !=
                m_delivered.end()) {
                m_dup_found.fetch_add(1);
                return;
            }
            m_delivered.push_back(ev.block_id);
            while (m_delivered.size() > 256) m_delivered.pop_front();
        }
        ev.at = std::chrono::steady_clock::now();
        m_found.push(std::move(ev));
    }

    static std::string hex_of(const sub::Hash& h) {
        static const char* kD = "0123456789abcdef";
        std::string s;
        s.reserve(64);
        for (const std::uint8_t b : h) {
            s.push_back(kD[b >> 4]);
            s.push_back(kD[b & 0x0f]);
        }
        return s;
    }

    nrelay::LevinBlockRelay& m_relay;
    sub::FoundBlockQueue&    m_found;
    CandidateLookup          m_lookup;
    std::atomic<bool>        m_enabled{false};
    std::atomic<bool>        m_solo{false};
    std::atomic<std::uint64_t> m_calls{0}, m_relayed{0}, m_peers{0},
                               m_refused{0}, m_failed{0}, m_stale{0},
                               m_solo_landed{0};
    std::atomic<std::size_t>   m_accepted{0};
    mutable std::mutex         m_mtx;
    std::string                m_last_error;

    Clock                      m_clock;
    Log                        m_log;
    mutable std::mutex         m_park_mx;       // m_retry, m_parked, m_delivered
    RetryPolicy                m_retry{};
    std::deque<Parked>         m_parked;
    std::deque<sub::Hash>    m_delivered;
    std::set<std::string>      m_parked_ever;   // D2: every block id ever parked (guarded by m_park_mx)
    std::atomic<std::uint64_t> m_parked_total{0}, m_late_reached{0}, m_abandoned{0},
                               m_orphaned_unreached{0}, m_dup_found{0};
};

} // namespace c2pool::v37n::xmr::o2
