// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH embedded coin-network P2P client (E1: instantiate + outbound dial).
//
// Live-dial counterpart of the S8 socket-node skeleton (p2p_node.hpp). Where
// NodeP2P owns only the request/reply lifecycle over an already-attached
// socket, CoinClient owns the WHOLE outbound connection to a dashd peer:
//
//   * dial: core::Factory<core::Client> resolve/connect to a HOST:PORT target
//     (repeatable targets rotate round-robin on reconnect — DialPlan below);
//   * handshake: version/verack (HandshakeTracker below — the KAT'd state
//     machine), advertising protocol 70230, the SAME version the vendored
//     SML/clsig codecs assume (vendor/smldiff.hpp, vendor/quorum_tail.hpp);
//   * keep-alive: Dash-Core-semantics ping/pong liveness (PeerLiveness below)
//     + handshake timeout teardown;
//   * reconnect: 30s retry while below the pool target, rotating the dial plan.
//
// ── MULTI-PEER POOL (why this client holds N connections, not one) ────────
//
// The daemonless template arm must include DKG quorum commitments (qfcommit)
// in the blocks it builds. Those objects exist ONLY in each full node's
// in-memory minableCommitments map until some miner mines them. Upstream
// announces each one EXACTLY ONCE, at DKG finalize —
// RelayInv(MSG_QUORUM_FINAL_COMMITMENT, SerializeHash(fqc)) — and serves it on
// getdata BY COMMITMENT HASH ONLY. There is no request keyed by
// (llmqType, quorumHash), and the inv hash is a digest of the full signed
// object, so it cannot be derived. IF YOU DID NOT WITNESS THE ANNOUNCEMENT,
// YOU CANNOT OBTAIN THE OBJECT. MSG_CLSIG (29) has the identical shape.
//
// dashd has exactly the same hole. It survives it by holding 8+ persistent
// outbound peers for weeks, so it essentially never misses an announcement —
// and THAT is what makes its "I hold no commitment for this slot, therefore I
// mine null" trustworthy. Holding one peer, "we did not hear it" is a guess,
// and the governing rule in dkg_commitments.hpp is explicit that absence of a
// relayed qfcommit is NOT evidence that the commitment is null: absence is not
// a vote. At mainnet 1520106 this client null-served 32 rotated slots while
// dashd mined 29 real ones, diverging merkleRootQuorums, for precisely that
// reason.
//
// So the pool is an EVIDENCE mechanism, not a throughput one. Miss probability
// falls geometrically in the peer count (roughly 1-(1-p)^N witnesses per
// announcement), which is the difference between "we usually miss it" and "we
// essentially never do". Everything below is designed around that:
//
//   * N concurrent peers (default 8, hard cap 16), each with its OWN liveness
//     policy / ping nonce / handshake tracker / unhandled-command set —
//     PeerSession above. No shared mutable per-connection state.
//   * Inbound fan-in dedup (InvDedup above): the same inv now arrives from
//     several peers; ONE getdata is issued, from a bounded expiring set.
//   * A designated PRIMARY peer carries every request/response leg
//     (getheaders / getmnlistd / getqrinfo / govsync / getdata-for-block), so
//     a reply is always matched to the peer that was asked and the
//     ReplyMatcher state on that Connection stays coherent. Non-primary peers
//     are witnesses: they deliver inv-pushed traffic and are pulled from, but
//     are never asked a stateful question. Losing the primary promotes another
//     handshaked peer and re-kicks the sync, exactly as a reconnect does today.
//   * A silent peer is dropped on its OWN unanswered-ping deadline and cannot
//     stall the others; the pool refills from the scored candidate set.
//
// Ported 1:1 from the PROVEN per-coin clients (src/impl/dgb/coin/p2p_node.hpp
// mirror lineage btc <- ltc), trimmed to the E1 scope: NO ingest legs. The
// tx/block/headers/inv/clsig/mnlistdiff handlers parse and FIRE the
// dash::interfaces::Node events (new_block / new_tx / full_block / new_headers
// / new_chainlock) — that event surface is the seam later slices (E2+) attach
// CoinStateMaintainer / HeaderChain / Mempool ingest to. With no subscribers
// (the E1 run_node wiring), every event is a no-op and NodeCoinState stays
// default-unpopulated, so get_work() keeps taking the retained dashd-RPC
// fallback — zero behavior change on the mining path.
//
// EXPLICITLY NOT HERE (later slices): getheaders sync driving (E2 — dash
// BlockType serialization is header-only, so multi-entry `headers` batches
// need a raw-payload parser first), getdata pulls, compact-block
// reconstruction, mnlistdiff-driven SML maintenance, fee pricing.
//
// Wire magic (pchMessageStart): mainnet bf0c6bbd / testnet cee2caff — supplied
// by run_node via config.coin()->m_p2p.prefix, never hard-coded here. The
// coin-network magic is DISTINCT from the sharechain PREFIX (pool peer
// isolation primitive): different layers, never conflated.
//
// Header-only to match the sibling dash coin leaves.

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"
#include "block.hpp"
#include "transaction.hpp"
#include "spork.hpp"

#include <impl/dash/crypto/hash_x11.hpp>   // block identity on Dash = X11(header)
#include <impl/dash/coin/governance_object.hpp> // govobject_hash / govvote_signature_hash (dashcore-exact digests)
#include <impl/dash/coin/historical_sml.hpp>    // HistoricalMnListDiffDemux (reward-critical tip/historical split)
#include <impl/dash/coin/bulk_peer_policy.hpp>   // #154 select_bulk_eligible_keys (LEVER 1 pure logic)
#include <impl/dash/coin/arrival_timing.hpp>     // PR-0: per-peer per-datum-class delivery-latency EWMA (instrumentation only)
#include <impl/dash/coin/fresh_datum_race.hpp>   // PR-2: fresh-datum race (K-way fan-out selector + single-flight dedup; flag/K default-OFF)
#include <impl/dash/coin/coin_peer_manager.hpp> // PR-2: peer_network_group() for distinct-netgroup racing
#include <impl/dash/coin/proactive_rotation_policy.hpp>  // PR-3: LOW-RATE proactive rotation decision helpers (pure, shared with the KAT)

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/log.hpp>
#include <core/netaddress.hpp>   // classify_address / AddrClass (#154 protected-local primary predicate)
#include <core/random.hpp>
#include <core/factory.hpp>
#include <core/timer.hpp>

namespace dash
{
namespace coin
{
namespace p2p
{

namespace io = boost::asio;

inline std::string parse_net_error(const boost::system::error_code& ec)
{
    switch (ec.value())
    {
    case boost::asio::error::eof:
        return "EOF, socket disconnected";
    default:
        return ec.message();
    }
}

// ── Handshake state machine (pure, KAT-able) ─────────────────────────────
//
// version/verack progress tracker, extracted from the client so the
// transition rules are unit-testable without sockets:
//
//   Idle --on_connected()--> Connected        (socket up, our version sent)
//   Connected --on_version()--> VersionReceived (peer version seen, verack sent)
//   VersionReceived --on_verack()--> Complete   (peer verack seen)
//
// verack-before-version is tolerated (Connected --on_verack()--> Complete;
// some implementations ack eagerly). Events received while Idle are ignored
// (a stray message must not fabricate a session). reset() returns to Idle on
// any disconnect/error.
class HandshakeTracker
{
public:
    enum class State { Idle, Connected, VersionReceived, Complete };

private:
    State m_state{State::Idle};

public:
    State state() const { return m_state; }
    bool complete() const { return m_state == State::Complete; }

    void on_connected() { m_state = State::Connected; }

    // Returns true if this version message is the handshake-advancing one
    // (i.e. we should reply verack); duplicates / pre-connect strays => false.
    bool on_version()
    {
        if (m_state != State::Connected)
            return false;
        m_state = State::VersionReceived;
        return true;
    }

    // Returns true if the handshake just completed.
    bool on_verack()
    {
        if (m_state != State::Connected && m_state != State::VersionReceived)
            return false;
        m_state = State::Complete;
        return true;
    }

    void reset() { m_state = State::Idle; }
};

// ── Dial plan (pure, KAT-able) ───────────────────────────────────────────
//
// Ordered outbound targets for --coin-p2p-connect (repeatable). current() is
// the target being dialed; advance() rotates round-robin so a dead first
// target does not wedge reconnection when alternates were supplied.
class DialPlan
{
    std::vector<NetService> m_targets;
    std::size_t m_index{0};

public:
    void set_targets(std::vector<NetService> targets)
    {
        m_targets = std::move(targets);
        m_index = 0;
    }

    bool empty() const { return m_targets.empty(); }
    std::size_t size() const { return m_targets.size(); }

    // Read-only view of the scored targets — the archival outbound-rotation
    // pump peeks it to decide whether a FRESH (not-already-held, not-in-flight,
    // not-in-cooldown) candidate exists before it evicts a demoted slot-holder.
    // Never mutates the round-robin cursor (a bare check must not consume it).
    const std::vector<NetService>& targets() const { return m_targets; }

    const NetService& current() const { return m_targets.at(m_index); }

    // Rotate to the next target (single-target plans stay put) and return it.
    const NetService& advance()
    {
        if (!m_targets.empty())
            m_index = (m_index + 1) % m_targets.size();
        return current();
    }
};

// ── Peer liveness policy (pure, KAT-able) ────────────────────────────────
//
// Decides, from timestamps alone, whether a peer is still alive. Extracted
// from the client so the rules are unit-testable without sockets or wall
// clocks (test/test_dash_coin_p2p_client.cpp).
//
// WHY THIS EXISTS. The previous rule was a single "no inbound message for
// IDLE_TIMEOUT_SEC (100s) => drop". That rule cannot tell "healthy and quiet"
// from "dead": a peer that is synced with us at the chain tip legitimately
// sends nothing for minutes at a time, so the better-synced we are, the
// faster we killed our own peers. Every inv-PUSHED message type — qfcommit
// (announced once, at DKG finalize) and clsig (announced ~once per block) —
// requires being connected AT THE MOMENT the peer announces, so peer churn
// destroys their acquisition probability. Request/response traffic
// (getmnlistd -> mnlistdiff) survives churn because we re-ask on every fresh
// handshake; inv-push does not. That asymmetry is exactly why the masternode
// bridge completes while the quorum plan never does.
//
// The replacement mirrors Dash Core / Bitcoin Core net.cpp:
//
//   * ping the peer once it has been quiet for m_ping_interval_sec
//     (Dash Core PING_INTERVAL = 2 min);
//   * ANY inbound message — pong included — is liveness evidence and pushes
//     the deadline out;
//   * only drop when a ping has gone UNANSWERED past m_peer_timeout_sec
//     (Dash Core TIMEOUT_INTERVAL = 20 min), or when nothing at all has been
//     received for that same interval.
//
// INVARIANT: liveness is evidence about the PEER. Nothing we SEND may push
// the deadline out — that is what turns a half-open socket into a connection
// we believe is healthy. The only mutator of m_last_recv is on_inbound().
class PeerLiveness
{
public:
    enum class Action
    {
        None,             // nothing to do this tick
        SendPing,         // peer has been quiet for ping_interval; probe it
        DropIdle,         // nothing received at all within peer_timeout
        DropPingTimeout,  // our ping went unanswered past peer_timeout
    };

private:
    time_t m_ping_interval_sec{120};
    time_t m_peer_timeout_sec{1200};

    int64_t  m_last_recv{0};
    bool     m_ping_outstanding{false};
    int64_t  m_ping_sent_at{0};
    uint64_t m_ping_nonce{0};
    uint64_t m_pings_sent{0};
    uint64_t m_pongs_matched{0};

public:
    void configure(time_t ping_interval_sec, time_t peer_timeout_sec)
    {
        if (ping_interval_sec > 0) m_ping_interval_sec = ping_interval_sec;
        if (peer_timeout_sec > 0)  m_peer_timeout_sec = peer_timeout_sec;
    }

    time_t ping_interval_sec() const { return m_ping_interval_sec; }
    time_t peer_timeout_sec() const { return m_peer_timeout_sec; }

    /// Begin (or restart) a session at `now` — call on handshake completion.
    /// Counters are session-scoped and reset with it.
    void start(int64_t now)
    {
        m_last_recv = now;
        m_ping_outstanding = false;
        m_ping_sent_at = 0;
        m_ping_nonce = 0;
        m_pings_sent = 0;
        m_pongs_matched = 0;
    }

    /// ANY inbound message. The ONLY thing that pushes the deadline out.
    void on_inbound(int64_t now) { m_last_recv = now; }

    /// A pong. Only a nonce MATCHING the outstanding ping clears it — a peer
    /// must not be able to hold a link "alive" by replaying an old nonce, and
    /// an unsolicited pong is not an answer to anything. Returns true if this
    /// pong closed the outstanding ping.
    bool on_pong(uint64_t nonce, int64_t now)
    {
        on_inbound(now);
        if (!m_ping_outstanding || nonce != m_ping_nonce)
            return false;
        m_ping_outstanding = false;
        ++m_pongs_matched;
        return true;
    }

    /// Record that a ping with `nonce` was actually written to the wire.
    void note_ping_sent(uint64_t nonce, int64_t now)
    {
        m_ping_outstanding = true;
        m_ping_nonce = nonce;
        m_ping_sent_at = now;
        ++m_pings_sent;
    }

    /// Evaluate the policy. Pure: the caller performs the action and reports
    /// a ping back through note_ping_sent().
    Action tick(int64_t now) const
    {
        if (m_ping_outstanding && (now - m_ping_sent_at) >= m_peer_timeout_sec)
            return Action::DropPingTimeout;
        if ((now - m_last_recv) >= m_peer_timeout_sec)
            return Action::DropIdle;
        if (!m_ping_outstanding && (now - m_last_recv) >= m_ping_interval_sec)
            return Action::SendPing;
        return Action::None;
    }

    bool ping_outstanding() const { return m_ping_outstanding; }
    uint64_t ping_nonce() const { return m_ping_nonce; }
    uint64_t pings_sent() const { return m_pings_sent; }
    uint64_t pongs_matched() const { return m_pongs_matched; }
    int64_t last_recv() const { return m_last_recv; }
};

// ── Inbound inv fan-in dedup (pure, KAT-able) ────────────────────────────
//
// WHY THIS EXISTS. With ONE peer, every inv we saw was the only announcement
// of that object, so answering each one with a getdata was exactly right. With
// a POOL, the same object is announced by every peer that holds it — a single
// DKG finalize is inv'd by all N of them within a few hundred milliseconds. A
// naive port would then issue N getdata for one object and download it N times
// (a full block N times over), for zero extra evidence: the EVIDENCE is having
// WITNESSED the announcement, which we already have from the first inv.
//
// So the fan-in is collapsed here: the FIRST (type, hash) seen is admitted and
// answered; every later announcement of the same (type, hash) inside the TTL is
// suppressed. The announcer count is still tallied, because "this qfcommit was
// announced by 6 of our 8 peers" is precisely the measurement that quantifies
// what the pool bought us.
//
// BOUNDEDNESS IS THE POINT, NOT A DETAIL. This node runs for weeks; an
// unbounded seen-set is a slow leak that only shows up in production. TWO
// independent bounds are enforced, and both are asserted by KATs — neither is
// left as a comment:
//
//   1. TTL (default 600s): entries are inserted in non-decreasing time order,
//      so expiry is a bounded pop_front walk from the oldest end.
//   2. CAPACITY (default 4096 entries): a hard ceiling on set size regardless
//      of arrival rate. Overflow evicts strict-FIFO from the oldest end.
//
// Worst-case residency is therefore capacity entries (~36 bytes each), reached
// and held, never exceeded. size() can never exceed capacity() after admit().
//
// ACCEPTED TRADE-OFF (stated plainly): suppression means one object is pulled
// from ONE peer, so if that peer answers the getdata with nothing we do not
// re-ask a different announcer. That is the SAME exposure the single-peer
// client already had, not a new one — dashd serves what it has just announced
// straight out of its own in-memory map, and the one routinely-observed
// notfound case (a superseded ChainLock) is already handled as benign and
// self-correcting. Re-asking a second announcer would require knowing whether
// the object ever arrived, and for qfcommit/clsig the inv hash is a digest of
// the whole signed object, so there is no key to reconcile an arrival against.
// Deliberately NOT built here.
class InvDedup
{
public:
    static constexpr std::size_t DEFAULT_CAPACITY = 4096;
    static constexpr int64_t     DEFAULT_TTL_SEC  = 600;

    struct Stats
    {
        uint64_t admitted{0};          // getdata actually issued
        uint64_t suppressed{0};        // duplicate announcement collapsed
        uint64_t evicted_capacity{0};  // dropped because the set was full
        uint64_t evicted_ttl{0};       // dropped because the entry aged out
    };

private:
    using key_t = std::pair<uint32_t, uint256>;

    struct Entry
    {
        key_t   key;
        int64_t at;
    };

    std::size_t m_capacity{DEFAULT_CAPACITY};
    int64_t     m_ttl_sec{DEFAULT_TTL_SEC};

    // Insertion-ordered (therefore time-ordered) eviction queue; front is the
    // oldest live entry. m_seen is the O(log n) membership index. The two are
    // maintained in lockstep and always have identical size — that equality is
    // the leak invariant, and it is asserted directly by a KAT.
    std::deque<Entry>   m_order;
    std::map<key_t, int64_t> m_seen;
    Stats m_stats;

    void expire(int64_t now)
    {
        while (!m_order.empty() && (now - m_order.front().at) >= m_ttl_sec)
        {
            m_seen.erase(m_order.front().key);
            m_order.pop_front();
            ++m_stats.evicted_ttl;
        }
    }

    void enforce_capacity()
    {
        while (m_order.size() > m_capacity)
        {
            m_seen.erase(m_order.front().key);
            m_order.pop_front();
            ++m_stats.evicted_capacity;
        }
    }

public:
    /// Both bounds are configurable; capacity is floored at 1 so the set can
    /// never be configured into a state where the entry just admitted is
    /// immediately evicted (which would silently disable dedup entirely).
    void configure(std::size_t capacity, int64_t ttl_sec)
    {
        m_capacity = std::max<std::size_t>(1, capacity);
        if (ttl_sec > 0) m_ttl_sec = ttl_sec;
        enforce_capacity();
    }

    std::size_t capacity() const { return m_capacity; }
    int64_t ttl_sec() const { return m_ttl_sec; }
    std::size_t size() const { return m_order.size(); }
    std::size_t index_size() const { return m_seen.size(); }   // KAT: == size()
    const Stats& stats() const { return m_stats; }

    /// Returns true if THIS announcement is the one to act on (issue the
    /// getdata / fire the event), false if it is a duplicate already covered.
    bool admit(uint32_t type, const uint256& hash, int64_t now)
    {
        expire(now);
        const key_t k{type, hash};
        if (m_seen.find(k) != m_seen.end())
        {
            ++m_stats.suppressed;
            return false;
        }
        m_seen.emplace(k, now);
        m_order.push_back(Entry{k, now});
        ++m_stats.admitted;
        enforce_capacity();
        return true;
    }

    /// Membership probe that does NOT admit (KAT + diagnostics only).
    bool contains(uint32_t type, const uint256& hash) const
    {
        return m_seen.find(key_t{type, hash}) != m_seen.end();
    }

    void clear()
    {
        m_order.clear();
        m_seen.clear();
    }
};

// ── Per-peer session state ───────────────────────────────────────────────
//
// EVERY piece of per-connection mutable state lives HERE, one instance per
// peer, and nothing in this struct is shared between peers. That is not a
// stylistic choice: a shared ping nonce across a pool means a pong from peer A
// closes peer B's outstanding ping, so a dead peer is held "alive" forever by
// its healthy neighbours — the same class of bug the 100s-idle-timeout fix
// removed, but harder to see because the peer count still looks right.
//
// The scheduling GRAIN (one repeating pool tick) is shared; the DECISIONS are
// not. PeerLiveness::tick() is a pure function of that peer's own timestamps,
// so evaluating eight of them from one timer is exactly equivalent to eight
// timers, with one timer's worth of asio state.
struct PeerSession
{
    std::unique_ptr<Connection> conn;
    NetService  addr;
    std::string key;                 // addr.to_string() — the demux key

    HandshakeTracker handshake;      // per-peer
    PeerLiveness     liveness;       // per-peer (own nonce, own deadlines)

    // Pre-handshake deadline, absolute seconds. 0 = not armed (post-handshake:
    // liveness owns the peer from there on). Checked on the pool tick rather
    // than by a per-peer one-shot timer so no timer is ever destroyed from
    // inside its own completion handler.
    int64_t handshake_deadline{0};

    // Version-message metadata, per peer (peers legitimately differ).
    uint64_t    services{0};
    uint32_t    version{0};
    std::string subver;
    uint32_t    start_height{0};

    // First-drop WARNING set for commands outside our Handler set, per peer:
    // one line per (peer, command), not one per message. Bounded by the size of
    // the dashd command vocabulary (tens of entries), and it dies with the
    // session, so it cannot accumulate across reconnects.
    std::set<std::string> unhandled_seen;

    std::chrono::steady_clock::time_point connected_at{
        std::chrono::steady_clock::now()};

    bool primary{false};

    // Messages written TO THIS PEER this session. Per-peer, like everything
    // else here: it is the direct read on "did the fan-in collapse actually
    // stop us issuing N getdata", and on "did the won block reach every peer".
    uint64_t msgs_sent{0};

    // PR-0 ARRIVAL INSTRUMENTATION (record-only). Per-datum-class request-sent
    // timestamp (monotonic ms; -1 = none outstanding) and the smoothed
    // delivery-latency EWMA. note_request_sent() stamps when we ask THIS peer;
    // note_reply_received() closes the latency when the matching reply lands on
    // THIS peer and returns it (or -1 if there was no outstanding request of
    // that class — e.g. a rotated fold whose reply came from a different peer).
    // Pure telemetry: nothing here gates selection, fetch, or derivation.
    std::array<int64_t, static_cast<size_t>(DatumClass::Count)> req_sent_at_ms{
        {-1, -1, -1}};
    PeerDeliveryLatency delivery;

    void note_request_sent(DatumClass cls, int64_t now_ms)
    {
        req_sent_at_ms[static_cast<size_t>(cls)] = now_ms;
    }
    // Returns the observed latency (ms), or -1 when no request of this class was
    // outstanding on this peer. Updates the per-class EWMA on a real match.
    int64_t note_reply_received(DatumClass cls, int64_t now_ms)
    {
        const size_t i = static_cast<size_t>(cls);
        const int64_t sent = req_sent_at_ms[i];
        if (sent < 0 || now_ms < sent) return -1;
        req_sent_at_ms[i] = -1;
        const int64_t latency = now_ms - sent;
        delivery.observe(cls, latency);
        return latency;
    }

    int64_t age_sec() const
    {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - connected_at).count();
    }

    void write(std::unique_ptr<RawMessage>& rmsg)
    {
        ++msgs_sent;
        if (conn) conn->write(rmsg);
    }
};

// PR-0 ARRIVAL INSTRUMENTATION: monotonic milliseconds for delivery-latency
// stamps. Independent of the liveness clock; used only to time request->reply
// round trips for telemetry. Never gates behaviour.
inline int64_t arrival_now_ms()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

#define ADD_P2P_HANDLER(name)\
    void handle(std::unique_ptr<dash::coin::p2p::message_##name> msg)

// Outbound coin-network client: dial, handshake, keep-alive, reconnect.
// Concrete on dash::Config (per-coin isolation — no cross-coin template reuse).
template <typename ConfigType>
class CoinClient : public core::ICommunicator, public core::INetwork, public core::Factory<core::Client>
{
    using config_t = ConfigType;

private:
    static constexpr time_t CONNECT_TIMEOUT_SEC = 10;
    // Dash Core net.h PING_INTERVAL: probe a peer that has been quiet this long.
    static constexpr time_t PING_INTERVAL_SEC = 120;
    // Dash Core net.h TIMEOUT_INTERVAL: drop only when a ping has gone
    // UNANSWERED this long (or nothing at all arrived in that window). This
    // replaces the old 100s "peer sent us nothing => peer is dead" rule, which
    // could not distinguish a healthy tip-synced peer from a dead one.
    static constexpr time_t PEER_TIMEOUT_SEC = 1200;
    // How often the pool tick runs: liveness policy for every peer, pre-handshake
    // deadlines, stale dial-slot reclamation, periodic pool-status log. Only a
    // scheduling grain — every decision is timestamp-based and evaluated from the
    // peer's OWN PeerLiveness, so the grain never changes an outcome, it only
    // makes it punctual. 1s over a pool of 8 is eight integer comparisons a
    // second.
    static constexpr time_t POOL_TICK_SEC = 1;
    static constexpr time_t RECONNECT_INTERVAL_SEC = 30;
    // ── Lost-body watchdog (#1089 208 s tail; same defect class as the
    // #1077 rotated-pending wedge: a request with no timeout). A tracked
    // getdata(block) answered by nothing has NO protocol-level retry, and
    // InvDedup (TTL 600 s) suppresses the same block's inv from every other
    // peer — so a single lost body request can stall the tip body for up to
    // 10 minutes (the 208 s episode measured on soak0804e sits squarely in
    // this class). T = 10 s: ~5x the worst normal same-stream headers→block
    // gap (~1-2 s), far below the 157.5 s block interval, and a false
    // positive costs one duplicate block-sized response — cheap. Re-requests
    // rotate through the pool's OTHER handshaked peers (post-#1082 up to 8),
    // capped at BODY_REREQUEST_MAX consecutive stalls per peer-set, after which
    // the STALLING peer is disconnected so the block is re-requested from a
    // churned peer set — the slot is NEVER abandoned.
    //
    // dashd model (net_processing block download): a needed block stays in
    // mapBlocksInFlight until it is delivered; a peer that stalls its window
    // past BLOCK_STALLING_TIMEOUT (starts ~2 s, doubles, caps at 64 s) loses its
    // in-flight slot and is disconnected, and FindNextBlocksToDownload
    // re-assigns the block to any peer whose announced tip covers it. We mirror
    // that: a tracked slot is removed ONLY when the body actually lands (the
    // block handler), the per-slot stall window doubles per consecutive stall,
    // and a chronic staller is disconnected so the pool churns to a peer that
    // will serve the body. This closes the height-967736 wedge where the old
    // fixed cap erased the slot and left the lane frozen with connected=8/8.
    static constexpr int64_t BODY_STALL_TIMEOUT_INIT = 2;   // dashd start
    static constexpr int64_t BODY_STALL_TIMEOUT_MAX  = 64;  // dashd doubling cap
    // Consecutive stalls against the CURRENT peer set before the blamed peer is
    // disconnected (releasing its slot; the peer-manager backoff keeps it from
    // being re-dialed immediately) so recovery churns to a peer that has it.
    static constexpr int      BODY_REREQUEST_MAX = 4;
    // Tracked slots floor: the tip body plus a short burst of near-tip
    // blocks. The tip-follow path never needs more than this.
    static constexpr size_t PENDING_BODY_CAP  = 8;
    // dashd MAX_BLOCKS_IN_TRANSIT_PER_PEER: the parallel in-flight window it
    // keeps PER PEER during IBD (net_processing.cpp). The tracked-body watchdog
    // now also carries the mn-checkpoint anchor->tip BULK fold (a ~9.5k-block
    // deep replay on a cut cold start), so the in-flight bound is dashd's
    // per-peer window times the handshaked pool size (effective_pending_cap),
    // never below PENDING_BODY_CAP. This lets a full fold window
    // (MnCheckpointLane::kWindow) stay tracked and spread across the pool
    // instead of being evicted at a fixed 8 — the eviction that used to strand
    // bulk-fold slots and leave the whole fold funnelled at one primary.
    static constexpr size_t MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
    // Pool-status log cadence (the soak's direct read on peer count + durability).
    static constexpr time_t POOL_STATUS_INTERVAL_SEC = 60;
    // A dial that never calls back (no connected(), no connect_failed()) must not
    // hold a pool slot forever. Slots are reclaimed after this long; the peer
    // manager's own backoff keeps the target from being re-dialed immediately.
    static constexpr time_t DIAL_SLOT_TIMEOUT_SEC = 60;

    // Dash Core PROTOCOL_VERSION we advertise. MUST stay >= 70230: the
    // vendored mnlistdiff/clsig wire codecs (vendor/smldiff.hpp,
    // vendor/quorum_tail.hpp) parse the >=70230 layout.
    static constexpr uint32_t PROTOCOL_VERSION = 70230;
    static constexpr uint64_t NODE_NETWORK = 1;   // no segwit/witness on Dash
    // dashd service-flag classification (net_processing CanServeBlocks /
    // IsLimitedPeer). A PRUNED node advertises NODE_NETWORK_LIMITED (serves
    // only the last ~288 blocks) and CLEARS NODE_NETWORK; a full/archival node
    // sets NODE_NETWORK (usually LIMITED too). The mn-checkpoint anchor->tip
    // bulk fold reaches ~9.5k blocks deep, so a limited-only peer can never
    // serve it — CanServeBlocks convergence must exclude it from selection.
    static constexpr uint64_t NODE_NETWORK_LIMITED = 0x400;
    // dashd NODE_NETWORK_LIMITED_MIN_BLOCKS(288) - 2: the depth beyond which a
    // limited peer is not asked (FindNextBlocksToDownload historical gate).
    static constexpr uint32_t LIMITED_PEER_HISTORY_BLOCKS = 286;
    // A peer that answers NOTFOUND for a bulk body, or that the stall watchdog
    // disconnects for a chronic body stall, is demoted after this many strikes:
    // next_bulk_peer() then skips it so the round-robin CONVERGES onto peers
    // that actually deliver deep history (dashd per-peer download-failure
    // demotion). One clean body delivery from a peer forgives it.
    static constexpr int BULK_NONSERVER_STRIKE_MAX = 2;
    static constexpr uint16_t MAINNET_P2P_PORT = 9999;

public:
    // Concurrent outbound peers held by default. 8 matches what dashd itself
    // keeps, which is the empirical bar for "we essentially never miss an
    // announcement". Raise it and the miss probability keeps falling; the cap
    // exists so a config typo cannot turn this node into a connection storm
    // against the network.
    static constexpr std::size_t DEFAULT_POOL_PEERS = 8;
    static constexpr std::size_t POOL_PEERS_HARD_CAP = 16;

    // ── dashd outbound-acquisition parity (archival rotation pump) ─────────
    // dashd never stays starved on a full-but-shallow peer set: while it is
    // behind it opens EXTRA full-relay outbound (GetExtraFullOutboundCount) and
    // it DISCONNECTS a peer that holds a download slot without serving
    // (BLOCK_STALLING_TIMEOUT) so ThreadOpenConnections refills the freed slot
    // with a FRESH addrman candidate — cycling until every download slot holds
    // an archival (NODE_NETWORK) peer and the block-download window fills. Our
    // pool, in contrast, latched: a full pool early-returns from refill_pool()
    // (a frozen full pool) and the bulk lane only DEMOTES a demonstrated
    // non-server (holds it off fresh ranges) without ever freeing its slot, so
    // the large addrman bank behind the working set was never drawn again and
    // "only 7 peers serve deep bodies" was the frozen first-come set, not the
    // network's ceiling. This pump is the missing acquisition half, and it is
    // connection-management ONLY: the per-block merkleRoot fold self-check +
    // payee cross-check + poison fail-closed are untouched, no block is skipped
    // — it only changes WHICH / HOW-MANY peers the fold fetches from.
    //
    // GetExtraFullOutboundCount analog: while a demonstrated deep-body
    // non-server occupies a slot we are "behind" on archival coverage, so raise
    // the effective dial target by this many (clamped to the hard cap) — dial
    // MORE fresh candidates to reach archival servers beyond the frozen set.
    static constexpr std::size_t OUTBOUND_BEHIND_EXTRA = 2;
    // BLOCK_STALLING_TIMEOUT cadence: minimum seconds between two evict+refill
    // rotations so a transiently-quiet peer is never churned (dashd's stall
    // timeout is seconds, doubling; this is the steady rotation floor).
    static constexpr int64_t OUTBOUND_ROTATE_INTERVAL_SEC = 20;
    // A just-rotated-out address is held OFF redial this long (addrman-backoff
    // analog) so refill_pool() draws a genuinely fresh candidate instead of
    // immediately re-dialing the non-server we just dropped.
    static constexpr int64_t OUTBOUND_ROTATE_COOLDOWN_SEC = 120;
    // PR-3 proactive rotation cadence: a LOW rate (5 min) — far slower than
    // the stall rotation (OUTBOUND_ROTATE_INTERVAL_SEC=20s). Bounds the
    // proactive probe+shed so a HEALTHY pool trends toward the fastest
    // deliverers without churning connections.
    static constexpr int64_t PROACTIVE_ROTATE_INTERVAL_SEC = 300;

private:
    dash::interfaces::Node* m_coin;
    io::io_context* m_context;
    config_t* m_config;
    p2p::Handler m_handler;

    // ── the pool ─────────────────────────────────────────────────────────
    // Stable-address ownership (unique_ptr elements) so PeerSession* cursors
    // survive vector growth; erase is by key, never by index.
    std::vector<std::unique_ptr<PeerSession>> m_pool;
    // The peer carrying every request/response leg. Set when the FIRST peer
    // completes its handshake and re-elected from the surviving handshaked
    // peers when that one is lost. nullptr => no peer is ready to be asked.
    PeerSession* m_primary{nullptr};
    // Round-robin cursor over m_pool for bulk/historical block-body getdata
    // (dashd FindNextBlocksToDownload spreads a deep IBD window across peers,
    // never funnelling it at one peer).
    std::size_t  m_bulk_rr{0};
    // dashd per-peer download-failure demotion (archival convergence). Keyed by
    // peer addr:port so a strike survives the PeerSession object and even a
    // reconnect to the same non-serving address. Incremented on NOTFOUND for a
    // bulk body and on stall-eviction; cleared when that peer delivers a body.
    std::map<std::string, int> m_bulk_nonserver_strikes;
    // ── archival outbound-rotation pump state (dashd acquisition parity) ───
    // Master switch. Default ON (this is an always-on port like the bulk demote
    // #1272 / header stall-disconnect #1283 that precede it); flipping it OFF
    // restores BYTE-IDENTICAL pre-port behaviour (a frozen full pool), which is
    // both the safety escape hatch and the RED arm of the acquisition KATs.
    bool m_outbound_rotate_enabled{true};
    // Rate limit: wall-second of the last evict+refill rotation.
    int64_t m_last_outbound_rotate{0};
    // Just-evicted addresses held OFF redial: addr -> skip-until wall-second.
    std::map<std::string, int64_t> m_rotation_cooldown;
    // Telemetry: how many demoted slot-holders we have rotated out for a fresh
    // archival dial (asserted by the KATs, surfaced in the pool-status log).
    uint64_t m_outbound_rotations{0};
    // ── PR-3 proactive rotation (LOW-RATE, default OFF) ────────────────────
    // When armed (--embedded-proactive-rotate), a HEALTHY pool periodically
    // probes one fresh candidate and sheds its slowest measured non-primary
    // server (maybe_proactive_rotate). OFF by default => on_pool_tick() runs the
    // stall-only path, BYTE-IDENTICAL to master.
    bool     m_proactive_rotate_enabled{false};
    int64_t  m_last_proactive_rotate{0};
    uint64_t m_proactive_rotations{0};
    // Round-robin cursor for the STATEFUL request legs (the mn-checkpoint
    // anchor->tip fold's getmnlistd snapshot). dashd picks a sync peer for a
    // mnlistdiff and ROTATES to another on stall rather than re-asking one slow
    // peer forever; a live cold soak froze 26 min pinned to a single slow
    // primary waiting for the deep base->anchor fold snapshot. This cursor
    // spreads the fold's getmnlistd (and its re-asks) across the eligible
    // (CanServeBlocks) pool. m_last_stateful_peer lets a re-ask prefer a
    // DIFFERENT carrier so it actually fans out.
    std::size_t  m_stateful_rr{0};
    std::string  m_last_stateful_peer;
    // dashd TipMayBeStale/SetTryNewOutboundPeer analog for the STATEFUL leg: a
    // bridging getmnlistd (fold / ondemand-mnlist) that the mn-ckpt lane has
    // found outstanding past its wall-clock re-ask grace. While set,
    // outbound_behind() is true so effective_max_peers() expands and refill/
    // rotation dials past the base pool to reach a peer that will answer —
    // exactly as dashd opens an extra OUTBOUND_FULL_RELAY when it falls behind.
    // Set/cleared every lane watchdog tick via note_stateful_stall(), so it
    // self-clears the moment the leg is served. Dial-count only.
    bool         m_stateful_stall{false};
    // The peer select_block_peer() last sent a block getdata to, so
    // request_block_tracked() arms the watchdog against the peer actually
    // asked (not an unrelated primary).
    std::string  m_last_requested_peer;
    // Dispatch cursor: the peer whose message is being handled RIGHT NOW.
    // Valid only inside handle(); this client is single-thread-confined to the
    // io_context (main_dash.cpp:1613), so this is a parameter, not shared state.
    PeerSession* m_active{nullptr};
    std::size_t m_max_peers{DEFAULT_POOL_PEERS};
    // Outbound dials issued but not yet resolved into connected()/connect_failed().
    // key -> issued-at. They hold a pool slot so a refill cannot over-dial, and
    // are reclaimed after DIAL_SLOT_TIMEOUT_SEC so a callback that never comes
    // cannot wedge the pool below target.
    std::map<std::string, int64_t> m_dialing;
    // Collapses the N-peer inv fan-in to one getdata. Bounded + expiring.
    InvDedup m_inv_dedup;

    /// Reclaim tx-pull slots whose getdata was never answered. Without this a
    /// peer that goes quiet after announcing permanently consumes the budget.
    void expire_tx_pulls(int64_t now)
    {
        for (auto it = m_tx_pull_inflight.begin(); it != m_tx_pull_inflight.end(); ) {
            if (now - it->second > TX_PULL_TIMEOUT_SEC) {
                it = m_tx_pull_inflight.erase(it);
                ++m_tx_pull_expired;
            } else {
                ++it;
            }
        }
    }

    /// Re-issue getdata for tx/dstx invs parked while a tip body was in flight
    /// (mempool-ingest-completeness). One pass per pool tick. The tip body
    /// ALWAYS keeps priority: nothing drains while a body is outstanding, and
    /// the loop bails the instant a body arrives mid-drain. Each retry rides
    /// the SAME inflight budget/cap and txid-keyed dedup as a first-time pull
    /// (the inv hash IS the txid for both lanes), and echoes the ANNOUNCED
    /// type so a DSTX is re-asked as MSG_DSTX. The getdata goes to a
    /// handshaked peer (tx relay is gossiped — any peer holding it in mempool
    /// serves it; a peer that lacks it answers notfound, which is benign and
    /// self-correcting, exactly like the block watchdog's cross-peer re-ask).
    void drain_tx_retry_busy(int64_t now)
    {
        if (m_tx_retry_busy.empty())    return;
        if (!m_pending_bodies.empty())  return;   // tip body still wins
        // A peer to ask: prefer the active session, else any handshaked peer.
        PeerSession* peer = (m_active && m_active->handshake.complete())
                            ? m_active : nullptr;
        if (!peer)
            for (auto& up : m_pool)
                if (up->handshake.complete()) { peer = up.get(); break; }
        if (!peer) return;   // no one to ask yet — keep the queue for next tick
        expire_tx_pulls(now);
        while (!m_tx_retry_busy.empty())
        {
            if (!m_pending_bodies.empty()) break;                 // a body arrived
            if (m_tx_pull_inflight.size() >= m_tx_pull_inflight_cap) break;  // budget
            const TxRetry r = m_tx_retry_busy.front();
            m_tx_retry_busy.pop_front();
            if (m_tx_pull_inflight.count(r.hash)) continue;       // already in flight
            m_tx_pull_inflight.emplace(r.hash, now);
            const bool is_dstx = (r.type == static_cast<uint32_t>(inventory_type::dstx));
            if (is_dstx) ++m_dstx_pull_sent; else ++m_tx_pull_sent;
            ++m_tx_retry_drained;
            auto getdata_msg = message_getdata::make_raw(
                {inventory_type(static_cast<inventory_type::inv_type>(r.type), r.hash)});
            peer->write(getdata_msg);
        }
    }

    // ── MEMPOOL INGEST (phase 1): the MSG_TX pull ────────────────────────
    // The whole reason every embedded template is EMPTY. inv_type_is_pulled()
    // admits quorum_final_commitment and clsig only, so a peer's inv(MSG_TX)
    // was dropped without a getdata, the `tx` handler below never fired, and
    // Mempool::add_tx was unreachable FROM THE NETWORK. Everything downstream
    // of that handler already exists (#1110).
    //
    // Not simply added to inv_type_is_pulled: tx invs arrive orders of
    // magnitude more often than blocks or clsigs, so an unbudgeted pull lets
    // a peer make us getdata-flood ourselves. This lane is therefore:
    //   * OPT-IN                (m_tx_pull_enabled, --embedded-mempool-ingest)
    //   * BUDGETED              (m_tx_pull_inflight_cap outstanding at once)
    //   * STRICTLY LOWER PRIORITY than the tip body — no tx getdata is issued
    //     while a tracked block body is outstanding, the same invariant the
    //     bulk-fetch lane observes.
    // In-flight slots expire on their own (TX_PULL_TIMEOUT_SEC) so a peer that
    // answers a getdata with silence cannot wedge the budget.
    static constexpr int64_t TX_PULL_TIMEOUT_SEC = 60;
    bool     m_tx_pull_enabled{false};
    // BLS-verified isdlock lane (--embedded-ingest-isdlock): OPT-IN. The
    // getdata itself is NOT gated (the #1230 fee-only-safe new_islock lane
    // rides every received isdlock); OFF only means the handler does not
    // forward to the BLS-verified new_isdlock lane. No budget needed: dashd
    // announces at most one isdlock per locked tx, orders of magnitude rarer
    // than MSG_TX, and the payload is bounded at decode (MAX_ISDLOCK_INPUTS).
    bool     m_isdlock_pull_enabled{false};
    // DSTX (CoinJoin broadcast tx) lane (--embedded-ingest-dstx): OPT-IN,
    // and — unlike isdlock — the GETDATA ITSELF is gated: a DSTX has no
    // fee-only-safe unconditional consumer (its whole effect is putting a
    // zero-fee tx INTO templates at top priority), so off-flag there is no
    // reason to spend bandwidth. The pull rides the SAME budget/inflight
    // machinery as MSG_TX (the DSTX inv hash IS the plain txid,
    // net_processing.cpp:2567, so the txid-keyed slots are correct).
    bool     m_dstx_pull_enabled{false};
    uint64_t m_dstx_inv_seen{0};     // inv(MSG_DSTX) admitted by the dedup
    uint64_t m_dstx_pull_sent{0};    // getdata(MSG_DSTX) issued
    uint64_t m_dstx_received{0};     // dstx bodies that arrived
    size_t   m_tx_pull_inflight_cap{64};
    std::map<uint256, int64_t> m_tx_pull_inflight;   // txid -> requested-at
    uint64_t m_tx_inv_offered{0};    // inv(MSG_TX) SEEN on the wire, pre-dedup
    uint64_t m_tx_inv_seen{0};       // inv(MSG_TX) admitted by the dedup
    uint64_t m_tx_pull_sent{0};      // getdata(MSG_TX) issued
    uint64_t m_tx_pull_skipped_budget{0};
    uint64_t m_tx_pull_skipped_busy{0};
    uint64_t m_tx_received{0};       // tx bodies that arrived
    uint64_t m_tx_pull_expired{0};   // getdata that never got an answer

    // ── Tip-body-busy retry queue (mempool-ingest-completeness) ──────────
    // A tx/dstx inv admitted by InvDedup but then SKIPPED because a tip body
    // was in flight is parked here — NOT dropped. InvDedup holds the (type,
    // hash) for its 600 s TTL, so a re-announcement from any other peer is
    // suppressed and the tx would otherwise be stranded until the entry ages
    // out (by which time it is usually already mined). When the tip body
    // clears, drain_tx_retry_busy() re-issues the getdata, recovering the
    // ~2 % of invs this window costs. Bounded FIFO: a sustained body-in-flight
    // burst drops the OLDEST parked inv, never grows unbounded. Dormant unless
    // the owning lane (m_tx_pull_enabled / m_dstx_pull_enabled) is armed — the
    // park site is downstream of the is_tx/is_dstx flag gate — so a
    // default-configured node parks nothing and its wire is byte-identical.
    struct TxRetry { uint32_t type; uint256 hash; };
    std::deque<TxRetry> m_tx_retry_busy;
    size_t   m_tx_retry_busy_cap{256};
    uint64_t m_tx_retry_requeued{0};   // invs parked while a tip body was busy
    uint64_t m_tx_retry_drained{0};    // parked invs later re-issued as getdata

    // ── SPORK listener (state + telemetry ONLY — nothing gates on it) ────
    // Seeded with the assume-active mainnet defaults (7/7 active, matching
    // dashd's hardened mainnet spork values), refined by VERIFIED spork
    // messages from peers. Verification key defaults to the mainnet spork key
    // ID from dashd chainparams; overridable only by the test seam below.
    SporkState m_spork_state;
    std::array<uint8_t, 20> m_spork_pubkey_id{MAINNET_SPORK_PUBKEY_ID};
    // IS/CL mining-safety hold seam (set_spork_change_callback): fired on the
    // io thread whenever a verified spork applies, so the hold's spork2+spork3
    // arm-bit is recomputed on the SAME thread that owns m_spork_state.
    std::function<void()> m_spork_change_cb;

    // ── Lost-body watchdog state (see BODY_REREQUEST_* above) ────────────
    // One slot per tracked outstanding getdata(block); disarmed by the block
    // handler on receipt (from ANY peer), serviced by the pool tick.
    struct PendingBody
    {
        uint256     hash;
        int64_t     first_req{0};
        int64_t     last_req{0};
        int         rerequests{0};
        std::string last_peer;    // don't re-ask the peer that just failed us
        // dashd BLOCK_STALLING_TIMEOUT: fast first retry, doubling per stall,
        // reset to INIT whenever the slot is (re)assigned to a fresh peer.
        int64_t     stall_timeout{BODY_STALL_TIMEOUT_INIT};
        // Consecutive stall-driven re-requests since the last staller eviction;
        // at BODY_REREQUEST_MAX the blamed peer is disconnected to churn the set.
        int         stalls_since_evict{0};
        // Stallers disconnected to recover THIS body (per-slot telemetry).
        int         evictions{0};
    };
    std::vector<PendingBody> m_pending_bodies;
    uint64_t m_body_rerequests_total{0};
    // Stalling peers disconnected to keep a needed body from wedging the lane
    // (dashd disconnect-on-stall). Surfaced as body_stall_evictions.
    uint64_t m_body_stall_evictions{0};

    // ── tip-body announcer routing (#1082 pool + #1094 body-first) ───────
    // A block `inv` names a peer that HOLDS the block. The tip-body getdata
    // (and the getheaders that must precede its connect) is fetched from THAT
    // peer — not from an arbitrary primary that, on a WARM node, may be behind
    // or wedged and silently never delivers (no notfound, so the watchdog just
    // exhausts). This mirrors the qfcommit/clsig pull, which already asks the
    // announcer. Bounded FIFO; the announcer is resolved LIVE (never a cached
    // pointer), so pool churn just falls back to the primary.
    struct BlockAnnouncer { uint256 hash; std::string key; };
    std::vector<BlockAnnouncer> m_block_announcers;
    static constexpr std::size_t ANNOUNCER_CAP = 64;

    std::unique_ptr<core::Timer> m_reconnect_timer;
    // ONE repeating tick for the whole pool (liveness, handshake deadlines,
    // dial-slot reclamation, status log). Per-peer STATE stays per-peer.
    std::unique_ptr<core::Timer> m_pool_timer;
    time_t m_pool_tick_sec{POOL_TICK_SEC};
    // Keepalive thresholds STAMPED onto every PeerSession at attach. The client
    // holds the configuration; each peer evaluates its own copy against its own
    // timestamps. Overridable only by set_keepalive_for_test().
    time_t m_ping_interval_sec{PING_INTERVAL_SEC};
    time_t m_peer_timeout_sec{PEER_TIMEOUT_SEC};
    DialPlan m_dial_plan;
    bool m_reconnect_enabled = false;
    std::string m_chain_label = "COIN-P2P";

    // Wall-clock source for EVERY deadline this client evaluates: handshake
    // deadlines, the ping/unanswered-ping policy, dial-slot reclamation.
    // Default is the steady clock; tests inject a fake one (same seam shape as
    // CoinStateMaintainer::set_now_fn).
    std::function<int64_t()> m_now_fn{[]() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }};

    int64_t m_last_status_log{0};
    uint64_t m_sessions_started{0};
    uint64_t m_sessions_lost{0};
    // Keepalive tallies of sessions already torn down. Folded into the
    // pool-wide pings_sent()/pongs_matched() so a reaped peer's evidence is not
    // erased by the reaping.
    uint64_t m_retired_pings_sent{0};
    uint64_t m_retired_pongs_matched{0};
    // Highest peer-advertised height seen across the WHOLE pool. The height
    // callback drives a sync-progress gauge, so it is fed monotonically: a
    // lagging pool member must not be able to walk the target backwards.
    uint32_t m_best_peer_height{0};

    // E2+ seams (callbacks, all optional)
    using AddrCallback = std::function<void(const std::vector<NetService>&)>;
    AddrCallback m_addr_callback;
    using PeerHeightCallback = std::function<void(uint32_t)>;
    PeerHeightCallback m_on_peer_height;
    using HandshakeCallback = std::function<void()>;
    HandshakeCallback m_on_handshake_complete;
    // Peer lifecycle seams for the DASH-isolated CoinPeerManager scoring feed
    // (coin/coin_peer_manager.hpp). Fired with the peer's "host:port" key so the
    // manager can score connects/disconnects and persist anchors. Both optional;
    // unset on the legacy single-peer --coin-p2p-connect path (no behaviour change).
    using PeerLifecycleCallback = std::function<void(const NetService&)>;
    PeerLifecycleCallback m_on_peer_connected;
    PeerLifecycleCallback m_on_peer_disconnected;
    // #940: fired when an OUTBOUND DIAL fails before the socket comes up (the
    // core Factory could not connect/resolve the target). Distinct from
    // m_on_peer_disconnected, which only fires AFTER a socket was established —
    // a dial that dies at ECONNREFUSED/ETIMEDOUT never reaches that seam. Feeds
    // the CoinPeerManager scorer so dead targets are penalised instead of
    // re-selected forever. Optional; unset on the legacy single-peer path.
    PeerLifecycleCallback m_on_dial_failed;

    // HISTORICAL mnlistdiff DEMUX: consumes full base=ZERO snapshots at OLD
    // blocks — requested by QuorumMemberSource (quorum work blocks) and by
    // MnCheckpointLane (per-height PoSe fold points) — BEFORE they reach the
    // tip-SML maintainer, which treats any ZERO-base diff as a full snapshot
    // and would overwrite the LIVE tip SML to that historical block. See
    // historical_sml.hpp for the chain semantics (non-short-circuiting: two
    // consumers may legitimately await the same block hash). No filters
    // registered => every diff falls through to the tip feed, as before.
    using MnListDiffFilter = HistoricalMnListDiffDemux::Filter;
    HistoricalMnListDiffDemux m_historical_mnlistdiff_demux;

    // DIP-24 qrinfo consumers. Unlike mnlistdiff there is no tip-feed hazard
    // (nothing else consumes qrinfo, so nothing can be corrupted by a stray
    // reply); this is a plain additive fan-out, and no registered consumer
    // means a received qrinfo is logged and dropped.
    using QrInfoConsumer = std::function<void(const vendor::CQuorumRotationInfo&)>;
    std::vector<QrInfoConsumer> m_qrinfo_consumers;

    // ── W2 replay bulk-fetch demux seams (replay_bulk_fetch.hpp) ─────────
    // Registered ONLY under --replay-bulk; unset (the default and every
    // released posture) both are null and the handlers below behave
    // byte-identically to before.
    //
    //   * headers filter: a `headers` batch CLAIMED by the genesis→anchor
    //     backfill walker is consumed BEFORE the new_headers event — the main
    //     HeaderChain must never see pre-anchor batches (they orphan-reject
    //     and pollute the CP2 accepted==0 diagnostic), and the tip lane's
    //     header ingest must never be re-pointed at 2012-era headers.
    //   * block-body filter: a body the bulk scheduler has in flight is
    //     consumed BEFORE the full_block event — bulk bodies must never
    //     enter the live ingest legs (whose deferral buffers assume tip-rate
    //     traffic), and tip bodies must never be swallowed by the bulk lane
    //     (the filter only claims hashes it requested itself).
    //   * block notfound callback: lets the bulk lane requeue an archival
    //     gap on a different peer instead of waiting out its timeout.
    using HeadersFilter =
        std::function<bool(const std::string& peer_key,
                           const std::vector<BlockType>&)>;
    HeadersFilter m_headers_filter;
    using BlockBodyFilter =
        std::function<bool(const uint256&, const BlockType&)>;
    BlockBodyFilter m_block_body_filter;
    using BlockNotFoundCallback = std::function<void(const uint256&)>;
    BlockNotFoundCallback m_on_block_notfound;

    // Commands already reported as dropped-unhandled, so the WARNING fires
    // once per distinct command instead of once per message. See handle().
    std::set<std::string> m_unhandled_seen;

public:
    CoinClient(io::io_context* context, dash::interfaces::Node* coin, config_t* config,
               const std::string& chain_label = "COIN-P2P")
        : core::Factory<core::Client>(context, this, chain_label)
        , m_coin(coin), m_context(context), m_config(config)
        , m_chain_label(chain_label)
    {
    }

    ~CoinClient()
    {
        m_reconnect_enabled = false;
        if (m_reconnect_timer) m_reconnect_timer->stop();
        if (m_pool_timer) m_pool_timer->stop();
        m_primary = nullptr;
        m_active = nullptr;
        m_pool.clear();
    }

    /// Target number of CONCURRENT peers. Clamped to [1, POOL_PEERS_HARD_CAP].
    /// Call before connect(); raising it later is honoured on the next refill,
    /// lowering it does NOT tear existing peers down (they age out normally).
    void set_max_peers(std::size_t n)
    {
        m_max_peers = std::clamp<std::size_t>(n, 1, POOL_PEERS_HARD_CAP);
    }
    std::size_t max_peers() const { return m_max_peers; }

    /// IS/CL mining-safety hold seam: invoked on the io thread after every
    /// VERIFIED spork APPLIES to SporkState (never for stale/bad-signature
    /// messages). main_dash uses it to recompute the spork2+spork3 conjunction
    /// and push the result into the mempool's hold arm-bit (an atomic), so the
    /// hold tracks live spork flips exactly as dashd's TestPackageTransactions
    /// does (IsInstantSendEnabled / RejectConflictingBlocks). Set once at
    /// wiring time, before the io loop runs; optional (unset = no-op).
    void set_spork_change_callback(std::function<void()> cb)
    {
        m_spork_change_cb = std::move(cb);
    }

    /// Dial the given targets with automatic reconnection (30s interval,
    /// round-robin over the target list on each retry).
    ///
    /// An EMPTY target list is legal in the --coin-p2p-discover cold-start case
    /// (fresh peer-db + DNS unavailable): the reconnect loop is armed anyway and
    /// simply idles (the empty-plan guard below), so when update_dial_targets()
    /// later delivers seed-discovered peers (fixed seeds at t+60s / HTTP at
    /// t+90s) the dial starts — no restart needed. Without this, an initially
    /// empty discover peer set would wedge permanently.
    void connect(std::vector<NetService> targets)
    {
        m_dial_plan.set_targets(std::move(targets));
        m_reconnect_enabled = true;
        if (!m_dial_plan.empty()) {
            LOG_INFO << "[" << m_chain_label << "] dialing up to " << m_max_peers
                     << " concurrent peer[s] from " << m_dial_plan.size()
                     << " target[s] in plan";
            refill_pool();
        } else {
            LOG_INFO << "[" << m_chain_label << "] no initial dial targets; "
                        "reconnect loop armed, awaiting seed discovery";
        }
        arm_reconnect_timer();
        ensure_pool_timer();
    }

    /// Refresh the reconnect dial plan in place WITHOUT tearing the current
    /// connection. The DASH-isolated CoinPeerManager calls this periodically
    /// with a freshly-scored, group-diverse target set (pinned local dashd
    /// first, then the highest-scoring discovered peers) so that on the next
    /// reconnect the single embedded connection rotates onto an INDEPENDENT
    /// peer — the mechanism that graduates the embedded arm to a network-
    /// standalone witness. Empty target lists are ignored (never wedge redial).
    ///
    /// Cold-start kick: if the plan was EMPTY (the discover daemonless case) and
    /// we are currently disconnected with the reconnect loop armed, dial the
    /// first new target immediately rather than waiting up to 30s for the next
    /// reconnect tick — so the arm connects as soon as seeds arrive.
    void update_dial_targets(std::vector<NetService> targets)
    {
        if (targets.empty()) return;
        m_dial_plan.set_targets(std::move(targets));
        LOG_DEBUG_COIND << "[" << m_chain_label << "] dial plan refreshed ("
                        << m_dial_plan.size() << " scored target[s])";
        // Cold-start kick AND steady-state top-up in one: refill_pool() is a
        // no-op when the pool is already at target, so calling it on every
        // refresh both starts the daemonless discover case as soon as seeds
        // land and closes any slot lost since the last 30s reconnect tick.
        if (m_reconnect_enabled)
            refill_pool();
    }

    // INetwork
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        // Factory::Client calls socket->init() then connected() WITHOUT
        // checking status (unlike the Server accept path), so a socket whose
        // local/remote endpoint lookup failed can arrive here already dead —
        // with a default (":0") address that would occupy a pool slot under a
        // bogus key until its handshake deadline matured. Treat it as the dial
        // failure it is.
        if (socket && !socket->status())
        {
            const NetService dead = socket->get_addr();
            LOG_DEBUG_COIND << "[" << m_chain_label
                            << "] connected() on an already-dead socket ("
                            << dead.to_string() << ") — treating as dial failure";
            connect_failed(dead);
            return;
        }
        const NetService addr = socket ? socket->get_addr() : NetService{};
        attach_peer(std::move(socket), addr);
    }

    void disconnect() override
    {
        m_primary = nullptr;
        m_active = nullptr;
        m_pool.clear();
    }

    // #940: INetwork hook — an outbound dial failed BEFORE the socket came up
    // (ECONNREFUSED / ETIMEDOUT / DNS-resolve error), so connected() never ran
    // and neither did the m_on_peer_connected/disconnected seams. Feed the dead
    // target to the scored peer manager (attempt_count++/backoff + score drop)
    // so the dial plan rotates onto a fresh target. The 30s reconnect loop
    // (arm_reconnect_timer) already handles the actual redial; this only reports
    // the failure for scoring, so no dial is issued here (no retry-storm).
    void connect_failed(const NetService& addr) override
    {
        LOG_DEBUG_COIND << "[" << m_chain_label << "] dial failed to "
                        << addr.to_string() << " — feeding peer scorer";
        if (m_on_dial_failed)
            m_on_dial_failed(addr);
    }

    /// Whether AT LEAST ONE peer has completed version/verack and is therefore
    /// answerable. This is the gate the won-block relay and the E5 readiness
    /// poll ride: with a pool, "ready" means some peer can carry the block,
    /// which is exactly the single-peer meaning generalised.
    bool is_handshake_complete() const { return m_primary != nullptr; }
    bool is_connected() const { return !m_pool.empty(); }

    // ── pool observability (the MEASUREMENT surface) ─────────────────────
    /// Sockets currently held (handshaked or still negotiating).
    std::size_t connected_peer_count() const { return m_pool.size(); }
    /// Peers past version/verack — the ones that can actually deliver an inv.
    std::size_t handshaked_peer_count() const
    {
        std::size_t n = 0;
        for (const auto& p : m_pool) if (p->handshake.complete()) ++n;
        return n;
    }
    /// Outbound dials issued and not yet resolved.
    std::size_t dialing_count() const { return m_dialing.size(); }
    std::vector<std::string> dialing_keys() const
    {
        std::vector<std::string> out;
        out.reserve(m_dialing.size());
        for (const auto& kv : m_dialing) out.push_back(kv.first);
        return out;
    }
    /// Total messages written across the pool this process — the direct read on
    /// whether the inv fan-in actually collapsed.
    uint64_t total_msgs_sent() const
    {
        uint64_t n = 0;
        for (const auto& p : m_pool) n += p->msgs_sent;
        return n;
    }
    /// Distinct remote endpoints in the pool. Equals connected_peer_count()
    /// unless a duplicate address slipped in — which is what makes it worth
    /// publishing separately: "3 connections, 1 address" is the failure the
    /// single-peer rotation produced for 9h and nothing named it.
    std::size_t distinct_peer_addresses() const
    {
        std::set<std::string> keys;
        for (const auto& p : m_pool) keys.insert(p->key);
        return keys.size();
    }
    std::vector<std::string> connected_peer_keys() const
    {
        std::vector<std::string> out;
        out.reserve(m_pool.size());
        for (const auto& p : m_pool) out.push_back(p->key);
        return out;
    }
    /// Per-peer connection age in seconds, in pool order — durability, direct.
    std::vector<int64_t> peer_ages_sec() const
    {
        std::vector<int64_t> out;
        out.reserve(m_pool.size());
        for (const auto& p : m_pool) out.push_back(p->age_sec());
        return out;
    }
    uint64_t sessions_started() const { return m_sessions_started; }
    uint64_t sessions_lost() const { return m_sessions_lost; }
    const InvDedup& inv_dedup() const { return m_inv_dedup; }
    /// Both dedup bounds are configurable (capacity floored at 1, TTL > 0).
    void configure_inv_dedup(std::size_t capacity, int64_t ttl_sec)
    {
        m_inv_dedup.configure(capacity, ttl_sec);
    }

    /// Active-spork map + listener counters (assume-active seed + verified
    /// refinements). Read-only: nothing outside the spork handler mutates it.
    const SporkState& spork_state() const { return m_spork_state; }
    nlohmann::json spork_json() const { return m_spork_state.to_json(now_sec()); }

    /// TEST-ONLY: swap the spork verification key ID so KATs can exercise the
    /// accept path with a synthetic signer. Production always verifies against
    /// the hardcoded mainnet spork key (chainparams vSporkAddresses[0]).
    void set_spork_pubkey_id_for_test(const std::array<uint8_t, 20>& key_id)
    {
        m_spork_pubkey_id = key_id;
    }

    /// The peer the single-peer-shaped accessors below describe: the PRIMARY
    /// when one exists, otherwise the oldest connected peer (the pre-verack
    /// window). nullptr only when the pool is empty.
    const PeerSession* described() const
    {
        if (m_primary) return m_primary;
        return m_pool.empty() ? nullptr : m_pool.front().get();
    }

    /// Peer metadata accessors. These describe the PRIMARY peer — the one the
    /// request/response legs are bound to — which is the peer the single-peer
    /// callers of these accessors were always describing. Before any peer has
    /// completed its handshake they describe the OLDEST connected peer, so the
    /// pre-verack window (version seen, verack pending) reports exactly what the
    /// single-peer client reported there. Empty/zero when the pool is empty.
    uint64_t peer_services() const { auto* p = described(); return p ? p->services : 0; }
    uint32_t peer_version() const { auto* p = described(); return p ? p->version : 0; }
    const std::string& peer_subver() const {
        static const std::string empty;
        auto* p = described();
        return p ? p->subver : empty;
    }
    /// Stable identity of the primary peer (addr:port) — the R5
    /// govsync-completeness tracker keys peer coverage on this. Empty when no
    /// peer is connected.
    std::string peer_key() const {
        auto* p = described();
        return p ? p->key : std::string();
    }
    uint32_t peer_start_height() const {
        auto* p = described(); return p ? p->start_height : 0;
    }
    /// Best height advertised by ANY peer in the pool (monotone). The pool's
    /// honest answer to "how far behind are we" — a single lagging member
    /// cannot walk it backwards.
    uint32_t best_peer_height() const { return m_best_peer_height; }
    const std::string& chain_label() const { return m_chain_label; }
    int64_t peer_uptime_sec() const {
        auto* p = described(); return p ? p->age_sec() : 0;
    }

    // ── keepalive observability ──────────────────────────────────────────
    /// Whether the ping we sent to the PRIMARY is still waiting for its pong.
    /// Deliberately names ONE peer: the nonce and the deadline are per-session,
    /// and "is a ping outstanding" has no pool-wide meaning. Use
    /// peer_session(key)->liveness for any other peer.
    bool ping_outstanding() const {
        auto* p = described();
        return p && p->liveness.ping_outstanding();
    }
    /// Pings sent / pongs matched ACROSS THE POOL, including the tallies of
    /// sessions already retired. Aggregated (and retained past a drop) because
    /// a per-session counter would read zero the moment the peer it described
    /// was reaped — which is exactly when the number is worth having.
    uint64_t pings_sent() const {
        uint64_t n = m_retired_pings_sent;
        for (const auto& p : m_pool) n += p->liveness.pings_sent();
        return n;
    }
    uint64_t pongs_matched() const {
        uint64_t n = m_retired_pongs_matched;
        for (const auto& p : m_pool) n += p->liveness.pongs_matched();
        return n;
    }
    /// Nonce of the primary's most recent ping (0 before the first one).
    uint64_t last_ping_nonce() const {
        auto* p = described();
        return p ? p->liveness.ping_nonce() : 0;
    }
    time_t ping_interval_sec() const { return m_ping_interval_sec; }
    time_t peer_timeout_sec() const { return m_peer_timeout_sec; }

    /// Same keepalive observability for ANY peer, by endpoint key. The pool
    /// KATs need to assert that peer A's pong did NOT close peer B's ping.
    const PeerSession* peer_session(const std::string& key) const
    {
        for (const auto& p : m_pool) if (p->key == key) return p.get();
        return nullptr;
    }

    /// TEST-ONLY: scale the keepalive cadence so the liveness policy can be
    /// driven in seconds of real time rather than minutes. Production never
    /// calls this — the defaults are PING_INTERVAL_SEC / PEER_TIMEOUT_SEC /
    /// POOL_TICK_SEC. The values are stored on the CLIENT and stamped onto
    /// every PeerSession at attach, so a peer that joins later gets the same
    /// scaled cadence; each peer still evaluates its OWN copy.
    void set_keepalive_for_test(time_t ping_interval_sec, time_t peer_timeout_sec,
                                time_t tick_sec)
    {
        if (ping_interval_sec > 0) m_ping_interval_sec = ping_interval_sec;
        if (peer_timeout_sec > 0)  m_peer_timeout_sec = peer_timeout_sec;
        if (tick_sec > 0) m_pool_tick_sec = tick_sec;
        for (auto& p : m_pool)
            p->liveness.configure(m_ping_interval_sec, m_peer_timeout_sec);
    }

    /// Override the time source every deadline is measured against (default:
    /// the steady clock).
    ///
    /// WHY THIS SEAM EXISTS. Every deadline here — handshake, ping interval,
    /// unanswered-ping drop, dial-slot reclamation — is a comparison against
    /// now_sec(). A test that instead measures ELAPSED REAL MILLISECONDS is
    /// racing the machine: under AddressSanitizer the binary runs 2-10x slower,
    /// and an assertion like `elapsed >= 3000` loses that race by a millisecond
    /// on a loaded runner. Worse, a test with slop widened to absorb that can no
    /// longer tell "the deadline logic regressed" from "the runner was busy" —
    /// it becomes a check that cannot fail.
    ///
    /// So the tests drive SIMULATED seconds through this seam and assert on the
    /// resulting DECISIONS (ping sent at exactly T+120, peer dropped at exactly
    /// T+1200), which is what the policy actually promises. That is
    /// deterministic under any sanitizer and any load, and it still fails for
    /// the right reason if the policy changes. It also lets the tests assert
    /// against the SHIPPED constants (120s/1200s) rather than scaled stand-ins,
    /// because simulated hours are free.
    void set_now_fn(std::function<int64_t()> fn)
    {
        if (fn) m_now_fn = std::move(fn);
    }

    /// TEST-ONLY: run ONE pool tick synchronously, exactly as the repeating
    /// pool timer would. Paired with set_now_fn this replaces the io_context
    /// entirely for policy tests — no real timer, no real waiting, no race.
    void tick_for_test() { on_pool_tick(); }
    /// Test-only: simulate the block handler having consumed every tracked
    /// tip body (the ONLY in-tree place m_pending_bodies is erased), so a KAT
    /// can drive the body-busy -> body-clear transition drain_tx_retry_busy
    /// keys on without constructing a hash-matched block body.
    void clear_pending_bodies_for_test() { m_pending_bodies.clear(); }

    /// TEST-ONLY: exercise the bulk/historical body peer SELECTION directly
    /// (announcer-less path), returning the chosen peer's key — the seam the
    /// CanServeBlocks/demotion KATs assert convergence on.
    std::string select_bulk_peer_key_for_test(const uint256& hash)
    { PeerSession* p = select_block_peer(hash); return p ? p->key : std::string{}; }
    /// TEST-ONLY: current non-server strike count for a peer address.
    int bulk_nonserver_strikes_for_test(const std::string& key) const
    { auto it = m_bulk_nonserver_strikes.find(key); return it == m_bulk_nonserver_strikes.end() ? 0 : it->second; }
    /// TEST-ONLY: is this peer currently demoted out of bulk selection?
    bool bulk_demoted_for_test(const std::string& key) const { return bulk_demoted(key); }
    /// TEST-ONLY: clear a peer's non-server strike (the forgiveness a real
    /// body delivery triggers on the ingest path).
    void forgive_bulk_nonserver_for_test(const std::string& key) { forgive_bulk_nonserver(key); }
    /// TEST-ONLY: record a non-server strike directly (stands in for the live
    /// NOTFOUND/stall path the archival-rotation KATs demote a peer through).
    void note_bulk_nonserver_for_test(const std::string& key) { note_bulk_nonserver(key); }
    // ── archival outbound-rotation pump — test seams ──────────────────────
    /// TEST-ONLY: master switch. Default ON; OFF restores the byte-identical
    /// pre-port frozen-full-pool behaviour (the RED arm of the acquisition KATs).
    void set_outbound_rotate_enabled_for_test(bool on) { m_outbound_rotate_enabled = on; }
    /// PR-3: arm the LOW-RATE proactive rotation (--embedded-proactive-rotate).
    /// Default OFF => byte-identical to master (stall-only rotation).
    void set_proactive_rotate_enabled(bool on) { m_proactive_rotate_enabled = on; }
    void set_proactive_rotate_enabled_for_test(bool on) { m_proactive_rotate_enabled = on; }
    uint64_t proactive_rotations_for_test() const { return m_proactive_rotations; }
    /// TEST-ONLY: the dashd GetExtraFullOutboundCount-raised effective target.
    std::size_t effective_max_peers_for_test() const { return effective_max_peers(); }
    /// TEST-ONLY: behind on archival coverage (a demoted non-server holds a slot)?
    bool outbound_behind_for_test() const { return outbound_behind(); }
    /// TEST-ONLY: how many demoted slot-holders have been rotated out for a
    /// fresh archival dial.
    uint64_t outbound_rotations_for_test() const { return m_outbound_rotations; }
    /// TEST-ONLY: exercise the STATEFUL (getmnlistd fold) carrier selection —
    /// the seam the rotate-on-timeout KAT asserts fans out on. Returns the
    /// chosen peer key and records it as the last stateful carrier, exactly as
    /// send_getmnlistd_rotating() does on the wire, so repeated calls rotate.
    std::string select_stateful_peer_key_for_test()
    { PeerSession* p = next_stateful_peer(); if (p) m_last_stateful_peer = p->key; return p ? p->key : std::string{}; }

    /// TEST-ONLY: stand a peer session up with a synthetic endpoint and NO
    /// socket, the way Factory does on a live connect. A null socket is legal
    /// for the Connection leaf (write() no-ops), so everything above the socket
    /// — demux, per-peer state, liveness, primary election — is the real code.
    /// The explicit address is what makes a MULTI-peer rig possible at all:
    /// without it every socketless peer would key to the same ":0".
    void attach_peer_for_test(const NetService& addr)
    {
        attach_peer(nullptr, addr);
    }

    // ── E2+ seams ────────────────────────────────────────────────────────
    /// addr-message peer discovery feed.
    void set_addr_callback(AddrCallback cb) { m_addr_callback = std::move(cb); }
    /// Peer's reported chain height (from its version message).
    void set_on_peer_height(PeerHeightCallback cb) { m_on_peer_height = std::move(cb); }
    /// Fired once per session when the version/verack handshake completes —
    /// the hook E2 uses to kick the initial getheaders/mnlistdiff sync.
    void set_on_handshake_complete(HandshakeCallback cb) { m_on_handshake_complete = std::move(cb); }
    /// Register ONE historical-mnlistdiff consumer. Additive, not a slot: the
    /// Phase-L member source and the MN-checkpoint lane both source historical
    /// snapshots off this client and both must be offered every reply.
    void add_historical_mnlistdiff_filter(MnListDiffFilter f)
    {
        m_historical_mnlistdiff_demux.add_filter(std::move(f));
    }
    size_t historical_mnlistdiff_filter_count() const
    {
        return m_historical_mnlistdiff_demux.filter_count();
    }
    /// Register a DIP-24 qrinfo consumer (additive, same rationale as above).
    void add_qrinfo_consumer(QrInfoConsumer c)
    {
        m_qrinfo_consumers.push_back(std::move(c));
    }
    size_t qrinfo_consumer_count() const { return m_qrinfo_consumers.size(); }
    // ── W2 replay bulk-fetch seams (see the member-block rationale) ──────
    /// Register the backfill headers demux (single slot: exactly one bulk
    /// lane exists per client; --replay-bulk wiring only).
    void set_headers_filter(HeadersFilter f) { m_headers_filter = std::move(f); }
    /// Register the bulk block-body demux (single slot, same rationale).
    void set_block_body_filter(BlockBodyFilter f) { m_block_body_filter = std::move(f); }
    /// Fired for every notfound(block) inv AFTER the reply matchers complete
    /// (tip-lane semantics unchanged); the bulk lane requeues off this.
    void set_on_block_notfound(BlockNotFoundCallback cb) { m_on_block_notfound = std::move(cb); }

    /// Handshaked peer keys, pool order — the bulk scheduler's peer universe.
    std::vector<std::string> handshaked_peer_keys() const
    {
        std::vector<std::string> out;
        out.reserve(m_pool.size());
        for (const auto& p : m_pool)
            if (p->handshake.complete()) out.push_back(p->key);
        return out;
    }
    /// The PRIMARY's key ("" when none) — the peer the bulk lane must NOT
    /// load while any other handshaked peer exists (it carries every
    /// request/response leg).
    std::string primary_peer_key() const
    {
        return m_primary ? m_primary->key : std::string{};
    }

    /// The bulk lane's peer universe FILTERED through dashd CanServeBlocks
    /// (#1254 bulk_eligible: handshaked + advertises full-block service + not
    /// demoted). The replay BulkFetchLane wires this as its eligible_peers seam
    /// so a deep-history getdata is only ever handed to an archival deliverer —
    /// the reactive stall-demote + this proactive service-bit filter are dashd
    /// net_processing's two halves of the block-download peer policy. Liveness
    /// fallback: if the CanServeBlocks filter empties the set (a transient
    /// all-pruned/all-demoted pool), fall back to the raw handshaked set so the
    /// lane never freezes — the same Pass-0/Pass-1 shape as next_bulk_peer().
    /// A REMOTE primary is excluded unless it is the only survivor (priority
    /// invariant 1); a pinned PROTECTED-LOCAL primary is KEPT (see #154 below).
    std::vector<std::string> eligible_bulk_peer_keys() const
    {
        std::vector<std::string> serving, handshaked;
        for (const auto& up : m_pool)
        {
            const PeerSession* p = up.get();
            if (!p->handshake.complete()) continue;
            handshaked.push_back(p->key);
            if (bulk_eligible(p)) serving.push_back(p->key);
        }
        std::vector<std::string> keys =
            serving.empty() ? std::move(handshaked) : std::move(serving);
        // #154 LEVER 1: priority invariant 1 keeps the bulk lane off the PRIMARY
        // while any other handshaked peer exists — but that invariant exists only
        // to protect the live-tip request/response legs a REMOTE primary carries.
        // A pinned PROTECTED-LOCAL primary (a loopback / LAN archival dashd — the
        // "Protected local dashd node") carries no tip-lane pressure during a
        // historical replay and is the FASTEST bulk deliverer, so it stays
        // bulk-eligible. The pure decision lives in bulkpolicy so this shipped
        // path and the KAT exercise identical logic.
        return bulkpolicy::select_bulk_eligible_keys(
            std::move(keys), primary_peer_key(), primary_is_protected_local());
    }

    /// True when the PRIMARY is a pinned PROTECTED-LOCAL dashd node: its address
    /// classifies as loopback or private-LAN (AddrClass loopback / private_net —
    /// the same local/private class CoinPeerManager::set_local_node pins as the
    /// "Protected local dashd node"). #154: such a primary is kept bulk-eligible;
    /// a REMOTE primary (routable) is still excluded from the bulk lane. No
    /// primary ⇒ false (nothing to protect, nothing to keep).
    bool primary_is_protected_local() const
    {
        if (!m_primary) return false;
        const AddrClass c = classify_address(m_primary->addr.address());
        return c == AddrClass::loopback || c == AddrClass::private_net;
    }

    /// dashd FindNextBlocksToDownload per-(peer,height) coverage for the replay
    /// bulk lane's pump() assignment: the named peer serves blocks at all
    /// (CanServeBlocks), is not demoted, and its announced start_height covers
    /// `height` (peer_covers_height — the lever for a lagging peer that joined
    /// below the wanted band). Unknown/incomplete peer ⇒ false.
    bool bulk_peer_can_serve(const std::string& key, uint32_t height) const
    {
        for (const auto& up : m_pool)
        {
            const PeerSession* p = up.get();
            if (p->key != key) continue;
            return p->handshake.complete()
                   && can_serve_blocks(p)
                   && !bulk_demoted(key)
                   && peer_covers_height(p, height);
        }
        return false;
    }

    /// getheaders to a NAMED peer (bulk header backfill: the walker rotates
    /// its own peer cursor and must not disturb the primary-bound tip legs).
    /// Returns false when the peer is unknown/not handshaked.
    bool send_getheaders_to(const std::string& peer_key, uint32_t version,
                            const std::vector<uint256>& locator,
                            const uint256& stop)
    {
        PeerSession* p = find_peer(peer_key);
        if (!p || !p->handshake.complete()) return false;
        auto msg = message_getheaders::make_raw(version, locator, stop);
        p->write(msg);
        return true;
    }

    /// One getdata(MSG_BLOCK…) carrying `hashes` to a NAMED peer — the bulk
    /// lane's pipelined batch pull. UNTRACKED by the tip-body watchdog by
    /// design: bulk volume would defeat PENDING_BODY_CAP, and the bulk
    /// scheduler owns its own timeout/re-request loop. Returns false when
    /// the peer is unknown/not handshaked (the scheduler's service() pass
    /// then requeues the batch off the live-peer set).
    bool request_blocks_from(const std::string& peer_key,
                             const std::vector<uint256>& hashes)
    {
        if (hashes.empty()) return true;
        PeerSession* p = find_peer(peer_key);
        if (!p || !p->handshake.complete()) return false;
        std::vector<inventory_type> invs;
        invs.reserve(hashes.size());
        for (const auto& h : hashes)
            invs.emplace_back(inventory_type::block, h);
        auto msg = message_getdata::make_raw(invs);
        p->write(msg);
        return true;
    }

    /// dashd net_processing BLOCK_STALLING_TIMEOUT: force-drop a single named
    /// peer session and redial a replacement NOW. The pre-anchor header-backfill
    /// lane calls this on a peer that received a getheaders but never answered
    /// within the stalling window — dashd disconnects such a peer ('Peer is
    /// stalling block download, disconnecting') instead of leaving the zombie
    /// session occupying a pool slot at max RTO backoff. remove_peer() fires the
    /// disconnect seam + re-elects the primary if needed; refill_pool() redials
    /// from the scored dial plan immediately rather than waiting the 30 s
    /// reconnect tick (which is only the backstop). Returns true iff a session
    /// was actually dropped. A no-op (peer already gone) when the key is stale.
    bool stall_disconnect_and_redial(const std::string& peer_key,
                                     const std::string& reason)
    {
        PeerSession* p = find_peer(peer_key);
        if (!p) return false;
        remove_peer(p, reason);
        refill_pool();   // immediate redial; the 30 s loop is only the backstop
        return true;
    }

    /// Fired on socket connect (before handshake) with the peer endpoint — the
    /// DashCoinPeerManager scores the connect + tracks anchors off this.
    void set_on_peer_connected(PeerLifecycleCallback cb) { m_on_peer_connected = std::move(cb); }
    /// Fired on disconnect/error with the peer endpoint — the DashCoinPeerManager
    /// scores the drop + applies exponential backoff off this.
    void set_on_peer_disconnected(PeerLifecycleCallback cb) { m_on_peer_disconnected = std::move(cb); }
    /// #940: fired when an outbound dial fails before the socket comes up — the
    /// DashCoinPeerManager penalises the dead target so it stops being reselected.
    void set_on_dial_failed(PeerLifecycleCallback cb) { m_on_dial_failed = std::move(cb); }

    // ── request/response legs — PRIMARY-TARGETED ─────────────────────────
    //
    // ROUTING POLICY. Every leg below is a QUESTION whose answer must be
    // matched to the peer that was asked: the ReplyMatcher deferral state lives
    // on that peer's Connection (p2p_connection.hpp), the historical-mnlistdiff
    // demux keys on the reply's own content, and fanning a getmnlistd /
    // getqrinfo / govsync out to N peers would multiply an entire mainnet
    // governance stream by N for no extra evidence. So they all go to the
    // PRIMARY peer, and the reply arrives on the primary's socket, where
    // handle() routes it back to that same session. Non-primary peers are
    // witnesses: they are never asked a stateful question.
    //
    // When the primary is lost, another handshaked peer is promoted and
    // m_on_handshake_complete re-fires — which is exactly the re-ask the
    // single-peer client already performed on every reconnect, so no leg
    // silently loses its driver.

    /// Send a getheaders request (E2 sync driver seam; unused by E1 run_node).
    void send_getheaders(uint32_t version, const std::vector<uint256>& locator, const uint256& stop)
    {
        if (!m_primary) return;
        auto msg = message_getheaders::make_raw(version, locator, stop);
        m_primary->write(msg);
    }

    /// getheaders targeted at the peer that announced `block_hash`. The
    /// tip-follow header pull must reach the peer that HAS the new tip — the
    /// same #1082 announcer!=primary hazard as the body pull: routing it to an
    /// arbitrary (possibly behind/wedged) primary is exactly why the warm-node
    /// header tip could stall while a neighbour was announcing past it. Falls
    /// back to the primary via block_source().
    void send_getheaders_from_block_source(const uint256& block_hash,
                                           uint32_t version,
                                           const std::vector<uint256>& locator,
                                           const uint256& stop)
    {
        PeerSession* p = block_source(block_hash);
        if (!p) return;
        auto msg = message_getheaders::make_raw(version, locator, stop);
        p->write(msg);
    }

    /// Send getaddr to request peer addresses (feeds set_addr_callback).
    ///
    /// BROADCAST, deliberately: an addr reply carries no per-peer matching
    /// state, and address breadth is what refills the pool after a loss. Each
    /// peer answers with its own view, so asking all of them is strictly more
    /// discovery for one small message per peer. (Newly-handshaked non-primary
    /// peers are also asked once automatically — see the verack handler.)
    void send_getaddr()
    {
        for (auto& p : m_pool) {
            if (!p->handshake.complete()) continue;
            auto msg = message_getaddr::make_raw();
            p->write(msg);
        }
    }

    /// Request the peer's mempool inventory (E2a initial-sync seam). The peer
    /// replies with inv(MSG_TX,...) announcements; our inv handler currently
    /// only pulls block invs (tx pull is relay-driven), so this primes the
    /// relay feed — mempool contents are OPTIONAL for embedded-template
    /// viability (an empty mempool still yields a valid coinbase-only template),
    /// so this never gates populate; it only enriches the assembled template.
    void send_mempool()
    {
        if (!m_primary) return;
        auto msg = message_mempool::make_raw();
        m_primary->write(msg);
    }

    /// Arm the MSG_TX pull (phase-1 mempool ingest). OFF by default: turning it
    /// on changes what this node asks its peers for, so it is an explicit
    /// operator decision (--embedded-mempool-ingest), not a side effect of
    /// running a newer build. `cap` bounds outstanding tx getdata.
    void set_tx_pull(bool on, size_t cap = 64)
    {
        m_tx_pull_enabled      = on;
        m_tx_pull_inflight_cap = cap ? cap : 1;
        if (!on) m_tx_pull_inflight.clear();
    }
    bool tx_pull_enabled() const { return m_tx_pull_enabled; }

    /// Arm the BLS-verified isdlock lane (new_isdlock → maintainer BLS gate →
    /// G4 conflict-tx-lock adoption). OFF by default: an explicit operator
    /// decision (--embedded-ingest-isdlock), not a side effect of a newer
    /// build. The MSG_ISDLOCK getdata is NOT gated by this flag — the #1230
    /// fee-only-safe new_islock feed pulls unconditionally; OFF only means
    /// the handler never fires new_isdlock, so the verified adoption path
    /// stays dormant.
    void set_isdlock_pull(bool on) { m_isdlock_pull_enabled = on; }
    bool isdlock_pull_enabled() const { return m_isdlock_pull_enabled; }

    /// Arm the DSTX (CoinJoin broadcast tx) lane (--embedded-ingest-dstx).
    /// OFF by default: an explicit operator decision. Unlike isdlock this
    /// gates the GETDATA itself — no fee-only-safe unconditional consumer
    /// exists for a DSTX, so off-flag no inv(MSG_DSTX=16) ever earns a
    /// request and the wire is byte-identical to master.
    void set_dstx_pull(bool on) { m_dstx_pull_enabled = on; }
    bool dstx_pull_enabled() const { return m_dstx_pull_enabled; }

    /// One greppable line: what the ingest lane asked for and what it got.
    /// received < pull_sent is normal (notfound, races, peers that drop);
    /// received == 0 with pull_sent > 0 for a sustained period is the
    /// signature of a peer set that will not serve us transactions.
    std::string tx_ingest_status() const
    {
        return "[MEMPOOL-INGEST] tx_inv_offered=" + std::to_string(m_tx_inv_offered)
             + " tx_inv=" + std::to_string(m_tx_inv_seen)
             + " getdata=" + std::to_string(m_tx_pull_sent)
             + " received=" + std::to_string(m_tx_received)
             + " inflight=" + std::to_string(m_tx_pull_inflight.size())
             + "/" + std::to_string(m_tx_pull_inflight_cap)
             + " skipped(budget)=" + std::to_string(m_tx_pull_skipped_budget)
             + " skipped(tip-body-busy)=" + std::to_string(m_tx_pull_skipped_busy)
             + " expired=" + std::to_string(m_tx_pull_expired)
             + " retry(parked/drained)=" + std::to_string(m_tx_retry_requeued)
             + "/" + std::to_string(m_tx_retry_drained)
             + " dstx_inv=" + std::to_string(m_dstx_inv_seen)
             + " dstx_getdata=" + std::to_string(m_dstx_pull_sent)
             + " dstx_received=" + std::to_string(m_dstx_received);
    }
    uint64_t tx_received_count() const { return m_tx_received; }
    size_t   tx_pull_inflight()  const { return m_tx_pull_inflight.size(); }
    uint64_t tx_pull_sent_count()        const { return m_tx_pull_sent; }
    uint64_t tx_pull_skipped_busy_count()const { return m_tx_pull_skipped_busy; }
    size_t   tx_retry_busy_count()       const { return m_tx_retry_busy.size(); }
    uint64_t tx_retry_requeued_count()   const { return m_tx_retry_requeued; }
    uint64_t tx_retry_drained_count()    const { return m_tx_retry_drained; }
    uint64_t dstx_inv_seen_count()       const { return m_dstx_inv_seen; }
    uint64_t dstx_pull_sent_count()      const { return m_dstx_pull_sent; }
    uint64_t dstx_received_count()       const { return m_dstx_received; }

    /// Request a full block via plain MSG_BLOCK getdata (E2 pull seam).
    /// Routed to the peer that ANNOUNCED this block (block_source), which holds
    /// it by definition; falls back to the primary when the announcer is
    /// unknown (bulk/historical legs) or has churned out.
    ///
    /// Returns TRUE when the getdata was written to a peer; FALSE when there
    /// is no route at all (announcer unknown/churned AND no primary) — the
    /// request then died locally and NO peer will ever answer it. #138: a
    /// caller that keeps a request ledger (MnCheckpointLane::request_window)
    /// must not count a false return as requested, or a dropped tip-body
    /// fetch is never re-asked and the reseed bridge wedges. Callers with
    /// their own re-request loops may keep ignoring the return value.
    bool request_block(const uint256& block_hash)
    {
        // Announcer for a tip body; round-robin across the handshaked pool for
        // a bulk/historical body (dashd IBD spread). select_block_peer records
        // the chosen peer for the watchdog.
        PeerSession* p = select_block_peer(block_hash);
        if (!p) return false;
        auto msg = message_getdata::make_raw(
            {inventory_type(inventory_type::block, block_hash)});
        p->write(msg);
        // PR-0 instrumentation (record-only): stamp the tip/body getdata on the
        // chosen carrier so the block reply can be timed. Pure telemetry.
        p->note_request_sent(DatumClass::TipBody, arrival_now_ms());
        return true;
    }

    /// Request a full block AND arm the lost-body watchdog for it (tip-follow
    /// path — see the BODY_REREQUEST_* rationale above). Plain
    /// request_block() stays untracked for the bulk/historical legs (UTXO
    /// window refill, checkpoint-lane bulk windows), whose volume would defeat
    /// the bound and whose own re-request loops already exist.
    ///
    /// #138: returns request_block()'s truth — TRUE only when the initial
    /// getdata reached a peer — so a ledger-keeping caller
    /// (MnCheckpointLane::request_window) can refuse to count a dead send.
    /// The watchdog slot is armed EITHER WAY: the locally-dead request (no
    /// announcer, no primary) is precisely the one that needs the retry most,
    /// and service_pending_bodies() puts it on the wire against the WHOLE
    /// pool as soon as a handshaked peer exists. A dead send leaves last_req
    /// at 0 so that first watchdog attempt is immediate, not 10 s late; a
    /// dead RE-ask of an existing slot leaves last_req alone so a caller's
    /// pump cadence can never push the watchdog's own timer out.
    bool request_block_tracked(const uint256& block_hash)
    {
        const bool sent = request_block(block_hash);
        const int64_t now = now_sec();
        for (auto& pb : m_pending_bodies)
            if (pb.hash == block_hash) {
                if (sent) pb.last_req = now;
                return sent;
            }
        if (m_pending_bodies.size() >= effective_pending_cap())
            m_pending_bodies.erase(m_pending_bodies.begin());   // oldest slot
        PendingBody pb;
        pb.hash      = block_hash;
        pb.first_req = now;
        pb.last_req  = sent ? now : 0;
        // The peer request_block() just sent the initial getdata to (announcer
        // for a tip body, or the round-robin pool peer for a bulk/historical
        // body). Recorded so the watchdog rotates AWAY from it to a neighbour
        // if it does not answer in time.
        pb.last_peer = m_last_requested_peer;
        m_pending_bodies.push_back(std::move(pb));
        return sent;
    }

    /// Watchdog observability (KATs + POOL-STATUS).
    std::size_t pending_body_count()    const { return m_pending_bodies.size(); }
    uint64_t body_rerequests_total()    const { return m_body_rerequests_total; }
    uint64_t body_stall_evictions()     const { return m_body_stall_evictions; }

    /// Send a getmnlistd (SML diff request) — E2/E3 masternode-list sync seam.
    ///
    /// OBSERVABILITY (2026-08-06). This used to return SILENTLY when there was
    /// no primary peer, and logged nothing on the way out either. That made a
    /// whole class of stall undiagnosable: when the hotel node's SML sat behind
    /// the tip for 156 s there was no way to tell from the log whether the
    /// request had been sent and gone unanswered, or had never been sent at
    /// all. Those two have completely different fixes, and the absence of this
    /// one line is what made the question unanswerable.
    ///
    /// Full hashes, not a prefix: at mainnet difficulty the leading ~14 nibbles
    /// of a block hash are difficulty padding and carry no information, and
    /// this line fires about once per tip so it can afford the bytes.
    void send_getmnlistd(const uint256& base_block_hash, const uint256& block_hash)
    {
        if (!m_primary) {
            LOG_WARNING << "[COIN-P2P] getmnlistd DROPPED (no primary peer):"
                        << " base=" << base_block_hash.GetHex()
                        << " target=" << block_hash.GetHex()
                        << " — the SML cannot advance until a peer is up";
            return;
        }
        LOG_INFO << "[COIN-P2P] getmnlistd -> base=" << base_block_hash.GetHex()
                 << " target=" << block_hash.GetHex();
        auto msg = message_getmnlistd::make_raw(base_block_hash, block_hash);
        m_primary->write(msg);
    }

    /// Fold-snapshot variant of send_getmnlistd that ROTATES its carrier across
    /// the eligible pool (next_stateful_peer) instead of pinning to m_primary.
    /// The mn-checkpoint anchor->tip fold's deep base->anchor snapshot is the
    /// stateful leg that froze a cold soak for 26 min behind a single slow
    /// primary (LANE-WATCHDOG waiting_for=fold-mnlist-reply, re-asking the SAME
    /// primary). The reply is matched by block hash and only one getmnlistd is
    /// ever outstanding, so a reply from ANY carrier satisfies the same await —
    /// rotating the carrier is safe, and is exactly dashd's rotate-on-stall
    /// sync-peer behaviour. Reward-safe: this changes WHICH peer is asked, never
    /// the served MN-payee/quorum-root bytes (those stay DIP-4 client-verified
    /// against the block's own cbTx commitment before they are believed).
    void send_getmnlistd_rotating(const uint256& base_block_hash,
                                  const uint256& block_hash)
    {
        PeerSession* p = next_stateful_peer();
        if (!p) {
            LOG_WARNING << "[COIN-P2P] getmnlistd(rotating) DROPPED (no peer):"
                        << " base=" << base_block_hash.GetHex()
                        << " target=" << block_hash.GetHex()
                        << " — the fold cannot advance until a peer is up";
            return;
        }
        m_last_stateful_peer = p->key;
        LOG_INFO << "[COIN-P2P] getmnlistd(rotating) -> peer=" << p->key
                 << " base=" << base_block_hash.GetHex()
                 << " target=" << block_hash.GetHex();
        auto msg = message_getmnlistd::make_raw(base_block_hash, block_hash);
        p->write(msg);
        // PR-0 instrumentation (record-only): stamp the mnlistdiff ask on this
        // carrier so the matching reply can be timed. Pure telemetry.
        p->note_request_sent(DatumClass::MnListDiff, arrival_now_ms());
    }

    /// TIMEOUT RE-ASK of the STATEFUL getmnlistd leg — the recovery half of
    /// dashd's rotate-on-stall sync-peer behaviour, fired when the carrier we
    /// last asked did not answer in time (the tip-follow SmlResyncWatchdog
    /// re-request, or the mn-checkpoint fold's tick_pending_fold re-ask). Two
    /// things happen, and the live A/B (wf w8cr3yepg) proved BOTH were missing
    /// on this leg — it pinned every ask AND every re-ask to one primary:
    ///
    ///   (B) ROTATE — send_getmnlistd_rotating() picks a DIFFERENT eligible
    ///       archival carrier (next_stateful_peer avoids m_last_stateful_peer
    ///       and prefers CanServeBlocks/NODE_NETWORK), so a slow/limited peer
    ///       cannot wedge the fold by being re-asked forever.
    ///
    ///   (A) DEMOTE — strike the carrier that just stalled us as a demonstrated
    ///       non-server, in the SAME bulk-demotion tally the block-body lane
    ///       feeds. This is what makes the acquisition pump SEE a getmnlistd
    ///       stall: outbound_behind() then reads a demoted slot-holder, the
    ///       effective dial target expands (GetExtraFullOutboundCount) and
    ///       refill/rotate pulls in MORE fresh archival peers to reach one that
    ///       actually serves. Without it "behind" was blind to everything but
    ///       block bodies, so a getmnlistd-dominated near-tip window kept the
    ///       pool frozen at its base size even while a slow primary starved the
    ///       SML — exactly the EXPANSION-never-engaged half of the finding.
    ///
    /// Reward-safe: this changes only WHICH peer is asked and HOW MANY we dial.
    /// Exactly one getmnlistd is outstanding, so a reply from ANY carrier
    /// satisfies the same await; the served MN-payee/quorum-root bytes are
    /// still DIP-4 client-verified against the block's own cbTx commitment
    /// before they are believed; and a peer that later delivers a body clears
    /// its strike (forgive_bulk_nonserver on the ingest path).
    // PR-2 FRESH-DATUM RACE (flag/K default-OFF). Project the live pool into
    // ranked RaceCandidates for a datum class: only CanServeBlocks + handshaked
    // + non-demoted carriers are eligible (the SAME gate the stateful/bulk
    // selectors apply), scored so a lower measured delivery-latency EWMA (PR-0)
    // ranks higher and an unmeasured peer sits neutral (so it still gets raced
    // and gathers a measurement). Pure projection — no socket is touched here.
    std::vector<dash::coin::RaceCandidate> race_candidates(DatumClass cls) const
    {
        std::vector<dash::coin::RaceCandidate> out;
        out.reserve(m_pool.size());
        for (const auto& up : m_pool) {
            const PeerSession* pp = up.get();
            dash::coin::RaceCandidate c;
            c.key       = pp->key;
            c.netgroup  = dash::coin::peer_network_group(pp->addr.address());
            c.can_serve = can_serve_blocks(pp);
            c.eligible  = pp->handshake.complete() && !bulk_demoted(pp->key);
            const int64_t e = pp->delivery.ewma_ms(cls);
            c.score     = (e < 0) ? 0
                        : (e > 1000000 ? -1000000 : static_cast<int>(1000000 - e));
            out.push_back(std::move(c));
        }
        return out;
    }

    // Fan the SAME idempotent getmnlistd out to the K fastest-scored
    // CanServeBlocks carriers in DISTINCT netgroups and let the first valid
    // self-checked reply win (the lane's on_historical_snapshot dedups the
    // rest). Returns the number of carriers actually asked (0 => caller must
    // fall back to its single-carrier send; racing never REMOVES a request).
    // Reward-safe: this only changes FROM-WHOM and HOW-MANY; every reply still
    // flows through the identical DIP-4/merkle/payee self-check before it is
    // believed, and exactly one fold is licensed.
    int race_getmnlistd(const uint256& base_block_hash, const uint256& block_hash)
    {
        const int width = dash::coin::fresh_datum_race_width();
        if (width <= 1) return 0;   // flag OFF or K==1 -> single carrier (today)
        auto targets = dash::coin::select_race_targets(
            race_candidates(DatumClass::MnListDiff), width);
        if (targets.size() < 2) return 0;   // <2 distinct-group carriers -> today
        int sent = 0;
        for (const auto& key : targets) {
            PeerSession* p = nullptr;
            for (const auto& up : m_pool) if (up->key == key) { p = up.get(); break; }
            if (!p) continue;
            auto msg = message_getmnlistd::make_raw(base_block_hash, block_hash);
            p->write(msg);
            // PR-0 instrumentation (record-only): time each carrier's leg.
            p->note_request_sent(DatumClass::MnListDiff, arrival_now_ms());
            ++sent;
        }
        if (sent > 0)
            LOG_INFO << "[COIN-P2P] getmnlistd(RACE x" << sent << ") -> "
                     << targets.size() << " distinct-netgroup carriers,"
                     << " base=" << base_block_hash.GetHex()
                     << " target=" << block_hash.GetHex()
                     << " — first valid self-checked reply wins, the rest are"
                        " deduped";
        return sent;
    }

    void send_getmnlistd_reask(const uint256& base_block_hash,
                               const uint256& block_hash)
    {
        // (A) the carrier we last asked demonstrably did not answer in time —
        // strike it so the acquisition pump treats it as a slot-holding non-
        // server and expands/rotates the outbound set toward a real server.
        if (!m_last_stateful_peer.empty() && holds_key(m_last_stateful_peer))
            note_bulk_nonserver(m_last_stateful_peer);
        // (B') PR-2: race the re-ask across K distinct-netgroup carriers so a
        // slow winner does not cost a whole wall-clock re-ask interval. Only
        // WHO/HOW-MANY changes; the reply is matched by the unchanged
        // m_snapshot_hash and DIP-4 self-checked before it is folded. Flag OFF
        // or K==1 or <2 carriers => race_getmnlistd() returns 0 and we take the
        // identical single rotating carrier below (byte-identical to master).
        if (race_getmnlistd(base_block_hash, block_hash) > 0) return;
        // (B) rotate to a fresh archival carrier and send (never drops: the
        // rotating send falls back to any handshaked peer, then m_primary).
        send_getmnlistd_rotating(base_block_hash, block_hash);
    }

    /// dashd SetTryNewOutboundPeer for the STATEFUL leg. The mn-ckpt lane's
    /// wall-clock watchdog calls this TRUE while a bridging getmnlistd has been
    /// unanswered past its grace and FALSE once it is served, raising/clearing
    /// the outbound-behind expansion signal so the pool acquires a peer that
    /// will answer instead of pinning at its base target on a silent carrier.
    /// Reward-safe: dial-count only, the applied list is untouched.
    void note_stateful_stall(bool stalled) { m_stateful_stall = stalled; }

    /// Send a getqrinfo (DIP-24 quorum-rotation-info request) — the ROTATED
    /// counterpart of send_getmnlistd above. An EMPTY baseBlockHashes asks for
    /// FULL (base=ZERO) mnlistdiffs at every cycle height, which is what the
    /// member-set port needs: a full list is self-authenticating against its
    /// own cbTx.merkleRootMNList, an incremental one is not.
    void send_getqrinfo(const std::vector<uint256>& base_block_hashes,
                        const uint256& block_request_hash,
                        bool extra_share = false)
    {
        if (!m_primary) return;
        auto msg = message_getqrinfo::make_raw(base_block_hashes,
                                               block_request_hash, extra_share);
        m_primary->write(msg);
        // PR-0 instrumentation (record-only): stamp the qrinfo ask so the reply
        // can be timed. Pure telemetry.
        m_primary->note_request_sent(DatumClass::QrInfo, arrival_now_ms());
    }

    /// Send a govsync (MNGOVERNANCESYNC) — E-SUPERBLOCK governance-object sync
    /// seam. A zero nProp with an EMPTY bloom filter requests ALL governance
    /// objects + votes; the peer streams them back as govobj / govobjvote
    /// messages, which the handlers above forward into the GovernanceStore.
    void send_govsync()
    {
        if (!m_primary) return;
        auto msg = message_govsync::make_raw(
            uint256::ZERO,               // nProp = 0 => request all
            std::vector<uint8_t>{},      // empty filter vData
            /*nHashFuncs=*/0u, /*nTweak=*/0u, /*nFlags=*/uint8_t{0});
        m_primary->write(msg);
    }

    /// Relay a pre-serialized won block as a `block` P2P message (the embedded
    /// P2P-relay arm of the dual-path broadcaster).
    ///
    /// ── RELAY POLICY: BROADCAST TO EVERY HANDSHAKED PEER. ────────────────
    ///
    /// This is the money path, so the policy is stated here and not inferred.
    /// With one peer there was no decision to make. With a pool there is, and
    /// the two failure modes are not symmetric:
    ///
    ///   * relaying the same found block to N peers costs N block-sized sends
    ///     and is, protocol-wise, a NON-EVENT — every node we reach already
    ///     forwards it to its own peers, and a node that already has it simply
    ///     ignores the duplicate. Duplicate submission IS success.
    ///   * relaying to ONE peer that happens to be a slow, forked, or
    ///     half-open link loses the block outright. There is no retry: the
    ///     share is already spent.
    ///
    /// So we deliberately buy redundancy with bandwidth we do not care about,
    /// on the one message per day where it matters. No peer selection, no
    /// "best" peer heuristic, no primary-only shortcut — every peer that has
    /// finished its handshake gets the block.
    ///
    /// Returns the number of peers written to; 0 means the block reached NO
    /// coin-P2P peer and the caller must fall back to the submitblock-RPC arm.
    /// The dual-path broadcaster's NEVER-SILENT-DROP contract depends on that
    /// count being honest, so it is logged either way.
    std::size_t submit_block_p2p_raw(const std::vector<unsigned char>& raw_block)
    {
        std::size_t sent = 0;
        std::string targets;
        for (auto& p : m_pool)
        {
            if (!p->handshake.complete()) continue;
            auto rmsg = std::make_unique<RawMessage>("block", PackStream(raw_block));
            p->write(rmsg);
            if (!targets.empty()) targets += ",";
            targets += p->key;
            ++sent;
        }
        if (sent == 0)
        {
            LOG_ERROR << "[" << m_chain_label << "] no handshaked coin-network peer; "
                         "cannot relay won block over embedded P2P";
            return 0;
        }
        LOG_INFO << "[" << m_chain_label << "] won-block BROADCAST over embedded P2P ("
                 << raw_block.size() << " bytes) to " << sent
                 << " peer[s]: " << targets;
        return sent;
    }

    // ICommunicator
    void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        // Copy — the NetService reference may dangle once the socket is freed.
        NetService svc_copy = service;
        // DEMUX: an error names the socket it came from (core/socket.cpp passes
        // its own m_addr on every error path), so it removes exactly THAT peer.
        // One peer erroring out must never disturb the other seven.
        PeerSession* p = find_peer(svc_copy.to_string());
        if (!p)
        {
            // Already removed (double-fire race), or an error for a socket we
            // never attached. Safe to ignore — but say so, because silently
            // swallowing it is how a leaked pool slot would hide.
            LOG_DEBUG_COIND << "[" << m_chain_label << "] error for unknown peer "
                            << svc_copy.to_string() << ": " << err
                            << " (already removed?)";
            return;
        }
        remove_peer(p, err);
    }

    void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        error(parse_net_error(ec), service, where);
    }

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        // ── INBOUND DEMUX ────────────────────────────────────────────────
        // core/socket.cpp:321 delivers every message tagged with its own
        // socket's m_addr, so the peer this message came from is known exactly.
        // m_active is that peer for the duration of the dispatch: every handler
        // that WRITES (verack, pong, getdata-for-inv) writes back to the peer
        // that spoke, and every handler that completes a ReplyMatcher completes
        // it on the Connection that was asked. A message from a socket we do
        // not hold is dropped rather than misattributed.
        PeerSession* peer = find_peer(service.to_string());
        if (!peer)
        {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] message from unattached peer "
                            << service.to_string() << " — dropped";
            return;
        }
        m_active = peer;
        // Scope guard: the dispatch below can remove this peer (a handler that
        // errors the socket), and it can throw. m_active must be cleared either
        // way or the next handle() could route through a dangling cursor.
        struct ActiveGuard {
            PeerSession** slot;
            ~ActiveGuard() { *slot = nullptr; }
        } active_guard{&m_active};

        on_activity(*peer);

        // Copy the command BEFORE parse: parse() consumes rmsg, and the guard
        // below has to be able to name what threw.
        const std::string cmd = rmsg ? rmsg->m_command : std::string("<null>");

        p2p::Handler::result_t result;
        try
        {
            result = m_handler.parse(rmsg);
        } catch (const std::runtime_error& ec)
        {
            LOG_ERROR << "[" << m_chain_label << "] handle(" << cmd
                      << ") from " << peer->key << ": " << ec.what();
            return;
        } catch (const std::out_of_range&)
        {
            // Command outside our Handler set — dashd peers push CoinJoin/
            // quorum traffic (senddsq, qsendrecsigs, ...) unsolicited;
            // ignoring them is protocol-legal for a light client.
            // A DROPPED REPLY TO A REQUEST WE SENT is not benign, and this path
            // used to be indistinguishable from it: the DIP-24 rotated lane sent
            // getqrinfo, dashd answered, and the qrinfo landed here because the
            // type was missing from p2p::Handler. At DEBUG nobody ever saw it and
            // the whole lane looked like "nothing happened". So the FIRST drop of
            // each command is a WARNING naming it and its size.
            //
            // PER-PEER, not shared: with a pool the interesting signal is "THIS
            // peer speaks something we do not", and one shared set would let the
            // first peer's vocabulary mask every later peer's — re-hiding exactly
            // what this warning exists to surface. Bounded by (peers x distinct
            // commands), so it still cannot flood; repeats stay at DEBUG.
            if (peer->unhandled_seen.insert(cmd).second) {
                LOG_WARNING << "[" << m_chain_label << "] peer " << peer->key
                            << " DROPPED unhandled p2p command '" << cmd
                            << "' cause=not_in_handler_set value="
                            << (rmsg ? rmsg->m_data.size() : 0) << "B (first occurrence "
                               "for this peer; further drops log at debug). If this is a "
                               "REPLY to something we requested, the requesting lane "
                               "is silently dead — add the type to p2p::Handler.";
            } else {
                LOG_DEBUG_COIND << "[" << m_chain_label << "] ignoring unhandled command '"
                                << cmd << "' from " << peer->key << " ("
                                << (rmsg ? rmsg->m_data.size() : 0) << " bytes)";
            }
            return;
        } catch (const std::exception& ec)
        {
            // Anything else out of the codec (std::length_error / bad_alloc /
            // ios_base::failure variants) — see the dispatch guard below for
            // why NOTHING may escape this function.
            LOG_ERROR << "[" << m_chain_label << "] parse('" << cmd
                      << "') threw: " << ec.what() << " — message dropped";
            return;
        }

        // ── READ-LOOP PRESERVATION GUARD ─────────────────────────────────
        //
        // This function is called from core::Socket::message_processing, and
        // the socket's read loop is re-armed by the line AFTER that call
        // (core/socket.cpp Socket::read_payload: `message_processing(packet);
        // read();`). An exception escaping here therefore unwinds straight
        // past `read()` and out of the asio completion handler — the socket
        // stays OPEN, no error() callback ever fires, and the connection
        // becomes permanently deaf while still looking connected. main_dash's
        // #755 io-handler guard catches the throw at ioc.run() and resumes the
        // loop, so the process survives and the damage is invisible: the ONLY
        // subsequent symptom is this client's own liveness timer firing later
        // on a peer that has actually been silenced by us.
        //
        // Handlers below fan out into subscriber code (new_block /
        // new_mnlistdiff / new_qfcommit / new_chainlock ...) that we do not
        // own, so a throw from any of them must be contained here. A bad
        // message costs that message, never the peer.
        try
        {
            std::visit([&](auto& msg){ handle(std::move(msg)); }, result);
        } catch (const std::exception& ec)
        {
            LOG_ERROR << "[" << m_chain_label << "] handler for '" << cmd
                      << "' threw: " << ec.what()
                      << " — message dropped, peer kept (read loop preserved)";
        } catch (...)
        {
            LOG_ERROR << "[" << m_chain_label << "] handler for '" << cmd
                      << "' threw a non-std exception"
                      << " — message dropped, peer kept (read loop preserved)";
        }
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_p2p.prefix;
    }

private:
    // ── pool membership ──────────────────────────────────────────────────

    PeerSession* find_peer(const std::string& key)
    {
        for (auto& p : m_pool) if (p->key == key) return p.get();
        return nullptr;
    }

    /// Record which peer announced a block, so its body/headers pull can be
    /// routed back to it. Bounded FIFO (block invs arrive ~1 / 2.5 min).
    void record_block_announcer(const uint256& hash, const std::string& key)
    {
        for (auto& a : m_block_announcers)
            if (a.hash == hash) { a.key = key; return; }
        if (m_block_announcers.size() >= ANNOUNCER_CAP)
            m_block_announcers.erase(m_block_announcers.begin());
        m_block_announcers.push_back(BlockAnnouncer{hash, key});
    }

    /// The peer that ANNOUNCED this block (it holds it by definition and its
    /// reply routes back to its own session), or nullptr when no live
    /// handshaked announcer is known — the deep-historical / bulk-fold case,
    /// where the block was buried long before this node connected and was
    /// never inv'd to us. Never returns a stale pointer — resolved live.
    PeerSession* announced_source(const uint256& hash)
    {
        for (auto& a : m_block_announcers)
            if (a.hash == hash)
            {
                PeerSession* p = find_peer(a.key);
                if (p && p->handshake.complete()) return p;
                break;
            }
        return nullptr;
    }

    /// The peer to fetch a block from for the ORDERED, non-bulk legs
    /// (getheaders-before-connect): the announcer, else the primary. Unchanged
    /// from the pre-rotation behaviour so the header/tip legs keep their stable
    /// carrier.
    PeerSession* block_source(const uint256& hash)
    {
        if (PeerSession* a = announced_source(hash)) return a;
        return m_primary;
    }

    /// Round-robin the next handshaked peer for a bulk/historical block-body
    /// getdata. dashd's FindNextBlocksToDownload assigns each needed block to a
    /// peer whose tip covers it and keeps MAX_BLOCKS_IN_TRANSIT_PER_PEER in
    /// flight PER PEER, in parallel across the whole peer set — it never
    /// funnels a deep IBD window at a single peer. For a buried block every
    /// handshaked peer's tip covers it, so we spread the window across them: a
    /// slow / rate-limiting peer then serialises only its 1/N share instead of
    /// wedging the entire anchor->tip fold behind one primary. Falls back to
    /// the primary only when the pool holds no handshaked peer at all.
    // ── dashd CanServeBlocks service-flag classification ─────────────────
    /// A peer advertises full-block (archival) service — dashd NODE_NETWORK.
    static bool advertises_full_blocks(const PeerSession* p)
    { return p && (p->services & NODE_NETWORK); }
    /// dashd IsLimitedPeer: pruned — serves only the last ~288 blocks.
    static bool advertises_limited_only(const PeerSession* p)
    { return p && !(p->services & NODE_NETWORK) && (p->services & NODE_NETWORK_LIMITED); }
    /// dashd CanServeBlocks: serves blocks AT ALL (full or limited).
    static bool can_serve_blocks(const PeerSession* p)
    { return p && (p->services & (NODE_NETWORK | NODE_NETWORK_LIMITED)); }
    /// dashd pindexBestKnownBlock coverage: the peer's announced tip is at or
    /// above the wanted height, so it can be expected to hold that block.
    static bool peer_covers_height(const PeerSession* p, uint32_t height)
    { return p && p->start_height >= height; }

    /// Has this peer been demoted as a demonstrated non-server of deep history?
    bool bulk_demoted(const std::string& key) const
    {
        auto it = m_bulk_nonserver_strikes.find(key);
        return it != m_bulk_nonserver_strikes.end()
               && it->second >= BULK_NONSERVER_STRIKE_MAX;
    }
    void note_bulk_nonserver(const std::string& key)
    { if (!key.empty()) ++m_bulk_nonserver_strikes[key]; }
    void forgive_bulk_nonserver(const std::string& key)
    { if (!key.empty()) m_bulk_nonserver_strikes.erase(key); }

    /// dashd FindNextBlocksToDownload eligibility for a DEEP-historical bulk
    /// body: the peer must have handshaked, advertise full-block service (a
    /// limited/pruned peer cannot serve ~9.5k-deep history), and not be a
    /// demoted non-server. Height coverage is not gated here because the fold
    /// requests span the whole anchor->tip window and every peer's start_height
    /// (its own tip) covers every buried block; peer_covers_height() is the
    /// available lever should a lagging peer ever join.
    bool bulk_eligible(const PeerSession* p) const
    {
        return p && p->handshake.complete()
               && advertises_full_blocks(p)
               && !advertises_limited_only(p)
               && !bulk_demoted(p->key);
    }

    PeerSession* next_bulk_peer()
    {
        const std::size_t n = m_pool.size();
        if (n == 0) return m_primary;
        // Pass 0: dashd CanServeBlocks + per-peer failure demotion — only peers
        // that advertise full-block service AND have not been demoted for
        // chronic non-service. This makes the round-robin CONVERGE onto
        // archival deliverers instead of blindly re-asking pruned/dead peers.
        // Pass 1: any handshaked peer (non-regression — when the reachable set
        // holds no eligible peer we still spread across the pool exactly as
        // #1253 did, rather than wedge on an empty selection; this is the real
        // historical-body-scarcity case where every reachable peer is
        // limited/demoted).
        for (int pass = 0; pass < 2; ++pass)
        {
            for (std::size_t i = 0; i < n; ++i)
            {
                PeerSession* p = m_pool[(m_bulk_rr + i) % n].get();
                if (!p->handshake.complete()) continue;
                if (pass == 0 && !bulk_eligible(p)) continue;
                m_bulk_rr = (m_bulk_rr + i + 1) % n;
                return p;
            }
        }
        return m_primary;
    }

    /// dashd sync-peer selection for the STATEFUL request legs (the
    /// mn-checkpoint fold's getmnlistd snapshot). Round-robin across the
    /// eligible (CanServeBlocks + handshaked + non-demoted) pool, PREFERRING a
    /// peer other than the one the last stateful request went to so a re-ask
    /// actually fans out instead of re-hammering one slow peer (the 26-min
    /// single-primary freeze). Falls back — like next_bulk_peer — to any
    /// eligible peer (first ask / pool of one), then any handshaked peer
    /// (historical-scarcity), then m_primary.
    PeerSession* next_stateful_peer()
    {
        const std::size_t n = m_pool.size();
        if (n == 0) return m_primary;
        for (int pass = 0; pass < 3; ++pass)
        {
            for (std::size_t i = 0; i < n; ++i)
            {
                PeerSession* p = m_pool[(m_stateful_rr + i) % n].get();
                if (!p->handshake.complete()) continue;
                if (pass < 2 && !bulk_eligible(p)) continue;
                if (pass == 0 && p->key == m_last_stateful_peer) continue;
                m_stateful_rr = (m_stateful_rr + i + 1) % n;
                return p;
            }
        }
        return m_primary;
    }

    /// dashd mapBlocksInFlight bound: MAX_BLOCKS_IN_TRANSIT_PER_PEER across
    /// every handshaked peer, floored at PENDING_BODY_CAP so a momentarily
    /// empty pool still keeps the tip-follow slots.
    std::size_t effective_pending_cap() const
    {
        const std::size_t hs = handshaked_peer_count();
        const std::size_t cap = MAX_BLOCKS_IN_TRANSIT_PER_PEER * (hs ? hs : 1);
        return cap > PENDING_BODY_CAP ? cap : PENDING_BODY_CAP;
    }

    /// The peer a plain block-body getdata is sent to: the announcer when one
    /// is live (tip-follow), else round-robin across the pool (bulk/historical
    /// IBD). Records the chosen peer (m_last_requested_peer) so
    /// request_block_tracked() arms the watchdog slot against the peer that was
    /// ACTUALLY asked.
    PeerSession* select_block_peer(const uint256& hash)
    {
        PeerSession* p = announced_source(hash);
        if (!p) p = next_bulk_peer();
        m_last_requested_peer = p ? p->key : std::string{};
        return p;
    }

    bool holds_key(const std::string& key) const
    {
        for (const auto& p : m_pool) if (p->key == key) return true;
        return false;
    }

    bool owns(const PeerSession* p) const
    {
        for (const auto& up : m_pool) if (up.get() == p) return true;
        return false;
    }

    /// Stand a peer session up: own Connection, own handshake tracker, own
    /// liveness policy (stamped with this client's thresholds), own
    /// pre-handshake deadline, own unhandled-command set. Then send OUR version.
    void attach_peer(std::shared_ptr<core::Socket> socket, const NetService& addr)
    {
        const std::string key = addr.to_string();
        // Never hold two sockets to the same endpoint: it would burn a pool
        // slot for zero extra evidence (the same node cannot witness an
        // announcement twice) and would make the demux ambiguous.
        if (holds_key(key))
        {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] already connected to "
                            << key << " — dropping duplicate socket";
            m_dialing.erase(key);
            return;
        }
        if (m_pool.size() >= m_max_peers)
        {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] pool full ("
                            << m_pool.size() << "/" << m_max_peers
                            << ") — dropping late socket from " << key;
            m_dialing.erase(key);
            return;
        }

        auto session = std::make_unique<PeerSession>();
        session->conn = std::make_unique<Connection>(m_context, socket);
        session->addr = addr;
        session->key = key;
        session->liveness.configure(m_ping_interval_sec, m_peer_timeout_sec);
        session->handshake.on_connected();
        // Require version/verack progress soon after connect. Checked on the
        // pool tick against this peer's OWN deadline.
        session->handshake_deadline = now_sec() + CONNECT_TIMEOUT_SEC;
        session->connected_at = std::chrono::steady_clock::now();

        PeerSession* p = session.get();
        m_pool.push_back(std::move(session));
        m_dialing.erase(key);
        ++m_sessions_started;

        LOG_INFO << "[" << m_chain_label << "] connected to " << key
                 << " — sending version (proto " << PROTOCOL_VERSION
                 << "); pool " << m_pool.size() << "/" << m_max_peers;
        if (m_on_peer_connected)
            m_on_peer_connected(addr);

        ensure_pool_timer();

        auto msg_version = message_version::make_raw(
            PROTOCOL_VERSION,
            NODE_NETWORK,
            core::timestamp(),
            addr_t{NODE_NETWORK, addr},
            addr_t{NODE_NETWORK, NetService{"0.0.0.0", MAINNET_P2P_PORT}},
            core::random::random_nonce(),
            "c2pool-dash",
            0
        );
        p->write(msg_version);
    }

    /// Remove ONE peer. Fires the disconnect seam, re-elects the primary if the
    /// peer being removed was it, and leaves every other session untouched.
    void remove_peer(PeerSession* p, const std::string& reason)
    {
        if (!p) return;
        const std::string key = p->key;
        const NetService addr = p->addr;
        const bool was_primary = (p == m_primary);
        const int64_t age = p->age_sec();

        LOG_WARNING << "[" << m_chain_label << "] peer " << key
                    << " disconnected after " << age << "s: " << reason
                    << (was_primary ? " [PRIMARY]" : "")
                    << " — pool " << (m_pool.size() - 1) << "/" << m_max_peers
                    << (m_reconnect_enabled ? " (refill armed)" : "");

        m_retired_pings_sent += p->liveness.pings_sent();
        m_retired_pongs_matched += p->liveness.pongs_matched();

        if (m_active == p) m_active = nullptr;
        if (was_primary) m_primary = nullptr;

        // Erase LAST: the unique_ptr destructor tears the Connection (and its
        // socket) down, so nothing may hold p afterwards.
        for (auto it = m_pool.begin(); it != m_pool.end(); ++it)
        {
            if (it->get() == p) { m_pool.erase(it); break; }
        }
        ++m_sessions_lost;

        if (m_on_peer_disconnected)
            m_on_peer_disconnected(addr);

        // GRACEFUL DEGRADATION: losing a peer — even the primary — never stops
        // the node. The survivors keep delivering, and a survivor takes over
        // the request/response legs.
        if (was_primary)
            elect_primary();
    }

    /// Pick a primary from the handshaked survivors, oldest-first (longest-held
    /// connection is the most proven one), and re-fire the handshake-complete
    /// seam so the sync legs re-ask on their new carrier — the same re-ask the
    /// single-peer client performed on every reconnect.
    void elect_primary()
    {
        if (m_primary) return;
        PeerSession* best = nullptr;
        for (auto& up : m_pool)
        {
            if (!up->handshake.complete()) continue;
            if (!best || up->age_sec() > best->age_sec()) best = up.get();
        }
        if (!best) return;
        promote_primary(best);
    }

    void promote_primary(PeerSession* p)
    {
        m_primary = p;
        p->primary = true;
        LOG_INFO << "[" << m_chain_label << "] PRIMARY peer = " << p->key
                 << " (request/response legs bound here)";
        if (m_on_handshake_complete)
            m_on_handshake_complete();
    }

    // ── dialing / refill ─────────────────────────────────────────────────

    /// Arm the 30s refill loop. The empty-plan guard makes it safe to arm
    /// before any target exists (--coin-p2p-discover cold start): the tick
    /// no-ops until update_dial_targets() supplies seed-discovered peers.
    void arm_reconnect_timer()
    {
        m_reconnect_timer = std::make_unique<core::Timer>(m_context, /*repeat=*/true);
        m_reconnect_timer->start(RECONNECT_INTERVAL_SEC, [this]() {
            refill_pool();
        });
    }

    /// Bring the pool back up to m_max_peers from the scored dial plan.
    ///
    /// The plan itself is produced by CoinPeerManager (score + /16 group
    /// diversity + backoff); this does NOT re-implement selection, it only
    /// decides HOW MANY slots are open and skips targets we already hold or
    /// are already dialing. Rotating with advance() means a dead head of the
    /// plan cannot wedge the refill.
    void refill_pool()
    {
        if (!m_reconnect_enabled || m_dial_plan.empty()) return;
        const int64_t now = now_sec();
        prune_stale_dials(now);
        prune_rotation_cooldown(now);

        // dashd GetExtraFullOutboundCount: while we are behind on archival
        // coverage the effective target is raised, so a full-at-base pool still
        // dials MORE fresh candidates to reach archival servers.
        const std::size_t target = effective_max_peers();
        const std::size_t held = m_pool.size() + m_dialing.size();
        if (held >= target) return;
        std::size_t slots = target - held;

        // One pass over the plan at most: every target is considered exactly
        // once per refill, so a plan shorter than the slot count simply fills
        // fewer slots rather than dialing the same address repeatedly.
        //
        // The pass starts at the CURRENT cursor and rotates from there, so a
        // freshly-set plan is consumed from its FIRST entry — which is the
        // pinned local dashd in the discover posture. (Rotating first would
        // reach the pinned node only after a full lap.) The cursor is left
        // rotated so a later refill does not re-try the same dead head.
        const std::size_t n = m_dial_plan.size();
        std::size_t dialed = 0;
        for (std::size_t i = 0; i < n && slots > 0; ++i)
        {
            const NetService target_addr = m_dial_plan.current();
            m_dial_plan.advance();
            const std::string key = target_addr.to_string();
            if (holds_key(key) || m_dialing.count(key)) continue;
            // Skip an address we just rotated OUT — the addrman-backoff analog
            // that forces refill onto a genuinely fresh candidate.
            if (is_rotation_cooled(key, now)) continue;
            m_dialing[key] = now;
            LOG_INFO << "[" << m_chain_label << "] dialing " << key
                     << " (pool " << m_pool.size() << "/" << m_max_peers
                     << ", " << m_dialing.size() << " in flight)";
            core::Factory<core::Client>::connect(target_addr);
            --slots;
            ++dialed;
        }
        if (dialed == 0 && m_pool.size() < target)
        {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] pool below target ("
                            << m_pool.size() << "/" << target
                            << ") but no fresh dial target in a "
                            << n << "-entry plan";
        }
    }

    // ── archival outbound-rotation pump (dashd acquisition parity) ─────────
    /// Live strike count for an address (0 when unknown). The demotion state
    /// the notfound/stall handlers already feed (note_bulk_nonserver).
    int bulk_strikes(const std::string& key) const
    {
        auto it = m_bulk_nonserver_strikes.find(key);
        return it == m_bulk_nonserver_strikes.end() ? 0 : it->second;
    }

    /// Pool peers that are demonstrated deep-body NON-servers (bulk-demoted for
    /// chronic NOTFOUND / stall). Each holds a download slot dashd would have
    /// freed; while any exist we are "behind" on archival coverage.
    std::size_t pool_demoted_count() const
    {
        std::size_t n = 0;
        for (const auto& up : m_pool)
            if (up->handshake.complete() && bulk_demoted(up->key)) ++n;
        return n;
    }

    /// Behind on archival coverage ⇒ a demonstrated non-server occupies a slot,
    /// OR a bridging getmnlistd (fold / ondemand-mnlist) is stalled unanswered
    /// (dashd opens an extra outbound in BOTH cases). The stall arm is what
    /// makes a frozen ondemand-mnlist expand the pool without waiting for the
    /// carrier to accumulate block-body strikes.
    bool outbound_behind() const
    { return m_outbound_rotate_enabled
             && (pool_demoted_count() > 0 || m_stateful_stall); }

    /// dashd GetExtraFullOutboundCount analog: the dial target, RAISED while we
    /// are behind so refill dials MORE fresh candidates to reach archival
    /// servers (clamped to the hard cap). Base target when not behind, so a
    /// healthy pool is byte-identical to before this port.
    std::size_t effective_max_peers() const
    {
        if (!outbound_behind()) return m_max_peers;
        return std::min<std::size_t>(m_max_peers + OUTBOUND_BEHIND_EXTRA,
                                     POOL_PEERS_HARD_CAP);
    }

    bool is_rotation_cooled(const std::string& key, int64_t now) const
    {
        auto it = m_rotation_cooldown.find(key);
        return it != m_rotation_cooldown.end() && it->second > now;
    }
    void prune_rotation_cooldown(int64_t now)
    {
        for (auto it = m_rotation_cooldown.begin(); it != m_rotation_cooldown.end(); )
            if (it->second <= now) it = m_rotation_cooldown.erase(it);
            else ++it;
    }

    /// Is there a plan entry we could dial RIGHT NOW that we do not already
    /// hold, have in flight, or just rotated out? Without a fresh candidate an
    /// eviction would only re-dial the same non-server, so the pump holds.
    bool has_fresh_dial_candidate(int64_t now) const
    {
        for (const auto& t : m_dial_plan.targets())
        {
            const std::string key = t.to_string();
            if (holds_key(key) || m_dialing.count(key)) continue;
            if (is_rotation_cooled(key, now)) continue;
            return true;
        }
        return false;
    }

    /// The worst demoted slot-holder to rotate out: most strikes first, then
    /// the oldest (longest-latched) session. Skips one still in its own
    /// post-rotation cooldown. nullptr ⇒ nothing eligible to evict.
    PeerSession* worst_demoted_pool_peer(int64_t now) const
    {
        PeerSession* worst = nullptr;
        int worst_strikes = 0;
        for (const auto& up : m_pool)
        {
            PeerSession* p = up.get();
            if (!p->handshake.complete()) continue;
            if (!bulk_demoted(p->key)) continue;
            if (is_rotation_cooled(p->key, now)) continue;
            const int s = bulk_strikes(p->key);
            if (!worst || s > worst_strikes ||
                (s == worst_strikes && p->age_sec() > worst->age_sec()))
            { worst = p; worst_strikes = s; }
        }
        return worst;
    }

    /// dashd's acquisition loop, once per pool tick: keep cycling fresh peers
    /// until the block-download window can fill.
    ///   (1) EXTRA OUTBOUND while behind — refill_pool() already honours the
    ///       raised effective target, so a call here dials more the moment a
    ///       slot is notionally open (GetExtraFullOutboundCount).
    ///   (2) EVICT-THEN-REFILL when the (expanded) pool is FULL yet still holds
    ///       a demoted non-server AND a fresh candidate exists: drop the worst
    ///       non-server (BLOCK_STALLING_TIMEOUT disconnect) and refill from the
    ///       addrman-fed plan (ThreadOpenConnections). Rate-limited so a
    ///       transiently-quiet peer is never churned.
    /// Reward-safe: this changes only WHICH / HOW-MANY peers we fetch from — the
    /// per-block merkleRoot fold self-check, payee cross-check, and poison
    /// fail-closed are all untouched, and no block is ever skipped.
    void maybe_rotate_outbound(int64_t now)
    {
        if (!m_outbound_rotate_enabled) return;
        prune_rotation_cooldown(now);
        if (!outbound_behind()) return;

        // (1) Room under the raised target ⇒ dial more fresh candidates.
        if (m_pool.size() + m_dialing.size() < effective_max_peers())
        {
            refill_pool();
            return;
        }

        // (2) Saturated even at the expanded target: rotate the worst
        // non-server out for a fresh dial — but only when it buys a genuinely
        // new candidate, and no more often than the stall cadence.
        if (now - m_last_outbound_rotate < OUTBOUND_ROTATE_INTERVAL_SEC) return;
        if (!has_fresh_dial_candidate(now)) return;
        PeerSession* victim = worst_demoted_pool_peer(now);
        if (!victim) return;

        const std::string vkey = victim->key;
        LOG_INFO << "[" << m_chain_label << "] archival rotation: evicting "
                    "demonstrated deep-body non-server " << vkey
                 << " (strikes=" << bulk_strikes(vkey)
                 << ") for a fresh archival dial (dashd BLOCK_STALLING_TIMEOUT "
                    "+ ThreadOpenConnections refill)";
        m_rotation_cooldown[vkey] = now + OUTBOUND_ROTATE_COOLDOWN_SEC;
        forgive_bulk_nonserver(vkey);   // a reconnect starts with a clean slate
        m_last_outbound_rotate = now;
        ++m_outbound_rotations;
        remove_peer(victim, "archival rotation: deep-body non-server rotated out "
                            "for a fresh addrman candidate");
        refill_pool();                  // immediate redial; 30s loop is backstop
    }

    /// PR-3: dial EXACTLY ONE fresh plan candidate (the proactive probe).
    /// Unlike refill_pool() this ignores the effective target and dials a single
    /// fresh address the pool does not already hold / dial / just rotated out,
    /// so a HEALTHY pool can add one probe peer without a stall having raised the
    /// target. Returns true iff a dial was issued. Reward-safe: a connection
    /// only — the probe's replies flow through the identical fold self-checks.
    bool dial_one_fresh_candidate(int64_t now)
    {
        if (!m_reconnect_enabled || m_dial_plan.empty()) return false;
        prune_stale_dials(now);
        const std::size_t n = m_dial_plan.size();
        for (std::size_t i = 0; i < n; ++i)
        {
            const NetService target_addr = m_dial_plan.current();
            m_dial_plan.advance();
            const std::string key = target_addr.to_string();
            if (holds_key(key) || m_dialing.count(key)) continue;
            if (is_rotation_cooled(key, now)) continue;
            m_dialing[key] = now;
            LOG_INFO << "[" << m_chain_label << "] proactive probe dial " << key
                     << " (pool " << m_pool.size() << "/" << m_max_peers
                     << ", " << m_dialing.size() << " in flight)";
            core::Factory<core::Client>::connect(target_addr);
            return true;
        }
        return false;
    }

    // ── PR-3 proactive rotation (LOW-RATE, default OFF) ────────────────────
    /// The proactive half of the acquisition loop, gated behind
    /// --embedded-proactive-rotate. Even when NOT behind (no demoted slot-holder
    /// and no stateful stall, so maybe_rotate_outbound() is a no-op), a healthy
    /// pool that has latched on its frozen first-come set never discovers a
    /// faster peer. Once per PROACTIVE_ROTATE_INTERVAL_SEC this:
    ///   (1) PROBES — dials ONE fresh candidate if there is head-room under the
    ///       hard cap, so its TipBody delivery-latency EWMA (PR-0 feed) starts
    ///       filling on the next tip it answers; and
    ///   (2) RETIRES — sheds the SLOWEST measured non-primary CanServeBlocks
    ///       server, but ONLY when a genuine surplus remains afterwards (pool
    ///       above the base target) and a fresh candidate exists to replace it.
    /// m_primary and any protected-local peer (#147) are the latency reference
    /// and are NEVER retired; selection operates ONLY among CanServeBlocks peers
    /// (#148) and never promotes a non-server. Bounded by the cadence + the hard
    /// cap. Default OFF => this whole method returns immediately, so
    /// on_pool_tick() is byte-identical to master.
    ///
    /// Reward-safe (same class as #1329): only WHICH / HOW-MANY peers we fetch
    /// from and WHEN we probe changes — never WHAT is fetched or derived. Every
    /// reply still passes the identical merkle/payee/DIP-4/BLS self-checks;
    /// worst case is one extra probe connection + one reconnect.
    void maybe_proactive_rotate(int64_t now)
    {
        if (!proactivepolicy::proactive_due(m_proactive_rotate_enabled, now,
                                            m_last_proactive_rotate,
                                            PROACTIVE_ROTATE_INTERVAL_SEC))
            return;

        prune_rotation_cooldown(now);
        bool acted = false;

        // (1) PROBE one fresh candidate while there is head-room under the cap.
        if (m_pool.size() + m_dialing.size() < POOL_PEERS_HARD_CAP
            && has_fresh_dial_candidate(now))
        {
            acted = dial_one_fresh_candidate(now);
        }

        // (2) RETIRE the slowest measured non-primary server — only with a
        // surplus over the base target AND a fresh candidate to replace it, so
        // proactive rotation can never drop the pool below its healthy count.
        if (m_pool.size() > m_max_peers && has_fresh_dial_candidate(now))
        {
            std::vector<proactivepolicy::PeerLatencyView> views;
            views.reserve(m_pool.size());
            for (const auto& up : m_pool)
            {
                PeerSession* p = up.get();
                if (!p->handshake.complete()) continue;
                if (is_rotation_cooled(p->key, now)) continue;
                const AddrClass ac = classify_address(p->addr.address());
                const auto& e = p->delivery.get(DatumClass::TipBody);
                proactivepolicy::PeerLatencyView v;
                v.key = p->key;
                v.is_primary = (p == m_primary);
                v.is_protected_local =
                    (ac == AddrClass::loopback || ac == AddrClass::private_net);
                v.can_serve_blocks = can_serve_blocks(p);
                v.has_latency = e.has_sample();
                v.ewma_ms = e.ewma_ms();
                views.push_back(std::move(v));
            }
            const int idx = proactivepolicy::slowest_retirement_victim(views);
            if (idx >= 0)
            {
                const std::string vkey = views[static_cast<std::size_t>(idx)].key;
                PeerSession* victim = find_peer(vkey);
                // Belt-and-suspenders: the primary is exempt in the selector,
                // but never remove it here even if identity somehow shifted.
                if (victim && victim != m_primary)
                {
                    LOG_INFO << "[" << m_chain_label << "] proactive rotation: "
                                "retiring slowest server " << vkey
                             << " (tip_body_ewma_ms="
                             << views[static_cast<std::size_t>(idx)].ewma_ms
                             << ") for a fresh archival probe (PR-3, reward-safe: "
                                "connection-management only)";
                    m_rotation_cooldown[vkey] = now + OUTBOUND_ROTATE_COOLDOWN_SEC;
                    forgive_bulk_nonserver(vkey);
                    remove_peer(victim, "proactive rotation: slowest measured "
                                        "server shed for a fresh probe");
                    refill_pool();   // immediate redial; 30s loop is backstop
                    acted = true;
                }
            }
        }

        // Advance the cadence clock only when we actually acted, so a quiet
        // interval (no fresh candidate, pool already at cap) re-checks next tick
        // rather than silently burning the interval.
        if (acted)
        {
            m_last_proactive_rotate = now;
            ++m_proactive_rotations;
        }
    }

    /// Reclaim dial slots whose callback never came. Without this a Factory
    /// dial that neither connects nor fails (a black-holed SYN) would hold a
    /// pool slot for the life of the process and silently cap the pool.
    void prune_stale_dials(int64_t now)
    {
        for (auto it = m_dialing.begin(); it != m_dialing.end(); )
        {
            if (now - it->second >= DIAL_SLOT_TIMEOUT_SEC)
            {
                LOG_DEBUG_COIND << "[" << m_chain_label << "] dial slot for "
                                << it->first << " reclaimed after "
                                << DIAL_SLOT_TIMEOUT_SEC << "s with no callback";
                it = m_dialing.erase(it);
            }
            else ++it;
        }
    }

    // ── pool tick ────────────────────────────────────────────────────────

    void ensure_pool_timer()
    {
        if (m_pool_timer) return;
        m_pool_timer = std::make_unique<core::Timer>(m_context, /*repeat=*/true);
        m_pool_timer->start(m_pool_tick_sec, [this]() { on_pool_tick(); });
    }

    /// The ONE time source every deadline in this client is measured against.
    /// Injectable (set_now_fn) so the liveness policy can be driven by
    /// simulated seconds instead of wall-clock ones — see the seam's rationale
    /// on set_now_fn below.
    int64_t now_sec() const { return m_now_fn(); }

    /// Inbound traffic observed FROM THIS PEER. This is the ONLY liveness input
    /// — nothing we SEND may push the deadline out (see PeerLiveness's
    /// invariant) and nothing ANOTHER peer sends may push THIS peer's deadline
    /// out, which is the whole reason the policy object is per-session.
    void on_activity(PeerSession& p)
    {
        p.liveness.on_inbound(now_sec());
        if (!p.handshake.complete())
        {
            // Pre-handshake the deadline is still the short CONNECT one: a
            // peer that opens a socket and then stalls mid-version must not
            // hold a pool slot for the full liveness window.
            p.handshake_deadline = now_sec() + CONNECT_TIMEOUT_SEC;
        }
    }

    void send_ping(PeerSession& p)
    {
        if (!p.handshake.complete()) return;
        const uint64_t nonce = core::random::random_nonce();
        auto msg_ping = message_ping::make_raw(nonce);
        p.write(msg_ping);
        p.liveness.note_ping_sent(nonce, now_sec());
        LOG_DEBUG_COIND << "[" << m_chain_label << "] ping sent to " << p.key
                        << " (nonce=" << nonce << ", quiet for "
                        << (now_sec() - p.liveness.last_recv()) << "s)";
    }

    /// One tick for the WHOLE pool. Every peer is evaluated against its OWN
    /// PeerLiveness — a silent peer matures its own unanswered-ping deadline
    /// and is dropped while its neighbours, whose deadlines were pushed out by
    /// their own inbound traffic, keep delivering.
    void on_pool_tick()
    {
        const int64_t now = now_sec();

        // Collect first, act after: remove_peer() erases from m_pool, which
        // would invalidate the iteration.
        std::vector<std::pair<PeerSession*, std::string>> drops;
        for (auto& up : m_pool)
        {
            PeerSession* p = up.get();
            if (!p->handshake.complete())
            {
                if (p->handshake_deadline > 0 && now >= p->handshake_deadline)
                    drops.emplace_back(p, std::string("peer timeout: handshake timeout"));
                continue;
            }
            switch (p->liveness.tick(now))
            {
            case PeerLiveness::Action::SendPing:
                send_ping(*p);
                break;
            case PeerLiveness::Action::DropPingTimeout:
                LOG_WARNING << "[" << m_chain_label << "] ping (nonce="
                            << p->liveness.ping_nonce() << ") to " << p->key
                            << " unanswered for " << p->liveness.peer_timeout_sec() << "s";
                drops.emplace_back(p, "peer timeout: ping unanswered for "
                        + std::to_string(p->liveness.peer_timeout_sec()) + "s");
                break;
            case PeerLiveness::Action::DropIdle:
                drops.emplace_back(p, "peer timeout: no message received in "
                        + std::to_string(p->liveness.peer_timeout_sec()) + "s");
                break;
            case PeerLiveness::Action::None:
                break;
            }
        }
        for (auto& [p, why] : drops)
        {
            // Re-validate: remove_peer() fires user callbacks (the peer-manager
            // scoring feed, the promotion sync-kick). Nothing in-tree removes a
            // second peer from inside them, but a stale pointer here would be a
            // use-after-free, so the membership check is not optional.
            if (!owns(p)) continue;
            remove_peer(p, why);
        }

        service_pending_bodies(now);
        drain_tx_retry_busy(now);
        prune_stale_dials(now);
        // dashd acquisition parity: while behind on archival coverage, dial
        // more and rotate the frozen full pool's worst non-server out for a
        // fresh archival candidate (connection-management only, reward-safe).
        maybe_rotate_outbound(now);
        // PR-3: LOW-RATE proactive rotation — even a HEALTHY (not-behind) pool
        // periodically probes a fresh candidate and sheds its slowest measured
        // server. Default OFF => no-op (byte-identical to master).
        maybe_proactive_rotate(now);
        maybe_log_pool_status(now);
    }

    /// Lost-body watchdog service (one pass per pool tick). A tracked
    /// getdata(block) unanswered for its per-slot stall window is re-issued — from a
    /// DIFFERENT handshaked peer when the pool holds one (the announcing peer
    /// may be slow/wedged; its neighbours demonstrably hold the block they
    /// all announced), rotating through the pool on successive attempts —
    /// bounded at BODY_REREQUEST_MAX, every re-request named in the log.
    void service_pending_bodies(int64_t now)
    {
        for (auto it = m_pending_bodies.begin(); it != m_pending_bodies.end();)
        {
            PendingBody& pb = *it;
            // dashd BLOCK_STALLING_TIMEOUT: the per-slot window doubles on each
            // consecutive stall (fast first retry; a chronically-missing block
            // backs off). Not yet due — leave it.
            if (now - pb.last_req < pb.stall_timeout) { ++it; continue; }

            // The peer we last leaned on did not deliver within the window.
            // A slot is NEVER erased here: dashd keeps a needed block in
            // mapBlocksInFlight until the body actually lands (that removal
            // lives in the block handler). Abandoning it is the wedge this
            // replaces (height 967736: connected=8/8, slot dropped, lane frozen).
            const std::string staller = pb.last_peer;
            ++pb.stalls_since_evict;

            // Rotate through the handshaked peers, preferring one we did not
            // just ask; a single-peer pool re-asks the same peer (still
            // strictly better than the 600 s inv-TTL wait). The ANNOUNCER goes
            // first — it holds the block by definition.
            std::vector<PeerSession*> cands;
            if (PeerSession* src = block_source(pb.hash))
                if (src->handshake.complete()) cands.push_back(src);
            for (auto& up : m_pool)
                if (up->handshake.complete() &&
                    (cands.empty() || up.get() != cands.front()))
                    cands.push_back(up.get());
            if (cands.empty()) { ++it; continue; }   // retry when the pool refills
            PeerSession* target =
                cands[static_cast<size_t>(pb.rerequests) % cands.size()];
            if (target->key == pb.last_peer && cands.size() > 1)
                target = cands[(static_cast<size_t>(pb.rerequests) + 1)
                               % cands.size()];
            auto msg = message_getdata::make_raw(
                {inventory_type(inventory_type::block, pb.hash)});
            target->write(msg);
            ++pb.rerequests;
            ++m_body_rerequests_total;
            pb.last_req = now;
            // A freshly-assigned peer gets the full fast window (dashd resets
            // the stall clock on (re)assignment); doubling, capped, only when
            // the pool leaves us re-asking the same staller.
            if (target->key != staller)
                pb.stall_timeout = BODY_STALL_TIMEOUT_INIT;
            else
                pb.stall_timeout =
                    std::min<int64_t>(pb.stall_timeout * 2, BODY_STALL_TIMEOUT_MAX);
            pb.last_peer = target->key;
            LOG_INFO << "[" << m_chain_label << "] cause=body-rerequest attempt="
                     << pb.rerequests << " peer=" << target->key << " hash="
                     << pb.hash.GetHex().substr(0, 16) << "... unanswered_for="
                     << (now - pb.first_req) << "s next_stall_window="
                     << pb.stall_timeout << "s";

            // dashd disconnect-on-stall + FindNextBlocksToDownload: with 8/8
            // connected but none serving THIS body, rotation alone spins. Once
            // the current peer set has stalled the slot BODY_REREQUEST_MAX times,
            // DISCONNECT the blamed peer — this fires the peer-manager scorer,
            // frees the in-flight slot, and arms a refill of a DIFFERENT address
            // so the pool churns toward a peer that actually holds the body.
            // Guarded: only when a real staller is still held AND a survivor (or
            // an armed refill) can replace it, so one missing block can never
            // drain the pool to zero.
            if (pb.stalls_since_evict >= BODY_REREQUEST_MAX && !staller.empty())
            {
                PeerSession* bad = find_peer(staller);
                const bool have_alternative =
                    handshaked_peer_count() > 1 || m_reconnect_enabled;
                if (bad && owns(bad) && have_alternative)
                {
                    ++pb.evictions;
                    ++m_body_stall_evictions;
                    pb.stalls_since_evict = 0;
                    // The disconnected staller demonstrably did not serve this
                    // deep body: demote its address so a refill/reconnect to it
                    // is skipped by next_bulk_peer() (dashd failure demotion).
                    note_bulk_nonserver(staller);
                    pb.stall_timeout = BODY_STALL_TIMEOUT_INIT;
                    remove_peer(bad,
                        "block-stall: body " + pb.hash.GetHex().substr(0, 16)
                        + "... unanswered over "
                        + std::to_string(now - pb.first_req)
                        + "s — disconnecting the staller to re-request from"
                          " another peer (dashd disconnect-on-stall)");
                }
            }
            ++it;
        }
    }

    /// THE MEASUREMENT. One line, every POOL_STATUS_INTERVAL_SEC, naming the
    /// pool state a soak has to be able to read directly: how many peers we
    /// hold, how many are answerable, how many DISTINCT addresses they are (the
    /// number that was silently 3-over-9-hours before this change), and how old
    /// each connection is — because durability, not count, is what determines
    /// whether we were connected AT THE MOMENT an announcement went out.
    ///
    /// The dedup counters ride along: `suppressed` is the direct count of
    /// duplicate announcements the pool gave us, i.e. how much redundancy we
    /// actually bought, and the eviction counters make the bound observable
    /// instead of asserted.
    void maybe_log_pool_status(int64_t now)
    {
        if (m_last_status_log != 0 &&
            (now - m_last_status_log) < POOL_STATUS_INTERVAL_SEC)
            return;
        m_last_status_log = now;

        std::string ages;
        for (const auto& p : m_pool)
        {
            if (!ages.empty()) ages += " ";
            ages += p->key + "=" + std::to_string(p->age_sec()) + "s"
                  + (p->handshake.complete() ? "" : "(hs)")
                  + (p.get() == m_primary ? "*" : "");
        }
        const auto& st = m_inv_dedup.stats();
        LOG_INFO << "[" << m_chain_label << "] POOL-STATUS connected="
                 << m_pool.size() << "/" << m_max_peers
                 << " handshaked=" << handshaked_peer_count()
                 << " distinct_addrs=" << distinct_peer_addresses()
                 << " dialing=" << m_dialing.size()
                 << " primary=" << (m_primary ? m_primary->key : std::string("none"))
                 << " sessions(started/lost)=" << m_sessions_started << "/" << m_sessions_lost
                 << " ages=[" << ages << "]"
                 << " inv_dedup(size/cap)=" << m_inv_dedup.size() << "/"
                 << m_inv_dedup.capacity()
                 << " admitted=" << st.admitted
                 << " suppressed=" << st.suppressed
                 << " evicted(cap/ttl)=" << st.evicted_capacity << "/" << st.evicted_ttl
                 << " pending_bodies=" << m_pending_bodies.size()
                 << " body_rerequests=" << m_body_rerequests_total
                 << " body_stall_evictions=" << m_body_stall_evictions;
    }

    // ── PR-0 ARRIVAL INSTRUMENTATION (record-only) ────────────────────────
    // Close the delivery-latency clock for `cls` on the peer that answered
    // (m_active during dispatch), update its per-class EWMA, and — only when the
    // default-OFF flag is armed — emit the per-peer latency on [COIN-P2P]. When
    // the flag is OFF this still records into the peer's EWMA (invisible) and
    // emits nothing, so the log is byte-identical to master. Never gates the
    // handler; a reply with no matching outstanding request is a silent no-op.
    void record_delivery_latency(DatumClass cls)
    {
        if (!m_active) return;
        const int64_t lat = m_active->note_reply_received(cls, arrival_now_ms());
        if (lat < 0 || !arrival_instr_enabled()) return;
        LOG_INFO << "[COIN-P2P] delivery peer=" << m_active->key
                 << " datum=" << datum_class_name(cls)
                 << " delivery_latency_ms=" << lat
                 << " ewma_ms=" << m_active->delivery.ewma_ms(cls)
                 << " samples=" << m_active->delivery.get(cls).samples();
    }

    // ── handshake ────────────────────────────────────────────────────────

    ADD_P2P_HANDLER(version)
    {
        PeerSession* p = m_active;
        if (!p) return;
        p->services = msg->m_services;
        p->version = msg->m_version;
        p->subver = msg->m_subversion;
        p->start_height = msg->m_start_height;
        LOG_INFO << "[" << m_chain_label << "] peer " << p->key
                 << " version: proto=" << msg->m_version
                 << " start_height=" << msg->m_start_height
                 << " services=0x" << std::hex << msg->m_services << std::dec
                 << " subver=" << msg->m_subversion;
        // MONOTONE across the pool: the height callback drives a sync-progress
        // gauge, and with N peers a lagging member would otherwise walk the
        // target backwards every time it (re)connected. Only a NEW best is
        // published.
        if (msg->m_start_height > m_best_peer_height)
        {
            m_best_peer_height = msg->m_start_height;
            if (m_on_peer_height)
                m_on_peer_height(msg->m_start_height);
        }
        if (!p->handshake.on_version())
            return;   // duplicate / stray version — do not re-ack
        auto verack_msg = message_verack::make_raw();
        p->write(verack_msg);
    }

    ADD_P2P_HANDLER(verack)
    {
        PeerSession* p = m_active;
        if (!p) return;
        if (!p->handshake.on_verack())
            return;   // stray verack outside a session

        // Arm THIS peer's request matchers. The lambdas capture the session
        // pointer, not `this`+m_peer: a deferred request must be re-issued to
        // the peer it belongs to, never to whichever peer happens to be current.
        // The session owns the Connection that owns these matchers, so they
        // cannot outlive it.
        p->conn->init_requests(
            [p](uint256 hash)
            {
                auto getdata_msg = message_getdata::make_raw({inventory_type(inventory_type::block, hash)});
                p->write(getdata_msg);
            },
            [p](uint256 hash)
            {
                auto getheaders_msg = message_getheaders::make_raw(1, {}, hash);
                p->write(getheaders_msg);
            }
        );

        LOG_INFO << "[" << m_chain_label << "] handshake complete with " << p->key
                 << " (peer proto=" << p->version
                 << " height=" << p->start_height << "); handshaked "
                 << handshaked_peer_count() << "/" << m_pool.size();

        // The handshake deadline has been met — retire it. From here liveness
        // is the ping/pong policy, NOT a bare "peer went quiet" stopwatch.
        p->handshake_deadline = 0;
        p->liveness.start(now_sec());
        ensure_pool_timer();

        // SPORK SYNC: ask THIS peer for its full spork set (dashd answers
        // "getsporks" with every spork it holds, and relays new ones
        // unsolicited from here on). Per-peer and idempotent — a duplicate
        // spork is verified, found stale, and dropped by the state machine, so
        // asking every handshaked peer costs one tiny message each and buys
        // N-witness refinement of the assume-active seed.
        auto msg_getsporks = message_getsporks::make_raw();
        p->write(msg_getsporks);

        if (!m_primary)
        {
            // First peer to become answerable carries the request/response legs
            // and fires the sync kick — identical to the single-peer behaviour.
            promote_primary(p);
        }
        else if (m_addr_callback)
        {
            // A witness peer joining the pool. It is never asked a stateful
            // question, but it IS asked for addresses once: address breadth is
            // what refills the pool after a loss, and each peer has its own
            // view. Only when a discovery consumer is registered — otherwise
            // the reply would be parsed and thrown away.
            auto msg_getaddr = message_getaddr::make_raw();
            p->write(msg_getaddr);
        }
    }

    // ── keep-alive ───────────────────────────────────────────────────────

    ADD_P2P_HANDLER(ping)
    {
        PeerSession* p = m_active;
        if (!p) return;
        auto msg_pong = message_pong::make_raw(msg->m_nonce);
        p->write(msg_pong);
    }

    ADD_P2P_HANDLER(pong)
    {
        PeerSession* p = m_active;
        if (!p) return;
        // on_activity() already refreshed THIS peer's last-recv for any inbound
        // message; this additionally CLOSES that peer's outstanding ping, which
        // is what stops its ping-unanswered deadline from ever maturing while
        // it is alive. A nonce that does not match ITS outstanding ping is still
        // liveness evidence but answers nothing — and because the nonce lives on
        // the session, a pong from this peer can NEVER answer another peer's
        // ping. That isolation is the difference between a pool and a pool that
        // holds dead sockets open forever.
        const bool matched = p->liveness.on_pong(msg->m_nonce, now_sec());
        LOG_DEBUG_COIND << "[" << m_chain_label << "] pong from " << p->key
                        << " (nonce=" << msg->m_nonce
                        << (matched ? ") — ping answered" : ") — unsolicited/stale");
    }

    // ── E1 seam handlers: parse + fire interfaces::Node events, NO ingest ─

    ADD_P2P_HANDLER(inv)
    {
        PeerSession* p = m_active;
        if (!p) return;
        const int64_t now = now_sec();
        // ── FAN-IN COLLAPSE ──────────────────────────────────────────────
        // With N peers the SAME announcement arrives N times within a few
        // hundred milliseconds. Witnessing it N times is the point; ACTING on
        // it N times is waste — N getdata for one object, N full-block
        // downloads, N new_block events fanned into every downstream ingest
        // leg. InvDedup admits the first (type, hash) and suppresses the rest
        // out of a bounded, expiring set (see the class comment for both
        // bounds and the trade-off we are accepting).
        //
        // Block invs fire new_block (the E2 ingest seam, which pulls headers
        // then the block). Object invs in the pull policy get an immediate
        // getdata; everything else is ignored.
        for (auto& inv : msg->m_invs)
        {
            // inv_type_is_pulled is the TYPE predicate. isdlock is pulled
            // UNCONDITIONALLY (#1230): the fee-only-safe new_islock lane
            // (G4 guard + IS mining-safety hold) rides every received
            // isdlock. The runtime opt-in (--embedded-ingest-isdlock) gates
            // only the BLS-verified new_isdlock lane at the handler, not
            // the getdata.
            const bool pulled = inv_type_is_pulled(inv.m_type);
            const bool is_block = (inv.base_type() == inventory_type::block);
            const bool is_tx = (inv.base_type() == inventory_type::tx)
                            && m_tx_pull_enabled;
            // W5-B: MSG_DSTX rides the tx-pull budget path (same strict
            // tip-body priority, same inflight cap and txid-keyed dedup —
            // the DSTX inv hash IS the plain txid). Gated on its OWN flag:
            // no fee-only-safe unconditional consumer exists for a DSTX.
            const bool is_dstx = (inv.m_type == inventory_type::dstx)
                              && m_dstx_pull_enabled;
            // Offered-vs-admitted (diagnosis, not policy): counted BEFORE the
            // dedup so "peers are not announcing" can be told apart from "we
            // are filtering". Same announcement from N peers = N offered, 1
            // admitted — that gap is the fan-in the pool exists to produce.
            if (inv.base_type() == inventory_type::tx) ++m_tx_inv_offered;
            if (!pulled && !is_block && !is_tx && !is_dstx)
                continue;   // not actionable — do not spend a dedup slot on it
            if (!m_inv_dedup.admit(static_cast<uint32_t>(inv.m_type), inv.m_hash, now))
            {
                // Already answered from an earlier peer's announcement. This
                // is the redundancy the pool exists to produce, counted.
                LOG_DEBUG_COIND << "[" << m_chain_label << "] duplicate inv type="
                                << static_cast<uint32_t>(inv.m_type) << " "
                                << inv.m_hash.GetHex().substr(0, 16)
                                << "... from " << p->key << " — already requested";
                continue;
            }
            // Sourcing legs: pull the announced object for every inv type in
            // the pull policy (inv_type_is_pulled, p2p_messages.hpp) —
            // MSG_QUORUM_FINAL_COMMITMENT = 21 feeding the Phase-L
            // MineableCommitmentCache, and MSG_CLSIG = 29 feeding the
            // ChainLock lane. Dash announces both by inv and serves them only
            // on getdata; without this the clsig handler below can never fire,
            // which is exactly why on_new_chainlock had never been reached.
            //
            // NOTE the ChainLock inv hash is SerializeHash(clsig) — SHA256d
            // over the whole 132-byte ChainLockSig — NOT the locked block's
            // hash, so it is only ever echoed straight back in the getdata; we
            // cannot derive it and must not try. dashd also serves ONLY its
            // current best ChainLock (GetChainLockByHash refuses anything
            // else), so a getdata for a superseded announcement legitimately
            // comes back notfound; that is benign and self-correcting — the
            // next ChainLock is announced ~2.5 min later.
            if (pulled)
            {
                // Ask the peer that ANNOUNCED it — it demonstrably holds the
                // object, and its reply routes back to this same session.
                auto getdata_msg = message_getdata::make_raw(
                    {inventory_type(inv.m_type, inv.m_hash)});
                p->write(getdata_msg);
                continue;
            }
            if (is_tx || is_dstx)
            {
                if (is_tx) ++m_tx_inv_seen; else ++m_dstx_inv_seen;
                expire_tx_pulls(now);
                // STRICT PRIORITY: the tip body always wins. A transaction is
                // worth a fraction of a block's fees; a late tip body is a
                // stale template on every attached rig.
                if (!m_pending_bodies.empty()) {
                    ++m_tx_pull_skipped_busy;
                    // Do NOT let the 600 s InvDedup TTL strand it: park the
                    // announcement and re-issue the getdata the moment the
                    // tip body clears (drain_tx_retry_busy on the pool tick).
                    if (m_tx_retry_busy.size() >= m_tx_retry_busy_cap)
                        m_tx_retry_busy.pop_front();
                    m_tx_retry_busy.push_back(
                        TxRetry{static_cast<uint32_t>(inv.m_type), inv.m_hash});
                    ++m_tx_retry_requeued;
                    continue;
                }
                if (m_tx_pull_inflight.size() >= m_tx_pull_inflight_cap) {
                    ++m_tx_pull_skipped_budget;
                    continue;
                }
                // Budget slots are keyed by TXID — correct for BOTH lanes
                // because the DSTX inv hash IS the plain txid (dashd
                // net_processing.cpp:2567); a type-1 and a type-16
                // announcement of the same tx share one slot here even
                // though InvDedup (keyed on type+hash) admitted both.
                if (m_tx_pull_inflight.count(inv.m_hash)) continue;
                m_tx_pull_inflight.emplace(inv.m_hash, now);
                if (is_tx) ++m_tx_pull_sent; else ++m_dstx_pull_sent;
                // Echo the ANNOUNCED type back: a getdata(MSG_TX) for a
                // DSTX-only tx would get notfound from dashd until it leaves
                // the DSTX relay window.
                auto getdata_msg = message_getdata::make_raw(
                    {inventory_type(inv.m_type, inv.m_hash)});
                p->write(getdata_msg);
                continue;
            }
            LOG_INFO << "[" << m_chain_label << "] block inv "
                     << inv.m_hash.GetHex().substr(0, 16) << "... from " << p->key;
            // Remember WHO announced it: the body/headers pull the new_block
            // subscriber fires next must be routed back to this peer, which
            // holds the block, not to an arbitrary primary (block_source).
            record_block_announcer(inv.m_hash, p->key);
            m_coin->new_block.happened(inv.m_hash);
        }
    }

    ADD_P2P_HANDLER(tx)
    {
        ++m_tx_received;
        // Release the budget slot. The txid is the SHA256d of the serialized
        // body; computing it here (rather than trusting the announcement we
        // asked for) means an unsolicited or substituted body cannot free a
        // slot it never occupied.
        {
            ::PackStream ps;
            ps << msg->m_tx;
            auto sp = ps.get_span();
            uint256 txid;
            CHash256()
                .Write(std::span<const unsigned char>(
                    reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
                .Finalize(std::span<unsigned char>(txid.data(), 32));
            m_tx_pull_inflight.erase(txid);
        }
        m_coin->new_tx.happened(Transaction(msg->m_tx));
    }

    ADD_P2P_HANDLER(block)
    {
        // PR-0 instrumentation (record-only): time the tip/body delivery on the
        // peer that answered. Pure telemetry; the block is verified identically
        // downstream. The emit is gated on the default-OFF flag.
        record_delivery_latency(DatumClass::TipBody);
        // E2a: BlockType now deserializes the full body (header + tx set), so
        // msg->m_block carries the transactions the ingest legs consume
        // (MnStateMachine::apply_block special txs, UTXO connect_block). The
        // full_block event below feeds the E2a live-feed bridge, which derives
        // the block height off the header chain and fires block_connected.
        PeerSession* p = m_active;
        if (!p) return;
        auto header = static_cast<BlockHeaderType>(msg->m_block);
        auto packed_header = pack(header);
        auto blockhash = dash::crypto::hash_x11(packed_header.get_span());
        // Complete the matcher on the peer that was ASKED — this reply arrived
        // on its socket, and its deferral state is the one waiting.
        try { p->conn->get_block(blockhash, msg->m_block); } catch (...) {}
        try { p->conn->get_header(blockhash, header); } catch (...) {}
        // Lost-body watchdog: the body has arrived (from whichever peer
        // answered first) — disarm its slot.
        for (auto it = m_pending_bodies.begin();
             it != m_pending_bodies.end(); ++it)
            if (it->hash == blockhash) { m_pending_bodies.erase(it); break; }
        // This peer just DELIVERED a body — it demonstrably serves blocks, so
        // clear any non-server strike so it re-enters bulk selection (dashd
        // forgives a peer the moment it satisfies a download).
        forgive_bulk_nonserver(p->key);
        // W2 bulk demux: a body the replay bulk lane has in flight is consumed
        // HERE (verified + folded + pruned by the lane) and never fires
        // full_block — the live ingest legs are tip-rate consumers and must
        // not see 1.49M historical bodies. The filter claims ONLY hashes the
        // bulk scheduler itself requested, so a tip body can never be
        // swallowed. DEBUG, not INFO: bulk arrival rate would flood the
        // journal (the [BULK] telemetry line is the throughput surface).
        if (m_block_body_filter && m_block_body_filter(blockhash, msg->m_block))
        {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] bulk body from "
                            << p->key << ": "
                            << blockhash.GetHex().substr(0, 16)
                            << "... (consumed by replay bulk lane)";
            return;
        }
        LOG_INFO << "[" << m_chain_label << "] block received from " << p->key
                 << ": " << blockhash.GetHex().substr(0, 16) << "...";
        m_coin->full_block.happened(msg->m_block);
    }

    ADD_P2P_HANDLER(headers)
    {
        // CP1 parse: a complete `headers` message was framed and parsed — log
        // the batch count + wire payload size. Fires only per successfully
        // parsed message, so a stall upstream of parse stays silent here.
        LOG_INFO << "[" << m_chain_label << "] CP1 parse headers: batch="
                 << msg->m_headers.size()
                 << " payload_bytes=" << pack(msg->m_headers).size();
        // E2a: BlockType now round-trips the wire `headers` layout (each entry
        // is an 80-byte header + CompactSize(0) tx-count), so multi-entry
        // getheaders-driven batches deserialize correctly. The new_headers event
        // feeds the E2a live-feed bridge -> HeaderChain::add_headers, which is
        // the tip authority driving the embedded template's next-work/MTP.
        PeerSession* p = m_active;
        if (!p) return;
        // W2 bulk demux: a batch extending the genesis→anchor backfill walk
        // is consumed here — the main HeaderChain fast-starts at the anchor
        // and would orphan-reject every pre-anchor header (CP2 accepted==0
        // noise), and the tip-lane matchers below have nothing waiting on
        // 2012-era headers. Unclaimed batches (the tip sync) fall through
        // unchanged.
        if (m_headers_filter && m_headers_filter(p->key, msg->m_headers))
        {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] headers batch ("
                            << msg->m_headers.size()
                            << ") consumed by replay backfill";
            return;
        }
        std::vector<BlockHeaderType> vheaders;
        for (auto& block : msg->m_headers)
        {
            auto header = static_cast<BlockHeaderType>(block);
            auto packed_header = pack(header);
            auto blockhash = dash::crypto::hash_x11(packed_header.get_span());
            try { p->conn->get_header(blockhash, header); } catch (...) {}
            vheaders.push_back(header);
        }
        if (!vheaders.empty())
            m_coin->new_headers.happened(vheaders);
    }

    ADD_P2P_HANDLER(addr)
    {
        if (m_addr_callback && !msg->m_addrs.empty()) {
            std::vector<NetService> addrs;
            addrs.reserve(msg->m_addrs.size());
            for (auto& rec : msg->m_addrs)
                addrs.push_back(rec.m_endpoint);
            m_addr_callback(addrs);
        }
    }

    ADD_P2P_HANDLER(addrv2)
    {
        LOG_DEBUG_COIND << "[" << m_chain_label << "] addrv2: "
                        << msg->m_addrs.size() << " record(s) (discovery seam is E2)";
    }

    ADD_P2P_HANDLER(clsig)
    {
        // ChainLock announcement — finalization signal. Fire the event seam;
        // recording into chainlocked_blocks is state population (E2+).
        LOG_INFO << "[" << m_chain_label << "] chainlock from "
                 << (m_active ? m_active->key : std::string("?"))
                 << ": height=" << msg->m_height
                 << " block=" << msg->m_block_hash.GetHex().substr(0, 16) << "...";
        m_coin->new_chainlock.happened({msg->m_block_hash, msg->m_height});
        // Daemonless CCbTx path: forward the recovered 96-byte threshold sig so
        // the maintainer can adopt this ChainLock as the coinbase bestCLSignature.
        // m_sig is decoded as a fixed 96-byte array (p2p_messages.hpp clsig);
        // guard the copy defensively in case a peer sent a short blob.
        if (msg->m_sig.size() == 96) {
            ::dash::interfaces::Node::ChainLockSigEvent ev;
            ev.height     = msg->m_height;
            ev.block_hash = msg->m_block_hash;
            std::copy(msg->m_sig.begin(), msg->m_sig.end(), ev.sig.begin());
            m_coin->new_chainlock_sig.happened(ev);
        }
    }

    ADD_P2P_HANDLER(isdlock)
    {
        // DIP-0010/0022 deterministic InstantSend lock. TWO consumer lanes,
        // deliberately layered (rebase composite of #1230 + the isdlock-intake
        // branch):
        //
        //   Lane 1 (ALWAYS, #1230): IslockSeen → new_islock — the G4
        //   conflict-tx-lock guard's feed and the IS mining-safety hold's
        //   IsLocked short-circuit. The BLS sig is NOT verified on this lane;
        //   consumers are restricted to the fee-only-safe directions — see the
        //   trust-posture note on message_isdlock (p2p_messages.hpp).
        //
        //   Lane 2 (OPT-IN, --embedded-ingest-isdlock): IsdLockEvent →
        //   new_isdlock — NO trust decision here; the maintainer-side BLS gate
        //   (CoinStateMaintainer::on_new_isdlock, fail-closed) decides whether
        //   the verified adoption path ever runs.
        //
        // Version-gate defensively for BOTH lanes: dashd CURRENT_VERSION==1
        // (deterministic islock); anything else is a layout we have not
        // pinned, so drop it rather than mis-map outpoints.
        if (msg->m_version != 1) {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] isdlock DROPPED"
                            << " cause=unknown-version v="
                            << static_cast<int>(msg->m_version);
            return;
        }
        {
            ::dash::interfaces::Node::IslockSeen ev;
            ev.txid = msg->m_txid;
            ev.inputs.reserve(msg->m_inputs.size());
            for (const auto& in : msg->m_inputs)
                ev.inputs.emplace_back(in.hash, in.index);
            // DEBUG, not INFO: mainnet forms an islock for most transactions,
            // so this is tx-relay-cadence traffic (the mempool's own counters
            // are the observability surface).
            LOG_DEBUG_COIND << "[" << m_chain_label << "] isdlock from "
                            << (m_active ? m_active->key : std::string("?"))
                            << ": txid=" << msg->m_txid.GetHex().substr(0, 16)
                            << " inputs=" << msg->m_inputs.size();
            m_coin->new_islock.happened(ev);
        }
        // ── Lane 2: BLS-verified G4 adoption feed (opt-in) ─────────────────
        if (!m_isdlock_pull_enabled) {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] isdlock from "
                            << (m_active ? m_active->key : std::string("?"))
                            << " not forwarded to the BLS-verified lane"
                            << " (--embedded-ingest-isdlock off)";
            return;
        }
        // Structural refusals dashd makes in TriviallyValid + version check
        // (instantsend/lock.cpp): empty inputs, null txid, non-96-byte sig
        // (version==1 already gated above). Local drop + log; no ban; the
        // unverified lane above has already fired — this refusal only keeps
        // a malformed payload out of the verified adoption path.
        if (msg->m_inputs.empty()
            || msg->m_txid.IsNull() || msg->m_sig.size() != 96) {
            LOG_INFO << "[" << m_chain_label << "] isdlock from "
                     << (m_active ? m_active->key : std::string("?"))
                     << " REFUSED (version=" << static_cast<int>(msg->m_version)
                     << " inputs=" << msg->m_inputs.size()
                     << " sig_bytes=" << msg->m_sig.size() << ")";
            return;
        }
        ::dash::interfaces::Node::IsdLockEvent ev;
        ev.version    = msg->m_version;
        ev.txid       = msg->m_txid;
        ev.cycle_hash = msg->m_cycle_hash;
        ev.inputs.reserve(msg->m_inputs.size());
        for (const auto& in : msg->m_inputs)
            ev.inputs.emplace_back(in.hash, in.index);
        std::copy(msg->m_sig.begin(), msg->m_sig.end(), ev.sig.begin());
        // The inv hash is SerializeHash(payload) — SHA256d over the whole
        // message — same shape as clsig's. Diagnostic only (names the object
        // in logs); the getdata echoed the announcing peer's hash back.
        {
            auto ps = ::pack(*msg);
            ev.inv_hash = ::Hash(ps.get_span());
        }
        LOG_INFO << "[" << m_chain_label << "] isdlock from "
                 << (m_active ? m_active->key : std::string("?"))
                 << ": txid=" << msg->m_txid.GetHex().substr(0, 16)
                 << "... inputs=" << msg->m_inputs.size()
                 << " cycle=" << msg->m_cycle_hash.GetHex().substr(0, 16)
                 << "...";
        m_coin->new_isdlock.happened(ev);
    }

    ADD_P2P_HANDLER(dstx)
    {
        // W5-B: CoinJoin broadcast tx (dashd CCoinJoinBroadcastTx). NO trust
        // decision here — the maintainer-side BLS gate
        // (CoinStateMaintainer::on_new_dstx, fail-closed without a verifier)
        // decides whether the zero-fee admission path ever runs. This
        // handler: (1) releases the shared tx-pull budget slot by the
        // COMPUTED txid (never the announcement's — an unsolicited or
        // substituted body cannot free a slot it never occupied, same rule
        // as the tx handler); (2) applies dashd's STRUCTURAL refusals
        // (CCoinJoinBroadcastTx::IsValidStructure, coinjoin.cpp:83-102 —
        // local drop + log, no ban); (3) fires new_dstx when the lane is
        // armed.
        ++m_dstx_received;
        const uint256 txid = dash_txid(msg->m_tx);
        m_tx_pull_inflight.erase(txid);

        if (!m_dstx_pull_enabled) {
            // Off-flag no getdata was ever sent; an unsolicited dstx is
            // decode-and-discard (belt-and-suspenders).
            LOG_DEBUG_COIND << "[" << m_chain_label << "] dstx from "
                            << (m_active ? m_active->key : std::string("?"))
                            << " DISCARDED (--embedded-ingest-dstx off)";
            return;
        }

        // dashd IsValidStructure, KAT-pinned free predicate
        // (p2p_messages.hpp dstx_is_valid_structure).
        if (!dstx_is_valid_structure(msg->m_tx, msg->m_protx_hash,
                                     msg->m_sig.size())) {
            LOG_INFO << "[" << m_chain_label << "] dstx from "
                     << (m_active ? m_active->key : std::string("?"))
                     << " REFUSED structure (txid="
                     << txid.GetHex().substr(0, 16)
                     << " vin=" << msg->m_tx.vin.size()
                     << " vout=" << msg->m_tx.vout.size()
                     << " sig_bytes=" << msg->m_sig.size()
                     << " protx_null=" << (msg->m_protx_hash.IsNull() ? 1 : 0)
                     << ")";
            return;
        }

        ::dash::interfaces::Node::DstxEvent ev;
        ev.tx         = msg->m_tx;
        ev.txid       = txid;
        ev.protx_hash = msg->m_protx_hash;
        ev.sig_time   = msg->m_sig_time;
        std::copy(msg->m_sig.begin(), msg->m_sig.end(), ev.sig.begin());
        LOG_INFO << "[" << m_chain_label << "] dstx from "
                 << (m_active ? m_active->key : std::string("?"))
                 << ": txid=" << txid.GetHex().substr(0, 16)
                 << "... vin=" << msg->m_tx.vin.size()
                 << " protx=" << msg->m_protx_hash.GetHex().substr(0, 16)
                 << "... sig_time=" << msg->m_sig_time;
        m_coin->new_dstx.happened(ev);
    }

    ADD_P2P_HANDLER(qfcommit)
    {
        // E1 Phase-L sourcing leg: a peer-relayed DKG final commitment — the
        // same stream dashd's own miner mines type-6 txs from. Fire the event
        // seam; main_dash feeds the MineableCommitmentCache (structural
        // admission there; BLS verification is the Phase-L gate before any
        // template inclusion). No subscriber => no-op, zero behavior change.
        // Name the DELIVERING peer: the acceptance evidence for the pool is
        // "which peer did this arrive from", and over a soak the distribution
        // of that field is what shows the pool is doing its job rather than
        // eight sockets all shadowing one.
        LOG_INFO << "[" << m_chain_label << "] qfcommit from "
                 << (m_active ? m_active->key : std::string("?")) << ": type="
                 << static_cast<int>(msg->m_commitment.llmqType)
                 << " quorum=" << msg->m_commitment.quorumHash.GetHex().substr(0, 16)
                 << "... signers=" << msg->m_commitment.CountSigners();
        m_coin->new_qfcommit.happened(msg->m_commitment);
    }

    ADD_P2P_HANDLER(mnlistdiff)
    {
        // PR-0 instrumentation (record-only): time the mnlistdiff delivery on
        // the peer that answered. Pure telemetry; the diff is authenticated
        // identically downstream. The emit is gated on the default-OFF flag.
        record_delivery_latency(DatumClass::MnListDiff);
        // SML/quorum snapshot. message_mnlistdiff already fully deserialized the
        // wire form into msg->m_diff (a vendor::CSimplifiedMNListDiff, see
        // p2p_messages.hpp) — apply_diff + the QuorumTail parser + the CCbTx
        // seed all consume it downstream. Fire the reception event so the
        // subscribed CoinStateMaintainer::on_mnlistdiff advances the local SML
        // (merkleRootMNList), the QuorumManager (merkleRootQuorums), and seeds
        // bestCL*/creditPool from the diff's embedded cbTx. With no subscriber
        // (E1 posture / coin-P2P off) this is a no-op and the node keeps taking
        // the retained dashd-RPC fallback — zero behavior change on that path.
        LOG_INFO << "[" << m_chain_label << "] mnlistdiff: base="
                 << msg->m_diff.baseBlockHash.GetHex().substr(0, 16)
                 << " tip=" << msg->m_diff.blockHash.GetHex().substr(0, 16)
                 << " +" << msg->m_diff.mnList.size() << "mn -"
                 << msg->m_diff.deletedMNs.size() << "del qtail="
                 << msg->m_diff.quorum_tail.size() << "B";
        // DEMUX: a HISTORICAL reply (member sourcing, or the MN-checkpoint
        // lane's per-height PoSe fold) is consumed here and must NOT reach the
        // tip-SML maintainer — base=ZERO would overwrite the LIVE tip SML to
        // the old block. Only tip-sync diffs fall through. The tip feed is
        // passed IN so it is structurally impossible to fire it on a consumed
        // reply (see HistoricalMnListDiffDemux::dispatch).
        const bool consumed = m_historical_mnlistdiff_demux.dispatch(
            msg->m_diff,
            [this](const vendor::CSimplifiedMNListDiff& d) {
                m_coin->new_mnlistdiff.happened(d);
            });
        if (consumed) {
            LOG_INFO << "[" << m_chain_label << "] mnlistdiff consumed as "
                        "HISTORICAL (tip SML untouched)";
        }
    }

    ADD_P2P_HANDLER(qrinfo)
    {
        // PR-0 instrumentation (record-only): time the qrinfo delivery on the
        // peer that answered. Pure telemetry; the reply is verified identically
        // downstream. The emit is gated on the default-OFF flag.
        record_delivery_latency(DatumClass::QrInfo);
        // DIP-24 quorum rotation info. Decoded HERE (not in the codec) so a
        // malformed reply is a local, logged refusal rather than a stream
        // exception on the coin connection — see p2p_messages.hpp.
        vendor::CQuorumRotationInfo info;
        if (!vendor::decode_quorum_rotation_info(msg->m_raw, info)) {
            LOG_WARNING << "[" << m_chain_label << "] qrinfo REJECTED cause=undecodable"
                        << " value=" << msg->m_raw.size()
                        << "B — dropped, rotated sourcing stays fail-closed";
            return;
        }
        // RECEIVED is its own named event: before this existed, "no reply came"
        // and "a reply came and was dropped" were indistinguishable from a log.
        LOG_INFO << "[" << m_chain_label << "] qrinfo RECEIVED tip="
                 << info.mnListDiffTip.blockHash.GetHex().substr(0, 16)
                 << " H=" << info.mnListDiffH.blockHash.GetHex().substr(0, 16)
                 << " snapshots(active)="
                 << info.quorumSnapshotAtHMinusC.activeQuorumMembers.size() << "/"
                 << info.quorumSnapshotAtHMinus2C.activeQuorumMembers.size() << "/"
                 << info.quorumSnapshotAtHMinus3C.activeQuorumMembers.size()
                 << " lastCommitmentPerIndex=" << info.lastCommitmentPerIndex.size()
                 << " extraShare=" << (info.extraShare ? 1 : 0)
                 << " consumers=" << m_qrinfo_consumers.size();
        if (m_qrinfo_consumers.empty()) {
            // Reachable posture, not a bug: coin-P2P on but the rotated lane
            // unwired. Say so rather than letting the reply vanish.
            LOG_WARNING << "[" << m_chain_label << "] qrinfo DISCARDED cause=no_consumer"
                        << " — rotated member sourcing is not wired, every rotated "
                           "quorum stays null-serve";
            return;
        }
        for (auto& c : m_qrinfo_consumers) c(info);
    }

    // ── E-SUPERBLOCK: governance objects + votes (daemonless superblock) ──

    ADD_P2P_HANDLER(govobj)
    {
        // MNGOVERNANCEOBJECT. Compute the dashcore object identity hash via
        // govobject_hash — the EXACT Governance::Object::GetHash() preimage
        // (governance/common.cpp), which dashcore itself notes "doesn't match
        // serialization": it EXCLUDES nCollateralHash and nObjectType,
        // hex-string-encodes vchData, and inserts legacy dummy bytes after
        // the outpoint. This hash is what votes carry as nParentHash, so a
        // wrong preimage silently detaches every vote from its trigger.
        // Pinned byte-exact against from-wire testnet objects in
        // test_dash_superblock.
        ::dash::interfaces::Node::GovObjectRecord rec;
        rec.object_hash = ::dash::coin::govobject_hash(
            msg->m_hash_parent, msg->m_revision, msg->m_time, msg->m_vch_data,
            msg->m_masternode_outpoint.hash, msg->m_masternode_outpoint.index,
            msg->m_vch_sig);
        rec.object_type = msg->m_object_type;
        rec.vch_data    = msg->m_vch_data;
        LOG_INFO << "[" << m_chain_label << "] govobj: hash="
                 << rec.object_hash.GetHex().substr(0, 16) << " type="
                 << rec.object_type << " data=" << rec.vch_data.size() << "B";
        m_coin->new_govobject.happened(rec);
    }

    ADD_P2P_HANDLER(govobjvote)
    {
        // MNGOVERNANCEOBJECTVOTE. Forward the vote for the maintainer to
        // VERIFY + TALLY. For TRIGGER funding votes — the only votes the
        // superblock tally consults — verification is BLS by the voting MN's
        // OPERATOR key (dashcore CGovernanceVote::IsValid with
        // useVotingKey=false -> CheckSignature(pubKeyOperator); the
        // ECDSA/keyIDVoting path applies ONLY to PROPOSAL funding votes).
        // vote_hash is govvote_signature_hash — the exact dashcore
        // GetSignatureHash preimage (outpoint, parent, outcome, signal, time;
        // vchSig excluded), i.e. the digest the operator key signed.
        ::dash::interfaces::Node::GovVoteRecord rec;
        rec.parent_hash      = msg->m_parent_hash;
        rec.mn_outpoint_hash = msg->m_masternode_outpoint.hash;
        rec.mn_outpoint_index= msg->m_masternode_outpoint.index;
        rec.mn_outpoint_key  = msg->m_masternode_outpoint.to_key();
        rec.outcome          = msg->m_vote_outcome;
        rec.signal           = msg->m_vote_signal;
        rec.time             = msg->m_time;
        rec.vch_sig          = msg->m_vch_sig;
        rec.vote_hash        = ::dash::coin::govvote_signature_hash(
            msg->m_masternode_outpoint.hash, msg->m_masternode_outpoint.index,
            msg->m_parent_hash, msg->m_vote_outcome, msg->m_vote_signal,
            msg->m_time);
        // DEBUG, not INFO: a mainnet governance sync streams tens of
        // thousands of votes (per-vote INFO would flood the journal).
        LOG_DEBUG_COIND << "[" << m_chain_label << "] govobjvote: parent="
                        << rec.parent_hash.GetHex().substr(0, 16) << " mn="
                        << rec.mn_outpoint_key.substr(0, 20) << " outcome="
                        << rec.outcome << " signal=" << rec.signal;
        m_coin->new_govvote.happened(rec);
    }

    ADD_P2P_HANDLER(govsync)   { /* inbound sync request — we don't serve governance */ }

    // ── SPORK listener (state + telemetry only; NO serve-gate consults this) ─

    ADD_P2P_HANDLER(spork)
    {
        // A spork is operator policy, so it is only evidence once the 65-byte
        // compact signature recovers to the chainparams spork key. Verification
        // FIRST, state second: an unverifiable spork is counted + WARNed and
        // never touches the map — the assume-active mainnet seed (7/7 active)
        // stays authoritative, which is the posture that is RIGHT today even if
        // this listener never hears a single valid message.
        PeerSession* p = m_active;
        const int32_t id = msg->m_spork_id;
        const bool sig_ok = verify_spork_signature(
            id, msg->m_value, msg->m_time_signed, msg->m_sig, m_spork_pubkey_id);
        const SporkIngest outcome =
            m_spork_state.on_spork(id, msg->m_value, msg->m_time_signed, sig_ok);
        const std::string peer_key = p ? p->key : std::string("?");
        switch (outcome)
        {
        case SporkIngest::Applied:
            LOG_INFO << "[SPORK] " << spork_name(id) << " id=" << id
                     << " value=" << msg->m_value
                     << " signed=" << msg->m_time_signed
                     << " from " << peer_key << " — applied (verified); active "
                     << m_spork_state.active_count(now_sec()) << "/"
                     << m_spork_state.known_count() << ", listener-refined "
                     << m_spork_state.listener_refined_count();
            // A spork actually CHANGED state: let the IS mining-safety hold
            // re-derive its spork2+spork3 arm-bit (same thread as the map).
            if (m_spork_change_cb) m_spork_change_cb();
            break;
        case SporkIngest::Stale:
            LOG_DEBUG_COIND << "[SPORK] " << spork_name(id) << " id=" << id
                            << " value=" << msg->m_value
                            << " signed=" << msg->m_time_signed
                            << " from " << peer_key
                            << " — stale (not newer than held entry), kept ours";
            break;
        case SporkIngest::BadSignature:
            LOG_WARNING << "[SPORK] REJECTED cause=bad-signature id=" << id
                        << " (" << spork_name(id) << ") value=" << msg->m_value
                        << " signed=" << msg->m_time_signed
                        << " sig=" << msg->m_sig.size() << "B from " << peer_key
                        << " — state untouched (assume-active seed stands)";
            break;
        }
    }

    ADD_P2P_HANDLER(getsporks) { /* we don't serve sporks */ }

    // ── tolerated / ignored peer traffic ─────────────────────────────────

    ADD_P2P_HANDLER(alert)
    {
        LOG_WARNING << "[" << m_chain_label << "] alert: " << msg->m_signature;
    }

    ADD_P2P_HANDLER(reject)
    {
        LOG_WARNING << "[" << m_chain_label << "] peer rejected " << msg->m_message
                    << " (code=" << static_cast<int>(msg->m_ccode)
                    << "): " << msg->m_reason
                    << " hash=" << msg->m_data.GetHex();
    }

    ADD_P2P_HANDLER(notfound)
    {
        PeerSession* p = m_active;
        if (!p) return;
        for (auto& inv : msg->m_invs)
        {
            if (inv.base_type() == inventory_type::block)
            {
                // Complete the ReplyMatcher with an empty response so pending
                // requests don't wait out the 15s deferral timeout. On the peer
                // that was asked — a notfound from a different peer must not
                // cancel this peer's still-pending request.
                try { p->conn->get_block(inv.m_hash, BlockType{}); } catch (...) {}
                try { p->conn->get_header(inv.m_hash, BlockHeaderType{}); } catch (...) {}
                // W2 bulk lane: an archival gap answered notfound is requeued
                // on a DIFFERENT peer immediately instead of waiting out the
                // scheduler timeout. No-op unless --replay-bulk registered it.
                if (m_on_block_notfound) m_on_block_notfound(inv.m_hash);
                // dashd per-peer download-failure demotion: this peer just
                // declared it does NOT hold a block we asked for. Strike it so
                // next_bulk_peer() converges away from non-servers of deep
                // history onto archival peers that actually deliver.
                note_bulk_nonserver(p->key);
            }
        }
    }

    ADD_P2P_HANDLER(sendcmpct)
    {
        LOG_DEBUG_COIND << "[" << m_chain_label << "] peer sendcmpct v"
                        << msg->m_version << " (compact-block lane is a later slice)";
    }

    ADD_P2P_HANDLER(feefilter)
    {
        LOG_DEBUG_COIND << "[" << m_chain_label << "] peer feefilter: "
                        << msg->m_feerate << " duff/kB (fee pricing is a later slice)";
    }

    ADD_P2P_HANDLER(sendheaders)   { /* peer preference noted; we don't announce */ }
    ADD_P2P_HANDLER(sendaddrv2)    { /* acknowledged */ }
    ADD_P2P_HANDLER(mempool)       { /* we don't serve mempool */ }
    ADD_P2P_HANDLER(getaddr)       { /* we don't serve addresses */ }
    ADD_P2P_HANDLER(getdata)       { /* we don't serve blocks/txs */ }
    ADD_P2P_HANDLER(getblocks)     { /* we don't serve blocks */ }
    ADD_P2P_HANDLER(getheaders)    { /* we don't serve headers */ }
    ADD_P2P_HANDLER(getmnlistd)    { /* we don't serve SML diffs */ }
    ADD_P2P_HANDLER(getqrinfo)     { /* we don't serve rotation info either */ }
    ADD_P2P_HANDLER(cmpctblock)    { LOG_DEBUG_COIND << "[" << m_chain_label << "] cmpctblock ignored (E1)"; }
    ADD_P2P_HANDLER(getblocktxn)   { /* we never announce compact blocks */ }
    ADD_P2P_HANDLER(blocktxn)      { /* no pending compact block in E1 */ }

    #undef ADD_P2P_HANDLER
};

} // namespace p2p
} // namespace coin
} // namespace dash
