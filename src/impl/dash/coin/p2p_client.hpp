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
    // capped at 4 (~50 s total), after which the headers-driven re-request /
    // inv-TTL expiry remains the backstop.
    static constexpr time_t BODY_REREQUEST_SEC = 10;
    static constexpr int    BODY_REREQUEST_MAX = 4;
    // Tracked slots are bounded by design: the tip body plus a short burst
    // of near-tip blocks; oldest evicted beyond this.
    static constexpr size_t PENDING_BODY_CAP  = 8;
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
    static constexpr uint16_t MAINNET_P2P_PORT = 9999;

public:
    // Concurrent outbound peers held by default. 8 matches what dashd itself
    // keeps, which is the empirical bar for "we essentially never miss an
    // announcement". Raise it and the miss probability keeps falling; the cap
    // exists so a config typo cannot turn this node into a connection storm
    // against the network.
    static constexpr std::size_t DEFAULT_POOL_PEERS = 8;
    static constexpr std::size_t POOL_PEERS_HARD_CAP = 16;

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
    size_t   m_tx_pull_inflight_cap{64};
    std::map<uint256, int64_t> m_tx_pull_inflight;   // txid -> requested-at
    uint64_t m_tx_inv_offered{0};    // inv(MSG_TX) SEEN on the wire, pre-dedup
    uint64_t m_tx_inv_seen{0};       // inv(MSG_TX) admitted by the dedup
    uint64_t m_tx_pull_sent{0};      // getdata(MSG_TX) issued
    uint64_t m_tx_pull_skipped_budget{0};
    uint64_t m_tx_pull_skipped_busy{0};
    uint64_t m_tx_received{0};       // tx bodies that arrived
    uint64_t m_tx_pull_expired{0};   // getdata that never got an answer

    // ── SPORK listener (state + telemetry ONLY — nothing gates on it) ────
    // Seeded with the assume-active mainnet defaults (7/7 active, matching
    // dashd's hardened mainnet spork values), refined by VERIFIED spork
    // messages from peers. Verification key defaults to the mainnet spork key
    // ID from dashd chainparams; overridable only by the test seam below.
    SporkState m_spork_state;
    std::array<uint8_t, 20> m_spork_pubkey_id{MAINNET_SPORK_PUBKEY_ID};

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
    };
    std::vector<PendingBody> m_pending_bodies;
    uint64_t m_body_rerequests_total{0};
    uint64_t m_body_rerequests_exhausted{0};

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
             + " expired=" + std::to_string(m_tx_pull_expired);
    }
    uint64_t tx_received_count() const { return m_tx_received; }
    size_t   tx_pull_inflight()  const { return m_tx_pull_inflight.size(); }

    /// Request a full block via plain MSG_BLOCK getdata (E2 pull seam).
    /// Routed to the peer that ANNOUNCED this block (block_source), which holds
    /// it by definition; falls back to the primary when the announcer is
    /// unknown (bulk/historical legs) or has churned out.
    void request_block(const uint256& block_hash)
    {
        PeerSession* p = block_source(block_hash);
        if (!p) return;
        auto msg = message_getdata::make_raw(
            {inventory_type(inventory_type::block, block_hash)});
        p->write(msg);
    }

    /// Request a full block AND arm the lost-body watchdog for it (tip-follow
    /// path — see the BODY_REREQUEST_* rationale above). Plain
    /// request_block() stays untracked for the bulk/historical legs (UTXO
    /// window refill, checkpoint-lane windows), whose volume would defeat the
    /// bound and whose own re-request loops already exist.
    void request_block_tracked(const uint256& block_hash)
    {
        request_block(block_hash);
        const int64_t now = now_sec();
        for (auto& pb : m_pending_bodies)
            if (pb.hash == block_hash) { pb.last_req = now; return; }
        if (m_pending_bodies.size() >= PENDING_BODY_CAP)
            m_pending_bodies.erase(m_pending_bodies.begin());   // oldest slot
        PendingBody pb;
        pb.hash      = block_hash;
        pb.first_req = now;
        pb.last_req  = now;
        // The announcer just got the initial getdata; record it so the watchdog
        // rotates AWAY from it (to a neighbour) if it does not answer in time.
        PeerSession* src = block_source(block_hash);
        pb.last_peer = src ? src->key : std::string{};
        m_pending_bodies.push_back(std::move(pb));
    }

    /// Watchdog observability (KATs + POOL-STATUS).
    std::size_t pending_body_count()    const { return m_pending_bodies.size(); }
    uint64_t body_rerequests_total()    const { return m_body_rerequests_total; }
    uint64_t body_rerequests_exhausted() const { return m_body_rerequests_exhausted; }

    /// Send a getmnlistd (SML diff request) — E2/E3 masternode-list sync seam.
    void send_getmnlistd(const uint256& base_block_hash, const uint256& block_hash)
    {
        if (!m_primary) return;
        auto msg = message_getmnlistd::make_raw(base_block_hash, block_hash);
        m_primary->write(msg);
    }

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

    /// The peer to fetch a block from: the one that ANNOUNCED it (it holds it
    /// by definition and its reply routes back to its own session), falling
    /// back to the primary when the announcer is unknown or has since churned
    /// out of the pool. Never returns a stale pointer — resolved live.
    PeerSession* block_source(const uint256& hash)
    {
        for (auto& a : m_block_announcers)
            if (a.hash == hash)
            {
                PeerSession* p = find_peer(a.key);
                if (p && p->handshake.complete()) return p;
                break;
            }
        return m_primary;
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

        const std::size_t held = m_pool.size() + m_dialing.size();
        if (held >= m_max_peers) return;
        std::size_t slots = m_max_peers - held;

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
            const NetService target = m_dial_plan.current();
            m_dial_plan.advance();
            const std::string key = target.to_string();
            if (holds_key(key) || m_dialing.count(key)) continue;
            m_dialing[key] = now;
            LOG_INFO << "[" << m_chain_label << "] dialing " << key
                     << " (pool " << m_pool.size() << "/" << m_max_peers
                     << ", " << m_dialing.size() << " in flight)";
            core::Factory<core::Client>::connect(target);
            --slots;
            ++dialed;
        }
        if (dialed == 0 && m_pool.size() < m_max_peers)
        {
            LOG_DEBUG_COIND << "[" << m_chain_label << "] pool below target ("
                            << m_pool.size() << "/" << m_max_peers
                            << ") but no fresh dial target in a "
                            << n << "-entry plan";
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
        prune_stale_dials(now);
        maybe_log_pool_status(now);
    }

    /// Lost-body watchdog service (one pass per pool tick). A tracked
    /// getdata(block) unanswered for BODY_REREQUEST_SEC is re-issued — from a
    /// DIFFERENT handshaked peer when the pool holds one (the announcing peer
    /// may be slow/wedged; its neighbours demonstrably hold the block they
    /// all announced), rotating through the pool on successive attempts —
    /// bounded at BODY_REREQUEST_MAX, every re-request named in the log.
    void service_pending_bodies(int64_t now)
    {
        for (auto it = m_pending_bodies.begin(); it != m_pending_bodies.end();)
        {
            PendingBody& pb = *it;
            if (now - pb.last_req < BODY_REREQUEST_SEC) { ++it; continue; }
            if (pb.rerequests >= BODY_REREQUEST_MAX)
            {
                ++m_body_rerequests_exhausted;
                LOG_WARNING << "[" << m_chain_label
                            << "] body-rerequest EXHAUSTED hash="
                            << pb.hash.GetHex().substr(0, 16) << "... after "
                            << pb.rerequests << " re-request(s) over "
                            << (now - pb.first_req)
                            << "s — leaving recovery to the headers-driven"
                               " re-request / inv-TTL backstop";
                it = m_pending_bodies.erase(it);
                continue;
            }
            // Rotate through the handshaked peers, preferring one we did not
            // just ask; a single-peer pool re-asks the same peer (still
            // strictly better than the 600 s inv-TTL wait). The ANNOUNCER goes
            // first — it holds the block by definition — so a re-request tries
            // it before any neighbour that may not have it yet (the fixed-
            // subset-that-never-has-it rotation was the #1082 warm-node bug).
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
            pb.last_req  = now;
            pb.last_peer = target->key;
            LOG_INFO << "[" << m_chain_label << "] cause=body-rerequest attempt="
                     << pb.rerequests << " peer=" << target->key << " hash="
                     << pb.hash.GetHex().substr(0, 16) << "... unanswered_for="
                     << (now - pb.first_req) << "s";
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
                 << "/" << m_body_rerequests_exhausted;
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
            const bool pulled = inv_type_is_pulled(inv.m_type);
            const bool is_block = (inv.base_type() == inventory_type::block);
            const bool is_tx = (inv.base_type() == inventory_type::tx)
                            && m_tx_pull_enabled;
            // Offered-vs-admitted (diagnosis, not policy): counted BEFORE the
            // dedup so "peers are not announcing" can be told apart from "we
            // are filtering". Same announcement from N peers = N offered, 1
            // admitted — that gap is the fan-in the pool exists to produce.
            if (inv.base_type() == inventory_type::tx) ++m_tx_inv_offered;
            if (!pulled && !is_block && !is_tx)
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
            if (is_tx)
            {
                ++m_tx_inv_seen;
                expire_tx_pulls(now);
                // STRICT PRIORITY: the tip body always wins. A transaction is
                // worth a fraction of a block's fees; a late tip body is a
                // stale template on every attached rig.
                if (!m_pending_bodies.empty()) {
                    ++m_tx_pull_skipped_busy;
                    continue;
                }
                if (m_tx_pull_inflight.size() >= m_tx_pull_inflight_cap) {
                    ++m_tx_pull_skipped_budget;
                    continue;
                }
                if (m_tx_pull_inflight.count(inv.m_hash)) continue;
                m_tx_pull_inflight.emplace(inv.m_hash, now);
                ++m_tx_pull_sent;
                auto getdata_msg = message_getdata::make_raw(
                    {inventory_type(inventory_type::tx, inv.m_hash)});
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
