#pragma once

// Phase S8 — Dash coin-daemon P2P node (socket-node skeleton LEAF).
//
// Minimal node lifecycle layer that sits one rung above the per-peer
// request/response router:
//
//     p2p_messages -> p2p_connection -> [p2p_node] -> broadcaster
//
// This leaf owns ONLY the socket-node skeleton:
//
//   * lifecycle: construct -> attach a live peer (Connection over a socket)
//     -> teardown. attach()/teardown() are idempotent and timer-safe.
//   * the outbound-request -> inbound-reply exchange, driven entirely through
//     the already-landed Connection matcher (request_block/header out,
//     deliver_block/header in). The node arms the matchers on attach and
//     forwards exchange calls to the live peer; with no peer the calls are
//     dropped (no throw — a torn-down node must not crash the caller).
//   * the timeout path: a single idle/liveness Timer. Every inbound reply or
//     explicit note_activity() restarts it; if it ever fires we run
//     on_timeout(reason) -> teardown and notify an optional observer. This is
//     the p2pool "no peer activity within N seconds => drop" liveness guard,
//     decoupled from the per-request deferral timeout that Connection already
//     owns (reply_matcher.hpp).
//
// EXPLICITLY OUT OF SCOPE for this leaf (later S8 slices): the dashd handshake
// (version/verack), GBT fetch, block-submit / submit_block_raw, quorum and
// mnlistdiff sync, reconnect/ping cadence, and the INetwork/Factory<Client>
// socket-acceptor wiring. None of that surface is pulled in here.
//
// Header-only to match the sibling leaves (p2p_connection.hpp, p2p_messages.hpp).

#include "p2p_connection.hpp"
#include "block.hpp"

#include <functional>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/socket.hpp>
#include <core/timer.hpp>

namespace dash
{
namespace coin
{
namespace p2p
{

// Socket-node skeleton over Connection. Concrete (not yet templated on
// coin/config — that threading arrives with the broadcaster slice), so the
// type stays trivially constructible and testable.
class NodeP2P
{
public:
    // Seconds of peer silence tolerated before the liveness timer fires and the
    // node tears the peer down. Distinct from Connection's per-request deferral
    // timeout (reply_matcher.hpp) — that bounds a single in-flight request; this
    // bounds the whole peer's idleness.
    static constexpr time_t IDLE_TIMEOUT_SEC = 100;

    using TimeoutObserver = std::function<void(const std::string& /*reason*/)>;

private:
    boost::asio::io_context* m_context{};
    std::unique_ptr<Connection> m_peer;
    std::unique_ptr<core::Timer> m_idle_timer;
    TimeoutObserver m_on_timeout;
    // Liveness deadline actually used by arm_idle_timer(); defaults to
    // IDLE_TIMEOUT_SEC. Overridable (set_idle_timeout_sec) so tests can
    // drive a real, short timer-fire of the timeout path.
    time_t m_idle_timeout_sec{IDLE_TIMEOUT_SEC};

    void ensure_idle_timer()
    {
        if (!m_idle_timer)
            m_idle_timer = std::make_unique<core::Timer>(m_context, /*repeat*/false);
    }

public:
    explicit NodeP2P(boost::asio::io_context* context)
        : m_context(context) {}

    ~NodeP2P() { teardown(); }

    NodeP2P(const NodeP2P&) = delete;
    NodeP2P& operator=(const NodeP2P&) = delete;

    // Observer fired when the liveness timer expires (peer went silent). The
    // node has already torn the peer down by the time this runs.
    void set_on_timeout(TimeoutObserver cb) { m_on_timeout = std::move(cb); }

    // Override the liveness deadline (seconds) before attach(). The default
    // is IDLE_TIMEOUT_SEC; production never changes it.
    void set_idle_timeout_sec(time_t s) { m_idle_timeout_sec = s; }

    // ── lifecycle ────────────────────────────────────────────────────────

    // Attach a freshly-connected peer socket. Builds the Connection, arms its
    // request matchers with the supplied outbound-wire callbacks, and starts
    // the liveness timer. Replaces any existing peer (idempotent re-attach).
    void attach(std::shared_ptr<core::Socket> socket,
                std::function<void(uint256)> block_req,
                std::function<void(uint256)> header_req)
    {
        teardown();
        m_peer = std::make_unique<Connection>(m_context, socket);
        m_peer->init_requests(std::move(block_req), std::move(header_req));
        arm_idle_timer();
    }

    // Drop the peer and stop the liveness timer. Safe to call when not attached
    // and safe to call from inside a timer callback.
    void teardown()
    {
        if (m_idle_timer)
            m_idle_timer->stop();
        m_peer.reset();
    }

    bool is_attached() const { return m_peer != nullptr; }

    auto peer_addr() const { return m_peer ? m_peer->get_addr() : NetService{}; }

    // ── liveness / timeout path ──────────────────────────────────────────

    // (Re)start the idle countdown. Called on attach and whenever fresh peer
    // activity is observed.
    void arm_idle_timer()
    {
        if (!m_peer) return;
        ensure_idle_timer();
        m_idle_timer->start(m_idle_timeout_sec, [this]() { on_timeout("idle timeout"); });
    }

    // Note inbound peer activity — pushes the idle deadline forward.
    void note_activity()
    {
        if (m_peer && m_idle_timer)
            m_idle_timer->restart(m_idle_timeout_sec);
    }

    // Invoked by the liveness timer (or directly, for the deterministic test
    // path). Tears the peer down, then notifies the observer.
    void on_timeout(const std::string& reason)
    {
        LOG_WARNING << "[DashP2P] peer timeout: " << reason;
        teardown();
        if (m_on_timeout)
            m_on_timeout(reason);
    }

    // ── outbound-request -> inbound-reply exchange (through Connection) ───

    // Outbound: emit a get-block request keyed by `id` for `hash`. The reply is
    // delivered later via deliver_block(id, ...). Dropped silently if no peer.
    void request_block(uint256 id, uint256 hash, std::function<void(BlockType)> handler)
    {
        if (!m_peer) return;
        m_peer->request_block(id, hash, std::move(handler));
    }

    // Inbound: route a block reply to its pending request handler and refresh
    // liveness. Dropped silently if no peer.
    void deliver_block(uint256 id, BlockType response)
    {
        if (!m_peer) return;
        note_activity();
        m_peer->get_block(id, response);
    }

    void request_header(uint256 id, uint256 hash, std::function<void(BlockHeaderType)> handler)
    {
        if (!m_peer) return;
        m_peer->request_header(id, hash, std::move(handler));
    }

    void deliver_header(uint256 id, BlockHeaderType response)
    {
        if (!m_peer) return;
        note_activity();
        m_peer->get_header(id, response);
    }
};

} // namespace p2p
} // namespace coin
} // namespace dash
