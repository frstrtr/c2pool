#pragma once
// V37 Track A2 — carrier peer transport: the production binding of the W3
// ICarrierTransport seam over a real socket layer. CONSUMER-tree code
// (src/c2pool/v37/). It carries W3 carrier FRAMES (CarrierWire::encode output)
// between nodes and pumps received frames into a CarrierRelay. It is NOT
// consensus code: it owns no lane state, computes no digest, and every append
// it causes goes through CarrierRelay -> CarrierIngest -> V37Engine (O1).
//
// WHY A SEPARATE TRANSPORT: w3_relay.hpp documents the production transport as a
// binding to the v36 pool::Peer::write / NodeImpl::broadcast_share path, but the
// v37 btc-dash daemon (main_v37_btc_dash.cpp) stands up NO v36 pool::Node — it
// is stratum + dashd-RPC only, single-node by construction (no --peer). Rather
// than drag the whole v36 sharechain-p2p handshake into the daemon just to move
// carrier bodies, this slice binds the SAME ICarrierTransport seam to a small,
// self-contained TCP peer layer: length-prefixed carrier frames over loopback/
// LAN sockets. That is exactly the "loopback-socket transport in the KAT is a
// test binding of the SAME seam" note in w3_relay.hpp, promoted to a real,
// reusable, bidirectional peer node.
//
// WIRE (framing only; the carrier bytes inside are W3's, unchanged):
//   [u32 LE length][length bytes = CarrierWire frame]
// A length over kMaxFrame is a protocol error -> the peer is dropped (never a
// huge alloc). Framing is deliberately trivial: W3 owns the carrier semantics,
// this owns only "one frame in, one frame out" over a stream socket.
//
// DUPLEX: every established connection — whether we accepted it or dialed it —
// is a full peer: it is added to the broadcast set AND gets a reader thread, so
// carriers flow both directions over one socket (node A's win reaches node B,
// and B's win reaches A).
//
// PORTABILITY: POSIX sockets + std::thread only (Linux/macOS). No Boost, so it
// links into the stdlib-only v37 test harness and needs no io_context. The
// daemon runs it on its own threads, independent of its Boost.Asio ioc.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "w3_relay.hpp"   // ICarrierTransport

namespace c2pool::v37n {

// A carrier frame larger than this is refused (the peer is dropped). A carrier
// is a share + <= R_MAX receipts; even generous per-event bounds keep this far
// under 64 KiB. Sized well above that so a legitimate frame is never clipped.
constexpr std::uint32_t kMaxCarrierFrame = 1u << 20;   // 1 MiB hard ceiling

// ── the peer transport ──────────────────────────────────────────────────────
class CarrierPeerNode final : public ICarrierTransport {
public:
    // Received-frame handler: bind to [relay](const auto& f){ relay.handle_inbound(f); }.
    using InboundFn = std::function<void(const std::vector<std::uint8_t>&)>;
    // Fired once per ESTABLISHED connection (accepted or dialled), on the
    // accepting/dialling thread, with NO transport lock held. Bind it to
    // CarrierRelay::note_peer_connected() so a (re)connecting peer arms the
    // bounded carrier re-offer sweep (w3_relay.hpp §RE-OFFER). It MUST be O(1)
    // and MUST NOT call back into this node (it runs on the accept loop).
    using PeerConnectFn = std::function<void()>;

    CarrierPeerNode() = default;
    ~CarrierPeerNode() override { stop(); }

    CarrierPeerNode(const CarrierPeerNode&) = delete;
    CarrierPeerNode& operator=(const CarrierPeerNode&) = delete;

    void set_inbound(InboundFn f) { m_inbound = std::move(f); }
    void set_on_peer_connect(PeerConnectFn f) { m_on_connect = std::move(f); }

    // Bind + listen on host:port. port==0 selects an ephemeral port, readable
    // afterward via listen_port() (the multi-node test binds 0 and dials the
    // reported port). Returns false on any socket error (caller decides).
    bool listen(const std::string& host, std::uint16_t port) {
        int ls = ::socket(AF_INET, SOCK_STREAM, 0);
        if (ls < 0) return false;
        int one = 1;
        ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) {
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        if (::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(ls); return false; }
        socklen_t alen = sizeof(a);
        if (::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &alen) != 0) { ::close(ls); return false; }
        m_listen_port = ntohs(a.sin_port);
        if (::listen(ls, 16) != 0) { ::close(ls); return false; }
        m_listen_fd = ls;
        m_accept_thread = std::thread([this] { accept_loop(); });
        return true;
    }

    std::uint16_t listen_port() const { return m_listen_port; }

    // Dial a peer (the --peer path). Returns true if the connection was
    // established and added as a full duplex peer. Safe to call before or after
    // listen(); a failed dial is a no-op the caller may retry.
    bool add_peer(const std::string& host, std::uint16_t port) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return false; }
        if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(fd); return false; }
        add_established(fd);
        return true;
    }

    // ── ICarrierTransport ────────────────────────────────────────────────────
    // Flood the frame to every connected peer; return the count that took the
    // whole frame. 0 => DEFER (w3_relay.hpp §"the transport seam": the relay
    // leaves the append standing and retries later — a block-winner is never
    // dropped for want of a peer).
    //
    // ★ PER-DESCRIPTOR WRITE LOCKS (head-of-line fix). Each connection has its
    // OWN write mutex (m_write_locks, keyed by fd), held across [length prefix +
    // body] so two writers can never interleave a frame on ONE socket, while a
    // peer that has stopped reading — and therefore holds its own lock for the
    // whole of a large blocking write — no longer blocks writes to any OTHER
    // peer. Before this, a single shared m_write_mtx guarded every send_all, so
    // one slow reader stalled the flood to the entire peer set (and, because the
    // relay drives broadcast() under its own mutex, stalled the relay with it).
    //
    // TWO PASSES for the same reason WITHIN one call: pass 1 takes only the
    // locks that are free right now (try_lock) and serves those peers
    // immediately; pass 2 blocks on whatever is left. So a peer whose lock is
    // held by another in-flight write is served LAST instead of delaying every
    // peer behind it. Cross-peer frame ORDER was never guaranteed here (two
    // concurrent broadcasts already interleave across the peer loop) — the
    // guarantee this class makes, and keeps, is PER-CONNECTION: frames arrive
    // whole and in the order they were written on that connection.
    std::size_t broadcast(const std::vector<std::uint8_t>& frame) override {
        std::uint8_t lenbuf[4];
        const std::uint32_t len = static_cast<std::uint32_t>(frame.size());
        for (int i = 0; i < 4; ++i) lenbuf[i] = static_cast<std::uint8_t>(len >> (8 * i));

        std::vector<int> targets;
        { std::lock_guard<std::mutex> lk(m_mtx); targets = m_peers; }

        std::size_t reached = 0;
        std::vector<int> dead;
        std::vector<std::pair<int, std::shared_ptr<std::mutex>>> deferred;
        deferred.reserve(targets.size());

        // pass 1 — every peer whose write lock is free right now.
        for (int fd : targets) {
            std::shared_ptr<std::mutex> wl = write_lock(fd);
            std::unique_lock<std::mutex> wlk(*wl, std::try_to_lock);
            if (!wlk.owns_lock()) { deferred.emplace_back(fd, std::move(wl)); continue; }
            if (send_all(fd, lenbuf, 4) && (len == 0 || send_all(fd, frame.data(), len)))
                ++reached;
            else
                dead.push_back(fd);
        }
        // pass 2 — the peers that were busy; blocking, one connection at a time.
        for (auto& [fd, wl] : deferred) {
            std::lock_guard<std::mutex> wlk(*wl);
            if (send_all(fd, lenbuf, 4) && (len == 0 || send_all(fd, frame.data(), len)))
                ++reached;
            else
                dead.push_back(fd);
        }
        for (int fd : dead) drop_peer(fd);
        return reached;
    }

    std::size_t n_peers() const override {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_peers.size();
    }

    void stop() {
        if (!m_running.exchange(false)) return;
        // Wake the accept loop out of accept() by shutting the listen fd down.
        // Do NOT write m_listen_fd here — accept_loop() is still reading it; the
        // -1 is stamped only after the join below (no concurrent reader then).
        const int lfd = m_listen_fd;
        if (lfd >= 0) { ::shutdown(lfd, SHUT_RDWR); ::close(lfd); }
        std::vector<int> peers;
        { std::lock_guard<std::mutex> lk(m_mtx); peers = m_peers; }
        for (int fd : peers) ::shutdown(fd, SHUT_RDWR);
        if (m_accept_thread.joinable()) m_accept_thread.join();
        m_listen_fd = -1;                       // safe: accept_loop has joined
        for (auto& t : m_readers) if (t.joinable()) t.join();
        m_readers.clear();
        { std::lock_guard<std::mutex> lk(m_mtx);
          for (int fd : m_peers) ::close(fd);
          m_peers.clear(); }
        // A blocked writer may still hold a shared_ptr to one of these; the
        // map drops its own reference and the mutex dies with the last holder.
        { std::lock_guard<std::mutex> lk(m_wl_mtx); m_write_locks.clear(); }
    }

private:
    void accept_loop() {
        // m_listen_fd is set in listen() BEFORE this thread is created (a
        // happens-before), so a single read into a local is race-free; stop()
        // never rewrites it until after this thread joins.
        const int lfd = m_listen_fd;
        while (m_running.load()) {
            int cfd = ::accept(lfd, nullptr, nullptr);
            if (cfd < 0) { if (!m_running.load()) break; continue; }
            add_established(cfd);
        }
    }

    void add_established(int fd) {
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        bool established = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (!m_running.load()) { ::close(fd); return; }   // stopping: never orphan a reader
            m_peers.push_back(fd);
            m_readers.emplace_back([this, fd] { reader_loop(fd); });
            established = true;
        }
        if (established) {
            (void)write_lock(fd);               // fresh lock for a fresh connection
            // OUTSIDE m_mtx on purpose: the callback arms the relay's re-offer
            // sweep, and the relay's own broadcast path takes m_mtx — firing it
            // under the lock would invert the order (relay -> transport).
            PeerConnectFn cb = m_on_connect;
            if (cb) cb();
        }
    }

    void reader_loop(int fd) {
        for (;;) {
            std::uint8_t lenbuf[4];
            if (!recv_all(fd, lenbuf, 4)) break;
            std::uint32_t len = 0;
            for (int i = 0; i < 4; ++i) len |= static_cast<std::uint32_t>(lenbuf[i]) << (8 * i);
            if (len > kMaxCarrierFrame) break;                 // protocol error -> drop
            std::vector<std::uint8_t> frame(len);
            if (len && !recv_all(fd, frame.data(), len)) break;
            // -> CarrierRelay::handle_inbound. ONE reader thread PER PEER calls
            // this concurrently; CarrierRelay serializes its handlers under its
            // own mutex (w3_relay.hpp THREADING), so the handler needs no lock
            // of its own. A slow admit (the live index's bounded Unknown retry,
            // carrier_index.hpp) stalls only this peer's reader.
            if (m_inbound) m_inbound(frame);
        }
        drop_peer(fd);
    }

    void drop_peer(int fd) {
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto it = m_peers.begin(); it != m_peers.end(); ++it)
                if (*it == fd) { m_peers.erase(it); break; }
            // The fd is closed by stop() (join order) or here once fully removed;
            // closing once is enough — mark by removing from the set above.
        }
        // Drop the map's reference to this connection's write lock so the table
        // stays bounded by the LIVE peer count. A writer blocked on the socket
        // right now still holds its own shared_ptr, so the mutex it is waiting
        // on stays alive until it returns. The fd itself is not closed before
        // stop() (unchanged behaviour), so it cannot be handed to a new
        // connection while an old lock object is still in flight.
        std::lock_guard<std::mutex> lk(m_wl_mtx);
        m_write_locks.erase(fd);
    }

    // One write lock PER DESCRIPTOR: held across a frame's length prefix AND
    // body, so two writers never interleave on one socket, and a peer that
    // stopped reading blocks only its own connection. Created on connect,
    // dropped on disconnect, created on demand if a broadcast races a connect.
    std::shared_ptr<std::mutex> write_lock(int fd) {
        std::lock_guard<std::mutex> lk(m_wl_mtx);
        auto it = m_write_locks.find(fd);
        if (it != m_write_locks.end()) return it->second;
        auto m = std::make_shared<std::mutex>();
        m_write_locks.emplace(fd, m);
        return m;
    }

    static bool send_all(int fd, const void* buf, std::size_t n) {
        const std::uint8_t* p = static_cast<const std::uint8_t*>(buf);
        std::size_t off = 0;
        while (off < n) {
            ssize_t k = ::send(fd, p + off, n - off, MSG_NOSIGNAL);
            if (k <= 0) return false;
            off += static_cast<std::size_t>(k);
        }
        return true;
    }
    static bool recv_all(int fd, void* buf, std::size_t n) {
        std::uint8_t* p = static_cast<std::uint8_t*>(buf);
        std::size_t off = 0;
        while (off < n) {
            ssize_t k = ::recv(fd, p + off, n - off, 0);
            if (k <= 0) return false;
            off += static_cast<std::size_t>(k);
        }
        return true;
    }

    InboundFn                 m_inbound;
    PeerConnectFn             m_on_connect;
    int                       m_listen_fd = -1;
    std::uint16_t             m_listen_port = 0;
    // The node is "running" for its whole lifetime (construction -> stop()),
    // independent of whether it ever listen()s. A dial-only node (--peer with no
    // inbound bind) still spawns reader threads that stop() must join, so this
    // must start true or stop() would early-return and orphan them.
    std::atomic<bool>         m_running{true};
    std::thread               m_accept_thread;
    std::vector<std::thread>  m_readers;
    mutable std::mutex        m_mtx;          // guards m_peers / m_readers
    mutable std::mutex        m_wl_mtx;       // guards m_write_locks ONLY
    std::map<int, std::shared_ptr<std::mutex>> m_write_locks;   // fd -> its write lock
    std::vector<int>          m_peers;
};

} // namespace c2pool::v37n
