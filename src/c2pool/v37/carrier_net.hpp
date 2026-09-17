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
// ── ★ THE FIRST-BYTE NAMESPACE (Stage 1 supply, frozen here) ────────────────
// The framing carries NO type byte: frame[0] has always been the CarrierWire
// version (0x01 / 0x02 live). That byte is now split, permanently:
//
//      0x01 .. 0x7f   CarrierWire VERSIONS   (carrier bodies -> handle_inbound)
//      0x80 .. 0xff   CONTROL OPCODES        (repair channel -> the control fn)
//
// reader_loop() DEMUXES on frame[0] >= kCtrlOpcodeBase BEFORE handle_inbound, so
// a control frame never reaches CarrierWire::decode on a repair-aware node. The
// opcodes are NOT wire versions: they are absent from w3_wire_freeze.hpp's
// kAcceptedVersions, they move no frozen v0x01 / v0x02 golden, and they carry no
// consensus whatsoever. carrier_supply.hpp defines the frames themselves.
//
// BACKWARD TOLERANCE, BOTH DIRECTIONS — why this split deploys piecemeal:
//   * an OLD peer (built before this) has no demux, so a 0x8x frame goes
//     straight into CarrierWire::decode, which answers REJECT_BAD_VERSION. That
//     is a VERDICT, not an error: handle_inbound returns it, the reader loop
//     does not break, and the SOCKET STAYS UP. reader_loop breaks only on a
//     short read or an over-long length prefix — never on a decode verdict.
//   * a REPAIR-AWARE peer that meets an opcode it does not implement counts it
//     (SupplyServeStats::unknown_opcode) and ignores it — likewise never a drop.
// Neither side needs a flag day, and neither side can be disconnected by a
// control frame it does not understand.
//
// ── ★ PEER IDENTITY + TARGETED SEND ────────────────────────────────────────
// The repair channel is a CONVERSATION with one peer, so flood-only broadcast()
// is not enough. Every established connection now carries a PeerId — a monotone
// counter, FRESH on every connection, never reused after a drop — and send_to()
// addresses exactly that connection. Because the id dies with the connection,
// all per-peer state anyone keys on it (token buckets, outstanding requests) is
// flap-safe by construction: a peer that reconnects gets a NEW id and a NEW
// budget, and can neither inherit nor poison the state of any other peer.
//
// ── ★ SO_SNDTIMEO + DROP-SLOW-PEER (closing c2pool#1655 Defect-B) ───────────
// c2pool#1655 gave each connection its own write lock, so one peer that stopped
// reading no longer stalled the flood to the others. It did NOT bound the write
// itself: send_all() blocks as long as the kernel makes it. Broadcast could
// tolerate that (the frames are small and the peer set is served in parallel);
// the SERVE path cannot — a GETFRAMES answer is up to kCtrlMaxReplyBytes and a
// peer can request one and then never read, pinning a reader thread forever.
// Every connection therefore gets SO_SNDTIMEO (default 10 s). A write that
// times out mid-frame leaves that stream DESYNCED — half a frame is on it — so
// the peer is dropped HARD: shutdown(SHUT_RDWR) so its reader thread unwinds,
// then removed from the peer set. That is the only correct move; leaving a
// half-written frame on a live socket would feed a truncated body into the
// peer's decoder.
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

#include <sys/time.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
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

// ── the first-byte namespace split (see the header note) ────────────────────
// frame[0] < kCtrlOpcodeBase  => a CarrierWire body  (0x01..0x7f are versions)
// frame[0] >= kCtrlOpcodeBase => a control opcode    (carrier_supply.hpp)
// This constant lives here, not in carrier_supply.hpp, so the demux needs no
// dependency on the repair layer: a build with no supply service still routes
// correctly (and, with no control handler bound, ignores-and-counts).
constexpr std::uint8_t kCtrlOpcodeBase = 0x80;

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

    // ── ★ peer identity ─────────────────────────────────────────────────────
    // A monotone handle for ONE connection. Fresh on every connect, NEVER
    // reused after a drop, so per-peer state keyed on it dies with the socket
    // (the flap-safety property the repair channel relies on). 0 is "no peer".
    using PeerId = std::uint64_t;

    // A control frame (frame[0] >= kCtrlOpcodeBase), demuxed BEFORE any
    // CarrierWire decode, tagged with the connection it arrived on. Bind it to
    // the repair layer (carrier_supply.hpp SupplyService + SupplyRequester).
    // UNBOUND is a valid configuration: the frame is ignored and counted, and
    // the peer is NEVER dropped for it.
    using ControlFn = std::function<void(PeerId, const std::vector<std::uint8_t>&)>;

    // Connection lifecycle with the id, so a listener can release the
    // per-peer state it keeps (token bucket, outstanding request). Fired on the
    // accept/dial thread for `true`, on the reader thread for `false`, with NO
    // transport lock held; it MUST be O(1) and MUST NOT call back into us.
    using PeerEventFn = std::function<void(PeerId, bool /*connected*/)>;

    CarrierPeerNode() = default;
    ~CarrierPeerNode() override { stop(); }

    CarrierPeerNode(const CarrierPeerNode&) = delete;
    CarrierPeerNode& operator=(const CarrierPeerNode&) = delete;

    void set_inbound(InboundFn f) { m_inbound = std::move(f); }
    void set_on_peer_connect(PeerConnectFn f) { m_on_connect = std::move(f); }
    void set_control(ControlFn f) { m_control = std::move(f); }
    void set_on_peer_event(PeerEventFn f) { m_on_peer_event = std::move(f); }

    // Bound write time per connection (SO_SNDTIMEO). Applied to connections
    // established AFTER the call. 0 restores "block indefinitely" (the
    // pre-c2pool#1655 behaviour); the default is 10 s. See the header note.
    void set_send_timeout(std::chrono::milliseconds t) {
        m_send_timeout_ms.store(static_cast<long>(t.count()));
    }

    // Control frames seen with NO control handler bound: ignored, counted, peer
    // kept. This is the "unknown opcode never drops the peer" counter for a
    // node built with the demux but without the repair layer.
    std::uint64_t ctrl_frames_ignored() const { return m_ctrl_ignored.load(); }
    std::uint64_t ctrl_frames_routed() const { return m_ctrl_routed.load(); }
    std::uint64_t peers_dropped_slow() const { return m_slow_drops.load(); }

    // ── ★ targeted send (the repair channel's reply path) ───────────────────
    // Write ONE frame to ONE connection. Returns false if the peer is gone or
    // the write failed/timed out (in which case the peer has been dropped HARD,
    // because a timed-out write leaves the stream desynced). Takes only that
    // connection's own write lock, so it can never stall another peer.
    bool send_to(PeerId id, const std::vector<std::uint8_t>& frame) {
        int fd = -1;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_id_fd.find(id);
            if (it == m_id_fd.end()) return false;
            fd = it->second;
        }
        std::uint8_t lenbuf[4];
        const std::uint32_t len = static_cast<std::uint32_t>(frame.size());
        for (int i = 0; i < 4; ++i) lenbuf[i] = static_cast<std::uint8_t>(len >> (8 * i));
        std::shared_ptr<std::mutex> wl = write_lock(fd);
        {
            std::lock_guard<std::mutex> wlk(*wl);
            if (send_all(fd, lenbuf, 4) && (len == 0 || send_all(fd, frame.data(), len)))
                return true;
        }
        drop_peer(fd, /*hard=*/true);
        return false;
    }

    // The id of the connection a fd belongs to (test/diagnostic helper).
    std::vector<PeerId> peer_ids() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::vector<PeerId> v;
        v.reserve(m_id_fd.size());
        for (const auto& [id, fd] : m_id_fd) { (void)fd; v.push_back(id); }
        return v;
    }

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
        // HARD drop: with SO_SNDTIMEO armed, a failed send_all may be a TIMEOUT
        // that left a partial frame on the stream. A desynced connection must
        // not be left live — the peer would decode a truncated body.
        for (int fd : dead) drop_peer(fd, /*hard=*/true);
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
          m_peers.clear();
          m_fd_id.clear();
          m_id_fd.clear(); }
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
        // ★ BOUND THE WRITE (c2pool#1655 Defect-B). Without this a peer that
        // stops reading pins whichever thread is writing to it for as long as
        // it likes; with the repair channel serving multi-frame replies on the
        // reader thread, that is a per-peer denial of service on us.
        const long tmo = m_send_timeout_ms.load();
        if (tmo > 0) {
            timeval tv{};
            tv.tv_sec = static_cast<time_t>(tmo / 1000);
            tv.tv_usec = static_cast<suseconds_t>((tmo % 1000) * 1000);
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        bool established = false;
        PeerId pid = 0;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (!m_running.load()) { ::close(fd); return; }   // stopping: never orphan a reader
            pid = ++m_next_peer_id;
            m_peers.push_back(fd);
            m_fd_id[fd] = pid;
            m_id_fd[pid] = fd;
            m_readers.emplace_back([this, fd, pid] { reader_loop(fd, pid); });
            established = true;
        }
        if (established) {
            (void)write_lock(fd);               // fresh lock for a fresh connection
            // OUTSIDE m_mtx on purpose: the callback arms the relay's re-offer
            // sweep, and the relay's own broadcast path takes m_mtx — firing it
            // under the lock would invert the order (relay -> transport).
            PeerConnectFn cb = m_on_connect;
            if (cb) cb();
            PeerEventFn ev = m_on_peer_event;
            if (ev) ev(pid, true);
        }
    }

    void reader_loop(int fd, PeerId pid) {
        for (;;) {
            std::uint8_t lenbuf[4];
            if (!recv_all(fd, lenbuf, 4)) break;
            std::uint32_t len = 0;
            for (int i = 0; i < 4; ++i) len |= static_cast<std::uint32_t>(lenbuf[i]) << (8 * i);
            if (len > kMaxCarrierFrame) break;                 // protocol error -> drop
            std::vector<std::uint8_t> frame(len);
            if (len && !recv_all(fd, frame.data(), len)) break;
            // ── ★ CONTROL DEMUX, BEFORE handle_inbound ──────────────────────
            // frame[0] >= 0x80 is the repair channel, not a carrier body. It
            // never reaches CarrierWire::decode here. With no handler bound the
            // frame is IGNORED and COUNTED — the socket stays up either way, so
            // an opcode we do not implement can never cost us a peer.
            if (!frame.empty() && frame[0] >= kCtrlOpcodeBase) {
                ControlFn cf = m_control;
                if (cf) { m_ctrl_routed.fetch_add(1); cf(pid, frame); }
                else    { m_ctrl_ignored.fetch_add(1); }
                continue;
            }
            // -> CarrierRelay::handle_inbound. ONE reader thread PER PEER calls
            // this concurrently; CarrierRelay serializes its handlers under its
            // own mutex (w3_relay.hpp THREADING), so the handler needs no lock
            // of its own. A slow admit (the live index's bounded Unknown retry,
            // carrier_index.hpp) stalls only this peer's reader.
            if (m_inbound) m_inbound(frame);
        }
        drop_peer(fd);
    }

    // `hard` => the stream is unusable (a timed-out write left half a frame on
    // it), so shut the socket down: the peer's reader thread unwinds instead of
    // sitting in recv() on a connection nobody will ever write to again.
    void drop_peer(int fd, bool hard = false) {
        PeerId pid = 0;
        bool had = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            for (auto it = m_peers.begin(); it != m_peers.end(); ++it)
                if (*it == fd) { m_peers.erase(it); had = true; break; }
            auto fit = m_fd_id.find(fd);
            if (fit != m_fd_id.end()) {
                pid = fit->second;
                m_id_fd.erase(pid);
                m_fd_id.erase(fit);
            }
            // The fd is closed by stop() (join order) or here once fully removed;
            // closing once is enough — mark by removing from the set above.
        }
        if (hard) {
            if (had) m_slow_drops.fetch_add(1);
            ::shutdown(fd, SHUT_RDWR);
        }
        if (pid) { PeerEventFn ev = m_on_peer_event; if (ev) ev(pid, false); }
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
    ControlFn                 m_control;        // frame[0] >= 0x80 (repair channel)
    PeerEventFn               m_on_peer_event;  // (PeerId, connected)
    std::atomic<std::uint64_t> m_ctrl_routed{0};
    std::atomic<std::uint64_t> m_ctrl_ignored{0};
    std::atomic<std::uint64_t> m_slow_drops{0};
    // SO_SNDTIMEO, ms. 10 s by default: long enough that no healthy peer ever
    // trips it, short enough that a peer which stopped reading cannot pin one
    // of our threads indefinitely. 0 => block forever (pre-Stage-1 behaviour).
    std::atomic<long>         m_send_timeout_ms{10000};
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
    // ★ peer identity. Ids are never reused, so per-peer state keyed on a
    // PeerId dies with the connection — the flap-safety property the repair
    // channel depends on. Both maps are guarded by m_mtx.
    PeerId                    m_next_peer_id = 0;
    std::map<int, PeerId>     m_fd_id;
    std::map<PeerId, int>     m_id_fd;
};

} // namespace c2pool::v37n
