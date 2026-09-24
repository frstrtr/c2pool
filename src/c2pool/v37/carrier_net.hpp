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
#include <cerrno>
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
#include <list>
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
    // GAP-2 (the Family-B receipt relay, xmr/relay/): the same inbound path,
    // TAGGED with the connection the frame arrived on, so a handler can keep
    // per-peer state (HELLO gate, DoS budget, flood-except-source). When bound
    // it takes precedence over set_inbound; unbound, the reader loop is
    // byte-for-byte the pre-GAP-2 one.
    using InboundFromFn = std::function<void(PeerId, const std::vector<std::uint8_t>&)>;
    void set_inbound_from(InboundFromFn f) { m_inbound_from = std::move(f); }
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
    // Targeted sends refused because the frame was over kMaxCarrierFrame. The
    // receiver's reader loop MUST break on such a frame (the length prefix is
    // how it finds the next boundary), so writing one would cost us an honest
    // peer. Zero on every honest path — carrier_supply.hpp sizes every reply
    // under the ceiling by construction — and counted so a regression surfaces
    // here instead of as a mysterious disconnect.
    std::uint64_t sends_refused_oversize() const { return m_oversize_refused.load(); }

    // ── ★ targeted send (the repair channel's reply path) ───────────────────
    // Write ONE frame to ONE connection. Returns false if the peer is gone, the
    // frame is over the ceiling, or the write failed/timed out (in which case
    // the peer has been dropped HARD, because a timed-out write leaves the
    // stream desynced). Takes only that connection's own write lock, so it can
    // never stall another peer.
    bool send_to(PeerId id, const std::vector<std::uint8_t>& frame) {
        if (frame.size() > kMaxCarrierFrame) {
            // NOT a peer drop and NOT a silent success: a refusal the caller
            // sees, counted here. The connection is untouched.
            m_oversize_refused.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        std::shared_ptr<Conn> c;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_conns.find(id);
            if (it == m_conns.end()) return false;
            c = it->second;
        }
        std::uint8_t lenbuf[4];
        const std::uint32_t len = static_cast<std::uint32_t>(frame.size());
        for (int i = 0; i < 4; ++i) lenbuf[i] = static_cast<std::uint8_t>(len >> (8 * i));
        {
            std::lock_guard<std::mutex> wlk(c->wmtx);
            if (c->closed) return false;                  // gone while we looked it up
            if (send_all(c->fd, lenbuf, 4) && (len == 0 || send_all(c->fd, frame.data(), len)))
                return true;
        }
        drop_conn(c, /*hard=*/true);
        return false;
    }

    // The id of the connection a fd belongs to (test/diagnostic helper).
    std::vector<PeerId> peer_ids() const {
        std::lock_guard<std::mutex> lk(m_mtx);
        std::vector<PeerId> v;
        v.reserve(m_conns.size());
        for (const auto& [id, c] : m_conns) { (void)c; v.push_back(id); }
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

    // GAP-2: dial and return the new connection's PeerId (0 = the dial failed).
    // Same semantics as add_peer(); the id lets a caller keep per-target state
    // (the relay's redial-with-backoff). PeerEventFn(id, true) has already fired
    // by the time this returns.
    PeerId add_peer_id(const std::string& host, std::uint16_t port) {
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return 0;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { ::close(fd); return 0; }
        if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(fd); return 0; }
        return add_established(fd);
    }

    // GAP-2: drop ONE connection on purpose (a protocol refusal: HELLO
    // mismatch, a ban, over the peer cap). The reader unwinds and
    // PeerEventFn(id, false) fires. Not counted as a slow-peer drop. No-op for an
    // id that is already gone. Must not be called with a lock held that the
    // PeerEventFn handler takes (it may fire synchronously from here).
    void disconnect(PeerId id) {
        std::shared_ptr<Conn> c;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_conns.find(id);
            if (it == m_conns.end()) return;
            c = it->second;
        }
        drop_conn(c, /*hard=*/true, /*slow=*/false);
    }

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
    // OWN write mutex (Conn::wmtx), held across [length prefix +
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

        std::vector<std::shared_ptr<Conn>> targets;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            targets.reserve(m_conns.size());
            for (const auto& [id, c] : m_conns) { (void)id; targets.push_back(c); }
        }

        std::size_t reached = 0;
        std::vector<std::shared_ptr<Conn>> dead;
        std::vector<std::shared_ptr<Conn>> deferred;
        deferred.reserve(targets.size());

        // pass 1 — every peer whose write lock is free right now.
        for (auto& c : targets) {
            std::unique_lock<std::mutex> wlk(c->wmtx, std::try_to_lock);
            if (!wlk.owns_lock()) { deferred.push_back(c); continue; }
            if (c->closed) continue;                      // reader already closed it
            if (send_all(c->fd, lenbuf, 4) && (len == 0 || send_all(c->fd, frame.data(), len)))
                ++reached;
            else
                dead.push_back(c);
        }
        // pass 2 — the peers that were busy; blocking, one connection at a time.
        for (auto& c : deferred) {
            std::lock_guard<std::mutex> wlk(c->wmtx);
            if (c->closed) continue;
            if (send_all(c->fd, lenbuf, 4) && (len == 0 || send_all(c->fd, frame.data(), len)))
                ++reached;
            else
                dead.push_back(c);
        }
        // HARD drop: with SO_SNDTIMEO armed, a failed send_all may be a TIMEOUT
        // that left a partial frame on the stream. A desynced connection must
        // not be left live — the peer would decode a truncated body.
        for (auto& c : dead) drop_conn(c, /*hard=*/true);
        return reached;
    }

    std::size_t n_peers() const override {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_conns.size();
    }

    void stop() {
        if (!m_running.exchange(false)) return;
        // Wake the accept loop out of accept() by shutting the listen fd down.
        // Do NOT write m_listen_fd here — accept_loop() is still reading it; the
        // -1 is stamped only after the join below (no concurrent reader then).
        const int lfd = m_listen_fd;
        if (lfd >= 0) ::shutdown(lfd, SHUT_RDWR);
        if (m_accept_thread.joinable()) m_accept_thread.join();
        // Closed only after the join: accept_loop() reads the descriptor until
        // it returns, and a closed number could be reused by a concurrent open.
        if (lfd >= 0) ::close(lfd);
        m_listen_fd = -1;                       // safe: accept_loop has joined
        // m_running is false, so add_established() admits nothing after this
        // snapshot (it checks under m_mtx). Every reader closes its OWN
        // descriptor as it unwinds (reader_loop); shutting each live socket
        // down and joining every reader therefore releases every fd.
        std::list<Reader> readers;
        std::vector<std::shared_ptr<Conn>> conns;
        { std::lock_guard<std::mutex> lk(m_mtx);
          readers.swap(m_readers);
          for (const auto& [id, c] : m_conns) { (void)id; conns.push_back(c); } }
        for (auto& c : conns) shutdown_conn(*c);
        for (auto& r : readers) if (r.t.joinable()) r.t.join();
        { std::lock_guard<std::mutex> lk(m_mtx); m_conns.clear(); }
    }

    // ── diagnostics (RELAY-FD) ──────────────────────────────────────────────
    // accept() failures on resource exhaustion (EMFILE / ENFILE / ENOBUFS /
    // ENOMEM): each one is a backed-off retry, never a spin.
    std::uint64_t accept_exhausted() const { return m_accept_exhausted.load(); }
    // Reader threads spawned and not yet joined (bounded by live connections
    // plus the ones that unwound since the last connect).
    std::size_t reader_threads() const { std::lock_guard<std::mutex> lk(m_mtx); return m_readers.size(); }
    // Rate-limited transport diagnostics (the accept loop's exhaustion notice).
    using LogFn = std::function<void(const std::string&)>;
    void set_log(LogFn f) { m_log = std::move(f); }

private:
    // ONE connection. Every path that writes to, shuts down or closes the
    // socket goes through this object, so a descriptor number the kernel
    // reuses for a later connection can never be reached through a stale one.
    //   wmtx : the per-connection WRITE lock (held across [length + body], so
    //          frames never interleave and a slow peer blocks only itself)
    //   fmtx : descriptor lifetime (shutdown vs close), never held across I/O
    //   closed: set by the reader under BOTH locks when it closes the fd
    struct Conn {
        int fd = -1;
        PeerId pid = 0;
        std::mutex wmtx;
        std::mutex fmtx;
        bool closed = false;
    };
    struct Reader {
        std::thread t;
        std::shared_ptr<std::atomic<bool>> done;
    };

    void accept_loop() {
        // m_listen_fd is set in listen() BEFORE this thread is created (a
        // happens-before), so a single read into a local is race-free; stop()
        // never rewrites it until after this thread joins.
        //
        // ★ RELAY-FD: accept() on an exhausted descriptor table (EMFILE/ENFILE,
        // or ENOBUFS/ENOMEM) fails IMMEDIATELY and leaves the pending connection
        // in the backlog, so the old bare `continue` spun one core at 100% and
        // never let anything else free a descriptor. Back off instead (50 ms
        // doubling to 1 s, woken early by stop()), log at most once per 5 s with
        // the count suppressed in between, and resume the moment a descriptor
        // is free: the queued connection is then accepted normally.
        const int lfd = m_listen_fd;
        int backoff_ms = 0;
        auto last_log = std::chrono::steady_clock::time_point{};
        std::uint64_t suppressed = 0;
        while (m_running.load()) {
            int cfd = ::accept(lfd, nullptr, nullptr);
            if (cfd >= 0) {
                if (backoff_ms && m_log)
                    m_log("carrier-net: accept recovered (descriptors available again)");
                backoff_ms = 0; suppressed = 0;
                add_established(cfd);
                continue;
            }
            const int e = errno;
            if (!m_running.load()) break;
            if (e == EINTR || e == ECONNABORTED) continue;
            if (e == EMFILE || e == ENFILE || e == ENOBUFS || e == ENOMEM) {
                m_accept_exhausted.fetch_add(1, std::memory_order_relaxed);
                backoff_ms = backoff_ms ? std::min(1000, backoff_ms * 2) : 50;
                const auto now = std::chrono::steady_clock::now();
                if (now - last_log >= std::chrono::seconds(5)) {
                    if (m_log)
                        m_log(std::string("carrier-net: accept failed: ") + std::strerror(e) +
                              " -- backing off " + std::to_string(backoff_ms) + " ms (" +
                              std::to_string(suppressed) + " more since last notice)");
                    last_log = now; suppressed = 0;
                } else {
                    ++suppressed;
                }
            } else {
                backoff_ms = 100;                        // any other error: never spin either
            }
            for (int slept = 0; slept < backoff_ms && m_running.load(); slept += 25)
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }

    PeerId add_established(int fd) {
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
        std::list<Reader> finished;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            if (!m_running.load()) { ::close(fd); return 0; }   // stopping: never orphan a reader
            // RELAY-FD: reap readers that already unwound, so a connection churn
            // (a partitioned peer redialed every second) does not accumulate one
            // unjoined thread -- and its stack -- per connection until stop().
            for (auto it = m_readers.begin(); it != m_readers.end();) {
                auto nx = std::next(it);
                if (it->done->load() && it->t.get_id() != std::this_thread::get_id())
                    finished.splice(finished.end(), m_readers, it);
                it = nx;
            }
            pid = ++m_next_peer_id;
            auto c = std::make_shared<Conn>();
            c->fd = fd; c->pid = pid;
            m_conns[pid] = c;
            auto done = std::make_shared<std::atomic<bool>>(false);
            m_readers.push_back(Reader{std::thread([this, c, done] { reader_loop(c); done->store(true); }), done});
            established = true;
        }
        for (auto& r : finished) if (r.t.joinable()) r.t.join();   // already returned: no wait
        if (established) {
            // OUTSIDE m_mtx on purpose: the callback arms the relay's re-offer
            // sweep, and the relay's own broadcast path takes m_mtx — firing it
            // under the lock would invert the order (relay -> transport).
            PeerConnectFn cb = m_on_connect;
            if (cb) cb();
            PeerEventFn ev = m_on_peer_event;
            if (ev) ev(pid, true);
        }
        return established ? pid : 0;
    }

    void reader_loop(const std::shared_ptr<Conn>& c) {
        const int fd = c->fd;
        const PeerId pid = c->pid;
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
            if (m_inbound_from) m_inbound_from(pid, frame);
            else if (m_inbound) m_inbound(frame);
        }
        drop_conn(c);
        shutdown_conn(*c);   // wake any writer still blocked on this socket
        // ★ RELAY-FD: the reader OWNS the descriptor's close. Before this the fd
        // of a dropped connection was closed only by stop() -- and not even
        // there once the drop had removed it from the peer set -- so every
        // refused, timed-out, banned or partition-dropped connection leaked one
        // descriptor for the life of the process (fds=1024/1024 after the
        // SIGUSR1 partition). The close happens under the connection's write
        // lock with `closed` set, so no writer that still holds this Conn can
        // ever write into a later connection that reuses the number.
        std::lock_guard<std::mutex> wlk(c->wmtx);
        std::lock_guard<std::mutex> flk(c->fmtx);
        c->closed = true;
        ::close(fd);
    }

    // `hard` => the stream is unusable (a timed-out write left half a frame on
    // it), so shut the socket down: the peer's reader thread unwinds instead of
    // sitting in recv() on a connection nobody will ever write to again.
    // Remove ONE connection from the peer set (idempotent: the first caller
    // fires PeerEventFn(id, false), later ones are no-ops). `hard` => the stream
    // is unusable (a timed-out write left half a frame on it, or a protocol
    // refusal), so shut the socket down: its reader unwinds out of recv() and
    // closes the descriptor (reader_loop). The descriptor is never closed here:
    // only the reader, which is the last user of the number, closes it.
    void drop_conn(const std::shared_ptr<Conn>& c, bool hard = false, bool slow = true) {
        bool had = false;
        {
            std::lock_guard<std::mutex> lk(m_mtx);
            auto it = m_conns.find(c->pid);
            if (it != m_conns.end() && it->second == c) { m_conns.erase(it); had = true; }
        }
        if (hard) {
            if (had && slow) m_slow_drops.fetch_add(1);
            shutdown_conn(*c);
        }
        if (had) { PeerEventFn ev = m_on_peer_event; if (ev) ev(c->pid, false); }
    }

    // shutdown(2) a live connection's socket; a no-op once its reader closed the
    // descriptor (the number may belong to someone else by then).
    static void shutdown_conn(Conn& c) {
        std::lock_guard<std::mutex> flk(c.fmtx);
        if (!c.closed) ::shutdown(c.fd, SHUT_RDWR);
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
    InboundFromFn             m_inbound_from;   // GAP-2: pid-tagged inbound (precedence when bound)
    PeerConnectFn             m_on_connect;
    ControlFn                 m_control;        // frame[0] >= 0x80 (repair channel)
    PeerEventFn               m_on_peer_event;  // (PeerId, connected)
    std::atomic<std::uint64_t> m_ctrl_routed{0};
    std::atomic<std::uint64_t> m_ctrl_ignored{0};
    std::atomic<std::uint64_t> m_slow_drops{0};
    std::atomic<std::uint64_t> m_oversize_refused{0};
    std::atomic<std::uint64_t> m_accept_exhausted{0};
    LogFn                     m_log;            // rate-limited diagnostics (RELAY-FD)
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
    std::list<Reader>         m_readers;      // reaped on connect once `done`
    mutable std::mutex        m_mtx;          // guards m_conns / m_readers / m_next_peer_id
    // ★ peer identity. Ids are never reused, so per-peer state keyed on a
    // PeerId dies with the connection — the flap-safety property the repair
    // channel depends on. Ordered by id = connection order (the broadcast order).
    PeerId                    m_next_peer_id = 0;
    std::map<PeerId, std::shared_ptr<Conn>> m_conns;
};

} // namespace c2pool::v37n
