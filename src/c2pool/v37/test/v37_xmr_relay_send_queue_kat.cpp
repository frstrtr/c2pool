// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_relay_send_queue_kat -- RELAY-SEND-QUEUE on the Path B relay node:
// the HELLO re-offer of a full pending set goes through the per-link send
// queue, never a blocking send.
//
//   S1  two Path B relay nodes over loopback TCP, each holding a full pending
//       set (P-09 receipts on a tip it has moved past) the other lacks; they
//       HELLO and both re-offer every pending receipt (FB_RECEIPTS v3). B's
//       reader is held at A's first re-offer frame (B reads nothing more from
//       A) until A's whole re-offer is queued behind it (asserted: bytes
//       queued). A then floods a small frame from another thread (its share
//       of a job made before the HELLO): the call returns while B is held and
//       the link is up; once B reads again, the frame reaches B in the link's
//       order, behind every re-offer frame A queued before it; every
//       re-offered frame is delivered, both directions; no send timeout, no
//       hard drop, no redial (one HELLO per side); no frame of either
//       re-offer dropped by the receiver's valid-object budget (P-15).
//       A send that blocks for less than the wait bound (30 s) passes the
//       call check. SO_SNDTIMEO (10 s) bounds how long B may be held. The
//       order check pins FIFO order on the link.
//   S3  the per-link send queue stays bounded (high-water mark measured), with
//       0 queue-full drops and 0 send-timeout drops.
//   S4  first A runs every job of the S1 exchange (every FB_RECEIPTS frame
//       handled, its verify queue empty, nothing parked, no ticket open, on
//       two samples in a row; one verify thread). A peer that reads nothing
//       (a raw socket) HELLOs A, which re-offers its full pending set: at A's
//       send queue bound the whole re-offer is queued and the link kept; the
//       peer then reads every frame. At a bound below the re-offer's bytes
//       (an eighth of them: paged; and the re-offer x 16,777,216 /
//       17,418,240, the default bound against P-09 x P-10) a peer that reads
//       nothing until A's re-offer has paused at the bound (or ended), then
//       drains: the link kept, every frame sent and read, 0 queue-full drops.
//   S5  at the bound / 8, such a peer asks FC_GETHEADERS right after its
//       HELLO, and A mines a carrier once the re-offer has paused at the bound
//       (paged within the bound less one FC_HEADERS frame), before the peer
//       reads: the link kept, 0 queue-full drops; the peer reads every
//       re-offer frame, the carrier and the FC_HEADERS reply.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#include "xmr_pathb_relay_test_util.hpp"

using namespace pathb_relay_test;
using namespace std::chrono_literals;
using SClock = std::chrono::steady_clock;

static long long ms_since(SClock::time_point t0, SClock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t - t0).count();
}

static pb::PathbRelayOptions opts(bool listen, std::vector<u16> dial) {
    pb::PathbRelayOptions o = Rig::opts(listen, dial);
    o.keepalive_ms = 300;   // PINGs flow during the test
    return o;
}

// The first arrival time of each small frame by the id it carries: an FC_CARRIER (its carrier) or an FB_RECEIPTS of
// one body (that receipt); and the FB_RECEIPTS frames read before it on the link.
struct SmallArrivals {
    std::mutex m;
    std::map<pb::Hash32, SClock::time_point> at;
    std::map<pb::Hash32, std::uint64_t> behind;
    std::map<pb::Hash32, std::pair<u8, std::size_t>> shape;   // its opcode and bytes
    std::uint64_t receipts = 0;   // FB_RECEIPTS frames read
    pb::RelayBuffers buf;
    void tap(const std::vector<u8>& f) {
        if (f.empty()) return;
        const bool rf = f[0] == pb::kOpFbReceipts;
        if (f.size() < pb::kFrameHeaderBytes) {
            if (rf) {
                std::lock_guard<std::mutex> lk(m);
                ++receipts;
            }
            return;
        }
        std::optional<pb::Hash32> id;
        if (f[0] == pb::kOpFcCarrier) {
            pb::CarrierBodyV3 c;
            if (pb::decode_carrier_body_v3(f.data() + pb::kFrameHeaderBytes, f.size() - pb::kFrameHeaderBytes,
                                           pb::CarrierLimits{buf.receipt, pb::kRuledLaneParams.r_max}, c) == pb::WireError::None)
                id = pb::receipt_id(c.own);
        } else if (f[0] == pb::kOpFbReceipts && f.size() > pb::kFrameHeaderBytes && f[pb::kFrameHeaderBytes] == 1) {
            pb::ReceiptBodyV3 r;
            if (pb::decode_receipt_body_v3(f.data() + pb::kFrameHeaderBytes + 1, f.size() - pb::kFrameHeaderBytes - 1,
                                           pb::receipt_limits(buf), r) == pb::WireError::None)
                id = pb::receipt_id(r);
        }
        std::lock_guard<std::mutex> lk(m);
        if (id && at.emplace(*id, SClock::now()).second) {
            behind.emplace(*id, receipts);
            shape.emplace(*id, std::make_pair(f[0], f.size()));
        }
        if (rf) ++receipts;
    }
    std::optional<SClock::time_point> of(const pb::Hash32& id) {
        std::lock_guard<std::mutex> lk(m);
        const auto it = at.find(id);
        if (it == at.end()) return std::nullopt;
        return it->second;
    }
    std::optional<std::uint64_t> behind_of(const pb::Hash32& id) {
        std::lock_guard<std::mutex> lk(m);
        const auto it = behind.find(id);
        if (it == behind.end()) return std::nullopt;
        return it->second;
    }
    std::pair<u8, std::size_t> shape_of(const pb::Hash32& id) {
        std::lock_guard<std::mutex> lk(m);
        const auto it = shape.find(id);
        return it == shape.end() ? std::make_pair(u8{0}, std::size_t{0}) : it->second;
    }
};

// Holds the reader it runs on (a node's tap) at the first FB_RECEIPTS frame after arm(), until open(): the node reads
// nothing more from that link meanwhile.
struct ReadGate {
    std::mutex m;
    std::condition_variable cv;
    bool armed = false, held = false, opened = false;
    void arm() {
        std::lock_guard<std::mutex> lk(m);
        armed = true;
    }
    void at(const std::vector<u8>& f) {
        if (f.empty() || f[0] != pb::kOpFbReceipts) return;
        std::unique_lock<std::mutex> lk(m);
        if (!armed || held || opened) return;
        held = true;
        cv.notify_all();
        cv.wait(lk, [&] { return opened; });
    }
    bool wait_held(std::chrono::milliseconds limit) {
        std::unique_lock<std::mutex> lk(m);
        return cv.wait_for(lk, limit, [&] { return held; });
    }
    void open() {
        {
            std::lock_guard<std::mutex> lk(m);
            opened = true;
        }
        cv.notify_all();
    }
};

// A raw peer on A's port, on its own thread: sends `hello` ([u32 LE length][frame]) and then `ask` (when given), then
// reads nothing until read(), then whatever has arrived, until stop(), which joins it and closes the socket. ops(): the
// complete frames read, by opcode; closed(): the other side closed the connection.
class RawPeer {
public:
    RawPeer(std::uint16_t port, const std::vector<u8>& hello, const std::vector<u8>* ask = nullptr) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return;
        const int rcv = 4096;
        (void)::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0) return;
        std::vector<u8> out;
        for (const std::vector<u8>* f : {&hello, ask}) {
            if (f == nullptr) continue;
            const std::uint32_t n = static_cast<std::uint32_t>(f->size());
            for (int i = 0; i < 4; ++i) out.push_back(static_cast<u8>(n >> (8 * i)));
            out.insert(out.end(), f->begin(), f->end());
        }
        if (::send(fd_, out.data(), out.size(), MSG_NOSIGNAL) != static_cast<ssize_t>(out.size())) return;
        connected_ = true;
        t_ = std::thread([this] { loop(); });
    }
    RawPeer(const RawPeer&) = delete;
    RawPeer& operator=(const RawPeer&) = delete;
    ~RawPeer() { stop(); }
    bool connected() const { return connected_; }
    void read() { read_ = true; }
    void stop() {
        stop_ = true;
        if (t_.joinable()) t_.join();
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }
    bool closed() const { return closed_.load(); }
    std::uint64_t ops(u8 op) const { return ops_[op].load(); }

private:
    void loop() {
        std::vector<u8> buf(16384), acc;
        std::size_t at = 0;
        while (!stop_ && !closed_) {
            if (!read_) {  // reads nothing: a 5 ms step, then look again
                pollfd p{fd_, 0, 0};
                if (::poll(&p, 1, 5) > 0 && (p.revents & (POLLERR | POLLHUP)) != 0) closed_ = true;
                continue;
            }
            for (;;) {
                pollfd p{fd_, POLLIN, 0};
                if (::poll(&p, 1, 5) <= 0) break;
                const ssize_t r = ::recv(fd_, buf.data(), buf.size(), MSG_DONTWAIT);
                if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) closed_ = true;
                if (r <= 0) break;
                acc.insert(acc.end(), buf.begin(), buf.begin() + r);
                for (;;) {
                    if (acc.size() - at < 4) break;
                    const std::uint32_t len = static_cast<std::uint32_t>(acc[at]) | (static_cast<std::uint32_t>(acc[at + 1]) << 8) |
                                              (static_cast<std::uint32_t>(acc[at + 2]) << 16) |
                                              (static_cast<std::uint32_t>(acc[at + 3]) << 24);
                    if (acc.size() - at < 4 + static_cast<std::size_t>(len)) break;
                    if (len > 0) ++ops_[acc[at + 4]];
                    at += 4 + len;
                }
                if (at > (1u << 20)) {
                    acc.erase(acc.begin(), acc.begin() + static_cast<std::ptrdiff_t>(at));
                    at = 0;
                }
            }
        }
    }
    int fd_ = -1;
    bool connected_ = false;
    std::thread t_;
    std::atomic<bool> read_{false}, stop_{false}, closed_{false};
    std::array<std::atomic<std::uint64_t>, 256> ops_{};
};

int main() {
    Checker C;
    std::printf("== v37_xmr_relay_send_queue_kat ==\n");
    Rig rig;
    const std::size_t K = static_cast<std::size_t>(pb::relay_horizons(pb::kRuledLaneParams).pending_cap);   // P-09
    // each node: K shares of one job at position 0, then a carrier at position 1: K pending receipts it holds alone
    auto pend = [&](RNode& n, std::size_t payee, std::uint32_t en, std::uint32_t nonce0) {
        const std::optional<pb::PathbJob> j = rig.job(n, payee, en);
        if (!j || rig.mine(n, payee, nonce0 - 1).action != pb::NodeAction::Placed) return std::size_t{0};
        std::size_t k = 0;
        for (std::uint32_t i = 0; i < K; ++i) k += rig.share(n, *j, nonce0 + i).action == pb::NodeAction::Pending ? 1 : 0;
        return k;
    };
    SmallArrivals arrivals;   // before B: B's reader threads use it until B stops
    ReadGate gate;            // the same
    const auto t_pend = SClock::now();
    auto A = rig.make("A", opts(true, {}), /*launch=*/true);
    const std::size_t pa = pend(*A, 1, 0xA1, 0x10000000u);
    std::string why;
    C(A->start(why), "S1 A listens " + why);
    auto B = rig.make("B", opts(false, {A->port()}), /*launch=*/true);
    const std::size_t pb_ = pend(*B, 2, 0xB2, 0x20000000u);
    arrivals.buf = B->node->config().buffers;
    B->links.set_tap([&](std::uint64_t, const std::vector<u8>& f) {
        arrivals.tap(f);
        gate.at(f);
    });
    const std::vector<pb::ReceiptBodyV3> one{A->r().with_node([](pb::PathbNode& n) { return n.pending().all().front()->body; })};
    const std::size_t body = pb::encode_fb_receipts(0, one, pb::kRuledLaneParams).value_or(std::vector<u8>{}).size();
    std::printf("    pending A=%zu B=%zu (P-09 = %zu) in %lld ms; a one-body frame %zu B; ~%zu B each way\n", pa, pb_, K,
                ms_since(t_pend, SClock::now()), body, body * K);
    std::printf("    receipt buffer (P-10) %llu B: P-09 x P-10 = %llu B; per-link send queue %zu B\n",
                (unsigned long long)arrivals.buf.receipt, (unsigned long long)(arrivals.buf.receipt * K),
                pb::PathbRelayOptions{}.send_queue_bytes);
    C(pa == K && pb_ == K, "S1 each node holds a full pending set the other lacks (" + std::to_string(K) + " receipts)");

    const auto tj = SClock::now();
    const std::optional<pb::PathbJob> jsmall = rig.job(*A, 3, 0x30);
    std::printf("    a job on A with its full pending set: %lld ms\n", ms_since(tj, SClock::now()));
    if (!jsmall) {
        C(false, "S1 A builds a job on its best tip");
        return C.done("v37_xmr_relay_send_queue_kat");
    }
    gate.arm();   // B's reader stops at A's first re-offer frame
    const auto t_start = SClock::now();
    C(B->start(why), "S1 B dials A " + why);
    const bool up = wait_until([&] { return A->r().ready_peers().size() == 1 && B->r().ready_peers().size() == 1; }, 5000ms, 10ms);
    C(up, "S1 HELLO A<->B (both re-offer their pending sets now)");
    const bool parked = gate.wait_held(30000ms);   // B holds A's first re-offer frame: B reads nothing more from A
    const bool queued_all = parked && wait_until([&] { return A->st().reoffer_done.load() >= 1; }, 30000ms, 1ms);
    const std::vector<std::uint64_t> ra = A->r().ready_peers();
    const std::uint64_t r0 = A->st().reoffer_frames.load();   // A's re-offer frames queued before the small frame
    const std::size_t q0 = ra.empty() ? 0 : A->links.net().queued_bytes(ra.front());
    C(queued_all && q0 > 0, "S1 A's re-offer is queued behind a peer that reads nothing (" + std::to_string(q0) + " B)");

    // A concurrent small sender: A's share of a job made before the HELLO, flooded as one frame (the stratum /
    // verify-flood path in the daemon), while B is held.
    std::atomic<bool> returned{false};
    pb::NodeEventResult shared;
    long long call_ms = -1;
    bool link_up = false;   // A's link to B still up as the call returns
    const auto t0 = SClock::now();
    std::thread caller([&] {
        shared = rig.share(*A, *jsmall, 0x30000000u);
        call_ms = ms_since(t0, SClock::now());
        link_up = !ra.empty() && A->links.has_peer(ra.front());
        returned = true;
    });
    const bool while_held = parked && wait_until([&] { return returned.load(); }, 30000ms, 1ms);
    gate.open();
    caller.join();
    const pb::Hash32 small = pb::receipt_id(body_of(*jsmall, 0x30000000u));

    const bool delivered = wait_until([&] {
        return A->st().reoffer_frames.load() > 0 && B->st().reoffer_frames.load() > 0 &&
               B->links.frames(pb::kOpFbReceipts) >= A->st().reoffer_frames.load() &&
               A->links.frames(pb::kOpFbReceipts) >= B->st().reoffer_frames.load() && arrivals.of(small).has_value();
    }, 30000ms, 10ms);
    const auto t_done = SClock::now();
    const std::optional<SClock::time_point> at = arrivals.of(small);
    const long long arrive_ms = at ? ms_since(t0, *at) : -1;
    const std::optional<std::uint64_t> behind = arrivals.behind_of(small);
    const std::pair<u8, std::size_t> sh = arrivals.shape_of(small);
    const auto helloA = A->st().hello_ok.load(), helloB = B->st().hello_ok.load();
    std::printf("    S1 METRIC small_send_call_ms=%lld small_arrive_ms=%lld small_frame=0x%02x/%zu B | B held=%d, returned held=%d "
                "link up=%d, A queued %zu B, %llu re-offer frames before the small one, B read it behind %lld | re-offered "
                "A->B %llu (B got %llu) B->A %llu (A got %llu) frames in %lld ms | hello_ok A=%llu B=%llu\n",
                call_ms, arrive_ms, static_cast<unsigned>(sh.first), sh.second, parked ? 1 : 0, while_held ? 1 : 0,
                link_up ? 1 : 0, q0, (unsigned long long)r0, behind ? (long long)*behind : -1LL,
                (unsigned long long)A->st().reoffer_frames.load(), (unsigned long long)B->links.frames(pb::kOpFbReceipts),
                (unsigned long long)B->st().reoffer_frames.load(), (unsigned long long)A->links.frames(pb::kOpFbReceipts),
                ms_since(t_start, t_done), (unsigned long long)helloA, (unsigned long long)helloB);
    C((shared.action == pb::NodeAction::Placed || shared.action == pb::NodeAction::Pending) && while_held && link_up,
      "S1 a concurrent small send never blocks behind the re-offer (the call returns while B reads nothing, the link up)");
    C(behind.has_value() && *behind >= r0 && r0 > 0,
      "S1 ... and reaches the peer in the link's order, behind the " + std::to_string(r0) +
              " re-offer frames queued before it");
    C(delivered, "S1 every re-offered frame is delivered, both directions");
    C(helloA == 1 && helloB == 1, "S1 no send timeout -> no hard drop -> no redial (one HELLO per side)");
    std::printf("    S1 METRIC p15 A drops=%llu counted=%llu | B drops=%llu counted=%llu\n",
                (unsigned long long)A->st().p15_drops.load(), (unsigned long long)A->st().p15_counted.load(),
                (unsigned long long)B->st().p15_drops.load(), (unsigned long long)B->st().p15_counted.load());
    C(A->st().p15_drops.load() == 0 && B->st().p15_drops.load() == 0 && A->st().p15_counted.load() > 0 &&
      B->st().p15_counted.load() > 0,
      "S1 a restarted node's honest re-offer (P-09 receipts) passes the receiver's valid-object budget (P-15): 0 dropped");

    // ── S3 the per-link send queue is bounded ────────────────────────────────
    {
        auto& na = A->links.net();
        auto& nb = B->links.net();
        std::printf("    S3 METRIC A hwm=%zu bound=%zu full_drops=%llu slow_drops=%llu | B hwm=%zu bound=%zu full_drops=%llu "
                    "slow_drops=%llu\n",
                    na.queued_bytes_hwm(), na.send_queue_limit(), (unsigned long long)na.peers_dropped_queue_full(),
                    (unsigned long long)na.peers_dropped_slow(), nb.queued_bytes_hwm(), nb.send_queue_limit(),
                    (unsigned long long)nb.peers_dropped_queue_full(), (unsigned long long)nb.peers_dropped_slow());
        C(na.queued_bytes_hwm() <= na.send_queue_limit() && nb.queued_bytes_hwm() <= nb.send_queue_limit(),
          "S3 per-link queued bytes never exceed the bound");
        C(na.peers_dropped_queue_full() == 0 && nb.peers_dropped_queue_full() == 0 && na.peers_dropped_slow() == 0 &&
          nb.peers_dropped_slow() == 0, "S3 0 queue-full drops, 0 send-timeout drops");
    }
    // ── S4 a slow peer while a full pending set is re-offered ────────────────
    {
        auto& na = A->links.net();
        // A runs every job of the S1 exchange first (B's re-offered receipts); one verify thread
        const auto ti = SClock::now();
        const std::size_t vq0 = A->r().verify_queue_size();
        const std::uint64_t ad0 = A->st().p15_counted.load();
        int calm = 0;
        const bool idle = wait_until([&] {
            const bool now = A->links.handled(pb::kOpFbReceipts) == A->links.frames(pb::kOpFbReceipts) &&
                             A->r().verify_queue_size() == 0 && A->r().parked_size() == 0 && A->r().open_tickets() == 0 &&
                             A->r().parked_receipts() == 0;
            calm = now ? calm + 1 : 0;
            return calm >= 2;
        }, 60000ms, 20ms);
        std::printf("    S4 METRIC A idle=%d in %lld ms (verify queue %zu at the start; %llu receipts admitted meanwhile; verify "
                    "threads %llu)\n",
                    idle ? 1 : 0, ms_since(ti, SClock::now()), vq0, (unsigned long long)(A->st().p15_counted.load() - ad0),
                    (unsigned long long)A->st().verify_threads.load());
        C(idle && A->st().verify_threads.load() == 1,
          "S4 A has run every job of the S1 exchange before a slow peer HELLOs (verify queue empty, nothing parked)");
        const std::uint64_t b_link = ra.empty() ? 0 : ra.front();
        // the raw peer's link at A (none: gone)
        auto peer_link = [&]() -> std::optional<std::uint64_t> {
            for (const std::uint64_t p : A->r().ready_peers())
                if (p != b_link) return p;
            return std::nullopt;
        };
        // A holds B's link alone (a raw peer's link gone)
        auto only_b = [&] { return wait_until([&] { return A->r().ready_peers().size() == 1 && A->links.n_peers() == 1; }, 30000ms); };
        const std::size_t reoffer = body * K;
        const std::uint64_t per = pb::fc_ids_max(pb::kRuledLaneParams);
        auto want_frames = [&] {
            const std::uint64_t pend = A->r().with_node([](pb::PathbNode& n) { return n.pending().size(); });
            return std::make_pair(pend, (pend + per - 1) / per);
        };
        {
            const bool clean = only_b();
            const auto [pend, want] = want_frames();
            const std::uint64_t full0 = na.peers_dropped_queue_full();
            const std::uint64_t ro0 = A->st().reoffer_frames.load(), d0 = A->st().reoffer_done.load();
            RawPeer peer(A->port(), A->hello_bytes(A->r().node_nonce() ^ 0x5151ull, 0));
            const bool hello = peer.connected() && wait_until([&] { return A->r().ready_peers().size() == 2; }, 30000ms);
            // the bound holds the whole re-offer: it is queued while the peer reads nothing
            const bool queued = hello && wait_until([&] { return A->st().reoffer_done.load() > d0; }, 30000ms);
            const std::optional<std::uint64_t> pl = peer_link();
            const std::size_t q = pl ? na.queued_bytes(*pl) : 0;
            peer.read();
            const bool read_all = queued && wait_until([&] { return peer.ops(pb::kOpFbReceipts) >= want; }, 30000ms);
            const bool kept = !peer.closed() && peer_link().has_value();
            peer.stop();
            const std::size_t hwm = na.queued_bytes_hwm();
            const std::uint64_t full1 = na.peers_dropped_queue_full();
            const std::uint64_t frames = A->st().reoffer_frames.load() - ro0;
            std::printf("    S4 METRIC bound=%zu re-offer=%zu B (%llu frames, %llu pending) queued=%zu B hwm=%zu full_drops=%llu "
                        "kept=%d read=%llu\n",
                        na.send_queue_limit(), reoffer, (unsigned long long)frames, (unsigned long long)pend, q, hwm,
                        (unsigned long long)(full1 - full0), kept ? 1 : 0, (unsigned long long)peer.ops(pb::kOpFbReceipts));
            C(clean && queued && read_all && kept && full1 == full0 && frames >= want && hwm >= reoffer / 4,
              "S4 a peer that reads nothing at A's send queue bound: the whole re-offer queued (" + std::to_string(q) +
                      " B on the link), the link kept, every frame read");
        }
        // below the re-offer's bytes: a frame queued only within the bound
        const std::size_t worst = static_cast<std::size_t>(static_cast<double>(reoffer) * 16777216.0 / 17418240.0);
        const std::size_t hf = static_cast<std::size_t>(A->node->frame_bytes_headers());
        const std::size_t eighth = std::max(reoffer / 8, 2 * hf);
        int k = 0;
        for (const std::size_t bound : {eighth, worst}) {
            const bool clean = only_b();
            na.set_send_queue(bound);
            const auto [pend, want] = want_frames();
            const std::uint64_t f0 = na.peers_dropped_queue_full(), r0 = A->st().reoffer_frames.load();
            const std::uint64_t z0 = A->st().reoffer_paused.load(), d0 = A->st().reoffer_done.load();
            RawPeer peer(A->port(), A->hello_bytes(A->r().node_nonce() ^ (0x5252ull + k), 0));
            const bool hello = peer.connected() && wait_until([&] { return A->r().ready_peers().size() == 2; }, 30000ms);
            // the peer reads nothing until A's re-offer has paused at the bound (or ended)
            const bool filled = hello && wait_until([&] {
                return A->st().reoffer_paused.load() > z0 || A->st().reoffer_done.load() > d0;
            }, 30000ms);
            peer.read();
            const bool read_all = filled && wait_until([&] {
                return peer.ops(pb::kOpFbReceipts) >= want && A->st().reoffer_done.load() > d0;
            }, 30000ms);
            const bool held = !peer.closed() && peer_link().has_value();
            peer.stop();
            const std::uint64_t done = A->st().reoffer_done.load() - d0;
            const std::uint64_t f1 = na.peers_dropped_queue_full(), sent = A->st().reoffer_frames.load() - r0;
            const std::uint64_t paused = A->st().reoffer_paused.load() - z0;
            std::printf("    S4 METRIC bound=%zu sent=%llu of %llu frames (%llu pending) paused=%llu full_drops=%llu kept=%d "
                        "read=%llu\n",
                        bound, (unsigned long long)sent, (unsigned long long)want, (unsigned long long)pend,
                        (unsigned long long)paused, (unsigned long long)(f1 - f0), held ? 1 : 0,
                        (unsigned long long)peer.ops(pb::kOpFbReceipts));
            C(clean && filled && read_all && held && f1 == f0 && sent >= want && (k == 1 || paused > 0) && done == 1,
              std::string("S4 a bound below the re-offer's bytes (") +
                      (k == 0 ? "an eighth" : "x 16,777,216 / 17,418,240") +
                      ", " + std::to_string(bound) + " B): the link kept, every frame sent and read, 0 queue-full drops (paused " +
                      std::to_string(paused) + (k == 0 ? ", paged" : "") + "), the re-offer timed to its end (" +
                      std::to_string(done) + ", " + std::to_string(A->st().reoffer_last_ms.load()) + " ms)");
            ++k;
        }
        // S5: paging, live traffic and a serve reply on one slow link: the re-offer leaves one FC_HEADERS frame free
        {
            const bool clean = only_b();
            na.set_send_queue(eighth);
            const auto [pend, want] = want_frames();
            const std::uint64_t f0 = na.peers_dropped_queue_full(), r0 = A->st().reoffer_frames.load();
            const std::uint64_t z0 = A->st().reoffer_paused.load(), d0 = A->st().reoffer_done.load();
            const std::vector<u8> ask = pb::encode_fc_getheaders(pb::GetHeaders{0, pb::Hash32{}, pb::Hash32{}, 64});
            RawPeer peer(A->port(), A->hello_bytes(A->r().node_nonce() ^ 0x5353ull, 0), &ask);
            const bool hello = peer.connected() && wait_until([&] { return A->r().ready_peers().size() == 2; }, 30000ms);
            // the re-offer paused at the bound, the peer reading nothing: a live carrier now
            const bool filled = hello && wait_until([&] { return A->st().reoffer_paused.load() > z0; }, 30000ms);
            rig.tick_monero();
            const pb::NodeEventResult live = rig.mine(*A, 5, 0x55000000u);
            peer.read();
            const bool read_all = filled && wait_until([&] {
                return peer.ops(pb::kOpFbReceipts) >= want && peer.ops(pb::kOpFcCarrier) >= 1 &&
                       peer.ops(pb::kOpFcHeaders) >= 1 && A->st().reoffer_done.load() > d0;
            }, 30000ms);
            const bool held = !peer.closed() && peer_link().has_value();
            peer.stop();
            const std::uint64_t f1 = na.peers_dropped_queue_full(), sent = A->st().reoffer_frames.load() - r0;
            const std::uint64_t paused = A->st().reoffer_paused.load() - z0;
            std::printf("    S5 METRIC bound=%zu headers frame=%zu sent=%llu of %llu (%llu pending) paused=%llu full_drops=%llu "
                        "kept=%d | read: FB_RECEIPTS %llu FC_CARRIER %llu FC_HEADERS %llu\n",
                        eighth, hf, (unsigned long long)sent, (unsigned long long)want, (unsigned long long)pend,
                        (unsigned long long)paused, (unsigned long long)(f1 - f0), held ? 1 : 0,
                        (unsigned long long)peer.ops(pb::kOpFbReceipts), (unsigned long long)peer.ops(pb::kOpFcCarrier),
                        (unsigned long long)peer.ops(pb::kOpFcHeaders));
            C(clean && filled && read_all && live.action == pb::NodeAction::Placed && held && f1 == f0 && sent >= want &&
                      paused > 0,
              "S5 a slow peer (the re-offer paged within the bound less one FC_HEADERS frame) gets a live carrier and a "
              "serve reply while paged: the link kept, 0 queue-full drops, every re-offer frame, the carrier and the "
              "FC_HEADERS reply read");
        }
        (void)only_b();
        na.set_send_queue(pb::PathbRelayOptions{}.send_queue_bytes);
    }
    return C.done("v37_xmr_relay_send_queue_kat");
}
