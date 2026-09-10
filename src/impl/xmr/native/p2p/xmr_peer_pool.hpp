// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/p2p/xmr_peer_pool.hpp
//
// Wave 1, component C1c: THE POOL. Many links (C1b) driven by one plan
// (xmr_dial_plan.hpp) over one store (xmr_peer_store.hpp), metered by one
// budget per peer (xmr_p2p_dos.hpp), and the three ports the rest of the native
// node reaches the network through:
//
//   IChainFetcher   (C2 -> C1) request_chain / request_objects /
//                   request_fluffy_missing / penalize / peers
//   IBroadcastPort  (C5 -> C1) broadcast_notify / send_notify /
//                   set_fluffy_missing_handler
//   the SERVING side -- our answers to a peer's 2003 / 2006 / 2009 / 2010,
//                   read out of C2's IChainServing.
//
// THE STATE_NORMAL TRAP is the reason the serving side exists at all, and it is
// worth restating here because it is the failure this component is most likely
// to be blamed for. A monerod peer relays new blocks and transactions to a
// connection only while its own protocol handler holds that connection in
// state_normal. It leaves state_normal when we advertise a tip it does not
// have, and it drops us outright if we fail to answer a chain or objects
// request. A client that dials, handshakes, and then serves nothing looks
// perfectly healthy -- peers connected, TIMED_SYNC answering, no errors -- and
// receives NOTHING. That is silent starvation, and it is what
// InboundLiveness::relay_silent() (C1b) measures and what
// telemetry().relay_silent_peers reports.
//
// THE FOURTH C1-LENS FACT, carried forward from C1b and re-asserted here
// because this is the layer that would suffer from forgetting it:
//
//     LEVIN SUCCESS IS `return_code >= 0`, NOT `== LEVIN_OK`.
//
// epee copies the handler's own return value into the response header, and
// EVERY monerod handler ends in `return 1`. A HANDSHAKE answer from a real
// daemon therefore carries return_code = 1, and a matcher that insisted on 0
// would refuse every honest peer on the network -- which is exactly what the
// first live run of this transport against a stagenet daemon did. The rule
// lives in rc_is_error()/RC_HANDLER_OK (levin_invoke_queue.hpp); the pool
// re-asserts it by answering every invoke it serves with RC_HANDLER_OK so a C6
// byte-parity capture against monerod matches, and the live KAT prints the
// return code it actually received.
//
// THREADING. Everything that touches a link happens on the io thread.
// IChainFetcher is called from the C2 verify thread and IBroadcastPort from the
// stratum thread, so both post and return; the only exception is
// broadcast_notify(), which must report how many peers the frame reached (the
// never-silent-drop rule) and therefore waits for the io thread to answer --
// unless it is already ON the io thread, in which case it runs inline. peers()
// reads a snapshot kept under a small mutex rather than reaching into the link
// map from another thread.
//
// SCOPE FENCE (standing XMR-lane rule): everything under src/impl/xmr/. This
// tree is a WORK SOURCE for the pool, not part of the v37 share-chain record;
// nothing here activates v37 consensus and src/sharechain/v37 is not touched.
//
// Header-only. STL plus boost::asio.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/contracts/broadcast.hpp"
#include "impl/xmr/native/contracts/chain_index.hpp"
#include "impl/xmr/native/contracts/fetcher.hpp"
#include "impl/xmr/native/contracts/serving.hpp"
#include "impl/xmr/native/contracts/txpool.hpp"
#include "impl/xmr/native/contracts/types.hpp"
#include "impl/xmr/native/p2p/chain_locator.hpp"
#include "impl/xmr/native/p2p/chain_seeds.hpp"
#include "impl/xmr/native/p2p/levin_messages.hpp"
#include "impl/xmr/native/p2p/xmr_dial_plan.hpp"
#include "impl/xmr/native/p2p/xmr_levin_link.hpp"
#include "impl/xmr/native/p2p/xmr_p2p_dos.hpp"
#include "impl/xmr/native/p2p/xmr_peer_store.hpp"

namespace c2pool::xmr::native::p2p {

namespace levinns = ::c2pool::xmr::native::levin;

// ---------------------------------------------------------------------------
// Observability. The O-3 gap the X9 stagenet bring-up ran into was not a bug in
// any one handler: it was that nothing reported WHY a connected node received
// nothing. Every number below exists to answer that question without a debugger.
// ---------------------------------------------------------------------------
struct PoolTelemetry {
    std::size_t peers_total       = 0;
    std::size_t peers_handshaked  = 0;
    std::size_t peers_dialing     = 0;
    std::size_t netgroups         = 0;
    bool        eclipse_floor_met = false;
    std::size_t relay_silent_peers = 0;   // handshaked but never relayed: state_normal suspect
    std::string primary;                  // peer key, "" when none

    std::uint64_t dials_started = 0;
    std::uint64_t dials_failed  = 0;
    std::uint64_t handshakes    = 0;
    std::uint64_t rotations     = 0;
    std::uint64_t netgroup_drops= 0;
    std::uint64_t bans          = 0;
    std::uint64_t seed_rounds   = 0;

    std::uint64_t frames_in     = 0;
    std::uint64_t frames_dropped_dos = 0;
    std::uint64_t blocks_in     = 0;
    std::uint64_t txs_in        = 0;
    std::uint64_t chain_entries_in = 0;
    std::uint64_t objects_in    = 0;

    std::uint64_t served_chain    = 0;   // 2006 answered
    std::uint64_t served_objects  = 0;   // 2003 answered
    std::uint64_t served_fluffy   = 0;   // 2009 answered
    std::uint64_t served_declined = 0;   // asked for something outside the window

    std::uint64_t broadcasts      = 0;
    std::uint64_t broadcast_peers = 0;

    // Per-command inbound tally and the last close reason. These are the two
    // numbers that answer "I am connected and receiving nothing, why?" without
    // a debugger -- the exact question the X9 stagenet bring-up could not
    // answer from the outside.
    std::map<std::uint32_t, std::uint64_t> frames_by_cmd;
    std::string last_close_peer;
    std::string last_close_why;
};

// ---------------------------------------------------------------------------
class XmrPeerPool final : public IChainFetcher,
                          public IBroadcastPort,
                          public std::enable_shared_from_this<XmrPeerPool> {
public:
    using tcp = boost::asio::ip::tcp;

    struct Config {
        levinns::XmrNet net = levinns::XmrNet::Stagenet;
        levinns::LinkConfig  link{};
        DialPlanConfig       dial{};
        DosConfig            dos{};
        PeerStore::Limits    store{};

        // Operator-pinned peers ("ip:port"). Protected: never evicted, never
        // banned, never rotated, exempt from the /16 cap, preferred as PRIMARY.
        std::vector<std::string> manual_peers;
        // Anchor set restored from the previous run, best first.
        std::vector<std::string> anchor_peers;
        bool   use_seeds = true;
        Millis maintenance_tick_ms = 1'000;
        Millis connect_timeout_ms  = levinns::P2P_DEFAULT_CONNECTION_TIMEOUT_MS;

        // D-3 back-pressure.
        std::size_t max_spans_per_peer = MAX_SPANS_PER_PEER;
        std::size_t max_spans_total    = MAX_SPANS_TOTAL;
    };

    struct Deps {
        IChainServing*      serving = nullptr;   // REQUIRED: sync data + serving reads
        IChainIndexInbound* index   = nullptr;   // optional until C2 is wired
        IRelayedTxSink*     txpool  = nullptr;   // optional until C3 is wired
    };

    static std::shared_ptr<XmrPeerPool> create(boost::asio::io_context& io,
                                               Config cfg, Deps deps) {
        return std::shared_ptr<XmrPeerPool>(new XmrPeerPool(io, std::move(cfg), std::move(deps)));
    }

    XmrPeerPool(const XmrPeerPool&)            = delete;
    XmrPeerPool& operator=(const XmrPeerPool&) = delete;

    ~XmrPeerPool() override = default;

    // -----------------------------------------------------------------------
    void start() {
        auto self = shared_from_this();
        boost::asio::post(ex_, [self]() {
            const Millis now = self->now_ms();
            for (const std::string& k : self->cfg_.manual_peers)
                self->store_.add(k, PeerSource::Manual, now);
            for (const std::string& k : self->cfg_.anchor_peers)
                self->store_.add(k, PeerSource::Anchor, now);
            self->running_ = true;
            self->maintain();
            self->arm_tick();
        });
    }

    void stop() {
        auto self = shared_from_this();
        boost::asio::post(ex_, [self]() {
            self->running_ = false;
            self->tick_.cancel();
            // Same reentrancy rule as close_peer(): LevinLink::stop() fires our
            // on_closed callback synchronously, and that callback erases from
            // peers_. Iterating the live map while stopping links would invalidate
            // the loop's own iterator on the first peer. Empty the map first.
            std::map<std::string, Peer> going = std::move(self->peers_);
            self->peers_.clear();
            for (auto& [k, p] : going)
                if (p.link) p.link->stop("pool shutdown");
            self->publish_snapshot();
        });
    }

    // --- IChainFetcher (called on the C2 verify thread) ---------------------
    bool request_chain(const PeerRef& ref, std::vector<Hash> locator, bool prune) override {
        if (locator.empty()) return false;
        // The terminus rule is enforced HERE, on the way out, and not left to
        // the caller: a locator without the genesis id is a dropped connection
        // with no error frame (chain_locator.hpp), so the last chance to get it
        // right is the last place that touches the bytes.
        locator = finalize_locator(std::move(locator), genesis_id(cfg_.net));
        if (locator.empty()) return false;

        levinns::RequestChain m;
        m.block_ids = std::move(locator);
        m.prune     = prune;
        std::vector<std::uint8_t> body;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::encode_request_chain(m, body, err)) return false;

        auto self = shared_from_this();
        const std::string key = ref.addr;
        boost::asio::post(ex_, [self, key, body = std::move(body)]() mutable {
            Peer* p = self->find(key);
            if (!p || !p->handshaked) return;
            p->pending.push_back(Pending{levinns::CMD_REQUEST_CHAIN, std::move(body), kNoSpan});
            self->pump(*p);
        });
        return true;
    }

    // D-3: the caller may hand us a whole span (up to MAX_SPAN_IDS); we chunk it
    // into requests of at most MAX_OBJECT_REQUEST_IDS ids, because monerod DROPS
    // a 2003 carrying more than CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT
    // (100) ids -- and reassemble the answers back into one on_objects() per
    // span, so C2 sees the span it planned rather than our chunking.
    bool request_objects(const PeerRef& ref, std::vector<Hash> ids, bool prune) override {
        if (ids.empty()) return false;
        if (ids.size() > MAX_SPAN_IDS) return false;

        auto self = shared_from_this();
        const std::string key = ref.addr;
        boost::asio::post(ex_, [self, key, ids = std::move(ids), prune]() mutable {
            Peer* p = self->find(key);
            if (!p || !p->handshaked) return;
            if (p->spans.size() >= self->cfg_.max_spans_per_peer) return;
            if (self->spans_outstanding() >= self->cfg_.max_spans_total) return;
            Span s;
            s.ids   = std::move(ids);
            s.prune = prune;
            const std::uint64_t id = self->next_span_id_++;
            p->spans.emplace(id, std::move(s));
            p->span_order.push_back(id);
            self->issue_next_chunk(*p, id);
            self->pump(*p);
        });
        return true;
    }

    bool request_fluffy_missing(const PeerRef& ref, const Hash& block_id,
                                std::uint64_t height,
                                std::vector<std::uint64_t> tx_indices) override {
        levinns::RequestFluffyMissingTx m;
        m.block_hash = block_id;
        m.current_blockchain_height = height;
        m.missing_tx_indices = std::move(tx_indices);
        std::vector<std::uint8_t> body;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::encode_request_fluffy_missing_tx(m, body, err)) return false;

        auto self = shared_from_this();
        const std::string key = ref.addr;
        boost::asio::post(ex_, [self, key, body = std::move(body)]() mutable {
            Peer* p = self->find(key);
            if (!p || !p->handshaked || !p->link) return;
            // 2009 is answered with a 2008 NOTIFICATION, not a matched response,
            // so it needs no FIFO record and no expect latch.
            p->link->send_notify(levinns::CMD_REQUEST_FLUFFY_MISSING_TX, body);
        });
        return true;
    }

    void penalize(const PeerRef& ref, PeerFault f, const std::string& why) override {
        auto self = shared_from_this();
        const std::string key = ref.addr;
        boost::asio::post(ex_, [self, key, f, why]() {
            self->raise_fault(key, fault_of(f), why);
        });
    }

    std::vector<std::pair<PeerRef, PeerSyncData>> peers() const override {
        std::lock_guard<std::mutex> lk(snap_mu_);
        return snapshot_;
    }

    // --- IBroadcastPort (called on the stratum thread) ----------------------
    std::size_t broadcast_notify(std::uint32_t cmd, std::vector<std::uint8_t> frame) override {
        if (ex_.running_in_this_thread()) return do_broadcast(cmd, frame);

        auto self  = shared_from_this();
        auto prom  = std::make_shared<std::promise<std::size_t>>();
        auto fut   = prom->get_future();
        boost::asio::post(ex_, [self, cmd, frame = std::move(frame), prom]() mutable {
            prom->set_value(self->do_broadcast(cmd, frame));
        });
        // A bounded wait, never an unbounded one: the caller is on the path that
        // decides whether a found block reached the network, and a hung io
        // thread must surface as "reached nobody", loudly, rather than as a
        // stalled submit.
        if (fut.wait_for(std::chrono::seconds(5)) != std::future_status::ready) return 0;
        return fut.get();
    }

    bool send_notify(const PeerRef& ref, std::uint32_t cmd,
                     std::vector<std::uint8_t> frame) override {
        auto self = shared_from_this();
        const std::string key = ref.addr;
        boost::asio::post(ex_, [self, key, cmd, frame = std::move(frame)]() {
            Peer* p = self->find(key);
            if (p && p->handshaked && p->link) p->link->send_notify(cmd, frame);
        });
        return true;
    }

    void set_fluffy_missing_handler(FluffyMissingHandler h) override {
        std::lock_guard<std::mutex> lk(snap_mu_);
        fluffy_handler_ = std::move(h);
    }

    std::size_t peer_count() const override {
        std::lock_guard<std::mutex> lk(snap_mu_);
        return snapshot_.size();
    }

    std::map<std::uint32_t, std::size_t> peers_by_asn() const override {
        // We have no ASN feed; the /16 netgroup is the diversity unit C1c
        // actually enforces, and reporting it here (rather than an empty map)
        // is what lets the C4 eclipse guard see real structure.
        std::lock_guard<std::mutex> lk(snap_mu_);
        return netgroups_;
    }

    // --- observation (io thread, or after stop()) ---------------------------
    PoolTelemetry telemetry() const {
        std::lock_guard<std::mutex> lk(snap_mu_);
        return tel_;
    }
    std::string primary() const {
        std::lock_guard<std::mutex> lk(snap_mu_);
        return tel_.primary;
    }
    PeerStore&       store()       noexcept { return store_; }
    const PeerStore& store() const noexcept { return store_; }
    DialPlan&        dial_plan()   noexcept { return plan_; }

    // Dial one address immediately, bypassing the plan. Used by the live KAT
    // and by --xmr-p2p-connect at startup.
    void dial_now(const std::string& key) {
        auto self = shared_from_this();
        boost::asio::post(ex_, [self, key]() {
            self->store_.add(key, PeerSource::Manual, self->now_ms());
            self->begin_dial(key);
        });
    }

    Millis now_ms() const {
        using namespace std::chrono;
        return static_cast<Millis>(
            duration_cast<milliseconds>(steady_clock::now() - epoch_).count());
    }

private:
    static constexpr std::uint64_t kNoSpan = 0;

    struct Span {
        std::vector<Hash>       ids;
        std::size_t             issued = 0;      // ids already put on the wire
        std::size_t             in_flight_ids = 0;
        bool                    prune = false;
        std::vector<BlockEntry> blocks;          // reassembled across chunks
        std::vector<Hash>       missed;
        std::uint64_t           peer_height = 0;
        bool complete() const { return issued >= ids.size() && in_flight_ids == 0; }
    };

    struct Pending {
        std::uint32_t             cmd;
        std::vector<std::uint8_t> body;
        std::uint64_t             span = kNoSpan;
    };

    struct Peer {
        std::string   key;
        std::uint32_t netgroup = 0;
        bool          is_protected = false;
        std::shared_ptr<levinns::LevinLink> link;
        PeerRef       ref{};
        PeerSyncData  sync{};
        PeerDosGuard  dos;
        bool          handshaked = false;
        Millis        connected_at_ms  = 0;
        Millis        handshaked_at_ms = 0;
        Millis        last_sync_ms     = 0;
        Millis        last_relay_ms    = 0;

        std::deque<Pending>                pending;
        std::map<std::uint64_t, Span>      spans;
        std::deque<std::uint64_t>          span_order;
        std::uint64_t                      in_flight_span = kNoSpan;
        bool                               wire_busy = false;

        explicit Peer(const DosConfig& c) : dos(c) {}
    };

    XmrPeerPool(boost::asio::io_context& io, Config cfg, Deps deps)
        : io_(io)
        , ex_(io.get_executor())
        , cfg_(std::move(cfg))
        , deps_(deps)
        , store_(cfg_.store)
        , plan_(cfg_.dial)
        , tick_(io)
        , epoch_(std::chrono::steady_clock::now()) {
        cfg_.link.handshake.net = cfg_.net;
    }

    // --- dialing ------------------------------------------------------------
    void arm_tick() {
        if (!running_) return;
        tick_.expires_after(std::chrono::milliseconds(cfg_.maintenance_tick_ms));
        auto self = shared_from_this();
        tick_.async_wait([self](const boost::system::error_code& ec) {
            if (ec || !self->running_) return;
            self->maintain();
            self->arm_tick();
        });
    }

    void maintain() {
        const Millis now = now_ms();

        // Reap links whose transport ended between ticks.
        for (auto it = peers_.begin(); it != peers_.end();) {
            if (it->second.link && it->second.link->close_reason() != levinns::LinkClose::None) {
                const std::string key = it->first;
                ++it;
                close_peer(key, "link closed", /*healthy=*/false);
            } else {
                ++it;
            }
        }

        std::vector<LivePeer> live = live_view();
        DialDecision d = plan_.plan(store_, live, now);

        for (const auto& [key, reason] : d.drop) {
            if (reason == DropReason::Rotation) { ++tel_.rotations; plan_.note_rotation(now); }
            if (reason == DropReason::NetgroupOverCap) ++tel_.netgroup_drops;
            close_peer(key, to_string(reason), /*healthy=*/true);
        }

        if (d.use_seeds && cfg_.use_seeds) {
            ++tel_.seed_rounds;
            store_.seed_from_tables(cfg_.net, now);
            // Re-plan once with the seeds in hand rather than waiting a whole
            // tick: a cold start should not idle for a second per seed round.
            live = live_view();
            d = plan_.plan(store_, live, now);
        }

        for (const std::string& key : d.dial) begin_dial(key);

        elect(live, now);
        publish_snapshot();
    }

    void begin_dial(const std::string& key) {
        if (peers_.count(key)) return;
        const Millis now = now_ms();
        if (store_.is_banned(key, now)) return;

        std::string ip;
        std::uint16_t port = 0;
        if (!split_peer_key(key, ip, port)) return;

        boost::system::error_code ec;
        const auto addr = boost::asio::ip::make_address(ip, ec);
        if (ec) return;   // hostnames are resolved by the DNS seeder, not here

        store_.on_dial_started(key, now);
        ++tel_.dials_started;

        auto sock = std::make_shared<tcp::socket>(io_);
        auto self = shared_from_this();
        const tcp::endpoint ep(addr, port);

        // A connect timer, because async_connect on a black-holed address can
        // hang for the OS default (minutes) and would hold a dial slot the
        // whole time.
        auto timer = std::make_shared<boost::asio::steady_timer>(io_);
        timer->expires_after(std::chrono::milliseconds(cfg_.connect_timeout_ms));
        timer->async_wait([sock](const boost::system::error_code& tec) {
            if (!tec) { boost::system::error_code ig; sock->close(ig); }
        });

        sock->async_connect(ep, [self, key, sock, timer](const boost::system::error_code& cec) {
            timer->cancel();
            if (cec) {
                self->store_.on_dial_failed(key, self->now_ms());
                ++self->tel_.dials_failed;
                return;
            }
            self->on_connected(key, std::move(*sock));
        });
    }

    void on_connected(const std::string& key, tcp::socket sock) {
        if (peers_.count(key)) return;
        const Millis now = now_ms();

        auto [it, ok] = peers_.emplace(key, Peer(cfg_.dos));
        if (!ok) return;
        Peer& p = it->second;
        p.key      = key;
        p.netgroup = netgroup16_of_key(key);
        p.connected_at_ms = now;
        p.ref.addr = key;
        if (const PeerRecord* r = store_.find(key)) p.is_protected = r->is_protected;

        auto self = shared_from_this();
        levinns::LinkCallbacks cb;
        cb.our_sync_data = [self]() -> PeerSyncData {
            return self->deps_.serving ? self->deps_.serving->our_sync_data() : PeerSyncData{};
        };
        cb.on_handshaked = [self, key](const PeerRef& ref) { self->on_handshaked(key, ref); };
        cb.on_peer_sync_data = [self, key](const PeerRef& ref, const PeerSyncData& d) {
            self->on_peer_sync(key, ref, d);
        };
        cb.on_peerlist = [self, key](const PeerRef&, const std::vector<levinns::PeerlistEntry>& v) {
            self->on_peerlist(key, v);
        };
        cb.on_frame = [self, key](const PeerRef& ref, const levinns::BucketHead& h,
                                  const std::uint8_t* body, std::size_t n) {
            self->on_frame(key, ref, h, body, n);
        };
        cb.on_closed = [self, key](const PeerRef&, levinns::LinkClose c, const std::string& why) {
            self->close_peer(key, std::string(levinns::to_string(c)) + ": " + why,
                             /*healthy=*/false);
        };

        p.link = levinns::LevinLink::create(std::move(sock), cfg_.link, std::move(cb));
        p.link->start();
    }

    // --- link callbacks -----------------------------------------------------
    void on_handshaked(const std::string& key, const PeerRef& ref) {
        Peer* p = find(key);
        if (!p) return;
        const Millis now = now_ms();
        p->handshaked = true;
        p->handshaked_at_ms = now;
        p->ref = ref;
        store_.on_handshaked(key, ref.peer_id, now);
        ++tel_.handshakes;
        publish_snapshot();
    }

    void on_peer_sync(const std::string& key, const PeerRef& ref, const PeerSyncData& d) {
        Peer* p = find(key);
        if (!p) return;
        p->sync = d;
        p->last_sync_ms = now_ms();
        p->ref = ref;
        if (deps_.index) deps_.index->on_peer_sync_data(ref, d);
        publish_snapshot();
    }

    void on_peerlist(const std::string& key, const std::vector<levinns::PeerlistEntry>& v) {
        // The wire cap (250) is enforced by the decoder; a peer that gets past
        // it did so because the limit was widened, so re-assert it here and
        // treat the excess as a fault rather than silently learning from it.
        if (v.size() > levinns::MAX_PEERS_IN_HANDSHAKE) {
            raise_fault(key, DosFault::OversizePeerlist, "peerlist over the wire cap");
            return;
        }
        const Millis now = now_ms();
        for (const levinns::PeerlistEntry& e : v) {
            // v1 dials IPv4 only; an IPv6 or onion entry is remembered by
            // nobody rather than stored as an address we can never reach.
            if (e.adr.kind != levinns::NetworkAddress::Kind::Ipv4) continue;
            const auto oct = levinns::ipv4_octets(e.adr.m_ip);
            const std::string ip = std::to_string(oct[0]) + "." + std::to_string(oct[1]) + "."
                                 + std::to_string(oct[2]) + "." + std::to_string(oct[3]);
            if (oct[0] == 0 || oct[0] == 127) continue;
            if (e.adr.port == 0) continue;
            store_.add(make_peer_key(ip, e.adr.port), PeerSource::Peerlist, now,
                       e.last_seen, e.id, e.pruning_seed);
        }
    }

    void on_frame(const std::string& key, const PeerRef& ref, const levinns::BucketHead& h,
                  const std::uint8_t* body, std::size_t n) {
        Peer* p = find(key);
        if (!p) return;
        const Millis now = now_ms();
        ++tel_.frames_in;
        ++tel_.frames_by_cmd[h.command];

        // Count transactions, not frames, for the 2002 bucket: a peer that
        // batches 500 txs into one frame has spent 500 tokens.
        std::size_t units = 1;
        levinns::NewTransactions txm;
        levinns::MessageError err = levinns::MessageError::None;
        const bool is_tx = (h.command == levinns::CMD_NEW_TRANSACTIONS);
        if (is_tx) {
            if (!levinns::decode_new_transactions(body, n, txm, err)) {
                raise_fault(key, DosFault::MalformedBody, "2002 body");
                return;
            }
            units = txm.txs.empty() ? 1 : txm.txs.size();
        }

        DosFault fault = DosFault::None;
        const DosAction act = p->dos.on_frame(h.command, n, units, now, fault);
        if (act != DosAction::Accept) {
            ++tel_.frames_dropped_dos;
            apply_action(key, act, fault, "inbound budget");
            return;
        }

        switch (h.command) {
            case levinns::CMD_NEW_BLOCK:
            case levinns::CMD_NEW_FLUFFY_BLOCK: handle_new_block(key, ref, h, body, n); return;
            case levinns::CMD_NEW_TRANSACTIONS: handle_transactions(key, ref, txm);      return;
            case levinns::CMD_RESPONSE_CHAIN_ENTRY:  handle_chain_entry(key, ref, body, n); return;
            case levinns::CMD_RESPONSE_GET_OBJECTS:  handle_objects(key, ref, body, n);     return;
            case levinns::CMD_REQUEST_CHAIN:         serve_chain(key, body, n);             return;
            case levinns::CMD_REQUEST_GET_OBJECTS:   serve_objects(key, body, n);           return;
            case levinns::CMD_REQUEST_FLUFFY_MISSING_TX: serve_fluffy_missing(key, ref, body, n); return;
            case levinns::CMD_GET_TXPOOL_COMPLEMENT: serve_txpool_complement(key, body, n); return;
            default:
                // An unknown NOTIFICATION is ignored (nothing is owed back);
                // C1b already answers an unknown INVOKE with
                // LEVIN_ERROR_CONNECTION_HANDLER_NOT_DEFINED so the peer's own
                // FIFO matcher stays in step.
                return;
        }
    }

    // --- inbound handlers ---------------------------------------------------
    void handle_new_block(const std::string& key, const PeerRef& ref,
                          const levinns::BucketHead& h, const std::uint8_t* body, std::size_t n) {
        levinns::NewBlock m;
        levinns::MessageError err = levinns::MessageError::None;
        const bool fluffy = (h.command == levinns::CMD_NEW_FLUFFY_BLOCK);
        const bool ok = fluffy ? levinns::decode_new_fluffy_block(body, n, m, err)
                               : levinns::decode_new_block(body, n, m, err);
        if (!ok) { raise_fault(key, DosFault::MalformedBody, "block push body"); return; }

        if (Peer* p = find(key)) p->last_relay_ms = now_ms();
        ++tel_.blocks_in;
        if (deps_.index)
            deps_.index->on_new_block(ref, std::move(m.b), m.current_blockchain_height, fluffy);
    }

    void handle_transactions(const std::string& key, const PeerRef& ref,
                             levinns::NewTransactions& m) {
        if (Peer* p = find(key)) p->last_relay_ms = now_ms();
        if (m.txs.empty()) return;

        // In-batch duplicate blobs are dropped BEFORE the pool sees them: the
        // work of decoding the same bytes twice is exactly what a prober wants
        // to buy for the price of one frame.
        std::vector<std::vector<std::uint8_t>> uniq;
        uniq.reserve(m.txs.size());
        bool dup = false;
        for (auto& blob : m.txs) {
            bool seen = false;
            for (const auto& u : uniq) if (u == blob) { seen = true; break; }
            if (seen) { dup = true; continue; }
            uniq.push_back(std::move(blob));
        }
        if (dup) raise_fault(key, DosFault::DuplicateTxInBatch, "duplicate blob in one 2002");

        tel_.txs_in += uniq.size();
        if (!deps_.txpool) return;
        const std::vector<TxRelayVerdict> verdicts =
            deps_.txpool->on_relayed(ref, std::move(uniq), m.dandelionpp_fluff);
        for (const TxRelayVerdict& v : verdicts)
            if (v.drop_offense) { raise_fault(key, DosFault::MalformedBody, "relayed tx offence"); break; }
    }

    void handle_chain_entry(const std::string& key, const PeerRef& ref,
                            const std::uint8_t* body, std::size_t n) {
        ChainEntry e;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::decode_response_chain_entry(body, n, e, err)) {
            raise_fault(key, DosFault::MalformedBody, "2007 body");
            return;
        }
        ++tel_.chain_entries_in;
        if (Peer* p = find(key)) { p->wire_busy = false; pump(*p); }
        if (deps_.index) deps_.index->on_chain_entry(ref, std::move(e));
    }

    void handle_objects(const std::string& key, const PeerRef& ref,
                        const std::uint8_t* body, std::size_t n) {
        levinns::ResponseGetObjects m;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::decode_response_get_objects(body, n, m, err)) {
            raise_fault(key, DosFault::MalformedBody, "2004 body");
            return;
        }
        Peer* p = find(key);
        if (!p) return;
        ++tel_.objects_in;
        p->wire_busy = false;

        const std::uint64_t span_id = p->in_flight_span;
        p->in_flight_span = kNoSpan;
        auto it = p->spans.find(span_id);
        if (span_id == kNoSpan || it == p->spans.end()) {
            // No span owns this: the C1b expect-latch already refused an
            // entirely unsolicited 2004, so this is our own bookkeeping gone
            // wrong rather than the peer's fault. Forward it whole and move on.
            if (deps_.index)
                deps_.index->on_objects(ref, std::move(m.blocks), std::move(m.missed_ids),
                                        m.current_blockchain_height);
            pump(*p);
            return;
        }

        Span& s = it->second;
        s.in_flight_ids = 0;
        s.peer_height = m.current_blockchain_height;
        for (BlockEntry& b : m.blocks) s.blocks.push_back(std::move(b));
        for (const Hash& id : m.missed_ids) s.missed.push_back(id);

        if (s.issued < s.ids.size()) {
            issue_next_chunk(*p, span_id);   // more chunks of the same span
            pump(*p);
            return;
        }

        // Span complete: emit ONE on_objects, exactly the span C2 planned.
        std::vector<BlockEntry> blocks = std::move(s.blocks);
        std::vector<Hash>       missed = std::move(s.missed);
        const std::uint64_t     height = s.peer_height;
        p->spans.erase(it);
        p->span_order.erase(std::remove(p->span_order.begin(), p->span_order.end(), span_id),
                            p->span_order.end());
        if (deps_.index)
            deps_.index->on_objects(ref, std::move(blocks), std::move(missed), height);
        pump(*p);
    }

    // --- serving (the state_normal obligation) ------------------------------
    void serve_chain(const std::string& key, const std::uint8_t* body, std::size_t n) {
        levinns::RequestChain m;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::decode_request_chain(body, n, m, err)) {
            raise_fault(key, DosFault::MalformedBody, "2006 body");
            return;
        }
        Peer* p = find(key);
        if (!p || !p->link || !deps_.serving) return;

        std::optional<ChainEntry> sup = deps_.serving->find_supplement(m.block_ids);
        if (!sup) {
            // monerod's own behaviour: no common block means the connection is
            // useless to this peer, and a misleading supplement is worse than a
            // clean close.
            ++tel_.served_declined;
            close_peer(key, "no common block for a chain request", /*healthy=*/true);
            return;
        }
        std::vector<std::uint8_t> out;
        if (!levinns::encode_response_chain_entry(*sup, out, err)) return;
        p->link->send_notify(levinns::CMD_RESPONSE_CHAIN_ENTRY, out);
        ++tel_.served_chain;
    }

    void serve_objects(const std::string& key, const std::uint8_t* body, std::size_t n) {
        levinns::RequestGetObjects m;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::decode_request_get_objects(body, n, m, err)) {
            raise_fault(key, DosFault::MalformedBody, "2003 body");
            return;
        }
        Peer* p = find(key);
        if (!p || !p->link || !deps_.serving) return;
        if (m.blocks.size() > MAX_OBJECT_REQUEST_IDS) {
            raise_fault(key, DosFault::MalformedBody, "2003 over the 100-id cap");
            return;
        }

        levinns::ResponseGetObjects r;
        r.current_blockchain_height = deps_.serving->our_sync_data().current_height;
        for (const Hash& id : m.blocks) {
            std::optional<BlockEntry> b = deps_.serving->get_block_entry(id, m.prune);
            if (b) r.blocks.push_back(std::move(*b));
            else   r.missed_ids.push_back(id);
        }
        if (!r.missed_ids.empty()) ++tel_.served_declined;
        std::vector<std::uint8_t> out;
        if (!levinns::encode_response_get_objects(r, out, err)) return;
        p->link->send_notify(levinns::CMD_RESPONSE_GET_OBJECTS, out);
        ++tel_.served_objects;
    }

    void serve_fluffy_missing(const std::string& key, const PeerRef& ref,
                              const std::uint8_t* body, std::size_t n) {
        levinns::RequestFluffyMissingTx m;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::decode_request_fluffy_missing_tx(body, n, m, err)) {
            raise_fault(key, DosFault::MalformedBody, "2009 body");
            return;
        }
        Peer* p = find(key);
        if (!p || !p->link) return;

        // C5 owns the retained-block book (D-10), so it answers first; the
        // index's retained window is the fallback for anything older.
        FluffyMissingHandler h;
        { std::lock_guard<std::mutex> lk(snap_mu_); h = fluffy_handler_; }
        std::vector<std::uint8_t> reply;
        if (h && h(ref, m.block_hash, m.current_blockchain_height, m.missing_tx_indices, reply)) {
            p->link->send_notify(levinns::CMD_NEW_FLUFFY_BLOCK, reply);
            ++tel_.served_fluffy;
            return;
        }
        if (!deps_.serving) { ++tel_.served_declined; return; }
        std::optional<BlockEntry> b = deps_.serving->get_block_entry(m.block_hash, /*prune=*/false);
        if (!b) { ++tel_.served_declined; return; }

        levinns::NewBlock nb;
        nb.b = std::move(*b);
        nb.current_blockchain_height = m.current_blockchain_height;
        std::vector<std::uint8_t> out;
        if (!levinns::encode_new_fluffy_block(nb, out, err)) return;
        p->link->send_notify(levinns::CMD_NEW_FLUFFY_BLOCK, out);
        ++tel_.served_fluffy;
    }

    void serve_txpool_complement(const std::string& key, const std::uint8_t* body, std::size_t n) {
        levinns::GetTxpoolComplement m;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::decode_get_txpool_complement(body, n, m, err)) {
            raise_fault(key, DosFault::MalformedBody, "2010 body");
            return;
        }
        // R-CITIZEN: a pool-scoped node does not serve its txpool complement.
        // Declining costs the peer nothing (2010 expects no answer) and keeps
        // us from re-broadcasting transactions we never validated at full depth.
        ++tel_.served_declined;
        (void)key;
    }

    // --- outbound pump ------------------------------------------------------
    // The 2003/2006 answers come back as NOTIFICATIONS matched by C1b's single
    // ExpectResponse latch, so exactly ONE of them may be in flight per link.
    // Everything else queues behind it here rather than being refused.
    void pump(Peer& p) {
        if (!p.link || p.wire_busy || p.pending.empty()) return;
        Pending& next = p.pending.front();
        if (!p.link->send_notify_answered_request(next.cmd, next.body)) return;
        p.wire_busy = true;
        p.in_flight_span = next.span;
        p.pending.pop_front();
    }

    void issue_next_chunk(Peer& p, std::uint64_t span_id) {
        auto it = p.spans.find(span_id);
        if (it == p.spans.end()) return;
        Span& s = it->second;
        if (s.issued >= s.ids.size()) return;

        const std::size_t take = std::min(MAX_OBJECT_REQUEST_IDS, s.ids.size() - s.issued);
        levinns::RequestGetObjects m;
        m.blocks.assign(s.ids.begin() + static_cast<std::ptrdiff_t>(s.issued),
                        s.ids.begin() + static_cast<std::ptrdiff_t>(s.issued + take));
        m.prune = s.prune;
        std::vector<std::uint8_t> body;
        levinns::MessageError err = levinns::MessageError::None;
        if (!levinns::encode_request_get_objects(m, body, err)) return;

        s.issued        += take;
        s.in_flight_ids  = take;
        p.pending.push_back(Pending{levinns::CMD_REQUEST_GET_OBJECTS, std::move(body), span_id});
    }

    std::size_t spans_outstanding() const {
        std::size_t n = 0;
        for (const auto& [k, p] : peers_) n += p.spans.size();
        return n;
    }

    // --- broadcast ----------------------------------------------------------
    std::size_t do_broadcast(std::uint32_t cmd, const std::vector<std::uint8_t>& frame) {
        std::size_t written = 0;
        for (auto& [key, p] : peers_) {
            if (!p.handshaked || !p.link) continue;
            // "state_normal peers only": we cannot read the peer's own state, so
            // the observable proxy is whether it has ever relayed to us on this
            // connection. A peer that holds us in state_synchronizing sends no
            // relay traffic, which is exactly what relay_silent() measures.
            if (p.link->liveness().relay_silent(now_ms())) continue;
            if (p.link->send_notify(cmd, frame)) ++written;
        }
        ++tel_.broadcasts;
        tel_.broadcast_peers += written;
        return written;
    }

    // --- faults and teardown ------------------------------------------------
    void raise_fault(const std::string& key, DosFault f, const std::string& why) {
        Peer* p = find(key);
        const Millis now = now_ms();
        DosAction act = DosAction::Drop;
        if (p) act = p->dos.on_fault(f, now);
        else   act = fault_points(f) >= P2P_FAILS_BEFORE_BAN ? DosAction::Ban : DosAction::Drop;
        apply_action(key, act, f, why);
    }

    void apply_action(const std::string& key, DosAction act, DosFault f, const std::string& why) {
        const Millis now = now_ms();
        switch (act) {
            case DosAction::Accept:
            case DosAction::Drop:
                store_.penalize(key, fault_points(f), now);
                return;
            case DosAction::Disconnect:
                store_.penalize(key, fault_points(f), now);
                close_peer(key, std::string(to_string(f)) + ": " + why, /*healthy=*/false);
                return;
            case DosAction::Ban:
                store_.ban(key, cfg_.dos.ban_ms, now);
                ++tel_.bans;
                close_peer(key, std::string("banned, ") + to_string(f) + ": " + why,
                           /*healthy=*/false);
                return;
        }
    }

    // REENTRANCY. LevinLink::stop() runs its close path SYNCHRONOUSLY, and our
    // on_closed callback calls straight back into close_peer(). So the entry
    // must leave the map BEFORE the link is told to stop: otherwise the inner
    // call erases it, the outer call's iterator and `Peer&` dangle, and the
    // pool segfaults on the first peer it drops. Moving the Peer out first
    // makes the reentrant call a no-op find() miss.
    void close_peer(const std::string& key, const std::string& why, bool healthy) {
        auto it = peers_.find(key);
        if (it == peers_.end()) return;
        Peer p = std::move(it->second);
        peers_.erase(it);

        const bool was_handshaked = p.handshaked;
        const PeerRef ref = p.ref;
        tel_.last_close_peer = key;
        tel_.last_close_why  = why;
        if (p.link) p.link->stop(why);
        store_.on_disconnected(key, now_ms(), healthy && was_handshaked);
        if (was_handshaked && deps_.index) deps_.index->on_peer_gone(ref);
        publish_snapshot();
    }

    // --- views --------------------------------------------------------------
    Peer* find(const std::string& key) {
        auto it = peers_.find(key);
        return it == peers_.end() ? nullptr : &it->second;
    }

    std::vector<LivePeer> live_view() const {
        std::vector<LivePeer> out;
        out.reserve(peers_.size());
        for (const auto& [key, p] : peers_) {
            LivePeer lp;
            lp.key = key;
            lp.netgroup = p.netgroup;
            lp.peer_id = p.ref.peer_id;
            lp.handshaked = p.handshaked;
            lp.is_protected = p.is_protected;
            lp.connected_at_ms = p.connected_at_ms;
            lp.handshaked_at_ms = p.handshaked_at_ms;
            lp.sync = p.sync;
            lp.last_sync_ms = p.last_sync_ms;
            lp.dialing = !p.handshaked;
            out.push_back(std::move(lp));
        }
        return out;
    }

    void elect(const std::vector<LivePeer>& live, Millis now) {
        const std::string next = plan_.elect_primary(live, store_, primary_, now);
        primary_ = next;
    }

    void publish_snapshot() {
        std::vector<std::pair<PeerRef, PeerSyncData>> snap;
        std::map<std::uint32_t, std::size_t> groups;
        std::size_t handshaked = 0, dialing = 0, silent = 0;
        const Millis now = now_ms();
        for (const auto& [key, p] : peers_) {
            if (p.handshaked) {
                ++handshaked;
                snap.emplace_back(p.ref, p.sync);
                ++groups[p.netgroup];
                if (p.link && p.link->liveness().relay_silent(now)) ++silent;
            } else {
                ++dialing;
            }
        }
        std::lock_guard<std::mutex> lk(snap_mu_);
        snapshot_ = std::move(snap);
        netgroups_ = groups;
        tel_.peers_total      = peers_.size();
        tel_.peers_handshaked = handshaked;
        tel_.peers_dialing    = dialing;
        tel_.netgroups        = groups.size();
        tel_.eclipse_floor_met= groups.size() >= cfg_.dial.min_netgroups;
        tel_.relay_silent_peers = silent;
        tel_.primary          = primary_;
    }

    boost::asio::io_context&               io_;
    boost::asio::io_context::executor_type ex_;
    Config    cfg_;
    Deps      deps_;
    PeerStore store_;
    DialPlan  plan_;
    boost::asio::steady_timer tick_;
    std::chrono::steady_clock::time_point epoch_;

    std::map<std::string, Peer> peers_;
    std::uint64_t next_span_id_ = 1;
    std::string   primary_;
    bool          running_ = false;

    mutable std::mutex snap_mu_;
    std::vector<std::pair<PeerRef, PeerSyncData>> snapshot_;
    std::map<std::uint32_t, std::size_t>          netgroups_;
    PoolTelemetry                                 tel_;
    FluffyMissingHandler                          fluffy_handler_;
};

} // namespace c2pool::xmr::native::p2p
