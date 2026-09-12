// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_levin_link_kat.cpp
//
// Wave 1, component C1b: the HANDSHAKE / TIMED_SYNC exchange KAT. The other
// half of K-C1-3, and the pure checks for the FIFO reply matcher and the
// handshake state machine.
//
// The peer on the other end of the loopback is a hand-rolled monerod stand-in:
// it writes real levin frames built with C1a's encoders and parses ours with an
// INDEPENDENT header reader (a few lines of little-endian loads, not
// levin_codec's read_header), so the two directions are each other's oracle
// rather than the same code agreeing with itself.
//
// THE THREE C1-LENS CORRECTIONS get an assertion each, because they were found
// by a live monerod and a later refactor would otherwise be free to undo them:
//
//   (a) SORTED KEY ORDER -- our HANDSHAKE request is scanned on the wire and
//       its key names must appear in ascending order, at the root and inside
//       node_data. monerod's section is a std::map; anything else is not
//       byte-parity, it is a different message.
//   (b) SIGNATURE_B = 0x01020101 -- the storage header on the wire must be the
//       nine bytes 01 11 01 01 01 01 02 01 01. Getting the byte order of the
//       second word wrong is invisible to a round-trip test and fatal against a
//       real daemon.
//   (c) TIMED_SYNC RESPONSE = payload_data + local_peerlist_new, and no more.
//       Asserted in both directions: a peer answer carrying ONLY payload_data
//       (no peerlist key at all) is accepted and is NOT a drop, and our own
//       answer to an inbound 1002 emits exactly one key, with no local_time and
//       no legacy local_peerlist.
//
// LIVE MODE (opt-in, never in CI):
//     xmr_levin_link_kat --live <host>:<port> [--net mainnet|testnet|stagenet]
// dials a real daemon, completes the handshake, sends one TIMED_SYNC, prints
// what came back and disconnects. Read-only: it advertises the peer's own top
// block back at it, asks for nothing and pushes nothing, so it costs the daemon
// one connection slot for about a second.
//
// STL plus boost::asio. No test framework, matching the neighbouring KATs.
// ---------------------------------------------------------------------------

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/p2p/xmr_levin_link.hpp"
#include "xmr_p2p_kat_util.hpp"

using namespace c2pool::xmr::native::levin;
namespace native = c2pool::xmr::native;
namespace kat    = c2pool::xmr::native::kat;
namespace epee   = c2pool::xmr::native::epee;
namespace asio   = boost::asio;
using tcp = asio::ip::tcp;

namespace {

constexpr std::uint64_t OUR_PEER_ID  = 0x0123456789abcdefull;
constexpr std::uint64_t PEER_PEER_ID = 0xfedcba9876543210ull;

// --- an independent frame reader for the stand-in peer -----------------------
struct RawFrame {
    std::uint64_t             signature = 0;
    std::uint64_t             cb = 0;
    bool                      have_to_return_data = false;
    std::uint32_t             command = 0;
    std::int32_t              return_code = 0;
    std::uint32_t             flags = 0;
    std::uint32_t             protocol_version = 0;
    std::vector<std::uint8_t> body;
};

std::uint64_t le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
std::uint32_t le32(const std::uint8_t* p) {
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

// --- the stand-in peer -------------------------------------------------------
class FakePeer {
public:
    explicit FakePeer(asio::io_context& io) : sock_(io) {}

    void adopt(tcp::socket s) { sock_ = std::move(s); arm(); }

    void write(const std::vector<std::uint8_t>& frame) {
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(frame), ec);
    }
    void shutdown() {
        boost::system::error_code ec;
        sock_.close(ec);
    }

    std::vector<RawFrame> frames;

private:
    void arm() {
        sock_.async_read_some(asio::buffer(chunk_),
            [this](const boost::system::error_code& ec, std::size_t n) {
                if (ec) return;
                buf_.insert(buf_.end(), chunk_, chunk_ + n);
                drain();
                arm();
            });
    }

    void drain() {
        for (;;) {
            if (buf_.size() < HEADER_SIZE) return;
            RawFrame f;
            const std::uint8_t* p = buf_.data();
            f.signature           = le64(p + 0);
            f.cb                  = le64(p + 8);
            f.have_to_return_data = p[16] != 0;
            f.command             = le32(p + 17);
            f.return_code         = static_cast<std::int32_t>(le32(p + 21));
            f.flags               = le32(p + 25);
            f.protocol_version    = le32(p + 29);
            if (f.cb > 64u * 1024u * 1024u) { buf_.clear(); return; }   // stand-in sanity
            if (buf_.size() < HEADER_SIZE + f.cb) return;
            f.body.assign(buf_.begin() + HEADER_SIZE,
                          buf_.begin() + HEADER_SIZE + static_cast<std::size_t>(f.cb));
            buf_.erase(buf_.begin(),
                       buf_.begin() + HEADER_SIZE + static_cast<std::ptrdiff_t>(f.cb));
            frames.push_back(std::move(f));
        }
    }

    tcp::socket               sock_;
    std::uint8_t              chunk_[8192]{};
    std::vector<std::uint8_t> buf_;
};

// --- the rig -----------------------------------------------------------------
struct Observed {
    std::vector<native::PeerSyncData>       sync;
    std::vector<PeerlistEntry>      peers;
    bool                                    handshaked = false;
    bool                                    closed     = false;
    LinkClose                               reason     = LinkClose::None;
    std::string                             why;
    std::vector<std::uint32_t>              frame_cmds;
};

native::PeerSyncData our_sync_fixture() {
    native::PeerSyncData s;
    s.current_height        = 1'700'001;
    s.cumulative_difficulty = native::U128{/*lo=*/0x1122334455667788ull, /*hi=*/0x9ull};
    s.top_id.fill(0xa5);
    s.top_version           = 16;
    s.pruning_seed          = 0;
    return s;
}

native::PeerSyncData peer_sync_fixture() {
    native::PeerSyncData s;
    s.current_height        = 1'700'042;
    s.cumulative_difficulty = native::U128{0x00ff00ff00ff00ffull, 0x1ull};
    s.top_id.fill(0x5a);
    s.top_version           = 16;
    s.pruning_seed          = 0;
    return s;
}

PeerlistEntry make_peer_entry(std::uint8_t d, std::uint16_t port) {
    PeerlistEntry e;
    e.adr.kind = NetworkAddress::Kind::Ipv4;
    e.adr.m_ip = ipv4_from_octets(203, 0, 113, d);
    e.adr.port = port;
    e.id        = 0x1000ull + d;
    e.last_seen = 1'760'000'000 + d;
    return e;
}

class Rig {
public:
    Rig() : peer(io) {}

    void build(LinkConfig cfg, bool install_frame_sink = false) {
        tcp::acceptor acc(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
        acc.listen();
        tcp::socket a(io), b(io);
        bool ok_a = false, ok_b = false;
        acc.async_accept(b, [&](const boost::system::error_code& ec) { ok_b = !ec; });
        a.async_connect(acc.local_endpoint(), [&](const boost::system::error_code& ec) { ok_a = !ec; });
        io.restart();
        io.run_for(std::chrono::seconds(2));
        kat::check(ok_a && ok_b, "rig: loopback pair connects");

        LinkCallbacks cb;
        cb.our_sync_data = []() { return our_sync_fixture(); };
        cb.on_peer_sync_data = [this](const native::PeerRef&, const native::PeerSyncData& s) {
            obs.sync.push_back(s);
        };
        cb.on_peerlist = [this](const native::PeerRef&,
                                const std::vector<PeerlistEntry>& p) {
            obs.peers.insert(obs.peers.end(), p.begin(), p.end());
        };
        cb.on_handshaked = [this](const native::PeerRef&) { obs.handshaked = true; };
        cb.on_closed = [this](const native::PeerRef&, LinkClose r, const std::string& w) {
            obs.closed = true; obs.reason = r; obs.why = w;
        };
        if (install_frame_sink) {
            cb.on_frame = [this](const native::PeerRef&, const BucketHead& h,
                                 const std::uint8_t*, std::size_t) {
                obs.frame_cmds.push_back(h.command);
            };
        }

        link = LevinLink::create(std::move(b), cfg, cb);
        peer.adopt(std::move(a));
        link->start();
        pump(60);
    }

    void pump(int ms = 120) {
        io.restart();
        io.run_for(std::chrono::milliseconds(ms));
    }

    // Pumps until the peer has seen at least `n` frames, or the budget runs out.
    bool wait_frames(std::size_t n, int budget_ms = 1500) {
        for (int spent = 0; spent < budget_ms && peer.frames.size() < n; spent += 50)
            pump(50);
        return peer.frames.size() >= n;
    }

    asio::io_context           io;
    FakePeer                   peer;
    std::shared_ptr<LevinLink> link;
    Observed                   obs;
};

// A config whose TIMED_SYNC beat is parked far in the future. The FIFO and
// expect-response tests are about what happens with EXACTLY the questions they
// asked, so a background beat sliding another invoke into the queue would be
// testing the scheduler instead.
LinkConfig quiet_config();

LinkConfig fast_config() {
    LinkConfig cfg;
    cfg.handshake.net         = XmrNet::Stagenet;
    cfg.handshake.our_peer_id = OUR_PEER_ID;
    cfg.handshake_timeout_ms   = 400;
    cfg.invoke_timeout_ms      = 400;
    cfg.timed_sync_interval_ms = 60;
    cfg.timed_sync_jitter_ms   = 10;
    cfg.peer_timeout_ms        = 100'000;   // off unless a test turns it on
    cfg.tick_ms                = 10;
    return cfg;
}

LinkConfig quiet_config() {
    LinkConfig cfg = fast_config();
    cfg.timed_sync_interval_ms = 100'000;
    cfg.timed_sync_jitter_ms   = 0;
    return cfg;
}

// The stand-in peer's HANDSHAKE answer, with knobs for every refusal.
std::vector<std::uint8_t> handshake_reply(NetworkId net,
                                          std::uint64_t peer_id,
                                          std::size_t   peerlist_n,
                                          std::uint32_t pruning_seed = 0) {
    HandshakeResponse r;
    r.node_data.network_id    = net;
    r.node_data.peer_id       = peer_id;
    r.node_data.my_port       = 38080;
    r.node_data.support_flags = SUPPORT_FLAG_FLUFFY_BLOCKS;
    r.payload_data            = peer_sync_fixture();
    r.payload_data.pruning_seed = pruning_seed;
    for (std::size_t i = 0; i < peerlist_n; ++i)
        r.local_peerlist_new.push_back(
            make_peer_entry(static_cast<std::uint8_t>(i & 0xff),
                            static_cast<std::uint16_t>(38080 + i)));
    std::vector<std::uint8_t> body;
    MessageError err = MessageError::None;
    encode_handshake_response(r, body, err);
    // A REAL daemon answers with 1, not LEVIN_OK: epee copies
    // node_server::handle_handshake's own `return 1` into the header. The
    // stand-in does the same so this KAT would have caught the live failure.
    return make_response(CMD_HANDSHAKE, body, RC_HANDLER_OK);
}

// Where a key name appears inside a body, or npos. Names are length-prefixed by
// a single byte, so searching for (len, name) is unambiguous enough for an
// ordering assertion.
std::size_t key_offset(const std::vector<std::uint8_t>& body, const char* name) {
    const std::size_t n = std::strlen(name);
    if (n == 0 || n > 255) return std::string::npos;
    for (std::size_t i = 0; i + 1 + n <= body.size(); ++i) {
        if (body[i] != static_cast<std::uint8_t>(n)) continue;
        if (std::memcmp(body.data() + i + 1, name, n) == 0) return i;
    }
    return std::string::npos;
}

bool contains_ascii(const std::vector<std::uint8_t>& body, const char* needle) {
    return key_offset(body, needle) != std::string::npos;
}

// =============================================================================
// 1. The handshake, and corrections (a) and (b) on our own request bytes.
// =============================================================================
void test_handshake_happy_path() {
    Rig r;
    r.build(fast_config());
    kat::check(r.wait_frames(1), "handshake: the request reached the peer");
    if (r.peer.frames.empty()) return;

    const RawFrame& f = r.peer.frames[0];
    kat::checkf(f.command == CMD_HANDSHAKE, "handshake: command is 1001 (%u)", f.command);
    kat::check(f.signature == SIGNATURE, "handshake: Bender's nightmare on the wire");
    kat::check(f.protocol_version == PROTOCOL_VER_1, "handshake: protocol version 1");
    kat::check((f.flags & PACKET_REQUEST) != 0 && (f.flags & PACKET_RESPONSE) == 0,
               "handshake: flagged as a request");
    kat::check(f.have_to_return_data, "handshake: an answer is owed (it is an invoke)");
    kat::check(f.return_code == RC_OK, "handshake: return code 0 in a request");
    kat::checkf(f.cb == f.body.size(), "handshake: cb matches the body (%llu)",
                static_cast<unsigned long long>(f.cb));

    // CORRECTION (b): the epee storage header, byte for byte.
    const std::vector<std::uint8_t> want_hdr =
        kat::from_hex("01 11 01 01  01 01 02 01  01");
    kat::check(f.body.size() >= 9, "handshake: body carries a storage header");
    if (f.body.size() >= 9) {
        std::vector<std::uint8_t> got_hdr(f.body.begin(), f.body.begin() + 9);
        kat::check_bytes(got_hdr, want_hdr,
                         "correction (b): SIGNATURE_B is 01 01 02 01 on the wire");
    }

    // CORRECTION (a): sorted key order, at the root and one level down.
    const std::size_t o_node = key_offset(f.body, "node_data");
    const std::size_t o_pay  = key_offset(f.body, "payload_data");
    kat::check(o_node != std::string::npos && o_pay != std::string::npos,
               "handshake: both root keys are present");
    kat::check(o_node < o_pay,
               "correction (a): root keys sorted -- node_data before payload_data");

    const std::size_t o_nid   = key_offset(f.body, "network_id");
    const std::size_t o_pid   = key_offset(f.body, "peer_id");
    const std::size_t o_port  = key_offset(f.body, "my_port");
    const std::size_t o_flags = key_offset(f.body, "support_flags");
    kat::check(o_port < o_nid && o_nid < o_pid && o_pid < o_flags,
               "correction (a): node_data keys sorted -- my_port, network_id, peer_id, support_flags");

    const std::size_t o_cd = key_offset(f.body, "cumulative_difficulty");
    const std::size_t o_ch = key_offset(f.body, "current_height");
    const std::size_t o_ti = key_offset(f.body, "top_id");
    const std::size_t o_tv = key_offset(f.body, "top_version");
    kat::check(o_cd < o_ch && o_ch < o_ti && o_ti < o_tv,
               "correction (a): CORE_SYNC_DATA keys sorted");

    // And the request decodes to what we meant to say.
    HandshakeRequest req;
    MessageError err = MessageError::None;
    const bool ok = decode_handshake_request(f.body.data(), f.body.size(), req, err);
    kat::checkf(ok, "handshake: our request decodes (%s)", to_string(err));
    if (ok) {
        kat::check(req.node_data.network_id == NETWORK_ID_STAGENET,
                   "handshake: stagenet network id");
        kat::check(req.node_data.peer_id == OUR_PEER_ID, "handshake: our peer id");
        kat::check(req.node_data.my_port == 0,
                   "handshake: my_port 0 -- outbound-only, no PING call-back");
        kat::check(req.node_data.support_flags == SUPPORT_FLAG_FLUFFY_BLOCKS,
                   "handshake: FLUFFY_BLOCKS advertised up front");
        const auto ours = our_sync_fixture();
        kat::check(req.payload_data.current_height == ours.current_height
                   && req.payload_data.top_id == ours.top_id
                   && req.payload_data.top_version == ours.top_version,
                   "handshake: CORE_SYNC_DATA is what our chain view said");
    }

    // Answer it.
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 3));
    r.pump(200);

    kat::check(r.link->handshaked(), "handshake: the link reports Handshaked");
    kat::check(r.obs.handshaked, "handshake: on_handshaked fired");
    kat::check(!r.obs.closed, "handshake: the link stayed open");
    kat::checkf(r.obs.sync.size() == 1, "handshake: one sync-data delivery (%zu)",
                r.obs.sync.size());
    if (!r.obs.sync.empty()) {
        kat::check(r.obs.sync[0].current_height == peer_sync_fixture().current_height,
                   "handshake: the peer's height reached C2");
        kat::check(r.obs.sync[0].support_flags == SUPPORT_FLAG_FLUFFY_BLOCKS,
                   "handshake: support_flags folded in from basic_node_data");
    }
    kat::checkf(r.obs.peers.size() == 3, "handshake: three peerlist entries (%zu)",
                r.obs.peers.size());
    kat::check(r.link->peer().peer_id == PEER_PEER_ID,
               "handshake: the PeerRef carries the peer id");

    // The cap flip: a 300 KiB fluffy block is over the pre-handshake ceiling and
    // under 2008's own cap, so it can only arrive after the flip.
    r.peer.write(make_notify(CMD_NEW_FLUFFY_BLOCK,
                             std::vector<std::uint8_t>(300u * 1024u, 0x7e)));
    r.pump(250);
    kat::check(!r.obs.closed, "cap flip: a 300 KiB push after the handshake is accepted");
}

// =============================================================================
// 2. Correction (c), both directions.
// =============================================================================
void test_timed_sync_response_shape() {
    Rig r;
    r.build(fast_config());
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(150);
    kat::check(r.link->handshaked(), "timed-sync: handshake landed");
    kat::check(r.obs.peers.empty(),
               "correction (c): an EMPTY peerlist in the handshake is not a fault");

    // --- the peer asks us. Our answer is the thing under test. ---------------
    {
        TimedSyncRequest req;
        req.payload_data = peer_sync_fixture();
        std::vector<std::uint8_t> body;
        MessageError err = MessageError::None;
        encode_timed_sync_request(req, body, err);
        const std::size_t before = r.peer.frames.size();
        r.peer.write(make_invoke(CMD_TIMED_SYNC, body));
        r.wait_frames(before + 1);

        kat::checkf(r.peer.frames.size() > before,
                    "timed-sync: we answered the peer's invoke (%zu frames)",
                    r.peer.frames.size());
        if (r.peer.frames.size() > before) {
            const RawFrame& ans = r.peer.frames[before];
            kat::check(ans.command == CMD_TIMED_SYNC, "timed-sync: answer is command 1002");
            kat::check((ans.flags & PACKET_RESPONSE) != 0,
                       "timed-sync: answer is flagged as a response");
            kat::checkf(ans.return_code == RC_HANDLER_OK,
                        "timed-sync: we answered with monerod's own handler code 1 (%d)",
                        ans.return_code);

            // CORRECTION (c), writing side.
            kat::check(!contains_ascii(ans.body, "local_time"),
                       "correction (c): our answer carries NO local_time");
            kat::check(!contains_ascii(ans.body, "local_peerlist"),
                       "correction (c): our answer carries NO legacy local_peerlist");
            kat::check(contains_ascii(ans.body, "payload_data"),
                       "correction (c): our answer carries payload_data");

            epee::Value root;
            MessageError perr = MessageError::None;
            if (parse_body(ans.body.data(), ans.body.size(), root, perr)) {
                kat::checkf(root.obj.size() == 1,
                            "correction (c): an empty peerlist emits exactly one root key (%zu)",
                            root.obj.size());
                if (root.obj.size() == 1)
                    kat::check(root.obj[0].name == "payload_data",
                               "correction (c): and that key is payload_data");
            } else {
                kat::check(false, "timed-sync: our own answer parses");
            }

            TimedSyncResponse decoded;
            MessageError derr = MessageError::None;
            kat::check(decode_timed_sync_response(ans.body.data(), ans.body.size(),
                                                  decoded, derr),
                       "timed-sync: our answer decodes as a TIMED_SYNC response");
            kat::check(decoded.payload_data.current_height == our_sync_fixture().current_height,
                       "timed-sync: we advertised our own height back");
            kat::check(decoded.local_peerlist_new.empty(),
                       "correction (c): an absent local_peerlist_new decodes to empty");
        }
    }

    // --- we ask the peer, and it answers with payload_data ONLY --------------
    {
        const std::size_t before = r.peer.frames.size();
        kat::check(r.wait_frames(before + 1),
                   "timed-sync: our own 1002 invoke went out on the 60 ms cadence");
        if (r.peer.frames.size() > before) {
            const RawFrame& q = r.peer.frames[before];
            kat::check(q.command == CMD_TIMED_SYNC && q.have_to_return_data,
                       "timed-sync: our beat is an invoke of 1002");
            TimedSyncRequest got;
            MessageError err = MessageError::None;
            kat::check(decode_timed_sync_request(q.body.data(), q.body.size(), got, err),
                       "timed-sync: our request decodes");

            TimedSyncResponse resp;
            resp.payload_data = peer_sync_fixture();
            resp.payload_data.current_height += 1;
            std::vector<std::uint8_t> body;
            MessageError eerr = MessageError::None;
            encode_timed_sync_response(resp, body, eerr);   // NO peerlist key at all
            kat::check(!contains_ascii(body, "local_peerlist_new"),
                       "correction (c): the fixture answer really omits the key");
            r.peer.write(make_response(CMD_TIMED_SYNC, body, RC_HANDLER_OK));
            r.pump(150);

            kat::check(!r.obs.closed,
                       "correction (c): a peerlist-free TIMED_SYNC answer is NOT a drop");
            kat::checkf(r.link->timed_syncs_answered() >= 1,
                        "timed-sync: the answer was matched (%llu)",
                        static_cast<unsigned long long>(r.link->timed_syncs_answered()));
            bool saw_new_height = false;
            for (const auto& s : r.obs.sync)
                if (s.current_height == peer_sync_fixture().current_height + 1)
                    saw_new_height = true;
            kat::check(saw_new_height, "timed-sync: the fresh height reached C2");
        }
    }
}

// =============================================================================
// 3. The cadence.
// =============================================================================
void test_timed_sync_cadence() {
    Rig r;
    r.build(fast_config());
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(100);

    // Answer every 1002 we see, for half a second. At 60 ms +/- 10 ms that is
    // six to ten beats; assert three so the check is about the cadence
    // existing, not about the scheduler's exact luck.
    std::size_t answered = 0;
    std::size_t seen     = 0;   // cursor into the peer's frame log
    for (int spent = 0; spent < 600; spent += 20) {
        r.pump(20);
        for (std::size_t i = seen; i < r.peer.frames.size(); ++i) {
            const RawFrame& f = r.peer.frames[i];
            if (f.command == CMD_TIMED_SYNC && f.have_to_return_data) {
                TimedSyncResponse resp;
                resp.payload_data = peer_sync_fixture();
                std::vector<std::uint8_t> body;
                MessageError err = MessageError::None;
                encode_timed_sync_response(resp, body, err);
                r.peer.write(make_response(CMD_TIMED_SYNC, body, RC_HANDLER_OK));
                ++answered;
            }
            seen = i + 1;
        }
    }
    kat::checkf(answered >= 3, "cadence: at least three TIMED_SYNC beats in 600 ms (%zu)",
                answered);
    kat::checkf(r.link->timed_syncs_answered() >= 3,
                "cadence: each beat was matched to its answer (%llu)",
                static_cast<unsigned long long>(r.link->timed_syncs_answered()));
    kat::check(!r.obs.closed, "cadence: the link stayed open across many beats");
}

// =============================================================================
// 4. FIFO reply matching.
// =============================================================================
void test_fifo_reply_matching() {
    Rig r;
    r.build(quiet_config());
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(80);
    kat::check(r.link->handshaked(), "fifo: handshake landed");

    // Two questions in the air at once. Levin carries no id, so the ONLY thing
    // that says which answer belongs to which is arrival order.
    r.link->send_invoke(CMD_REQUEST_SUPPORT_FLAGS, encode_empty_request());
    r.link->send_invoke(CMD_PING, encode_empty_request());
    r.pump(80);
    kat::checkf(r.link->invokes().size() == 2, "fifo: two invokes outstanding (%zu)",
                r.link->invokes().size());

    // Answer them OUT OF ORDER. monerod drops for exactly this, and so must we:
    // after one mismatched answer no later answer means anything.
    PingResponse pong;
    pong.status  = PING_OK_RESPONSE_STATUS_TEXT;
    pong.peer_id = PEER_PEER_ID;
    std::vector<std::uint8_t> pong_body;
    MessageError err = MessageError::None;
    encode_ping_response(pong, pong_body, err);
    r.peer.write(make_response(CMD_PING, pong_body, RC_HANDLER_OK));
    r.pump(150);

    kat::check(r.obs.closed, "fifo: an out-of-order answer closes the link");
    kat::checkf(r.obs.reason == LinkClose::ReplyMismatch,
                "fifo: closed as ReplyMismatch (%s)", to_string(r.obs.reason));
}

void test_unsolicited_response() {
    Rig r;
    r.build(quiet_config());
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(80);

    // Nothing is outstanding at this instant (the handshake was consumed and the
    // first beat has not fired). An answer now is an answer to nothing.
    TimedSyncResponse resp;
    resp.payload_data = peer_sync_fixture();
    std::vector<std::uint8_t> body;
    MessageError err = MessageError::None;
    encode_timed_sync_response(resp, body, err);
    r.peer.write(make_response(CMD_TIMED_SYNC, body, RC_HANDLER_OK));
    r.pump(30);

    kat::check(r.obs.closed, "unsolicited: an answer to nothing closes the link");
    kat::checkf(r.obs.reason == LinkClose::Unsolicited,
                "unsolicited: closed as Unsolicited (%s)", to_string(r.obs.reason));
}

void test_unsolicited_chain_entry() {
    Rig r;
    r.build(quiet_config(), /*install_frame_sink=*/true);
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(80);

    // 2007 answers 2006, and it arrives as a NOTIFICATION with no id: the only
    // defence against a peer pushing one unasked is the expect_response latch.
    native::ChainEntry ce;
    ce.start_height = 1;
    ce.total_height = 2;
    ce.ids.push_back(native::Hash{});
    std::vector<std::uint8_t> body;
    MessageError err = MessageError::None;
    encode_response_chain_entry(ce, body, err);
    r.peer.write(make_notify(CMD_RESPONSE_CHAIN_ENTRY, body));
    r.pump(120);

    kat::check(r.obs.closed, "expect-response: an unrequested 2007 closes the link");
    kat::checkf(r.obs.reason == LinkClose::Unsolicited,
                "expect-response: closed as Unsolicited (%s)", to_string(r.obs.reason));
}

void test_requested_chain_entry_is_accepted() {
    Rig r;
    r.build(quiet_config(), /*install_frame_sink=*/true);
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(80);

    RequestChain rq;
    rq.block_ids.push_back(native::Hash{});
    std::vector<std::uint8_t> qbody;
    MessageError qerr = MessageError::None;
    encode_request_chain(rq, qbody, qerr);
    kat::check(r.link->send_notify_answered_request(CMD_REQUEST_CHAIN, qbody),
               "expect-response: arming a 2006 succeeds");
    kat::check(!r.link->send_notify_answered_request(CMD_REQUEST_CHAIN, qbody),
               "expect-response: a second 2006 while one is in flight is refused");
    r.pump(50);

    native::ChainEntry ce;
    ce.start_height = 10;
    ce.total_height = 12;
    ce.ids.push_back(native::Hash{});
    std::vector<std::uint8_t> body;
    MessageError err = MessageError::None;
    encode_response_chain_entry(ce, body, err);
    r.peer.write(make_notify(CMD_RESPONSE_CHAIN_ENTRY, body));
    r.pump(120);

    kat::check(!r.obs.closed, "expect-response: a requested 2007 is accepted");
    kat::check(!r.link->expect().armed(), "expect-response: the latch disarmed");
    bool saw = false;
    for (std::uint32_t c : r.obs.frame_cmds) if (c == CMD_RESPONSE_CHAIN_ENTRY) saw = true;
    kat::check(saw, "expect-response: the frame reached the demux");
}

// =============================================================================
// 5. Every handshake refusal.
// =============================================================================
void expect_handshake_refusal(const char* label,
                              const std::vector<std::uint8_t>& reply,
                              HandshakeFailure want) {
    Rig r;
    r.build(fast_config());
    r.wait_frames(1);
    r.peer.write(reply);
    r.pump(200);
    kat::checkf(r.obs.closed, "%s: the link closed", label);
    kat::checkf(r.obs.reason == LinkClose::HandshakeRefused,
                "%s: closed as HandshakeRefused (%s)", label, to_string(r.obs.reason));
    kat::checkf(r.link->hs_failure() == want, "%s: refusal is %s (got %s)",
                label, to_string(want), to_string(r.link->hs_failure()));
    kat::checkf(!r.link->handshaked(), "%s: never reached Handshaked", label);
}

void test_handshake_refusals() {
    expect_handshake_refusal("network-id",
                             handshake_reply(NETWORK_ID_MAINNET, PEER_PEER_ID, 0),
                             HandshakeFailure::NetworkIdMismatch);
    expect_handshake_refusal("self-connect",
                             handshake_reply(NETWORK_ID_STAGENET, OUR_PEER_ID, 0),
                             HandshakeFailure::SelfConnect);
    expect_handshake_refusal("zero-peer-id",
                             handshake_reply(NETWORK_ID_STAGENET, 0, 0),
                             HandshakeFailure::ZeroPeerId);
    expect_handshake_refusal("peerlist-spam",
                             handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID,
                                             MAX_PEERS_IN_HANDSHAKE + 1),
                             HandshakeFailure::PeerlistSpam);
    expect_handshake_refusal("pruning-seed",
                             handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0,
                                             /*pruning_seed=*/5),
                             HandshakeFailure::BadPruningSeed);

    // A 250-entry peerlist is exactly at the ceiling and must be fine.
    {
        Rig r;
        r.build(fast_config());
        r.wait_frames(1);
        r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID,
                                     MAX_PEERS_IN_HANDSHAKE));
        r.pump(250);
        kat::check(r.link->handshaked(), "peerlist edge: exactly 250 entries is accepted");
        kat::checkf(r.obs.peers.size() == MAX_PEERS_IN_HANDSHAKE,
                    "peerlist edge: all 250 delivered (%zu)", r.obs.peers.size());
    }

    // A garbage body on 1001.
    {
        Rig r;
        r.build(fast_config());
        r.wait_frames(1);
        r.peer.write(make_response(CMD_HANDSHAKE,
                                   std::vector<std::uint8_t>{1, 2, 3, 4, 5}, RC_OK));
        r.pump(200);
        kat::check(r.obs.closed && r.link->hs_failure() == HandshakeFailure::BadEncoding,
                   "bad-body: an undecodable 1001 answer is BadEncoding");
    }

    // A negative levin return code instead of an answer.
    {
        Rig r;
        r.build(fast_config());
        r.wait_frames(1);
        r.peer.write(make_response(CMD_HANDSHAKE, {}, RC_ERROR_CONNECTION_NOT_FOUND));
        r.pump(200);
        kat::check(r.obs.closed, "peer-error: a refused handshake closes the link");
        kat::checkf(r.obs.reason == LinkClose::HandshakeRefused,
                    "peer-error: closed as HandshakeRefused (%s)", to_string(r.obs.reason));
    }
}

// =============================================================================
// 6. Deadlines.
// =============================================================================
void test_handshake_timeout() {
    Rig r;
    LinkConfig cfg = fast_config();
    cfg.handshake_timeout_ms = 80;
    r.build(cfg);
    r.wait_frames(1);
    r.pump(400);                          // the peer says nothing at all
    kat::check(r.obs.closed, "handshake timeout: an unanswered 1001 closes the link");
    kat::checkf(r.obs.reason == LinkClose::InvokeTimeout,
                "handshake timeout: closed as InvokeTimeout (%s)", to_string(r.obs.reason));
}

void test_peer_timeout_counts_inbound_only() {
    Rig r;
    LinkConfig cfg = fast_config();
    cfg.peer_timeout_ms        = 150;
    cfg.timed_sync_interval_ms = 40;
    cfg.timed_sync_jitter_ms   = 0;
    cfg.invoke_timeout_ms      = 100'000;   // isolate the liveness rule
    r.build(cfg);
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(60);
    kat::check(r.link->handshaked(), "peer timeout: handshake landed");

    // We keep WRITING (the beat keeps firing) and the peer never answers. Only
    // inbound bytes push the deadline, so this must still die.
    r.pump(500);
    kat::check(r.obs.closed, "peer timeout: a write-only connection still times out");
    kat::checkf(r.obs.reason == LinkClose::PeerUnresponsive,
                "peer timeout: closed as PeerUnresponsive (%s)", to_string(r.obs.reason));
}

// =============================================================================
// 7. The invokes we answer.
// =============================================================================
void test_we_answer_inbound_invokes() {
    Rig r;
    r.build(fast_config());
    r.wait_frames(1);
    r.peer.write(handshake_reply(NETWORK_ID_STAGENET, PEER_PEER_ID, 0));
    r.pump(60);

    std::size_t before = r.peer.frames.size();
    r.peer.write(make_invoke(CMD_REQUEST_SUPPORT_FLAGS, encode_empty_request()));
    r.wait_frames(before + 1);
    bool saw_flags = false, saw_pong = false, saw_decline = false;
    for (std::size_t i = before; i < r.peer.frames.size(); ++i) {
        const RawFrame& f = r.peer.frames[i];
        if (f.command == CMD_REQUEST_SUPPORT_FLAGS && (f.flags & PACKET_RESPONSE)) {
            kat::checkf(f.return_code == RC_HANDLER_OK,
                        "inbound invoke: our support-flags answer carries code 1 (%d)",
                        f.return_code);
            SupportFlagsResponse sf;
            MessageError err = MessageError::None;
            if (decode_support_flags_response(f.body.data(), f.body.size(), sf, err)
                && sf.support_flags == SUPPORT_FLAG_FLUFFY_BLOCKS)
                saw_flags = true;
        }
    }
    kat::check(saw_flags, "inbound invoke: we answer REQUEST_SUPPORT_FLAGS with our flags");

    before = r.peer.frames.size();
    r.peer.write(make_invoke(CMD_PING, encode_empty_request()));
    r.wait_frames(before + 1);
    for (std::size_t i = before; i < r.peer.frames.size(); ++i) {
        const RawFrame& f = r.peer.frames[i];
        if (f.command == CMD_PING && (f.flags & PACKET_RESPONSE)) {
            kat::checkf(f.return_code == RC_HANDLER_OK,
                        "inbound invoke: our PING answer carries code 1 (%d)",
                        f.return_code);
            PingResponse pr;
            MessageError err = MessageError::None;
            if (decode_ping_response(f.body.data(), f.body.size(), pr, err)
                && pr.status == PING_OK_RESPONSE_STATUS_TEXT
                && pr.peer_id == OUR_PEER_ID)
                saw_pong = true;
        }
    }
    kat::check(saw_pong, "inbound invoke: we answer PING with OK and our peer id");

    // An invoke nobody claimed. Silence would stall the PEER's matcher and it
    // would drop us, so the answer is an explicit error, not nothing.
    before = r.peer.frames.size();
    r.peer.write(make_invoke(CMD_GET_TXPOOL_COMPLEMENT, encode_empty_request()));
    r.wait_frames(before + 1);
    for (std::size_t i = before; i < r.peer.frames.size(); ++i) {
        const RawFrame& f = r.peer.frames[i];
        if (f.command == CMD_GET_TXPOOL_COMPLEMENT && (f.flags & PACKET_RESPONSE)
            && f.return_code == RC_ERROR_HANDLER_NOT_DEFINED)
            saw_decline = true;
    }
    kat::check(saw_decline,
               "inbound invoke: an unclaimed invoke is declined, never left silent");
    kat::check(!r.obs.closed, "inbound invoke: none of that closed the link");
}

// =============================================================================
// 8. Pure checks: the FIFO, the latch, the seeds, the machine.
// =============================================================================
void test_invoke_queue_pure() {
    InvokeQueue q;
    InvokeRecord rec;
    InvokeError  err = InvokeError::None;

    kat::check(!q.match_response(CMD_TIMED_SYNC, RC_OK, 0, rec, err)
               && err == InvokeError::Unsolicited,
               "queue: a response with an empty FIFO is Unsolicited");

    const auto s1 = q.push(CMD_HANDSHAKE, 1000, 5000);
    const auto s2 = q.push(CMD_TIMED_SYNC, 1100, 120000);
    kat::check(s1 && s2 && *s1 == 1 && *s2 == 2, "queue: sequence numbers increment");
    kat::check(q.size() == 2, "queue: both are outstanding");

    kat::check(!q.match_response(CMD_TIMED_SYNC, RC_OK, 1200, rec, err)
               && err == InvokeError::WrongCommand,
               "queue: answering the SECOND question first is WrongCommand");
    kat::check(q.size() == 2, "queue: a mismatch consumes nothing");

    kat::check(q.match_response(CMD_HANDSHAKE, RC_OK, 1200, rec, err)
               && rec.command == CMD_HANDSHAKE && rec.seq == 1,
               "queue: the front matches and pops");
    kat::check(q.last_matched_rtt_ms() == 200, "queue: round-trip time recorded");

    kat::check(!q.match_response(CMD_TIMED_SYNC, RC_ERROR_FORMAT, 1300, rec, err)
               && err == InvokeError::PeerError && rec.command == CMD_TIMED_SYNC,
               "queue: a negative return code still consumes the record");
    kat::check(q.empty(), "queue: and the FIFO is drained");

    // The return-code rule itself. monerod puts its HANDLER'S return value in
    // the response header and every handler ends in `return 1`, so success on
    // the wire is "not negative" -- insisting on LEVIN_OK refuses every honest
    // daemon, which is exactly what the first live run did.
    kat::check(!rc_is_error(RC_OK) && !rc_is_error(RC_HANDLER_OK) && !rc_is_error(2),
               "queue: LEVIN_OK, monerod's 1, and any other non-negative code are success");
    kat::check(rc_is_error(RC_ERROR_CONNECTION) && rc_is_error(RC_ERROR_FORMAT)
               && rc_is_error(RC_ERROR_HANDLER_NOT_DEFINED),
               "queue: every levin error code is negative");
    InvokeQueue q_ok;
    q_ok.push(CMD_HANDSHAKE, 0, 1000);
    kat::check(q_ok.match_response(CMD_HANDSHAKE, RC_HANDLER_OK, 1, rec, err)
               && err == InvokeError::None,
               "queue: a response carrying monerod's return code 1 MATCHES");

    // Deadlines: the OLDEST expired record is the one reported.
    InvokeQueue q2;
    q2.push(CMD_TIMED_SYNC, 0, 100);
    q2.push(CMD_PING,       50, 10);
    kat::check(!q2.expired(59).has_value(), "queue: nothing expired before its deadline");
    const auto e60 = q2.expired(60);
    kat::check(e60 && e60->command == CMD_PING,
               "queue: the short deadline fires first even though it was sent later");
    const auto e200 = q2.expired(200);
    kat::check(e200 && e200->command == CMD_TIMED_SYNC,
               "queue: with both expired the OLDEST is reported");

    InvokeQueue q3;
    for (std::size_t i = 0; i < InvokeQueue::MAX_OUTSTANDING; ++i)
        kat::check(q3.push(CMD_TIMED_SYNC, 0, 1000).has_value(),
                   "queue: fills to MAX_OUTSTANDING");
    kat::check(!q3.push(CMD_TIMED_SYNC, 0, 1000).has_value(),
               "queue: refuses beyond MAX_OUTSTANDING");
    q3.clear();
    kat::check(q3.empty(), "queue: clear drops every outstanding record");
}

void test_expect_response_pure() {
    kat::check(response_command_for(CMD_REQUEST_GET_OBJECTS) == CMD_RESPONSE_GET_OBJECTS,
               "expect: 2003 is answered by 2004");
    kat::check(response_command_for(CMD_REQUEST_CHAIN) == CMD_RESPONSE_CHAIN_ENTRY,
               "expect: 2006 is answered by 2007");
    kat::check(response_command_for(CMD_TIMED_SYNC) == 0,
               "expect: 1002 has no notify answer -- it is a real invoke");

    ExpectResponse e;
    kat::check(!e.accept(CMD_RESPONSE_CHAIN_ENTRY, 0),
               "expect: an unarmed latch refuses a 2007");
    kat::check(e.arm(CMD_REQUEST_CHAIN, 1000), "expect: arming on 2006 works");
    kat::check(!e.arm(CMD_REQUEST_GET_OBJECTS, 1000),
               "expect: only one notify-answered request in flight");
    kat::check(!e.arm(CMD_TIMED_SYNC, 1000), "expect: 1002 cannot arm the latch");
    kat::check(!e.kick_due(1000 + NON_RESPONSIVE_PEER_KICK_MS - 1),
               "expect: no kick before NON_RESPONSIVE_PEER_KICK_TIME");
    kat::check(e.kick_due(1000 + NON_RESPONSIVE_PEER_KICK_MS),
               "expect: kick at 20 s");
    kat::check(!e.idle_drop_due(1000 + NON_RESPONSIVE_PEER_KICK_MS),
               "expect: a kick is not yet a drop");
    kat::check(e.idle_drop_due(1000 + IDLE_PEER_KICK_MS),
               "expect: drop at IDLE_PEER_KICK_TIME");
    kat::check(!e.accept(CMD_RESPONSE_GET_OBJECTS, 1500),
               "expect: the WRONG answer does not disarm the latch");
    kat::check(e.accept(CMD_RESPONSE_CHAIN_ENTRY, 1500), "expect: the right answer disarms");
    kat::check(!e.armed() && e.last_rtt_ms() == 500, "expect: latch clear, rtt recorded");
}

void test_liveness_pure() {
    InboundLiveness l;
    l.start(1000);
    kat::check(!l.timed_out(1000 + PEER_TIMEOUT_MS - 1, PEER_TIMEOUT_MS),
               "liveness: not timed out before the deadline");
    kat::check(l.timed_out(1000 + PEER_TIMEOUT_MS, PEER_TIMEOUT_MS),
               "liveness: timed out at the deadline");
    l.on_inbound_bytes(1000 + PEER_TIMEOUT_MS - 1);
    kat::check(!l.timed_out(1000 + PEER_TIMEOUT_MS, PEER_TIMEOUT_MS),
               "liveness: inbound bytes push the deadline");

    // The silent-starvation tripwire is a different clock: it measures time
    // since the FIRST inbound byte (or the last relay frame), because a peer
    // holding us in state_synchronizing keeps answering TIMED_SYNC while never
    // pushing a block. Two block intervals of that is the alarm.
    InboundLiveness s;
    s.start(1000);
    s.on_inbound_bytes(1000);
    kat::check(!s.relay_silent(1000 + 239'999, 240'000),
               "liveness: no starvation alarm inside the window");
    kat::check(s.relay_silent(1000 + 240'000, 240'000),
               "liveness: a peer that answers but never pushes trips the alarm");
    s.on_relay_frame(1000 + 240'000);
    kat::check(!s.relay_silent(1000 + 240'001, 240'000),
               "liveness: one relay frame clears it");
    kat::check(s.relay_seen_at() == 1000 + 240'000,
               "liveness: relay_seen_at is what the per-peer gauge reports");
}

void test_pruning_seed_table() {
    kat::check(is_valid_pruning_seed(0), "pruning: 0 means not pruned");
    for (std::uint32_t stripe = 1; stripe <= 8; ++stripe) {
        const std::uint32_t seed = (PRUNING_LOG_STRIPES << PRUNING_SEED_LOG_STRIPES_SHIFT)
                                 | (stripe - 1);
        kat::checkf(is_valid_pruning_seed(seed), "pruning: seed %u (stripe %u) is valid",
                    seed, stripe);
        kat::checkf(pruning_stripe(seed) == stripe, "pruning: stripe round-trips (%u)", stripe);
    }
    kat::check(!is_valid_pruning_seed(1), "pruning: log_stripes 0 is not a seed");
    kat::check(!is_valid_pruning_seed(5), "pruning: 5 is not a seed");
    kat::check(!is_valid_pruning_seed((2u << PRUNING_SEED_LOG_STRIPES_SHIFT) | 0u),
               "pruning: log_stripes 2 is refused");
    kat::check(!is_valid_pruning_seed(0xffffffffu), "pruning: garbage is refused");
}

void test_handshake_machine_pure() {
    HandshakeConfig cfg;
    cfg.net         = XmrNet::Stagenet;
    cfg.our_peer_id = OUR_PEER_ID;

    HandshakeMachine m(cfg);
    kat::check(m.state() == HandshakeState::Idle, "machine: starts Idle");

    std::vector<std::uint8_t> body;
    kat::check(!m.build_request(our_sync_fixture(), body),
               "machine: cannot build a request before the dial lands");
    kat::check(m.state() == HandshakeState::Failed
               && m.failure() == HandshakeFailure::WrongState,
               "machine: that is a WrongState failure");

    HandshakeMachine m2(cfg);
    m2.on_dialed();
    kat::check(m2.state() == HandshakeState::Dialed, "machine: Dialed after the connect");
    kat::check(m2.build_request(our_sync_fixture(), body),
               "machine: the request builds");
    kat::check(m2.state() == HandshakeState::HandshakeSent, "machine: HandshakeSent");
    kat::check(m2.sent().node_data.my_port == 0, "machine: my_port 0 was advertised");

    // A response arriving twice: the second is a WrongState close, not a
    // silent re-admission.
    HandshakeResponse ok;
    ok.node_data.network_id    = NETWORK_ID_STAGENET;
    ok.node_data.peer_id       = PEER_PEER_ID;
    ok.node_data.support_flags = SUPPORT_FLAG_FLUFFY_BLOCKS;
    ok.payload_data            = peer_sync_fixture();
    std::vector<std::uint8_t> ok_body;
    MessageError err = MessageError::None;
    encode_handshake_response(ok, ok_body, err);
    kat::check(m2.on_response(ok_body.data(), ok_body.size(), RC_HANDLER_OK),
               "machine: a good response with monerod's own return code 1 lands");
    kat::check(m2.state() == HandshakeState::Handshaked, "machine: Handshaked");
    kat::check(m2.outcome().payload_data.support_flags == SUPPORT_FLAG_FLUFFY_BLOCKS,
               "machine: support_flags folded into the sync view");
    kat::check(!m2.on_response(ok_body.data(), ok_body.size(), RC_HANDLER_OK),
               "machine: a second response is refused");
    kat::check(m2.failure() == HandshakeFailure::WrongState,
               "machine: refused as WrongState");

    std::string why;
    native::PeerSyncData bad;
    bad.current_height = 0;
    kat::check(!HandshakeMachine::validate_sync_data(bad, why),
               "machine: current_height 0 is not a slow peer, it is a broken one");
    bad.current_height = 10;
    bad.pruning_seed   = 7;
    kat::check(!HandshakeMachine::validate_sync_data(bad, why),
               "machine: an impossible pruning seed is refused");
    bad.pruning_seed = 0;
    kat::check(HandshakeMachine::validate_sync_data(bad, why),
               "machine: an honest sync-data passes");
}

// =============================================================================
// 9. LIVE mode (opt-in).
// =============================================================================
int run_live(const std::string& hostport, XmrNet net) {
    const std::size_t colon = hostport.rfind(':');
    if (colon == std::string::npos) {
        std::fprintf(stderr, "--live wants <host>:<port>\n");
        return 2;
    }
    const std::string host = hostport.substr(0, colon);
    const std::string port = hostport.substr(colon + 1);

    asio::io_context io;
    tcp::resolver resolver(io);
    boost::system::error_code ec;
    const auto endpoints = resolver.resolve(host, port, ec);
    if (ec) { std::fprintf(stderr, "resolve: %s\n", ec.message().c_str()); return 2; }

    tcp::socket sock(io);
    asio::connect(sock, endpoints, ec);
    if (ec) { std::fprintf(stderr, "connect: %s\n", ec.message().c_str()); return 2; }

    // READ-ONLY. We advertise a sync-data whose top_id is all zeros and whose
    // height is 1: the peer will simply consider us far behind, which costs it
    // nothing, and we ask for no blocks, no chain and no transactions. One
    // handshake, one TIMED_SYNC, disconnect.
    LinkConfig cfg;
    cfg.handshake.net         = net;
    cfg.handshake.our_peer_id = 0xC2'00'11'22'33'44'55'66ull;
    cfg.handshake_timeout_ms   = 8'000;
    cfg.invoke_timeout_ms      = 15'000;
    cfg.timed_sync_interval_ms = 1'000;
    cfg.timed_sync_jitter_ms   = 0;
    cfg.peer_timeout_ms        = 30'000;
    cfg.tick_ms                = 100;

    LinkCallbacks cb;
    cb.our_sync_data = []() {
        native::PeerSyncData s;
        s.current_height = 1;
        s.top_version    = 1;
        return s;
    };
    bool  handshaked = false;
    int   syncs      = 0;
    std::string closed_why;
    std::shared_ptr<LevinLink> link;

    cb.on_handshaked = [&](const native::PeerRef& p) {
        handshaked = true;
        std::printf("LIVE: handshaked with %s peer_id=%016llx\n",
                    p.addr.c_str(), static_cast<unsigned long long>(p.peer_id));
    };
    cb.on_peer_sync_data = [&](const native::PeerRef&, const native::PeerSyncData& s) {
        ++syncs;
        std::printf("LIVE: sync #%d height=%llu top_version=%u pruning_seed=%u "
                    "cum_diff=%llu:%llu top_id=%s\n",
                    syncs, static_cast<unsigned long long>(s.current_height),
                    static_cast<unsigned>(s.top_version), s.pruning_seed,
                    static_cast<unsigned long long>(s.cumulative_difficulty.hi),
                    static_cast<unsigned long long>(s.cumulative_difficulty.lo),
                    kat::to_hex(std::vector<std::uint8_t>(s.top_id.begin(),
                                                          s.top_id.end())).c_str());
    };
    cb.on_peerlist = [&](const native::PeerRef&,
                         const std::vector<PeerlistEntry>& p) {
        std::printf("LIVE: peerlist %zu entries\n", p.size());
    };
    cb.on_closed = [&](const native::PeerRef&, LinkClose r, const std::string& w) {
        closed_why = std::string(to_string(r)) + ": " + w;
    };

    link = LevinLink::create(std::move(sock), cfg, cb);
    link->start();

    for (int spent = 0; spent < 20'000 && syncs < 2 && closed_why.empty(); spent += 100) {
        io.restart();
        io.run_for(std::chrono::milliseconds(100));
    }
    link->stop("live probe finished");
    io.restart();
    io.run_for(std::chrono::milliseconds(200));

    std::printf("LIVE: handshaked=%d sync_updates=%d timed_syncs_sent=%llu "
                "timed_syncs_answered=%llu closed=%s\n",
                handshaked ? 1 : 0, syncs,
                static_cast<unsigned long long>(link->timed_syncs_sent()),
                static_cast<unsigned long long>(link->timed_syncs_answered()),
                closed_why.empty() ? "(still open)" : closed_why.c_str());

    kat::check(handshaked, "LIVE: the handshake completed against a real daemon");
    kat::check(syncs >= 2, "LIVE: a TIMED_SYNC round trip completed");
    return kat::report("xmr_levin_link_kat --live");
}

} // namespace

int main(int argc, char** argv) {
    std::string live;
    XmrNet      net = XmrNet::Stagenet;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--live" && i + 1 < argc)      live = argv[++i];
        else if (a == "--net" && i + 1 < argc) {
            const std::string n = argv[++i];
            if (n == "mainnet")       net = XmrNet::Mainnet;
            else if (n == "testnet")  net = XmrNet::Testnet;
            else                      net = XmrNet::Stagenet;
        }
    }
    if (!live.empty()) return run_live(live, net);

    test_handshake_happy_path();
    test_timed_sync_response_shape();
    test_timed_sync_cadence();
    test_fifo_reply_matching();
    test_unsolicited_response();
    test_unsolicited_chain_entry();
    test_requested_chain_entry_is_accepted();
    test_handshake_refusals();
    test_handshake_timeout();
    test_peer_timeout_counts_inbound_only();
    test_we_answer_inbound_invokes();
    test_invoke_queue_pure();
    test_expect_response_pure();
    test_liveness_pure();
    test_pruning_seed_table();
    test_handshake_machine_pure();
    return kat::report("xmr_levin_link_kat");
}
