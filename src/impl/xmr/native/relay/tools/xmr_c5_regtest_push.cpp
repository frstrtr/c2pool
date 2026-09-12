// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/relay/tools/xmr_c5_regtest_push.cpp
//
// THE C5 LIVE PROOF. Pushes one block to a REAL monerod over levin, through the
// real LevinBlockRelay and the real C1a codec -- the same code the pool runs.
// The KAT proves the frame against our own decoder; this proves it against the
// only decoder whose opinion counts.
//
// It is BUILT by CI and RUN by nobody: it needs a daemon, and CI must not
// depend on one. ctest never sees it (it registers no test), so the #1539
// Not-Run rule does not apply -- but it IS in both build.yml --target lists, so
// it cannot bit-rot unnoticed.
//
// RUN IT AGAINST AN ISOLATED REGTEST DAEMON ONLY: own data dir, own ports,
// --regtest --fixed-difficulty 1. See tools/README.md for the two-node recipe
// and for the run this component was landed on.
//
//   argv: <host> <p2p_port> <peer_height> <top_id_hex> <cumdiff> <top_version>
//         <block_blob_hex> <nonce>
//   env : C5_SRC_IP -- source address to bind (monerod allows one connection
//         per remote IP, and in a two-node loopback rig 127.0.0.1 is taken)
//
// SCOPE FENCE: src/impl/xmr/ only; src/sharechain/v37 is not touched.
// ---------------------------------------------------------------------------
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "impl/xmr/native/relay/xmr_block_relay.hpp"

using namespace c2pool::xmr::native;
namespace R = c2pool::xmr::native::relay;

static std::vector<std::uint8_t> from_hex(const std::string& h) {
    std::vector<std::uint8_t> o;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<std::uint8_t>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}

static std::string to_hex(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 15]); }
    return s;
}

static int g_fd = -1;

static bool write_all(const std::vector<std::uint8_t>& v) {
    std::size_t off = 0;
    while (off < v.size()) {
        const ssize_t n = ::send(g_fd, v.data() + off, v.size() - off, 0);
        if (n <= 0) return false;
        off += static_cast<std::size_t>(n);
    }
    return true;
}

static bool read_exact(std::uint8_t* p, std::size_t n) {
    std::size_t off = 0;
    while (off < n) {
        const ssize_t r = ::recv(g_fd, p + off, n - off, 0);
        if (r <= 0) return false;
        off += static_cast<std::size_t>(r);
    }
    return true;
}

// The IBroadcastPort C5 writes through. One peer: the daemon on the other end.
class SocketPort final : public IBroadcastPort {
public:
    std::size_t broadcast_notify(std::uint32_t cmd, std::vector<std::uint8_t> frame) override {
        std::printf("[live] writing %zu bytes, command %u\n", frame.size(), cmd);
        return write_all(frame) ? 1u : 0u;
    }
    bool send_notify(const PeerRef&, std::uint32_t, std::vector<std::uint8_t> f) override {
        return write_all(f);
    }
    void set_fluffy_missing_handler(FluffyMissingHandler h) override { handler = std::move(h); }
    std::size_t peer_count() const override { return 1; }
    std::map<std::uint32_t, std::size_t> peers_by_asn() const override { return {}; }

    FluffyMissingHandler handler;
};

int main(int argc, char** argv) {
    if (argc < 9) {
        std::fprintf(stderr, "usage: %s host port height top_id cumdiff top_version blob nonce\n",
                     argv[0]);
        return 2;
    }
    const std::string host = argv[1];
    const int         port = std::atoi(argv[2]);
    const std::uint64_t peer_height = std::strtoull(argv[3], nullptr, 10);
    const std::string top_id_hex = argv[4];
    const std::uint64_t cumdiff  = std::strtoull(argv[5], nullptr, 10);
    const std::uint8_t  top_ver  = static_cast<std::uint8_t>(std::atoi(argv[6]));
    std::vector<std::uint8_t> blob = from_hex(argv[7]);
    const std::uint32_t nonce = static_cast<std::uint32_t>(std::strtoul(argv[8], nullptr, 10));

    // --- patch the winning nonce into the template blob ---------------------
    ParsedBlock pb;
    if (parse_block(blob, pb) != BlockParseStatus::Ok) {
        std::fprintf(stderr, "blob does not parse\n");
        return 1;
    }
    const std::size_t nonce_off = pb.header_size - 4;
    for (int i = 0; i < 4; ++i)
        blob[nonce_off + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff);

    BlockIdentity ident;
    if (parse_and_identify(blob, pb, ident) != BlockParseStatus::Ok) {
        std::fprintf(stderr, "blob does not re-parse\n");
        return 1;
    }
    CoinbaseFields cb;
    parse_coinbase_fields(blob.data(), pb, cb);
    std::printf("[live] block id %s at height %llu, %zu txs, nonce %u\n",
                to_hex(ident.id).c_str(), static_cast<unsigned long long>(cb.height),
                pb.tx_hashes.size(), nonce);

    // --- connect -------------------------------------------------------------
    g_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    // monerod allows ONE connection per remote IP by default, and the two
    // regtest daemons already hold each other's 127.0.0.1 slot. Source-bind to
    // another loopback address so we arrive as a distinct peer.
    if (const char* src = std::getenv("C5_SRC_IP")) {
        sockaddr_in local{};
        local.sin_family = AF_INET;
        ::inet_pton(AF_INET, src, &local.sin_addr);
        if (::bind(g_fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0)
            std::perror("bind source");
        else
            std::printf("[live] source address %s\n", src);
    }
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(static_cast<std::uint16_t>(port));
    ::inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
    if (::connect(g_fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        std::perror("connect");
        return 1;
    }
    int one = 1;
    ::setsockopt(g_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    timeval tv{};
    tv.tv_sec = 5;
    ::setsockopt(g_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::printf("[live] connected to %s:%d\n", host.c_str(), port);

    // --- HANDSHAKE (1001) ----------------------------------------------------
    levin::HandshakeRequest hs;
    hs.node_data.network_id    = levin::network_id_of(levin::XmrNet::Mainnet);  // fakechain
    hs.node_data.peer_id       = 0xC2005EEDC5000001ull;
    hs.node_data.my_port       = 0;
    hs.node_data.support_flags = levin::SUPPORT_FLAG_FLUFFY_BLOCKS;
    hs.payload_data.current_height = peer_height;
    hs.payload_data.cumulative_difficulty.lo = cumdiff;
    hs.payload_data.top_version = top_ver;
    {
        const std::vector<std::uint8_t> t = from_hex(top_id_hex);
        if (t.size() == 32) std::memcpy(hs.payload_data.top_id.data(), t.data(), 32);
    }

    std::vector<std::uint8_t> body;
    levin::MessageError merr = levin::MessageError::None;
    if (!levin::encode_handshake_request(hs, body, merr)) {
        std::fprintf(stderr, "handshake encode failed\n");
        return 1;
    }
    if (!write_all(levin::make_invoke(levin::CMD_HANDSHAKE, body))) return 1;
    std::printf("[live] handshake sent (height %llu, top %s, hf %u)\n",
                static_cast<unsigned long long>(peer_height), top_id_hex.c_str(), top_ver);

    // --- pump frames until the handshake response arrives --------------------
    bool handshaked = false;
    for (int i = 0; i < 12 && !handshaked; ++i) {
        std::uint8_t hdr[levin::HEADER_SIZE];
        if (!read_exact(hdr, sizeof(hdr))) break;
        levin::BucketHead h;
        levin::HeaderError herr = levin::HeaderError::None;
        levin::HeaderPolicy pol;
        pol.handshaked = true;
        if (!levin::read_header(hdr, sizeof(hdr), pol, h, herr)) {
            std::fprintf(stderr, "bad header: %s\n", levin::to_string(herr));
            break;
        }
        std::vector<std::uint8_t> in(static_cast<std::size_t>(h.cb));
        if (h.cb && !read_exact(in.data(), in.size())) break;
        std::printf("[live] <- command %u (%s), %llu bytes, class %s\n", h.command,
                    levin::command_name(h.command), static_cast<unsigned long long>(h.cb),
                    levin::frame_class_name(levin::classify(h)));

        if (levin::classify(h) == levin::FrameClass::Response &&
            h.command == levin::CMD_HANDSHAKE) {
            handshaked = true;
        } else if (h.command == levin::CMD_REQUEST_SUPPORT_FLAGS &&
                   levin::classify(h) == levin::FrameClass::Invoke) {
            levin::SupportFlagsResponse sf;
            sf.support_flags = levin::SUPPORT_FLAG_FLUFFY_BLOCKS;
            std::vector<std::uint8_t> b2;
            levin::encode_support_flags_response(sf, b2, merr);
            write_all(levin::make_response(levin::CMD_REQUEST_SUPPORT_FLAGS, b2));
        } else if (h.command == levin::CMD_TIMED_SYNC &&
                   levin::classify(h) == levin::FrameClass::Invoke) {
            levin::TimedSyncResponse ts;
            ts.payload_data = hs.payload_data;
            std::vector<std::uint8_t> b2;
            levin::encode_timed_sync_response(ts, b2, merr);
            write_all(levin::make_response(levin::CMD_TIMED_SYNC, b2));
        }
    }
    if (!handshaked) {
        std::fprintf(stderr, "[live] no handshake response\n");
        return 1;
    }
    std::printf("[live] HANDSHAKED\n");

    // --- the real C5 relay ---------------------------------------------------
    SocketPort port_out;
    R::RelayConfig cfg;   // defaults: Parallel, self-contained, serve 2009
    R::LevinBlockRelay relay(port_out, R::DaemonSubmitSink{}, nullptr, nullptr, cfg,
                             [](bool err, const std::string& line) {
                                 std::printf("[relay:%s] %s\n", err ? "ERR" : "info", line.c_str());
                             });

    BlockRelayRequest req;
    req.block_id   = ident.id;
    req.height     = cb.height;
    req.block_blob = blob;
    req.tx_hashes  = pb.tx_hashes;
    req.nonce      = nonce;

    const BlockRelayVerdict v = relay.relay_with_gate(req, R::pow_attestation(ident.id));
    std::printf("[live] verdict: peers=%zu reached=%d why='%s'\n", v.p2p_peers_sent,
                v.reached_network() ? 1 : 0, v.why.c_str());

    // Stay on the connection for a moment: the daemon may answer with a 2009,
    // and dropping the socket early would look like a peer that vanished.
    for (int i = 0; i < 4; ++i) {
        std::uint8_t hdr[levin::HEADER_SIZE];
        if (!read_exact(hdr, sizeof(hdr))) break;
        levin::BucketHead h;
        levin::HeaderError herr = levin::HeaderError::None;
        levin::HeaderPolicy pol;
        pol.handshaked = true;
        if (!levin::read_header(hdr, sizeof(hdr), pol, h, herr)) break;
        std::vector<std::uint8_t> in(static_cast<std::size_t>(h.cb));
        if (h.cb && !read_exact(in.data(), in.size())) break;
        std::printf("[live] <- command %u (%s) after the push\n", h.command,
                    levin::command_name(h.command));
        if (h.command == levin::CMD_REQUEST_FLUFFY_MISSING_TX && port_out.handler) {
            levin::RequestFluffyMissingTx rq;
            if (levin::decode_request_fluffy_missing_tx(in.data(), in.size(), rq, merr)) {
                std::vector<std::uint8_t> reply;
                if (port_out.handler(PeerRef{1, "daemon", 0}, rq.block_hash,
                                     rq.current_blockchain_height, rq.missing_tx_indices, reply)) {
                    write_all(reply);
                    std::printf("[live] answered 2009 with %zu bytes\n", reply.size());
                }
            }
        }
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
    ::close(g_fd);
    return v.reached_network() ? 0 : 1;
}
