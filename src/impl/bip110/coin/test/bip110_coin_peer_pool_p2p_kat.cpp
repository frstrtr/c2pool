// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_coin_peer_pool_p2p_kat -- the pooled fork-peer connection
// (impl/bip110/coin/coin_peer_pool_p2p.hpp) over the BIP-110 coin P2P driver
// (impl/bip110/coin/p2p_node.hpp), the driver hooks the pool uses, and a source
// check that main_bip110.cpp wires the pool.
//
// Proves:
//   [A] every headers message reaches the count hook, an empty one included.
//   [B] the fetch filter is asked about every announced block and
//       transaction (inv: block, tx, wtx); a "no" sends no getdata; the block
//       announcement still reaches the sink.
//   [C] the driver's block hash is SHA256d(header) by default (the primary /
//       fan-out drivers unchanged) and the BIP-110 identity once set;
//       pool_peer_setup sets it and then runs the caller's setup.
//   [D] a BIP 130 headers announcement of a v2 block, over a real loopback
//       socket: the fetch filter is asked with the BLAKE2b identity and the
//       getdata on the wire carries it (MSG_WITNESS_BLOCK); a driver without
//       the identity asks by SHA256d(header).
//   [E] a pooled connection (make_pool_peer): its driver is shared_ptr-owned
//       (tracked lifetime), labelled "CoinP2P <peer>", got the identity and the
//       caller's setup before it dialed, and survives a pending dial dropped.
//   [G] request_txs over a pooled connection to a loopback listener: one
//       getdata (MSG_WITNESS_TX) for all the transactions.
//   [F] main_bip110.cpp wires the pool: built from the explicit peers and the
//       peer manager, each peer with the primary arm's crawl / self-advertise
//       seams and the BIP 35 opt-in; bodies checked by the BIP-110 rules and
//       connected in chain order by the BLAKE2b identity; the won-block relay,
//       the mempool's parent fetches, the fan-out (relay and crawl only, never
//       a pooled peer), the driver and the dashboard.

#include <impl/bip110/coin/coin_peer_pool_p2p.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/bip110/coin/node_interface.hpp>
#include <impl/bip110/coin/p2p_node.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/socket.hpp>
#include <core/uint256.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#ifndef BIP110_MAIN_SRC
#error "BIP110_MAIN_SRC must be defined by CMake to the path of src/c2pool/main_bip110.cpp"
#endif

using namespace bip110::coin;

namespace {

int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

/// What NodeP2P reads from its config: the network magic.
struct KatConfig {
    struct P2P {
        std::vector<std::byte> prefix{std::byte{0xf9}, std::byte{0xbe}, std::byte{0xb4},
                                      std::byte{0xd9}};
        NetService address;
    };
    struct Coin {
        P2P m_p2p;
        bool m_testnet{false};
    };
    Coin m_coin;
    Coin* coin() { return &m_coin; }
};

using KatNode = p2p::NodeP2P<KatConfig>;

BlockHeaderType v2_header(uint32_t nonce)
{
    BlockHeaderType h;
    h.m_version = 0x80000000u | 0x20000000u;
    h.m_previous_block.SetHex("0000000000000000000000000000000000000000000000000000000000000abc");
    h.m_merkle_root.SetHex("0000000000000000000000000000000000000000000000000000000000000def");
    h.m_timestamp = 1790000000;
    h.m_bits = 0x1d00ffff;
    h.m_nonce = nonce;
    h.m_extranonce.fill(0x11);
    h.m_txcount = 1;
    h.m_height = 970001;
    return h;
}

uint256 sha256d_of(const BlockHeaderType& h)
{
    auto packed = pack(h);
    return Hash(packed.get_span());
}

std::unique_ptr<RawMessage> headers_message(const std::vector<BlockHeaderType>& hdrs)
{
    std::vector<BlockType> blocks;
    for (const auto& h : hdrs) {
        BlockType b;
        static_cast<BlockHeaderType&>(b) = h;
        blocks.push_back(b);
    }
    PackStream ps;
    ps << blocks;
    auto sp = ps.get_span();
    std::vector<unsigned char> bytes(reinterpret_cast<const unsigned char*>(sp.data()),
                                     reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return std::make_unique<RawMessage>("headers", PackStream(bytes));
}

/// A connected loopback pair: `client` for the driver, `server` to read what
/// it wrote.
struct Loopback {
    boost::asio::io_context& ioc;
    boost::asio::ip::tcp::acceptor acceptor;
    std::unique_ptr<boost::asio::ip::tcp::socket> client;
    boost::asio::ip::tcp::socket server;

    explicit Loopback(boost::asio::io_context& io)
        : ioc(io),
          acceptor(io, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0)),
          client(std::make_unique<boost::asio::ip::tcp::socket>(io)),
          server(io)
    {
        client->connect(acceptor.local_endpoint());
        acceptor.accept(server);
    }

    /// Every message the driver wrote so far: (command, payload).
    std::vector<std::pair<std::string, std::vector<unsigned char>>> read_messages()
    {
        std::vector<unsigned char> buf;
        for (int i = 0; i < 20; ++i) {
            ioc.run_for(std::chrono::milliseconds(20));
            boost::system::error_code ec;
            const size_t avail = server.available(ec);
            if (ec || avail == 0)
                continue;
            std::vector<unsigned char> chunk(avail);
            const size_t n = server.read_some(boost::asio::buffer(chunk), ec);
            if (ec)
                break;
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + static_cast<long>(n));
        }
        std::vector<std::pair<std::string, std::vector<unsigned char>>> out;
        size_t pos = 0;
        while (pos + 24 <= buf.size()) {
            std::string cmd(reinterpret_cast<const char*>(&buf[pos + 4]), 12);
            cmd = cmd.substr(0, cmd.find('\0'));
            const uint32_t len = static_cast<uint32_t>(buf[pos + 16])
                | (static_cast<uint32_t>(buf[pos + 17]) << 8)
                | (static_cast<uint32_t>(buf[pos + 18]) << 16)
                | (static_cast<uint32_t>(buf[pos + 19]) << 24);
            if (pos + 24 + len > buf.size())
                break;
            out.emplace_back(cmd, std::vector<unsigned char>(buf.begin() + static_cast<long>(pos + 24),
                                                             buf.begin() + static_cast<long>(pos + 24 + len)));
            pos += 24 + len;
        }
        return out;
    }
};

std::string main_src_code()
{
    std::ifstream in(BIP110_MAIN_SRC);
    std::stringstream ss;
    ss << in.rdbuf();
    // Drop // comments so a mention in a comment does not count as wiring.
    std::string out;
    std::istringstream lines(ss.str());
    std::string line;
    while (std::getline(lines, line)) {
        const auto c = line.find("//");
        out += (c == std::string::npos ? line : line.substr(0, c)) + "\n";
    }
    return out;
}

bool has(const std::string& src, const char* what) { return src.find(what) != std::string::npos; }

/// `what` occurs after `from` within `window` bytes.
bool near_after(const std::string& src, size_t from, const char* what, size_t window)
{
    if (from == std::string::npos)
        return false;
    const auto at = src.find(what, from);
    return at != std::string::npos && at - from <= window;
}

} // namespace

int run_coin_peer_pool_p2p_kat()
{
    // ── [A] the headers-message count ─────────────────────────────────────────
    {
        boost::asio::io_context ioc;
        KatConfig cfg;
        bip110::interfaces::Node sink;
        auto node = std::make_shared<KatNode>(&ioc, &sink, &cfg, "kat");
        std::vector<size_t> counts;
        int new_headers = 0;
        sink.new_headers.subscribe([&](const std::vector<BlockHeaderType>&) { ++new_headers; });
        node->set_on_headers_message([&](size_t n) { counts.push_back(n); });
        node->handle(std::make_unique<RawMessage>("headers", PackStream(std::vector<unsigned char>{0x00})),
                     NetService("127.0.0.1", 8333));
        CHECK(counts == std::vector<size_t>{0} && new_headers == 0,
              "[A] an empty headers message reaches the count hook (and not new_headers)");
    }

    // ── [B] the fetch filter ──────────────────────────────────────────────────
    {
        boost::asio::io_context ioc;
        KatConfig cfg;
        bip110::interfaces::Node sink;
        auto node = std::make_shared<KatNode>(&ioc, &sink, &cfg, "kat");
        std::vector<std::pair<uint256, bool>> asked;
        node->set_fetch_filter([&](const uint256& h, bool is_block) {
            asked.emplace_back(h, is_block);
            return false;
        });
        std::vector<uint256> announced;
        sink.new_block.subscribe([&](const uint256& h) { announced.push_back(h); });
        const uint256 bh = block_hash(v2_header(1));
        const uint256 th = sha256d_of(v2_header(2));
        const uint256 wh = sha256d_of(v2_header(3));
        using p2p::inventory_type;
        node->handle(p2p::message_inv::make_raw({inventory_type(inventory_type::block, bh),
                                                 inventory_type(inventory_type::tx, th),
                                                 inventory_type(inventory_type::wtx, wh)}),
                     NetService("127.0.0.1", 8333));
        CHECK(asked.size() == 3 && asked[0] == std::make_pair(bh, true)
                  && asked[1] == std::make_pair(th, false) && asked[2] == std::make_pair(wh, false),
              "[B] the filter is asked about the block, the tx and the wtx");
        CHECK(announced == std::vector<uint256>{bh}, "[B] the block announcement still reaches the sink");
    }

    // ── [C] the driver's block hash ───────────────────────────────────────────
    {
        boost::asio::io_context ioc;
        KatConfig cfg;
        bip110::interfaces::Node sink;
        auto node = std::make_shared<KatNode>(&ioc, &sink, &cfg, "kat");
        const BlockHeaderType h = v2_header(4);
        CHECK(node->header_hash(h) == sha256d_of(h), "[C] unset: the driver hashes a header by SHA256d");
        bool more_ran = false;
        auto setup = pool_peer_setup<KatConfig>([&](KatNode& d) {
            more_ran = true;
            d.enable_getaddr_discovery();
        });
        setup(*node);
        CHECK(node->header_hash(h) == block_hash(h) && block_hash(h) != sha256d_of(h),
              "[C] pool_peer_setup: the driver hashes by the BLAKE2b identity");
        CHECK(more_ran && node->getaddr_discovery_enabled(), "[C] ... and runs the caller's setup");
    }

    // ── [D] a BIP 130 announcement over a loopback socket ─────────────────────
    {
        boost::asio::io_context ioc;
        KatConfig cfg;
        bip110::interfaces::Node sink;
        auto node = std::make_shared<KatNode>(&ioc, &sink, &cfg, "kat");
        pool_peer_setup<KatConfig>()(*node);
        std::vector<uint256> filtered;
        std::vector<size_t> counts;
        node->set_fetch_filter([&](const uint256& hh, bool is_block) {
            if (is_block) filtered.push_back(hh);
            return true;
        });
        node->set_on_headers_message([&](size_t n) { counts.push_back(n); });
        int new_headers = 0;
        sink.new_headers.subscribe([&](const std::vector<BlockHeaderType>&) { ++new_headers; });
        Loopback lo(ioc);
        node->connected(core::make_socket(std::move(lo.client), core::connection_type::outgoing,
                                          node.get()));
        const BlockHeaderType h = v2_header(5);
        const uint256 id = block_hash(h);
        node->handle(headers_message({h}), NetService("127.0.0.1", 8333));
        CHECK(counts == std::vector<size_t>{1} && new_headers == 1,
              "[D] the one-header announcement is counted and reaches new_headers");
        CHECK(filtered == std::vector<uint256>{id}, "[D] the fetch filter is asked with the BLAKE2b identity");
        bool found = false;
        for (const auto& [cmd, payload] : lo.read_messages()) {
            if (cmd != "getdata" || payload.size() != 1 + 36)
                continue;
            uint32_t type = static_cast<uint32_t>(payload[1]) | (static_cast<uint32_t>(payload[2]) << 8)
                | (static_cast<uint32_t>(payload[3]) << 16) | (static_cast<uint32_t>(payload[4]) << 24);
            uint256 got;
            std::memcpy(got.data(), payload.data() + 5, 32);
            if (payload[0] == 1 && type == 0x40000002u && got == id)
                found = true;
        }
        CHECK(found, "[D] the getdata on the wire asks MSG_WITNESS_BLOCK by the BLAKE2b identity");

        // A driver without the identity (the primary / fan-out default).
        auto plain = std::make_shared<KatNode>(&ioc, &sink, &cfg, "plain");
        std::vector<uint256> plain_filtered;
        plain->set_fetch_filter([&](const uint256& hh, bool) {
            plain_filtered.push_back(hh);
            return false;
        });
        Loopback lp(ioc);
        plain->connected(core::make_socket(std::move(lp.client), core::connection_type::outgoing,
                                           plain.get()));
        plain->handle(headers_message({h}), NetService("127.0.0.1", 8333));
        CHECK(plain_filtered == std::vector<uint256>{sha256d_of(h)},
              "[D] unset: the same announcement is asked by SHA256d(header)");
    }

    // ── [E] a pooled connection ───────────────────────────────────────────────
    {
        boost::asio::io_context ioc;
        KatConfig cfg;
        int headers = 0;
        bool more_ran = false;
        PoolPeerHooks hooks;
        hooks.headers_message = [&](size_t) { ++headers; };
        {
            auto peer = make_pool_peer<KatConfig>(&ioc, &cfg, NetService("127.0.0.1", 1), hooks,
                                                  [&](KatNode& d) {
                                                      more_ran = true;
                                                      d.enable_getaddr_discovery();
                                                  });
            auto* pooled = dynamic_cast<NodeP2PPoolPeer<KatConfig>*>(peer.get());
            CHECK(pooled != nullptr, "[E] make_pool_peer builds a NodeP2PPoolPeer");
            if (pooled) {
                CHECK(pooled->lifetime_managed(), "[E] the driver's lifetime is tracked");
                CHECK(pooled->label() == "CoinP2P 127.0.0.1:1", "[E] the driver is labelled by its peer");
                const BlockHeaderType h = v2_header(6);
                CHECK(pooled->driver().header_hash(h) == block_hash(h),
                      "[E] the driver hashes by the BLAKE2b identity");
                CHECK(more_ran && pooled->driver().getaddr_discovery_enabled(),
                      "[E] the caller's setup ran");
            }
            CHECK(!peer->handshaked(), "[E] not handshaked before the dial completes");
        }
        // The connection is gone while its dial is pending: the dial completes
        // (refused) against a driver kept alive by the dial-lifetime handle.
        ioc.run_for(std::chrono::milliseconds(500));
        CHECK(headers == 0, "[E] a dropped pending dial reports nothing");
    }

    // ── [G] request_txs: one getdata ─────────────────────────────────────────
    {
        static_assert(requires(KatNode& d, const std::vector<uint256>& v) { d.request_tx(v); },
                      "the bip110 driver takes a list: the pooled connection batches");
        boost::asio::io_context ioc;
        KatConfig cfg;
        boost::asio::ip::tcp::acceptor acceptor(
            ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
        boost::asio::ip::tcp::socket server(ioc);
        bool accepted = false;
        acceptor.async_accept(server, [&](const boost::system::error_code& ec) { accepted = !ec; });
        auto peer = make_pool_peer<KatConfig>(
            &ioc, &cfg, NetService("127.0.0.1", acceptor.local_endpoint().port()), PoolPeerHooks{});
        for (int i = 0; i < 50 && !accepted; ++i)
            ioc.run_for(std::chrono::milliseconds(20));
        ioc.run_for(std::chrono::milliseconds(50));
        uint256 a, b;
        a.SetHex("00000000000000000000000000000000000000000000000000000000000000c1");
        b.SetHex("00000000000000000000000000000000000000000000000000000000000000c2");
        peer->request_txs({a, b});
        std::vector<unsigned char> buf;
        for (int i = 0; i < 20; ++i) {
            ioc.run_for(std::chrono::milliseconds(20));
            boost::system::error_code ec;
            const size_t avail = server.available(ec);
            if (ec || avail == 0)
                continue;
            std::vector<unsigned char> chunk(avail);
            const size_t n = server.read_some(boost::asio::buffer(chunk), ec);
            if (ec)
                break;
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + static_cast<long>(n));
        }
        size_t getdata = 0;
        bool both = false;
        for (size_t pos = 0; pos + 24 <= buf.size();) {
            std::string cmd(reinterpret_cast<const char*>(&buf[pos + 4]), 12);
            cmd = cmd.substr(0, cmd.find('\0'));
            const uint32_t len = static_cast<uint32_t>(buf[pos + 16])
                | (static_cast<uint32_t>(buf[pos + 17]) << 8)
                | (static_cast<uint32_t>(buf[pos + 18]) << 16)
                | (static_cast<uint32_t>(buf[pos + 19]) << 24);
            if (pos + 24 + len > buf.size())
                break;
            const unsigned char* pl = &buf[pos + 24];
            if (cmd == "getdata") {
                ++getdata;
                if (len == 1 + 2 * 36 && pl[0] == 2) {
                    auto type_at = [&](size_t off) {
                        return static_cast<uint32_t>(pl[off]) | (static_cast<uint32_t>(pl[off + 1]) << 8)
                            | (static_cast<uint32_t>(pl[off + 2]) << 16)
                            | (static_cast<uint32_t>(pl[off + 3]) << 24);
                    };
                    uint256 x, y;
                    std::memcpy(x.data(), pl + 5, 32);
                    std::memcpy(y.data(), pl + 41, 32);
                    both = type_at(1) == 0x40000001u && type_at(37) == 0x40000001u && x == a && y == b;
                }
            }
            pos += 24 + len;
        }
        CHECK(accepted, "[G] the pooled connection dialed the loopback listener");
        CHECK(getdata == 1 && both, "[G] request_txs of two transactions is one getdata (MSG_WITNESS_TX)");
    }

    // ── [F] main_bip110.cpp wires the pool ────────────────────────────────────
    {
        const std::string src = main_src_code();
        CHECK(!src.empty(), "[F] main_bip110.cpp read");
        // The pool is declared before the won-block relay, which reaches it first.
        const auto decl = src.find("std::unique_ptr<bip110::coin::CoinPeerPool> coin_pool;");
        const auto relay = src.find("auto primary_relay = [&coin_node, &coin_pool]");
        const auto stratum = src.find("auto stratum_submit_fn =");
        CHECK(decl != std::string::npos && relay != std::string::npos && stratum != std::string::npos
                  && decl < relay && relay < stratum,
              "[F] coin_pool and primary_relay come before stratum_submit_fn");
        const auto pool_relay = src.find("coin_pool->broadcast_block(block_bytes)", relay);
        const auto node_relay = src.find("coin_node.submit_block_with_fallback(block_bytes)", relay);
        CHECK(pool_relay != std::string::npos && node_relay != std::string::npos
                  && pool_relay < node_relay && node_relay < stratum,
              "[F] primary_relay: every pooled peer, then coin_node's arm");
        CHECK(near_after(src, stratum, ": primary_relay(block_bytes);", 1200),
              "[F] the stratum won block takes the primary relay (flag off)");
        CHECK(has(src, "coin_broadcaster_full->set_primary_submit(primary_relay);"),
              "[F] the fan-out keystone's ARM B is the primary relay (flag on)");
        // The UTXO connect: the follower (UtxoFollower) over the view, the
        // active chain and the pool's body fetch; by the BLAKE2b identity.
        const auto follow = src.find("bip110::coin::UtxoFollowHost fh;");
        CHECK(follow != std::string::npos
                  && near_after(src, follow, "fh.view = [&utxo_cache]() { return utxo_cache.get_best(); };", 200)
                  && near_after(src, follow, "header_chain.get_header_by_height(h);", 600),
              "[F] the follower reads the view and the active chain");
        const auto conn = src.find("fh.connect = [&utxo_cache, &utxo_db, &mempool, bip110_txid, BIP110_KEEP_DEPTH]");
        CHECK(near_after(src, conn, "bip110::coin::block_hash(", 400)
                  && near_after(src, conn, "utxo_cache.connect_block(block, height, bip110_txid, block_hash);", 900),
              "[F] the UTXO connect keys the block by the BIP-110 identity");
        CHECK(!has(src, "Hash(packed_hdr.get_span())"), "[F] no SHA256d(header) lookup is left");
        const auto rb = src.find("fh.rollback = [");
        CHECK(near_after(src, rb, "utxo_consistent.store(false, std::memory_order_relaxed);", 400)
                  && near_after(src, rb, "bip110::coin::reorg_disconnect_or_discard(", 700)
                  && near_after(src, rb, "mempool.requarantine_all();", 2400),
              "[F] the rollback: inconsistent while it runs, a failure dropped, the mempool re-priced after");
        CHECK(!has(src, "bip110::coin::reorg_disconnect_to_fork("),
              "[F] no rollback that can leave the view half-undone");
        const auto fr = src.find("fh.on_fresh = [fresh_ws]() {");
        CHECK(near_after(src, fr, "ws->bump_work_generation();", 200),
              "[F] a connect that brings the view to the tip bumps the work generation");
        const auto ra = src.find("fh.reanchor = [&utxo_cache, &mempool, &utxo_consistent]() -> bool {");
        CHECK(near_after(src, ra, "if (!utxo_cache.reanchor())", 200),
              "[F] the re-anchor wipes the view (UTXOViewCache::reanchor)");
        CHECK(has(src, "coin_pool->fetch_bodies(ids);"), "[F] the follower's bodies come through the pool");
        const auto connect_fn = src.find("auto utxo_connect_block = [utxo_follower](const bip110::coin::BlockType& block) {");
        CHECK(near_after(src, connect_fn, "utxo_follower->on_body(block);", 200),
              "[F] a body goes to the follower (connect, else keep)");
        const auto tipc = src.find("header_chain.set_on_tip_changed(");
        CHECK(near_after(src, tipc, "utxo_follower->on_tip_changed()", 400),
              "[F] every tip change goes to the follower (kept bodies first, then a rollback)");
        const auto cu = src.find("pool_ptr->poll();");
        CHECK(near_after(src, cu, "utxo_follower->on_tick(*hdr_caught_up);", 100),
              "[F] the pool driver ticks the follower (catch-up once header sync is caught up)");
        const auto gate = src.find("work_source->set_mempool(&mempool, serve_mempool_txs,");
        CHECK(near_after(src, gate, "&& utxo_follower && utxo_follower->fresh();", 500),
              "[F] the serve gate requires the view at the tip");
        CHECK(has(src, "rule_alarm->should_log(id, rule, peers, std::chrono::steady_clock::now())")
                  && has(src, "bip110::coin::block_body_rule(b, rdts_cap_for(b));"),
              "[F] a BIP-110-only body failure from 2+ peers is an ERROR naming the rule");
        CHECK(has(src, "bip110::coin::is_peer_hostname(ns)") && has(src, "resolver->async_resolve(")
                  && has(src, "bip110::coin::add_resolved_peers(*explicit_list, ns, addrs);")
                  && has(src, "bip110::coin::peer_resolve_backoff_sec(failures);")
                  && has(src, "(*again)(ns, failures + 1);"),
              "[F] a host-name --peer is resolved for the pool, again after a failure");
        const auto mgr_decl = src.find("std::unique_ptr<bip110::coin::BtcCoinPeerManager> coin_peer_mgr;");
        const auto fan_decl = src.find("std::unique_ptr<bip110::coin::Bip110Broadcaster<MiniConfig>>     coin_broadcaster;");
        CHECK(mgr_decl != std::string::npos && fan_decl != std::string::npos && decl != std::string::npos
                  && mgr_decl < fan_decl && mgr_decl < decl,
              "[F] the peer manager outlives the fan-out and the pool (declared first)");
        const auto sub = src.find("utxo_connect_block, utxo_connect_by_pool]", connect_fn);
        CHECK(sub != std::string::npos && near_after(src, sub, "if (*utxo_connect_by_pool) return;", 2000)
                  && near_after(src, sub, "utxo_connect_block(block);", 2100),
              "[F] the full_block subscriber leaves the connect to the pool");
        const auto build = src.find("if (!explicit_peers.empty() || coin_peer_mgr) {");
        const auto by_pool = src.find("*utxo_connect_by_pool = true;");
        CHECK(build != std::string::npos && by_pool != std::string::npos && build < by_pool
                  && near_after(src, by_pool, "ph.on_body_in_order = utxo_connect_block;", 200),
              "[F] the pool, built from --peer or the peer manager, runs the UTXO connect");
        CHECK(has(src, "coin_pool = std::make_unique<bip110::coin::CoinPeerPool>(")
                  && has(src, "std::move(ph), bip110::coin::kCoinPoolTargetPeers, \"[EMB-BIP110]\");"),
              "[F] the pool: kCoinPoolTargetPeers fork peers, tagged [EMB-BIP110]");
        CHECK(!has(src, "coin_node.start_p2p("), "[F] the primary connection is no longer dialed");
        // Who is dialed and how each peer is set up.
        CHECK(has(src, "bip110::coin::pool_candidates(") && has(src, "*explicit_list, exclude,")
                  && has(src, "coin_broadcaster ? coin_broadcaster->slot_keys()")
                  && has(src, "return mgr->get_peers_to_connect(taken);"),
              "[F] candidates: explicit first, then the peer manager, never a fan-out slot");
        const auto dial = src.find("bip110::coin::make_pool_peer<MiniConfig>(");
        CHECK(dial != std::string::npos, "[F] each pooled peer is a bip110 make_pool_peer");
        for (const char* seam : {"peer.enable_getaddr_discovery();", "peer.set_addr_callback(",
                                 "mgr->add_discovered_peer(a, source.address());",
                                 "peer.set_local_addr_table(local_addr);",
                                 "peer.set_self_nonce_registry(self_nonce);",
                                 "peer.set_addr_relay_sink(", "peer.enable_mempool_request();"}) {
            const std::string what = std::string("[F] pooled peer setup: ") + seam;
            CHECK(near_after(src, dial, seam, 2000), what.c_str());
        }
        CHECK(has(src, "ph.connected    = [mgr](const std::string& k) { mgr->notify_connected(k); };")
                  && has(src, "ph.disconnected = [mgr](const std::string& k) { mgr->notify_disconnected(k); };")
                  && has(src, "ph.dial_failed  = [mgr](const std::string& k) { mgr->notify_dial_failed(k); };"),
              "[F] the pool reports to the peer manager");
        // Headers, caught-up, events.
        CHECK(has(src, "ph.caught_up = [hdr_caught_up]() { return *hdr_caught_up; };"),
              "[F] the pool reads the caught-up flag");
        const auto empty = src.find("ph.on_empty_headers = [hdr_caught_up]");
        CHECK(near_after(src, empty, "*hdr_caught_up = true;", 400),
              "[F] the empty-headers rule sets the caught-up flag");
        CHECK(has(src, "coin_node.new_headers.happened(h);") && has(src, "coin_node.full_block.happened(b);")
                  && has(src, "coin_node.new_tx.happened(tx);") && has(src, "coin_node.new_block.happened(h);"),
              "[F] pool events feed coin_node's subscribers");
        const auto tip = src.find("ph.tip = [&header_chain]()");
        CHECK(near_after(src, tip, "return tip ? tip->block_hash : uint256();", 200),
              "[F] the header tip is the chain's tip block");
        // Bodies: the BIP-110 check with the RDTS cap by the parent's median time.
        const auto cap = src.find("auto rdts_cap_for = [&header_chain](const bip110::coin::BlockType& b) {");
        const auto valid = src.find("ph.body_valid = [rdts_cap_for](const bip110::coin::BlockType& b) {");
        CHECK(near_after(src, cap, "bip110::coin::parent_median_time_past(", 200)
                  && near_after(src, cap, "return bip110::coin::rdts_weight_cap_applies(b, mtp);", 700)
                  && near_after(src, valid, "return bip110::coin::block_body_matches_header(b, rdts_cap_for(b));", 200),
              "[F] bodies pass the BIP-110 body check, RDTS cap by the parent's median time past");
        const auto best = src.find("ph.body_best_height = [&utxo_cache]");
        CHECK(near_after(src, best, "utxo_cache.get_best_block().IsNull()", 200),
              "[F] the chain order follows the UTXO view's best height");
        const auto late = src.find("ph.after_late_connect = [&mempool, &utxo_cache, weak_ws]");
        CHECK(near_after(src, late, "mempool.revalidate_inputs(&utxo_cache);", 300)
                  && near_after(src, late, "mempool.recompute_unknown_fees(&utxo_cache);", 400)
                  && near_after(src, late, "ws->bump_work_generation();", 700),
              "[F] a held body's late connect: UTXO-based mempool passes and the work bump");
        // The mempool's parent fetches go to the pool.
        CHECK(has(src, "coin_pool->request_txs(txids);"), "[F] T3 parent fetches go to a pooled peer");
        // The driver.
        CHECK(has(src, "pool_ptr->poll();")
                  && has(src, "std::chrono::seconds(static_cast<int>(bip110::coin::kCoinPoolPollSec))"),
              "[F] the driver polls the pool every kCoinPoolPollSec");
        // The fan-out: relay and crawl only, never a pooled peer.
        CHECK(has(src, "coin_pool ? &fanout_sink : static_cast<bip110::interfaces::Node*>(&coin_node)"),
              "[F] with the pool, fan-out events go to fanout_sink");
        CHECK(has(src, "slot.set_fetch_filter([](const uint256&, bool) { return false; });"),
              "[F] fan-out slots fetch no announced block or transaction");
        CHECK(has(src, "for (const auto& k : coin_pool->slot_keys())")
                  && has(src, "coin_peer_mgr->get_peers_to_connect(pooled)")
                  && has(src, "return pooled.count(t.to_string()) != 0;"),
              "[F] the fan-out never dials a pooled peer");
        // The dashboard.
        size_t rows = 0;
        for (size_t at = src.find("coin_pool->rows()"); at != std::string::npos;
             at = src.find("coin_pool->rows()", at + 1))
            ++rows;
        CHECK(rows == 2 && has(src, "coin_pool ? coin_pool->live_count() : 0"),
              "[F] the dashboard lists and counts the pooled peers");
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_coin_peer_pool_p2p_kat PASS" : "bip110_coin_peer_pool_p2p_kat FAIL");
    return g_fail;
}
