// SPDX-License-Identifier: AGPL-3.0-or-later
// c2pool-bip110 — Bitcoin Knots BLAKE2b hard fork (BIP-110) node entry.
//
// M1 = EMBEDDED daemonless SPV header-follower. With --run --coin-p2p-discover
// this binary dials NODE_BLAKE2B (bit 28) fork peers, downloads v2 (164-byte)
// headers, applies the BLAKE2b PoW at/after Blake2bHeight=961640 (SHA256d below,
// shared prefix), and FOLLOWS the BLAKE2b fork chain — rejecting the canonical
// SHA256d chain past the fork despite its higher work — with NO Knots/bitcoind
// daemon, exactly as btc.voidbind runs embedded today. --selftest keeps the
// live BLAKE2b block-hash KAT arm. Mining (164-byte template assembly / the
// Knots-GBT backend) is M2+; this milestone proves fork-following header sync.
//
// PER-COIN ISOLATION: src/impl/bip110 lane + the lane-local BLAKE2b primitive.
// No SHA256d/scrypt/X11 lane is touched.

#include <impl/bip110/params.hpp>
#include <impl/bip110/pow.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/bip110/coin/node.hpp>
#include <impl/bip110/coin/node_interface.hpp>
#include <impl/bip110/coin/coin_peer_manager.hpp>
#include <impl/bip110/coin/chain_seeds.hpp>
#include <impl/bip110/stratum/work_source.hpp>

#include <core/uint256.hpp>
#include <core/target_utils.hpp>
#include <core/netaddress.hpp>
#include <core/stratum_server.hpp>
#include <core/log.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <vector>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace io = boost::asio;

namespace {

// Standalone header-sync driver cadence (file-scope so the nested async lambdas
// use them as constant expressions without an explicit capture).
constexpr int kTickSec = 10;
constexpr int kNoProgressFailoverSec = 40;

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

void print_banner(const char* argv0)
{
    std::printf(
        "c2pool-bip110 %s — Bitcoin Knots BLAKE2b hard fork (BIP-110)\n\n"
        "Usage: %s [--version] [--help] [--selftest]\n"
        "       %s --run [--coin-p2p-discover] [--peer IP:PORT ...]\n"
        "                 [--fork-checkpoint] [--http [HOST:]PORT]\n\n"
        "  --run                embedded daemonless SPV header-follower\n"
        "  --coin-p2p-discover  discover NODE_BLAKE2B fork peers (DNS + fixed seeds)\n"
        "  --peer IP:PORT       add an explicit fork peer (repeatable)\n"
        "  --fork-checkpoint    seed the Knots 961640 checkpoint for a fast proof\n"
        "  --http [HOST:]PORT   serve a JSON sync-status endpoint\n\n"
        "PoW: BLAKE2b commitment pipeline (bip110::pow); block hash == PoW hash.\n"
        "Fork: Blake2bHeight=%u; RDTS weight cap=%u WU; network==Bitcoin mainnet\n"
        "      (magic f9beb4d9, default port %u).\n",
        C2POOL_VERSION, argv0, argv0,
        bip110::BLAKE2B_HEIGHT, bip110::RDTS_MAX_BLOCK_WEIGHT, bip110::COIN_P2P_PORT);
}

// Drive the LIVE CoinParams-bound BLAKE2b block-hash path against real block
// 961640 (the first BLAKE2b block; also a Knots checkpoint).
int run_selftest()
{
    core::CoinParams params = bip110::make_coin_params(/*testnet=*/false);

    const std::string header_hex =
        "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000";
    const std::string canonical =
        "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";
    const uint32_t nbits = 0x1a008d4f;

    std::vector<unsigned char> header = from_hex(header_hex);
    uint256 got = params.block_hash_func(std::span<const unsigned char>(header.data(), header.size()));
    uint256 pow = params.pow_func(std::span<const unsigned char>(header.data(), header.size()));
    uint256 target = chain::bits_to_target(nbits);

    const bool hash_ok = (got.GetHex() == canonical);
    const bool pow_bound = (pow.GetHex() == canonical);  // pow == block hash for BIP-110
    const bool pow_ok = (pow <= target);

    std::printf("[selftest] coin=%s  pow == block_hash (BLAKE2b) bound\n", params.symbol.c_str());
    std::printf("[selftest]   block 961640 hash   = %s\n", got.GetHex().c_str());
    std::printf("[selftest]   canonical (chain)   = %s  match=%s\n",
                canonical.c_str(), hash_ok ? "yes" : "NO");
    std::printf("[selftest]   pow == block_hash   = %s\n", pow_bound ? "yes" : "NO");
    std::printf("[selftest]   PoW <= target(0x%08x) = %s\n", nbits, pow_ok ? "yes" : "NO");
    std::printf("[selftest]   RDTS weight cap     = %u WU\n", params.block_max_weight);

    if (hash_ok && pow_bound && pow_ok) {
        std::printf("[selftest] PASS — CoinParams BLAKE2b reproduces the real chain block hash.\n");
        return 0;
    }
    std::printf("[selftest] FAIL — BLAKE2b block hash did not match the chain.\n");
    return 1;
}

// ── Minimal duck-typed config for the coin NodeP2P template ──────────────────
// btc::coin::Node<ConfigType> / NodeP2P<ConfigType> only read
// config->coin()->m_p2p.prefix (the network magic used to frame messages). The
// pool-side btc::Config carries a lot more (sharechain identity etc.) that a
// header-only follower never uses, so we hand a lean composite here rather than
// clone the pool-side config surface into the lane.
struct MiniCoinCfg {
    struct P2P { std::vector<std::byte> prefix; NetService address; } m_p2p;
    bool m_testnet{false};
    bool m_regtest{false};
    std::string m_symbol{"BIP110"};
};
struct MiniConfig {
    MiniCoinCfg m_coin;
    bool m_testnet{false};
    MiniCoinCfg* coin() { return &m_coin; }
};

// ── Minimal JSON status HTTP endpoint (live-proof surface) ───────────────────
// Serves one JSON body describing the header tip on any request, then closes.
class StatusHttp : public std::enable_shared_from_this<StatusHttp> {
public:
    StatusHttp(io::io_context& ioc, const std::string& host, uint16_t port,
               bip110::coin::HeaderChain& chain, uint32_t fork_height)
        : m_acceptor(ioc), m_chain(chain), m_fork_height(fork_height)
    {
        io::ip::tcp::endpoint ep(io::ip::make_address(host), port);
        m_acceptor.open(ep.protocol());
        m_acceptor.set_option(io::socket_base::reuse_address(true));
        m_acceptor.bind(ep);
        m_acceptor.listen();
    }
    void start() { do_accept(); }
private:
    void do_accept() {
        auto self = shared_from_this();
        m_acceptor.async_accept([self](const boost::system::error_code& ec, io::ip::tcp::socket sock) {
            if (!ec) self->serve(std::move(sock));
            self->do_accept();
        });
    }
    void serve(io::ip::tcp::socket sock) {
        auto s = std::make_shared<io::ip::tcp::socket>(std::move(sock));
        auto buf = std::make_shared<std::array<char, 1024>>();
        s->async_read_some(io::buffer(*buf), [this, s, buf](const boost::system::error_code&, std::size_t) {
            auto tip = m_chain.tip();
            const uint32_t h = m_chain.height();
            const std::string hash = tip ? tip->block_hash.GetHex() : std::string("null");
            const uint32_t peer_tip = m_chain.peer_tip_height();
            char body[512];
            std::snprintf(body, sizeof(body),
                "{\"coin\":\"BIP110\",\"header_height\":%u,\"header_tip\":\"%s\","
                "\"peer_tip\":%u,\"blake2b_height\":%u,\"on_blake2b_chain\":%s}\n",
                h, hash.c_str(), peer_tip, m_fork_height,
                (h >= m_fork_height ? "true" : "false"));
            auto resp = std::make_shared<std::string>();
            *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    "Connection: close\r\nContent-Length: " + std::to_string(std::strlen(body)) +
                    "\r\n\r\n" + std::string(body);
            io::async_write(*s, io::buffer(*resp),
                [s, resp](const boost::system::error_code&, std::size_t) {
                    boost::system::error_code ig; s->shutdown(io::ip::tcp::socket::shutdown_both, ig);
                });
        });
    }
    io::ip::tcp::acceptor m_acceptor;
    bip110::coin::HeaderChain& m_chain;
    uint32_t m_fork_height;
};

int run_embedded(bool coin_p2p_discover,
                 const std::vector<NetService>& explicit_peers,
                 bool fork_checkpoint,
                 const std::string& http_host, uint16_t http_port,
                 uint16_t stratum_port)
{
    core::log::Logger::init();

    LOG_INFO << "[EMB-BIP110] c2pool-bip110 " << C2POOL_VERSION
             << " starting — EMBEDDED daemonless BLAKE2b fork follower (mainnet)";

    auto chain_params = bip110::coin::BTCChainParams::mainnet();
    if (fork_checkpoint) {
        // Seed the Knots consensus checkpoint at the first BLAKE2b block so the
        // node follows the fork from 961640 without a full genesis IBD. All
        // pre-fork (SHA256d) history is implicitly trusted; the fork gate then
        // requires every subsequent header to be v2 BLAKE2b.
        bip110::coin::BTCChainParams::Checkpoint cp;
        cp.height = bip110::BLAKE2B_HEIGHT;  // 961640
        cp.hash.SetHex("0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb");
        chain_params.fast_start_checkpoint = cp;
        LOG_INFO << "[EMB-BIP110] fork checkpoint seeded: height=" << cp.height
                 << " hash=" << cp.hash.GetHex();
    }

    const std::string db_path = std::string(getenv("HOME") ? getenv("HOME") : ".")
                              + "/.c2pool/bip110/embedded_headers";
    bip110::coin::HeaderChain header_chain(chain_params, db_path);
    if (!header_chain.init())
        LOG_WARNING << "[EMB-BIP110] HeaderChain init failed — running in-memory only";
    LOG_INFO << "[EMB-BIP110] HeaderChain ready: height=" << header_chain.height()
             << " genesis=" << chain_params.genesis_hash.GetHex().substr(0, 16)
             << " blake2b_height=" << chain_params.blake2b_height;

    io::io_context ioc;

    MiniConfig config;
    config.coin()->m_p2p.prefix = { std::byte{0xf9}, std::byte{0xbe}, std::byte{0xb4}, std::byte{0xd9} };

    bip110::coin::Node<MiniConfig> coin_node(&ioc, &config);

    // ── M2 MINING: stratum server + BLAKE2b Sv1 work source (miner-facing) ──
    // submit_block_fn relays a won 164-byte v2 block to the FORK peers over the
    // coin P2P (submit_block_with_fallback: P2P relay + optional submitblock RPC
    // backup). The work source serves coinbase-only jobs, validates shares with
    // an independent BLAKE2b recompute, and dispatches block-target hits here.
    auto stratum_submit_fn =
        [&coin_node](const std::vector<unsigned char>& block_bytes, uint32_t height) -> bool {
            LOG_INFO << "[EMB-BIP110] submitting won block height=" << height
                     << " bytes=" << block_bytes.size();
            return coin_node.submit_block_with_fallback(block_bytes);
        };
    auto work_source = std::make_shared<bip110::stratum::Bip110WorkSource>(
        header_chain, /*is_testnet=*/false, std::move(stratum_submit_fn));

    std::unique_ptr<core::StratumServer> stratum_server;
    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, "0.0.0.0", stratum_port, work_source);
        if (stratum_server->start())
            LOG_INFO << "[EMB-BIP110] stratum server LIVE on :" << stratum_port
                     << " (BLAKE2b Sv1 work source, coinbase-only M2)";
        else
            LOG_WARNING << "[EMB-BIP110] stratum server failed to bind :" << stratum_port;
    }

    auto header_block_hash = [](const bip110::coin::BlockHeaderType& hdr) {
        return bip110::coin::block_hash(hdr);
    };

    auto hdr_caught_up = std::make_shared<bool>(false);

    // Ingest header batches, drive the peer's start_height into the fast-sync
    // gate, and chain the next getheaders forward until caught up. Bump the work
    // generation on every fork-tip move so stratum sessions re-push fresh work.
    coin_node.new_headers.subscribe(
        [&header_chain, &coin_node, header_block_hash, hdr_caught_up, work_source]
        (const std::vector<bip110::coin::BlockHeaderType>& headers)
        {
            if (headers.empty()) return;
            int accepted = header_chain.add_headers(headers);
            if (accepted > 0) work_source->bump_work_generation();
            uint256 last_hash = header_block_hash(headers.back());
            const auto& lh = headers.back();
            LOG_INFO << "[EMB-BIP110] new_headers: received=" << headers.size()
                     << " accepted=" << accepted
                     << " height=" << header_chain.height()
                     << " last=" << last_hash.GetHex().substr(0, 16)
                     << " v2=" << (lh.is_v2() ? 1 : 0)
                     << " committed_height=" << lh.m_height;
            if (headers.size() >= 2000) {
                *hdr_caught_up = false;
                coin_node.send_getheaders(70016, {last_hash}, uint256::ZERO);
            } else {
                *hdr_caught_up = true;
            }
        });

    // Peer discovery + explicit peers -> a shared candidate dialer with failover.
    std::unique_ptr<bip110::coin::BtcCoinPeerManager> coin_peer_mgr;
    const std::string pm_dir = std::string(getenv("HOME") ? getenv("HOME") : ".")
                             + "/.c2pool/bip110/peers";
    if (coin_p2p_discover) {
        bip110::coin::BtcPeerManagerConfig pm_cfg;
        pm_cfg.valid_ports = { 8333, 9333 };  // two of the fixed fork peers listen on 9333
        coin_peer_mgr = std::make_unique<bip110::coin::BtcCoinPeerManager>(
            ioc, "BIP110", pm_dir, pm_cfg);
        coin_peer_mgr->set_dns_seeds(bip110::coin::btc_dns_seeds(false));
        coin_peer_mgr->set_fixed_seeds(bip110::coin::btc_fixed_seeds(false));
        coin_peer_mgr->start();
        const auto st = coin_peer_mgr->peer_stats();
        LOG_INFO << "[EMB-BIP110] NODE_BLAKE2B peer discovery ARMED: peers=" << st.total
                 << " groups=" << st.unique_groups;
    }

    // Round-robin dialer over explicit peers + the discovered set. Redials the
    // next candidate whenever the handshake is not complete (a non-fork peer is
    // dropped at the NODE_BLAKE2B version gate and we walk on).
    auto explicit_list = std::make_shared<std::vector<NetService>>(explicit_peers);
    auto explicit_idx  = std::make_shared<size_t>(0);
    auto tried = std::make_shared<std::set<std::string>>();
    auto dial_next = [&coin_node, &coin_peer_mgr, explicit_list, explicit_idx, tried]() -> bool {
        // Prefer explicit peers first (round-robin), then discovered candidates.
        if (!explicit_list->empty()) {
            NetService ep = (*explicit_list)[(*explicit_idx)++ % explicit_list->size()];
            LOG_INFO << "[EMB-BIP110] dialing explicit fork peer " << ep.to_string();
            coin_node.start_p2p(ep);
            return true;
        }
        if (coin_peer_mgr) {
            auto cands = coin_peer_mgr->get_peers_to_connect(*tried);
            if (cands.empty()) { tried->clear(); cands = coin_peer_mgr->get_peers_to_connect(*tried); }
            if (cands.empty()) {
                LOG_WARNING << "[EMB-BIP110] no fork peers to dial yet";
                return false;
            }
            const auto& ep = cands.front();
            tried->insert(ep.to_string());
            LOG_INFO << "[EMB-BIP110] dialing discovered fork peer " << ep.to_string();
            coin_node.start_p2p(ep.to_net_service());
            return true;
        }
        return false;
    };
    dial_next();

    // Self-rescheduling driver: (re)issue getheaders on a fresh handshake or a
    // stall, and fail over to the next candidate after no header progress.
    auto last_height   = std::make_shared<uint32_t>(header_chain.height());
    auto last_progress = std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());
    auto was_handshaked = std::make_shared<bool>(false);
    auto timer = std::make_shared<io::steady_timer>(ioc);
    auto driver = std::make_shared<std::function<void()>>();
    std::weak_ptr<std::function<void()>> weak_driver = driver;
    auto keepalive = driver;  // outlive this scope
    *driver = [timer, weak_driver, &coin_node, &header_chain, &chain_params,
               dial_next, hdr_caught_up, last_height, last_progress, was_handshaked]() {
        timer->expires_after(std::chrono::seconds(kTickSec));
        timer->async_wait([timer, weak_driver, &coin_node, &header_chain, &chain_params,
                           dial_next, hdr_caught_up, last_height, last_progress, was_handshaked]
                          (const boost::system::error_code& ec) {
            if (ec) return;
            const uint32_t h = header_chain.height();
            const bool handshaked = coin_node.is_handshake_complete();
            const bool caught_up = *hdr_caught_up;
            const auto now = std::chrono::steady_clock::now();
            const bool advanced = (h > *last_height);
            if (advanced) { *last_height = h; *last_progress = now; }

            auto send_locator = [&]() {
                uint256 loc;
                if (auto tip = header_chain.tip(); tip) loc = tip->block_hash;
                else loc = chain_params.genesis_hash;
                LOG_INFO << "[EMB-BIP110] getheaders locator=" << loc.GetHex().substr(0, 16)
                         << " height=" << h << (h >= chain_params.blake2b_height ? " [on BLAKE2b fork]" : "");
                coin_node.send_getheaders(70016, {loc}, uint256::ZERO);
            };
            if (handshaked && !caught_up) {
                if (!*was_handshaked || !advanced) send_locator();
            }
            *was_handshaked = handshaked;

            if (!caught_up && now - *last_progress >= std::chrono::seconds(kNoProgressFailoverSec)) {
                LOG_INFO << "[EMB-BIP110] no header progress for " << kNoProgressFailoverSec
                         << "s (height=" << h << ", handshaked=" << handshaked << ") — failover";
                dial_next();
                *last_progress = now;
                *was_handshaked = false;
            }
            if (auto self = weak_driver.lock()) (*self)();
        });
    };
    (*driver)();

    // Optional JSON status endpoint.
    std::shared_ptr<StatusHttp> http;
    if (http_port != 0) {
        try {
            http = std::make_shared<StatusHttp>(ioc, http_host, http_port, header_chain, chain_params.blake2b_height);
            http->start();
            LOG_INFO << "[EMB-BIP110] status endpoint on " << http_host << ":" << http_port;
        } catch (const std::exception& e) {
            LOG_WARNING << "[EMB-BIP110] status endpoint bind failed: " << e.what();
        }
    }

    // Periodic tip log — the live-proof capture line.
    auto tip_timer = std::make_shared<io::steady_timer>(ioc);
    auto tip_log = std::make_shared<std::function<void()>>();
    auto tip_ka = tip_timer;
    std::weak_ptr<std::function<void()>> weak_tip = tip_log;
    *tip_log = [tip_timer, weak_tip, &header_chain, &chain_params]() {
        tip_timer->expires_after(std::chrono::seconds(15));
        tip_timer->async_wait([tip_timer, weak_tip, &header_chain, &chain_params]
                              (const boost::system::error_code& ec) {
            if (ec) return;
            auto tip = header_chain.tip();
            const uint32_t h = header_chain.height();
            LOG_INFO << "[EMB-BIP110][TIP] height=" << h
                     << " hash=" << (tip ? tip->block_hash.GetHex() : std::string("null"))
                     << " peer_tip=" << header_chain.peer_tip_height()
                     << " on_blake2b_chain=" << (h >= chain_params.blake2b_height ? "YES" : "no");
            if (auto self = weak_tip.lock()) (*self)();
        });
    };
    (*tip_log)();

    io::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc](const boost::system::error_code&, int) {
        LOG_INFO << "[EMB-BIP110] shutdown signal — stopping";
        ioc.stop();
    });

    LOG_INFO << "[EMB-BIP110] entering io loop";
    ioc.run();
    (void)keepalive; (void)tip_ka;
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool selftest = true;
    bool run = false;
    bool coin_p2p_discover = false;
    bool fork_checkpoint = false;
    std::string http_host = "0.0.0.0";
    uint16_t http_port = 0;
    uint16_t stratum_port = 9336;  // BIP-110 Stratum port (params.hpp worker_port)
    std::vector<NetService> explicit_peers;

    auto parse_hostport = [](const std::string& v, std::string& h, uint16_t& p) {
        auto c = v.rfind(':');
        if (c == std::string::npos) { p = static_cast<uint16_t>(std::stoi(v)); }
        else { h = v.substr(0, c); p = static_cast<uint16_t>(std::stoi(v.substr(c + 1))); }
    };

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--version") { std::printf("c2pool-bip110 %s\n", C2POOL_VERSION); return 0; }
        if (a == "--help" || a == "-h") { print_banner(argv[0]); return 0; }
        else if (a == "--selftest") { selftest = true; run = false; }
        else if (a == "--run") { run = true; selftest = false; }
        else if (a == "--coin-p2p-discover") { coin_p2p_discover = true; }
        else if (a == "--fork-checkpoint") { fork_checkpoint = true; }
        else if (a == "--peer" && i + 1 < argc) {
            std::string host = "127.0.0.1"; uint16_t port = 8333;
            parse_hostport(argv[++i], host, port);
            explicit_peers.emplace_back(host, port);
        }
        else if (a == "--http" && i + 1 < argc) {
            parse_hostport(argv[++i], http_host, http_port);
        }
        else if (a == "--stratum" && i + 1 < argc) {
            stratum_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
        else if (a == "--no-stratum") { stratum_port = 0; }
    }

    if (run) {
        if (!coin_p2p_discover && explicit_peers.empty()) {
            // Default to discovery so `--run` alone still finds fork peers.
            coin_p2p_discover = true;
        }
        return run_embedded(coin_p2p_discover, explicit_peers, fork_checkpoint, http_host, http_port, stratum_port);
    }

    print_banner(argv[0]);
    std::printf("\n");
    return run_selftest();
}
