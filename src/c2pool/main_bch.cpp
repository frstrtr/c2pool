// c2pool-bch — Bitcoin Cash (BCH, SHA256d standalone parent, V36) p2pool node
// entry point.
//
// EXE-WIRE slice (integrator 2026-06-18) closed the "no runnable c2pool-bch
// entrypoint" gap. This slice adds the --ibd RUN-LOOP: a read-only headers-first
// initial-block-download harness that stands up the embedded daemon over its
// P2P front-end against VM300 bchn-bch (192.168.86.110:8333) and reports the
// live sync evidence the M5 size loop rests on:
//   - synced height advancing PAST the init() checkpoint  (chain-ingest works)
//   - false_evict_count                                   (0 == clean sync)
//   - in_flight / reissue_count                           (download-window health)
//
// TWO MODES:
//   --selftest (default) : drive the LIVE ABLA template-budget path
//       (coin/abla.hpp, 1:1 BCHN consensus/abla.cpp port) std-only, proving the
//       GROWTH and FLOOR invariants. Network-free, no core runtime.
//   --ibd [opts]         : stand up EmbeddedDaemon::start_ibd over the P2P
//       front-end and run a bounded io_context loop, logging the evidence tuple
//       each tick until caught up or the deadline. Read-only: a P2P peer
//       connection issues no qm/control op, so VM300 stays read-only. This is
//       the evidence harness, NOT the production daemon — start_ibd skips
//       init_rpc(); run() still owns the external BCHN-RPC fallback.
//
// PER-COIN ISOLATION: src/impl/bch headers only; the --ibd path links the core
// OBJECT-lib (NodeP2P/HeaderChain/Timer) — a SAFE-ADDITIVE link-line addition
// on this target only (integrator 2026-06-18), no shared-base/core source edit.
// p2pool-merged-v36 surface: NONE — ABLA + SPV header state carry no share/
// coinbase/PPLNS/PoW bytes. Conformance oracle: frstrtr/p2poolBCH (kr1z1sBCH);
// BCH = SHA256d standalone parent (NOT merged-mined).

#include <impl/bch/coin/abla.hpp>
#include <impl/bch/config.hpp>
#include <impl/bch/coin/embedded_daemon.hpp>
#include <impl/bch/coin/regtest_block.hpp>
#include <impl/bch/coin/rpc.hpp>
#include <impl/bch/coin/node.hpp>
#include <impl/bch/pool_entrypoint.hpp>
#include <btclibs/util/strencodings.h>   // ParseHexBytes (sharechain prefix)

#include <core/core_util.hpp>

#include <cstdlib>
#include <fstream>

#include <core/netaddress.hpp>
#include <core/timer.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace {

using bch::coin::abla::Config;
using bch::coin::abla::State;
using bch::coin::abla::DEFAULT_CONSENSUS_BLOCK_SIZE;
using bch::coin::abla::ONE_MEGABYTE;
using bch::coin::EmbeddedDaemon;

void print_banner(const char* argv0)
{
    std::cout
        << "c2pool-bch " << C2POOL_VERSION << " — Bitcoin Cash (SHA256d, V36)\n\n"
        << "Usage: " << argv0 << " [--version] [--help] [--selftest]\n"
        << "       " << argv0 << " --ibd [--testnet] [--near-tip] [--auto-kick] [--peer HOST:PORT] [--max-seconds N]\n"
        << "       " << argv0 << " --with-peer-verify [--testnet] [--peer HOST:PORT] [--max-seconds N]\n"
        << "       " << argv0 << " --leg-c-capture [--rpc-conf PATH]\n"
        << "       " << argv0 << " --leg-c-capture-p2p [--rpc-conf PATH] [--p2p-port N]\n"
        << "       " << argv0 << " --pool [--testnet|--regtest] [--stratum [HOST:]PORT] [--peer HOST:PORT] [--anchor N]\n\n"
        << "Status: M5 pool/sharechain + embedded-daemon assembly live.\n"
        << "        The embedded daemon (coin/embedded_daemon.hpp) is the primary\n"
        << "        work source; external BCHN-RPC stays as the fallback.\n"
        << "Consensus: ABLA floor budget = "
        << (DEFAULT_CONSENSUS_BLOCK_SIZE / ONE_MEGABYTE) << " MB; ASERT DAA; CTOR;\n"
        << "        CashTokens transparent; standalone SHA256d parent.\n";
}

// Drive the LIVE ABLA template-budget path (coin/abla.hpp, 1:1 BCHN port).
//   (1) GROWTH  — sustained full blocks raise the limit above the floor.
//   (2) FLOOR   — empty/small blocks never undercut the 32 MB activation floor.
int run_selftest()
{
    const Config config = Config::MakeDefault();         // 32 MB floor default
    const uint64_t floor_limit = State(config, 0).GetBlockSizeLimit();

    State grow(config, DEFAULT_CONSENSUS_BLOCK_SIZE);
    for (int i = 0; i < 5000; ++i)
        grow = grow.NextBlockState(config, grow.GetBlockSizeLimit());
    const uint64_t grown_limit = grow.GetBlockSizeLimit();

    State hold(config, DEFAULT_CONSENSUS_BLOCK_SIZE);
    for (int i = 0; i < 5000; ++i)
        hold = hold.NextBlockState(config, 0);
    const uint64_t held_limit = hold.GetBlockSizeLimit();

    std::cout
        << "[selftest] live bch::coin::abla::State replayed (BCHN consensus/abla port)\n"
        << "[selftest]   floor  limit = " << floor_limit
        << " (" << (floor_limit / ONE_MEGABYTE) << " MB)\n"
        << "[selftest]   grown  limit = " << grown_limit
        << " (" << (grown_limit / ONE_MEGABYTE) << " MB) after 5000 full blocks\n"
        << "[selftest]   held   limit = " << held_limit
        << " (" << (held_limit / ONE_MEGABYTE) << " MB) after 5000 empty blocks\n";

    const bool grew = grown_limit > floor_limit;
    const bool held = held_limit >= floor_limit;
    if (!grew || !held) {
        std::cout << "[selftest] FAIL — ABLA invariant violated"
                  << " (grew=" << grew << " held=" << held << ")\n";
        return 1;
    }
    std::cout << "[selftest]   GROWTH ok (grown > floor); FLOOR ok (held >= floor)\n"
              << "[selftest] OK\n";
    return 0;
}

// Read-only headers-first IBD harness. Stands up the embedded daemon over the
// P2P front-end pointed at one BCHN peer, kicks the first getheaders once the
// handshake is up, and logs the evidence tuple every TICK seconds until the
// chain catches the peer tip (with no in-flight blocks) or the deadline fires.
int run_ibd(const std::string& host, uint16_t port, bool testnet, uint32_t max_seconds,
             bool near_tip, bool auto_kick)
{
    boost::asio::io_context ctx;

    // Construct config WITHOUT a file load: Config(coin_name) only stores paths
    // (Fileconfig ctor reads nothing until init()), so we skip init() and set
    // by hand only the two fields the IBD harness touches — the testnet flag and
    // the single BCHN P2P peer. No pool.yaml/coin.yaml is read or written.
    bch::Config cfg("bch-ibd");
    cfg.m_testnet = testnet;
    const NetService peer(host, port);
    cfg.coin()->m_p2p.address = peer;
    // BCH P2P network magic (pchMessageStart). The harness builds config WITHOUT
    // a YAML load, so m_p2p.prefix is empty by default -> core::Socket frames the
    // version message with a zero-length magic and BCHN drops the peer with EOF
    // right after connect (handshake never completes). Set it by hand, the only
    // other field the IBD harness touches beyond address. Values per BCHN
    // chainparams.cpp: mainnet e3e1f3e8, testnet3 f4e5f3f4.
    cfg.coin()->m_p2p.prefix = testnet
        ? std::vector<std::byte>{ std::byte{0xf4}, std::byte{0xe5}, std::byte{0xf3}, std::byte{0xf4} }
        : std::vector<std::byte>{ std::byte{0xe3}, std::byte{0xe1}, std::byte{0xf3}, std::byte{0xe8} };

    EmbeddedDaemon<bch::Config> daemon(&ctx, &cfg, /*anchor_height=*/0);
    // --near-tip seeds the header origin at the operator-approved BCHN anchor
    // (height 955700) so the sync covers only anchor -> tip; this is the ONLY
    // mode that actually advances the ABLA cursor in a harness window (the
    // genesis-origin cold-start stays ~900k blocks below the anchor -> cursor
    // pinned at the floor by construction; see UID 1375). Default --ibd is the
    // genesis-origin liveness/eviction-evidence loop.
    if (near_tip)
        daemon.start_ibd_near_tip(peer);
    else
        daemon.start_ibd(peer);

    // --auto-kick proves the handshake-gated self-start: arm the embedded
    // header-sync kick on the P2P node and DO NOT poll ibd_kick_sync(). If the
    // synced height advances, the verack handler self-issued the initial
    // getheaders on-wire with no external kick (production run() contract).
    if (auto_kick) {
        daemon.arm_auto_getheaders();
        std::cout << "[ibd] auto-kick armed — header sync self-starts at handshake"
                     " (no manual getheaders poll)\n";
    }

    const uint32_t init_height = daemon.ibd_synced_height();
    std::cout << "[ibd] read-only sync vs " << host << ":" << port
              << (testnet ? " (testnet)" : " (mainnet)")
              << (near_tip ? " [near-tip: anchor-seeded ABLA-feed]" : " [cold-start]")
              << " — init checkpoint=" << init_height
              << ", deadline=" << max_seconds << "s\n";

    bool kicked = false;
    uint32_t elapsed = 0;
    const uint32_t TICK = 5;

    core::Timer tick(&ctx, /*repeat=*/true);
    tick.start(TICK, [&]() {
        elapsed += TICK;
        if (!kicked && daemon.ibd_handshake_ready()) {
            if (!auto_kick) {
                daemon.ibd_kick_sync();
                std::cout << "[ibd] handshake up; getheaders kicked from height "
                          << daemon.ibd_synced_height() << "\n";
            } else {
                std::cout << "[ibd] handshake up; AUTO getheaders self-started"
                             " (no manual kick) from height "
                          << daemon.ibd_synced_height() << "\n";
            }
            kicked = true;
        }
        const uint32_t h   = daemon.ibd_synced_height();
        const uint32_t tip = daemon.ibd_peer_tip();
        std::cout << "[ibd] t=" << elapsed << "s synced=" << h
                  << " peer_tip=" << tip
                  << " in_flight=" << daemon.ibd_in_flight()
                  << " reissue=" << daemon.ibd_reissue_count()
                  << " false_evict=" << daemon.ibd_false_evict_count()
                  << " abla_cursor=" << daemon.ibd_abla_cursor()
                  << " abla_budget=" << daemon.ibd_abla_budget() << "\n";

        const bool advanced  = h > init_height;
        const bool caught_up = kicked && tip > 0 && h >= tip && daemon.ibd_in_flight() == 0;
        if (caught_up || elapsed >= max_seconds) {
            std::cout << "[ibd] " << (caught_up ? "SYNCED" : "DEADLINE")
                      << " — final synced=" << h
                      << " (init checkpoint=" << init_height
                      << ", advanced=" << (advanced ? "yes" : "NO") << ")"
                      << " false_evict=" << daemon.ibd_false_evict_count()
                      << " reissue=" << daemon.ibd_reissue_count()
                      << " abla_cursor=" << daemon.ibd_abla_cursor()
                      << " abla_budget=" << daemon.ibd_abla_budget() << "\n";
            tick.stop();
            ctx.stop();
        }
    });

    ctx.run();
    return 0;
}

// ---------------------------------------------------------------------------
// --with-peer-verify: WITH-PEER end-to-end check of the #231 production arming.
//
// #231 wired the embedded P2P leg into the PRODUCTION run() (maybe_start_p2p),
// closing the won-block RPC-only degradation. Its unit slice only proved the
// OFFLINE no-peer contract; the leg actually FIRING with a configured peer was
// unverified end-to-end (integrator UID 1560). This mode closes that gap
// against the live VM300 bchn-bch peer, strictly READ-ONLY (start_p2p connects
// + getheaders + getdata only -- no init_rpc, no qm/control op):
//
//   (a) drives the REAL maybe_start_p2p() through arm_p2p_no_rpc() (run() minus
//       init_rpc) and asserts it returned true AND broadcast_route()=="p2p" --
//       the won-block dispatcher now TAKES the embedded P2P relay leg, not the
//       RPC-only fallback. Routing is asserted WITHOUT relaying a block onto
//       mainnet (broadcast_route is a dry sink-selection read); actual
//       fire+ACCEPT of a c2pool-built block is the CLOSED co-located-regtest
//       broadcaster gate (leg-C), not repeated against live mainnet here.
//   (b) forces a REAL download-window stall: enqueues an unservable block hash
//       through request_block_downloads -- the EXACT sink the BlockConnector
//       deep-reorg re-request wires to (set_block_requester ->
//       p2p->request_block_downloads). VM300 never delivers it, so after
//       BLOCK_DL_TIMEOUT_SEC the expire tick requeues it and ibd_reissue_count()
//       goes NONZERO off the live window -- not the synthetic-tick substitute
//       the unit test uses.
//
// p2pool-merged-v36 surface: NONE (transport + local block-dl plumbing only).
// ---------------------------------------------------------------------------
int run_with_peer_verify(const std::string& host, uint16_t port, bool testnet,
                         uint32_t max_seconds)
{
    boost::asio::io_context ctx;

    bch::Config cfg("bch-with-peer-verify");
    cfg.m_testnet = testnet;
    const NetService peer(host, port);
    cfg.coin()->m_p2p.address = peer;               // the production "configured peer"
    cfg.coin()->m_p2p.prefix = testnet
        ? std::vector<std::byte>{ std::byte{0xf4}, std::byte{0xe5}, std::byte{0xf3}, std::byte{0xf4} }
        : std::vector<std::byte>{ std::byte{0xe3}, std::byte{0xe1}, std::byte{0xf3}, std::byte{0xe8} };

    EmbeddedDaemon<bch::Config> daemon(&ctx, &cfg, /*anchor_height=*/0);

    // (a) Production arming: run() minus init_rpc, driving the real
    //     maybe_start_p2p() through its configured-peer gate.
    const bool armed = daemon.arm_p2p_no_rpc();
    const std::string route0 = daemon.broadcast_route();
    std::cout << "[verify] arm_p2p_no_rpc -> " << (armed ? "P2P-LIVE" : "RPC-ONLY")
              << "; broadcast_route=" << route0
              << " (peer " << host << ":" << port
              << (testnet ? " testnet" : " mainnet") << ")\n";

    int failures = 0;
    if (!armed) { std::cerr << "FAIL: maybe_start_p2p did not arm with a configured peer\n"; ++failures; }

    bool kicked = false;
    bool stall_injected = false;
    bool route_p2p_seen = false;
    uint32_t elapsed = 0;
    const uint32_t TICK = 5;

    // An unservable (orphan) block hash: VM300 has no such block, so a getdata
    // for it is never satisfied -> the window must time out and reissue it.
    uint256 orphan; orphan.SetHex(
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    core::Timer tick(&ctx, /*repeat=*/true);
    tick.start(TICK, [&]() {
        elapsed += TICK;

        if (!kicked && daemon.ibd_handshake_ready()) {
            kicked = true;
            // Handshake up => P2P transport live => dispatcher takes the P2P leg.
            const std::string route = daemon.broadcast_route();
            route_p2p_seen = (route == "p2p");
            std::cout << "[verify] handshake up; broadcast_route=" << route
                      << " (expect p2p) -- won-block dispatcher takes P2P leg\n";
            // (b) Inject the forced stall through the connector's re-request sink.
            if (auto* p2p = daemon.node().p2p()) {
                p2p->request_block_downloads({orphan});
                stall_injected = true;
                std::cout << "[verify] forced stall: enqueued 1 unservable block via"
                          << " request_block_downloads (connector re-request sink);"
                          << " awaiting timeout->reissue (BLOCK_DL_TIMEOUT 60s)\n";
            }
        }

        const std::size_t reissue = daemon.ibd_reissue_count();
        std::cout << "[verify] t=" << elapsed << "s handshake=" << (kicked ? "up" : "down")
                  << " route=" << daemon.broadcast_route()
                  << " in_flight=" << daemon.ibd_in_flight()
                  << " reissue=" << reissue << "\n";

        const bool reissue_seen = stall_injected && reissue > 0;
        if (reissue_seen || elapsed >= max_seconds) {
            std::cout << "[verify] " << (reissue_seen ? "REISSUE-CONFIRMED" : "DEADLINE")
                      << " -- armed=" << (armed ? "yes" : "NO")
                      << " route_p2p=" << (route_p2p_seen ? "yes" : "NO")
                      << " reissue=" << reissue << "\n";
            tick.stop();
            ctx.stop();
        }
    });

    ctx.run();

    if (!route_p2p_seen) { std::cerr << "FAIL: broadcast_route never == p2p after handshake\n"; ++failures; }
    if (daemon.ibd_reissue_count() == 0) { std::cerr << "FAIL: reissue_count stayed 0 (no live stall recovery)\n"; ++failures; }

    if (failures == 0) {
        std::cout << "with_peer_verify: ALL PASS (P2P leg armed+selected; live reissue confirmed)\n";
        return 0;
    }
    std::cerr << "with_peer_verify: " << failures << " FAILURE(S)\n";
    return 1;
}

// ---------------------------------------------------------------------------
// leg-C: dual-path broadcaster capture (RPC leg).
//
// The broadcaster-gate dual-path close needs ONE regtest capture proving a
// c2pool-BUILT, consensus-valid block is ACCEPTED by the node: submitblock=
// accept + a verbatim BCHN "UpdateTip: new best=... height=N" connect-block
// line. This mode drives the RPC leg of EmbeddedDaemon::broadcast_won_block --
// NodeRPC::submit_block_hex, the exact submitblock sink -- against the co-
// located self-provisioned regtest node (leg-C host, integrator 2026-06-18).
//
// Isolated regtest has zero peers, so getblocktemplate is node-gated
// ("Bitcoin is not connected!"); submitblock carries no such guard, so the
// block params are sourced directly (regtest::build_and_solve) off the live
// tip via getblockchaininfo. The P2P-relay leg (submit_block_p2p_raw over the
// embedded front-end) is the immediate follow-on sub-slice and reuses THIS
// built blocks raw bytes. PER-COIN ISOLATION: src/impl/bch only; zero
// p2pool-merged-v36 surface (parent BCH block dispatch, no share/PPLNS bytes).
struct RegtestRpcConf { std::string user; std::string pass; uint16_t port = 18443; };

inline std::string trim_conf(std::string s)
{
    const char* ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

// Parse rpcuser/rpcpassword/rpcport from a bitcoin.conf-style file (also accepts
// the c2pool bch_rpc_user/bch_rpc_password keys). The password stays in-file and
// is NEVER echoed (operator self-provision rule 2026-06-19).
bool load_rpc_conf(const std::string& path, RegtestRpcConf& out)
{
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        const auto h = line.find(char(35));
        if (h != std::string::npos) line = line.substr(0, h);
        const auto eq = line.find(char(61));
        if (eq == std::string::npos) continue;
        const std::string key = trim_conf(line.substr(0, eq));
        const std::string val = trim_conf(line.substr(eq + 1));
        if (val.empty()) continue;
        if (key == "rpcuser" || key == "bch_rpc_user")             out.user = val;
        else if (key == "rpcpassword" || key == "bch_rpc_password") out.pass = val;
        else if (key == "rpcport")                                 out.port = static_cast<uint16_t>(std::stoi(val));
    }
    return !out.user.empty() && !out.pass.empty();
}

int run_leg_c_capture(const std::string& conf_path)
{
    RegtestRpcConf rc;
    if (!load_rpc_conf(conf_path, rc)) {
        std::cout << "[leg-c] FAIL -- no rpcuser/rpcpassword in " << conf_path
                  << " (run scripts/gen-bch-daemon-creds.sh first)\n";
        return 1;
    }

    boost::asio::io_context ctx;
    bch::coin::NodeRPC rpc(&ctx, /*coin=*/nullptr, /*testnet=*/false);
    const NetService addr(std::string("127.0.0.1"), rc.port);
    // connect() posts async resolve/connect; the first synchronous Send() below
    // self-heals via NodeRPC::sync_reconnect() (blocking connect) on the not-yet-
    // connected stream -- the same path coin::Node::init_rpc() relies on.
    rpc.connect(addr, rc.user + ":" + rc.pass);

    nlohmann::json info;
    try {
        info = rpc.getblockchaininfo();
    } catch (const std::exception& e) {
        std::cout << "[leg-c] FAIL -- getblockchaininfo: " << e.what()
                  << " (regtest daemon up on 127.0.0.1:" << rc.port << "?)\n";
        return 1;
    }
    const uint256  prev   = uint256S(info.at("bestblockhash").get<std::string>());
    const uint32_t height = static_cast<uint32_t>(info.at("blocks").get<int>()) + 1;

    // Regtest consensus params (BCHN chainparams.cpp CRegTestParams): powLimit
    // nBits 0x207fffff (trivial target -> short nonce sweep), BIP9 version bit,
    // 50-coin subsidy for heights 1..149 (regtest halving interval 150).
    const uint32_t REGTEST_BITS = 0x207fffffu;
    const int32_t  VERSION      = 0x20000000;
    const int64_t  SUBSIDY      = 5000000000LL;
    const uint32_t curtime      = core::timestamp();

    auto built = bch::coin::regtest::build_and_solve(
        prev, REGTEST_BITS, VERSION, curtime, height, SUBSIDY);
    if (!built.solved) {
        std::cout << "[leg-c] FAIL -- regtest block did not solve (nBits misconfigured)\n";
        return 1;
    }
    std::cout << "[leg-c] built consensus-valid block: height=" << height
              << " hash=" << built.hash.GetHex()
              << " bytes=" << built.bytes.size() << "\n";

    // RPC leg of the dual-path broadcaster: NodeRPC::submit_block_hex is the exact
    // submitblock sink EmbeddedDaemon::broadcast_won_block fires. ignore_failure
    // false so a reject surfaces.
    const bool ok = rpc.submit_block_hex(built.hex, /*ignore_failure=*/false);
    std::cout << "[leg-c] submitblock RPC leg: " << (ok ? "ACCEPTED" : "REJECTED") << "\n"
              << "[leg-c] expect in regtest debug.log -> "
              << "UpdateTip: new best=" << built.hash.GetHex()
              << " height=" << height << "\n";
    return ok ? 0 : 1;
}


// ---------------------------------------------------------------------------
// leg-C: dual-path broadcaster capture (P2P-RELAY leg).
//
// Closes the SECOND half of the broadcaster gate (item 1). The RPC leg
// (run_leg_c_capture, @81ca0ca5) proved NodeRPC::submit_block_hex reaches and
// connects. This leg proves the PRIMARY embedded path -- Node::submit_block_
// p2p_raw, the sink EmbeddedDaemon::broadcast_won_block fires first -- relays a
// won block over the live P2P front-end and the node connects it (UpdateTip).
//
// Integrator verification catch (2026-06-19): do NOT reuse the RPC-leg block
// bytes -- that block is already the node tip, so a re-relay hits already-have-
// block and yields a FALSE-POSITIVE relay capture. This mode builds a FRESH
// block on the CURRENT tip (height N+1) and relays ONLY via P2P (no submitblock
// fired), so the resulting UpdateTip can ONLY have been caused by the embedded
// relay path. PER-COIN ISOLATION: src/impl/bch + main_bch.cpp only; P2P-only,
// zero p2pool-merged-v36 surface (parent BCH block dispatch, no share bytes).
//
// Regtest P2P magic = dab5bffa (BCHN chainparams.cpp CRegTestParams); default
// P2P port 18444 (RPC 18443). The node negotiates compact blocks; a solo-
// coinbase block prefills the only tx, so no getblocktxn round-trip is needed.
int run_leg_c_capture_p2p(const std::string& conf_path, uint16_t p2p_port)
{
    RegtestRpcConf rc;
    if (!load_rpc_conf(conf_path, rc)) {
        std::cout << "[leg-c-p2p] FAIL -- no rpcuser/rpcpassword in " << conf_path
                  << " (run scripts/gen-bch-daemon-creds.sh first)\n";
        return 1;
    }

    boost::asio::io_context ctx;

    // RPC client: reads the tip to build on + confirms the relayed block
    // connected (bestblockhash advances to the fresh hash). Submission itself is
    // P2P-only -- this RPC is read-back, NOT a submitblock sink.
    bch::coin::NodeRPC rpc(&ctx, /*coin=*/nullptr, /*testnet=*/false);
    rpc.connect(NetService(std::string("127.0.0.1"), rc.port), rc.user + ":" + rc.pass);

    // P2P front-end config (built by hand, no YAML load -- mirrors run_ibd).
    // Regtest magic dab5bffa, else core::Socket frames the version with empty
    // magic and the node drops the peer on EOF (handshake never completes).
    bch::Config cfg("bch-leg-c-p2p");
    cfg.m_testnet = false;
    const NetService p2p_addr(std::string("127.0.0.1"), p2p_port);
    cfg.coin()->m_p2p.address = p2p_addr;
    cfg.coin()->m_p2p.prefix = std::vector<std::byte>{
        std::byte{0xda}, std::byte{0xb5}, std::byte{0xbf}, std::byte{0xfa} };

    bch::coin::Node<bch::Config> node(&ctx, &cfg);
    node.start_p2p(p2p_addr);
    std::cout << "[leg-c-p2p] P2P relay connecting to 127.0.0.1:" << p2p_port
              << " (regtest magic dab5bffa)\n";

    bool     relayed   = false;
    bool     confirmed = false;
    uint256  want_hash;
    uint32_t want_height = 0;
    uint32_t elapsed     = 0;
    const uint32_t TICK     = 2;
    const uint32_t DEADLINE = 60;

    core::Timer tick(&ctx, /*repeat=*/true);
    tick.start(TICK, [&]() {
        elapsed += TICK;

        // Stage 1: await version/verack, then build + relay ONE fresh block.
        if (!relayed) {
            if (!node.is_handshake_complete()) {
                if (elapsed >= DEADLINE) {
                    std::cout << "[leg-c-p2p] FAIL -- P2P handshake never completed "
                              << "(regtest daemon listening on 127.0.0.1:" << p2p_port << "?)\n";
                    tick.stop(); ctx.stop();
                }
                return;
            }
            nlohmann::json info;
            try { info = rpc.getblockchaininfo(); }
            catch (const std::exception& e) {
                std::cout << "[leg-c-p2p] FAIL -- getblockchaininfo: " << e.what() << "\n";
                tick.stop(); ctx.stop(); return;
            }
            const uint256 prev = uint256S(info.at("bestblockhash").get<std::string>());
            want_height = static_cast<uint32_t>(info.at("blocks").get<int>()) + 1;

            const uint32_t REGTEST_BITS = 0x207fffffu;
            const int32_t  VERSION      = 0x20000000;
            const int64_t  SUBSIDY      = 5000000000LL;
            auto built = bch::coin::regtest::build_and_solve(
                prev, REGTEST_BITS, VERSION, core::timestamp(), want_height, SUBSIDY);
            if (!built.solved) {
                std::cout << "[leg-c-p2p] FAIL -- fresh block did not solve\n";
                tick.stop(); ctx.stop(); return;
            }
            want_hash = built.hash;
            std::cout << "[leg-c-p2p] built FRESH block: height=" << want_height
                      << " hash=" << built.hash.GetHex()
                      << " prev=" << prev.GetHex()
                      << " bytes=" << built.bytes.size() << "\n";

            // PRIMARY sink: P2P relay ONLY. No submitblock fired, so any
            // UpdateTip at this hash is attributable solely to the embedded path.
            node.submit_block_p2p_raw(built.bytes);
            relayed = true;
            std::cout << "[leg-c-p2p] relayed via submit_block_p2p_raw (P2P-only); "
                      << "polling node for UpdateTip to " << built.hash.GetHex() << "\n";
            return;
        }

        // Stage 2: confirm the node connected the relayed block (tip advanced).
        nlohmann::json info;
        try { info = rpc.getblockchaininfo(); }
        catch (const std::exception&) { return; }
        const uint256 tip = uint256S(info.at("bestblockhash").get<std::string>());
        if (tip == want_hash) {
            confirmed = true;
            std::cout << "[leg-c-p2p] P2P relay leg: UpdateTip CONFIRMED -- node best="
                      << tip.GetHex() << " height=" << want_height << "\n"
                      << "[leg-c-p2p] expect in regtest debug.log -> "
                      << "UpdateTip: new best=" << want_hash.GetHex()
                      << " height=" << want_height << "\n";
            tick.stop(); ctx.stop();
            return;
        }
        if (elapsed >= DEADLINE) {
            std::cout << "[leg-c-p2p] FAIL -- relayed but node tip did not advance to "
                      << want_hash.GetHex() << " within " << DEADLINE << "s (still "
                      << tip.GetHex() << ")\n";
            tick.stop(); ctx.stop();
        }
    });

    ctx.run();
    return confirmed ? 0 : 1;
}


// --pool: PRODUCTION pool run-loop -- the first non-harness c2pool-bch
// entrypoint. Stands up the BCH pool node + embedded coin daemon on one shared
// io_context via bch::standup_pool_run, with the won-block sink bound (dual
// path: embedded P2P primary + BCHN submitblock fallback) and, when --stratum
// is given, the miner-facing BCHWorkSource + core::StratumServer listening so a
// genuine share-author coinbase is what gets assembled and broadcast. The
// --ibd path is a read-only evidence harness; THIS path is the real node.
//
// Config is built WITHOUT a YAML load (matches run_ibd): no pool.yaml/coin.yaml
// is required for the slice. The two embedded-daemon wire fields (P2P magic +
// BCHN peer) and the sharechain PREFIX (bucket-1 isolation primitive, never
// standardized) are set by hand from BCH chainparams. The external BCHN-RPC
// fallback inside EmbeddedDaemon::run() is retained (external_fallback law).
//
// p2pool-merged-v36 surface: NONE -- run-loop bring-up + block dispatch, not
// share/PPLNS/coinbase/PoW bytes. PER-COIN ISOLATION: src/impl/bch only.
int run_pool(const std::string& peer_host, uint16_t peer_port, bool testnet,
             bool regtest, uint32_t anchor_height,
             const std::string& stratum_addr, uint16_t stratum_port)
{
    boost::asio::io_context ioc;

    bch::PoolConfig::is_testnet = testnet;

    bch::Config config("bch");
    // Skip Config::init() (no on-disk pool.yaml/coin.yaml); set only the fields
    // the run-loop touches, from BCH chainparams.
    config.coin()->m_testnet = testnet || regtest;
    config.coin()->m_symbol  = "BCH";
    config.coin()->m_p2p.address = NetService(peer_host, peer_port);
    // BCH P2P network magic (pchMessageStart, BCHN chainparams.cpp): mainnet
    // e3e1f3e8, testnet3 f4e5f3f4, regtest dab5bffa. Wrong magic == BCHN drops
    // the peer with EOF right after connect.
    config.coin()->m_p2p.prefix = regtest
        ? std::vector<std::byte>{ std::byte{0xda}, std::byte{0xb5}, std::byte{0xbf}, std::byte{0xfa} }
        : (testnet
            ? std::vector<std::byte>{ std::byte{0xf4}, std::byte{0xe5}, std::byte{0xf3}, std::byte{0xf4} }
            : std::vector<std::byte>{ std::byte{0xe3}, std::byte{0xe1}, std::byte{0xf3}, std::byte{0xe8} });
    // Sharechain identity: BCH p2pool PREFIX namespaces the sharechain P2P
    // framing. standup_pool_run's Node reads pool()->m_prefix.
    config.pool()->m_prefix = ParseHexBytes(bch::PoolConfig::prefix_hex());

    std::cout
        << "[pool] c2pool-bch pool run-loop"
        << (regtest ? " (regtest)" : (testnet ? " (testnet)" : " (mainnet)"))
        << " -- BCHN peer " << peer_host << ":" << peer_port
        << ", cold-start anchor=" << anchor_height;
    if (stratum_port)
        std::cout << ", stratum " << stratum_addr << ":" << stratum_port;
    else
        std::cout << ", stratum DISABLED (no --stratum)";
    std::cout << "\n";

    try {
        bch::standup_pool_run(ioc, config, anchor_height,
                              stratum_addr, stratum_port, testnet || regtest);
    } catch (const std::exception& e) {
        std::cout << "[pool] FATAL: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool want_help = false;
    bool want_ibd = false;
    bool want_leg_c = false;
    bool want_leg_c_p2p = false;
    bool want_with_peer_verify = false;
    bool want_pool = false;
    bool regtest = false;
    std::string stratum_addr = "0.0.0.0";
    uint16_t stratum_port = 0;        // 0 disables stratum; --stratum sets it
    uint32_t anchor_height = 0;       // cold-start ABLA floor anchor
    uint16_t leg_c_p2p_port = 18444;  // BCHN regtest P2P default
    std::string rpc_conf;
    bool testnet = false;
    bool near_tip = false;
    bool auto_kick = false;
    std::string host = "192.168.86.110";   // VM300 bchn-bch
    uint16_t port = 8333;
    uint32_t max_seconds = 600;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-bch " << C2POOL_VERSION << "\n";
            return 0;
        }
        if (std::strcmp(argv[i], "--help") == 0)     want_help = true;
        if (std::strcmp(argv[i], "--ibd") == 0)      want_ibd = true;
        if (std::strcmp(argv[i], "--with-peer-verify") == 0) want_with_peer_verify = true;
        if (std::strcmp(argv[i], "--pool") == 0)     want_pool = true;
        if (std::strcmp(argv[i], "--regtest") == 0)  { regtest = true; testnet = true; port = 18444; }
        if (std::strcmp(argv[i], "--anchor") == 0 && i + 1 < argc)
            anchor_height = static_cast<uint32_t>(std::stoul(argv[++i]));
        if (std::strcmp(argv[i], "--stratum") == 0 && i + 1 < argc) {
            std::string sp = argv[++i];
            const auto c = sp.rfind(char(58));  // ASCII colon
            if (c != std::string::npos) {
                stratum_addr = sp.substr(0, c);
                stratum_port = static_cast<uint16_t>(std::stoul(sp.substr(c + 1)));
            } else {
                stratum_port = static_cast<uint16_t>(std::stoul(sp));
            }
        }
        if (std::strcmp(argv[i], "--leg-c-capture") == 0) want_leg_c = true;
        if (std::strcmp(argv[i], "--leg-c-capture-p2p") == 0) want_leg_c_p2p = true;
        if (std::strcmp(argv[i], "--p2p-port") == 0 && i + 1 < argc)
            leg_c_p2p_port = static_cast<uint16_t>(std::stoul(argv[++i]));
        if (std::strcmp(argv[i], "--rpc-conf") == 0 && i + 1 < argc) rpc_conf = argv[++i];
        if (std::strcmp(argv[i], "--testnet") == 0) { testnet = true; port = 18333; }
        if (std::strcmp(argv[i], "--near-tip") == 0) near_tip = true;
        if (std::strcmp(argv[i], "--auto-kick") == 0) auto_kick = true;
        if (std::strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
            std::string hp = argv[++i];
            const auto c = hp.rfind(char(58));  // ASCII colon
            if (c != std::string::npos) {
                host = hp.substr(0, c);
                port = static_cast<uint16_t>(std::stoi(hp.substr(c + 1)));
            } else {
                host = hp;
            }
        }
        if (std::strcmp(argv[i], "--max-seconds") == 0 && i + 1 < argc)
            max_seconds = static_cast<uint32_t>(std::stoul(argv[++i]));
    }

    print_banner(argv[0]);
    if (want_help)
        return 0;

    if (want_leg_c_p2p) {
        if (rpc_conf.empty()) {
            const char* home = std::getenv("HOME");
            rpc_conf = std::string(home ? home : ".") + "/bch-regtest/bitcoin.conf";
        }
        return run_leg_c_capture_p2p(rpc_conf, leg_c_p2p_port);
    }

    if (want_leg_c) {
        if (rpc_conf.empty()) {
            const char* home = std::getenv("HOME");
            rpc_conf = std::string(home ? home : ".") + "/bch-regtest/bitcoin.conf";
        }
        return run_leg_c_capture(rpc_conf);
    }

    if (want_pool)
        return run_pool(host, port, testnet, regtest, anchor_height, stratum_addr, stratum_port);

    if (want_with_peer_verify)
        return run_with_peer_verify(host, port, testnet, max_seconds);

    if (want_ibd)
        return run_ibd(host, port, testnet, max_seconds, near_tip, auto_kick);

    // Default / --selftest: drive the live ABLA budget path, then exit.
    return run_selftest();
}
