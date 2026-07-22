// SPDX-License-Identifier: AGPL-3.0-or-later
// c2pool-dash — DASH (X11 standalone parent, older-than-v35 -> V36) p2pool node
// entry point.
//
// EXE-WIRE slice 2 (integrator 2026-06-23, stacked on launcher slice 1 #387):
// closes the "DASH is impl-files-only, not runnable" gap. Slice 1 registered
// DASH in the unified launcher dispatch (parse_blockchain / port / net-magic);
// this slice gives DASH its own runnable executable that drives the REAL dash
// consensus primitives, so `dash` is no longer a dispatch label with no body.
//
// PER-COIN ISOLATION: src/impl/dash headers only (params/crypto/subsidy); no
// src/impl/<other-coin> edit, no shared-base/core source edit, dashd RPC
// fallback untouched. Mirrors the c2pool-bch / c2pool-dgb add_executable shape,
// pruned to the header-only consensus path (DASH carries no node.cpp run-loop
// TU on master yet — that is the S7/S8 block-submission lane).
//
// ONE MODE TODAY:
//   --selftest (default) : drive the LIVE dash consensus paths std-only, network
//       free, exercising the exact code the sharechain depends on, then exit:
//         (1) make_coin_params  — the oracle-sourced CoinParams factory wired,
//             incl. the X11 pow_func reachable through the coin-params seam.
//         (2) X11 PoW           — DASH mainnet genesis + a real-node testnet3
//             block header reproduce their published hashes (CI-pinned KATs,
//             test_dash_x11_kat.cpp).
//         (3) subsidy           — post-V20 block reward + 3/4 MN payment match
//             the live-validated mainnet value (test_dash_subsidy.cpp).
//
// BLOCK-SUBMISSION (--run) — LIVE, dual-path (S8). A won DASH block reaches the
// network via dash::coin::broadcast_won_block over BOTH independent arms, wired
// into the DASHWorkSource won-block sink (stratum_submit_fn):
//   - ARM A embedded P2P relay (ALWAYS-PRIMARY, daemonless): the E1 CoinClient
//     (coin/p2p_client.hpp, --coin-p2p-connect) submit_block_p2p_raw pushes the
//     packed block onto the coin P2P net. With NO local dashd, a won block still
//     reaches the network on this arm alone — the daemonless critical path.
//   - ARM B dashd submitblock RPC backup (on-demand): the DASH NodeRPC TU
//     (coin/rpc.cpp, submit_block_hex), fired whenever a local dashd is armed
//     (also covers a cold/faulted relay). --no-p2p-relay suppresses ARM A only
//     (A/B isolation). NEVER a silent drop: reaching NEITHER sink logs LOUDLY.
//
// Conformance oracle: frstrtr/p2pool-dash (older-than-v35; transition 16 -> v36).
// External dashd RPC stays as a fallback alongside the (future) embedded path.

#include <impl/dash/params.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>   // must precede subsidy.hpp (dash_txid in scope)
#include <impl/dash/coin/subsidy.hpp>

#include <core/coin_params.hpp>
#include <core/core_util.hpp>              // raise_nofile_limit (hotel interim fix #4)
#include <core/uint256.hpp>
#include <core/netaddress.hpp>             // NetService (dashd RPC endpoint)

#include <impl/dash/coin/rpc.hpp>          // dash::coin::NodeRPC — external-dashd submitblock arm (slice 3)
#include <impl/dash/coin/work_source.hpp>   // dash::coin::select_dash_work -- embedded-gbt live-wire + dashd fallback (S8 capstone)
#include <impl/dash/coin/rpc_conf.hpp>     // dash.conf creds resolution (rpcpassword off argv)
#include <impl/dash/coin/node_interface.hpp>
#include <impl/dash/coin/p2p_client.hpp>   // dash::coin::p2p::CoinClient — OPT-IN coin-network dial (E1, --coin-p2p-connect)
#include <impl/dash/coin/won_block_dispatch.hpp> // dash::coin::broadcast_won_block — S8 dual-path won-block dispatcher (embedded P2P primary + submitblock RPC backup)
#include <impl/dash/coin/zmq_tip_notify.hpp> // dash::coin::TipHashDedup / ZmqHashblockSubscriber — dashd ZMQ hashblock INSTANT tip-notify (opt-in, hardening on the #770 poll)
#include <impl/dash/coin/node_coin_state.hpp>  // dash::coin::NodeCoinState (embedded work bundle)
#include <impl/dash/coin/dkg_window.hpp>       // dash::coin::is_dkg_commitment_window (BLOCKER-1 guard)
#include <impl/dash/coin/utxo_lane.hpp>    // dash::coin::UtxoLane — embedded UTXO/fee lane (E2b, #738)
#include <impl/dash/coin/header_chain.hpp>       // dash::coin::HeaderChain — SPV header/tip authority (E2a)
#include <impl/dash/coin/coin_state_maintainer.hpp>  // dash::coin::CoinStateMaintainer — populate ordering gate (E2a)
#include <impl/dash/coin/live_feed.hpp>          // E2a live-feed bridge (raw wire events -> derived ingest events)
#include <impl/dash/coin/mempool_ingest.hpp>     // wire_mempool_ingest (leg 1)
#include <impl/dash/coin/tip_ingest.hpp>         // wire_tip_ingest (leg 2)
#include <impl/dash/coin/block_connect_ingest.hpp>   // wire_block_connect_ingest (leg 3)
#include <impl/dash/coin/mn_list_ingest.hpp>     // wire_mn_list_ingest (leg 4)
#include <impl/dash/coin/mn_seed.hpp>            // E2c: RPC protx-list MN-set seed (parse_protx_list_seed)
#include <impl/dash/node.hpp>          // dash::Node — sharechain pool-node (NodeBridge<NodeImpl,Legacy,Actual>)
#include <impl/dash/config.hpp>        // dash::Config (PoolConfig/CoinConfig)
#include <impl/dash/config_pool.hpp>   // dash::SharechainConfig — P2P_PORT / PREFIX / min-proto SSOT
#include <core/filesystem.hpp>         // core::filesystem::config_path()
#include <btclibs/util/strencodings.h> // ParseHexBytes (prefix isolation primitive)
#include <filesystem>
#include <system_error>
#include <impl/dash/coin/block_producer.hpp>  // dash::coin::mine_block / serialize_full_block_hex (slice 5)
#include <impl/dash/coinbase_builder.hpp>      // dash::coinbase::build / compute_dash_payouts (slice 5)
#include <impl/dash/params.hpp>                // dash::make_coin_params (already via top include)
#include <core/uint256.hpp>                    // uint160 payout pubkey hash
#include <core/target_utils.hpp>              // chain::target_to_difficulty (dashboard net-diff)

#include <core/stratum_server.hpp>             // core::StratumServer — miner-facing accept-loop (run-path caller)
#include <impl/dash/stratum/work_source.hpp>   // dash::stratum::DASHWorkSource — concrete core::stratum::IWorkSource
#include <impl/dash/mint_runloop.hpp>          // dash::mint — run-loop share minting (slice 3/3)
#include <core/web_server.hpp>                 // core::WebServer — the EXISTING c2pool dashboard (same wiring main_ltc.cpp uses)
#include <impl/dash/enhanced_node.hpp>         // dash::EnhancedDashNode — core::IMiningNode the WebServer ctor takes
#include <core/log.hpp>

#include <chrono>
#include <ctime>
#include <optional>
#include <random>

#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>   // io-thread-decouple: background RPC pool
#include <boost/asio/post.hpp>

#include <cstdint>
#include <cstdlib>      // std::getenv
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace {

// -- Sharechain (pool-to-pool) peering CONTRACT (launcher-peering-cli slice) --
// The DASH dual-pool G2 ratchet (LIVE rows C1-C4) needs main_dash to accept the
// peering argv the way main_btc does (--sharechain-port + bootstrap). This slice
// lands the argv CONTRACT + validation those rows invoke. The LIVE bind/dial is
// driven by DASH's sharechain pool Node (the pool::NodeBridge analog of btc::Node
// / dgb::Node = node.hpp + peer/messages/share_tracker), which is NOT yet on
// master and is the next S8 leaf; this surface wires straight into it when it
// lands. No shared-base / other-coin edit; dashd-RPC fallback untouched.
struct PeeringConfig {
    std::string listen_host = "0.0.0.0";   // --listen [HOST:]PORT bind interface
    uint16_t    listen_port = 0;           // 0 => sharechain SSOT default (8999/18999)
    bool        listen_set  = false;
    std::vector<NetService> addnodes;      // --addnode HOST:PORT (persistent outbound)
    std::vector<NetService> connects;      // --connect HOST:PORT (connect-only; no listen/discovery)
};

// Parse "HOST:PORT" (PORT mandatory; IPv4/hostname single-colon form).
bool parse_hostport(const std::string& str, NetService& out)
{
    const auto colon = str.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= str.size())
        return false;
    const std::string host = str.substr(0, colon);
    const std::string pstr = str.substr(colon + 1);
    if (pstr.find_first_not_of("0123456789") != std::string::npos) return false;
    const long p = std::strtol(pstr.c_str(), nullptr, 10);
    if (p <= 0 || p > 65535) return false;
    out = NetService(host, static_cast<uint16_t>(p));
    return true;
}

// Parse "[HOST:]PORT". Bare PORT keeps the caller-supplied default host.
bool parse_listen(const std::string& str, std::string& host, uint16_t& port)
{
    const auto colon = str.rfind(':');
    std::string pstr = (colon == std::string::npos) ? str : str.substr(colon + 1);
    if (colon != std::string::npos) {
        if (colon == 0) return false;
        host = str.substr(0, colon);
    }
    if (pstr.empty() || pstr.find_first_not_of("0123456789") != std::string::npos) return false;
    const long p = std::strtol(pstr.c_str(), nullptr, 10);
    if (p <= 0 || p > 65535) return false;
    port = static_cast<uint16_t>(p);
    return true;
}

// Report the requested sharechain peering topology at run-loop bring-up. Honest
// about the deferred live bind: a won/seen share does NOT yet cross the wire
// until the sharechain pool-node leaf lands.
void report_peering(const PeeringConfig& peer, bool testnet)
{
    const uint16_t ssot = testnet ? 18999 : 8999;
    const uint16_t bind = peer.listen_port ? peer.listen_port : ssot;
    if (!peer.connects.empty() && !peer.listen_set) {
        std::cout << "[run] sharechain peering: --connect mode ("
                  << peer.connects.size() << " peer[s]); listen + discovery suppressed\n";
    } else {
        std::cout << "[run] sharechain peering: listen " << peer.listen_host << ":" << bind
                  << (peer.listen_set ? " (--listen)\n" : " (sharechain SSOT default)\n");
    }
    for (const auto& a : peer.addnodes)
        std::cout << "[run]   addnode (persistent outbound) -> " << a.to_string() << "\n";
    for (const auto& c : peer.connects)
        std::cout << "[run]   connect (connect-only)        -> " << c.to_string() << "\n";
    std::cout << "[run] peering argv contract is LIVE and the sharechain pool Node\n"
                 "[run]       (node.hpp: NodeBridge<NodeImpl,Legacy,Actual>) binds the listener\n"
                 "[run]       below (S8-p2p.3); reception rides #656/#657.\n";
}

using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;

void print_banner(const char* argv0)
{
    std::cout
        << "c2pool-dash " << C2POOL_VERSION << " — DASH (X11, older-than-v35 -> V36)\n\n"
        << "Usage: " << argv0 << " [--version] [--help] [--selftest]\n"
        << "  --data-dir PATH  root all per-instance state here (default ~/.c2pool);\n"
        << "                   isolates co-located instances\n"
        << "       " << argv0 << " --run [--coin-rpc H:P] [--coin-rpc-auth PATH]\n"
        << "           [--testnet] [--submit-block HEX | --submit-block-file PATH]\n"
        << "           [--listen [HOST:]PORT] [--addnode HOST:PORT]... [--connect HOST:PORT]...\n"
        << "           [--stratum [HOST:]PORT] [--coin-p2p-connect HOST:PORT]...\n"
        << "           [--web-port PORT] [--web-host ADDR] [--dashboard-dir PATH]\n"
        << "           [--embedded-utxo]\n"
        << "           [--give-author PCT] [-f|--fee PCT] [--node-owner-address ADDR]\n"
        << "           [--redistribute pplns|fee|boost|donate]\n"
        << "           [--coin-zmq-hashblock tcp://HOST:PORT]\n"
        << "       " << argv0 << " --mine-block [--coin-rpc H:P] [--coin-rpc-auth PATH]\n"
        << "           [--testnet] [--payout-pubkey-hash HEX] [--max-nonce N]\n\n"
        << "Status: consensus layer live (X11 PoW, subsidy, oracle CoinParams).\n"
        << "        --run stands up the run-loop and ARMS the external-dashd\n"
        << "        submitblock fallback (creds from dash.conf, never on argv).\n"
        << "        --stratum [HOST:]PORT binds the miner-facing Stratum accept-\n"
        << "        loop (DASHWorkSource seam; e.g. --stratum 3333 or\n"
        << "        --stratum 127.0.0.1:3333); omit to disable. Won X11 blocks\n"
        << "        dispatch via the retained dashd-RPC submitblock arm.\n"
        << "        --submit-block[-file] drives ONE real submitblock then exits\n"
        << "        (the won-block-reaches-network leg); embedded P2P relay = S8.\n"
        << "        --coin-p2p-connect HOST:PORT (repeatable) OPT-IN dials the DASH\n"
        << "        coin network directly (version/verack + keep-alive + reconnect);\n"
        << "        absent => no coin P2P client, dashd-RPC fallback path unchanged.\n"
        << "        --coin-zmq-hashblock tcp://HOST:PORT (opt-in) subscribes to dashd's\n"
        << "        ZMQ `hashblock` topic for INSTANT (~0 s) new-tip template refresh +\n"
        << "        clean_jobs notify on the fallback arm; absent/unreachable => the 3 s\n"
        << "        getbestblockhash poll is the active path (requires dashd\n"
        << "        zmqpubhashblock=tcp://HOST:PORT). No consensus effect.\n"
        << "        --web-port PORT (alias --http-port, default 8080) serves the FULL\n"
        << "        c2pool web dashboard + JSON API on --web-host (default 0.0.0.0)\n"
        << "        from --dashboard-dir (default web-static); --web-port 0 disables.\n"
        << "        Live sharechain tip/stats, pool hashrate and per-share difficulty\n"
        << "        are bound to the REAL DASH tracker; local hashrate comes from the\n"
        << "        DASH stratum acceptor. If stratum and web ports collide the web\n"
        << "        port moves to stratum+1.\n"
        << "Consensus: X11 PoW + block identity; 2.5 min spacing; 5 DASH post-V20\n"
        << "        base, -1/14 per 210240; masternode payment 3/4 of block value.\n";
}

// Serialize an 80-byte DASH block header (LE; host is LE on the x86_64 target).
void serialize_header(unsigned char out[80], uint32_t version, const char* prev_hex,
                      const char* merkle_hex, uint32_t time, uint32_t bits, uint32_t nonce)
{
    uint256 prev_block;  prev_block.SetHex(prev_hex);
    uint256 merkle_root; merkle_root.SetHex(merkle_hex);
    size_t off = 0;
    std::memcpy(out + off, &version, 4);             off += 4;
    std::memcpy(out + off, prev_block.data(), 32);   off += 32;
    std::memcpy(out + off, merkle_root.data(), 32);  off += 32;
    std::memcpy(out + off, &time, 4);                off += 4;
    std::memcpy(out + off, &bits, 4);                off += 4;
    std::memcpy(out + off, &nonce, 4);               off += 4;
}

// (1) The oracle CoinParams factory is wired and self-consistent, AND the X11
//     pow_func is reachable through the coin-params seam (the path the work
//     source + block-identity checks consume).
int check_coin_params()
{
    const core::CoinParams main = dash::make_coin_params(/*testnet=*/false);
    const core::CoinParams test = dash::make_coin_params(/*testnet=*/true);

    int fails = 0;
    auto want = [&](bool ok, const char* what) {
        std::cout << "[selftest]   coin_params: " << what << (ok ? " ok\n" : " FAIL\n");
        if (!ok) ++fails;
    };
    want(main.symbol == "DASH",            "symbol == DASH");
    // CoinParams.p2p_port is the SHARECHAIN/pool peer port (dash::PoolConfig SSOT),
    // distinct from the DASH coin-daemon P2P port (9999/19999) wired in slice-1's
    // get_coin_p2p_port. Assert the sharechain SSOT here.
    want(main.p2p_port == 8999,            "mainnet sharechain p2p_port == 8999 (SSOT)");
    want(test.p2p_port == 18999,           "testnet sharechain p2p_port == 18999 (SSOT)");
    want(main.current_share_version == 16, "share_version == 16 (older-than-v35 baseline)");
    want(main.address_version == 76,       "mainnet pubkey addr version == 76 (X...)");
    want(static_cast<bool>(main.pow_func), "pow_func wired");

    // Drive X11 THROUGH the CoinParams pow_func seam against the genesis header.
    if (main.pow_func) {
        unsigned char hdr[80];
        serialize_header(hdr, 1, "0000000000000000000000000000000000000000000000000000000000000000",
            "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
            1390095618u, 0x1e0ffff0u, 28917698u);
        const uint256 pow = main.pow_func(std::span<const unsigned char>(hdr, 80));
        const bool ok = pow.GetHex() == "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6";
        want(ok, "pow_func(genesis) reproduces genesis hash");
    }
    return fails;
}

// (2) X11 PoW KATs: mainnet genesis + a real-node testnet3 block (CI-pinned,
//     test_dash_x11_kat.cpp). Pins BLAKE->...->ECHO end to end via the direct
//     dash::crypto::hash_x11 entry.
int check_x11_kats()
{
    int fails = 0;
    struct Vec { const char* name; uint32_t v; const char* prev; const char* merkle;
                 uint32_t t; uint32_t bits; uint32_t nonce; const char* expect; };
    const Vec vecs[] = {
        { "mainnet-genesis", 1,
          "0000000000000000000000000000000000000000000000000000000000000000",
          "e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
          1390095618u, 0x1e0ffff0u, 28917698u,
          "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6" },
        { "testnet3-#1497944", 536870912u,
          "000000dbbc08ee519459b38b02bb7754b455dd00cd74069a1352f08f0dd986db",
          "0464a4ac5f058a742f6aa42b2b3c7489abde7609b529612bcfa5da34b10bdb1b",
          1781737170u, 0x1e00f256u, 721236u,
          "000000b6a4e5ea1a0854ef83f0028dde5b96cdaacc604decd8b064d0cea38234" },
    };
    for (const auto& vc : vecs) {
        unsigned char hdr[80];
        serialize_header(hdr, vc.v, vc.prev, vc.merkle, vc.t, vc.bits, vc.nonce);
        const uint256 pow = dash::crypto::hash_x11(hdr, sizeof(hdr));
        const bool ok = pow.GetHex() == vc.expect;
        std::cout << "[selftest]   x11 KAT " << vc.name << ": " << pow.GetHex()
                  << (ok ? " ok\n" : " FAIL\n");
        if (!ok) ++fails;
    }
    return fails;
}

// (3) Subsidy: post-V20 block reward + 3/4 MN payment (test_dash_subsidy.cpp,
//     live-validated against dashd getblocktemplate at h=2459985).
int check_subsidy()
{
    int fails = 0;
    const int64_t reward = compute_dash_block_reward_post_v20(2459985);
    const bool r_ok = reward == 177'022'505LL;
    std::cout << "[selftest]   subsidy h=2459985 reward = " << reward
              << (r_ok ? " ok\n" : " FAIL (want 177022505)\n");
    if (!r_ok) ++fails;

    const int64_t mn = compute_dash_mn_payment_post_v20(200'000'000LL);
    const bool mn_ok = mn == 150'000'000LL;
    std::cout << "[selftest]   masternode payment 3/4 of 2.0 DASH = " << mn
              << (mn_ok ? " ok\n" : " FAIL (want 150000000)\n");
    if (!mn_ok) ++fails;
    return fails;
}

int run_selftest()
{
    std::cout << "[selftest] driving live DASH consensus (network-free)\n";
    int fails = 0;
    fails += check_coin_params();
    fails += check_x11_kats();
    fails += check_subsidy();
    if (fails == 0) {
        std::cout << "[selftest] OK — CoinParams + X11 PoW + subsidy all conform to oracle\n";
        return 0;
    }
    std::cout << "[selftest] FAIL — " << fails << " consensus check(s) failed\n";
    return 1;
}

// --run: stand up a real run-loop and ARM the external-dashd submitblock fallback
// arm (rpc.cpp submit_block_hex -- the RPC leg of the won-block dual-path
// broadcaster). The embedded-P2P relay leg is still S8-deferred; this slice lights
// the dashd-RPC sink so a won DASH block CAN reach the network today.
//
// Creds posture (operator self-provision, 2026-06-19): the rpcpassword NEVER
// reaches the process table. --coin-rpc HOST:PORT carries only the endpoint;
// rpcuser/rpcpassword come from dash.conf (default ~/.dashcore/dash.conf, override
// --coin-rpc-auth PATH). No creds (or no port) => the arm stays UNARMED and
// submit_block_hex is never reached -- the run-loop still stands up cleanly.
//
// --submit-block HEX drives ONE real submitblock against the configured dashd and
// reports accept/reject, then exits: the G2 "won-block-reaches-network" evidence
// lever (point it at the VM200/201 dashd). NodeRPC::Send is synchronous with a
// blocking sync_reconnect fallback, so the submit self-connects -- no async race.
// A synthetic-only pass does NOT earn block-viable; the live dashd-reached run is
// the gate.
//
// --coin-p2p-connect HOST:PORT (repeatable) — E1 OPT-IN embedded coin-network
// dial. ABSENT (the released/prod path): no coin P2P client is instantiated,
// NodeCoinState stays default-unpopulated, and get_work() keeps taking the
// retained dashd-RPC fallback — byte-identical run_node behavior. PRESENT:
// a dash::coin::p2p::CoinClient dials the given dashd P2P endpoint(s)
// (version/verack handshake, ping keep-alive, 30s reconnect rotating over
// repeated targets). E1 establishes + maintains the connection only; the
// ingest legs that would populate NodeCoinState are later slices, so the
// fallback arm still serves templates even WITH the flag.
// Fee/donation flags (README design, LTC-path port — see the mint wiring):
//   dev_donation        --give-author (donation_percentage), default 0.1%
//   node_owner_fee      -f/--fee (node_owner_fee), default 0
//   node_owner_address  --node-owner-address (fee destination, P2PKH)
//   redistribute_mode   --redistribute (pplns/fee/boost/donate)
int run_node(bool testnet, const std::string& rpc_endpoint,
             const std::string& rpc_conf_path, const std::string& submit_hex,
             const PeeringConfig& peer,
             const std::string& stratum_host, uint16_t stratum_port,
             const std::string& web_host, uint16_t web_port,
             const std::string& dashboard_dir,
             const std::vector<NetService>& coin_p2p_targets,
             bool embedded_utxo,
             double dev_donation, double node_owner_fee,
             const std::string& node_owner_address,
             const std::string& redistribute_mode,
             bool no_p2p_relay,
             bool embedded_mainnet,
             const std::string& coin_zmq_hashblock)
{
    namespace io = boost::asio;

    dash::coin::RpcConf conf;
    std::string conf_path = rpc_conf_path;
    if (conf_path.empty()) {
        const char* home = std::getenv("HOME");
        conf_path = std::string(home ? home : ".") + "/.dashcore/dash.conf";
    }
    dash::coin::load_rpc_conf(conf_path, conf);
    dash::coin::apply_endpoint_override(rpc_endpoint, conf);
    if (conf.port == 0)
        conf.port = testnet ? 19998 : 9998;   // dashd default RPC ports

    io::io_context ioc;

    // Miner-facing Stratum acceptor handle, declared BEFORE the signal_set so
    // the shutdown callback can stop it (cancel acceptor + close sessions)
    // ahead of ioc.stop(). Populated below once the DASHWorkSource is built.
    std::unique_ptr<core::StratumServer> stratum_server;

    io::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc, &stratum_server](const boost::system::error_code&, int) {
        std::cout << "[run] shutdown signal -- stopping run-loop\n";
        // Stop stratum BEFORE ioc.stop() so the acceptor cancels and live miner
        // sessions close cleanly (their pending async ops unwind on the loop).
        if (stratum_server)
            stratum_server->stop();
        ioc.stop();
    });

    dash::interfaces::Node coin_state;
    std::unique_ptr<dash::coin::NodeRPC> rpc;
    if (conf.armed()) {
        rpc = std::make_unique<dash::coin::NodeRPC>(&ioc, &coin_state, testnet);
        rpc->connect(NetService(conf.host, conf.port), conf.userpass());
        std::cout << "[run] external-daemon submit arm ARMED: NodeRPC -> "
                  << conf.host << ":" << conf.port << " (creds from dash.conf)\n";
    } else {
        std::cout << "[run] external-daemon submit arm UNARMED "
                     "(no dash.conf creds / no port); the embedded coin-P2P relay "
                     "is the primary won-block path (daemonless) when "
                     "--coin-p2p-connect is set.\n";
    }

    // One-shot submit: the G2 won-block-reaches-network evidence path.
    if (!submit_hex.empty()) {
        if (!rpc) {
            std::cout << "[run] --submit-block given but submit arm UNARMED; supply "
                         "dashd creds via dash.conf or --coin-rpc-auth PATH\n";
            return 2;
        }
        std::cout << "[run] submitting block (" << submit_hex.size() / 2
                  << " bytes) to dashd " << conf.host << ":" << conf.port << "...\n";
        const bool accepted = rpc->submit_block_hex(submit_hex, /*ignore_failure=*/false);
        std::cout << "[run] submitblock " << (accepted ? "ACCEPTED" : "REJECTED")
                  << " by dashd\n";
        return accepted ? 0 : 1;
    }

    report_peering(peer, testnet);

    // ── S8-p2p.3: bind the REAL sharechain P2P listener ───────────────────
    // node.cpp reception bodies landed (#656/#657), so dash::Node is now fully
    // linkable and --run opens an actual socket instead of only echoing the
    // topology. Mirrors the dgb::Node bring-up (src/c2pool/main_dgb.cpp).
    dash::SharechainConfig::is_testnet = testnet;

    // Bucket-1 ISOLATION PRIMITIVE: DASH keeps its own net subdir + PREFIX,
    // per-coin AND per-pool-instance, in v36 and v37 — never standardised.
    const std::string net_subdir = testnet ? "dash_testnet" : "dash";
    std::error_code mkdir_ec;
    std::filesystem::create_directories(
        core::filesystem::config_path() / net_subdir, mkdir_ec);  // best effort

    dash::Config config(net_subdir);
    // PREFIX sourced from the frstrtr/p2pool-dash oracle constants (SharechainConfig).
    config.pool()->m_prefix = ParseHexBytes(dash::SharechainConfig::prefix_hex());
    config.m_testnet        = testnet;
    // --addnode (persistent outbound) + --connect (connect-only) both seed the
    // bootstrap addr store the NodeImpl ctor dials via start_outbound_connections().
    for (const auto& a : peer.addnodes)  config.pool()->m_bootstrap_addrs.push_back(a);
    for (const auto& c : peer.connects)  config.pool()->m_bootstrap_addrs.push_back(c);

    dash::Node p2p_node(&ioc, &config);

    // ── Mint slice 3/3: consensus params + sharechain persistence ────────
    // The tracker's CoinParams carry the X11 pow_func + targets every
    // reception/mint verify consumes — MUST be set before any share is
    // processed (an empty pow_func fails every share_init_verify).
    const core::CoinParams mint_params = dash::make_coin_params(testnet);
    p2p_node.tracker().m_coin_params = mint_params;
    // LevelDB sharechain store under the SAME per-net subdir as the rest of
    // the node state (bucket-1 isolation), loading any persisted shares.
    p2p_node.init_storage(net_subdir);

    // --connect (connect-only, no --listen) suppresses the inbound listener,
    // matching report_peering() above.
    const bool connect_only = !peer.connects.empty() && !peer.listen_set;
    const uint16_t bind_port =
        peer.listen_port ? peer.listen_port : dash::SharechainConfig::p2p_port();
    if (!connect_only) {
        // #755: an uncaught bind failure (EADDRINUSE from a lingering prior
        // instance) here threw boost::system::system_error straight through
        // main -> terminate -> Exit 134 core dump. The log made it LOOK like
        // a share-load crash (the throw lands right after the "Loaded N
        // persisted shares" lines). Fail CLEANLY with the actual reason.
        try {
            p2p_node.core::Server::listen(bind_port);
        } catch (const std::exception& e) {
            std::cerr << "[run] FATAL: cannot bind sharechain P2P port "
                      << bind_port << ": " << e.what()
                      << "\n[run] (another c2pool-dash instance running? "
                         "stop it or pass a different --listen port)\n";
            return 1;
        }
        std::cout << "[run] sharechain peer LISTENING on " << peer.listen_host << ":"
                  << bind_port
                  << " — min-proto=" << dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION
                  << " prefix=" << dash::SharechainConfig::prefix_hex() << "\n";
    } else {
        std::cout << "[run] --connect mode: inbound listener suppressed\n";
    }
    // #754 download/outbound slice: ACTIVE outbound dialing from the addr
    // store (--addnode/--connect seeds registered by the NodeImpl ctor) plus
    // the share-download pumps (handshake best-share advert drain here;
    // think()'s desired-set dispatch rides run_think). This is what lets an
    // EMPTY node JOIN an established p2pool-dash chain instead of only
    // serving inbound peers.
    p2p_node.start_outbound_connections();
    if (!config.pool()->m_bootstrap_addrs.empty())
        std::cout << "[run] outbound dialing started ("
                  << config.pool()->m_bootstrap_addrs.size()
                  << " seed peer[s]); share-download leg ARMED\n";


    // ── DASH web dashboard standup (the EXISTING c2pool dashboard) ────────
    // This is main_ltc.cpp's WebServer wiring, reused verbatim where the DASH
    // side has a real source for the datum. No stub metrics are invented: a
    // stat with no live DASH producer in this slice is left UNSET so the
    // dashboard reports its own honest "absent" state rather than a zero that
    // reads as a real measurement.
    //
    // Runs on THIS ioc (WebServer moves HTTP onto its own thread internally),
    // declared AFTER p2p_node so the callbacks it holds never outlive the node.
    //
    // DELIBERATE DIVERGENCE FROM main_ltc.cpp: we do NOT call
    // web_server.set_stratum_port(). On the LTC path that setter makes
    // WebServer::start() construct its OWN core::StratumServer driven by
    // MiningInterface (web_server.cpp:8409 -> start_stratum_server, :8722).
    // c2pool-dash already binds its own core::StratumServer to the
    // DASHWorkSource below; setting it here would double-bind the port and
    // serve X11 miners from the LTC work source. The dashboard is told the
    // miner-facing port through mining_interface->set_worker_port() (display)
    // and fed real stratum rates from the DASH acceptor after it starts.
    std::unique_ptr<core::WebServer> web_server;
    auto enhanced_node = std::make_shared<dash::EnhancedDashNode>(testnet);
    if (web_port != 0) {
        web_server = std::make_unique<core::WebServer>(
            ioc, web_host, web_port, testnet,
            std::static_pointer_cast<core::IMiningNode>(enhanced_node),
            c2pool::address::Blockchain::DASH);

        auto* mi = web_server->get_mining_interface();

        // ── Real, non-negotiable node identity ────────────────────────────
        mi->set_coin_label("DASH");
#ifdef C2POOL_VERSION
        mi->set_pool_version("c2pool/" C2POOL_VERSION);
#endif
        mi->set_worker_port(stratum_port);   // display only (see divergence note)
        mi->set_p2p_port(bind_port);
        // p2pool-compat protocol_version for /local_stats. The core seam
        // documents this exact value for DASH (web_server.hpp:565) and it
        // matches the sharechain SSOT floor.
        mi->set_protocol_version(
            static_cast<int>(dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION));
        // c2pool-dash drives its own work pipeline (DASHWorkSource), so the
        // WebServer's internal refresh_work()/m_cached_template gating would
        // hold the dashboard on the loading page forever. This seam exists in
        // core for exactly this caller (web_server.hpp:557).
        mi->set_dashboard_always_ready(true);
        // Truthful /api/node_topology has_rpc: c2pool-dash reaches its daemon
        // through the external dashd NodeRPC arm (armed above when creds
        // resolved), not an ICoinNode, so tell the dashboard RPC is present.
        mi->set_coin_rpc_available(static_cast<bool>(rpc));

        web_server->set_dashboard_dir(dashboard_dir);
        // Explicitly DISABLE the WebServer's own stratum acceptor. Its ctor
        // defaults stratum_port_ to (web_port + 10) (web_server.cpp:8330/8344/
        // 8358) and start() binds it unconditionally when non-zero
        // (web_server.cpp:8409 -> start_stratum_server, :8719), which on the
        // DASH path silently opened a SECOND miner-facing listener driven by
        // MiningInterface instead of DASHWorkSource (observed on the first
        // smoke run: "StratumServer started on 0.0.0.0:18909" for --web-port
        // 18899). c2pool-dash owns its stratum acceptor; this is the one place
        // the LTC wiring cannot be reused verbatim.
        web_server->set_stratum_port(0);

        // ── REAL sharechain tip (ported from main_ltc.cpp:3860) ───────────
        // std::nullopt is the honest "sharechain still bootstrapping" signal;
        // never a fabricated height.
        {
            dash::Node* node_ptr = &p2p_node;
            mi->set_sharechain_tip_fn(
                [node_ptr]() -> std::optional<core::SharechainTip> {
                    auto guard = node_ptr->read_tracker();
                    if (!guard) {
                        auto snap = node_ptr->get_tracker_snapshot();
                        if (snap.chain_count == 0)
                            return std::nullopt;
                        core::SharechainTip t;
                        t.hash   = "";
                        t.height = snap.verified_count > 0 ? snap.chain_count : -1;
                        t.total  = snap.chain_count;
                        return t;
                    }
                    auto& chain = guard->chain;
                    uint256 best;
                    int32_t best_height = -1;
                    for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                        auto h = chain.get_height(head_hash);
                        if (h > best_height) { best = head_hash; best_height = h; }
                    }
                    if (best.IsNull() && chain.size() == 0)
                        return std::nullopt;
                    core::SharechainTip t;
                    t.hash   = best.IsNull() ? "" : best.GetHex().substr(0, 16);
                    t.height = best_height;
                    t.total  = static_cast<int>(chain.size());
                    return t;
                });
            mi->mark_last_cache_tip_driven();

            // ── REAL sharechain stats ─────────────────────────────────────
            // Straight off the live tracker / published snapshot. Only fields
            // DASH actually computes are emitted — no LTC-shaped placeholders.
            mi->set_sharechain_stats_fn([node_ptr]() -> nlohmann::json {
                auto snap = node_ptr->get_tracker_snapshot();
                nlohmann::json out;
                out["chain_length"]   = static_cast<int>(dash::SharechainConfig::chain_length());
                out["fork_count"]     = snap.fork_count;
                out["verified_count"] = snap.verified_count;
                out["orphan_shares"]  = snap.orphan_shares;
                out["dead_shares"]    = snap.dead_shares;
                auto guard = node_ptr->read_tracker();
                if (!guard) {
                    // Tracker busy — report the snapshot only, and say so.
                    out["chain_height"] = snap.chain_count;
                    out["total_shares"] = snap.chain_count;
                    return out;
                }
                auto& chain = guard->chain;
                uint256 best;
                int32_t best_height = -1;
                for (const auto& [head_hash, tail_hash] : chain.get_heads()) {
                    auto h = chain.get_height(head_hash);
                    if (h > best_height) { best = head_hash; best_height = h; }
                }
                out["chain_tip_hash"] = best.IsNull() ? "" : best.GetHex();
                out["chain_height"]   = best.IsNull() ? 0 : chain.get_height(best);
                out["total_shares"]   = static_cast<int>(chain.size());
                return out;
            });

            // ── REAL pool hashrate (ported from main_ltc.cpp:2865) ────────
            // dash::ShareTracker::get_pool_attempts_per_second is the same
            // p2pool estimator LTC uses (share_tracker.hpp:1353), over DASH's
            // own TARGET_LOOKBEHIND. Returns the last good value on lock
            // contention rather than a spurious 0.
            mi->set_pool_hashrate_fn([node_ptr]() -> double {
                static double s_last_good = 0.0;
                auto best = node_ptr->best_share_hash();
                if (best.IsNull()) return s_last_good;
                auto guard = node_ptr->read_tracker();
                if (!guard) return s_last_good;
                if (!guard->chain.contains(best)) return s_last_good;
                int height = guard->chain.get_height(best);
                if (height < 3) return s_last_good;
                auto lookbehind = std::min(
                    height - 1,
                    static_cast<int>(dash::SharechainConfig::TARGET_LOOKBEHIND));
                auto aps = guard->get_pool_attempts_per_second(best, lookbehind, false);
                double hr = static_cast<double>(aps.GetLow64());
                if (hr > 0) s_last_good = hr;
                return s_last_good;
            });

            // ── REAL best-share hash ──────────────────────────────────────
            web_server->set_best_share_hash_fn(
                [node_ptr]() { return node_ptr->best_share_hash(); });

            // ── REAL pool-peer info (node-status card) ────────────────────
            // /local_stats {peers:{incoming,outgoing}} + the peer table read
            // this. Without it the node-status card reported 0 peers on DASH
            // (the m_node fallback in rest_local_stats never sees the pool
            // p2p peers). Same shape main_ltc.cpp:2830 uses. Display only.
            mi->set_peer_info_fn(
                [&p2p_node]() -> nlohmann::json {
                    return p2p_node.get_peer_info_json();
                });
        }

        // ── REAL per-share difficulty feed (main_ltc.cpp:4213) ────────────
        // Every verified DASH share reports its difficulty + miner through the
        // tracker hook (share_tracker.hpp:374); that is what drives the
        // dashboard's per-miner share tables and the share-difficulty graph.
        // NOT chained: nothing else on the DASH path installs this hook today
        // (verified by grep for m_on_share_difficulty in main_dash.cpp).
        {
            core::WebServer* ws = web_server.get();
            p2p_node.tracker().m_on_share_difficulty =
                [ws](double diff, const std::string& miner) {
                    ws->get_mining_interface()->record_share_difficulty(diff, miner);
                };
        }

        // ── REAL node-owner fee (already parsed from argv above) ──────────
        if (node_owner_fee > 0.0 && !node_owner_address.empty())
            mi->set_node_fee_from_address(node_owner_fee, node_owner_address);

        // Auto-detect the public IP for the "connect to this pool" panel.
        // Non-blocking, detached; identical to the LTC path.
        mi->auto_detect_external_info();

        if (web_server->start()) {
            std::cout << "[run] web dashboard LIVE on http://" << web_host << ":"
                      << web_port << " (dashboard-dir=" << dashboard_dir
                      << ") — real sharechain tip/stats/pool-hashrate + per-share\n"
                         "[run]       difficulty feed bound; stratum rates bind below\n";
        } else {
            std::cout << "[run] web dashboard FAILED to bind " << web_host << ":"
                      << web_port << " — dashboard disabled (mining unaffected)\n";
            web_server.reset();
        }
    } else {
        std::cout << "[run] web dashboard disabled (--web-port 0)\n";
    }

    // ── E1: OPT-IN embedded coin-network P2P dial (--coin-p2p-connect) ────
    // GUARANTEE: with no --coin-p2p-connect on argv, coin_p2p stays null and
    // this block is a no-op — the run path is unchanged and the mining-hotel
    // prod posture (NodeCoinState unpopulated -> dashd-RPC fallback) is
    // untouched. The coin-network wire MAGIC (dashd pchMessageStart: mainnet
    // bf0c6bbd / testnet cee2caff, same constants as the slice-1 launcher
    // dispatch) is DISTINCT from the sharechain PREFIX set above — different
    // layers, never conflated. The client rides the SAME ioc as the
    // sharechain node and stratum; declared after config/coin_state (both of
    // which it borrows), so it is destroyed before them at scope exit.
    std::unique_ptr<dash::coin::p2p::CoinClient<dash::Config>> coin_p2p;
    if (!coin_p2p_targets.empty()) {
        config.coin()->m_testnet = testnet;
        config.coin()->m_p2p.prefix =
            ParseHexBytes(testnet ? "cee2caff" : "bf0c6bbd");
        config.coin()->m_p2p.address = coin_p2p_targets.front();

        coin_p2p = std::make_unique<dash::coin::p2p::CoinClient<dash::Config>>(
            &ioc, &coin_state, &config, "COIN-P2P");
        coin_p2p->connect(coin_p2p_targets);
        std::cout << "[run] coin-network P2P client dialing "
                  << coin_p2p_targets.front().to_string()
                  << (coin_p2p_targets.size() > 1
                          ? " (+" + std::to_string(coin_p2p_targets.size() - 1)
                                + " alternate[s], reconnect rotates)"
                          : "")
                  << " magic=" << (testnet ? "cee2caff" : "bf0c6bbd")
                  << " proto=70230 (E1: dial+handshake+keep-alive only;\n"
                     "[run]       ingest legs are later slices — templates still source from\n"
                     "[run]       the dashd-RPC fallback until NodeCoinState is fed)\n";
    }

    // ── S8 miner-facing Stratum accept-loop standup (run-path caller) ─────
    // This is the production caller the DASHWorkSource 4a/4b skeleton (#706)
    // and the subscribe->notify->submit KATs (#630-634) were built for: a real
    // main constructs the work source and binds a core::StratumServer to it.
    //
    // node_coin_state MUST outlive work_source and stratum_server (DASHWorkSource
    // holds a non-owning const ref to it). It is declared here, in run_node's
    // scope, BEFORE work_source; the explicit stratum_server.reset() after
    // ioc.run() tears the acceptor down while node_coin_state is still alive.
    // Default (unpopulated) bundle: populated()==false, so get_work() takes the
    // retained dashd-fallback arm -- correct + documented for the 4a standup.
    //
    // E2b (#738) UTXO/fee lane: utxo_lane is declared BEFORE node_coin_state
    // deliberately -- attach() hands the lane's UTXOViewCache pointer to the
    // bundle's Mempool (set_utxo), so the lane must outlive the mempool that
    // references it (reverse destruction order at scope exit).
    dash::coin::UtxoLane utxo_lane;
    dash::coin::NodeCoinState node_coin_state;

    // ── E2b (#738): the embedded UTXO/fee lane -- OPT-IN via --embedded-utxo.
    // Transliterated from the PROVEN LTC wiring (main_ltc.cpp ~1750-1801 con-
    // struction + set_utxo + maturity gate; ~2385-2433 block-connect leg; see
    // utxo_lane.hpp). This is the root-cause fix for the fee_known=false ->
    // empty-template defect: Mempool::set_utxo previously had zero dash-arm
    // callers, so every relayed tx stayed unknown-fee and the conservative
    // selection guard (unknown fees EXCLUDED so coinbasevalue never overstates
    // vs dashd's GBT -- guard untouched) returned an empty selection forever.
    //
    // Default (flag absent): NOTHING here is constructed or subscribed -- the
    // dashd-RPC fallback path (mining-hotel prod) is byte-unchanged. With the
    // flag: the lane opens its LevelDB, arms the mempool's fee machinery, and
    // subscribes the coin-state block_connected seam (leg 3, the same event
    // block_connect_ingest.hpp routes to CoinStateMaintainer). The LIVE block
    // feed that FIRES that event is the E1/E2a coin-P2P leg; until it lands
    // the lane sits armed-but-dormant and get_work still routes to the
    // retained dashd fallback (populated()==false).
    std::shared_ptr<EventDisposable> utxo_block_sub;
    if (embedded_utxo) {
        const auto utxo_path = (core::filesystem::config_path()
            / net_subdir / "utxo_leveldb").string();
        if (utxo_lane.open(utxo_path)) {
            utxo_lane.attach(node_coin_state.mempool());
            // Mining gate: coinbase_maturity + reorg buffer = 100 + 6 = 106
            // (DASH_MINING_GATE_DEPTH, utxo_adapter.hpp; mirrors the LTC
            // set_utxo_ready_fn gate) -- embedded templates stay off until
            // the UTXO view is deep enough to exclude immature coinbase
            // spends. The dashd fallback is unaffected.
            node_coin_state.set_utxo_ready_fn(
                [&utxo_lane]() { return utxo_lane.mining_utxo_ready(); });
            utxo_block_sub = coin_state.block_connected.subscribe(
                [&utxo_lane](const dash::interfaces::BlockConnected& bc) {
                    utxo_lane.on_block_connected(bc.block, bc.height);
                });
            std::cout << "[run] embedded UTXO/fee lane ARMED: db=" << utxo_path
                      << " best_height=" << utxo_lane.cache()->get_best_height()
                      << " (mempool fee pricing live; block feed = E1/E2a leg;"
                         " maturity gate " << dash::coin::DASH_MINING_GATE_DEPTH
                      << " blocks)\n";
        } else {
            std::cout << "[run] embedded UTXO/fee lane FAILED to open " << utxo_path
                      << " -- fees stay unknown; dashd-RPC fallback unaffected\n";
        }
    }

    // REQUIRED always-reachable dashd-RPC fallback arm -- the safety +
    // [GBT-XCHECK] cross-check path, NEVER removed (operator standing rule).
    // Wired to NodeRPC::getwork() (dashd getblocktemplate -> rich DashWorkData,
    // the same seam run_mine_block uses). When the RPC arm is UNARMED (no
    // dash.conf creds) it returns the documented empty set-gap default and logs
    // loudly -- never a silent drop. &rpc is lifetime-safe: rpc is declared
    // above work_source in this scope, so work_source (which owns this lambda)
    // is destroyed BEFORE rpc at scope exit.
    std::function<dash::coin::DashWorkData()> dashd_fallback =
        [&rpc]() -> dash::coin::DashWorkData {
            if (!rpc) {
                std::cout << "[DASH-STRATUM-GBT] fallback arm UNARMED (no dashd "
                             "RPC creds) -- serving empty set-gap template\n";
                return dash::coin::DashWorkData{};
            }
            return rpc->getwork();
        };

    // Won-block dispatch (S8): the DUAL-PATH broadcaster, mirroring DGB's
    // make_on_block_found dual-arm structure. A won X11 block reaches the network
    // over BOTH independent arms via dash::coin::broadcast_won_block:
    //   ARM A -- embedded P2P relay (ALWAYS-PRIMARY, daemonless): the E1
    //            CoinClient's submit_block_p2p_raw pushes the packed block onto
    //            the coin P2P net. This closes the daemonless critical path: with
    //            NO local dashd, a won block still reaches the network here alone.
    //   ARM B -- submitblock RPC backup (on-demand): dashd submitblock, fired
    //            whenever a local dashd is armed (also covers a cold/faulted relay).
    // NEVER a silent drop: broadcast_won_block logs LOUDLY and any()==false if the
    // block reaches NEITHER sink, and the stratum surface below echoes that.
    //
    // ARM A binding: the sink is EMPTY (no embedded relay) when no
    // --coin-p2p-connect peer is dialed OR --no-p2p-relay suppresses it (the A/B
    // isolation toggle: prove the RPC backup lands the block ON ITS OWN, not
    // masked by a silent relay). Present: the relay fires from the stratum/compute
    // path, so the peer write is posted onto the io thread (CoinClient is
    // single-thread-confined), mirroring DGB's io::post relay sink.
    dash::coin::P2pRelaySink p2p_relay;
    if (coin_p2p && !no_p2p_relay) {
        p2p_relay =
            [&ioc, &coin_p2p](const std::vector<unsigned char>& block_bytes) -> bool {
                // H1 honest reporting: submit_block_p2p_raw SILENTLY DROPS a won
                // block when the coin-P2P peer is disconnected, and the io::post
                // returns before the send even runs -- so only claim a P2P relay
                // when the peer is actually connected+handshaked at dispatch time.
                // If not, return false so broadcast_won_block relies on ARM B
                // (submitblock RPC) and the NEVER-SILENT-DROP contract holds
                // (loud dispatcher log if neither arm is reachable).
                if (!coin_p2p || !coin_p2p->is_handshake_complete()) {
                    std::cout << "[DASH-STRATUM-BLOCK] embedded P2P relay skipped: "
                                 "coin-P2P peer not connected/handshaked -- relying "
                                 "on submitblock-RPC backup\n";
                    return false;
                }
                io::post(ioc, [&coin_p2p, bytes = block_bytes]() {
                    if (coin_p2p) coin_p2p->submit_block_p2p_raw(bytes);
                });
                return true;
            };
    } else if (no_p2p_relay) {
        std::cout << "[run] --no-p2p-relay: embedded P2P-relay arm SUPPRESSED; "
                     "submitblock-RPC backup remains live (A/B isolation)\n";
    }

    // ARM B binding: EMPTY when no dashd creds are armed (daemonless deployment).
    // ignore_failure=true so a duplicate/already-have after an ARM A accept is
    // success, not failure, and never masks the primary win.
    dash::coin::RpcSubmitSink rpc_submit;
    if (rpc) {
        rpc_submit = [&rpc](const std::string& block_hex) -> bool {
            return rpc->submit_block_hex(block_hex, /*ignore_failure=*/true);
        };
    }

    dash::stratum::DASHWorkSource::SubmitBlockFn stratum_submit_fn =
        [p2p_relay, rpc_submit](const std::vector<unsigned char>& block_bytes,
                                uint32_t height) -> bool {
            const std::string block_hex = HexStr(block_bytes);
            std::cout << "[DASH-STRATUM-BLOCK] won block height=" << height
                      << " bytes=" << block_bytes.size()
                      << " -- dispatching dual-path (embedded P2P primary + "
                         "submitblock-RPC backup)\n";
            const auto bcast = dash::coin::broadcast_won_block(
                p2p_relay, rpc_submit, block_bytes, block_hex);
            if (!bcast.any()) {
                std::cout << "[DASH-STRATUM-BLOCK] reached NEITHER sink "
                             "(no embedded P2P peer AND no dashd RPC creds) -- "
                             "won block NOT broadcast\n";
                return false;
            }
            std::cout << "[DASH-STRATUM-BLOCK] relayed: p2p="
                      << (bcast.p2p_sent ? "sent" : "off")
                      << " rpc=" << (bcast.rpc_ok ? "ok" : "off")
                      << " landed_first=" << bcast.landed_first << "\n";
            return true;
        };

    // DASHWorkSource holds a non-owning ref to node_coin_state (declared above,
    // same scope). The StratumServer co-owns the work source via shared_ptr.
    auto work_source = std::make_shared<dash::stratum::DASHWorkSource>(
        node_coin_state, std::move(dashd_fallback), std::move(stratum_submit_fn),
        core::stratum::StratumConfig{}, testnet);
    // Gate-lift (v0.2.4): allow the daemonless embedded arm on mainnet when the
    // operator opts in via --embedded-mainnet. The CbTx is proven byte-identical
    // to real dashd (both merkle roots reproduced from the mnlistdiff wire); the
    // SML+quorum freshness + superblock viability gates keep it fail-safe.
    work_source->set_embedded_mainnet(embedded_mainnet);
    // Reward-safety backstop: when a dashd fallback is configured, cross-check
    // the embedded creditPool against dashd's GBT before serving (catches any
    // seed bug the daemonless self-checks miss). Enabled alongside the embedded
    // arm; pure-daemonless deployments (no dashd) leave it off and rely on the
    // independent seed-height gate.
    work_source->set_gbt_xcheck(testnet || embedded_mainnet);

    // ── Mint slice 3/3: run-loop share minting wiring ─────────────────────
    // ShareAccept -> build_mint_share -> tracker insert -> peer broadcast.
    // All callbacks below run on THIS ioc (StratumServer shares it), so the
    // node's IO-thread invariants (try_to_lock tracker access) hold.
    {
        dash::Node* node_ptr = &p2p_node;
        auto mint_registry = std::make_shared<dash::mint::FrozenJobRegistry>();

        // ── Fee policy (README flags, LTC sharechain-lane port) ───────────
        // --give-author -> the share's donation field (oracle dev-fee channel;
        // the donation output itself is ALWAYS emitted by the gentx, even at
        // 0% — the dust-marker semantic is preserved by construction).
        // --fee/--node-owner-address -> probabilistic identity substitution
        // (consensus-safe). --redistribute -> broken-credential policy.
        dash::mint::MintFeePolicy fee_policy;
        fee_policy.donation_u16       = dash::mint::donation_percent_to_u16(dev_donation);
        fee_policy.node_owner_fee_pct = node_owner_fee;
        fee_policy.redistribute =
            dash::mint::MintFeePolicy::parse_redistribute(redistribute_mode);
        if (!node_owner_address.empty()) {
            auto owner_script = core::address_to_script(node_owner_address);
            if (dash::stratum::pubkey_hash_from_p2pkh(owner_script)) {
                fee_policy.node_owner_script = std::move(owner_script);
            } else {
                std::cout << "[run] --node-owner-address is not a P2PKH DASH "
                             "address -- node-owner fee/redistribute-to-owner "
                             "DISABLED (shares are pubkey_hash-keyed)\n";
            }
        }
        if (fee_policy.node_owner_fee_pct > 0.0 && fee_policy.node_owner_script.empty())
            std::cout << "[run] --fee " << node_owner_fee << " set but no usable "
                         "--node-owner-address -- node-owner fee DISABLED\n";
        std::cout << "[run] fee policy: give-author=" << dev_donation
                  << "% (donation_u16=" << fee_policy.donation_u16
                  << ") node-owner-fee=" << node_owner_fee
                  << "% (owner=" << (fee_policy.node_owner_script.empty() ? "unset" : node_owner_address)
                  << ") redistribute=" << redistribute_mode << "\n";

        // Best-share election: prev_share_hash for new jobs = the live tip
        // think() elected (verified-work-first; ZERO with peers-but-no-
        // verified-chain so we never mint on an unverified foreign chain).
        work_source->set_best_share_hash_fn(
            [node_ptr]() -> uint256 { return node_ptr->best_share_hash(); });

        // ── REAL best-share feed for the dashboard "Best Share" card ──────
        // Every ACCEPTED stratum submit reports the actual PoW difficulty of
        // the found hash (target_to_difficulty(pow_hash)) + miner + pow-hash.
        // record_share_difficulty tracks the pool-wide/session/round max WITH
        // the hash + timestamp; /best_share + /local_stats render it. This is
        // the PRIMARY best-share feed on the DASH solo path — the tracker's
        // verified-share m_on_share_difficulty hook (wired above) almost never
        // fires here because solo shares seldom mint onto the sharechain, so
        // without this the 🎯 Best Share card sat empty. Display only; the
        // callback touches no share/target/payout logic (consensus-neutral).
        if (web_server) {
            core::WebServer* ws = web_server.get();
            work_source->set_on_share_difficulty_fn(
                [ws](double diff, const std::string& miner, const uint256& pow_hash) {
                    ws->get_mining_interface()->record_share_difficulty(
                        diff, miner, pow_hash.GetHex());
                });

            // ── Recent-blocks feed: DASH block wins into the history card ──
            // Every dispatched block solution records to /recent_blocks with
            // the height, X11 block hash (== pow_hash for DASH), miner, and the
            // net difficulty at find time. Without this DASH block wins never
            // appeared on the recent-blocks card (main_ltc.cpp:2970 parity).
            // Display only; the callback runs after dispatch, never gates it.
            work_source->set_on_found_block_fn(
                [ws](uint32_t height, const uint256& block_hash,
                     const std::string& miner, bool reached_network) {
                    auto* mi = ws->get_mining_interface();
                    mi->record_found_block(
                        height, block_hash,
                        static_cast<uint64_t>(std::time(nullptr)),
                        "DASH", miner, block_hash.GetHex(),
                        mi->get_network_difficulty(),
                        /*share_difficulty=*/0.0,
                        /*pool_hashrate=*/0.0,
                        /*subsidy=*/0);
                    if (!reached_network)
                        LOG_WARNING << "[DASH] recorded found block height="
                                    << height << " that reached NO network sink";
                });
        }

        // Producer job: the stratum coinbase IS the producer share gentx
        // (byte-parity with the mint-time rebuild by construction). The
        // frozen per-job context is registered under its ref_hash.
        //
        // Per-(prev, payout, template) CACHE: sessions re-notify every ~1 s;
        // a fresh random share_nonce per notify would make every job's bytes
        // unique — defeating the session's shared-payload reuse AND churning
        // the frozen-job registry past its eviction window. Rebuilding is
        // deterministic given the same inputs, so within a 30 s TTL (the
        // template staleness window) the SAME job is served.
        struct ProducerJobCacheEntry {
            dash::mint::ProducerJobBuild build;
            uint256 coin_tip;
            uint32_t height{0};
            std::chrono::steady_clock::time_point at;
        };
        using ProducerJobKey = std::pair<uint256, std::vector<unsigned char>>;
        auto job_cache = std::make_shared<
            std::map<ProducerJobKey, ProducerJobCacheEntry>>();

        work_source->set_producer_job_fn(
            [node_ptr, mint_params, mint_registry, job_cache, fee_policy](
                const uint256& prev_share_hash,
                const std::vector<unsigned char>& payout_script,
                const dash::coin::DashWorkData& wd)
                -> std::optional<dash::stratum::DASHWorkSource::ProducerJob>
            {
                const auto now = std::chrono::steady_clock::now();
                const ProducerJobKey key{prev_share_hash, payout_script};

                // Cache hit: same sharechain tip, same coin template, fresh.
                if (auto it = job_cache->find(key); it != job_cache->end()) {
                    auto& e = it->second;
                    if (e.coin_tip == wd.m_previous_block && e.height == wd.m_height
                        && now - e.at < std::chrono::seconds(30)) {
                        mint_registry->put(e.build.job.ref_hash, e.build.frozen);
                        return e.build.job;
                    }
                    job_cache->erase(it);
                }
                // Lazy TTL sweep keeps the cache bounded across miner churn.
                if (job_cache->size() > 128) {
                    for (auto it = job_cache->begin(); it != job_cache->end();) {
                        if (now - it->second.at > std::chrono::seconds(60))
                            it = job_cache->erase(it);
                        else
                            ++it;
                    }
                }

                auto guard = node_ptr->read_tracker();
                if (!guard)
                    return std::nullopt;   // compute thread busy — degrade this job

                static std::mt19937 nonce_rng{std::random_device{}()};
                const uint32_t share_nonce = static_cast<uint32_t>(nonce_rng());

                // Fee policy: one roll per job build (p2pool's per-get_work
                // fee roll); resolve the share identity + donation.
                const uint32_t roll_x100 = static_cast<uint32_t>(nonce_rng() % 10000u);
                auto identity = dash::mint::resolve_mint_identity(
                    fee_policy, payout_script, roll_x100);
                if (!identity) {
                    static int redist_log = 0;
                    if (redist_log++ % 50 == 0)
                        LOG_WARNING << "[MINT] no usable share identity for this "
                                       "miner (non-P2PKH credentials; redistribute="
                                    << "policy declined) -- job degrades to the "
                                       "non-producer coinbase";
                    return std::nullopt;
                }
                if (identity->substituted) {
                    static int fee_log = 0;
                    if (fee_log++ % 50 == 0)
                        LOG_INFO << "[MINT] share identity substituted by fee/"
                                    "redistribute policy (node-owner)";
                }

                auto built = dash::mint::build_producer_job(
                    guard->chain, mint_params, prev_share_hash,
                    identity->payout_script, wd,
                    static_cast<uint32_t>(std::time(nullptr)), share_nonce,
                    identity->donation_u16, /*pool_tag=*/"c2pool");
                if (!built)
                    return std::nullopt;

                mint_registry->put(built->job.ref_hash, built->frozen);
                // Template txs -> m_known_txs so share relay can serve
                // remember_tx for the share's new_transaction_hashes.
                node_ptr->register_template_txs(wd.m_txs, wd.m_tx_hashes);

                auto job = built->job;
                (*job_cache)[key] = ProducerJobCacheEntry{
                    std::move(*built), wd.m_previous_block, wd.m_height, now};
                return job;
            });

        // The mint itself: registry lookup by the coinbase's OP_RETURN
        // commitment, deterministic producer rebuild (X11 identity gate +
        // pow<=target ban-safety gate inside), tracker insert + broadcast.
        work_source->set_mint_share_fn(
            [node_ptr, mint_params, mint_registry](
                const dash::stratum::DASHWorkSource::MintShareInputs& in) -> uint256
            {
                if (in.ref_hash.IsNull()) {
                    LOG_WARNING << "[MINT] solve on a non-producer job (zero ref) — "
                                   "no sharechain credit (fail-closed)";
                    return uint256();
                }
                auto frozen = mint_registry->get(in.ref_hash);
                if (!frozen) {
                    LOG_WARNING << "[MINT] no frozen job for ref="
                                << in.ref_hash.GetHex().substr(0, 16)
                                << " (evicted/foreign) — declined";
                    return uint256();
                }

                std::optional<dash::producer::BuiltShare> built;
                {
                    auto guard = node_ptr->read_tracker();
                    if (!guard) {
                        LOG_WARNING << "[MINT] tracker busy — solve declined "
                                       "(retry on next share)";
                        return uint256();
                    }
                    built = dash::mint::mint_from_inputs(
                        guard->chain, mint_params, in, *frozen);
                }
                if (!built) {
                    LOG_WARNING << "[MINT] producer rebuild declined the solve "
                                   "(identity/target gate) — NOT minted";
                    return uint256();
                }

                dash::ShareType share;
                share = new dash::DashShare(std::move(built->share));
                const uint256 minted = node_ptr->add_local_share(share);
                if (minted.IsNull()) {
                    // Not inserted (busy/duplicate) — reclaim the allocation.
                    share.invoke([](auto* obj) { delete obj; });
                    return uint256();
                }
                LOG_INFO << "[MINT] share " << minted.GetHex().substr(0, 16)
                         << " minted onto the sharechain (prev="
                         << in.prev_share_hash.GetHex().substr(0, 16) << ")";
                return minted;
            });

        // PPLNS fallback-coinbase weights (non-producer path): oracle-window
        // tracker walk so even a degraded job pays the live PPLNS window.
        // block_bits from the prev share's own header (same difficulty epoch);
        // ref stays ZERO — a solve on this path can never mint (fail-closed).
        work_source->set_pplns_weights_fn(
            [node_ptr, mint_params](const uint256& prev_share_hash)
                -> std::optional<dash::stratum::DASHWorkSource::PplnsWeights>
            {
                auto guard = node_ptr->read_tracker();
                if (!guard)
                    return std::nullopt;
                if (prev_share_hash.IsNull() || !guard->chain.contains(prev_share_hash))
                    return std::nullopt;
                uint32_t block_bits = 0;
                guard->chain.get_share(prev_share_hash).invoke([&](auto* obj) {
                    block_bits = obj->m_min_header.m_bits;
                });
                return dash::mint::pplns_weights_for(
                    guard->chain, mint_params, prev_share_hash, block_bits);
            });

        // New best share -> stratum work refresh (sessions re-notify) AND a
        // debounced dashboard work refresh, so /api tip + graphs move on the
        // real tip-change event (main_ltc.cpp:2768) rather than a poll timer.
        {
            core::WebServer* web = web_server.get();   // may be null (dashboard off)
            p2p_node.set_on_best_share_changed(
                [ws = work_source.get(), web]() {
                    ws->bump_work_generation();
                    if (web) web->trigger_work_refresh_debounced();
                });
        }

        std::cout << "[run] mint wiring LIVE: ShareAccept -> producer rebuild -> "
                     "tracker insert + broadcast (legacy v16 shares; PPLNS window "
                     "walk bound)\n";
    }

    // Stale-payee fix (defect 3): bind the CoindRPC reconnect-churn observer.
    // A "CoindRPC reconnecting" window means any cached template — and the
    // masternode payee frozen inside it — may predate the reconnect; the
    // observer drops the DASHWorkSource template cache and bumps the work
    // generation so every stratum session re-pulls FRESH work instead of
    // mining (and later submitting) a payee from before the churn. weak_ptr:
    // rpc outlives work_source in this scope (declared earlier), so the
    // callback must not extend or assume the work source's lifetime.
    //
    // This is the conservative DEFAULT (covers the embedded arm, and the
    // fallback arm before its tip poll is armed): every reconnect invalidates
    // unconditionally. On the fallback arm the tip-poll block below OVERRIDES
    // this with a tip-aware version that skips the invalidate when the tip is
    // provably unchanged (#751 idle-reconnect churn fix) -- see there.
    if (rpc) {
        std::weak_ptr<dash::stratum::DASHWorkSource> ws_weak = work_source;
        rpc->set_on_reconnect([ws_weak]() {
            if (auto ws = ws_weak.lock())
                ws->invalidate_template_cache("CoindRPC reconnect churn");
        });
    }

    if (stratum_port != 0) {
        stratum_server = std::make_unique<core::StratumServer>(
            ioc, stratum_host, stratum_port, work_source);
        if (stratum_server->start()) {
            std::cout << "[run] stratum listening on " << stratum_host << ":"
                      << stratum_port
                      << " (work source: DASHWorkSource 4c/4d -- X11 template"
                      << " serving + submit scoring; templates source from the"
                      << " embedded coin-state when seeded, else the retained"
                      << " dashd-RPC GBT fallback)\n";
            // ── REAL local (stratum) hashrate into the dashboard ───────
            // Same two callbacks WebServer wires for its own acceptor
            // (web_server.cpp:8730-8740), but sourced from the DASH
            // StratumServer that actually serves X11 miners. This is what
            // makes /local_stats report a truthful local hashrate + DOA
            // window instead of nothing.
            if (web_server) {
                auto* ss = stratum_server.get();
                auto* mi = web_server->get_mining_interface();
                mi->set_stratum_hashrate_fn(
                    [ss]() -> double { return ss->get_total_hashrate(); });
                mi->set_stratum_rate_stats_fn(
                    [ss]() -> core::MiningInterface::RateStats {
                        auto s = ss->get_rate_stats();
                        return {s.hashrate, s.effective_dt, s.total_datums,
                                s.dead_datums};
                    });
                // ── REAL per-worker registry into the dashboard ────────────
                // The DASH stratum acceptor's StratumSessions register/update
                // their per-connection hashrate + share/difficulty state into
                // DASHWorkSource (NOT the dashboard's own MiningInterface,
                // whose acceptor is disabled). Feed that live registry so
                // /local_stats + /stratum_stats report the true per-miner
                // hashrates, non-empty miner maps, and a correct connected-
                // miner count (no false "pool is idle"). Display only.
                mi->set_stratum_workers_fn(
                    [wsrc = work_source.get()]()
                        -> std::map<std::string, core::MiningInterface::WorkerInfo> {
                        return wsrc->get_stratum_workers();
                    });
                // ── REAL block value + network difficulty into the dashboard ─
                // c2pool-dash drives its own work pipeline, so WebServer's
                // m_cached_template stays empty. Expose the last-sourced dashd
                // GBT template so block_value / masternode payment split /
                // attempts_to_block read the live values. Non-fetching peek;
                // display only, never drives coinbase or consensus.
                mi->set_coin_work_fn(
                    [wsrc = work_source.get()]()
                        -> core::MiningInterface::CoinWorkInfo {
                        core::MiningInterface::CoinWorkInfo info;
                        auto t = wsrc->peek_template();
                        if (!t) return info;
                        info.valid              = true;
                        info.coinbase_value_sat = t->m_coinbase_value;
                        info.payment_amount_sat = t->m_payment_amount;
                        info.height             = t->m_height;
                        if (t->m_bits != 0)
                            info.network_difficulty = chain::target_to_difficulty(
                                dash::coin::target_from_nbits(t->m_bits));
                        return info;
                    });
                std::cout << "[run] dashboard local-hashrate + per-worker "
                             "registry + block-value/net-diff bound to the DASH "
                             "stratum acceptor\n";
            }
        } else {
            std::cout << "[run] stratum FAILED to bind " << stratum_host << ":"
                      << stratum_port << " -- stratum disabled\n";
            stratum_server.reset();
        }
    } else {
        std::cout << "[run] stratum disabled (no --stratum flag)\n";
    }

    // ── Think loop: initial election + 15 s keep-fresh tick ───────────────
    // Share arrivals trigger run_think() themselves (add_verified_shares);
    // the periodic tick covers quiet stretches (retries deferred broadcasts,
    // re-elects after verify continuations) and now runs clean_tracker()
    // (btc/ltc parity: think + stale-head eat + drop-tails beyond
    // 2*CHAIN_LENGTH+10 + LevelDB prune — without it the raw chain grows
    // unbounded). clean_tracker runs think inline, so the tick still keeps
    // the election fresh; it no-ops (defers) when a think is in flight.
    boost::asio::post(ioc, [&p2p_node]() { p2p_node.run_think(); });
    auto think_timer = std::make_shared<io::steady_timer>(ioc);
    auto think_tick =
        std::make_shared<std::function<void(const boost::system::error_code&)>>();
    *think_tick = [&p2p_node, think_timer, think_tick](
                      const boost::system::error_code& ec) {
        if (ec) return;   // cancelled at shutdown
        p2p_node.clean_tracker();
        think_timer->expires_after(std::chrono::seconds(15));
        think_timer->async_wait(*think_tick);
    };
    think_timer->expires_after(std::chrono::seconds(15));
    think_timer->async_wait(*think_tick);

    // ── E2a: wire the LIVE coin-P2P feed into the maintainer -> populate ──
    // GUARANTEE: this whole block is gated on `coin_p2p` (i.e. --coin-p2p-connect
    // was supplied). With NO flag, coin_p2p is null, none of the header chain /
    // maintainer / ingest legs below are constructed, and run_node is byte-
    // identical to the released dashd-fallback prod path. The subscriptions are
    // REGISTERED here (before ioc.run()); no wire event can fire until the loop
    // below pumps the socket I/O, so wiring after the E1 connect() is race-free.
    //
    // These locals are declared LAST in run_node's scope so they are destroyed
    // FIRST at return (after ioc.run() has stopped and no further events fire):
    // subscription handles -> maintainer -> header_chain, all torn down before
    // node_coin_state / coin_state (declared earlier) they reference.
    std::unique_ptr<dash::coin::HeaderChain> header_chain;
    std::unique_ptr<dash::coin::CoinStateMaintainer> maintainer;
    std::vector<std::shared_ptr<EventDisposable>> coin_feed_subs;
    if (coin_p2p) {
        const auto dash_params = testnet
            ? dash::coin::make_dash_chain_params_testnet()
            : dash::coin::make_dash_chain_params_mainnet();
        const auto hdr_db = (core::filesystem::config_path()
            / net_subdir / "dash_headers").string();
        header_chain = std::make_unique<dash::coin::HeaderChain>(dash_params, hdr_db);
        header_chain->init();

        maintainer = std::make_unique<dash::coin::CoinStateMaintainer>(node_coin_state);

        // Coin address versions for the embedded coinbase-payee encoding (the
        // TipAdvance carries them so build_embedded_workdata can encode the MN
        // payee); sourced from the oracle CoinParams, testnet/mainnet-aware.
        const core::CoinParams coin_params = dash::make_coin_params(testnet);
        const uint8_t addr_ver  = coin_params.address_version;
        const uint8_t p2sh_ver  = coin_params.address_p2sh_version;

        // Leg 1 (mempool relay): new_tx -> maintainer.on_mempool_tx. Optional
        // for viability; enriches the assembled template.
        coin_feed_subs.push_back(
            c2pool::dash::wire_mempool_ingest(coin_state, *maintainer));
        // Leg 2 (tip advance): Node::new_tip -> maintainer.on_new_tip. The
        // new_tip event is FIRED by the tip-changed callback below (off the
        // header chain), NOT the raw wire.
        coin_feed_subs.push_back(
            c2pool::dash::wire_tip_ingest(coin_state, *maintainer));
        // Leg 3 (block connect): Node::block_connected -> maintainer
        // .on_block_connected (MnStateMachine::apply_block, folds DIP3 special
        // txs into the DMN set). block_connected is fired by the live-feed
        // bridge (full_block -> height lookup). The E2b UTXO lane is ALSO
        // subscribed to the same event (its connect_block + fee recompute).
        coin_feed_subs.push_back(
            c2pool::dash::wire_block_connect_ingest(coin_state, *maintainer));
        // Leg 4 (MN-set RESYNC): Node::mn_list_update -> maintainer
        // .on_mn_list_update. Dash's P2P Simplified MN List omits scriptPayout,
        // so the payout-bearing feed for this leg is the E2c RPC seed below
        // (startup baseline) + leg 3's apply_block folding special txs on top.
        coin_feed_subs.push_back(
            c2pool::dash::wire_mn_list_ingest(coin_state, *maintainer));

        // Leg 5 (SML axis — DAEMONLESS CCbTx, v0.2.4 critical path): the raw
        // mnlistdiff off the live coin-P2P feed advances the SML
        // (merkleRootMNList) + QuorumManager (merkleRootQuorums) + seeds
        // bestCL*/creditPool via CoinStateMaintainer::on_mnlistdiff. This is
        // what makes the embedded coinbase's DIP-0004 type-5 payload
        // MAINNET-VALID (review finding C1). Distinct from leg 4 (the RPC-seeded PAYEE
        // axis). The getmnlistd request driver below primes it.
        coin_feed_subs.push_back(
            c2pool::dash::wire_mnlistdiff_ingest(coin_state, *maintainer));

        // getmnlistd base tracker: the block hash the local SML is current at.
        // Cold start = ZERO (full snapshot). Each accepted mnlistdiff advances
        // it to diff.blockHash so the NEXT request is an incremental diff off
        // the last synced point (avoids re-pulling the full ~450 kB list).
        auto sml_base = std::make_shared<uint256>(uint256::ZERO);
        coin_feed_subs.push_back(
            coin_state.new_mnlistdiff.subscribe(
                [sml_base](const dash::coin::vendor::CSimplifiedMNListDiff& d) {
                    *sml_base = d.blockHash;
                }));

        // review finding H3: the embedded arm must NOT serve a template without a valid
        // CCbTx (that block is consensus-invalid on mainnet). Gate embedded
        // viability on an applied SML — until the first mnlistdiff lands, and
        // after any reorg wipe, get_work stays on the retained dashd fallback.
        node_coin_state.set_require_sml(true);

        // Superblock guard: on a Dash superblock height the coinbase must pay the
        // governance/treasury outputs, which the embedded template does not
        // compute. Refuse the embedded arm on those heights and let the reward-
        // safe dashd fallback serve the correct superblock template. Cycle is
        // network-specific (mainnet 16616, testnet 24).
        {
            const int sb_cycle = testnet
                ? dash::coin::DASH_SUPERBLOCK_CYCLE_TESTNET
                : dash::coin::DASH_SUPERBLOCK_CYCLE_MAINNET;
            node_coin_state.set_is_superblock_fn(
                [sb_cycle](uint32_t next_height) {
                    return dash::coin::is_superblock_height(next_height, sb_cycle);
                });
        }

        // review PR #780 BLOCKER-1 (CRITICAL): refuse the embedded arm on DKG
        // commitment-window heights. There the block MUST carry mandatory type-6
        // quorum-commitment txs (which the C-3 filter strips) and merkleRootQuorums
        // must include them (which the mnlistdiff-fed set omits) — the embedded
        // arm would produce a bad-qc-missing / wrong-root block. Fail closed to
        // the reward-safe dashd fallback at those heights (it builds the qc block).
        node_coin_state.set_commitment_window_fn(
            [](uint32_t next_height) {
                return dash::coin::is_dkg_commitment_window(next_height);
            });

        // review PR #780 BLOCKER-2 (HIGH): refuse the embedded arm on a stale or
        // absent bestCL (dashcore CheckCbTxBestChainlock rejects null/older CL).
        // Only meaningful when the embedded arm actually serves (testnet or
        // --embedded-mainnet); harmless otherwise (the arm is off, work_source
        // never consults viability).
        node_coin_state.set_require_fresh_bestcl(testnet || embedded_mainnet);

        // SOAK FIX (bad-cbtx-assetlocked-amount): the DIP-0027 credit-pool seed
        // rides a separate on_mnlistdiff step and can lag one block while the SML
        // hash is already at the tip; the accrual then commits a stale
        // creditPoolBalance. Refuse the embedded arm unless the credit-pool seed
        // is current AT the tip, same discipline as the SML axis.
        node_coin_state.set_require_fresh_credit_pool(testnet || embedded_mainnet);

        // H-6: SML/quorum apply and bestCL adoption move ASYNCHRONOUSLY to the
        // header tip. When they advance (catching the SML up to a moved tip, or
        // adopting a fresher ChainLock) the served template changes but no tip
        // signal fires — so drive the same re-issue path the tip-change uses.
        // A reorg wipe also routes here so miners drop the orphaned-branch
        // template immediately. (weak_ptr so a late event can't resurrect a
        // torn-down work source during shutdown.)
        {
            std::weak_ptr<dash::stratum::DASHWorkSource> ws_dirty = work_source;
            maintainer->set_on_state_dirty(
                [ws_dirty, &stratum_server]() {
                    if (auto ws = ws_dirty.lock()) ws->bump_work_generation();
                    if (stratum_server) stratum_server->notify_all();
                });
        }

        // review PR #780 H-1 heal: on a malformed quorum tail the maintainer
        // wipes the base-relative SML/quorum state and asks for a FULL re-sync.
        // Reset the sml_base request tracker to ZERO and re-request a full
        // snapshot at the current tip, so the next mnlistdiff is base=ZERO (the
        // skipped delta cannot be silently ridden over by an incremental).
        maintainer->set_on_full_resync(
            [sml_base, cp = coin_p2p.get(), hc = header_chain.get()]() {
                *sml_base = uint256::ZERO;
                auto tip_entry = hc->tip();
                const uint256 tip = tip_entry ? tip_entry->hash : uint256::ZERO;
                if (cp) cp->send_getmnlistd(uint256::ZERO, tip);
            });

        // Leg 6 (ChainLock sig): Node::new_chainlock_sig -> maintainer
        // .on_new_chainlock. The clsig message carries the recovered 96-byte
        // threshold sig (new_chainlock above drops it); the maintainer adopts
        // the freshest observed ChainLock height+sig as the CCbTx bestCL*.
        coin_feed_subs.push_back(
            coin_state.new_chainlock_sig.subscribe(
                [m = maintainer.get()]
                (const dash::interfaces::Node::ChainLockSigEvent& c) {
                    m->on_new_chainlock(c.height, c.sig);
                }));

        // Bridge: new_headers -> HeaderChain::add_headers (X11 PoW + DGW
        // validated). The tip authority for the embedded template.
        coin_feed_subs.push_back(
            dash::coin::wire_header_ingest(coin_state, *header_chain));
        // Bridge: full_block -> (X11 hash -> header-chain height) ->
        // Node::block_connected, driving leg 3 + the E2b UTXO lane.
        coin_feed_subs.push_back(
            dash::coin::wire_full_block_ingest(coin_state, *header_chain));

        // new_block(inv hash) -> pull the headers THEN the full block from the
        // peer. The getheaders-first ordering is the steady-state tip-follow
        // fix (E2c): dashd announces new blocks via inv (we never negotiate
        // sendheaders), so without an explicit getheaders here the header
        // chain stalls at the initial-sync tip forever and EVERY live block
        // hits wire_full_block_ingest's not-in-header-chain deferral — no
        // block_connected, no apply_block, no UTXO bootstrap trigger. Same
        // single ordered TCP stream to the same peer, so the headers response
        // (tip advance, header now known) lands BEFORE the block does and the
        // connect proceeds. Mirrors the PROVEN LTC new-block handler
        // (main_ltc.cpp ~2133: request_headers off the locator + block pull).
        coin_feed_subs.push_back(
            coin_state.new_block.subscribe(
                [cp = coin_p2p.get(), hc = header_chain.get()](const uint256& hash) {
                    cp->send_getheaders(70230, hc->get_locator(), uint256::ZERO);
                    cp->request_block(hash);
                }));

        // new_chainlock -> record into the best-chainlock tracker (finalization
        // signal the block-find submit path can consult).
        coin_feed_subs.push_back(
            coin_state.new_chainlock.subscribe(
                [&coin_state](const std::pair<uint256, int32_t>& cl) {
                    coin_state.chainlocked_blocks[cl.first] = cl.second;
                }));

        // Header self-propel: after each accepted headers batch, request the
        // next batch off the updated locator so the chain catches up to tip.
        // Registered AFTER wire_header_ingest so add_headers runs first and the
        // locator reflects the new tip.
        coin_feed_subs.push_back(
            coin_state.new_headers.subscribe(
                [cp = coin_p2p.get(), hc = header_chain.get()]
                (const std::vector<dash::coin::BlockHeaderType>& batch) {
                    if (batch.empty()) return;
                    cp->send_getheaders(70230, hc->get_locator(), uint256::ZERO);
                }));

        // Tip-changed callback: (a) fire Node::new_tip (leg 2 arms tip-readiness
        // -> the maintainer republishes once the MN list is ALSO seeded ->
        // populated() flips), and (b) #739 idle-notify: bump work-generation +
        // notify sessions on a real tip change so idle miners are not wedged on
        // stale work between job-push timer firings (event-driven notify).
        header_chain->set_on_tip_changed(
            [&coin_state, &stratum_server, hc = header_chain.get(),
             addr_ver, p2sh_ver, ws = work_source.get(),
             cp = coin_p2p.get(), sml_base, m = maintainer.get()]
            (const uint256&, uint32_t, const uint256& new_tip, uint32_t new_height,
             bool was_reorg) {
                auto ta = dash::coin::tip_advance_from_chain(
                    *hc, addr_ver, p2sh_ver);
                if (ta) {
                    coin_state.new_tip.happened(*ta);
                    LOG_INFO << "[EMB-DASH] tip advanced h=" << new_height
                             << " " << new_tip.GetHex().substr(0, 16)
                             << " bits=0x" << std::hex << ta->bits_for_next << std::dec
                             << " -> new_tip fired (maintainer arm)";
                }
                // C-2 reorg wiring: a branch switch invalidates the incremental
                // SML (its applied diffs were relative to the orphaned branch).
                // Wipe + drop have_sml so the embedded arm falls back to dashd,
                // reset the sync base to ZERO, and re-request a FULL cold-start
                // snapshot at the new tip (an incremental diff off the stale base
                // would be rejected by the base-continuity guard anyway).
                if (was_reorg && m) {
                    LOG_WARNING << "[SML] reorg to h=" << new_height
                                << " -> SML wipe + cold-resync";
                    m->on_sml_reorg();
                    *sml_base = uint256::ZERO;
                }
                // SML axis: pull the mnlistdiff current AT the new tip. dashcore
                // computes block (tip+1)'s CbTx merkleRootMNList/Quorums from the
                // DMN/quorum list as-of `tip` (GetListForBlock(pindexPrev)), so
                // targeting the diff at `new_tip` puts the local SML in exactly
                // the state needed to build tip+1. Incremental off the last
                // synced base (ZERO after a reorg = full snapshot); the
                // new_mnlistdiff subscription advances sml_base on acceptance.
                if (cp) cp->send_getmnlistd(*sml_base, new_tip);
                // #739 + stale-payee window close: event-driven stale-work
                // notify. INVALIDATE the template cache FIRST (mirrors the
                // #770/#772 fire_refresh trio: invalidate + bump + notify) so the
                // next served job is ALWAYS re-sourced with the fresh-tip payee,
                // regardless of refresh_executor_ state. Without the explicit
                // invalidate the window only stays closed IMPLICITLY (the coin-P2P
                // arm has no refresh_executor_, so cached_work() re-sources inline);
                // if io-decouple is ever extended to this arm, cached_work() would
                // serve the STALE cached template while refreshing async and a
                // stale-payee job would go out. Make it robust, not implicit.
                if (ws) {
                    ws->invalidate_template_cache(
                        "coin-P2P tip changed: fresh-payee re-source");
                    ws->bump_work_generation();
                }
                if (stratum_server) stratum_server->notify_all();
            });

        // E2b UTXO bootstrap window-refill seam: request historical block
        // bodies BY HEIGHT (header-chain hash lookup) so the UTXO view + the
        // MnStateMachine (apply_block) fill forward from the live feed.
        if (embedded_utxo && utxo_lane.live()) {
            utxo_lane.set_request_block_fn(
                [cp = coin_p2p.get(), hc = header_chain.get()](uint32_t h) {
                    auto e = hc->get_header_by_height(h);
                    if (e) cp->request_block(e->hash);
                });
        }

        // Peer's reported chain height -> header-chain sync-progress gauge.
        coin_p2p->set_on_peer_height(
            [hc = header_chain.get()](uint32_t h) { hc->set_peer_tip_height(h); });

        // Kick the initial sync once the version/verack handshake completes:
        // getheaders off our current locator + a mempool prime.
        coin_p2p->set_on_handshake_complete(
            [cp = coin_p2p.get(), hc = header_chain.get(), sml_base]() {
                LOG_INFO << "[EMB-DASH] handshake complete -> initial sync:"
                            " getheaders + mempool + mnlistdiff(cold)";
                cp->send_getheaders(70230, hc->get_locator(), uint256::ZERO);
                cp->send_mempool();
                // Cold-start SML sync: full snapshot (base=ZERO) up to our best
                // known header tip. Steady-state incremental diffs then ride the
                // tip-changed driver. If the header chain is still empty at
                // handshake, target ZERO too — the first tip-change re-requests.
                auto tip_entry = hc->tip();
                const uint256 tip = tip_entry ? tip_entry->hash : uint256::ZERO;
                cp->send_getmnlistd(*sml_base, tip);
            });

        std::cout << "[run] E2a live-feed wired: header-chain(" << hdr_db
                  << ") + CoinStateMaintainer + 6 ingest subscriptions;"
                     " populate flips get_work to the EMBEDDED arm once the tip"
                     " (headers) AND the DMN set (block-connect apply_block) are"
                     " present" << (embedded_utxo ? " + UTXO maturity>=106" : "")
                  << "\n";

        // ── E2c (#738): RPC MN-set SEED — flip the DMN half of populated() ──
        // E2a proved the TIP half populates live, but populated() ALSO needs a
        // payout-bearing DMN set, and no live leg can cold-start one: the P2P
        // Simplified MN List (leg 4's wire form) omits scriptPayout +
        // nLastPaidHeight, and leg 3's apply_block only folds special txs from
        // blocks we actually connect (a full DIP3-height replay = E2d). So when
        // the dashd-RPC arm is ARMED, fetch the full valid DMN set ONCE via
        // `protx list valid true` (payoutAddress + lastPaidHeight — everything
        // GetMNPayee ordering needs) and publish it through the EXISTING leg-4
        // event, so the maintainer takes it exactly like any other resync. The
        // parse FAILS CLOSED (mn_seed.hpp): any undecodable payoutAddress
        // aborts the whole seed rather than minting a wrong payee (the
        // bad-cb-payee class #746 fixed). Synchronous-before-ioc.run() is safe:
        // NodeRPC::Send self-connects via the blocking sync_reconnect fallback
        // (the same property --submit-block relies on).
        if (rpc) {
            try {
                // Height-stable fetch: the snapshot must carry the exact
                // height it is current at (the maintainer fences off
                // re-application of blocks <= that height -- see
                // MnListUpdate::as_of_height). protx list is evaluated at
                // dashd's live tip, so bracket it with getblockcount and
                // refetch on a mid-flight tip move (bounded; a testnet block
                // race is rare, mainnet 2.5 min spacing makes it rarer).
                nlohmann::json protx_list;
                uint32_t as_of = 0;
                for (int attempt = 0; attempt < 3; ++attempt) {
                    const uint32_t h_before = static_cast<uint32_t>(
                        rpc->getblockchaininfo().value("blocks", 0));
                    protx_list = rpc->protx_list_valid_detailed();
                    const uint32_t h_after = static_cast<uint32_t>(
                        rpc->getblockchaininfo().value("blocks", 0));
                    if (h_before == h_after && h_after != 0) {
                        as_of = h_after;
                        break;
                    }
                }
                dash::coin::MnSeedStats seed_stats;
                auto seed = dash::coin::parse_protx_list_seed(
                    protx_list, addr_ver, p2sh_ver, &seed_stats);
                if (!seed.empty() && as_of != 0) {
                    dash::interfaces::MnListUpdate up;
                    up.mnstates     = std::move(seed);
                    up.as_of_height = as_of;
                    coin_state.mn_list_update.happened(up);
                    std::cout << "[run] E2c MN-set seed LOADED: "
                              << seed_stats.seeded << "/" << seed_stats.total
                              << " valid MNs (" << seed_stats.evo << " Evo)"
                                 " as-of h=" << as_of << " from dashd `protx"
                                 " list valid true` -> maintainer DMN half"
                                 " ARMED; populated() flips once the header"
                                 " tip syncs\n";
                } else if (as_of == 0) {
                    std::cout << "[run] E2c MN-set seed SKIPPED (dashd tip"
                                 " moved during every fetch attempt / height"
                                 " unavailable) -- populated() waits for the"
                                 " special-tx replay path; dashd fallback"
                                 " keeps serving\n";
                } else {
                    std::cout << "[run] E2c MN-set seed EMPTY/ABORTED (total="
                              << seed_stats.total << " decode_failed="
                              << seed_stats.payout_decode_failed
                              << " malformed=" << seed_stats.malformed
                              << ") -- populated() waits for the special-tx"
                                 " replay path; dashd fallback keeps serving\n";
                }
            } catch (const std::exception& e) {
                std::cout << "[run] E2c MN-set seed FAILED (protx list RPC: "
                          << e.what() << ") -- populated() waits for the"
                             " special-tx replay path; dashd fallback keeps"
                             " serving\n";
            }
        } else {
            // Pure daemonless: no dashd RPC to seed from. The DMN set must
            // come from a DIP3-height special-tx replay (sync block bodies
            // from DIP3 activation, replay ProRegTx/ProUpRegTx/... through
            // MnStateMachine::apply_block) — the flagged E2d follow-up slice.
            // Flag loudly, don't fail: the run-loop stands up, the tip half
            // still syncs, and get_work stays on the (unarmed) fallback.
            std::cout << "[run] E2c MN-set seed UNAVAILABLE (embedded arm"
                         " enabled but NO coin-RPC configured): populated()"
                         " will wait for the DIP3 special-tx replay path"
                         " (E2d follow-up) -- templates keep routing to the"
                         " fallback arm\n";
        }
    }

    // ── Fallback-arm event-driven tip refresh ────────────────────────────
    // On the dashd-fallback arm (no embedded coin-P2P tip source) the template
    // cache only re-sources on the 30 s staleness TTL (work_source.cpp
    // kStaleAfter) — there is NO tip-change signal like the embedded arm's
    // header_chain->set_on_tip_changed callback. DASH blocks arrive ~every
    // 150 s, so up to ~30 s of stale-tip mining can occur per block (accepted
    // pseudoshares that can no longer win the current block).
    //
    // TWO tip-notify paths, sharing ONE last-seen-tip dedup so a poll+ZMQ
    // double-fire on the same block coalesces to a single refresh:
    //   • BACKSTOP (always, #770): a 3 s getbestblockhash poll. When ZMQ is
    //     unconfigured/unreachable this is the sole active path.
    //   • PRIMARY (opt-in, --coin-zmq-hashblock): a dashd ZMQ `hashblock` SUB
    //     subscriber fires the INSTANT (~0 s) the daemon connects a new block.
    // On a genuine tip CHANGE either path drops the cached template + bumps
    // work-generation + notifies every session (clean_jobs) — the SAME refresh
    // pair the embedded arm fires. Gated on the fallback arm (coin_p2p null) AND
    // an armed rpc AND a live stratum acceptor. getbestblockhash is a trivial
    // RPC; failures are swallowed so a daemon hiccup never crashes the run-loop.
    // io-thread-decouple: dedicated single-thread pool for the fallback arm's
    // BLOCKING dashd RPC (getbestblockhash tip probe + the background template
    // re-source). Mirrors main_ltc.cpp hdr_pool ("keeps scrypt off io_context"):
    // synchronous beast I/O runs HERE, never on the stratum io_context, so 60+
    // sessions never starve while dashd is queried (or wedged -- the NodeRPC
    // socket timeout + m_rpc_mutex bound this thread). Declared here (after rpc /
    // work_source / stratum_server) so its explicit stop()+join() after the run
    // loop -- and its destructor -- happen BEFORE those objects unwind: no
    // background probe is ever mid-flight against freed state. Only created on
    // the fallback arm; null on the embedded arm (legacy inline path unchanged).
    // The opt-in ZMQ subscriber (declared here for the same teardown ordering)
    // only posts onto ioc; when unconfigured/uncompiled the poll is the whole
    // mechanism -- byte-identical to the poll-only #770/#781 behavior.
#ifdef C2POOL_ZMQ
    std::unique_ptr<dash::coin::ZmqHashblockSubscriber> zmq_sub;
#endif
    std::shared_ptr<boost::asio::thread_pool> rpc_pool;
    if (!coin_p2p && rpc && stratum_server) {
        rpc_pool = std::make_shared<boost::asio::thread_pool>(1);

        // Non-blocking template re-source: cached_work() hands the blocking
        // select_work()/GBT to rpc_pool as a single-flight background job
        // instead of blocking the io thread on every stale/generation miss (the
        // per-share ~15-30 s GBT block). The io thread serves the cached template
        // immediately; the pool updates it and the next notify picks it up.
        work_source->set_refresh_executor(
            [rpc_pool](std::function<void()> job) {
                boost::asio::post(*rpc_pool, std::move(job));
            });

        // Shared last-seen-tip dedup — the poll AND the ZMQ subscriber consult
        // it, so if both observe the same new block only the first fires the
        // refresh trio (the second is_new_tip() returns false → no-op).
        auto tip_dedup = std::make_shared<dash::coin::TipHashDedup>();

        // The refresh trio, shared by both paths. Runs on the io_context thread
        // ONLY (the poll follow-up is posted back to ioc; the ZMQ callback posts
        // onto ioc), so ws/ss/dedup are never touched concurrently. `verb`
        // differentiates the instant (ZMQ) vs polled log line. Returns true iff
        // the refresh trio actually fired (a NEW tip vs the shared dedup); false
        // when the tip was unchanged and the call coalesced to a no-op -- the
        // reconnect observer below uses that to tell a real tip change apart from
        // a benign idle-timeout reconnect.
        std::function<bool(const std::string&, const char*, const char*)>
            fire_refresh = [ws = work_source.get(), ss = stratum_server.get(),
                            tip_dedup](const std::string& tip,
                                       const char* source, const char* verb) {
                if (!tip_dedup->is_new_tip(tip))
                    return false; // dedup: coalesce a poll+ZMQ double-fire on one tip
                ws->invalidate_template_cache(
                    "tip-notify: dashd best-block changed");
                ws->bump_work_generation();
                ss->notify_all();
                LOG_INFO << "[Stratum] " << source << ": " << tip.substr(0, 16)
                         << " -> " << verb;
                std::cout << "[Stratum] " << source << ": " << tip.substr(0, 16)
                          << " -> " << verb << "\n";
                return true;
            };

        // #751 churn fix: refine the CoindRPC reconnect-churn observer on the
        // fallback arm. dashd closes an idle keep-alive connection on its
        // rpcservertimeout (default 30 s), so on an otherwise-idle pool c2pool
        // reconnects every ~30-90 s. The unconditional invalidate wired on the
        // main path (see "reconnect-churn observer" above) then fires clean_jobs
        // to every stratum session on EVERY such reconnect -> the endpoint flaps
        // and rigs waste work even though NOTHING changed on-chain. Here we
        // OVERRIDE that observer (this assignment runs after the main-path one,
        // still before the io loop starts) with a tip-aware version: on a
        // reconnect, probe dashd's best-block hash and invalidate ONLY if the tip
        // actually moved while we were disconnected.
        //
        //   INVARIANT (must NOT regress the stale-masternode-payee lost-block
        //   class): a tip change during the disconnect window MUST still
        //   invalidate -- a new tip means a new masternode payee, so any template
        //   cached from before the churn is stale and unsafe to serve or submit.
        //   We skip the invalidate ONLY when the tip is PROVABLY unchanged (probe
        //   succeeded AND equals the last-seen tip). If the probe itself fails
        //   (RPC not ready on the fresh socket) we FALL BACK to invalidating --
        //   never serve stale-payee work on an unproven tip.
        //
        // Deadlock note: m_on_reconnect fires from inside NodeRPC::sync_reconnect(),
        // which runs UNDER m_rpc_mutex from within Send(). A synchronous
        // getbestblockhash() here would re-enter Send() and self-deadlock on that
        // non-recursive mutex, so the probe is POSTED to rpc_pool (the RPC thread)
        // and runs after the triggering Send() releases the lock. The tip compare
        // + refresh trio then post BACK onto ioc, where fire_refresh / tip_dedup
        // are io-thread-confined -- identical threading to the 3 s tip poll below.
        rpc->set_on_reconnect(
            [rpc = rpc.get(), rpc_pool, fire_refresh, ws = work_source.get(),
             &ioc]() {
                boost::asio::post(*rpc_pool, [rpc, fire_refresh, ws, &ioc]() {
                    std::string tip;
                    bool ok = false;
                    try {
                        tip = rpc->getbestblockhash(); // BLOCKING -- background thread
                        ok = true;
                    } catch (...) {
                        // swallow -- treated as a probe failure (fail-safe below)
                    }
                    boost::asio::post(ioc,
                        [ok, tip = std::move(tip), fire_refresh, ws]() {
                            if (!ok || tip.empty()) {
                                // FAIL-SAFE: tip unproven -> conservatively drop
                                // the cache (the pre-#751 unconditional behaviour).
                                ws->invalidate_template_cache(
                                    "CoindRPC reconnect: tip probe failed "
                                    "(fail-safe invalidate)");
                                return;
                            }
                            // fire_refresh invalidates + bumps + notifies IFF the
                            // tip is NEW vs the shared last-seen dedup; an unchanged
                            // tip is a benign idle-timeout reconnect -> cache kept.
                            if (!fire_refresh(tip, "reconnect",
                                              "tip changed during disconnect -> "
                                              "refresh + notify")) {
                                LOG_INFO << "[Stratum] reconnect: benign idle-"
                                            "timeout, tip unchanged ("
                                         << tip.substr(0, 16)
                                         << ") -- template cache retained";
                            }
                        });
                });
            });

        // BACKSTOP: 3 s getbestblockhash poll (#770), io-decoupled (#781).
        auto tip_timer = std::make_shared<io::steady_timer>(ioc);
        auto tip_tick = std::make_shared<
            std::function<void(const boost::system::error_code&)>>();
        // tip_tick runs ON ioc when the 3 s timer fires. It does NOT call the
        // blocking RPC itself: it hands getbestblockhash to rpc_pool and posts
        // the tip-change follow-up + the timer re-arm BACK onto ioc (fire_refresh
        // / tip_timer are io-thread-confined), exactly like main_ltc.cpp's
        // post-to-pool -> post-back-to-ioc pattern. The timer is re-armed only
        // AFTER the RPC completes, so a slow dashd cannot pile up overlapping
        // polls. Lost-block-prevention is preserved: a real tip change still
        // fires the refresh trio -- only WHERE the probe runs has moved off the
        // stratum io thread.
        *tip_tick = [rpc = rpc.get(), tip_dedup, fire_refresh, tip_timer,
                     tip_tick, rpc_pool, &ioc](const boost::system::error_code& ec) {
            if (ec) return;   // cancelled at shutdown
            boost::asio::post(*rpc_pool,
                [rpc, tip_dedup, fire_refresh, tip_timer, tip_tick, &ioc]() {
                    std::string tip;
                    bool ok = false;
                    try {
                        tip = rpc->getbestblockhash();   // BLOCKING -- BACKGROUND THREAD
                        ok = true;
                    } catch (const std::exception& e) {
                        LOG_WARNING << "[Stratum] tip-poll getbestblockhash failed "
                                       "(non-fatal, retry next tick): " << e.what();
                    } catch (...) {
                        // swallow — never crash on a tip probe
                    }
                    // Follow-up + timer re-arm run BACK ON ioc (io-thread-confined
                    // state). If ioc is already stopped (shutdown) this handler
                    // simply never runs -> the poll stops cleanly.
                    boost::asio::post(ioc,
                        [ok, tip = std::move(tip), tip_dedup, fire_refresh,
                         tip_timer, tip_tick]() {
                            if (ok && !tip.empty()) {
                                if (tip_dedup->last().empty()) {
                                    // Startup baseline: this is the tip we are
                                    // already mining, not a change — seed the
                                    // dedup, do NOT notify.
                                    tip_dedup->set_last(tip);
                                } else {
                                    fire_refresh(tip, "tip-poll",
                                                 "template refresh + notify");
                                }
                            }
                            tip_timer->expires_after(std::chrono::seconds(3));
                            tip_timer->async_wait(*tip_tick);
                        });
                });
        };
        tip_timer->expires_after(std::chrono::seconds(3));
        tip_timer->async_wait(*tip_tick);
        std::cout << "[run] fallback-arm tip-poll ARMED (dashd getbestblockhash "
                     "every 3 s on a dedicated RPC thread -> event-driven template "
                     "refresh + clean_jobs notify on tip change; io thread never "
                     "blocks on dashd)\n";

        // PRIMARY: dashd ZMQ `hashblock` INSTANT tip-notify (opt-in). Absent or
        // uncompiled => the poll above is the sole active path (zero regression).
        if (coin_zmq_hashblock.empty()) {
            std::cout << "[run] ZMQ hashblock tip-notify NOT configured "
                         "(--coin-zmq-hashblock unset); the 3 s poll is the "
                         "active tip-notify path\n";
        } else {
#ifdef C2POOL_ZMQ
            // Every hashblock frame is a genuine new-block event. Hop onto the
            // io_context thread before touching ws/ss (fire_refresh contract);
            // the shared dedup coalesces it against the poll on the same block.
            zmq_sub = std::make_unique<dash::coin::ZmqHashblockSubscriber>(
                coin_zmq_hashblock,
                [&ioc, fire_refresh](const std::string& hash_hex) {
                    boost::asio::post(ioc, [fire_refresh, hash_hex]() {
                        fire_refresh(hash_hex, "zmq hashblock",
                                     "instant template refresh + notify");
                    });
                });
            zmq_sub->start();
            std::cout << "[run] ZMQ hashblock tip-notify ARMED at "
                      << coin_zmq_hashblock
                      << " (PRIMARY instant tip-notify; 3 s poll is the "
                         "backstop; reconnects if dashd ZMQ is down)\n";
#else
            std::cout << "[run] --coin-zmq-hashblock " << coin_zmq_hashblock
                      << " requested but this build has no libzmq (C2POOL_ZMQ "
                         "off); the 3 s poll is the active tip-notify path\n";
#endif
        }
    }

    std::cout << "[run] run-loop up (Ctrl-C to stop); won blocks relay DUAL-PATH:\n"
                 "[run]   ARM A embedded coin-P2P relay (primary, daemonless) = "
              << (p2p_relay ? "ARMED" : (no_p2p_relay ? "SUPPRESSED (--no-p2p-relay)"
                                                       : "off (no --coin-p2p-connect peer)"))
              << "\n[run]   ARM B dashd submitblock RPC backup = "
              << (rpc_submit ? "ARMED" : "off (no dashd creds)") << "\n";
    // #755 guard (btc main_btc.cpp:1309-1315 parity): an exception escaping an
    // io handler must NOT terminate the node (Exit 134 core-dump — e.g. a
    // chain-walk throw over unrooted persisted shares after a partial join).
    // Log + resume; after an escaped exception the io_context is NOT stopped,
    // so run() continues with the remaining handlers. Ctrl-C still exits via
    // the signal handler's ioc.stop() → run() returns normally → break.
    for (;;) {
        try {
            ioc.run();
            break;
        } catch (const std::exception& e) {
            LOG_ERROR << "[run] io handler exception (non-fatal, #755 guard): "
                      << e.what();
            std::cout << "[run] io handler exception (non-fatal): " << e.what()
                      << "\n";
        } catch (...) {
            LOG_ERROR << "[run] io handler exception (non-fatal, #755 guard): "
                         "unknown error";
        }
    }

    // Stop the ZMQ hashblock subscriber (joins its thread) BEFORE the stratum
    // acceptor + work source it refreshes are torn down. Its callback only posts
    // onto the now-stopped ioc, so no refresh can run past here.
#ifdef C2POOL_ZMQ
    if (zmq_sub) {
        zmq_sub->stop();
        zmq_sub.reset();
    }
#endif

    // io-thread-decouple: join the background RPC pool, before any of the
    // objects it dereferences (rpc / work_source / stratum_server) unwind. run()
    // has returned (ioc stopped), so no NEW work is posted; stop()+join() waits
    // out any in-flight getbestblockhash/GBT re-source (bounded by the NodeRPC
    // socket timeout) so no pool thread ever touches freed state. Any post-back
    // to the stopped ioc simply never executes.
    if (rpc_pool) {
        rpc_pool->stop();
        rpc_pool->join();
    }

    // Tear the acceptor + sessions down while the work source and node_coin_state
    // it references are still alive -- explicit reset keeps destruction order safe
    // (stratum_server was declared before them, so it would otherwise outlive them).
    stratum_server.reset();

    // Stop the dashboard BEFORE p2p_node unwinds: its callbacks hold a raw
    // dash::Node* and the HTTP thread must be joined while that is still valid.
    if (web_server) {
        web_server->stop();
        web_server.reset();
    }

    // Flush pending sharechain persistence buffers (verified marks + removals).
    p2p_node.shutdown_persistence();

    std::cout << "[run] run-loop stopped cleanly\n";
    return 0;
}

// --mine-block: the slice-5 PRODUCER one-shot. Pull a block template (dashd
// getblocktemplate via NodeRPC::getwork), build the coinbase, X11-mine the
// 80-byte header over the nonce until it meets the compact-bits target,
// serialize the FULL block to hex, and feed it into the EXISTING submit arm
// (NodeRPC::submit_block_hex). This is the "c2pool-dash builds and wins the
// block itself" lever -- slice-4 only re-submitted a pre-built hex.
//
// Creds posture is IDENTICAL to --submit-block: endpoint via --coin-rpc, creds
// from dash.conf (never argv). The optional --payout-pubkey-hash HEX (40 hex =
// 20 bytes) names the block-finder P2PKH payout; default all-zero placeholder
// (genesis-style: empty PPLNS weights, total_weight 0). max_nonce is bounded;
// regtest bits (0x207fffff) make the target trivial so a winner is found fast.
int run_mine_block(bool testnet, const std::string& rpc_endpoint,
                   const std::string& rpc_conf_path,
                   const std::string& payout_pkh_hex,
                   uint64_t max_nonce)
{
    namespace io = boost::asio;

    dash::coin::RpcConf conf;
    std::string conf_path = rpc_conf_path;
    if (conf_path.empty()) {
        const char* home = std::getenv("HOME");
        conf_path = std::string(home ? home : ".") + "/.dashcore/dash.conf";
    }
    dash::coin::load_rpc_conf(conf_path, conf);
    dash::coin::apply_endpoint_override(rpc_endpoint, conf);
    if (conf.port == 0)
        conf.port = testnet ? 19998 : 9998;

    if (!conf.armed()) {
        std::cout << "[mine] submit arm UNARMED (no dash.conf creds / no port); "
                     "supply dashd creds via dash.conf or --coin-rpc-auth PATH\n";
        return 2;
    }

    io::io_context ioc;
    dash::interfaces::Node coin_state;
    dash::coin::NodeRPC rpc(&ioc, &coin_state, testnet);
    rpc.connect(NetService(conf.host, conf.port), conf.userpass());
    std::cout << "[mine] producer ARMED: NodeRPC -> " << conf.host << ":"
              << conf.port << " (creds from dash.conf)\n";

    // 1) Pull the template.
    std::cout << "[mine] fetching block template (getblocktemplate)...\n";
    // Work source (S8 embedded_gbt live-wire capstone): PREFER the locally
    // assembled embedded template via build_embedded_workdata, fall back to
    // dashd getblocktemplate. The dashd arm is RETAINED as fallback + the
    // [GBT-XCHECK] cross-check -- never removed.
    //
    // NOTE: NodeImpl does not yet hold the embedded coin-state (masternode
    // list + mempool + header tip) that build_embedded_workdata consumes, so
    // emb.has_state stays false here and the selector routes to the dashd
    // fallback today. Populating that in-process state is the flagged next
    // sub-slice; once it lands, set emb.has_state=true and the embedded arm
    // goes live with zero change to this call site.
    dash::coin::EmbeddedWorkInputs emb;   // has_state=false until node-held coin-state lands
    dash::coin::WorkSelection sel =
        dash::coin::select_dash_work(emb, [&]{ return rpc.getwork(); });
    dash::coin::DashWorkData work = std::move(sel.work);
    std::cout << "[mine] work source: "
              << (sel.source == dash::coin::WorkSource::Embedded
                      ? "EMBEDDED (build_embedded_workdata)"
                      : "dashd getblocktemplate (fallback)") << "\n";
    std::cout << "[mine] template: height=" << work.m_height
              << " bits=0x" << std::hex << work.m_bits << std::dec
              << " prev=" << work.m_previous_block.GetHex().substr(0, 16) << "..."
              << " ntx(gbt)=" << work.m_tx_data_hex.size()
              << " coinbase_value=" << work.m_coinbase_value << "\n";

    // 2) Build the coinbase. Genesis-style payout (no prior shares): empty
    //    weights, total_weight 0 -> all of worker_payout goes to the finder
    //    (this_script, 2% rule) + donation remainder.
    uint160 payout_pkh;   // default all-zero
    if (!payout_pkh_hex.empty()) {
        if (payout_pkh_hex.size() != 40) {
            std::cout << "[mine] --payout-pubkey-hash must be 40 hex chars (20 bytes)\n";
            return 2;
        }
        payout_pkh.SetHex(payout_pkh_hex);
    }
    const core::CoinParams params = dash::make_coin_params(testnet);
    std::map<std::vector<unsigned char>, uint64_t> empty_weights;
    auto tx_outs = dash::coinbase::compute_dash_payouts(
        work.m_coinbase_value, work.m_packed_payments, payout_pkh,
        empty_weights, /*total_weight=*/0, params);
    // ref_hash is the PPLNS commitment; for a standalone producer block we use
    // zero (no sharechain commitment) -- consensus-irrelevant to dashd validity.
    auto layout = dash::coinbase::build(work, tx_outs, /*pool_tag=*/"c2pool",
                                        params, /*ref_hash=*/uint256::ZERO);
    std::cout << "[mine] coinbase built: " << layout.bytes.size()
              << " bytes, " << tx_outs.size() << " outputs\n";

    // 3) X11-mine.
    std::cout << "[mine] X11-mining header (max_nonce=" << max_nonce << ")...\n";
    dash::coin::MineResult mr =
        dash::coin::mine_block(work, layout.bytes, max_nonce);
    if (!mr.found) {
        std::cout << "[mine] NO winning nonce in [0, " << max_nonce
                  << "] -- raise --max-nonce or check bits\n";
        return 1;
    }
    std::cout << "[mine] WON: nonce=" << mr.nonce
              << " powhash=" << mr.block_hash.GetHex()
              << " block=" << (mr.block_hex.size() / 2) << " bytes\n";

    // 4) Submit via the EXISTING arm.
    const int64_t before = static_cast<int64_t>(
        rpc.getblockchaininfo().value("blocks", -1));
    std::cout << "[mine] getblockcount(before)=" << before << "\n";
    std::cout << "[mine] submitting mined block to dashd "
              << conf.host << ":" << conf.port << "...\n";
    const bool accepted = rpc.submit_block_hex(mr.block_hex, /*ignore_failure=*/false);
    const int64_t after = static_cast<int64_t>(
        rpc.getblockchaininfo().value("blocks", -1));
    std::cout << "[mine] submitblock " << (accepted ? "ACCEPTED" : "REJECTED")
              << " by dashd; block_hash=" << mr.block_hash.GetHex()
              << " getblockcount(after)=" << after
              << (after > before ? " (+1, tip advanced)\n" : "\n");
    return accepted ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    // Mining-hotel interim fix #4: raise RLIMIT_NOFILE to 65536 at startup
    // (one fd per stratum/miner session + RPC + sharechain P2P; distro-default
    // 1024 starves the accept loop). Report the effective soft limit.
    {
        const uint64_t nofile = core::raise_nofile_limit(65536);
        if (nofile == 0)
            std::cout << "[init] RLIMIT_NOFILE: unsupported on this platform (or query failed)\n";
        else
            std::cout << "[init] RLIMIT_NOFILE soft limit: " << nofile
                      << (nofile < 65536 ? " (< 65536; hard limit too low)" : "") << "\n";
    }

    bool want_help = false;
    bool want_run  = false;
    bool want_mine = false;
    bool testnet   = false;
    std::string payout_pkh_hex;   // --payout-pubkey-hash HEX (20-byte P2PKH finder)
    uint64_t    max_nonce = 0xffffffffull;  // --max-nonce N (producer search bound)
    std::string rpc_endpoint;     // --coin-rpc / --coin-daemon HOST:PORT (endpoint only)
    std::string rpc_conf_path;    // --coin-rpc-auth PATH (creds; default ~/.dashcore/dash.conf)
    std::string submit_hex;       // --submit-block HEX (one-shot won-block submit)
    std::string submit_file;      // --submit-block-file PATH
    std::string listen_raw;                    // --listen [HOST:]PORT (sharechain bind)
    std::vector<std::string> addnode_raw;      // --addnode HOST:PORT (persistent outbound)
    std::vector<std::string> connect_raw;      // --connect HOST:PORT (connect-only)
    std::vector<std::string> coin_p2p_raw;     // --coin-p2p-connect HOST:PORT (repeatable; E1 opt-in coin-network dial)
    bool no_p2p_relay = false;                 // --no-p2p-relay: suppress the embedded P2P-relay won-block arm (A/B isolation; RPC backup stays live)
    bool embedded_mainnet = false;             // --embedded-mainnet: gate-lift, allow the daemonless embedded template arm on MAINNET (byte-parity proven; default OFF = dashd fallback)
    std::string stratum_host = "0.0.0.0";      // --stratum [HOST:]PORT bind interface (default all)
    uint16_t    stratum_port = 0;              // 0 disables the Stratum accept-loop; --stratum sets it
    bool embedded_utxo = false;                // --embedded-utxo: arm the E2b UTXO/fee lane (opt-in)
    double dev_donation = 0.1;                 // --give-author (donation_percentage; README default 0.1%)
    double node_owner_fee = 0.0;               // -f / --fee (node_owner_fee; default 0)
    std::string node_owner_address;            // --node-owner-address (fee destination)
    // Web dashboard (the EXISTING c2pool dashboard, same defaults as main_ltc.cpp:
    // http_port 8080, dashboard_dir "web-static"). Default-ON for --run.
    std::string web_host      = "0.0.0.0";     // --web-host bind interface
    uint16_t    web_port      = 8080;          // --web-port / --http-port (0 disables)
    std::string dashboard_dir = "web-static";  // --dashboard-dir static asset root
    std::string redistribute_mode = "pplns";   // --redistribute pplns|fee|boost|donate
    std::string coin_zmq_hashblock;             // --coin-zmq-hashblock ENDPOINT (opt-in dashd ZMQ hashblock instant tip-notify, e.g. tcp://127.0.0.1:28332)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dash " << C2POOL_VERSION << "\n";
            return 0;
        }
        else if (std::strcmp(argv[i], "--help") == 0)    want_help = true;
        else if (std::strcmp(argv[i], "--data-dir") == 0) {
            // Root all per-instance state (LevelDB sharechain, mn_state_db,
            // addr store, logs, ...) under PATH so co-located instances don't
            // contend the LevelDB LOCK. Default keeps ~/.c2pool. See #722.
            if (i + 1 >= argc || argv[i + 1][0] == '\0' || argv[i + 1][0] == '-') {
                std::cerr << "error: --data-dir requires a PATH argument\n";
                return 1;
            }
            core::filesystem::set_data_dir(argv[++i]);
        }
        else if (std::strcmp(argv[i], "--run") == 0)     want_run  = true;
        else if (std::strcmp(argv[i], "--mine-block") == 0) want_mine = true;
        else if (std::strcmp(argv[i], "--payout-pubkey-hash") == 0 && i + 1 < argc)
            payout_pkh_hex = argv[++i];
        else if (std::strcmp(argv[i], "--max-nonce") == 0 && i + 1 < argc)
            max_nonce = std::strtoull(argv[++i], nullptr, 0);
        else if (std::strcmp(argv[i], "--testnet") == 0 ||
                 std::strcmp(argv[i], "--regtest") == 0)  testnet = true;
        else if ((std::strcmp(argv[i], "--coin-rpc") == 0 ||
                  std::strcmp(argv[i], "--coin-daemon") == 0) && i + 1 < argc)
            rpc_endpoint = argv[++i];
        else if (std::strcmp(argv[i], "--coin-rpc-auth") == 0 && i + 1 < argc)
            rpc_conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--submit-block") == 0 && i + 1 < argc)
            submit_hex = argv[++i];
        else if (std::strcmp(argv[i], "--submit-block-file") == 0 && i + 1 < argc)
            submit_file = argv[++i];
        else if (std::strcmp(argv[i], "--listen") == 0 && i + 1 < argc)
            listen_raw = argv[++i];
        else if (std::strcmp(argv[i], "--addnode") == 0 && i + 1 < argc)
            addnode_raw.emplace_back(argv[++i]);
        else if (std::strcmp(argv[i], "--connect") == 0 && i + 1 < argc)
            connect_raw.emplace_back(argv[++i]);
        else if (std::strcmp(argv[i], "--coin-p2p-connect") == 0 && i + 1 < argc)
            coin_p2p_raw.emplace_back(argv[++i]);
        else if (std::strcmp(argv[i], "--no-p2p-relay") == 0)
            no_p2p_relay = true;
        else if (std::strcmp(argv[i], "--embedded-mainnet") == 0)
            embedded_mainnet = true;
        else if (std::strcmp(argv[i], "--embedded-utxo") == 0)
            embedded_utxo = true;
        else if ((std::strcmp(argv[i], "--give-author") == 0 ||
                  std::strcmp(argv[i], "--dev-donation") == 0) && i + 1 < argc)
            dev_donation = std::strtod(argv[++i], nullptr);
        else if ((std::strcmp(argv[i], "-f") == 0 ||
                  std::strcmp(argv[i], "--fee") == 0) && i + 1 < argc)
            node_owner_fee = std::strtod(argv[++i], nullptr);
        else if (std::strcmp(argv[i], "--node-owner-address") == 0 && i + 1 < argc)
            node_owner_address = argv[++i];
        else if (std::strcmp(argv[i], "--redistribute") == 0 && i + 1 < argc)
            redistribute_mode = argv[++i];
        else if (std::strcmp(argv[i], "--coin-zmq-hashblock") == 0 && i + 1 < argc)
            coin_zmq_hashblock = argv[++i];   // opt-in dashd ZMQ hashblock endpoint
        else if ((std::strcmp(argv[i], "--web-port") == 0 ||
                  std::strcmp(argv[i], "--http-port") == 0) && i + 1 < argc) {
            const long p = std::strtol(argv[++i], nullptr, 10);
            if (p < 0 || p > 65535) {
                std::cout << "c2pool-dash: --web-port out of range: " << argv[i] << "\n";
                return 2;
            }
            web_port = static_cast<uint16_t>(p);
        }
        else if (std::strcmp(argv[i], "--web-host") == 0 && i + 1 < argc)
            web_host = argv[++i];
        else if (std::strcmp(argv[i], "--dashboard-dir") == 0 && i + 1 < argc)
            dashboard_dir = argv[++i];
        else if (std::strcmp(argv[i], "--stratum") == 0 && i + 1 < argc) {
            // --stratum [HOST:]PORT -- bind a Stratum TCP listener for miners.
            // Bare PORT keeps the default 0.0.0.0 bind host (parse_listen SSOT).
            if (!parse_listen(argv[++i], stratum_host, stratum_port)) {
                std::cout << "[run] --stratum malformed (want [HOST:]PORT): "
                          << argv[i] << "\n";
                return 2;
            }
        }
        // --selftest is the default; accepted explicitly for symmetry.
    }

    print_banner(argv[0]);
    if (want_help)
        return 0;
    if (want_mine)
        return run_mine_block(testnet, rpc_endpoint, rpc_conf_path,
                              payout_pkh_hex, max_nonce);
    if (want_run) {
        if (!submit_file.empty() && submit_hex.empty()) {
            std::ifstream bf(submit_file);
            if (!bf) {
                std::cout << "[run] cannot open --submit-block-file " << submit_file << "\n";
                return 2;
            }
            std::getline(bf, submit_hex, '\0');   // whole-file slurp
            while (!submit_hex.empty() &&
                   (submit_hex.back() == '\n' || submit_hex.back() == '\r' ||
                    submit_hex.back() == ' '  || submit_hex.back() == '\t'))
                submit_hex.pop_back();
        }
        PeeringConfig peer;
        for (const auto& raw : addnode_raw) {
            NetService ns;
            if (!parse_hostport(raw, ns)) {
                std::cout << "[run] --addnode malformed (want HOST:PORT): " << raw << "\n";
                return 2;
            }
            peer.addnodes.push_back(ns);
        }
        for (const auto& raw : connect_raw) {
            NetService ns;
            if (!parse_hostport(raw, ns)) {
                std::cout << "[run] --connect malformed (want HOST:PORT): " << raw << "\n";
                return 2;
            }
            peer.connects.push_back(ns);
        }
        if (!listen_raw.empty()) {
            if (!parse_listen(listen_raw, peer.listen_host, peer.listen_port)) {
                std::cout << "[run] --listen malformed (want [HOST:]PORT): " << listen_raw << "\n";
                return 2;
            }
            peer.listen_set = true;
        }
        std::vector<NetService> coin_p2p_targets;
        for (const auto& raw : coin_p2p_raw) {
            NetService ns;
            if (!parse_hostport(raw, ns)) {
                std::cout << "[run] --coin-p2p-connect malformed (want HOST:PORT): "
                          << raw << "\n";
                return 2;
            }
            coin_p2p_targets.push_back(ns);
        }
        // Guard against port conflicts between stratum and the web dashboard
        // (main_ltc.cpp:1480, same posture and same +1 resolution).
        if (stratum_port != 0 && web_port != 0 && stratum_port == web_port) {
            std::cout << "[run] stratum port " << stratum_port
                      << " conflicts with web dashboard port, moving dashboard to "
                      << (stratum_port + 1) << "\n";
            web_port = static_cast<uint16_t>(stratum_port + 1);
        }
        return run_node(testnet, rpc_endpoint, rpc_conf_path, submit_hex, peer,
                        stratum_host, stratum_port, web_host, web_port,
                        dashboard_dir, coin_p2p_targets,
                        embedded_utxo, dev_donation, node_owner_fee,
                        node_owner_address, redistribute_mode, no_p2p_relay,
                        embedded_mainnet,
                        coin_zmq_hashblock);
    }
    return run_selftest();
}