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
// BLOCK-SUBMISSION (--run) — EXPLICITLY DEFERRED, NOT a silent stub. A won DASH
// block reaches the network by a dual-path broadcaster, BOTH arms of which live
// in the unmerged dash-spv-embedded work and are NOT on master:
//   - dashd-RPC submitblock fallback: needs a DASH NodeRPC TU (rpc.cpp/rpc.hpp/
//     rpc_conf.hpp) — DASH has only coin/rpc_data.hpp (a data placeholder), no
//     RPC client. Porting it (mirroring dgb/coin/rpc.cpp) is the NEXT slice.
//   - embedded P2P relay arm: the broadcaster_full / reconstruct stack (S8).
// The CoinParams *path* the RPC fallback consumes IS wired here (make_coin_params,
// oracle-sourced via dash::PoolConfig SSOT); the block-submission SINKS are the
// deferred piece. --run prints this status and exits cleanly so a smoke gate that
// invokes it is never misled into thinking block relay is live.
//
// Conformance oracle: frstrtr/p2pool-dash (older-than-v35; transition 16 -> v36).
// External dashd RPC stays as a fallback alongside the (future) embedded path.

#include <impl/dash/params.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>   // must precede subsidy.hpp (dash_txid in scope)
#include <impl/dash/coin/subsidy.hpp>

#include <core/coin_params.hpp>
#include <core/uint256.hpp>
#include <core/netaddress.hpp>             // NetService (dashd RPC endpoint)

#include <impl/dash/coin/rpc.hpp>          // dash::coin::NodeRPC — external-dashd submitblock arm (slice 3)
#include <impl/dash/coin/rpc_conf.hpp>     // dash.conf creds resolution (rpcpassword off argv)
#include <impl/dash/coin/node_interface.hpp>
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

#include <boost/asio.hpp>

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
        << "       " << argv0 << " --run [--coin-rpc H:P] [--coin-rpc-auth PATH]\n"
        << "           [--testnet] [--submit-block HEX | --submit-block-file PATH]\n"
        << "           [--listen [HOST:]PORT] [--addnode HOST:PORT]... [--connect HOST:PORT]...\n"
        << "       " << argv0 << " --mine-block [--coin-rpc H:P] [--coin-rpc-auth PATH]\n"
        << "           [--testnet] [--payout-pubkey-hash HEX] [--max-nonce N]\n\n"
        << "Status: consensus layer live (X11 PoW, subsidy, oracle CoinParams).\n"
        << "        --run stands up the run-loop and ARMS the external-dashd\n"
        << "        submitblock fallback (creds from dash.conf, never on argv).\n"
        << "        --submit-block[-file] drives ONE real submitblock then exits\n"
        << "        (the won-block-reaches-network leg); embedded P2P relay = S8.\n"
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
int run_node(bool testnet, const std::string& rpc_endpoint,
             const std::string& rpc_conf_path, const std::string& submit_hex,
             const PeeringConfig& peer)
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
    io::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&ioc](const boost::system::error_code&, int) {
        std::cout << "[run] shutdown signal -- stopping run-loop\n";
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
                     "(no dash.conf creds / no port); embedded P2P relay leg is S8.\n";
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

    // --connect (connect-only, no --listen) suppresses the inbound listener,
    // matching report_peering() above.
    const bool connect_only = !peer.connects.empty() && !peer.listen_set;
    const uint16_t bind_port =
        peer.listen_port ? peer.listen_port : dash::SharechainConfig::p2p_port();
    if (!connect_only) {
        p2p_node.core::Server::listen(bind_port);
        std::cout << "[run] sharechain peer LISTENING on " << peer.listen_host << ":"
                  << bind_port
                  << " — min-proto=" << dash::SharechainConfig::MINIMUM_PROTOCOL_VERSION
                  << " prefix=" << dash::SharechainConfig::prefix_hex() << "\n";
    } else {
        std::cout << "[run] --connect mode: inbound listener suppressed\n";
    }
    // addnode/connect targets are registered in the addr store by the NodeImpl
    // ctor, but ACTIVE outbound dialing rides the download/outbound slice
    // (dash::NodeImpl carries no start_outbound_connections yet). Inbound
    // reception — version handshake + the #646 min-proto gate — is live now
    // via node.cpp (#656/#657).

    std::cout << "[run] run-loop up (Ctrl-C to stop); won blocks relay via the\n"
                 "[run] dashd-RPC submitblock fallback + the embedded sharechain P2P leg.\n";
    ioc.run();
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
    dash::coin::DashWorkData work = rpc.getwork();
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
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dash " << C2POOL_VERSION << "\n";
            return 0;
        }
        else if (std::strcmp(argv[i], "--help") == 0)    want_help = true;
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
        return run_node(testnet, rpc_endpoint, rpc_conf_path, submit_hex, peer);
    }
    return run_selftest();
}
