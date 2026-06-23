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

#include <boost/asio.hpp>

#include <cstdint>
#include <cstdlib>      // std::getenv
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace {

using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;

void print_banner(const char* argv0)
{
    std::cout
        << "c2pool-dash " << C2POOL_VERSION << " — DASH (X11, older-than-v35 -> V36)\n\n"
        << "Usage: " << argv0 << " [--version] [--help] [--selftest]\n"
        << "       " << argv0 << " --run [--coin-rpc H:P] [--coin-rpc-auth PATH]\n"
        << "           [--testnet] [--submit-block HEX | --submit-block-file PATH]\n\n"
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
             const std::string& rpc_conf_path, const std::string& submit_hex)
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

    std::cout << "[run] run-loop up (Ctrl-C to stop); won blocks relay via the\n"
                 "[run] dashd-RPC submitblock fallback. Embedded P2P relay = S8.\n";
    ioc.run();
    std::cout << "[run] run-loop stopped cleanly\n";
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    bool want_help = false;
    bool want_run  = false;
    bool testnet   = false;
    std::string rpc_endpoint;     // --coin-rpc / --coin-daemon HOST:PORT (endpoint only)
    std::string rpc_conf_path;    // --coin-rpc-auth PATH (creds; default ~/.dashcore/dash.conf)
    std::string submit_hex;       // --submit-block HEX (one-shot won-block submit)
    std::string submit_file;      // --submit-block-file PATH
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "c2pool-dash " << C2POOL_VERSION << "\n";
            return 0;
        }
        else if (std::strcmp(argv[i], "--help") == 0)    want_help = true;
        else if (std::strcmp(argv[i], "--run") == 0)     want_run  = true;
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
        // --selftest is the default; accepted explicitly for symmetry.
    }

    print_banner(argv[0]);
    if (want_help)
        return 0;
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
        return run_node(testnet, rpc_endpoint, rpc_conf_path, submit_hex);
    }
    return run_selftest();
}
