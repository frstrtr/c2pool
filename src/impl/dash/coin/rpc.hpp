// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// dash::coin::NodeRPC -- external dashd-RPC client (launcher slice 3).
//
// Real boost::beast + jsonrpccxx HTTP JSON-RPC client to an external dashd,
// mirroring src/impl/dgb/coin/rpc.{hpp,cpp} (itself mirrored from
// src/impl/btc/coin/rpc.{hpp,cpp}). This is the EXTERNAL-DAEMON FALLBACK path
// that V36 mandates persist alongside the embedded daemon (v36 external_fallback:
// "embedded primary, external fallback persists -- do NOT remove external-daemon
// code paths"). Closes the launcher-campaign gap: before this slice DASH had
// ONLY coin/rpc_data.hpp (the DashWorkData placeholder) and NO RPC client.
//
// DASH divergences from DGB/BTC (conformed at port time):
//   - getblocktemplate(): DASH is X11 and has NO segwit, so -- unlike DGB --
//     the GBT body carries NO {"algo":"scrypt"} param and injects NO "segwit"
//     rule. It is the plain {"rules": <caller rules>} dashd expects (default
//     {}). See coin/rpc_request.hpp (request-shape SSOT).
//   - getwork() returns the RICH dash::coin::DashWorkData (NOT the trimmed
//     rpc::WorkData family-1 seam DGB uses). It parses the dashd GBT JSON into:
//       * standard fields (version/prev/height/coinbasevalue/bits/curtime/...)
//       * the full transaction set (m_txs + m_tx_data_hex + m_tx_hashes + fees)
//       * the DASH masternode + superblock + platform payments
//         (m_packed_payments, normalized to the "!hex"/base58 payee convention
//         coin/embedded_gbt.hpp::gbt_xcheck compares against), with
//         m_payment_amount = sum of those amounts (the masternode+treasury
//         share miners do NOT receive)
//       * the DIP3/DIP4 coinbase extra payload (m_coinbase_payload, hex-decoded)
//   - check(): chain-identity probe uses the DASH genesis hash (mainnet vs
//     testnet3 by IS_TESTNET) from coin/rpc_request.hpp, not DGB's.
//
// submit_block_hex(block_hex, ignore_failure) is THE key deliverable: the dashd
// `submitblock` fallback arm. The embedded-P2P relay leg of the won-block
// dual-path broadcaster is still DEFERRED (lands with coin/p2p_node); this slice
// ships the RPC submit fallback only. NEVER remove the external-daemon path.
// ---------------------------------------------------------------------------

#include "block.hpp"
#include "rpc_data.hpp"
#include "node_interface.hpp"

#include <iostream>

#include <core/uint256.hpp>
#include <core/timer.hpp>
#include <core/netaddress.hpp>   // NetService m_address / connect() endpoint

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <jsonrpccxx/client.hpp>

namespace io = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

namespace dash
{

namespace coin
{

struct RPCAuthData;
class NodeRPC : public jsonrpccxx::IClientConnector
{
    const std::string ID = "curltest";
    const jsonrpccxx::version RPC_VER = jsonrpccxx::version::v2;

    const bool IS_TESTNET;
private:
    dash::interfaces::Node* m_coin;

    io::io_context* m_context;
    beast::tcp_stream m_stream;
    boost::asio::ip::tcp::resolver m_resolver;
    http::request<http::string_body> m_http_request;

    std::unique_ptr<RPCAuthData> m_auth;
    jsonrpccxx::JsonRpcClient m_client;

    // Reconnection state
    NetService m_address;
    std::string m_userpass;
    bool m_connected = false;
    std::unique_ptr<core::Timer> m_reconnect_timer;

    std::string Send(const std::string &request) override;
    nlohmann::json CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params = {});

public:
    NodeRPC(io::io_context* context, dash::interfaces::Node* coin, bool testnet);
    ~NodeRPC();

    void connect(NetService address, std::string userpass);
    void reconnect();
    void sync_reconnect();
    bool check();
    bool check_blockheader(uint256 header);

    // Parse a dashd getblocktemplate response into the rich DashWorkData (txs +
    // masternode/superblock payments + DIP3/DIP4 coinbase payload).
    DashWorkData getwork();

    void submit_block(BlockType& block, bool ignore_failure);
    // Submit a pre-serialised block passed in as a hex string (avoids re-packing)
    // -- THE dashd submitblock fallback arm. Returns true iff the daemon
    // accepted the block (result is null), false otherwise.
    bool submit_block_hex(const std::string& block_hex, bool ignore_failure);

    // RPC Methods
    // DASH: X11, no segwit -> rules are passed through plainly; no separate algo
    // param (the DGB Scrypt divergence does NOT apply). See rpc_request.hpp.
    nlohmann::json getblocktemplate(std::vector<std::string> rules = {});
    nlohmann::json getnetworkinfo();
    nlohmann::json getblockchaininfo();
    nlohmann::json getmininginfo();
    // verbose: true -- json result, false -- hex-encode result;
    nlohmann::json getblockheader(uint256 header, bool verbose = true);
    // verbosity: 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data
    nlohmann::json getblock(uint256 blockhash, int verbosity = 1);
};

struct RPCAuthData
{
    std::string authorization;
    std::string host;
};

} // namespace coin

} // namespace dash