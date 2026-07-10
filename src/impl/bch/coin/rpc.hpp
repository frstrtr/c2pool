// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// bch::coin::NodeRPC -- external coin-RPC client for BCH. Declaration ported
// from src/impl/btc/coin/rpc.hpp; the bch::interfaces::Node aggregate and the
// bch::coin::{BlockType, rpc::WorkData} ports (M3 slices 1-3) supply its types.
//
// >>> SCOPE (M3 slice 4) <<<
// This lands the NodeRPC *declaration* only, so the concrete CoinNode seam
// (coin_node.{hpp,cpp}) can name NodeRPC* and call getwork()/submit_block_hex().
// The network BODY (rpc.cpp) is the NEXT slice -- it carries the BCH-divergent
// bits that have no 1:1 BTC mirror and must be authored, not copied:
//   - getblocktemplate rules: BCH has NO "segwit"/witness rule; the GBT rule
//     set and version-bits differ from BTC Core.
//   - softfork_check.hpp: BCH activations (ASERT DAA Nov-2020, CTOR Nov-2018,
//     CashTokens+P2SH32 May-2023, ABLA CHIP-2023-01 May-2024) -- NOT BIP9.
//   - block header / getblock(header) parsing per BCH consensus.
//   - CashTokens-bearing outputs round-trip transparently (template carry).
// rpc.cpp also pulls impl/bch/config_pool.hpp + impl/bch/coin/softfork_check.hpp,
// neither of which is ported yet -- both are prerequisites of that next slice.
//
// Source-only; impl_bch stays unregistered in CMake (bch = skip-green).
// ---------------------------------------------------------------------------

#include "block.hpp"
#include "rpc_data.hpp"
#include "node_interface.hpp"

#include <iostream>

#include <core/uint256.hpp>
#include <core/timer.hpp>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <jsonrpccxx/client.hpp>

namespace io = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

namespace bch
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
    bch::interfaces::Node* m_coin;

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
    NodeRPC(io::io_context* context, bch::interfaces::Node* coin, bool testnet);
    ~NodeRPC();

    void connect(NetService address, std::string userpass);
    void reconnect();
    void sync_reconnect();
    bool check();
    bool check_blockheader(uint256 header);
    rpc::WorkData getwork();
    void submit_block(BlockType& block, bool ignore_failure);
    // Submit a pre-serialised block passed in as a hex string (avoids re-packing)
    // Returns true if the daemon accepted the block (result is null), false otherwise.
    bool submit_block_hex(const std::string& block_hex, bool ignore_failure);

    // RPC Methods
    nlohmann::json getblocktemplate(std::vector<std::string> rules);
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

} // namespace bch