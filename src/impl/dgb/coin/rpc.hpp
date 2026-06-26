#pragma once

// ---------------------------------------------------------------------------
// dgb::coin::NodeRPC -- external coin-RPC client (M3 transport).
//
// Real boost::beast + jsonrpccxx HTTP JSON-RPC client to an external
// digibyted, mirroring src/impl/btc/coin/rpc.{hpp,cpp}. This is the
// EXTERNAL-DAEMON FALLBACK path that V36 mandates persist alongside the
// embedded daemon (v36-master-plan external_fallback: "embedded primary,
// external fallback persists -- do NOT remove external-daemon code paths").
//
// DGB divergences from btc (conformed at port time):
//   - getblocktemplate(): DigiByte GBT requires the "segwit" rule AND a
//     separate top-level "algo" param. V36 is Scrypt-only, so the call is
//     {"rules":[...],"algo":"scrypt"}. ("scrypt" is the mining algorithm,
//     NOT a BIP9 rule -- the prior Path-A stub note rules=["scrypt"] was
//     incorrect and is fixed here.)
//   - check(): chain-identity probe uses the DigiByte genesis hash
//     (mainnet/testnet selected by IS_TESTNET), not BTC's early-block hash.
//   - WorkData is the trimmed (no m_txs) family-1 seam payload; getwork()
//     populates m_data/m_hashes/m_latency only (see rpc_data.hpp).
//
// Construction-site wiring (stub Node* -> io_context*,Node*,testnet) and the
// CMake/OBJECT-lib registration of rpc.cpp land post-#145 (the surface #145
// moves); this file + rpc.cpp are additive coin-layer source on master.
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

namespace dgb
{

namespace coin
{

struct RPCAuthData;
class NodeRPC : public jsonrpccxx::IClientConnector
{
    const std::string ID = "curltest";
    const jsonrpccxx::version RPC_VER = jsonrpccxx::version::v2;

    const bool IS_TESTNET;

    // Dev-only boot aid (off by default): when set, NodeRPC::check() relaxes the
    // DGB algo softfork gate on non-regtest, non-main chains. Never weakens the
    // gate on mainnet. See dgb::coin::compute_required_softforks.
    const bool DEV_RELAX_ALGO_SOFTFORKS;
private:
    dgb::interfaces::Node* m_coin;

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
    NodeRPC(io::io_context* context, dgb::interfaces::Node* coin, bool testnet,
            bool dev_relax_algo_softforks = false);
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
    // DGB: rules are versionbits softforks; the Scrypt algo is a separate GBT
    // param injected by the implementation (V36 Scrypt-only).
    nlohmann::json getblocktemplate(std::vector<std::string> rules);
    nlohmann::json getnetworkinfo();
	nlohmann::json getblockchaininfo();
	nlohmann::json getdeploymentinfo();
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

} // namespace dgb
