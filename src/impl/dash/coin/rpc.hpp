#pragma once

// Dashd JSON-RPC client.
// Uses Boost.Beast HTTP transport + jsonrpccxx for protocol framing.
// Modeled after src/impl/ltc/coin/rpc.{hpp,cpp} but stripped of MWEB/segwit
// and extended with Dash-specific getblocktemplate fields (masternode,
// superblock, platform payments, DIP3/DIP4 coinbase_payload).

#include "rpc_data.hpp"
#include "node_interface.hpp"

#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <nlohmann/json.hpp>
#include <jsonrpccxx/client.hpp>

#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <core/timer.hpp>

namespace dash
{
namespace coin
{

namespace io    = boost::asio;
namespace beast = boost::beast;
namespace http  = beast::http;

struct RPCAuthData {
    std::string authorization;
    std::string host;
};

class NodeRPC : public jsonrpccxx::IClientConnector
{
public:
    NodeRPC(io::io_context* context, dash::interfaces::Node* coin, bool testnet);
    ~NodeRPC() override;

    // Connect (async) to dashd's JSON-RPC endpoint.
    // userpass format: "user:password".
    void connect(NetService address, std::string userpass);

    void reconnect();
    void sync_reconnect();

    bool is_connected() const { return m_connected; }

    // Basic daemon health probe. Checks chain name + version.
    bool check();

    // ── Typed RPC wrappers ──────────────────────────────────────────────────
    nlohmann::json getblocktemplate(const std::vector<std::string>& rules);
    nlohmann::json getnetworkinfo();
    nlohmann::json getblockchaininfo();
    nlohmann::json getmininginfo();
    nlohmann::json getblockheader(const uint256& header, bool verbose = true);
    nlohmann::json getblock(const uint256& blockhash, int verbosity = 1);
    // Maps height → block hash. Used by block_dumper for the replay harness.
    nlohmann::json getblockhash(int height);

    // Fetch + parse GBT → DashWorkData (Dash-specific field extraction).
    DashWorkData getwork();

    // Submit a pre-serialized block (hex). Returns true if dashd accepted.
    bool submit_block_hex(const std::string& block_hex);

    // getpeerinfo — returns the array dashd emits (each element has
    // addr, subver, version, startingheight, inbound, conntime, ...).
    // Used by DashBroadcaster to discover peer endpoints to connect
    // to for redundant block propagation.
    nlohmann::json getpeerinfo();

    // Phase C-PAY step 3b: protx info / list — used by the DMN
    // snapshot dumper (--dump-mn-snapshot) and (in step 3b2) the
    // optional bootstrap fallback when --dashd-rpc is configured.
    //
    // protx_list_registered() returns ["proRegTxHash", ...] of all
    // currently-registered MNs. protx_info(hash) returns the full
    // protx_info JSON for a single MN (with the dmnstate.cpp:39+
    // field shape — version, registeredHeight, lastPaidHeight,
    // payoutAddress, pubKeyOperator, etc.).
    nlohmann::json protx_list_registered();
    nlohmann::json protx_info(const uint256& proRegTxHash);

private:
    // jsonrpccxx::IClientConnector contract.
    std::string Send(const std::string& request) override;

    nlohmann::json call_method(const std::string& method,
                               const jsonrpccxx::positional_parameter& params = {});

    // Normalize masternode + superblock + platform entries into PackedPayment
    // list + cumulative payment_amount. Mirrors p2pool-dash helper.py logic.
    void parse_payments(const nlohmann::json& gbt, DashWorkData& out);

    const std::string ID = "c2pool-dash-rpc";
    const jsonrpccxx::version RPC_VER = jsonrpccxx::version::v2;

    dash::interfaces::Node* m_coin;
    bool m_testnet;

    io::io_context* m_context;
    beast::tcp_stream m_stream;
    io::ip::tcp::resolver m_resolver;
    http::request<http::string_body> m_http_request;

    std::unique_ptr<RPCAuthData> m_auth;
    jsonrpccxx::JsonRpcClient m_client;

    // Reconnection state
    NetService m_address;
    std::string m_userpass;
    bool m_connected = false;
    std::unique_ptr<core::Timer> m_reconnect_timer;
};

} // namespace coin
} // namespace dash
