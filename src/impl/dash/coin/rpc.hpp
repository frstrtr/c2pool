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

#include <functional>
#include <iostream>
#include <mutex>

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
    // Serializes Send() (verbatim LTC parity, impl/ltc/coin/rpc.hpp:43-47).
    // io-thread-decouple drives this ONE shared client from TWO threads: the
    // stratum io_context thread (getwork() during a template re-source, and ARM
    // B submit_block_hex on a won block) AND the background rpc_pool thread (the
    // tip poll's getbestblockhash + the single-flight GBT refresh). m_http_request
    // + m_stream are NOT thread-safe: without this lock one thread's
    // prepare_payload() frees the Content-Length field element mid-write on the
    // other -> UAF / interleaved HTTP frames / cross-wired responses (a garbled
    // submitblock = lost block on the paying node). The lock also serializes the
    // sync_reconnect() retry path, which is only ever entered from inside Send().
    std::mutex m_rpc_mutex;

    std::unique_ptr<RPCAuthData> m_auth;
    jsonrpccxx::JsonRpcClient m_client;

    // Reconnection state
    NetService m_address;
    std::string m_userpass;
    bool m_connected = false;
    std::unique_ptr<core::Timer> m_reconnect_timer;
    // Reconnect-churn observer (stale-payee fix): fired whenever the RPC
    // connection is torn down / re-established (reconnect(), sync_reconnect()).
    // main_dash.cpp wires this to DASHWorkSource::invalidate_template_cache()
    // so no stratum job is ever served or submitted from a template/masternode
    // payee cached from BEFORE the churn window. Assigned once at startup,
    // before the io loop runs.
    std::function<void()> m_on_reconnect;

    std::string Send(const std::string &request) override;
    nlohmann::json CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params = {});

    // io-thread-decouple: a REAL deadline on the synchronous Send() I/O so a
    // wedged-but-connected dashd (socket open, no bytes) cannot hang the caller
    // forever -- which on the background rpc_pool thread would wedge
    // template_refresh_inflight_ true (permanent set-gap after the next tip
    // change), stop the tip-poll re-arming, AND block rpc_pool->join() at
    // shutdown (SIGKILL needed). beast's SYNCHRONOUS read_some/write_some call
    // socket.read_some() directly and do NOT honour tcp_stream::expires_after
    // (that timer only fires for ASYNC ops -- basic_stream.hpp), so the robust
    // bound is a kernel SO_RCV/SNDTIMEO on the socket forced back to BLOCKING
    // mode (async_connect leaves asio's non_blocking flag set, under which
    // SO_*TIMEO is a no-op). apply_socket_timeouts() does both; it is called
    // after every successful (re)connect. Linux release target.
    static constexpr int RPC_IO_TIMEOUT_SECONDS = 12;
    void apply_socket_timeouts();

public:
    NodeRPC(io::io_context* context, dash::interfaces::Node* coin, bool testnet);
    ~NodeRPC();

    void connect(NetService address, std::string userpass);
    void reconnect();
    void sync_reconnect();
    /// Register the reconnect-churn observer (see m_on_reconnect). Call once
    /// at startup before the io loop runs.
    void set_on_reconnect(std::function<void()> fn) { m_on_reconnect = std::move(fn); }
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
    // Trivial tip probe: the current best-block hash as a hex string. Used by
    // the fallback-arm tip poller (main_dash.cpp) to drive event-driven
    // template refresh without waiting on the 30 s staleness TTL. Empty string
    // on a null/absent result.
    std::string getbestblockhash();
    // verbose: true -- json result, false -- hex-encode result;
    nlohmann::json getblockheader(uint256 header, bool verbose = true);
    // verbosity: 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data
    nlohmann::json getblock(uint256 blockhash, int verbosity = 1);
    // E2c (#738): `protx list valid true` -- the full valid deterministic-MN
    // set at the current tip in the DETAILED shape (state.payoutAddress +
    // lastPaidHeight + registeredHeight + PoSe heights). This is the
    // payout-bearing MN-set SEED source for the embedded arm; the P2P
    // Simplified MN List omits scriptPayout/lastPaidHeight so it can never
    // back this. See coin/mn_seed.hpp (parse_protx_list_seed).
    nlohmann::json protx_list_valid_detailed();
};

struct RPCAuthData
{
    std::string authorization;
    std::string host;
};

} // namespace coin

} // namespace dash