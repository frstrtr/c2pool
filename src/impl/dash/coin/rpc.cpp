// SPDX-License-Identifier: AGPL-3.0-or-later
#include "rpc.hpp"

#include <impl/dash/coin/rpc_request.hpp>

#include <core/log.hpp>
#include <core/hash.hpp>
#include <core/core_util.hpp>    // core::timestamp() (getwork latency)

#include <util/strencodings.h>   // ParseHex / HexStr

namespace dash
{

namespace coin
{

// DASH chain-identity genesis hashes, DASH_MIN_DAEMON_VERSION and
// make_gbt_request: see impl/dash/coin/rpc_request.hpp (oracle/identity SSOT).
// check() probes getblockheader(dash_genesis_hash(IS_TESTNET)) to confirm the
// daemon is a real dashd on the selected network.

NodeRPC::NodeRPC(io::io_context* context, dash::interfaces::Node* coin, bool testnet)
    : IS_TESTNET(testnet), m_coin(coin), m_context(context), m_stream(*context),
      m_resolver(*context), m_client(*this, RPC_VER)
{
}

void NodeRPC::connect(NetService address, std::string userpass)
{
    m_address = address;
    m_userpass = userpass;

    m_auth = std::make_unique<RPCAuthData>();
    m_http_request = {http::verb::post, "/", 11};

    m_auth->host = address.to_string();
    m_http_request.set(http::field::host, m_auth->host);

    m_http_request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    m_http_request.set(http::field::content_type, "application/json");
    m_http_request.set(http::field::connection, "keep-alive");

    std::string encoded_login2;
    encoded_login2.resize(boost::beast::detail::base64::encoded_size(userpass.size()));
    const auto result = boost::beast::detail::base64::encode(&encoded_login2[0], userpass.data(), userpass.size());
    encoded_login2.resize(result);
    m_auth->authorization = "Basic " + encoded_login2;

    m_http_request.set(http::field::authorization, m_auth->authorization);

    // Async DNS resolve — must NOT use the blocking m_resolver.resolve() overload
    // as that stalls the entire io_context thread for the DNS round-trip.
    m_resolver.async_resolve(address.address(), address.port_str(),
        [this](boost::system::error_code ec, boost::asio::ip::tcp::resolver::results_type results)
        {
            if (ec)
            {
                LOG_ERROR << "CoindRPC DNS resolve failed: " << ec.message() << ", retrying in 15s";
                m_reconnect_timer = std::make_unique<core::Timer>(m_context, false);
                m_reconnect_timer->start(15, [this]() { connect(m_address, m_userpass); });
                return;
            }
            boost::asio::ip::tcp::endpoint endpoint = *results.begin();
            m_stream.async_connect(endpoint,
                [this](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        if (ec == boost::system::errc::operation_canceled)
                            return;

                        LOG_ERROR << "CoindRPC error when try connect: [" << ec.message() << "].";
                    } else
                    {
                        try
                        {
                            if (check())
                            {
                                m_connected = true;
                                LOG_INFO << "...CoindRPC connected!";
                                return;
                            }
                        }
                        catch(const std::runtime_error& ec)
                        {
                            LOG_ERROR << "Error when try check CoindRPC: " << ec.what();
                        }
                    }

                    LOG_INFO << "Retry after 15 seconds...";
                    m_connected = false;
                    m_stream.close();
                    m_reconnect_timer = std::make_unique<core::Timer>(m_context, false);
                    m_reconnect_timer->start(15, [this]() { connect(m_address, m_userpass); });
                }
            );
        });
}

NodeRPC::~NodeRPC()
{
    beast::error_code ec;
    m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
    if (ec)
    {
        // shutdown errors on close are typically benign; ignore
    }
}

void NodeRPC::reconnect()
{
    if (!m_connected)
        return;  // already reconnecting or never connected
    m_connected = false;
    LOG_WARNING << "RPC connection lost — reconnecting in 15 seconds...";
    m_stream.close();
    // Stale-payee fix: the connection churned — anything cached from before
    // this point (template / masternode payee) must not be served or
    // submitted. Notify the observer (DASHWorkSource cache invalidation).
    if (m_on_reconnect)
        m_on_reconnect();
    m_reconnect_timer = std::make_unique<core::Timer>(m_context, false);
    m_reconnect_timer->start(15, [this]() { connect(m_address, m_userpass); });
}

void NodeRPC::sync_reconnect()
{
    // Stale-payee fix: fire the churn observer FIRST — the caller (Send) is
    // about to retry against a fresh connection; any template cached from the
    // dead connection's era is suspect and must be invalidated.
    if (m_on_reconnect)
        m_on_reconnect();

    beast::error_code ec;
    m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
    m_stream.close();

    // Blocking resolve + connect for immediate retry
    auto results = m_resolver.resolve(m_address.address(), m_address.port_str(), ec);
    if (ec) {
        LOG_WARNING << "CoindRPC sync_reconnect resolve failed: " << ec.message();
        return;
    }
    m_stream.connect(*results.begin(), ec);
    if (ec) {
        LOG_WARNING << "CoindRPC sync_reconnect connect failed: " << ec.message();
        return;
    }
    LOG_INFO << "CoindRPC reconnected (sync)";
}

std::string NodeRPC::Send(const std::string &request)
{
    // Retry once after synchronous reconnect on write/read failure
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        m_http_request.body() = request;
        m_http_request.prepare_payload();
        try
        {
            http::write(m_stream, m_http_request);
        }
        catch(const std::exception& e)
        {
            LOG_WARNING << "CoindRPC write failed: " << e.what()
                        << (attempt == 0 ? " — reconnecting..." : "");
            if (attempt == 0) {
                sync_reconnect();
                continue;
            }
            return {};
        }

        beast::flat_buffer buffer;
        boost::beast::http::response<boost::beast::http::dynamic_body> response;

        try
        {
            boost::beast::http::read(m_stream, buffer, response);
        }
        catch (const std::exception& ex)
        {
            LOG_WARNING << "CoindRPC read failed: " << ex.what()
                        << (attempt == 0 ? " — reconnecting..." : "");
            if (attempt == 0) {
                sync_reconnect();
                continue;
            }
            return {};
        }

        auto body = boost::beast::buffers_to_string(response.body().data());
        if (body.empty()) {
            static int _empty_count = 0;
            if (_empty_count++ < 5)
                LOG_WARNING << "CoindRPC empty response: HTTP " << response.result_int()
                            << " content-length=" << response[http::field::content_length]
                            << " connection=" << response[http::field::connection];
            if (attempt == 0 && response.result_int() != 200) {
                sync_reconnect();
                continue;
            }
        }
        return body;
    }
    return {};
}

nlohmann::json NodeRPC::CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params)
{
    return m_client.CallMethod<nlohmann::json>(ID, method, params);
}

bool NodeRPC::check()
{
    uint256 genesis = uint256S(dash_genesis_hash(IS_TESTNET));
    bool has_block = check_blockheader(genesis);
    bool is_main_chain = getblockchaininfo()["chain"].get<std::string>() == "main";

    if (is_main_chain && !has_block)
    {
        LOG_ERROR << "Check failed! Make sure that you're connected to the right dashd with --dash-rpc-port, and that it has finished syncing!" << std::endl;
        return false;
    }

    try
    {
        auto networkinfo = getnetworkinfo();
        bool version_check_result = daemon_version_acceptable(networkinfo["version"].get<int>());
        if (!version_check_result)
        {
            LOG_ERROR << "Dash daemon too old! Upgrade!";
            return false;
        }
    } catch (const jsonrpccxx::JsonRpcException& ex)
    {
        LOG_WARNING << "NodeRPC::check() exception: " << ex.what();
        return false;
    }

    // DASH older-than-v35 baseline has NO segwit and no required-softfork gate
    // (params.hpp: softforks_required == {}). Unlike DGB (reservealgo/odo/
    // nversionbips), DASH carries no startup-readiness softfork requirement set,
    // so the genesis-identity + version-floor probe above is the full check.
    return true;
}

bool NodeRPC::check_blockheader(uint256 header)
{
    try
    {
        getblockheader(header);
        return true;
    } catch (const jsonrpccxx::JsonRpcException& ex)
    {
        return false;
    }
}

DashWorkData NodeRPC::getwork()
{
    auto start = core::timestamp();
    // DASH: X11, no segwit -> plain rules (no "algo", no injected "segwit").
    auto work = getblocktemplate({});
    auto end = core::timestamp();

    DashWorkData w;
    w.m_raw = work;

    // ----- Standard Bitcoin-family fields -----
    if (work.contains("version"))        w.m_version        = work["version"].get<int32_t>();
    if (work.contains("previousblockhash"))
        w.m_previous_block = uint256S(work["previousblockhash"].get<std::string>());
    if (work.contains("coinbasevalue"))  w.m_coinbase_value = work["coinbasevalue"].get<uint64_t>();
    if (work.contains("curtime"))        w.m_curtime        = work["curtime"].get<uint32_t>();
    if (work.contains("mintime"))        w.m_mintime        = work["mintime"].get<uint32_t>();
    if (work.contains("coinbaseaux") && work["coinbaseaux"].contains("flags"))
        w.m_coinbase_flags_hex = work["coinbaseaux"]["flags"].get<std::string>();
    if (work.contains("bits"))
    {
        // GBT "bits" is a hex string (compact nBits).
        w.m_bits = static_cast<uint32_t>(std::stoul(work["bits"].get<std::string>(), nullptr, 16));
    }

    // Height: prefer GBT's, else previous block + 1.
    if (work.contains("height"))
        w.m_height = work["height"].get<uint32_t>();
    else if (work.contains("previousblockhash"))
        w.m_height = getblock(w.m_previous_block)["height"].get<uint32_t>() + 1;

    // ----- Transactions (full parse + raw hex + txid + fees) -----
    if (work.contains("transactions"))
    {
        for (auto& packed_tx : work["transactions"])
        {
            std::string data_hex;
            if (packed_tx.is_object() && packed_tx.contains("data"))
                data_hex = packed_tx["data"].get<std::string>();
            else if (packed_tx.is_string())
                data_hex = packed_tx.get<std::string>();
            if (data_hex.empty())
                continue;

            w.m_tx_data_hex.push_back(data_hex);

            // Deserialize into a full MutableTransaction (DASH tx codec handles
            // the version|(type<<16) field + DIP3/DIP4 special-tx payload).
            MutableTransaction mtx;
            try
            {
                PackStream ps_tx(ParseHex(data_hex));
                ps_tx >> mtx;
            }
            catch (const std::exception& ex)
            {
                LOG_WARNING << "getwork: tx deserialize failed: " << ex.what();
            }
            w.m_txs.emplace_back(mtx);   // Transaction(MutableTransaction) is explicit

            // txid: prefer GBT's "txid" field, else recompute (DASH non-witness
            // canonical serialization == dash_txid).
            uint256 txid;
            if (packed_tx.is_object() && packed_tx.contains("txid"))
                txid = uint256S(packed_tx["txid"].get<std::string>());
            else
            {
                PackStream ps_id(ParseHex(data_hex));
                txid = Hash(ps_id.get_span());
            }
            w.m_tx_hashes.push_back(txid);

            uint64_t fee = 0;
            if (packed_tx.is_object() && packed_tx.contains("fee"))
                fee = packed_tx["fee"].get<uint64_t>();
            w.m_tx_fees.push_back(fee);
        }
    }

    // ----- DASH masternode + superblock + platform payments -----
    // Normalize into m_packed_payments in the EXACT coinbase-output order, using
    // the same "!hex" raw-script / base58-address payee convention that
    // coin/embedded_gbt.hpp::gbt_xcheck compares the embedded build against.
    //
    // dashd GBT carries these as either:
    //   - the v0.13+ "masternode" array (objects {payee, script, amount}) and
    //     "superblock" array (same shape), and/or
    //   - the legacy single-object "masternode"/"payee"+"payee_amount" fields.
    // We accept both shapes. Platform credit-pool OP_RETURN burns surface as a
    // payee with an empty/"6a" script -> normalized to "!6a".
    auto push_payment = [&w](const nlohmann::json& entry) {
        // bad-cb-payee fix: empty payee strings normalize to the raw "!"+script
        // form (see rpc_data.hpp::normalize_payment) instead of being dropped.
        PackedPayment pp = normalize_payment(entry);
        if (pp.amount == 0)
            return;
        w.m_packed_payments.push_back(std::move(pp));
        w.m_payment_amount += w.m_packed_payments.back().amount;
    };

    // Platform credit-pool OP_RETURN burn FIRST (dashcore GetBlockTxOuts order).
    if (work.contains("coinbase_payload_burn"))
    {
        PackedPayment burn;
        burn.payee  = "!6a";
        burn.amount = work["coinbase_payload_burn"].get<uint64_t>();
        if (burn.amount > 0)
        {
            w.m_packed_payments.push_back(std::move(burn));
            w.m_payment_amount += w.m_packed_payments.back().amount;
        }
    }

    if (work.contains("masternode"))
    {
        if (work["masternode"].is_array())
            for (auto& e : work["masternode"]) push_payment(e);
        else if (work["masternode"].is_object())
            push_payment(work["masternode"]);
    }
    if (work.contains("superblock") && work["superblock"].is_array())
        for (auto& e : work["superblock"]) push_payment(e);

    // ----- DIP3/DIP4 coinbase extra payload -----
    if (work.contains("coinbase_payload") && work["coinbase_payload"].is_string())
    {
        auto payload = ParseHex(work["coinbase_payload"].get<std::string>());
        w.m_coinbase_payload.assign(payload.begin(), payload.end());
    }

    w.m_latency = end - start;
    return w;
}

void NodeRPC::submit_block(BlockType& block, bool ignore_failure)
{
    // DASH is non-segwit, non-MWEB: full-block packing is the plain block codec.
    // NOTE: BlockType transaction-aware (de)serialization of m_txs is the S5
    // deferral (coin/block.hpp); until that lands, the hex submit arm
    // (submit_block_hex) carrying a fully-assembled block is the live won-block
    // RPC path. This typed overload packs the header form.
    PackStream packed_block = pack<dash::coin::BlockType>(block);
    auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {HexStr(packed_block.get_span())});
    bool success = result.is_null();

    auto success_expected = true;

    if ((!success && success_expected && !ignore_failure) || (success && !success_expected))
        LOG_ERROR << "Block submittal result: " << success << "(" << result.dump() << ") Expected: " << success_expected;
}

bool NodeRPC::submit_block_hex(const std::string& block_hex, bool ignore_failure)
{
    auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {block_hex});
    bool success = result.is_null();
    if (!success && !ignore_failure)
        LOG_ERROR << "submit_block_hex result: " << result.dump();
    else if (success)
        LOG_INFO << "submit_block_hex accepted";
    return success;
}

// RPC Methods

nlohmann::json NodeRPC::getblocktemplate(std::vector<std::string> rules)
{
    // Body shape (plain rules, NO algo, NO injected segwit) is the
    // rpc_request.hpp SSOT -- the key DASH<->DGB divergence.
    return CallAPIMethod("getblocktemplate", {make_gbt_request(rules)});
}

std::string NodeRPC::propose_block_hex(const std::string& block_hex)
{
    // getblocktemplate {mode:proposal, data:<blockhex>} runs dashd's
    // TestBlockValidity on the exact block and returns null on ACCEPT or a
    // reject-reason string. This is the ORACLE-SHADOW authoritative VERDICT
    // (mempool-independent). Never throws to the caller: an RPC-layer error is
    // surfaced as a reason string so a transient RPC blip is not read as a
    // consensus rejection.
    try {
        nlohmann::json req;
        req["mode"] = "proposal";
        req["data"] = block_hex;
        auto res = CallAPIMethod("getblocktemplate", {req});
        if (res.is_null()) return {};                 // ACCEPTED
        if (res.is_string()) return res.get<std::string>();
        return res.dump();
    } catch (const std::exception& e) {
        return std::string("rpc-error:") + e.what();
    }
}

nlohmann::json NodeRPC::getnetworkinfo()
{
    return CallAPIMethod("getnetworkinfo");
}

nlohmann::json NodeRPC::getblockchaininfo()
{
    return CallAPIMethod("getblockchaininfo");
}

nlohmann::json NodeRPC::getmininginfo()
{
    return CallAPIMethod("getmininginfo");
}

// Trivial tip probe -- `getbestblockhash` returns the best-block hash as a bare
// JSON string. Returns "" if the daemon result is null/absent (never throws on
// a well-formed-but-empty result; transport errors still propagate to the
// caller, which swallows them). No dashd config change is required.
std::string NodeRPC::getbestblockhash()
{
    auto result = CallAPIMethod("getbestblockhash");
    if (result.is_string())
        return result.get<std::string>();
    return {};
}

// verbose: true -- json result, false -- hex-encode result;
nlohmann::json NodeRPC::getblockheader(uint256 header, bool verbose)
{
    return CallAPIMethod("getblockheader", {header, verbose});
}

// verbosity: 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data
nlohmann::json NodeRPC::getblock(uint256 blockhash, int verbosity)
{
    return CallAPIMethod("getblock", {blockhash, verbosity});
}

// E2c (#738): the MN-set seed fetch. `protx list valid true` returns every
// registered, non-PoSe-banned masternode at the current tip with the detailed
// per-MN state (payoutAddress, lastPaidHeight, registeredHeight, PoSe
// heights, pubKeyOperator, ...). Chosen over `protx diff`: the diff (even
// extended) carries payoutAddress but NOT lastPaidHeight/registeredHeight, so
// a diff-seeded set would rank every MN equal in GetMNPayee ordering and
// project the WRONG payee (the bad-cb-payee class #746 fixed).
nlohmann::json NodeRPC::protx_list_valid_detailed()
{
    return CallAPIMethod("protx", {"list", "valid", true});
}

} // namespace coin

} // namespace dash