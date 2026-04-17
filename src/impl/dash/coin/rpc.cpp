#include "rpc.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>

#include <core/log.hpp>
#include <core/pack.hpp>
#include <btclibs/util/strencodings.h>

namespace dash
{
namespace coin
{

NodeRPC::NodeRPC(io::io_context* context, dash::interfaces::Node* coin, bool testnet)
    : m_coin(coin), m_testnet(testnet),
      m_context(context),
      m_stream(*context),
      m_resolver(*context),
      m_client(*this, RPC_VER)
{}

NodeRPC::~NodeRPC()
{
    beast::error_code ec;
    m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
    // shutdown errors on close are benign; ignore
}

void NodeRPC::connect(NetService address, std::string userpass)
{
    m_address = address;
    m_userpass = std::move(userpass);

    m_auth = std::make_unique<RPCAuthData>();
    m_http_request = {http::verb::post, "/", 11};

    m_auth->host = m_address.to_string();
    m_http_request.set(http::field::host, m_auth->host);
    m_http_request.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    m_http_request.set(http::field::content_type, "application/json");
    m_http_request.set(http::field::connection, "keep-alive");

    // Basic auth.
    std::string encoded;
    encoded.resize(beast::detail::base64::encoded_size(m_userpass.size()));
    const auto n = beast::detail::base64::encode(&encoded[0], m_userpass.data(), m_userpass.size());
    encoded.resize(n);
    m_auth->authorization = "Basic " + encoded;
    m_http_request.set(http::field::authorization, m_auth->authorization);

    m_resolver.async_resolve(m_address.address(), m_address.port_str(),
        [this](boost::system::error_code ec, io::ip::tcp::resolver::results_type results) {
            if (ec) {
                LOG_ERROR << "[DashRPC] DNS resolve failed: " << ec.message() << " (retry 15s)";
                m_reconnect_timer = std::make_unique<core::Timer>(m_context, false);
                m_reconnect_timer->start(15, [this]() { connect(m_address, m_userpass); });
                return;
            }
            io::ip::tcp::endpoint endpoint = *results.begin();
            m_stream.async_connect(endpoint, [this](boost::system::error_code ec) {
                if (ec) {
                    if (ec == boost::system::errc::operation_canceled) return;
                    LOG_ERROR << "[DashRPC] connect failed: " << ec.message();
                } else {
                    try {
                        if (check()) {
                            m_connected = true;
                            LOG_INFO << "[DashRPC] connected to " << m_address.to_string();
                            return;
                        }
                    } catch (const std::exception& e) {
                        LOG_ERROR << "[DashRPC] check() exception: " << e.what();
                    }
                }
                m_connected = false;
                m_stream.close();
                LOG_INFO << "[DashRPC] retry in 15s";
                m_reconnect_timer = std::make_unique<core::Timer>(m_context, false);
                m_reconnect_timer->start(15, [this]() { connect(m_address, m_userpass); });
            });
        });
}

void NodeRPC::reconnect()
{
    if (!m_connected) return;
    m_connected = false;
    LOG_WARNING << "[DashRPC] connection lost — reconnecting in 15s";
    m_stream.close();
    m_reconnect_timer = std::make_unique<core::Timer>(m_context, false);
    m_reconnect_timer->start(15, [this]() { connect(m_address, m_userpass); });
}

void NodeRPC::sync_reconnect()
{
    beast::error_code ec;
    m_stream.socket().shutdown(io::ip::tcp::socket::shutdown_both, ec);
    m_stream.close();

    auto results = m_resolver.resolve(m_address.address(), m_address.port_str(), ec);
    if (ec) {
        LOG_WARNING << "[DashRPC] sync_reconnect resolve: " << ec.message();
        return;
    }
    m_stream.connect(*results.begin(), ec);
    if (ec) {
        LOG_WARNING << "[DashRPC] sync_reconnect connect: " << ec.message();
        return;
    }
    LOG_INFO << "[DashRPC] reconnected (sync)";
}

std::string NodeRPC::Send(const std::string& request)
{
    for (int attempt = 0; attempt < 2; ++attempt) {
        m_http_request.body() = request;
        m_http_request.prepare_payload();
        try {
            http::write(m_stream, m_http_request);
        } catch (const std::exception& e) {
            LOG_WARNING << "[DashRPC] write failed: " << e.what()
                        << (attempt == 0 ? " — reconnecting..." : "");
            if (attempt == 0) { sync_reconnect(); continue; }
            return {};
        }

        beast::flat_buffer buffer;
        http::response<http::dynamic_body> response;
        try {
            http::read(m_stream, buffer, response);
        } catch (const std::exception& e) {
            LOG_WARNING << "[DashRPC] read failed: " << e.what()
                        << (attempt == 0 ? " — reconnecting..." : "");
            if (attempt == 0) { sync_reconnect(); continue; }
            return {};
        }

        auto body = beast::buffers_to_string(response.body().data());
        if (body.empty() && attempt == 0 && response.result_int() != 200) {
            LOG_WARNING << "[DashRPC] empty response HTTP " << response.result_int();
            sync_reconnect();
            continue;
        }
        return body;
    }
    return {};
}

nlohmann::json NodeRPC::call_method(const std::string& method,
                                     const jsonrpccxx::positional_parameter& params)
{
    return m_client.CallMethod<nlohmann::json>(ID, method, params);
}

bool NodeRPC::check()
{
    try {
        auto info = getblockchaininfo();
        auto chain = info.value("chain", std::string{});
        bool chain_ok = m_testnet
            ? (chain == "test" || chain == "testnet")
            : (chain == "main");
        if (!chain_ok) {
            LOG_ERROR << "[DashRPC] chain mismatch: daemon reports '" << chain
                      << "' but testnet=" << m_testnet;
            return false;
        }

        auto netinfo = getnetworkinfo();
        int version = netinfo.value("version", 0);
        // Dash Core 19.x = 190000, 20.x = 200000, 23.x = 230000
        if (version < 180000) {
            LOG_ERROR << "[DashRPC] dashd too old: version=" << version << " (need >=18.0)";
            return false;
        }
        LOG_INFO << "[DashRPC] daemon v" << version << " chain=" << chain;
        return true;
    } catch (const jsonrpccxx::JsonRpcException& e) {
        LOG_WARNING << "[DashRPC] check() exception: " << e.what();
        return false;
    }
}

// ── RPC wrappers ─────────────────────────────────────────────────────────────

nlohmann::json NodeRPC::getblocktemplate(const std::vector<std::string>& rules)
{
    // Dash v20+ requires a versionbits "rules" array. Empty rules works for
    // "long polling not supported" probes; passing typical rule list is safer.
    nlohmann::json params = nlohmann::json::object({{"rules", rules}});
    return call_method("getblocktemplate", {params});
}

nlohmann::json NodeRPC::getnetworkinfo()       { return call_method("getnetworkinfo"); }
nlohmann::json NodeRPC::getblockchaininfo()    { return call_method("getblockchaininfo"); }
nlohmann::json NodeRPC::getmininginfo()        { return call_method("getmininginfo"); }

nlohmann::json NodeRPC::getblockheader(const uint256& header, bool verbose)
{
    return call_method("getblockheader", {header, verbose});
}

nlohmann::json NodeRPC::getblock(const uint256& blockhash, int verbosity)
{
    return call_method("getblock", {blockhash, verbosity});
}

// ── Dash GBT parsing ─────────────────────────────────────────────────────────

void NodeRPC::parse_payments(const nlohmann::json& gbt, DashWorkData& out)
{
    out.m_packed_payments.clear();
    out.m_payment_amount = 0;

    auto collect = [&](const nlohmann::json& obj) {
        if (!obj.is_object()) return;
        uint64_t amount = obj.value("amount", uint64_t{0});
        if (amount == 0) return;
        out.m_payment_amount += amount;

        PackedPayment p;
        p.amount = amount;

        auto payee_it = obj.find("payee");
        if (payee_it != obj.end() && payee_it->is_string() && !payee_it->get<std::string>().empty()) {
            p.payee = payee_it->get<std::string>();
            out.m_packed_payments.push_back(std::move(p));
            return;
        }
        auto script_it = obj.find("script");
        if (script_it != obj.end() && script_it->is_string() && !script_it->get<std::string>().empty()) {
            // Script-only (e.g. platform OP_RETURN). "!" prefix is outside
            // base58 alphabet, signaling to downstream code that payee is raw
            // hex script, not an address.
            p.payee = std::string("!") + script_it->get<std::string>();
            out.m_packed_payments.push_back(std::move(p));
        }
    };

    auto mn_it = gbt.find("masternode");
    if (mn_it != gbt.end()) {
        if (mn_it->is_array()) {
            for (const auto& e : *mn_it) collect(e);
        } else if (mn_it->is_object()) {
            collect(*mn_it);
        }
    }

    auto sb_it = gbt.find("superblock");
    if (sb_it != gbt.end() && sb_it->is_array()) {
        for (const auto& e : *sb_it) collect(e);
    }
}

DashWorkData NodeRPC::getwork()
{
    auto t0 = std::chrono::steady_clock::now();
    auto gbt = getblocktemplate({"segwit"}); // Dash ignores segwit but some
                                             // daemons require any rules entry.
    auto t1 = std::chrono::steady_clock::now();

    DashWorkData out;
    out.m_raw    = gbt;
    out.m_latency = std::chrono::duration_cast<std::chrono::seconds>(t1 - t0).count();

    out.m_version        = gbt.value("version", 0);
    out.m_height         = gbt.value("height", 0u);
    out.m_coinbase_value = gbt.value("coinbasevalue", uint64_t{0});
    out.m_curtime        = gbt.value("curtime", gbt.value("time", 0u));
    out.m_mintime        = gbt.value("mintime", 0u);

    if (gbt.contains("previousblockhash"))
        out.m_previous_block.SetHex(gbt["previousblockhash"].get<std::string>());

    if (gbt.contains("bits")) {
        // bits is a hex string in GBT.
        auto bits_hex = gbt["bits"].get<std::string>();
        out.m_bits = static_cast<uint32_t>(std::stoul(bits_hex, nullptr, 16));
    }

    if (gbt.contains("coinbaseflags") && gbt["coinbaseflags"].is_string()) {
        out.m_coinbase_flags_hex = gbt["coinbaseflags"].get<std::string>();
    } else if (gbt.contains("coinbaseaux") && gbt["coinbaseaux"].is_object()) {
        std::string joined;
        for (auto& [k, v] : gbt["coinbaseaux"].items()) {
            if (v.is_string()) joined += v.get<std::string>();
        }
        out.m_coinbase_flags_hex = std::move(joined);
    }

    // Transactions: keep txid, fee, and raw hex (for block submission later).
    if (gbt.contains("transactions") && gbt["transactions"].is_array()) {
        for (const auto& tx_entry : gbt["transactions"]) {
            uint64_t fee = tx_entry.is_object() ? tx_entry.value("fee", uint64_t{0}) : 0;
            out.m_tx_fees.push_back(fee);

            if (tx_entry.is_object() && tx_entry.contains("txid")) {
                uint256 h;
                h.SetHex(tx_entry["txid"].get<std::string>());
                out.m_tx_hashes.push_back(h);
            } else if (tx_entry.is_object() && tx_entry.contains("hash")) {
                uint256 h;
                h.SetHex(tx_entry["hash"].get<std::string>());
                out.m_tx_hashes.push_back(h);
            }

            if (tx_entry.is_object() && tx_entry.contains("data") && tx_entry["data"].is_string()) {
                out.m_tx_data_hex.push_back(tx_entry["data"].get<std::string>());
            } else if (tx_entry.is_string()) {
                out.m_tx_data_hex.push_back(tx_entry.get<std::string>());
            } else {
                out.m_tx_data_hex.emplace_back();
            }
        }
    }

    parse_payments(gbt, out);

    if (gbt.contains("coinbase_payload") && gbt["coinbase_payload"].is_string()) {
        auto hex = gbt["coinbase_payload"].get<std::string>();
        if (!hex.empty()) {
            out.m_coinbase_payload = ParseHex(hex);
        }
    }

    return out;
}

bool NodeRPC::submit_block_hex(const std::string& block_hex)
{
    auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {block_hex});
    bool success = result.is_null();
    if (success) {
        LOG_INFO << "[DashRPC] submitblock accepted";
    } else {
        LOG_ERROR << "[DashRPC] submitblock rejected: " << result.dump();
    }
    return success;
}

} // namespace coin
} // namespace dash
