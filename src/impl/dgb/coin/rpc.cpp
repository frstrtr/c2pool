#include "rpc.hpp"

#include <impl/dgb/config_pool.hpp>
#include <impl/dgb/coin/softfork_check.hpp>
#include <impl/dgb/coin/rpc_request.hpp>

#include <core/log.hpp>
#include <core/hash.hpp>
namespace dgb
{

namespace coin
{

// DGB chain-identity genesis hashes, DGB_MIN_DAEMON_VERSION and
// make_gbt_request: see impl/dgb/coin/rpc_request.hpp (oracle/identity SSOT).
// check() probes getblockheader(dgb_genesis_hash(IS_TESTNET)) to confirm the
// daemon is a real digibyted on the selected network.

NodeRPC::NodeRPC(io::io_context* context, dgb::interfaces::Node* coin, bool testnet)
    : m_context(context), IS_TESTNET(testnet), m_resolver(*context), m_stream(*context),
	  m_client(*this, RPC_VER), m_coin(coin)
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
	m_reconnect_timer = std::make_unique<core::Timer>(m_context, false);
	m_reconnect_timer->start(15, [this]() { connect(m_address, m_userpass); });
}

void NodeRPC::sync_reconnect()
{
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
	uint256 genesis = uint256S(dgb_genesis_hash(IS_TESTNET));
	bool has_block = check_blockheader(genesis);
	bool is_main_chain = getblockchaininfo()["chain"].get<std::string>() == "main";
	nlohmann::json blockchaininfo;

	if (is_main_chain && !has_block)
	{
		LOG_ERROR << "Check failed! Make sure that you're connected to the right digibyted with --digibyte-rpc-port, and that it has finished syncing!" << std::endl;
		return false;
	}

	try
    {
		auto networkinfo = getnetworkinfo();
		bool version_check_result = daemon_version_acceptable(networkinfo["version"].get<int>());
		if (!version_check_result)
		{
			LOG_ERROR << "DigiByte daemon too old! Upgrade!";
			return false;
		}
	} catch (const jsonrpccxx::JsonRpcException& ex)
    {
        LOG_WARNING << "NodeRPC::check() exception: " << ex.what();
		return false;
    }

    try
    {
	    blockchaininfo = getblockchaininfo();
    } catch (const jsonrpccxx::JsonRpcException& ex)
    {
        return false;
    }

	std::set<std::string> softforks_supported;

	if (blockchaininfo.contains("softforks"))
		dgb::coin::collect_softfork_names(blockchaininfo["softforks"], softforks_supported);
	if (blockchaininfo.contains("bip9_softforks"))
		dgb::coin::collect_softfork_names(blockchaininfo["bip9_softforks"], softforks_supported);

	// DigiByte Core 8.26.2 (Bitcoin Core 26 base) no longer reports softfork
	// status under getblockchaininfo["softforks"]; it moved to the dedicated
	// getdeploymentinfo RPC. Read it when the legacy fields are absent so the
	// readiness gate sees the real deployment set on Core-26 daemons (whose
	// young chains otherwise expose only csv/segwit via GBT rules).
	if (softforks_supported.empty())
	{
		try
		{
			dgb::coin::collect_deployment_names(getdeploymentinfo(), softforks_supported);
		}
		catch (const std::exception&)
		{
			// Older daemons lack getdeploymentinfo; fall through to GBT rules.
		}
	}

	// Fallback for daemons that don't populate getblockchaininfo softfork fields.
	if (softforks_supported.empty())
	{
		try
		{
			auto gbt = getblocktemplate({"segwit"});
			if (gbt.contains("rules") && gbt["rules"].is_array())
			{
				for (const auto& rule : gbt["rules"])
				{
					if (!rule.is_string()) continue;
					auto r = rule.get<std::string>();
					if (!r.empty() && r[0] == '!') r.erase(r.begin());
					softforks_supported.insert(r);
				}
			}
		}
		catch (const std::exception&)
		{
			// Keep empty set; missing forks check below will fail safely.
		}
	}

	// Regtest does not deploy the DGB-specific algo softforks (reservealgo, odo)
	// nor nversionbips — those are mainnet/testnet deployments, so a regtest
	// digibyted legitimately signals only csv/segwit/taproot. Gating startup on
	// deployments the connected chain cannot carry would make the regtest
	// won-block path (and CI against regtest) impossible to start, with no
	// consensus benefit. Relax ONLY on regtest; mainnet/testnet keep the full
	// SSOT requirement set. Non-consensus startup readiness gate only.
	std::set<std::string> required = dgb::PoolConfig::SOFTFORKS_REQUIRED;
	if (blockchaininfo.value("chain", std::string{}) == "regtest")
	{
		for (const char* algo_fork : {"reservealgo", "odo", "nversionbips"})
			required.erase(algo_fork);
	}

	std::vector<std::string> missing;
	for (const auto& req : required)
	{
		if (!softforks_supported.contains(req))
			missing.push_back(req);
	}

	if (!missing.empty())
	{
		std::string joined;
		for (size_t i = 0; i < missing.size(); ++i)
		{
			if (i) joined += ", ";
			joined += missing[i];
		}
		LOG_ERROR << "DigiByte daemon missing required softfork features: " << joined;
		LOG_ERROR << "Refusing to start to avoid mining invalid/non-consensus blocks.";
		return false;
	}

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

rpc::WorkData NodeRPC::getwork()
{
	auto start = core::timestamp();
	// DGB: Scrypt-only template. "segwit" is the BIP9 rule; the Scrypt algo
	// is injected as the separate "algo" GBT param by getblocktemplate().
	auto work = getblocktemplate({"segwit"});
	auto end = core::timestamp();

	if (!m_coin->txidcache.is_started())
		m_coin->txidcache.start();

	// DGB family-1 seam carries txhashes only (WorkData is trimmed; no m_txs
	// until the coin/transaction work re-homes it -- see rpc_data.hpp). The
	// merkle tree uses the non-witness txid: prefer GBT's "txid" field, else
	// hash the stripped "data" with the txidcache.
	std::vector<uint256> txhashes;
    for (auto& packed_tx : work["transactions"])
    {
        PackStream ps_tx;

        uint256 txid;
		std::string x;

        if (packed_tx.contains("data"))
            x = packed_tx["data"].get<std::string>();
        else
            x = packed_tx.get<std::string>();

        if (packed_tx.is_object() && packed_tx.contains("txid")) {
            txid.SetHex(packed_tx["txid"].get<std::string>());
            txhashes.push_back(txid);
        } else if (m_coin->txidcache.exist(x))
        {
            txid = m_coin->txidcache.get(x);
            txhashes.push_back(txid);
        } else
        {
            ps_tx = PackStream(ParseHex(x));
            txid = Hash(ps_tx.get_span());
			m_coin->txidcache.add(x, txid);
			txhashes.push_back(txid);
        }
    }

	if ((core::timestamp() - m_coin->txidcache.time()) > 1800)
    {
        std::map<std::string, uint256> keepers;
        for (int i = 0; i < txhashes.size(); i++)
        {
            auto x = work["transactions"].at(i);
            std::string keep;
            if (x.contains("data"))
                keep = x["data"].get<std::string>();
            else
                keep = x.get<std::string>();
            uint256 txid = txhashes[i];
            keepers[keep] = txid;
        }
        m_coin->txidcache.clear();
        m_coin->txidcache.add(keepers);
    }

	if (!work.contains("height"))
    {
        uint256 previous_block_hash = work["previousblockhash"].get<uint256>();
        work["height"] = getblock(previous_block_hash)["height"].get<int>() + 1;
    }

    return rpc::WorkData{work, txhashes, end - start};
}

void NodeRPC::submit_block(BlockType& block, bool ignore_failure)
{
	// DGB is non-MWEB, btc-shaped: full-block packing includes witness data,
	// no MWEB tail to append.
	PackStream packed_block = pack<dgb::coin::BlockType>(block);
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
	// Body shape (segwit rule + separate Scrypt algo param) is the rpc_request.hpp SSOT.
	return CallAPIMethod("getblocktemplate", {make_gbt_request(rules)});
}

nlohmann::json NodeRPC::getnetworkinfo()
{
	return CallAPIMethod("getnetworkinfo");
}

nlohmann::json NodeRPC::getblockchaininfo()
{
	return CallAPIMethod("getblockchaininfo");
}

nlohmann::json NodeRPC::getdeploymentinfo()
{
	return CallAPIMethod("getdeploymentinfo");
}

nlohmann::json NodeRPC::getmininginfo()
{
	return CallAPIMethod("getmininginfo");
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

} // namespace coin


} // namespace dgb
