#include "rpc.hpp"

#include <impl/ltc/config_pool.hpp>
#include <impl/ltc/coin/softfork_check.hpp>

#include <core/log.hpp>
#include <core/hash.hpp>
namespace ltc
{

namespace coin
{

NodeRPC::NodeRPC(io::io_context* context, ltc::interfaces::Node* coin, bool testnet)
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

	std::string encoded_login2;
    encoded_login2.resize(boost::beast::detail::base64::encoded_size(userpass.size()));
    const auto result = boost::beast::detail::base64::encode(&encoded_login2[0], userpass.data(), userpass.size());
    encoded_login2.resize(result);
	m_auth->authorization = "Basic " + encoded_login2;

    m_http_request.set(http::field::authorization, m_auth->authorization);

    auto const results = m_resolver.resolve(address.address(), address.port_str());
	boost::asio::ip::tcp::endpoint endpoint = *results.begin();

    m_stream.async_connect(endpoint, 
		[&](boost::system::error_code ec)
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

std::string NodeRPC::Send(const std::string &request)
{
	m_http_request.body() = request;
	m_http_request.prepare_payload();
	try
	{
		http::write(m_stream, m_http_request);	
	}
	catch(const std::exception& e)
	{
		LOG_WARNING << "error when try to send message in CoindRPC -> " << e.what();
		reconnect();
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
		LOG_WARNING << "error when try to read response -> " << ex.what();
		reconnect();
		return {};
    }

	std::string json_result = boost::beast::buffers_to_string(response.body().data());

	return json_result;
}

nlohmann::json NodeRPC::CallAPIMethod(const std::string& method, const jsonrpccxx::positional_parameter& params)
{
	return m_client.CallMethod<nlohmann::json>(ID, method, params);
}

bool NodeRPC::check()
{
	bool has_block = check_blockheader(uint256S("12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2"));
	bool is_main_chain = getblockchaininfo()["chain"].get<std::string>() == "main";
	nlohmann::json blockchaininfo;

	if (is_main_chain && !has_block)
	{
		LOG_ERROR << "Check failed! Make sure that you're connected to the right bitcoind with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
		return false;
	}

	try
    {
		auto networkinfo = getnetworkinfo();
		bool version_check_result = (100400 <= networkinfo["version"].get<int>());
		if (!version_check_result)
		{
			LOG_ERROR << "Coin daemon too old! Upgrade!";
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
		ltc::coin::collect_softfork_names(blockchaininfo["softforks"], softforks_supported);
	if (blockchaininfo.contains("bip9_softforks"))
		ltc::coin::collect_softfork_names(blockchaininfo["bip9_softforks"], softforks_supported);

	// Fallback for daemons that don't populate getblockchaininfo softfork fields.
	if (softforks_supported.empty())
	{
		try
		{
			auto gbt = getblocktemplate({"segwit", "mweb"});
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

	std::vector<std::string> missing;
	for (const auto& req : ltc::PoolConfig::SOFTFORKS_REQUIRED)
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
		LOG_ERROR << "Coin daemon missing required softfork features: " << joined;
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
	auto work = getblocktemplate({"segwit", "mweb"}); // mweb for ltc
	auto end = core::timestamp();

	if (!m_coin->txidcache.is_started())
		m_coin->txidcache.start();

	std::vector<uint256> txhashes;
	std::vector<ltc::coin::Transaction> unpacked_transactions;
    for (auto& packed_tx : work["transactions"])
    {
        PackStream ps_tx;

        uint256 txid;
		std::string x;

        if (packed_tx.contains("data"))
            x = packed_tx["data"].get<std::string>();
        else
            x = packed_tx.get<std::string>();

        // Use the "txid" field from GBT when available — it is
        // the non-witness (stripped) hash, which is what the block
        // header merkle tree must use.  Hashing "data" directly
        // gives the wtxid when segwit witness data is present.
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

        ltc::coin::MutableTransaction unpacked_tx;
        if (m_coin->known_txs.contains(txid))
        {
			unpacked_tx = ltc::coin::MutableTransaction(m_coin->known_txs.at(txid));
        } else
        {
            if (ps_tx.empty())
                ps_tx = PackStream(ParseHex(x));
            UnserializeTransaction(unpacked_tx, ps_tx, TX_WITH_WITNESS);
        }
        unpacked_transactions.push_back(ltc::coin::Transaction(unpacked_tx));
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

    return rpc::WorkData{work, unpacked_transactions, txhashes, end - start};
}

void NodeRPC::submit_block(BlockType& block, std::string mweb, bool ignore_failure)
{
	// Determine whether segwit is active (required for full-block vs stripped packing).
	bool segwit_activated = false;
	auto work = *m_coin->work;
	if (work.m_data.contains("rules"))
	// if (  m_coin->work->m_data.contains("rules"))
	{
		std::vector<std::string> rules = work.m_data["rules"].get<std::vector<std::string>>();
    	segwit_activated += std::any_of(rules.begin(), rules.end(), [](const auto &v){ return v == "segwit";});
    	segwit_activated += std::any_of(rules.begin(), rules.end(), [](const auto &v){ return v == "!segwit";});
	}
	
	// Since taproot+segwit are required forks, stripped-block packing is not needed.
	PackStream packed_block = pack<ltc::coin::BlockType>(block);
	auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {HexStr(packed_block.get_span()) + mweb});
	bool success = result.is_null();
	
	auto block_header = pack<ltc::coin::BlockHeaderType>(block); // cast to header?
	// We always expect the submit to succeed (non-null result means rejection).
	auto success_expected = true;

	if ((!success && success_expected && !ignore_failure) || (success && !success_expected))
    	LOG_ERROR << "Block submittal result: " << success << "(" << result.dump() << ") Expected: " << success_expected;
}

bool NodeRPC::submit_block_hex(const std::string& block_hex, const std::string& mweb, bool ignore_failure)
{
	auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {block_hex + mweb});
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
	nlohmann::json j = nlohmann::json::object({{"rules", rules}});
	return CallAPIMethod("getblocktemplate", {j});
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


} // namespace ltc