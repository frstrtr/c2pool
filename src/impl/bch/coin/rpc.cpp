// SPDX-License-Identifier: AGPL-3.0-or-later
#include "rpc.hpp"

#include <impl/bch/config_pool.hpp>
#include <impl/bch/coin/softfork_check.hpp>

#include <core/log.hpp>
#include <core/hash.hpp>

// ---------------------------------------------------------------------------
// bch::coin::NodeRPC -- external coin-RPC client BODY (M3 slice 5).
// Ported from src/impl/btc/coin/rpc.cpp; carries the BCH-divergent bits that
// have no 1:1 BTC mirror (see per-method notes):
//   - check(): BCH-chain sentinel = the Aug-2017 fork block (478559); version
//     floor 100000 per p2pool-merged-v36 bitcoincash.py VERSION_CHECK; the
//     softfork-required gate is vacuous (bch::PoolConfig::SOFTFORKS_REQUIRED
//     is empty -- BCH activations are MTP-based, not BIP9/GBT-signalled).
//   - getwork(): getblocktemplate() takes NO "segwit" rule; transactions are
//     unpacked with the LEGACY (witness-free) BCH serialization, so the GBT
//     "txid" field == the data hash (no wtxid distinction).
//   - submit_block(): no witness packing, no MWEB tail.
//   - CashTokens-bearing outputs round-trip transparently (template carry).
// ---------------------------------------------------------------------------

namespace bch
{

namespace coin
{

NodeRPC::NodeRPC(io::io_context* context, bch::interfaces::Node* coin, bool testnet)
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

    // Async DNS resolve -- must NOT use the blocking m_resolver.resolve() overload
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
	// BCH-chain sentinel: the Aug-2017 fork block at height 478559. A daemon on
	// the BCH chain has this header; a BTC daemon has a DIFFERENT 478559 and
	// will fail the lookup -- this is what distinguishes BCH from BTC here.
	// (bitcoin/networks/bitcoincash.py RPC_CHECK fork-block hash.)
	bool has_block = check_blockheader(uint256S("000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"));
	bool is_main_chain = getblockchaininfo()["chain"].get<std::string>() == "main";
	nlohmann::json blockchaininfo;

	if (is_main_chain && !has_block)
	{
		LOG_ERROR << "Check failed! Make sure that you're connected to the right BCH node with --bitcoind-rpc-port, and that it has finished syncing!" << std::endl;
		return false;
	}

	try
    {
		auto networkinfo = getnetworkinfo();
		// BCH version floor 100000 per bitcoincash.py VERSION_CHECK
		// (Bitcoin 0.11.2-era; BCHN reports a higher value).
		bool version_check_result = (100000 <= networkinfo["version"].get<int>());
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
		bch::coin::collect_softfork_names(blockchaininfo["softforks"], softforks_supported);
	if (blockchaininfo.contains("bip9_softforks"))
		bch::coin::collect_softfork_names(blockchaininfo["bip9_softforks"], softforks_supported);

	// Fallback for daemons that don't populate getblockchaininfo softfork fields.
	// BCH GBT takes NO "segwit" rule -- request with empty rules.
	if (softforks_supported.empty())
	{
		try
		{
			auto gbt = getblocktemplate({});
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
			// Keep empty set; missing-fork check below is vacuous for BCH anyway.
		}
	}

	// bch::PoolConfig::SOFTFORKS_REQUIRED is EMPTY -- BCH activations are
	// MTP-based, not GBT-signalled -- so this gate always passes. Kept for
	// structural parity with the BTC port + future diagnostics.
	std::vector<std::string> missing;
	for (const auto& req : bch::PoolConfig::SOFTFORKS_REQUIRED)
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
	// BCH: NO "segwit" rule (SegWit rejected at the Aug-2017 fork).
	auto work = getblocktemplate({});
	auto end = core::timestamp();

	if (!m_coin->txidcache.is_started())
		m_coin->txidcache.start();

	std::vector<uint256> txhashes;
	std::vector<bch::coin::Transaction> unpacked_transactions;
    for (auto& packed_tx : work["transactions"])
    {
        PackStream ps_tx;

        uint256 txid;
		std::string x;

        if (packed_tx.contains("data"))
            x = packed_tx["data"].get<std::string>();
        else
            x = packed_tx.get<std::string>();

        // BCH has NO witness, so there is no wtxid/txid distinction: hashing
        // "data" directly yields the canonical txid. Prefer the GBT "txid"
        // field when present (identical value, saves a hash).
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

        bch::coin::MutableTransaction unpacked_tx;
        if (m_coin->known_txs.contains(txid))
        {
			unpacked_tx = bch::coin::MutableTransaction(m_coin->known_txs.at(txid));
        } else
        {
            if (ps_tx.empty())
                ps_tx = PackStream(ParseHex(x));
            // BCH legacy (witness-free) unserialization -- no TX_WITH_WITNESS flag.
            UnserializeTransaction(unpacked_tx, ps_tx);
        }
        unpacked_transactions.push_back(bch::coin::Transaction(unpacked_tx));
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

void NodeRPC::submit_block(BlockType& block, bool ignore_failure)
{
	// BCH: legacy block serialization -- no witness data, no MWEB tail.
	PackStream packed_block = pack<bch::coin::BlockType>(block);
	auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {HexStr(packed_block.get_span())});
	bool success = result.is_null();

	auto block_header = pack<bch::coin::BlockHeaderType>(block); // cast to header?
	// We always expect the submit to succeed (non-null result means rejection).
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

} // namespace bch