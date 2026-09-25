// SPDX-License-Identifier: AGPL-3.0-or-later
#include "rpc.hpp"

#include <algorithm>
#include <chrono>
#include <climits>

#include <boost/asio/detail/socket_ops.hpp>   // poll_read/poll_write: portable readiness wait with a timeout

#include <impl/btc/config_pool.hpp>
#include <impl/btc/coin/softfork_check.hpp>
#include <impl/btc/coin/genesis.hpp>       // btc_genesis_hash — per-net check() probe (#744/#787 B1)

#include <core/log.hpp>
#include <core/hash.hpp>
#include <core/coin/submitblock_result.hpp>
namespace btc
{

namespace coin
{

namespace
{

// Sync stream over the RPC socket that bounds every read_some/write_some by
// one absolute deadline (P0-SUBMIT-CSMAIN). The socket is in user
// non-blocking mode (apply_socket_timeouts), so asio hands would_block back
// instead of parking in poll(fd, -1); we then wait for readiness ourselves,
// for at most the time left, and fail with timed_out once it is spent.
// Satisfies beast's SyncReadStream/SyncWriteStream, so http::read/write run
// on it unchanged.
class DeadlineStream
{
    io::ip::tcp::socket& m_sock;
    const std::chrono::steady_clock::time_point m_deadline;

    bool wait_ready(bool for_read, boost::system::error_code& ec)
    {
        namespace ops = io::detail::socket_ops;
        for (;;)
        {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                m_deadline - std::chrono::steady_clock::now()).count();
            if (left <= 0)
            {
                ec = io::error::timed_out;
                return false;
            }
            const int msec = static_cast<int>(std::min<long long>(left, INT_MAX));
            const int ready = for_read ? ops::poll_read(m_sock.native_handle(), 0, msec, ec)
                                       : ops::poll_write(m_sock.native_handle(), 0, msec, ec);
            if (ready > 0)
                return true;
            if (ready < 0 && ec != io::error::interrupted)
                return false;
            // 0 = poll timed out (the clock check above ends the wait), or EINTR
        }
    }

    static bool would_block(const boost::system::error_code& ec)
    {
        return ec == io::error::would_block || ec == io::error::try_again;
    }

public:
    DeadlineStream(io::ip::tcp::socket& sock, std::chrono::steady_clock::time_point deadline)
        : m_sock(sock), m_deadline(deadline) {}

    template <class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec)
    {
        for (;;)
        {
            const std::size_t n = m_sock.read_some(buffers, ec);
            if (!would_block(ec))
                return n;
            if (!wait_ready(true, ec))
                return 0;
        }
    }

    template <class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers)
    {
        boost::system::error_code ec;
        const std::size_t n = read_some(buffers, ec);
        if (ec)
            throw boost::system::system_error(ec);
        return n;
    }

    template <class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec)
    {
        for (;;)
        {
            const std::size_t n = m_sock.write_some(buffers, ec);
            if (!would_block(ec))
                return n;
            if (!wait_ready(false, ec))
                return 0;
        }
    }

    template <class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers)
    {
        boost::system::error_code ec;
        const std::size_t n = write_some(buffers, ec);
        if (ec)
            throw boost::system::system_error(ec);
        return n;
    }
};

} // namespace

NodeRPC::NodeRPC(io::io_context* context, btc::interfaces::Node* coin, bool testnet)
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
                        // #744/#787 M2: arm the Send() socket deadline on the
                        // freshly-connected socket BEFORE check() issues any
                        // blocking RPC, so a daemon that connects but never
                        // responds cannot wedge the ioc here either.
                        apply_socket_timeouts();
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
	apply_socket_timeouts();   // #744/#787 M2: re-arm the Send() deadline on the fresh socket
	LOG_INFO << "CoindRPC reconnected (sync)";
}

void NodeRPC::apply_socket_timeouts()
{
	// Put the socket in user NON-blocking mode so Send()'s DeadlineStream owns
	// every wait. The old lever (blocking socket + SO_RCVTIMEO/SO_SNDTIMEO,
	// #744/#787 M2, after DASH #781) never fired on Linux: asio's sync recv/send
	// treat the EAGAIN the kernel timeout produces as would_block and fall
	// through to poll(fd, -1), an unbounded wait (.234 rig: 178 s ioc stall
	// behind one submitblock, zero "read failed" lines). In user non-blocking
	// mode asio returns would_block to the caller, and DeadlineStream waits for
	// at most the time left. asio's readiness wait is portable (select() on
	// Windows), so Windows gets the deadline too. P0-SUBMIT-CSMAIN.
	if (!m_stream.socket().is_open())
		return;
	boost::system::error_code ec;
	m_stream.socket().non_blocking(true, ec);
	if (ec)
		LOG_WARNING << "CoindRPC: could not set non-blocking mode (RPC deadline disarmed): " << ec.message();
}

std::string NodeRPC::Send(const std::string &request)
{
	// ONE deadline for the whole call, retry included: the ioc waits at most
	// m_io_timeout here, however long the daemon sits on the request.
	const auto deadline = std::chrono::steady_clock::now() + m_io_timeout;

	// Retry once after synchronous reconnect on write/read failure, but never
	// after a timeout (below).
	for (int attempt = 0; attempt < 2; ++attempt)
	{
		m_http_request.body() = request;
		m_http_request.prepare_payload();
		DeadlineStream io_stream(m_stream.socket(), deadline);
		beast::error_code ec;

		http::write(io_stream, m_http_request, ec);
		if (ec)
		{
			// Out of time mid-write: part of the request is on the wire and the
			// budget is spent. Drop the socket; the next call reconnects.
			const bool timed_out = ec == io::error::timed_out;
			const bool retry = attempt == 0 && !timed_out;
			LOG_WARNING << "CoindRPC write failed: " << ec.message()
			            << (retry ? " — reconnecting..." : timed_out ? " — dropping connection" : "");
			if (retry) {
				sync_reconnect();
				continue;
			}
			if (timed_out)
				m_stream.close();
			return {};
		}

		beast::flat_buffer buffer;
		boost::beast::http::response<boost::beast::http::dynamic_body> response;

		http::read(io_stream, buffer, response, ec);
		if (ec)
		{
			// Out of time waiting for the answer: the daemon HAS the request and
			// is still on it (submitblock queued behind cs_main). A re-send would
			// queue a second copy behind the first and double the stall, so give
			// up on this call. Drop the socket so the late reply is never read as
			// the answer to the NEXT call (every request carries the same id);
			// the next Send() fails its write on the closed stream and reconnects.
			const bool timed_out = ec == io::error::timed_out;
			const bool retry = attempt == 0 && !timed_out;
			LOG_WARNING << "CoindRPC read failed: " << ec.message()
			            << (retry ? " — reconnecting..."
			                      : timed_out ? " — request delivered, not re-sending; dropping connection" : "");
			if (retry) {
				sync_reconnect();
				continue;
			}
			if (timed_out)
				m_stream.close();
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
	// #744/#787 B1: probe the per-net BTC genesis (was the LITECOIN genesis,
	// copied from the LTC impl -- broke the mainnet handshake gate below).
	bool has_block = check_blockheader(uint256S(btc_genesis_hash(IS_TESTNET)));
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
		btc::coin::collect_softfork_names(blockchaininfo["softforks"], softforks_supported);
	if (blockchaininfo.contains("bip9_softforks"))
		btc::coin::collect_softfork_names(blockchaininfo["bip9_softforks"], softforks_supported);

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

	std::vector<std::string> missing;
	for (const auto& req : btc::PoolConfig::SOFTFORKS_REQUIRED)
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
	auto work = getblocktemplate({"segwit"});
	auto end = core::timestamp();

	if (!m_coin->txidcache.is_started())
		m_coin->txidcache.start();

	std::vector<uint256> txhashes;
	std::vector<btc::coin::Transaction> unpacked_transactions;
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

        btc::coin::MutableTransaction unpacked_tx;
        if (m_coin->known_txs.contains(txid))
        {
			unpacked_tx = btc::coin::MutableTransaction(m_coin->known_txs.at(txid));
        } else
        {
            if (ps_tx.empty())
                ps_tx = PackStream(ParseHex(x));
            UnserializeTransaction(unpacked_tx, ps_tx, TX_WITH_WITNESS);
        }
        unpacked_transactions.push_back(btc::coin::Transaction(unpacked_tx));
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
	// BTC: segwit + taproot are required forks; full-block packing always
	// includes witness data. No MWEB tail to append.
	PackStream packed_block = pack<btc::coin::BlockType>(block);
	auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {HexStr(packed_block.get_span())});
	bool success = result.is_null();

	auto block_header = pack<btc::coin::BlockHeaderType>(block); // cast to header?
	// We always expect the submit to succeed (non-null result means rejection).
	auto success_expected = true;

	if ((!success && success_expected && !ignore_failure) || (success && !success_expected))
    	LOG_ERROR << "Block submittal result: " << success << "(" << result.dump() << ") Expected: " << success_expected;
}

bool NodeRPC::submit_block_hex(const std::string& block_hex, bool ignore_failure)
{
	(void)ignore_failure;
	auto result = m_client.CallMethod<nlohmann::json>(ID, "submitblock", {block_hex});
	// Dual-path contract: a "duplicate"/"inconclusive"/already-have result means
	// the block already reached the network (our P2P relay, or a peer won the
	// race) — that is SUCCESS, not failure. See core::coin::submitblock_result_accepted.
	const bool success = core::coin::submitblock_result_accepted(result);
	if (success)
		LOG_INFO << "submit_block_hex accepted"
		         << (result.is_null() ? std::string{} : " (" + result.dump() + ")");
	else
		// A won block rejection reason is load-bearing diagnostic data: the
		// daemon returns a verdict string ("bad-witness-merkle-match",
		// "high-hash", "Superfluous witness record", ...). Surface it ALWAYS.
		// ignore_failure governs fatality (never throw out of the won-block
		// path), NOT log visibility -- a swallowed reason blinds block-prod
		// debugging (G3b submits went pending -> rejected with no cause).
		LOG_ERROR << "submit_block_hex REJECTED by daemon: " << result.dump();
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


} // namespace btc