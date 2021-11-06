#include <gtest/gtest.h>
#include <tuple>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

#include <boost/beast/core.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
namespace beast = boost::beast;
namespace http = beast::http; // from <boost/beast/http.hpp>
namespace net = boost::asio;
using tcp = net::ip::tcp;

#include <libcoind/jsonrpc/coind.h>
#include <libcoind/jsonrpc/jsonrpc_coind.h>

#ifdef PASS_EXIST
#include "pass.h"
#endif

using namespace coind::jsonrpc;
using namespace coind::jsonrpc::data;
using namespace std;

class Bitcoind_JSONRPC : public ::testing::Test
{
protected:
	std::shared_ptr<coind::JSONRPC_Coind> coind;

protected:

    virtual void SetUp()
    {
#ifdef PASS_EXIST
		auto context = std::make_shared<boost::asio::io_context>(2);

		auto _pass = get_pass();
		char *login = std::get<0>(_pass);
		char *addr = std::get<1>(_pass);
		char *port = std::get<2>(_pass);
		coind = std::make_shared<coind::JSONRPC_Coind>(context, std::make_shared<coind::DigibyteParentNetwork>(), addr, port, login);

#else
        coind = new Coind("bitcoin", "B1TC01ND", "http://127.0.0.1:8332/", std::make_shared<c2pool::DigibyteNetwork>());
#endif
    }

    virtual void TearDown()
    {

    }
};

/* Worked
TEST(BoostBeast, jsonrpc)
{
    // auto context = std::make_shared<boost::asio::io_context>(3);
    // ip::tcp::resolver resolver(*context);
    // beast::tcp_stream stream(*context);
    // auto const results = resolver.resolve("192.168.10.10", "14024");
    // stream.connect(results);

    // The io_context is required for all I/O
    net::io_context ioc;

    // These objects perform our I/O
    tcp::resolver resolver(ioc);
    beast::tcp_stream stream(ioc);

    // Look up the domain name
    auto const results = resolver.resolve("192.168.10.10", "14024");

    // Make the connection on the IP address we get from a lookup
    stream.connect(results);

    // Set up an HTTP post request message
    http::request<http::string_body> req{http::verb::post, "/", 11};
    req.set(http::field::host, "192.168.10.10:14024");
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, "application/json");

    const char *login = "user:VeryVeryLongPass123";
    char *encoded_login = new char[64];
    boost::beast::detail::base64::encode(encoded_login, login, strlen(login));
    char *login_data = new char[6 + strlen(encoded_login) + 1];
    sprintf(login_data, "Basic %s", encoded_login);
    delete[] encoded_login;
    req.set(http::field::authorization, login_data);

    req.body() = "{\"jsonrpc\":\"2.0\",\"id\":\"curltest\",\"method\":\"getblockchaininfo\",\"params\":[]}";
    req.prepare_payload();
    std::cout << req << ".END" << std::endl;

    // Send the HTTP request to the remote host
	http::write(stream, req);

//	std::cout << "before async write" << std::endl;
//    http::async_write(
//        stream, req,
//        [](const boost::system::error_code &ec, std::size_t bytes_transferred) {
//          std::cout << "WRITED" << std::endl;
//        });
//	std::cout << "after async write" << std::endl;

    { // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        boost::beast::http::response<boost::beast::http::dynamic_body> res;

        boost::beast::http::read(stream, buffer, res);

        // Write the message to standard out
        std::cout << res << std::endl;
    }

    req.body() = "{\"jsonrpc\":\"2.0\",\"id\":\"curltest\",\"method\":\"getmininginfo\",\"params\":[]}";
    req.prepare_payload();
    std::cout << req << ".END" << std::endl;

    // Send the HTTP request to the remote host
    http::write(stream, req);

    { // This buffer is used for reading and must be persisted
        beast::flat_buffer buffer;

        boost::beast::http::response<boost::beast::http::dynamic_body> res;

        boost::beast::http::read(stream, buffer, res);
        // Write the message to standard out
		std::string result_str = boost::beast::buffers_to_string(res.body().data());
        std::cout << "RESULT STR: " << result_str << std::endl;
    }

    // Gracefully close the socket
    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    // not_connected happens sometimes
    // so don't bother reporting it.
    //
    if (ec && ec != beast::errc::not_connected)
        throw beast::system_error{ec};
}
*/

/*
TEST(JSONRPC_COIND, getblockchaininfo)
{
	auto context = std::make_shared<boost::asio::io_context>(2);

	auto _pass = get_pass();
	char *login = std::get<0>(_pass);
	char *addr = std::get<1>(_pass);
	char *port = std::get<2>(_pass);
	auto coind = std::make_shared<coind::JSONRPC_Coind>(context, std::make_shared<coind::DigibyteParentNetwork>(), addr, port, login); // (username, password, addr, std::make_shared<coind::DigibyteParentNetwork>());

	std::cout << coind->getblockchaininfo().write() << std::endl;
}
*/

TEST_F(Bitcoind_JSONRPC, getblockchaininfo)
{
	std::cout << coind->getblockchaininfo().write() << std::endl;
}

TEST_F(Bitcoind_JSONRPC, getblock)
{
	uint256 block_hash;
	block_hash.SetHex("36643871691af2e0b6bfc7898a4399133c6e6e4885a67f9d9fe36942c2513772");
	auto getblock_req = std::make_shared<GetBlockRequest>(block_hash);

	std::cout << coind->getblock(getblock_req).write() << std::endl;
}

/*
TEST(Libcurl, init)
{
    CURL *curl;
    {
        curl_global_init(CURL_GLOBAL_ALL);
        curl = curl_easy_init();
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "content-type: application/json;");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_USERPWD, "user:VeryVeryLongPass123");
        curl_easy_setopt(curl, CURLOPT_URL, "http://192.168.10.10:14024");
    }
    const char *dataFormat =
        "{\"jsonrpc\": \"2.0\", \"id\":\"curltest\", \"method\": \"%s\", \"params\": %s }";

    for (int i = 0; i < 10; i++)
    {
        cout << i << endl;
        string result;

        string command = "getblockchaininfo";
        long data_length = strlen(dataFormat) + 1 + command.length();
        char *data = new char[data_length];
        const char *params = "[]";
        sprintf(data, dataFormat, command.c_str(), params);

        // const char *data =
        //     "{\"jsonrpc\": \"2.0\", \"id\":\"curltest\", \"method\": \"getblockchaininfo\", \"params\": [] }";

        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Writer);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
        curl_easy_perform(curl);
        // cout << result << endl;

        UniValue json_parsed;
        json_parsed.read(result);
        cout << json_parsed.write() << endl;
    }
}

TEST_F(Bitcoind_JSONRPC, getblockchaininfo_parse)
{
    std::string json_answer = "{\"result\":{\"chain\":\"main\",\"blocks\":13939669,\"headers\":13939669,\"bestblockhash\":\"00000000000000011bddca60ff1a4a9aa83c4ec90e1b6fecb23a1df5eccb1d30\",\"mediantime\":1635927301,\"verificationprogress\":0.9999998293695099,\"initialblockdownload\":false,\"chainwork\":\"0000000000000000000000000000000000000000000cb27161ae5010180f74cc\",\"size_on_disk\":23475634764,\"pruned\":false,\"difficulties\":{\"sha256d\":1536999299.641566,\"scrypt\":126779.2826991764,\"skein\":18165661.87357499,\"qubit\":3526961.091165715,\"odo\":834147.5196683727},\"softforks\":[],\"bip9_softforks\":{\"csv\":{\"status\":\"active\",\"startTime\":1489997089,\"timeout\":1521891345,\"since\":4394880},\"segwit\":{\"status\":\"active\",\"startTime\":1490355345,\"timeout\":1521891345,\"since\":4394880},\"nversionbips\":{\"status\":\"active\",\"startTime\":1489997089,\"timeout\":1521891345,\"since\":4394880},\"reservealgo\":{\"status\":\"active\",\"startTime\":1542672000,\"timeout\":1574208000,\"since\":8547840},\"odo\":{\"status\":\"active\",\"startTime\":1556668800,\"timeout\":1588291200,\"since\":9112320}},\"warnings\":\"\"},\"error\":null,\"id\":\"curltest\"}";
    UniValue readed;
    readed.read(json_answer);
}

TEST_F(Bitcoind_JSONRPC, getblockchaininfo)
{
    auto result = coind->GetBlockChainInfo();
    cout << "getblockchaininfo.bestblockhash = " << result["bestblockhash"].get_str() << endl;
    cout << result.write() << endl;
}

TEST_F(Bitcoind_JSONRPC, getblocktemplate)
{
    vector<string> rules{"segwit"};
    GetBlockTemplateRequest *request = new GetBlockTemplateRequest(rules);

    auto result = coind->getblocktemplate(request);
    cout << result["version"].get_int() << endl;
}

TEST_F(Bitcoind_JSONRPC, getblock)
{
    uint256 block_hash;
    block_hash.SetHex("a058f7934d45061a3431617330e21c4ea4d07b8bb6179471a4680366aee92b4f");
    GetBlockRequest *request = new GetBlockRequest(block_hash);

    auto result = coind->GetBlock(request);
    cout << result.write() << endl;
}

TEST_F(Bitcoind_JSONRPC, getnetworkinfo)
{
    auto result = coind->GetNetworkInfo();
    cout << result.write() << endl;
}
*/