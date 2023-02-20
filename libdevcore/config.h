#pragma once
#include <istream>
#include <iostream>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
namespace po = boost::program_options;

namespace c2pool::dev
{
    enum DebugState
    {
        trace = 0,
        debug = 1,
        normal = 2
    };

    std::istream &operator>>(std::istream &in, c2pool::dev::DebugState &value);
    class c2pool_config
    {
    public:
        DebugState debug = normal;

    private:
        static c2pool_config *_instance;

    public:
        static void INIT();
        static c2pool_config *get();
    };

    class coind_config;
    std::shared_ptr<coind_config> load_config_file(const std::string &name);

    class coind_config
    {
    public:
        coind_config(std::string _name) : name(std::move(_name)) {};
        coind_config(std::string _name, boost::property_tree::ptree &pt);

        static boost::property_tree::ptree make_default_config();

    public:
        std::string name;

        bool testnet;
        std::string address;
        int numaddresses;
        int timeaddresses;

        // Coind
        /// connect to this address (default: 127.0.0.1)
        std::string coind_ip;
        /// connect to P2P interface at this port (default: <read from bitcoin.conf if password not provided>)
        std::string coind_port;
        /// custom configuration file path (when coind -conf option used)
        std::string coind_config_path;
        /// connect to JSON-RPC interface using SSL
        bool coind_rpc_ssl;
        /// connect to JSON-RPC interface at this port (default: <read from bitcoin.conf if password not provided>)
        std::string jsonrpc_coind_port;
        /// coind RPC interface username, then password, space-separated (only one being provided will cause the username to default to being empty, and none will cause P2Pool to read them from bitcoin.conf)
        std::string jsonrpc_coind_login;

        // Pool Node
        /// use port PORT to listen for connections (forward this port from your router!)
        int c2pool_port;
        /// maximum incoming connections (default: 40)
        int max_conns;
        /// outgoing connections (default: 6)
        int desired_conns; //client max connections
        int max_attempts = 10; //client максимум одновременно обрабатываемых попыток подключения
        //попытка подключения = подключение, которое произошло, но не проверенно на версию и прочие условия.

        // Worker
        /// listen on PORT on interface with ADDR for RPC connections from miners
        std::string worker_port;
        /// charge workers mining to their own bitcoin address (by setting their miner's username to a bitcoin address) this percentage fee to mine on your c2pool instance. Amount displayed at http://127.0.0.1:WORKER_PORT/fee (default: 0)
        float fee;
        //TODO?: worker_group.add_options()("share-rate,s", po::value<float>()->default_value(3), fmt_c("Auto-adjust mining difficulty on each connection to target this many seconds per pseudoshare (default: %1%)", 3));                                                                                                       //p2pool: share_rate
    };
} // namespace c2pool::dev