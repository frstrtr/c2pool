#pragma once
#include <istream>
#include <iostream>
#include <string>

#include <boost/program_options.hpp>
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

    class coind_config
    {
    public:
        coind_config() {};
        coind_config(po::variables_map &vm)
        {
            if (vm.count("coind-address"))
                coind_ip = vm["coind-address"].as<std::string>();
            if (vm.count("coind-p2p-port"))
                coind_port = vm["coind-p2p-port"].as<std::string>();
            if (vm.count("coind-rpc-port"))
                jsonrpc_coind_port = vm["coind-rpc-port"].as<std::string>();
            if (vm.count("coind_rpc_userpass"))
                jsonrpc_coind_login = vm["coind_rpc_userpass"].as<std::string>();

            std::cout << coind_ip << " " << jsonrpc_coind_port << " " << jsonrpc_coind_login << std::endl;
        }
    public:
        // Coind
        std::string coind_ip;
        std::string coind_port;
        std::string jsonrpc_coind_port;
        std::string jsonrpc_coind_login;


        // Pool Node
        int listenPort = 3037;
        int max_conns = 40;    //server max connections
        int desired_conns = 6; //client max connections
        int max_attempts = 10; //client максимум одновременно обрабатываемых попыток подключения
        //попытка подключения = подключение, которое произошло, но не проверенно на версию и прочие условия.
    };
} // namespace c2pool::dev