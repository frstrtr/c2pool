#include "coind_master.h"

#include <iostream>
#include <cstring>
#include <string>
#include <signal.h>
#include <thread>
#include <chrono>
using std::cout, std::endl;
using std::string;

#include <boost/asio/thread_pool.hpp>
using namespace c2pool::dev;
#include <boost/program_options.hpp>
#include <boost/format.hpp>
namespace po = boost::program_options;

#include <libdevcore/config.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <networks/network.h>

#include "node_manager.h"

//TODO: move macros to other.h
#define fmt(TEMPL, DATA) (boost::format{TEMPL} % (DATA)).str()
#define fmt_c(TEMPL, DATA) fmt(TEMPL, DATA).data()


int main(int ac, char *av[])
{
    c2pool_config::INIT();
    //========================================================================================================================
    //TODO:
    //  add: --bench; --rconsole; --web-static; --merged; --coinbtext; --disable-advertise; --iocp; --irc-announce;
    //       --no-bugreport; --p2pool-node; --disable-upnp; --external-ip; --bitcoind_rpc_userpass; --allow-obsolete-bitcoind
    //========================================================================================================================
    po::options_description desc(fmt("c2pool (ver. %1%)\nAllowed options", 0.1)); //TODO: get %Version from Network config

    // args main
    desc.add_options()("help", "produce help message");
    desc.add_options()("version,v", "version");
    desc.add_options()("debug", po::value<c2pool::dev::DebugState>(&c2pool_config::get()->debug)->default_value(c2pool::dev::normal), "enable debugging mode");
    desc.add_options()("networks", po::value<std::vector<std::string>>()->multitoken(), "");
    desc.add_options()("datadir", po::value<string>()->default_value(""), "store data in this directory (default: <directory with c2pool build>/data)");
    desc.add_options()("give-author", po::value<float>()->default_value(0), "donate this percentage of work towards the development of p2pool (default: 0.0)");

    po::options_description cmd_options;
    cmd_options.add(desc);

    po::variables_map vm;
    po::parsed_options parse_option = po::parse_command_line(ac, av, cmd_options);
    po::store(parse_option, vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        cout << desc << endl;
        return C2PoolErrors::success;
    }

    if (vm.count("version"))
    {
        cout << 0.1 << endl; //TODO
        return C2PoolErrors::success;
    }

    //============================================================
    c2pool::console::Logger::Init();
    LOG_INFO << "Start c2pool...";
    // каждый второй поток для coind'a/stratum'a
    //boost::asio::thread_pool coind_threads(thread::hardware_concurrency()/2); //TODO: количество через аргументы запуска.
    boost::asio::thread_pool coind_threads(1);
    //Creating and initialization coinds network, config and NodeManager

    auto nodes = c2pool::master::make_nodes(coind_threads, vm);

    //Init exit handler
    ExitSignalHandler exitSignalHandler;
    signal(SIGINT, &ExitSignalHandler::handler);
    signal(SIGTERM, &ExitSignalHandler::handler);
    signal(SIGABRT, &ExitSignalHandler::handler);

    while (exitSignalHandler.working())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
//        std::cout << "main thread: " << (DGB == nullptr) << std::endl;
    }
    return C2PoolErrors::success;
}