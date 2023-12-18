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
#include <QCoreApplication>
#include <QtWidgets/QApplication>

#include <libdevcore/config.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <networks/network.h>

#include "c2pool_version.h"
#include "node_manager.h"

//TODO: move macros to other.h
#define fmt(TEMPL, DATA) (boost::format{TEMPL} % (DATA)).str()
#define fmt_c(TEMPL, DATA) fmt(TEMPL, DATA).data()


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    c2pool_config::INIT();
    //========================================================================================================================
    //TODO:
    //  add: --bench; --rconsole; --web-static; --merged; --coinbtext; --disable-advertise; --iocp; --irc-announce;
    //       --no-bugreport; --p2pool-node; --disable-upnp; --external-ip; --bitcoind_rpc_userpass; --allow-obsolete-bitcoind
    //========================================================================================================================
    po::options_description desc(fmt("c2pool (ver. %1%)\nAllowed options", c2pool::version_str()));

    // args main
    desc.add_options()("help", "produce help message");
    desc.add_options()("version,v", "version");
    desc.add_options()("trace", "enable trace logs");
    desc.add_options()("debug", po::value<std::vector<std::string>>()->multitoken(), "");
    desc.add_options()("networks", po::value<std::vector<std::string>>()->multitoken(), "");
    desc.add_options()("datadir", po::value<string>()->default_value(""), "store data in this directory (default: <directory with c2pool build>/data)");
    desc.add_options()("give-author", po::value<float>()->default_value(0), "donate this percentage of work towards the development of p2pool (default: 0.0)");
    desc.add_options()("web_server", po::value<std::string>(), "ip:port for web site");

    po::options_description cmd_options;
    cmd_options.add(desc);

    po::variables_map vm;
    po::parsed_options parse_option = po::parse_command_line(argc, argv, cmd_options);
    po::store(parse_option, vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        cout << desc << endl;
        return C2PoolErrors::success;
    }

    if (vm.count("version"))
    {
        cout << c2pool::version_str() << endl;
        return C2PoolErrors::success;
    }

    C2Log::Logger::Init();

    if (vm.count("trace"))
        C2Log::Logger::enable_trace();

    if (vm.count("debug"))
    {
        for (const auto &v: vm["debug"].as<std::vector<std::string>> ())
        {
            C2Log::Logger::add_category(v);
        }
    }

    //============================================================
    LOG_INFO << "Start c2pool...";
    // каждый второй поток для coind'a/stratum'a
    //boost::asio::thread_pool coind_threads(thread::hardware_concurrency()/2); //TODO: количество через аргументы запуска.
    boost::asio::thread_pool coind_threads(1);

    //Createing web server
    LOG_INFO << "web_server initialization in new thread...";
    std::shared_ptr<WebServer> web_server;

    tcp::endpoint web_endpoint;
    if (vm.count("web_server"))
    {
        std::vector<std::string> _addr;
        boost::split(_addr, vm["web_server"].as<std::string>(), boost::is_any_of(":"));

        if (_addr.size() == 2)
        {
            web_endpoint = tcp::endpoint(net::ip::make_address(_addr[0]), std::stoi(_addr[1]));
        } else
        {
            LOG_ERROR << "Incorrect web_server arg!";
            return 0;
        }
    } else
    {
        LOG_ERROR << "Use arg --web_server=ip:port!";
        return 0;
    }

    std::thread web_server_thread([&web_server, &web_endpoint](){
        auto ioc = std::make_shared<boost::asio::io_context>();

        web_server = std::make_shared<WebServer>(ioc, web_endpoint);
        c2pool::master::init_web(web_server);
        web_server->run();

        ioc->run();
    });
    web_server_thread.detach();

    while (!web_server || (web_server && !web_server->is_running()))
    {
        LOG_INFO << "\t...wait for web server initialization";
        this_thread::sleep_for(std::chrono::seconds(1));
    }

    //Creating and initialization coinds network, config and NodeManager
    auto nodes = c2pool::master::make_nodes(coind_threads, vm, web_server);

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

    if (web_server_thread.joinable())
        web_server_thread.join();

    return C2PoolErrors::success;
}