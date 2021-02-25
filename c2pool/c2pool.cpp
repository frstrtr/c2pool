#include "coind_master.h"

#include <devcore/config.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include <libnet/nodeManager.h>
#include <networks/network.h>
using namespace c2pool::dev;
using namespace c2pool::libnet;

#include <iostream>
#include <cstring>
#include <string>
#include <signal.h>
#include <thread>
#include <chrono>
using std::cout, std::endl;
using std::string;

#include <boost/program_options.hpp>
#include <boost/format.hpp>
namespace po = boost::program_options;

//TODO: move macros to other.h
#define fmt(TEMPL, DATA) (boost::format{TEMPL} % DATA).str()
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
    desc.add_options()("help", "produce help message");

    desc.add_options()("version", "version");
    desc.add_options()("debug", po::value<bool>(&c2pool_config::get()->debug)->default_value(false), "enable debugging mode");
    desc.add_options()("testnet", po::value<bool>()->default_value(false), "use the network's testnet");
    desc.add_options()("net", po::value<string>()->default_value("bitcoin"), "use specified network (default: bitcoin)");

    desc.add_options()("address,a", po::value<string>()->default_value(""), "generate payouts to this address (default: <address requested from bitcoind>), or (dynamic)");
    desc.add_options()("numaddresses,i", po::value<int>()->default_value(2), "number of bitcoin auto-generated addresses to maintain for getwork dynamic address allocation");
    desc.add_options()("timeaddresses,t", po::value<int>()->default_value(172800), "seconds between acquisition of new address and removal of single old (default: 2 days or 172800s)");
    desc.add_options()("datadir", po::value<string>()->default_value(""), "store data in this directory (default: <directory with c2pool build>/data)");
    desc.add_options()("logfile", po::value<string>()->default_value(""), "log to this file (default: data/<NET>/log)");
    desc.add_options()("give-author", po::value<float>()->default_value(0), "donate this percentage of work towards the development of p2pool (default: 0.0)");

    //c2pool interface
    po::options_description c2pool_group("c2pool interface");
    int p2p_port = 3035;                                                                                                                                                                                   //TODO: net.P2P_PORT
    c2pool_group.add_options()("c2pool-port", po::value<int>()->default_value(p2p_port), fmt_c("use port PORT to listen for connections (forward this port from your router!) (default: %1%)", p2p_port)); //fmt("s%1", 1).c_str());
    c2pool_group.add_options()("max-conns", po::value<int>()->default_value(40), "maximum incoming connections (default: 40)");                                                                            //in p2pool: dest='p2pool_conns'
    c2pool_group.add_options()("outgoing-conns", po::value<int>()->default_value(6), "outgoing connections (default: 6)");                                                                                 //in p2pool: dest='p2pool_outgoing_conns'
    desc.add(c2pool_group);

    //worker interface
    po::options_description worker_group("worker interface");
    worker_group.add_options()("worker-port,w", po::value<string>()->default_value(""), "listen on PORT on interface with ADDR for RPC connections from miners");                                                                                                                                                    //p2pool: worker_endpoint
    worker_group.add_options()("fee,f", po::value<float>()->default_value(0), "charge workers mining to their own bitcoin address (by setting their miner's username to a bitcoin address) this percentage fee to mine on your c2pool instance. Amount displayed at http://127.0.0.1:WORKER_PORT/fee (default: 0)"); //p2pool: worker_fee
    worker_group.add_options()("share-rate,s", po::value<float>()->default_value(3), fmt_c("Auto-adjust mining difficulty on each connection to target this many seconds per pseudoshare (default: %1%)", 3));                                                                                                       //p2pool: shhare_rate
    desc.add(worker_group);

    //coind interface
    po::options_description coind_group("coind interface");
    coind_group.add_options()("coind-config-path", po::value<string>()->default_value(""), "custom configuration file path (when coind -conf option used)");                                        //p2pool: bitcoind_config_path
    coind_group.add_options()("coind-address", po::value<string>()->default_value("127.0.0.1"), "connect to this address (default: 127.0.0.1)");                                                    //p2pool: bitcoind_address
    coind_group.add_options()("coind-rpc-port", po::value<string>()->default_value(""), "connect to JSON-RPC interface at this port (default: <read from bitcoin.conf if password not provided>)"); //p2pool: bitcoind_rpc_port [TODO]
    coind_group.add_options()("coind-rpc-ssl", po::value<bool>()->default_value(false), "connect to JSON-RPC interface using SSL");                                                                 //p2pool: bitcoind_rpc_ssl
    coind_group.add_options()("coind-p2p-port", po::value<string>()->default_value(""), "connect to P2P interface at this port (default: <read from bitcoin.conf if password not provided>)");      //p2pool: bitcoind_p2p_port [TODO]
    desc.add(coind_group);

    //=======================================
    //PARSE

    po::variables_map vm;
    po::store(po::parse_command_line(ac, av, desc), vm);
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

    //EXAMPLE:
    // if (vm.count("compression"))
    // {
    //     std::cout << "Compression level was set to "
    //               << vm["compression"].as<int>() << ".\n";
    // }
    // else
    // {
    //     std::cout << "Compression level was not set.\n";
    // }

    //============================================================
    c2pool::console::Logger::Init();
    LOG_INFO << "Start c2pool...";

    //Creating and initialization coinds network, config and NodeManager

    //##########################DGB###############################
    auto DGB = c2pool::master::Make_DGB();
    //############################################################


    //Init exit handler
    ExitSignalHandler exitSignalHandler;
    signal(SIGINT, &ExitSignalHandler::handler);
    signal(SIGTERM, &ExitSignalHandler::handler);
    signal(SIGINT, &ExitSignalHandler::handler);

    while (exitSignalHandler.working())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); //todo: std::chrono::milliseconds(100)
        std::cout << "main thread" << std::endl;
    }

    return C2PoolErrors::success;
}