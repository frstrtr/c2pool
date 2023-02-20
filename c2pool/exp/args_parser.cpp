//#include "../coind_master.h"

#include <iostream>
#include <cstring>
#include <string>
#include <signal.h>
#include <thread>
#include <chrono>
using std::cout, std::endl;
using std::string;

#include <boost/asio/thread_pool.hpp>
#include <boost/program_options.hpp>
#include <boost/format.hpp>
namespace po = boost::program_options;

#include <libdevcore/config.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <networks/network.h>

//TODO: move macros to other.h
#define fmt(TEMPL, DATA) (boost::format{TEMPL} % (DATA)).str()
#define fmt_c(TEMPL, DATA) fmt(TEMPL, DATA).data()


int main(int ac, char *av[])
{
    po::options_description desc(fmt("c2pool (ver. %1%)\nAllowed options", 0.1)); //TODO: get %Version from Network config

    //==args main
    desc.add_options()("help", "produce help message");
    desc.add_options()("version,v", "version");
    desc.add_options()("networks", po::value<std::vector<std::string>>()->multitoken(), "");

    po::variables_map vm;
    po::parsed_options parse_option = po::parse_command_line(ac, av, desc);
    po::store(parse_option, vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        cout << desc << endl;
        return 1;
    }

    if (vm.count("version"))
    {
        cout << "version: " << 0.1 << endl;
        return 1;
    }

    if (vm.count("networks"))
    {
        cout << "networks: [";
        auto nets = vm["networks"].as<std::vector<std::string>>(); //networks=digibyte bitcoin ethereum
        for (auto v : nets)
            std::cout << v << "; ";
        std::cout << "]";
    }
}