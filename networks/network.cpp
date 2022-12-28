#include "network.h"
#include <vector>
#include <string>
#include <iostream>
#include <tuple>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/algorithm/string.hpp>

#include <libdevcore/str.h>
#include <btclibs/uint256.h>
#include <btclibs/util/strencodings.h>
#include <libdevcore/stream_types.h>

namespace c2pool
{

    Network::Network(std::string name) : net_name(name)
    {
        LOG_INFO << "Created Network [" << name << "].";
    }

    Network::Network(std::string name, boost::property_tree::ptree &_pt) : Network(name)
    {
//        , std::shared_ptr<coind::ParentNetwork> _parent_net

        auto pt = _pt.get_child("network");

        auto _softforks = c2pool::dev::string_to_vector<std::string>(pt.get<std::string>("SOFTFORKS_REQUIRED"));
        SOFTFORKS_REQUIRED = std::set<std::string>(_softforks.begin(), _softforks.end());

        auto _bootstrap_addrs = c2pool::dev::string_to_vector<std::string>(pt.get<std::string>("BOOTSTRAP_ADDRS"));
        std::transform(_bootstrap_addrs.begin(), _bootstrap_addrs.end(), BOOTSTRAP_ADDRS.end(), [](std::string s){
            std::vector<std::string> _addr;
            boost::split(_addr, s, boost::is_any_of(":"));

            if (_addr.size() == 2)
            {
                return std::make_tuple(_addr[0], _addr[1]);
            } else
            {
                return std::make_tuple<std::string, std::string>("","");
            }
        });

        auto _prefix = pt.get<std::string>("PREFIX");
        PREFIX_LENGTH = _prefix.length() %2;
        PREFIX = new unsigned char[PREFIX_LENGTH];
        // TODO: PARSE PREFIX

//        network.put("PREFIX", "83e65d2c81bf6d68");
//        network.put("IDENTIFIER", "83e65d2c81bf6d66");
//
//        network.put("MINIMUM_PROTOCOL_VERSION", 1600);
//        network.put("SEGWIT_ACTIVATION_VERSION", 17);
//        network.put("TARGET_LOOKBEHIND", 200);
//        network.put("SHARE_PERIOD", 25);
//        network.put("BLOCK_MAX_SIZE", 1000000);
//        network.put("BLOCK_MAX_WEIGHT", 4000000);
//        network.put("REAL_CHAIN_LENGTH", 24 * 60 * 60 / 10);
//        network.put("CHAIN_LENGTH", 24 * 60 * 60 / 10);
//        network.put("SPREAD", 30);
//        network.put("ADDRESS_VERSION", 30);
//        network.put("PERSIST", true);
//
//        network.put("MIN_TARGET", "0");
//        network.put("MAX_TARGET", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
//
//        network.put("DONATION_SCRIPT", "5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae");
    }

    boost::property_tree::ptree Network::make_default_network()
    {
        using boost::property_tree::ptree;

        ptree root;

        // NETWORK
        ptree network;
        network.put("SOFTFORKS_REQUIRED", c2pool::dev::vector_to_string(std::vector<std::string>{"nversionbips", "csv", "segwit", "reservealgo", "odo"}));
        network.put("BOOTSTRAP_ADDRS", c2pool::dev::vector_to_string(std::vector<std::string>{}));
        network.put("PREFIX", "83e65d2c81bf6d68");
        network.put("IDENTIFIER", "83e65d2c81bf6d66");

        network.put("MINIMUM_PROTOCOL_VERSION", 1600);
        network.put("SEGWIT_ACTIVATION_VERSION", 17);
        network.put("TARGET_LOOKBEHIND", 200);
        network.put("SHARE_PERIOD", 25);
        network.put("BLOCK_MAX_SIZE", 1000000);
        network.put("BLOCK_MAX_WEIGHT", 4000000);
        network.put("REAL_CHAIN_LENGTH", 24 * 60 * 60 / 10);
        network.put("CHAIN_LENGTH", 24 * 60 * 60 / 10);
        network.put("SPREAD", 30);
        network.put("ADDRESS_VERSION", 30);
        network.put("PERSIST", true);

        network.put("MIN_TARGET", "0");
        network.put("MAX_TARGET", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        network.put("DONATION_SCRIPT", "5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae");

        // init gentx_before_refhash
//        std::vector<unsigned char> _gentx_before_refhash;
//        {
//            PackStream gentx_stream;
//
//            StrType dnt_scpt(ParseHex("5221038ab82f3a4f569c4571c483d56729e83399795badb32821cab64d04e7b5d106864104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b410457a337b86557f5b15c94544ad267f96a582dc2b91e6873968ff7ba174fda6874af979cd9af41ec2032dfdfd6587be5b14a4355546d541388c3f1555a67d11c2d53ae"));
//            gentx_stream << dnt_scpt;
//
//            IntType(64) empty_64int(0);
//            gentx_stream << empty_64int;
//
//            PackStream second_str_stream(std::vector<unsigned char>{0x6a, 0x28});
//            IntType(256) empty_256int(uint256::ZERO);
//            second_str_stream << empty_256int;
//            second_str_stream << empty_64int;
//
//            PackStream for_cut;
//            StrType second_str(second_str_stream.data);
//            for_cut << second_str;
//            for_cut.data.erase(for_cut.data.begin() + 3 , for_cut.data.end());
//
//            gentx_stream << for_cut;
//            _gentx_before_refhash = gentx_stream.data;
//        }
//
//        network.put("gentx_before_refhash", HexStr(_gentx_before_refhash));

        root.push_front(
                ptree::value_type( "network", network)
        );

        // PARENT NETWORK
        root.push_front(
                ptree::value_type("parent_network", coind::ParentNetwork::make_default_network())
        );

        return root;
    }

    std::shared_ptr<c2pool::Network> load_network_file(std::string net_name)
    {
        auto path = boost::filesystem::current_path() / net_name;

        // Проверка на существование пути, создание его, в случае отсутствия.
        boost::system::error_code ec;
        if (!boost::filesystem::exists(path))
        {
            boost::filesystem::create_directories(path, ec);
            if (ec)
                std::cout << "Error when opening network[" << net_name << "] " << ".cfg: " << ec.message() << std::endl;
        }

        // Проверка и создание default network файла.
        if (!boost::filesystem::exists(path/"network.cfg"))
        {
            std::fstream f((path/"network.cfg").string(), ios_base::out);
            boost::property_tree::write_ini(f, c2pool::Network::make_default_network());
            f.close();
        }

        // Загрузка из файла
        boost::property_tree::ptree pt;
        boost::property_tree::ini_parser::read_ini((path/"network.cfg").string(), pt);
        std::cout << pt.get<std::string>("network.DONATION_SCRIPT") << std::endl;

        return std::make_shared<c2pool::Network>(net_name, pt);
    }
} // namespace c2pool::config

namespace coind
{
    ParentNetwork::ParentNetwork(std::string name) : net_name(name)
    {
    }

    ParentNetwork::ParentNetwork(std::string name, boost::property_tree::ptree &pt) : ParentNetwork(name)
    {

    }

    boost::property_tree::ptree ParentNetwork::make_default_network()
    {
        using boost::property_tree::ptree;
        ptree network;

        network.put("PREFIX", "fac3b6da");
        network.put("P2P_ADDRESS", "217.72.4.157");
        network.put("P2P_PORT", 12024);
        network.put("ADDRESS_VERSION", 30);
        network.put("RPC_PORT", 14024);
        network.put("BLOCK_PERIOD", 150);
        network.put("DUMB_SCRYPT_DIFF", 1);
        network.put("DUST_THRESHOLD", 0.001e8);

        network.put("SANE_TARGET_RANGE_MIN", "10c6f7a0b5ed8d36b4c7f34938583621fafc8b0079a2834d26f9");
        network.put("SANE_TARGET_RANGE_MAX", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        return network;
    }
}
