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
#include "coind_networks/parent_func.h"

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
        std::transform(_bootstrap_addrs.begin(), _bootstrap_addrs.end(), std::back_inserter(BOOTSTRAP_ADDRS), [](std::string s){
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

        // PREFIX
        auto _prefix_str = pt.get<std::string>("PREFIX");
        auto _prefix = ParseHex(_prefix_str);
        PREFIX_LENGTH = _prefix.size();
        c2pool::dev::copy_to_const_c_str(_prefix, PREFIX);

        // IDENTIFIER
        auto _ident_str = pt.get<std::string>("IDENTIFIER");
        auto _ident = ParseHex(_ident_str);
        IDENTIFIER_LENGTH = _ident.size();
        c2pool::dev::copy_to_const_c_str(_ident, IDENTIFIER);

        //
        MINIMUM_PROTOCOL_VERSION = pt.get<int>("MINIMUM_PROTOCOL_VERSION");
        SEGWIT_ACTIVATION_VERSION = pt.get<int>("SEGWIT_ACTIVATION_VERSION");
        TARGET_LOOKBEHIND = pt.get<int>("TARGET_LOOKBEHIND");
        SHARE_PERIOD = pt.get<int>("SHARE_PERIOD");
        BLOCK_MAX_SIZE = pt.get<int>("BLOCK_MAX_SIZE");
        BLOCK_MAX_WEIGHT = pt.get<int>("BLOCK_MAX_SIZE");
        REAL_CHAIN_LENGTH = pt.get<int>("REAL_CHAIN_LENGTH");
        CHAIN_LENGTH = pt.get<int>("CHAIN_LENGTH");
        SPREAD = pt.get<int>("SPREAD");
        ADDRESS_VERSION = pt.get<int>("ADDRESS_VERSION");
        PERSIST = pt.get<bool>("PERSIST");

        MIN_TARGET = uint256S(pt.get<std::string>("MIN_TARGET"));
        MAX_TARGET = uint256S(pt.get<std::string>("MAX_TARGET"));

        DONATION_SCRIPT = ParseHex(pt.get<std::string>("DONATION_SCRIPT"));

//      init gentx_before_refhash
        {
            PackStream gentx_stream;

            StrType dnt_scpt(DONATION_SCRIPT);
            gentx_stream << dnt_scpt;

            IntType(64) empty_64int(0);
            gentx_stream << empty_64int;

            PackStream second_str_stream(std::vector<unsigned char>{0x6a, 0x28});
            IntType(256) empty_256int(uint256::ZERO);
            second_str_stream << empty_256int;
            second_str_stream << empty_64int;

            PackStream for_cut;
            StrType second_str(second_str_stream.data);
            for_cut << second_str;
            for_cut.data.erase(for_cut.data.begin() + 3 , for_cut.data.end());

            gentx_stream << for_cut;
            gentx_before_refhash = gentx_stream.data;
        }

        parent = std::make_shared<coind::ParentNetwork>(name, _pt.get_child("parent_network"));

//        for (auto v = parent->PREFIX; v < parent->PREFIX+parent->PREFIX_LENGTH; v++)
//        {
//            std::cout << (unsigned int) *v << " ";
//        }
//        std::cout << std::endl;
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
        // PREFIX
        auto _prefix_str = pt.get<std::string>("PREFIX");
        auto _prefix = ParseHex(_prefix_str);
        PREFIX_LENGTH = _prefix.size();
        c2pool::dev::copy_to_const_c_str(_prefix, PREFIX);


        BLOCK_PERIOD = pt.get<int32_t>("BLOCK_PERIOD");
        P2P_ADDRESS = pt.get<std::string>("P2P_ADDRESS");
        P2P_PORT = pt.get<int>("P2P_PORT");
        ADDRESS_VERSION = pt.get<int>("ADDRESS_VERSION");
        RPC_PORT = pt.get<int>("RPC_PORT");

//        DUMB_SCRYPT_DIFF = uint256S(pt.get<std::string>("DUMB_SCRYPT_DIFF"));
        {
            std::stringstream ss;
            ss << hex << pt.get<int>("DUMB_SCRYPT_DIFF");
            std::string hex_dumb_scrypt_diff;
            ss >> hex_dumb_scrypt_diff;
            DUMB_SCRYPT_DIFF = uint256S(hex_dumb_scrypt_diff);
        }

        DUST_THRESHOLD = pt.get<int>("DUST_THRESHOLD");

        SANE_TARGET_RANGE_MIN = uint256S(pt.get<std::string>("SANE_TARGET_RANGE_MIN"));
        SANE_TARGET_RANGE_MAX = uint256S(pt.get<std::string>("SANE_TARGET_RANGE_MAX"));

        // POW_FUNC
        set_pow_func(pt.get<std::string>("POW_FUNC"));

        // SUBSIDY_FUNC
        set_subsidy_func(pt.get<std::string>("SUBSIDY_FUNC"));
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
        network.put("DUMB_SCRYPT_DIFF", "10000");
        network.put("DUST_THRESHOLD", 3000000);

        network.put("SANE_TARGET_RANGE_MIN", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        network.put("SANE_TARGET_RANGE_MAX", "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        network.put("POW_FUNC", "scrypt");
        network.put("SUBSIDY_FUNC", "dgb");

        return network;
    }

    void ParentNetwork::set_pow_func(std::string name)
    {
        if (name == "scrypt")
        {
            POW_FUNC = [](auto &packed_block_header)
            {
                return SCRYPT_POW_FUNC(packed_block_header);
            };
            return;
        }


        // default:
        LOG_ERROR << "Not exist POW_FUNC with name: [" << name << "]";
        POW_FUNC = [](auto &packed_block_header)
        {
            LOG_ERROR << "empty POW_FUNC";
            return uint256::ZERO;
        };
    }

    void ParentNetwork::set_subsidy_func(std::string name)
    {
        if (name == "dgb")
        {
            SUBSIDY_FUNC = [](int32_t height)
            {
                return DGB_SUBSIDY_FUNC(height);
            };
            return;
        }


        // default:
        LOG_ERROR << "Not exist SUBSIDY_FUNC with name: [" << name << "]";
        SUBSIDY_FUNC = [](auto height)
        {
            LOG_ERROR << "empty SUBSIDY_FUNC";
            return 0;
        };
    }
}
