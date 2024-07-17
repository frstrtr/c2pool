#pragma once

#include <string>

#include <core/fileconfig.hpp>

namespace core {class Config;}

namespace pool
{
    class Config : protected core::Fileconfig
    {
        friend class core::Config;
        static constexpr const char* default_filename = "pool.yaml";

    protected:
        std::string get_default() override;
        void load() override;

    public:
        Config(const std::string& coin_name) 
            : core::Fileconfig(core::filesystem::config_path() / coin_name / default_filename)
        {

        }

    public:
        std::string m_worker;
        // int spread;
        // bool persist;
        // int share_period;
        // int chain_length;
        // int block_max_size;
        // int block_max_weight;
        // int target_lookbehind;
        // int real_chain_length;
        // int minimum_protocol_version;
        // int segwit_activation_version;
        // std::vector<std::string> bootstrap_addrs; // TODO: NetAddress
        // std::vector<unsigned char> donation_script;
        // std::string identifier; //TODO: const unsigned char*? + int identifier lenght
        // uint256 max_target;
        // uint256 min_target;
        // std::string pool_prefix; //=ad9614f6466a39cf //TODO: const unsigned char*? + int identifier lenght
        // std::set<std::string> softforks_required;//=bip65 csv segwit taproot mweb

        // std::string block_explorer_url_prefix;
        // std::string address_explorer_url_prefix;
        // std::string tx_explorer_url_prefix;

    };
} // namespace pool