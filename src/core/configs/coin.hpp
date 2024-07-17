#pragma once

#include <string>

#include <core/fileconfig.hpp>

namespace core { class Config; }

namespace coin
{
    class Config : protected core::Fileconfig
    {
        friend class core::Config;
        static constexpr const char* default_filename = "coin.yaml";

    protected:
        std::string get_default() override;
        void load() override;

    public:
        Config(const std::string& coin_name) 
            : core::Fileconfig(core::filesystem::config_path() / coin_name / default_filename)
        {

        }

    public:
        int m_share_period;
        // std::string symbol;
        // std::string coin_prefix; //TODO: const unsigned char*? + int identifier lenght
        // int32_t block_period;
        // std::string p2p_address;
        // int p2p_port
        // int address_vesion;
        // int address_p2sh_version;
        // int rpc_port;

        // uint256 dumb_scrypt_diff;
    };
} // namespace coin