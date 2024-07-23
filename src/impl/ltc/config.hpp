#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>

namespace ltc
{
    
class PoolConfig : protected core::Fileconfig
{
protected:
    std::string get_default() override;
    void load() override;

public:
    PoolConfig(const std::filesystem::path& path) : core::Fileconfig(path)
    {

    }

public:
    std::vector<std::byte> m_prefix;

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

class CoinConfig : protected core::Fileconfig
{
protected:
    std::string get_default() override;
    void load() override;

public:
    CoinConfig(const std::filesystem::path& path) : core::Fileconfig(path)
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

using Config = core::Config<PoolConfig, CoinConfig>;

} // namespace ltc
