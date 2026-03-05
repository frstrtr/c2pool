#pragma once

#include <core/config.hpp>
#include <core/fileconfig.hpp>
#include <core/netaddress.hpp>

#include <set>
#include <string>
#include <vector>

namespace ltc
{
    
class PoolConfig : protected core::Fileconfig
{
protected:
    std::ofstream& get_default(std::ofstream& file) override;
    void load() override;

public:
    PoolConfig(const std::filesystem::path& path) : core::Fileconfig(path)
    {

    }

    // -----------------------------------------------------------------------
    // Static LTC p2pool network constants (must match frstrtr/p2pool-merged-v36)
    // -----------------------------------------------------------------------
    static constexpr uint16_t P2P_PORT                  = 9326;
    static constexpr uint32_t SHARE_PERIOD              = 15;      // seconds
    static constexpr uint32_t CHAIN_LENGTH              = 8640;    // 24*60*60 / 10
    static constexpr uint32_t REAL_CHAIN_LENGTH         = 8640;
    static constexpr uint32_t TARGET_LOOKBEHIND         = 200;
    static constexpr uint32_t MINIMUM_PROTOCOL_VERSION  = 3301;
    static constexpr uint32_t SEGWIT_ACTIVATION_VERSION = 17;
    static constexpr uint32_t BLOCK_MAX_SIZE            = 1000000;
    static constexpr uint32_t BLOCK_MAX_WEIGHT          = 4000000;

    // Message framing prefix: 72 08 c1 a5 3e f6 29 b0
    static inline const std::string DEFAULT_PREFIX_HEX = "7208c1a53ef629b0";
    // Network identifier: e0 37 d5 b8 c6 92 34 10
    static inline const std::string IDENTIFIER_HEX     = "e037d5b8c6923410";

    static inline const std::set<std::string> SOFTFORKS_REQUIRED = {
        "bip65", "csv", "segwit", "taproot", "mweb"
    };

    // Default bootstrap peers for the LTC p2pool mainnet
    static inline const std::vector<std::string> DEFAULT_BOOTSTRAP_HOSTS = {
        "ml.toom.im",
        "usa.p2p-spb.xyz",
        "102.160.209.121",
        "5.188.104.245",
        "20.127.82.115",
        "31.25.241.224",
        "20.113.157.65",
        "20.106.76.227",
        "15.218.180.55",
        "173.79.139.224",
        "174.60.78.162",
    };

    // -----------------------------------------------------------------------
    // Runtime config loaded from pool.yaml
    // -----------------------------------------------------------------------
    std::vector<std::byte> m_prefix;
    std::string m_worker;
    std::vector<NetService> m_bootstrap_addrs;
};

} // namespace ltc
