#pragma once

#include <vector>
#include <string>
#include <map>

namespace c2pool
{

class settings
{
    static constexpr const char* default_filename = "settings.yaml";

private:
    void parse_networks();

public:

    bool m_testnet;
    std::vector<std::string> m_networks;
    float m_fee;

    static settings* load();
    static std::string get_default();
};

} // namespace c2pool