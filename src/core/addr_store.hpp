#pragma once

#include <map>
#include <fstream>

#include <core/log.hpp>
#include <core/filesystem.hpp>
#include <core/netaddress.hpp>

#include <nlohmann/json.hpp>

namespace core
{

struct AddrValue
{
    int m_service;
    uint64_t m_first_seen;
    uint64_t m_last_seen;

    AddrValue() {}
    AddrValue(int service, uint64_t first_seen, uint64_t last_seen) : m_service(service), m_first_seen(first_seen), m_last_seen(last_seen) { }

    NLOHMANN_DEFINE_TYPE_INTRUSIVE(AddrValue, m_service, m_first_seen, m_last_seen);
};

struct AddrStorePair
{
    NetService addr;
    AddrValue value;

    AddrStorePair(NetService& _addr, AddrValue& _value) : addr(_addr), value(_value) { }
    AddrStorePair(std::pair<const NetService, core::AddrValue> _pair) : addr(_pair.first), value(_pair.second) { }
};

class AddrStore
{
    static constexpr const char* default_filename = "addrs.json";

    std::map<NetService, AddrValue> m_data;
    std::filesystem::path m_path;

private:
    nlohmann::json to_json() const { return nlohmann::json{m_data}; }
    void from_json(std::string j_str);

public:
    AddrStore(const std::string& coin_name) : m_path(core::filesystem::config_path() / coin_name / default_filename)
    {
        // check for exist path + make default
        if (std::filesystem::exists(m_path))
        {
            std::fstream file(m_path);
            std::string j_str((std::istreambuf_iterator<char>(file)),
                 std::istreambuf_iterator<char>());
            from_json(j_str);
            file.close();
        }
        else
        {
            std::filesystem::create_directory(m_path.parent_path());
        
            std::ofstream file(m_path);
            file << nlohmann::json{}.dump();
            file.close();

            LOG_WARNING << "Config (" << m_path << "): not found, created default.";
        }
    }

    void save() const;
    bool check(const NetService& addr) const { return m_data.contains(addr); }
    AddrValue get(const NetService& addr) const { return check(addr) ? m_data.at(addr) : AddrValue{}; }

    void add(const NetService& addr, AddrValue value);
    void remove(const NetService& addr);
    // for bootstrap
    void load(const std::vector<NetService>& addrs);

    std::vector<AddrStorePair> get_all() const
    {
        std::vector<AddrStorePair> all;
        for (auto kv : m_data)
        {
            all.emplace_back(kv);
        }
        return all;
    }

    size_t len() const { return m_data.size(); }
};

} // namespace core
