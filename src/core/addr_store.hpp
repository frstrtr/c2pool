#pragma once

#include <map>

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
    const std::string filePath = "";

    std::map<NetService, AddrValue> data;

private:
    nlohmann::json to_json() { return nlohmann::json{data}; }
    void from_json(std::string j_str);

public:
    AddrStore() {}

    /**/void save() const;
    bool check(const NetService& addr) const { return data.contains(addr); }
    AddrValue get(const NetService& addr) const { return check(addr) ? data.at(addr) : AddrValue{}; }

    void add(const NetService& addr, AddrValue value);
    void remove(const NetService& addr);

    std::vector<AddrStorePair> get_all() const
    {
        std::vector<AddrStorePair> all;
        for (auto kv : data)
        {
            all.emplace_back(kv);
        }
        return all;
    }

    size_t len() const { return data.size(); }
};

} // namespace core
