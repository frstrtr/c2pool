#include "addr_store.hpp"

#include <core/common.hpp>
namespace core
{

void AddrStore::save() const
{
    std::fstream file(m_path);
    file << to_json();

    file.close();
    LOG_DEBUG_OTHER << "Addrs [" << m_path << "] saved in file!";
}

void AddrStore::from_json(std::string j_str)
{
    nlohmann::json j;
    try 
    {
        j = nlohmann::json::parse(j_str);
    } catch(const nlohmann::json::exception& e)
    {
        LOG_WARNING << "AddrStore::FromJSON " << e.what() << ", j_str = " << j_str;
        return;
    }
    m_data = j.get<std::map<NetService, AddrValue>>();
}

void AddrStore::add(const NetService& addr, AddrValue value)
{
    if (check(addr)) 
        return;
    
    m_data[addr] = value;
    save();
}

void AddrStore::remove(const NetService& addr)
{
    if (check(addr)) 
        return;
    
    m_data.erase(addr);
    save();
}

void AddrStore::load(const std::vector<NetService>& addrs)
{
    for (const NetService& addr : addrs)
    {
        m_data[addr] = {0, core::timestamp(), core::timestamp()};
    }
}

} // namespace core
