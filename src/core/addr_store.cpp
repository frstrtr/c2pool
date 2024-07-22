#include "addr_store.hpp"

namespace core
{

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
    data = j.get<std::map<NetService, AddrValue>>();
}

void AddrStore::add(const NetService& addr, AddrValue value)
{
    if (check(addr)) 
        return;
    
    data[addr] = value;
    save();
}

void AddrStore::remove(const NetService& addr)
{
    if (check(addr)) 
        return;
    
    data.erase(addr);
    save();
}


} // namespace core
