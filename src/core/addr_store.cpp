#include "addr_store.hpp"

#include <core/common.hpp>
namespace core
{

void AddrStore::save() const
{
    // Write a sibling temp file and rename it over the store: the old
    // std::fstream(m_path) opened in/out WITHOUT truncation, so a smaller set
    // left the tail of the previous JSON behind (an unparsable file on the
    // next start), and a crash mid-write lost the whole store.
    const auto tmp = m_path.string() + ".tmp";
    {
        std::ofstream file(tmp, std::ios::out | std::ios::trunc);
        file << to_json();
        if (!file.good()) { LOG_WARNING << "Addrs [" << m_path << "] save failed"; return; }
    }
    std::error_code ec;
    std::filesystem::rename(tmp, m_path, ec);
    if (ec) { LOG_WARNING << "Addrs [" << m_path << "] save failed: " << ec.message(); return; }
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
        LOG_WARNING << "AddrStore::FromJSON " << e.what();
        return;
    }
    if (j.is_null()) return;

    try {
        // Legacy: to_json() used brace-init which wrapped the map in an extra array.
        // Unwrap [[[k,v],...]] → [[k,v],...] so get<map>() can parse it.
        if (j.is_array() && j.size() == 1 && j[0].is_array())
            j = j[0];
        m_data = j.get<std::map<NetService, AddrValue>>();
    } catch (const nlohmann::json::exception& e) {
        LOG_WARNING << "AddrStore: cannot parse " << m_path.string() << ": " << e.what();
    }
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
    if (!check(addr))
        return;
    
    m_data.erase(addr);
    save();
}

void AddrStore::update(const NetService& addr, AddrValue new_value)
{
    m_data[addr] = new_value;
    save();
}

void AddrStore::replace_all(const std::vector<AddrStorePair>& v)
{
    m_data.clear();
    for (const auto& p : v)
        m_data[p.addr] = p.value;
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
