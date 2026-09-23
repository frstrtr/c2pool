#include "addr_store.hpp"

#include <system_error>

#include <core/common.hpp>
namespace core
{

void AddrStore::save() const
{
    // Write the whole document to a sibling temp file, then rename it over
    // addrs.json (#1719). The old std::fstream(m_path) opened in|out with no
    // truncate: a shorter document left the previous tail behind, the next load
    // failed to parse and dropped the peer book, and a missing file was never
    // recreated. rename() within one directory replaces the target atomically
    // on POSIX, so a crash mid-write leaves the previous file intact.
    std::filesystem::path tmp = m_path;
    tmp += ".tmp";

    std::error_code ec;
    {
        std::ofstream file(tmp, std::ios::out | std::ios::trunc);
        file << to_json();
        file.close();
        if (file.fail())
        {
            LOG_WARNING << "Addrs [" << m_path << "] not saved: cannot write " << tmp;
            std::filesystem::remove(tmp, ec);
            return;
        }
    }

    std::filesystem::rename(tmp, m_path, ec);
    if (ec)
    {
        LOG_WARNING << "Addrs [" << m_path << "] not saved: rename failed: " << ec.message();
        std::filesystem::remove(tmp, ec);
        return;
    }
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
        // Unwrap [[[k,v],...]] → [[k,v],...] so get<map>() can parse it. Only when
        // element 0 is itself a list of pairs (or the empty legacy book [[]]):
        // a current one-entry book [[k,v]] also has one array element, and
        // unwrapping it to [k,v] lost the whole book on reload (#1719).
        if (j.is_array() && j.size() == 1 && j[0].is_array()
            && (j[0].empty() || j[0][0].is_array()))
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

void AddrStore::load(const std::vector<NetService>& addrs)
{
    for (const NetService& addr : addrs)
    {
        m_data[addr] = {0, core::timestamp(), core::timestamp()};
    }
}

} // namespace core
