#include "addr_store.h"

#include <fstream>
#include <string>
#include <memory>

#include <networks/network.h>
#include <nlohmann/json.hpp>

#include "filesystem.h"
#include "logger.h"
#include "common.h"
using namespace c2pool::filesystem;

namespace c2pool::dev
{
    AddrStore::AddrStore(std::string path, std::shared_ptr<c2pool::Network> net)
    {
        filePath = path;
        std::fstream AddrsFile = getFile(path);

        //FILE
        //exist file
        if (AddrsFile)
        {
            std::stringstream tmp;
            tmp << AddrsFile.rdbuf();
            std::string json = tmp.str();

            FromJSON(json);
        }
        else
        {
            LOG_WARNING << "AddrsFile not found!";
        }

        //BOOTSTRAP
        for (const auto& key : net->BOOTSTRAP_ADDRS)
        {
            store[key] = {
                0,
                (int64_t) c2pool::dev::timestamp(),
                (int64_t) c2pool::dev::timestamp()
            };
        }

        //SAVE IN FILE
        if (!store.empty())
            SaveToFile();
        else
            LOG_WARNING << "AddrStore is empty!";

        AddrsFile.close();
    }

    void AddrStore::SaveToFile()
    {
        std::fstream AddrsFile = getFile(filePath);
        AddrsFile << ToJSON();

        AddrsFile.close();
        LOG_DEBUG_OTHER << "Addrs saved in file!";
    }

    bool AddrStore::Check(NetAddress key)
    {
        return store.find(key) != store.end();
    }

    AddrValue AddrStore::Get(NetAddress key)
    {
        if (Check(key))
            return store[key];
        else
            return EMPTY_ADDR_VALUE;
    }

    std::vector<std::pair<NetAddress, AddrValue>> AddrStore::GetAll()
    {
        std::vector<std::pair<NetAddress, AddrValue>> res;
        for (auto kv : store)
            res.push_back(kv);
        return res;
    }

    bool AddrStore::Add(NetAddress key, AddrValue value)
    {
        if (Check(key))
            return false;
        store.insert(std::pair<NetAddress, AddrValue>(key, value));
        SaveToFile();
        return true;
    }

    bool AddrStore::Remove(NetAddress key)
    {
        if (Check(key))
            return false;
        store.erase(key);
        SaveToFile();
        return true;
    }

    nlohmann::json AddrStore::ToJSON()
    {
        nlohmann::json j(store);
        // for (const auto& [k, v] : store)
        // {
        //     j.push_back({
        //         {"address", k.ip},
        //         {"port", k.port},
        //         {"service", v.service},
        //         {"first_seen", v.first_seen},
        //         {"last_seen", v.last_seen}
        //     });
        // }
        return j;
    }

    void AddrStore::FromJSON(string j_str)
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
        store = j.get<store_type>();
    }
} // namespace c2pool::p2p