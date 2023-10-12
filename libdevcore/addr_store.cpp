#include "addr_store.h"
#include "logger.h"
#include "common.h"
#include <univalue.h>
#include <networks/network.h>

#include <fstream>
#include <string>
#include <memory>

#include "filesystem.h"
using namespace c2pool::filesystem;
using std::shared_ptr;
using std::string;

namespace c2pool::dev
{
    AddrStore::AddrStore(string path, shared_ptr<c2pool::Network> net)
    {
        filePath = path;
        std::fstream AddrsFile = getFile(path);

        //FILE
        //exist file
        if (AddrsFile)
        {
            std::stringstream tmp;
            tmp << AddrsFile.rdbuf();
            string json = tmp.str();

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
                (int64_t) c2pool::dev::timestamp()};
        }

        //SAVE IN FILE
        if (!store.empty())
        {
            SaveToFile();
        }
        else
        {
            LOG_WARNING << "AddrStore is empty!";
        }

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
        if (store.find(key) != store.end())
            return true;
        else
            return false;
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
        {
            res.push_back(kv);
        }
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

    string AddrStore::ToJSON()
    {
        UniValue dict(UniValue::VARR);

        for (auto kv : store)
        {
            UniValue value(UniValue::VOBJ);

            value.pushKV("address", kv.first.ip);
            value.pushKV("port", kv.first.port);
            value.pushKV("services", kv.second.service);
            value.pushKV("first_seen", kv.second.first_seen);
            value.pushKV("last_seen", kv.second.last_seen);

            dict.push_back(value);
        }

        std::string json = dict.write();
        return json;
    }

    void AddrStore::FromJSON(string json)
    {
        UniValue AddrsValue(UniValue::VARR);
        AddrsValue.read(json); //TODO: add check for valid json.

        for (int i = 0; i < AddrsValue.size(); i++)
        {
            NetAddress key(AddrsValue[i]["address"].get_str(),
                                       AddrsValue[i]["port"].get_str());
            store[key] = {AddrsValue[i]["services"].get_int(),
                          AddrsValue[i]["first_seen"].get_int64(),
                          AddrsValue[i]["last_seen"].get_int64()};
        }
    }
} // namespace c2pool::p2p