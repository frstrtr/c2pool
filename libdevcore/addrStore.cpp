#include "addrStore.h"
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
        for (auto key : net->BOOTSTRAP_ADDRS)
        {
            store[key] = {
                0,
                (int64_t) c2pool::dev::timestamp(),
                (int64_t) c2pool::dev::timestamp()};
        }

        //SAVE IN FILE
        if (store.size() > 0)
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
        LOG_DEBUG << "Addrs saved in file!";
    }

    bool AddrStore::Check(addr_type key)
    {
        if (store.find(key) != store.end())
            return true;
        else
            return false;
    }

    AddrValue AddrStore::Get(addr_type key)
    {
        if (Check(key))
            return store[key];
        else
            return EMPTY_ADDR_VALUE;
    }

    std::vector<std::pair<addr_type, AddrValue>> AddrStore::GetAll()
    {
        std::vector<std::pair<addr_type, AddrValue>> res;
        for (auto kv : store)
        {
            res.push_back(kv);
        }
        return res;
    }

    bool AddrStore::Add(addr_type key, AddrValue value)
    {
        if (Check(key))
            return false;
        store.insert(std::pair<addr_type, AddrValue>(key, value));
        SaveToFile();
        return true;
    }

    bool AddrStore::Remove(addr_type key)
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

            value.pushKV("address", std::get<0>(kv.first));
            value.pushKV("port", std::get<1>(kv.first));
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
            addr_type key = std::make_tuple(AddrsValue[i]["address"].get_str(),
                                       AddrsValue[i]["port"].get_str());
            store[key] = {AddrsValue[i]["services"].get_int(),
                          AddrsValue[i]["first_seen"].get_int64(),
                          AddrsValue[i]["last_seen"].get_int64()};
        }
    }
} // namespace c2pool::p2p