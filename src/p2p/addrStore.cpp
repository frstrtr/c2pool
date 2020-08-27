#include "addrStore.h"
#include "univalue.h"
#include "config.h"
#include <string>
#include <fstream>
#include "console.h"

using std::string;

namespace c2pool::p2p
{
    //template path — "data//bitcoin//addrs"
    AddrStore::AddrStore(string path, c2pool::config::Network *net)
    {
        std::fstream AddrsFile(path, std::ios_base::in);

        //exist file
        if (AddrsFile)
        {

            string json;
            //Если будет баг с тем, что файл как-то не так читается, то винить эту строку, не меня.
            //Кто же знал, что вы будете разделять json файл на кучу строк.
            AddrsFile >> json;

            UniValue AddrsValue(UniValue::VARR);

            for (int i = 0; i < ArrsValue.size())

            value.pushKV("address", std::get<0>(kv.first));
            value.pushKV("port", std::get<1>(kv.first));
            value.pushKV("services", kv.second.service);
            value.pushKV("first_seen", kv.second.first_seen);
            value.pushKV("last_seen", kv.second.last_seen);

        }


    }

    bool AddrStore::Check(ADDR key)
    {
        if (store.find(key) != store.end())
            return true;
        else
            return false;
    }

    AddrValue AddrStore::Get(ADDR key)
    {
        if (Check(key))
            return store[key];
        else
            return EMPTY_ADDR_VALUE;
    }

    bool AddrStore::Add(ADDR key, AddrValue value)
    {
        if (Check(key))
            return false;
        store.insert(std::pair<ADDR, AddrValue>(key, value));
        return true;
    }

    bool AddrStore::Remove(ADDR key)
    {
        if (Check(key))
            return false;
        store.erase(key);
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
        UniValue ArrV(UniValue::VARR);
        ArrV.read(json); //TODO: add check for valid json.

        for (int i = 0; i < ArrV.size(); i++)
        {
            auto key = std::make_tuple(ArrV[i]["address"].get_str(), ArrV[i]["port"].get_str());

            store[key] = {
                ArrV[i]["services"].get_int(),
                ArrV[i]["first_seen"].get_real(),
                ArrV[i]["last_seen"].get_real()};
        }
    }
} // namespace c2pool::p2p