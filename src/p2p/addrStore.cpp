#include <addrStore.h>
#include <string>
#include <univalue>

using std::string;

namespace c2pool::p2p
{

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
            value.pushKV("services", kv.second.services);
            value.pushKV("first_seen", kv.second.first);
            value.pushKV("last_seen", kv.second.last);

            DictVal.push_back(V);
        }

        std::string json = DictVal.write();
    }

    void AddrStore::FromJSON(string json)
    {
        UniValue ArrV(UniValue::VARR);
        ArrV.read(json); //TODO: add check for valid json.

        for (int i = 0; i < vRead.size(); i++)
        {
            auto key = std::make_tuple(ArrV[i]["address"], ArrV[i]["port"]);

            store[key] = {
                ArrV[i]["services"],
                ArrV[i]["first_seen"],
                ArrV[i]["last_seen"]};
        }
    }
} // namespace c2pool::p2p