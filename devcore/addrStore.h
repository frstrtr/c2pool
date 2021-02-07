#pragma once

#include <string>
#include <map>
#include <tuple>
#include <vector>
#include <memory>

using std::shared_ptr;
using std::map;
using std::string;
using std::tuple;

#define ADDR tuple<string, string>
#define EMPTY_ADDR_VALUE {0, 0, 0}

namespace c2pool{
    class Network;
}

namespace c2pool::p2p
{

    struct AddrValue
    {
        int service;
        double first_seen;
        double last_seen;
    };

    class AddrStore
    {
    public:
        AddrStore(string path, shared_ptr<c2pool::Network> net);
        void SaveToFile();
        bool Check(ADDR addr);

        bool Add(ADDR key, AddrValue value);
        bool Remove(ADDR key);
        AddrValue Get(ADDR key);
        std::vector<std::pair<ADDR, AddrValue>> GetAll();

        string ToJSON();
        void FromJSON(string json);
        
        int len() { return store.size(); }
    private:
        map<ADDR, AddrValue> store;
        std::string filePath;
    };

} // namespace c2pool::p2p