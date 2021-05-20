#pragma once

#include <string>
#include <map>
#include <tuple>
#include <vector>
#include <memory>

#include <boost/dll.hpp>
#include <boost/filesystem.hpp>

using namespace boost::dll;
using namespace boost::filesystem;

using std::shared_ptr;
using std::map;
using std::string;
using std::tuple;

typedef tuple<string, string> addr;
#define EMPTY_ADDR_VALUE {0, 0, 0}

namespace c2pool{
    class Network;
}

namespace c2pool::dev
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
        bool Check(addr addr);

        bool Add(addr key, AddrValue value);
        bool Remove(addr key);
        AddrValue Get(addr key);
        std::vector<std::pair<addr, AddrValue>> GetAll();

        string ToJSON();
        void FromJSON(string json);
        
        int len() { return store.size(); }
    private:
        map<addr, AddrValue> store;
        std::string filePath;
    };

} // namespace c2pool::p2p