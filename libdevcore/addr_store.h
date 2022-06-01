#pragma once

#include <string>
#include <map>
#include <tuple>
#include <vector>
#include <memory>

#include <boost/dll.hpp>
#include <boost/filesystem.hpp>

#include "types.h"

using namespace boost::dll;
using namespace boost::filesystem;

using std::shared_ptr;
using std::map;
using std::string;
using std::tuple;

#define EMPTY_ADDR_VALUE {0, 0, 0}

namespace c2pool{
    class Network;
}

namespace c2pool::dev
{

    struct AddrValue
    {
        int service;
        int64_t first_seen;
        int64_t last_seen;

        AddrValue() {}

        AddrValue(int _service, int64_t _first_seen, int64_t _last_seen){
            service = _service;
            first_seen = _first_seen;
            last_seen = _last_seen;
        }
    };

    class AddrStore
    {
    public:
        AddrStore(string path, shared_ptr<c2pool::Network> net);
        void SaveToFile();
        bool Check(addr_type addr);

        bool Add(addr_type key, AddrValue value);
        bool Remove(addr_type key);
        AddrValue Get(addr_type key);
        std::vector<std::pair<addr_type, AddrValue>> GetAll();

        string ToJSON();
        void FromJSON(string json);
        
        size_t len() { return store.size(); }
    private:
        std::map<addr_type, AddrValue> store;
        std::string filePath;
    };

} // namespace c2pool::p2p