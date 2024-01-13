#pragma once

#include <string>
#include <map>
#include <tuple>
#include <vector>
#include <memory>
#include <climits>

#include <nlohmann/json.hpp>
#include <boost/dll.hpp>
#include <boost/filesystem.hpp>

#include "types.h"

using namespace boost::dll;
using namespace boost::filesystem;

#define EMPTY_ADDR_VALUE {0, 0, 0}

namespace c2pool
{
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

        AddrValue(int _service, int64_t _first_seen, int64_t _last_seen)
        {
            service = _service;
            first_seen = _first_seen;
            last_seen = _last_seen;
        }

        NLOHMANN_DEFINE_TYPE_INTRUSIVE(AddrValue, service, first_seen, last_seen);
    };

    class AddrStore
    {
        typedef std::map<NetAddress, AddrValue> store_type;
    public:
        AddrStore(std::string path, c2pool::Network* net);
        void SaveToFile();
        bool Check(NetAddress addr);

        bool Add(NetAddress key, AddrValue value);
        bool Remove(NetAddress key);
        AddrValue Get(NetAddress key);
        std::vector<std::pair<NetAddress, AddrValue>> GetAll();

        nlohmann::json ToJSON();
        void FromJSON(std::string j_str);
        
        size_t len() { return store.size(); }
    private:
        store_type store;
        std::string filePath;
    };

} // namespace c2pool::p2p