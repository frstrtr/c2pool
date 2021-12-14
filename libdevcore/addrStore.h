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
        int first_seen;
        int last_seen;

        AddrValue(int _service, int _first_seen, int _last_seen){
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
        bool Check(c2pool::libnet::addr addr);

        bool Add(c2pool::libnet::addr key, AddrValue value);
        bool Remove(c2pool::libnet::addr key);
        AddrValue Get(c2pool::libnet::addr key);
        std::vector<std::pair<c2pool::libnet::addr, AddrValue>> GetAll();

        string ToJSON();
        void FromJSON(string json);
        
        size_t len() { return store.size(); }
    private:
        map<c2pool::libnet::addr, AddrValue> store;
        std::string filePath;
    };

} // namespace c2pool::p2p