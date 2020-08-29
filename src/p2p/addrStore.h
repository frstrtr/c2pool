#ifndef ADDR_STORE_H
#define ADDR_STORE_H
#include <string>
#include <map>
#include <tuple>

using std::map;
using std::string;
using std::tuple;

#define ADDR tuple<string, string>
#define EMPTY_ADDR_VALUE {0, 0, 0}

namespace c2pool::config{
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
        AddrStore(string path, c2pool::config::Network* net);
        void SaveToFile();
        bool Check(ADDR addr);

        bool Add(ADDR key, AddrValue value);
        bool Remove(ADDR key);
        AddrValue Get(ADDR key);

        string ToJSON();
        void FromJSON(string json);
        
        int len() { return store.size(); }
    private:
        map<ADDR, AddrValue> store;
        std::string filePath;
    };

} // namespace c2pool::p2p

#endif //ADDR_STORE_H