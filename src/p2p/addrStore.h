#ifndef ADDR_STORE_H
#define ADDR_STORE_H
#include <string>
#include <map>
#include <tuple>

using std::map;
using std::string;
using std::tuple;

#define ADDR tuple<string, string>
#define EMPTY_ADDR_VALUE {-9999, -9999, -9999}

namespace c2pool::p2p
{

    struct AddrValue
    {
        int service;
        float first_seen;
        float last_seen;
    };

    class AddrStore
    {
    public:
        AddrStore();
        AddrStore(string json);
        bool Check(ADDR addr);

        AddrValue Get(ADDR key);
        bool Add(ADDR key, AddrValue value);
        bool Remove(ADDR key);

        string ToJSON();
        void FromJSON(string json);
        
        int len() { return store.size(); }
    private:
        map<ADDR, AddrValue> store;
    };

} // namespace c2pool::p2p

#endif //ADDR_STORE_H