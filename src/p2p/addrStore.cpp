#include <addrStore.h>
#include <string>
//#include <univalue>

using std::string;

namespace c2pool::p2p{

    bool AddrStore::Check(ADDR key){
        if (store.find(key) != store.end())
            return true;
        else
            return false;
    }

    AddrValue AddrStore::Get(ADDR key){
        if (Check(key))
            return store[key];
        else
            return EMPTY_ADDR_VALUE;
    }

    bool AddrStore::Add(ADDR key, AddrValue value){
        if (Check(key))
            return false;
        store.insert(std::pair<ADDR, AddrValue>(key, value));
        return true;
    }

    bool AddrStore::Remove(ADDR key){
        if (Check(key))
            return false;
        store.erase(key);
        return true;
    }

    string AddrStore::ToJSON(){
        //TODO:
    }
    
    void AddrStore::FromJSON(string json){
        //TODO:
    }
}