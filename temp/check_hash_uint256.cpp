#include <iostream>
#include <unordered_set>

#include <core/uint256.hpp>

struct ShareHasher
{
    // this used to call `GetCheapHash()` in uint256, which was later moved; the
    // cheap hash function simply calls ReadLE64() however, so the end result is
    // identical
    size_t operator()(const uint256& hash) const 
    {
        return hash.GetLow64();
    }
};

int main()
{
    std::unordered_set<uint256, ShareHasher> dirty_indexs;
    
}