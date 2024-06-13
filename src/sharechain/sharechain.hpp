#pragma once

#include <unordered_map>

namespace c2pool
{

namespace chain
{

// Base for ShareIndexType
template <typename HashType, typename ItemType, typename HasherType>
class ShareIndex
{
public:
    using hash_t = HashType;
    using item_t = ItemType;
    using hasher_t = HasherType;

    hash_t m_hash;
    int32_t m_height; 

    ShareIndex* prev;


public:


    virtual hash_t hash() const = 0;
    
};

template <typename ShareIndexType>
class ShareChain
{
    // using ChunkSize = std::integral_constant<std::size_t, ChunkSize>;
    using index_t = ShareIndexType;
    // using chunk_t = CacheChunk<typename index_t>;
    using hash_t = typename index_t::hash_t;
    using item_t = typename index_t::item_t;
    using hasher_t = typename index_t::hasher_t;

private:
    std::unordered_map<hash_t, item_t, hasher_t> m_shares;

public:    
    
};

} // namespace sharechain

}