#pragma once

#include <vector>
#include <unordered_map>
#include <list>

namespace c2pool
{
    
namespace chain
{

// Base for ShareIndexType
template <typename HashType, typename ItemType, typename HasherType>
class IndexType
{
public:
    using hash_t = HashType;
    using item_t = ItemType;
    using hasher_t = HasherType;

protected:
    const hash_t m_hash;

public:


    virtual hash_t hash() const = 0;
    
};

// template <std::size_t Size, typename ShareIndexType>
// class CacheChunk
// {
//     using index_t = ShareIndexType;
//     using hash_t = typename index_t::hash_t;
//     using item_t = typename index_t::item_t;

// private:
//     std::list<index_t> m_data;

// public:

// };

template <typename ShareIndexType>
class ShareChainCache
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
    
} // namespace chain


} // namespace c2pool
