#pragma once

#include <unordered_map>
#include <cstdint>
#include <stdexcept>

#include <sharechain/share.hpp>

namespace c2pool
{

namespace chain
{

// Base for ShareIndexType
template <typename HashType, typename VarShareType, typename HasherType>
class ShareIndex
{
public:
    using hash_t = HashType;
    using share_t = VarShareType;
    using hasher_t = HasherType;

    hash_t m_hash;
    int32_t m_height; 

    ShareIndex* prev {nullptr};

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
    using share_t = typename index_t::share_t;
    using hasher_t = typename index_t::hasher_t;

    struct chain_data
    {
        index_t* index;
        share_t share;

        chain_data(index_t* _index, share_t&& _share)
            : index(_index), share(std::move(_share))
        { }
    };

private:
    std::unordered_map<hash_t, chain_data, hasher_t> m_shares;

public:
    template <typename ShareT>
    void add(ShareT* _share)
    {
        static_assert(is_share_type<ShareT>, "In ShareChain can be added only BaseShare types!");

        // index
        auto index = new index_t(_share);
        
        
        // share
        share_t share = _share;
        

        m_shares[_share->m_hash] = {index, share};
    }

    chain_data& get(hash_t&& hash)
    {
        if (m_shares.contains(hash))
            return m_shares[hash];
        else
            throw std::out_of_range("Hash out of chain!");
    }

    share_t& get_share(hash_t&& hash)
    {
        return get(hash).share;
    }
    
    bool contains(hash_t&& hash)
    {
        return m_shares.contains(hash);
    }
};

} // namespace sharechain

}