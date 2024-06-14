#pragma once

#include <unordered_map>
#include <set>
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

    hash_t hash;
    int32_t height; 

    ShareIndex* prev {nullptr};

public:

    ShareIndex() : hash{}, height{0} {}
    template <typename ShareT> ShareIndex(ShareT* share) : hash{share->m_hash}, height{1} {}

    void calculate_index()
    {
        if (!prev)
            return;

        height += prev->height;
        calculate();
    }

protected:
    virtual void calculate() = 0;
};

template <typename ShareIndexType>
class ShareChain
{
    using index_t = ShareIndexType;
    using hash_t = typename index_t::hash_t;
    using share_t = typename index_t::share_t;
    using hasher_t = typename index_t::hasher_t;

    struct chain_data
    {
        index_t* index;
        share_t share;

        chain_data() {}
        chain_data(index_t* _index, share_t& _share) : index(_index), share(std::move(_share)) {}
    };

private:
    std::unordered_map<hash_t, chain_data, hasher_t> m_shares;
    std::unordered_map<hash_t, index_t*, hasher_t> heads;
    std::unordered_map<hash_t, std::set<index_t*>, hasher_t> heads;
    

public:
    template <typename ShareT>
    void add(ShareT* share)
    {
        static_assert(is_share_type<ShareT>, "In ShareChain can be added only BaseShare types!");

        // index
        auto index = new index_t(share);
        if (m_shares.contains(share->m_prev_hash))
            index->prev = m_shares[share->m_prev_hash].index;
        index->calculate_index(); 
        
        // share_variants
        share_t share_var; share_var = share;
        
        m_shares[share->m_hash] = chain_data{index, share_var};
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
        return get(std::move(hash)).share;
    }
    
    bool contains(hash_t&& hash)
    {
        return m_shares.contains(hash);
    }
};

} // namespace sharechain

}