#pragma once

#include <unordered_map>
#include <unordered_set>
#include <set>
#include <cstdint>
#include <stdexcept>

#include <sharechain/share.hpp>

namespace c2pool
{

namespace chain
{

// Base for ShareIndexType
template <typename HashType, typename VarShareType, typename HasherType, typename HighIndex>
class ShareIndex
{
protected:
    using base_index = ShareIndex<HashType, VarShareType, HasherType, HighIndex>;
public:
    using hash_t = HashType;
    using share_t = VarShareType;
    using hasher_t = HasherType;
    using high_index_t = HighIndex;

    hash_t hash;
    int32_t height; 

    high_index_t* prev {nullptr};

public:

    ShareIndex() : hash{}, height{0} {}
    template <typename ShareT> ShareIndex(ShareT* share) : hash{share->m_hash}, height{1} {}

    void calculate_index(high_index_t* index)
    {
        if (!index)
            throw std::invalid_argument("nullptr index");

        height += index->height;
        calculate(index);
    }

protected:
    virtual void calculate(high_index_t* index) = 0;
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

    std::unordered_map<hash_t, hash_t, hasher_t> m_heads;
    std::unordered_map<hash_t, std::set<index_t*>, hasher_t> m_tails;
    
    void calculate_head_tail(hash_t hash, hash_t prev, index_t* index)
    {
        enum fork_state
        {
            new_fork = 0,
            only_heads = 1,
            only_tails = 1 << 1,
            merge = only_heads | only_tails,

            split = 1 << 2
        };

        int state = new_fork;
        if (m_heads.contains(prev))
            state |= only_heads;
        if (m_tails.contains(hash))
            state |= only_tails;

        switch (state)
        {
        case new_fork:
            // создание нового форка
            {
                m_heads[hash] = prev;    
                m_tails[prev].insert(index);
            }
            break;
        case merge:
            // объединение двух форков на стыке нового элемента
            {
                auto left = m_heads.extract(prev); // heads[t]
                auto& l_tail = left.mapped(); auto& l_head = left.key();
                auto right = m_tails.extract(hash); // tails[h]
                auto& r_tail = right.key(); auto& r_heads = right.mapped();

                m_tails[l_tail].insert(r_heads.begin(), r_heads.end());
                m_tails[l_tail].erase(m_shares[prev].index);

                for (auto& i : m_tails[l_tail])
                    m_heads[i->hash] = l_tail;

                index->prev = m_shares[prev].index;
                index->calculate_index(index->prev);

                // // right
                std::unordered_set<index_t*> dirty_indexs;
                
                // right_parts.key() = left_part.key();
                for (auto& part : right.mapped())
                {
                    index_t* cur = part;
                    while(cur)
                    {
                        if (dirty_indexs.contains(cur))
                            break;
                        
                        dirty_indexs.insert(cur);
                        cur->calculate_index(index);

                        if (!cur->prev)
                        {
                            cur->prev = index;
                            break;
                        }

                        cur = cur->prev;
                    }
                }
                // for (auto& head : right_parts.mapped())
                // {
                //     m_heads[head->hash] = left_part.mapped();
                //     m_tails[left_part.mapped()].insert(head);
                // }
                // m_heads.insert(std::move(left_part));
                // m_tails.insert(std::move(right_parts));
            }
            break;
        case only_tails:
            // элемент слева
            {
                std::unordered_set<index_t*> dirty_indexs;
                auto right_parts = m_tails.extract(hash);
                for (auto& part : right_parts.mapped())
                {
                    index_t* cur = part;
                    while(cur)
                    {
                        if (dirty_indexs.contains(cur))
                            break;
                        
                        dirty_indexs.insert(cur);
                        cur->calculate_index(index);

                        if (!cur->prev)
                        {
                            cur->prev = index;
                            break;
                        }

                        cur = cur->prev;
                    }
                }
            }
            break;
        case only_heads:
            // элемент справа
            {
                auto left_part = m_heads.extract(prev);
                // left_part.key() = hash;

                index->prev = m_shares[prev].index;
                index->calculate_index(index->prev);
                m_heads[hash] = left_part.mapped();
                m_tails[left_part.mapped()].erase(m_shares[left_part.key()].index);
                m_tails[left_part.mapped()].insert(index);
                // m_heads.insert(std::move(left_part));
            }
            break;
        }
    }

public:
    template <typename ShareT>
    void add(ShareT* share)
    {
        static_assert(is_share_type<ShareT>, "In ShareChain can be added only BaseShare types!");

        // index
        auto index = new index_t(share);
        // if (m_shares.contains(share->m_prev_hash))
        //     index->prev = m_shares[share->m_prev_hash].index;
        // index->calculate_index(index->prev); 
        
        // share_variants
        share_t share_var; share_var = share;

        calculate_head_tail(share->m_hash, share->m_prev_hash, index);
        
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

    void debug()
    {
        std::cout << "m_heads: {";
        for (auto& [hash, value] : m_heads)
        {
            std::cout << " " << hash << ":" << value << "; ";
        }

        std::cout << "}, m_tails: {";
        for (auto& [hash, values] : m_tails)
        {
            std::cout << " " << hash << ": [ ";
            for (auto& value : values)
                std::cout << value->hash << " ";
            std::cout << "]; ";
        }
        std::cout << "}\n";
    }
};

} // namespace sharechain

}