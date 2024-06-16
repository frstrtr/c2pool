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
    std::unordered_map<hash_t, std::set<hash_t>, hasher_t> m_tails;
    
    void calculate_head_tail(hash_t hash, hash_t prev, index_t* index)
    {
        enum fork_state
        {
            new_fork = 0,
            only_heads = 1,
            only_tails = 1 << 1,
            merge = only_heads | only_tails,
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
                m_tails[prev].insert(hash);
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
                m_tails[l_tail].erase(prev);

                for (auto& i : m_tails[l_tail])
                    m_heads[i] = l_tail;

                index->prev = m_shares[prev].index;
                index->calculate_index(index->prev);

                std::unordered_set<hash_t> dirty_indexs;
                for (auto& part : right.mapped())
                {
                    index_t* cur = m_shares[part].index;
                    while(cur)
                    {
                        if (dirty_indexs.contains(cur->hash))
                            break;
                        
                        dirty_indexs.insert(cur->hash);
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
        case only_tails:
            // элемент слева
            {
                std::unordered_set<hash_t> dirty_indexs;
                auto right = m_tails.extract(hash);
                for (auto& part : right.mapped())
                {
                    index_t* cur = m_shares[part].index;
                    while(cur)
                    {
                        if (dirty_indexs.contains(cur->hash))
                            break;
                        
                        dirty_indexs.insert(cur->hash);
                        cur->calculate_index(index);

                        if (!cur->prev)
                        {
                            cur->prev = index;
                            break;
                        }

                        cur = cur->prev;
                    }
                }

                for (auto& v : right.mapped())
                    m_heads[v] = prev;
                right.key() = prev;
                m_tails.insert(std::move(right));
            }
            break;
        case only_heads:
            // элемент справа
            {
                auto left_part = m_heads.extract(prev);

                index->prev = m_shares[prev].index;
                index->calculate_index(index->prev);

                m_heads[hash] = left_part.mapped();
                m_tails[left_part.mapped()].erase(left_part.key());
                m_tails[left_part.mapped()].insert(hash);
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

    index_t& get_index(hash_t&& hash)
    {
        return get(std::move(hash)).index;
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
                std::cout << value << " ";
            std::cout << "]; ";
        }
        std::cout << "}\n";
    }
};

} // namespace sharechain

}