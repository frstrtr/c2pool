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

    int32_t get_height(hash_t&& hash)
    {
        return get_index(std::move(hash))->height;
    }

    hash_t get_last(hash_t&& hash)
    {
        //todo: check exist?
        return m_heads[hash];
    }

    struct height_and_last
    {
        int32_t height;
        hash_t last;
    };

    height_and_last get_height_and_last(hash_t item)
    {
        return {get_height(item), get_last(item)};
    }

    hash_t get_nth_parent_key(hash_t&& hash, int32_t n) const
    {
        auto index = get_index(std::move(hash));
        for (int i = 0; i < n; i++)
        {
            if (index->prev)
                index = index->prev;
            else
                throw std::invalid_argument("get_nth_parent_key: m_shares not exis't hash");
        }
        return index->hash;
    }

    bool is_child_of(hash_t&& item, hash_t&& possible_child)
    {
        if (item == possible_child)
            return true;
        
        auto [height, last] = get_height_and_last(item);
        auto [child_height, child_last] = get_height_and_last(possible_child);

        if (last != child_last)
            return false;

        auto height_up = child_height - height;
        return height_up >= 0 && get_nth_parent_key(possible_child, height_up) == item;
    }

    // // last------(ancestor------item]--->best
    // interval_t get_interval(hash_t item, hash_t ancestor)
    // {
    //     if (!is_child_of(ancestor, item))
    //         throw std::invalid_argument("get_sum item[" + item.ToString() + "] not child for ancestor[" + ancestor.ToString() + "]");

    //     auto [result, _head, _tail] = get_sum_to_last(item);
    //     auto [ances, _head2, _tail2] = get_sum_to_last(ancestor);

    //     return result.sub(ances);
    // }

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

    /*
    
    [~]void remove(hash_t&& key);
        [+]sum_to_last get_sum_to_last(hash_t hash);
    [?]sum_element get_sum_for_element(const hash_t& hash);
        [+]int32_t get_height(hash_t&& hash);
        [+]hash_type get_last(hash_t&& hash);
        [+]height_and_last get_height_and_last(hash_t&& item);
        [+]bool is_child_of(hash_t&& item, hash_t&& possible_child);
        [+]hash_type get_nth_parent_key(hash_t&& hash, int32_t n) const;
    []std::function<bool(hash_type&)> get_chain(hash_t&& hash, uint64_t n)
    []sum_element get_sum(hash_type item, hash_type ancestor)
    */
};

} // namespace sharechain

}