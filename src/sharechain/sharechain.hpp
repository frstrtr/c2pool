#pragma once

#include <unordered_map>
#include <unordered_set>
#include <set>
#include <cstdint>
#include <stdexcept>

#include <sharechain/share.hpp>

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

    hash_t head;
    hash_t tail;
    int32_t height; 

    high_index_t* prev {nullptr};
    
public:
    ShareIndex() : head{}, height{0} {}
    template <typename ShareT> 
    ShareIndex(ShareT* share) : head{share->m_hash}, tail{share->m_prev_hash}, height{1} {}

    void calculate_index(high_index_t* index)
    {
        if (!index)
            throw std::invalid_argument("nullptr index");

        operation(index, plus);
    }

    enum operation_type
    {
        plus,
        minus
    };

    void operation(high_index_t* index, operation_type operation)
    {
        switch (operation)
        {
        case plus:
            height += index->height;
            add(index);
            break;
        case minus:
            height -= index->height;
            sub(index);
            break;
        default:
            break;
        }
    }

protected:
    virtual void add(high_index_t* index) = 0;
    virtual void sub(high_index_t* index) = 0;
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

public:
    ~ShareChain()
    {
        for (auto& [h, cd] : m_shares)
        {
            cd.share.destroy();
            delete cd.index;
        }
    }

    /// Release indexes and clear maps without freeing share data.
    /// Use when this chain borrows raw share pointers owned by another chain.
    void clear_unowned()
    {
        for (auto& [h, cd] : m_shares)
            delete cd.index;
        m_shares.clear();
        m_reverse.clear();
        m_heads.clear();
        m_tails.clear();
    }

public:
    // Reverse map: prev_hash → set of children hashes.
    // Matches p2pool's tracker.reverse (forest.py).
    // Enables O(1) child lookup instead of O(N) scan.
    const auto& get_reverse() const { return m_reverse; }

private:
    std::unordered_map<hash_t, chain_data, hasher_t> m_shares;
    std::unordered_map<hash_t, std::set<hash_t>, hasher_t> m_reverse;

    std::unordered_map<hash_t, hash_t, hasher_t> m_heads;
    std::unordered_map<hash_t, std::set<hash_t>, hasher_t> m_tails;
    
    void calculate_head_tail(hash_t head, hash_t tail, index_t* index)
    {
        enum fork_state
        {
            new_fork = 0,
            only_heads = 1,
            only_tails = 1 << 1,
            merge = only_heads | only_tails,
        };

        int state = new_fork;
        if (m_heads.contains(tail))
            state |= only_heads;
        if (m_tails.contains(head))
            state |= only_tails;

        switch (state)
        {
        case new_fork:
            // create a new fork
            {
                m_heads[head] = tail;
                m_tails[tail].insert(head);
                // If prev_hash (tail) is already in the chain, connect the
                // prev pointer so get_height_and_last() can walk through it.
                // p2pool's forest also creates a new_fork here, but p2pool's
                // get_height_and_last uses items[prev_hash] lookup instead of
                // prev pointers, so it works for forks automatically.
                if (m_shares.contains(tail))
                {
                    index->prev = m_shares[tail].index;
                    index->calculate_index(index->prev);
                }
            }
            break;
        case merge:
            // merge two forks at the junction of a new element
            {
                auto left = m_heads.extract(tail); // heads[t]
                auto& l_tail = left.mapped(); auto& l_head = left.key();
                auto right = m_tails.extract(head); // tails[h]
                auto& r_tail = right.key(); auto& r_heads = right.mapped();

                m_tails[l_tail].insert(r_heads.begin(), r_heads.end());
                m_tails[l_tail].erase(tail);

                for (auto& i : m_tails[l_tail])
                    m_heads[i] = l_tail;

                index->prev = m_shares[tail].index;
                index->calculate_index(index->prev);

                std::unordered_set<hash_t, hasher_t> dirty_indexs;
                for (auto& part : right.mapped())
                {
                    index_t* cur = m_shares[part].index;
                    while(cur)
                    {
                        if (dirty_indexs.contains(cur->head))
                            break;
                        
                        dirty_indexs.insert(cur->head);
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
            // element on the left (tail side)
            {
                std::unordered_set<hash_t, hasher_t> dirty_indexs;
                auto right = m_tails.extract(head);
                for (auto& part : right.mapped())
                {
                    index_t* cur = m_shares[part].index;
                    while(cur)
                    {
                        if (dirty_indexs.contains(cur->head))
                            break;
                        
                        dirty_indexs.insert(cur->head);
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
                    m_heads[v] = tail;
                right.key() = tail;
                m_tails.insert(std::move(right));
            }
            break;
        case only_heads:
            // element on the right (head side)
            {
                auto left_part = m_heads.extract(tail);

                index->prev = m_shares[tail].index;
                index->calculate_index(index->prev);

                m_heads[head] = left_part.mapped();
                m_tails[left_part.mapped()].erase(left_part.key());
                m_tails[left_part.mapped()].insert(head);
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
        // Maintain reverse map (prev → children)
        if (!share->m_prev_hash.IsNull())
            m_reverse[share->m_prev_hash].insert(share->m_hash);
    }

    void add(share_t share)
    {
        share.USE(add);
    }

    chain_data& get(const hash_t& hash)
    {
        if (m_shares.contains(hash))
            return m_shares[hash];
        else
            throw std::out_of_range("Hash out of chain!");
    }

    index_t* get_index(const hash_t& hash)
    {
        return get(hash).index;
    }

    share_t& get_share(const hash_t& hash)
    {
        return get(hash).share;
    }
    
    bool contains(hash_t&& hash)
    {
        return m_shares.contains(hash);
    }

    bool contains(const hash_t& hash) const
    {
        return m_shares.contains(hash);
    }

    const auto& get_heads() const { return m_heads; }
    const auto& get_tails() const { return m_tails; }
    size_t size() const { return m_shares.size(); }

    int32_t get_height(const hash_t& hash)
    {
        return get_index(hash)->height;
    }

    hash_t get_last(const hash_t& hash)
    {
        //todo: check exist?
        // return m_heads[hash];
        auto index = m_shares[hash].index;
        while (index->prev)
        {
            index = index->prev;
        }
        return index->tail;
    }

    struct height_and_last
    {
        int32_t height;
        hash_t last;
    };

    height_and_last get_height_and_last(const hash_t& item)
    {
        return {get_height(item), get_last(item)};
    }

    hash_t get_nth_parent_key(const hash_t& hash, int32_t n)
    {
        auto index = get_index(hash);
        for (int i = 0; i < n; i++)
        {
            if (index->prev)
                index = index->prev;
            else
                throw std::invalid_argument("get_nth_parent_key: m_shares not exis't hash");
        }
        return index->head;
    }

    bool is_child_of(const hash_t& item, const hash_t& possible_child)
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

    // last------(ancestor------item]--->best
    index_t get_interval(hash_t item, hash_t ancestor)
    {
        if (!is_child_of(ancestor, item))
            throw std::invalid_argument("get interval: item not child for ancestor!");
            // throw std::invalid_argument("get_sum item[" + item + "] not child for ancestor[" + ancestor + "]");

        index_t result = *get_index(item);
        index_t* ances = get_index(ancestor);

        result.operation(ances, index_t::operation_type::minus);

        return result;
    }

    
    class Iterator
    {
        using data_t = std::unordered_map<hash_t, chain_data, hasher_t>;
    private:
        typename data_t::iterator m_it;
        ShareChain& m_chain;

    public:
        auto& operator*() 
        {
            return *m_it;
        }

        Iterator& operator++() 
        {
            m_it = m_chain.m_shares.find(m_it->second.index->tail);
            return *this;
        }

        bool operator!=(const Iterator& other) const 
        {
            return m_it != other.m_it;
        }

        Iterator(ShareChain& chain, typename data_t::iterator it) : m_chain(chain), m_it(it) { }
    };

    class ChainView
    {
    private:
        using data_t = std::unordered_map<hash_t, chain_data, hasher_t>;

        ShareChain& m_chain;
        hash_t m_start;
        size_t m_count;

    public:
        ChainView(ShareChain& chain, hash_t start, size_t n) : m_chain(chain), m_start(start), m_count(n) { }

        // Counter-based iterator: O(1) construction, O(1) per step.
        // Replaces old end() which was O(n) — walked the entire chain.
        class CIterator
        {
            ShareChain& m_chain;
            typename data_t::iterator m_it;
            size_t m_remaining;
        public:
            CIterator(ShareChain& chain, typename data_t::iterator it, size_t rem)
                : m_chain(chain), m_it(it), m_remaining(rem) { }

            std::pair<hash_t, chain_data&> operator*()
            {
                return {m_it->first, m_it->second};
            }

            CIterator& operator++()
            {
                if (m_remaining > 0) {
                    --m_remaining;
                }
                if (m_remaining == 0) {
                    m_it = m_chain.m_shares.end();
                } else if (m_it != m_chain.m_shares.end() && m_it->second.index->prev) {
                    auto tail = m_it->second.index->tail;
                    m_it = m_chain.m_shares.find(tail);
                } else {
                    m_it = m_chain.m_shares.end();
                    m_remaining = 0;
                }
                return *this;
            }

            bool operator!=(const CIterator& other) const
            {
                return m_it != other.m_it;
            }
        };

        CIterator begin()
        {
            return CIterator(m_chain, m_chain.m_shares.find(m_start), m_count);
        }

        CIterator end()
        {
            return CIterator(m_chain, m_chain.m_shares.end(), 0);
        }
    };

    ChainView get_chain(const hash_t& hash, uint64_t n)
    {
        if (n > get_height(hash))
        {
            throw std::invalid_argument("n > height for this hash in get_chain!");
        }

        return ChainView(*this, hash, n);
    }

    /// Remove all shares beyond max_size from the chain starting at head.
    /// Walks the prev-pointer chain, cuts at the boundary, subtracts the
    /// evicted accumulated index data, and frees the removed shares.
    /// Returns the number of shares removed.
    /// @param owns_data When true (default) the evicted share data is
    ///        destroyed.  Set to false for chains that borrow share
    ///        pointers from another chain (e.g. verified borrows from chain).
    /// @param evicted_hashes If non-null, hashes of removed shares are appended here.
    /// @param deferred_destroy If non-null, share variants are moved here instead of
    ///        destroyed. Caller must call destroy() on each after cascade cleanup.
    size_t trim(const hash_t& head, size_t max_size, bool owns_data = true,
                std::vector<hash_t>* evicted_hashes = nullptr,
                std::vector<share_t>* deferred_destroy = nullptr)
    {
        if (!m_shares.contains(head) || max_size == 0)
            return 0;

        // Walk from head toward tail via prev pointers
        std::vector<index_t*> chain_indexes;
        auto* current = get_index(head);
        chain_indexes.push_back(current);
        while (current->prev)
        {
            current = current->prev;
            chain_indexes.push_back(current);
        }

        if (chain_indexes.size() <= max_size)
            return 0;

        // chain_indexes[max_size-1] = boundary (new tail-end)
        // chain_indexes[max_size]   = first share to evict
        index_t* boundary = chain_indexes[max_size - 1];
        index_t* evicted_top = chain_indexes[max_size];

        // Subtract the evicted portion's accumulated data from every
        // index above (and including) the boundary
        for (size_t i = 0; i < max_size; ++i)
            chain_indexes[i]->operation(evicted_top, index_t::operation_type::minus);

        // Detach boundary from the evicted portion
        boundary->prev = nullptr;

        // Collect hashes to remove
        std::vector<hash_t> to_remove;
        to_remove.reserve(chain_indexes.size() - max_size);
        for (size_t i = max_size; i < chain_indexes.size(); ++i)
            to_remove.push_back(chain_indexes[i]->head);

        // Update head/tail tracking
        hash_t old_tail_ref = m_heads[head];
        hash_t new_tail_ref = boundary->tail; // boundary share's prev_hash

        m_heads[head] = new_tail_ref;

        if (m_tails.contains(old_tail_ref))
        {
            m_tails[old_tail_ref].erase(head);
            if (m_tails[old_tail_ref].empty())
                m_tails.erase(old_tail_ref);
        }
        m_tails[new_tail_ref].insert(head);

        // Remove evicted shares and free their indexes
        for (auto& h : to_remove)
        {
            // Clean up any stale head/tail entries
            m_heads.erase(h);
            m_tails.erase(h);

            auto it = m_shares.find(h);
            if (it != m_shares.end())
            {
                if (deferred_destroy && owns_data)
                {
                    // Move share variant out for deferred destruction
                    deferred_destroy->push_back(std::move(it->second.share));
                }
                else if (owns_data)
                {
                    it->second.share.destroy();
                }
                delete it->second.index;
                m_shares.erase(it);
            }
        }

        // Collect evicted hashes for caller (e.g. LevelDB pruning)
        if (evicted_hashes)
            evicted_hashes->insert(evicted_hashes->end(), to_remove.begin(), to_remove.end());

        return to_remove.size();
    }

    /// Remove a single share from the chain.
    /// If the share is a head (tip), the chain is shortened and its
    /// predecessor becomes the new head.
    /// If the share is mid-chain, the chain is split: children above it
    /// become a separate fork whose tail now points past the removed share.
    /// Returns true if the share was found and removed.
    bool remove(const hash_t& hash, bool owns_data = true)
    {
        auto it = m_shares.find(hash);
        if (it == m_shares.end())
            return false;

        index_t* idx = it->second.index;
        hash_t share_tail = idx->tail; // == share->m_prev_hash

        // Determine if this share is currently a head
        bool is_head = m_heads.contains(hash);

        // Find child shares via reverse map (O(1) instead of O(N) scan)
        std::vector<hash_t> children;
        {
            auto rev_it = m_reverse.find(hash);
            if (rev_it != m_reverse.end())
                children.assign(rev_it->second.begin(), rev_it->second.end());
        }

        // Remove this share from parent's reverse entry
        if (!share_tail.IsNull()) {
            auto parent_rev = m_reverse.find(share_tail);
            if (parent_rev != m_reverse.end()) {
                parent_rev->second.erase(hash);
                if (parent_rev->second.empty())
                    m_reverse.erase(parent_rev);
            }
        }
        // Remove our reverse entry (children will update theirs)
        m_reverse.erase(hash);

        if (is_head && children.empty())
        {
            // Simple case: head with no children above us.
            // Remove from heads, update tails.
            hash_t our_tail = m_heads[hash]; // the tail this fork reaches
            m_heads.erase(hash);

            if (m_tails.contains(our_tail))
            {
                m_tails[our_tail].erase(hash);
                if (m_tails[our_tail].empty())
                    m_tails.erase(our_tail);
            }

            // Parent becomes a new head (necessary for chain traversal).
            // clean_tracker will eat this new head on the next cycle if it's
            // also stale (>300s old). This progressively shortens the fork.
            if (idx->prev)
            {
                hash_t prev_hash = idx->prev->head;
                if (!m_heads.contains(prev_hash))
                {
                    m_heads[prev_hash] = our_tail;
                    m_tails[our_tail].insert(prev_hash);
                }
            }
        }
        else
        {
            // Mid-chain or has children: detach children so they form
            // new forks whose tail points past us to share_tail.
            for (auto& child_hash : children)
            {
                index_t* child_idx = m_shares[child_hash].index;

                // Walk from child up to the head of its fork, subtracting
                // our contribution.
                // Detach prev pointer — child now points past removed share.
                // Check that the grandparent still exists (it may have been
                // removed in a previous remove() call in the same batch).
                if (idx->prev && m_shares.contains(idx->prev->head))
                    child_idx->prev = idx->prev;
                else
                    child_idx->prev = nullptr;
                // Recalculate from scratch if needed (heights will be off
                // by idx->height, but since idx->height == 1 for a single
                // share we can just decrement).
                // Walk up from child_hash to its head:
                hash_t head_of_fork = child_hash;
                for (auto& [h, _] : m_heads)
                {
                    // Check if child_hash's fork reaches this head
                    if (m_shares.contains(h))
                    {
                        index_t* cur = m_shares[h].index;
                        while (cur)
                        {
                            if (cur->head == child_hash)
                            {
                                head_of_fork = h;
                                break;
                            }
                            cur = cur->prev;
                        }
                    }
                }

                // Update the head→tail mapping
                if (m_heads.contains(head_of_fork))
                {
                    hash_t old_tail = m_heads[head_of_fork];
                    m_heads[head_of_fork] = share_tail;

                    if (m_tails.contains(old_tail))
                    {
                        m_tails[old_tail].erase(head_of_fork);
                        if (m_tails[old_tail].empty())
                            m_tails.erase(old_tail);
                    }
                    m_tails[share_tail].insert(head_of_fork);
                }
            }

            // If we were a head, remove that entry
            if (is_head)
            {
                hash_t our_tail = m_heads[hash];
                m_heads.erase(hash);
                if (m_tails.contains(our_tail))
                {
                    m_tails[our_tail].erase(hash);
                    if (m_tails[our_tail].empty())
                        m_tails.erase(our_tail);
                }
            }
        }

        // Free the share object and index, then remove from m_shares
        if (owns_data)
            it->second.share.destroy();
        delete idx;
        m_shares.erase(it);
        return true;
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

    /*
    
    [~]void remove(hash_t&& key);
        [+]sum_to_last get_sum_to_last(hash_t hash);
        [-]sum_element get_sum_for_element(const hash_t& hash);
        [+]int32_t get_height(hash_t&& hash);
        [+]hash_type get_last(hash_t&& hash);
        [+]height_and_last get_height_and_last(hash_t&& item);
        [+]bool is_child_of(hash_t&& item, hash_t&& possible_child);
        [+]hash_type get_nth_parent_key(hash_t&& hash, int32_t n) const;
        [+]std::function<bool(hash_type&)> get_chain(hash_t&& hash, uint64_t n)
        [+]sum_element get_sum(hash_type item, hash_type ancestor)
    */
};

} // namespace chain