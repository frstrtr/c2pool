#pragma once

#include "skip_list.hpp"
#include "tracker_view.hpp"
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <cstdint>
#include <stdexcept>

#include <sharechain/share.hpp>

namespace chain
{

// Base for ShareIndexType.
// Stores per-share metadata only (no accumulated prefix-sums).
// Navigation is via hash lookup in m_shares[tail], matching p2pool's
// items[previous_hash] approach.  No prev pointers — eliminates
// dangling pointer crashes and new_fork segment issues entirely.
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

    hash_t head;    // this share's own hash
    hash_t tail;    // this share's prev_hash (navigation key)

public:
    ShareIndex() : head{} {}
    template <typename ShareT>
    ShareIndex(ShareT* share) : head{share->m_hash}, tail{share->m_prev_hash} {}
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
    ShareChain()
    {
        // Subscribe to ALL 3 removal signals (p2pool forest.py:108-110).
        // TrackerView uses all 3 for precise delta cache invalidation.
        // SkipList only needs 'removed'.
        on_removed([this](const hash_t& hash) {
            m_skip_list.forget_item(hash);
            m_view.handle_removed(hash);
        });
        on_remove_special([this](const hash_t& hash) {
            m_view.handle_remove_special(hash);
        });
        on_remove_special2([this](const hash_t& hash) {
            m_view.handle_remove_special2(hash);
        });

        auto contains_fn = [this](const hash_t& h) -> bool {
            return m_shares.contains(h);
        };
        auto prev_fn = [this](const hash_t& h) -> hash_t {
            auto it = m_shares.find(h);
            return it != m_shares.end() ? it->second.index->tail : hash_t();
        };

        // Init skip list (O(log n) get_nth_parent — p2pool DistanceSkipList)
        m_skip_list.init(prev_fn);

        // Init TrackerView (cached get_height/get_work/get_last)
        m_view.init(
            contains_fn,
            prev_fn,
            [this](const hash_t& h) -> uint288 {
                auto it = m_shares.find(h);
                return it != m_shares.end() ? it->second.index->work : uint288();
            },
            [this](const hash_t& h) -> uint288 {
                auto it = m_shares.find(h);
                return it != m_shares.end() ? it->second.index->min_work : uint288();
            }
        );
    }

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
        m_skip_list.clear();
        m_view.clear();
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

    // ─── Signal system (matches p2pool Twisted Event pattern) ──────────
    // Three signals matching p2pool forest.py Tracker:
    //   removed         — fired for ALL removals (line 330)
    //   remove_special  — tail with ≤1 child removed (line 310)
    //   remove_special2 — tail with >1 child removed (line 321)
    // p2pool: tracker.removed = variable.Event()
    //         TrackerSkipList subscribes: removed.watch_weakref(self, lambda self, item: self.forget_item(item.hash))
    //         On remove: removed.happened(item) → forget_item clears only that hash from skips{}
    //
    // c2pool: ShareChain fires signals, AccWorkCache subscribes.
    // Signals use std::function callbacks (equivalent to Twisted Event.watch).
public:
    using signal_fn = std::function<void(const hash_t&)>;

    // Register a callback for share removal events.
    // Returns an ID for unwatch (matches Event.watch → id pattern).
    uint64_t on_removed(signal_fn fn) {
        auto id = m_signal_id_gen++;
        m_removed_watchers[id] = std::move(fn);
        return id;
    }
    uint64_t on_remove_special(signal_fn fn) {
        auto id = m_signal_id_gen++;
        m_remove_special_watchers[id] = std::move(fn);
        return id;
    }
    uint64_t on_remove_special2(signal_fn fn) {
        auto id = m_signal_id_gen++;
        m_remove_special2_watchers[id] = std::move(fn);
        return id;
    }

private:
    uint64_t m_signal_id_gen{0};
    std::unordered_map<uint64_t, signal_fn> m_removed_watchers;
    std::unordered_map<uint64_t, signal_fn> m_remove_special_watchers;
    std::unordered_map<uint64_t, signal_fn> m_remove_special2_watchers;

    void fire_removed(const hash_t& hash) {
        for (auto& [id, fn] : m_removed_watchers) {
            try { fn(hash); } catch (...) {}
        }
    }
    void fire_remove_special(const hash_t& hash) {
        for (auto& [id, fn] : m_remove_special_watchers) {
            try { fn(hash); } catch (...) {}
        }
    }
    void fire_remove_special2(const hash_t& hash) {
        for (auto& [id, fn] : m_remove_special2_watchers) {
            try { fn(hash); } catch (...) {}
        }
    }

    // ─── Skip list for O(log n) get_nth_parent (p2pool DistanceSkipList) ──
    chain::DistanceSkipList<hash_t, hasher_t> m_skip_list;
    // Pointer to parent chain's skip list (SubsetTracker pattern).
    // If set, get_nth_parent uses parent's skip list (shared navigation).
    // p2pool: SubsetTracker.get_nth_parent_hash = subset_of.get_nth_parent_hash
    chain::DistanceSkipList<hash_t, hasher_t>* m_parent_skip_list{nullptr};

    // ─── TrackerView for cached get_height/get_work/get_last ──────────
    // Matches p2pool forest.py TrackerView: caches forward-walk deltas.
    // Height is MUTABLE — cache updated when shares are removed.
    chain::TrackerView<hash_t, uint288, hasher_t> m_view;

    void calculate_head_tail(hash_t head, hash_t tail, index_t* /*index*/)
    {
        // Matches p2pool forest.py add() logic.
        // No prev pointers, no accumulated values.
        // Just maintain heads/tails/reverse maps.
        //
        // head = new share's hash, tail = new share's prev_hash
        //
        // Cases:
        //   tail in heads → only_heads: new share extends existing chain top
        //   head in tails → only_tails: new share fills gap below existing chain
        //   both          → merge: new share connects two chains
        //   neither       → new_fork: new disconnected chain segment

        bool tail_in_heads = m_heads.contains(tail);
        bool head_in_tails = m_tails.contains(head);

        if (tail_in_heads && head_in_tails)
        {
            // MERGE: connect two chains.
            // tail was a head of chain A, head was a tail of chain B.
            // After adding this share: A ← new_share ← B become one chain.
            auto old_tail_of_A = m_heads[tail]; // A's deepest tail
            auto heads_of_B = m_tails[head];    // all heads that reached B's tail

            // Remove old entries
            m_heads.erase(tail);
            m_tails.erase(head);

            // All B's heads now reach A's tail
            for (auto& h : heads_of_B)
                m_heads[h] = old_tail_of_A;
            m_tails[old_tail_of_A].insert(heads_of_B.begin(), heads_of_B.end());
            m_tails[old_tail_of_A].erase(tail);
        }
        else if (tail_in_heads)
        {
            // ONLY_HEADS: extend chain from the top.
            // tail was a head → new share becomes the new head.
            auto old_tail = m_heads[tail];
            m_heads.erase(tail);
            m_heads[head] = old_tail;
            m_tails[old_tail].erase(tail);
            m_tails[old_tail].insert(head);
        }
        else if (head_in_tails)
        {
            // ONLY_TAILS: extend chain from the bottom.
            // head was a tail → shares above now reach deeper via new share.
            auto heads_above = m_tails[head];
            m_tails.erase(head);
            for (auto& h : heads_above)
                m_heads[h] = tail;
            m_tails[tail].insert(heads_above.begin(), heads_above.end());
        }
        else
        {
            // NEW_FORK: disconnected chain segment.
            m_heads[head] = tail;
            m_tails[tail].insert(head);
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

        // p2pool DistanceSkipList: no explicit build needed at add time.
        // Skip pointers are built lazily during get_nth_parent queries.
        // forget_item is called on removal (via removed signal in constructor).
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
        // Walk via m_shares[tail] hash lookup — matches p2pool's
        // get_delta_to_last(). O(n) but n ≤ 2*CHAIN_LENGTH.
        int32_t h = 0;
        hash_t cur = hash;
        while (!cur.IsNull() && m_shares.contains(cur))
        {
            ++h;
            cur = m_shares[cur].index->tail;
        }
        return h;
    }

    hash_t get_last(const hash_t& hash)
    {
        // Walk via tail until we reach a hash NOT in the chain.
        hash_t cur = hash;
        int steps = 0;
        while (!cur.IsNull() && m_shares.contains(cur))
        {
            cur = m_shares[cur].index->tail;
            if (++steps > 100000)
                break; // cycle guard
        }
        return cur;
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

    hash_t get_nth_parent_key(const hash_t& hash, int32_t n) const
    {
        // Walk n steps via tail (prev_hash) lookup. O(n) fallback.
        hash_t cur = hash;
        for (int i = 0; i < n; i++)
        {
            if (cur.IsNull())
                throw std::invalid_argument("get_nth_parent_key: chain too short");
            auto it = m_shares.find(cur);
            if (it == m_shares.end())
                throw std::invalid_argument("get_nth_parent_key: chain too short");
            cur = it->second.index->tail;
        }
        return cur;
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

    // ─── Navigation via Bitcoin Core skip list ──────────────────────
    // O(log n) ancestor lookup. O(1) height lookup.
    // Matches p2pool's SubsetTracker + DistanceSkipList pattern.

    /// Current chain depth — O(n) walk from hash to chain end.
    // ─── Navigation via TrackerView + Skip List ──────────────────────
    // TrackerView: cached get_height/get_work/get_last (p2pool forest.py)
    // Skip list: O(log n) get_nth_parent (Bitcoin Core chain.cpp)

    /// Height via TrackerView — cached, MUTABLE after pruning.
    /// Matches p2pool: tracker.get_height() → get_delta_to_last().height
    int32_t get_acc_height(const hash_t& hash)
    {
        if (!m_shares.contains(hash)) return 0;
        return m_view.get_height(hash);
    }

    /// Work via TrackerView — cached.
    /// Matches p2pool: tracker.get_work() → get_delta_to_last().work
    uint288 get_work(const hash_t& hash)
    {
        if (!m_shares.contains(hash)) return uint288();
        return m_view.get_work(hash);
    }

    /// Min work via TrackerView — cached.
    uint288 get_min_work(const hash_t& hash)
    {
        if (!m_shares.contains(hash)) return uint288();
        return m_view.get_min_work(hash);
    }

    /// Delta work between two shares.
    uint288 get_delta_work(const hash_t& near, const hash_t& far)
    {
        return get_work(near) - get_work(far);
    }

    /// Full delta between two shares via TrackerView.
    /// Matches p2pool: tracker.get_delta(item, ancestor)
    /// = get_delta_to_last(item) - get_delta_to_last(ancestor)
    auto get_delta(const hash_t& item, const hash_t& ancestor)
    {
        return m_view.get_delta(item, ancestor);
    }

    /// Delta from share to chain end via TrackerView.
    /// Matches p2pool: tracker.get_delta_to_last(hash)
    auto get_delta_to_last(const hash_t& hash)
    {
        return m_view.get_delta_to_last(hash);
    }

    /// O(log n) ancestor lookup via p2pool DistanceSkipList.
    /// Matches p2pool: tracker.get_nth_parent_hash(hash, n)
    /// If parent chain is set (SubsetTracker pattern), uses parent's skip list.
    /// p2pool: SubsetTracker.get_nth_parent_hash = subset_of.get_nth_parent_hash
    hash_t get_nth_parent_via_skip(const hash_t& hash, int32_t n) const
    {
        if (m_parent_skip_list)
            return m_parent_skip_list->get_nth_parent(hash, n);
        return m_skip_list.get_nth_parent(hash, n);
    }

    /// Set parent chain for SubsetTracker pattern.
    /// p2pool: SubsetTracker.get_nth_parent_hash = subset_of.get_nth_parent_hash
    /// The verified chain shares the main chain's skip list for navigation.
    void set_parent_chain(ShareChain* parent) {
        if (parent)
            m_parent_skip_list = &parent->m_skip_list;
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
                } else if (m_it != m_chain.m_shares.end()) {
                    // Follow tail (= prev_hash) to the next share.
                    // Works across new_fork segment boundaries: even when
                    // index->prev is null, tail is still the share's prev_hash.
                    auto tail = m_it->second.index->tail;
                    if (!tail.IsNull())
                        m_it = m_chain.m_shares.find(tail);
                    else {
                        m_it = m_chain.m_shares.end();
                        m_remaining = 0;
                    }
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

        // Walk from head toward tail via hash lookup, collect all hashes
        std::vector<hash_t> chain_hashes;
        hash_t cur = head;
        while (!cur.IsNull() && m_shares.contains(cur))
        {
            chain_hashes.push_back(cur);
            cur = m_shares[cur].index->tail;
        }

        if (chain_hashes.size() <= max_size)
            return 0;

        // chain_hashes[max_size-1] = boundary (kept, new deepest share)
        hash_t boundary_hash = chain_hashes[max_size - 1];
        hash_t new_tail_ref = m_shares[boundary_hash].index->tail;

        // Update head/tail tracking
        hash_t old_tail_ref = m_heads[head];
        m_heads[head] = new_tail_ref;
        if (m_tails.contains(old_tail_ref))
        {
            m_tails[old_tail_ref].erase(head);
            if (m_tails[old_tail_ref].empty())
                m_tails.erase(old_tail_ref);
        }
        m_tails[new_tail_ref].insert(head);

        // Remove evicted shares (from max_size onward)
        std::vector<hash_t> to_remove(chain_hashes.begin() + max_size, chain_hashes.end());
        for (auto& h : to_remove)
        {
            m_heads.erase(h);
            m_tails.erase(h);
            auto it = m_shares.find(h);
            if (it != m_shares.end())
            {
                // Remove h from its parent's reverse entry
                auto& t = it->second.index->tail;
                if (!t.IsNull()) {
                    auto pr = m_reverse.find(t);
                    if (pr != m_reverse.end()) {
                        pr->second.erase(h);
                        if (pr->second.empty()) m_reverse.erase(pr);
                    }
                }
                // Fire removed signal while share is still in m_shares
                // (handlers call make_element_delta which needs m_get_prev_fn)
                fire_removed(h);
                // Do NOT erase m_reverse[h] — kept children (e.g. boundary)
                // still have prev_hash = h and need this entry. The first
                // evicted item's reverse entry points to boundary_hash.
                if (deferred_destroy && owns_data)
                    deferred_destroy->push_back(std::move(it->second.share));
                else if (owns_data)
                    it->second.share.destroy();
                delete it->second.index;
                m_shares.erase(it);
            }
        }

        if (evicted_hashes)
            evicted_hashes->insert(evicted_hashes->end(), to_remove.begin(), to_remove.end());

        return to_remove.size();
    }

    /// Remove a single share from the chain.
    /// Line-by-line translation of p2pool forest.py:279-330.
    /// 4-branch structure with signals firing at exact p2pool locations.
    bool remove(const hash_t& hash, bool owns_data = true)
    {
        auto it = m_shares.find(hash);
        if (it == m_shares.end())
            return false;

        index_t* idx = it->second.index;
        hash_t share_tail = idx->tail; // delta.tail = prev_hash

        // p2pool line 289: children = self.reverse.get(delta.head, set())
        // Only used in branch 4 (is_child_of), but read upfront like p2pool.
        // Note: if hash is a head, children is empty (adding a child removes head status).

        bool is_head = m_heads.contains(hash);
        bool tail_in_tails = m_tails.contains(share_tail);

        // ── 4-branch logic (p2pool forest.py:291-323) ──
        // Reverse map is NOT modified yet — sibling counts are accurate.
        static int remove_log = 0;
        int branch = 0;

        if (is_head && tail_in_tails)
        {
            // Branch 1 (p2pool line 291-295): head in heads AND tail in tails
            // Item bridges two segment boundaries — just disconnect.
            hash_t tail = m_heads[hash];        // deep tail of head's chain segment
            m_heads.erase(hash);
            m_tails[tail].erase(hash);
            if (m_tails[share_tail].empty())
                m_tails.erase(share_tail);
            branch = 1;
        }
        else if (is_head)
        {
            // Branch 2 (p2pool line 296-303): head in heads (but tail NOT in tails)
            // Head removal — promote parent if this was the only child.
            hash_t tail = m_heads[hash];        // deep tail
            m_heads.erase(hash);
            m_tails[tail].erase(hash);

            // p2pool line 299: if self.reverse[delta.tail] != set([delta.head]):
            //     pass  # has sibling
            // else: promote parent to head
            auto rev_it = m_reverse.find(share_tail);
            bool only_child = (rev_it != m_reverse.end()
                               && rev_it->second.size() == 1
                               && rev_it->second.count(hash) == 1);

            if (only_child) {
                // p2pool line 302-303: parent becomes new head
                m_tails[tail].insert(share_tail);
                m_heads[share_tail] = tail;
            } else {
                // Has siblings — clean up empty tail entry.
                // p2pool ignores empty sets (falsy in Python); C++ keeps them.
                if (m_tails[tail].empty())
                    m_tails.erase(tail);
            }
            branch = only_child ? 22 : 21; // 22=promoted, 21=has siblings
        }
        else if (tail_in_tails)
        {
            // Branches 3 & 4 (p2pool line 304-321): tail in tails (tail-child removal)
            // Reverse map NOT yet modified — sibling count is accurate.
            auto rev_it = m_reverse.find(share_tail);
            size_t sibling_count = (rev_it != m_reverse.end()) ? rev_it->second.size() : 0;

            if (sibling_count <= 1)
            {
                // Branch 3 (p2pool line 304-310): sole child
                auto heads_above = m_tails[share_tail];
                m_tails.erase(share_tail);
                for (auto& h : heads_above)
                    m_heads[h] = hash;              // p2pool: self.heads[head] = delta.head
                m_tails[hash] = std::move(heads_above);

                fire_remove_special(hash);          // p2pool line 310
                branch = 3;
            }
            else
            {
                // Branch 4 (p2pool line 311-321): multiple siblings
                // Find heads that pass through this item.
                // p2pool: heads = [x for x in self.tails[delta.tail]
                //                  if self.is_child_of(delta.head, x)]
                std::set<hash_t> my_heads;
                for (auto& h : m_tails[share_tail]) {
                    if (is_child_of(hash, h))
                        my_heads.insert(h);
                }

                // p2pool line 313-315: remove my heads from parent's tail entry
                for (auto& h : my_heads)
                    m_tails[share_tail].erase(h);
                if (m_tails[share_tail].empty())
                    m_tails.erase(share_tail);

                // p2pool line 316-317: reassign my heads to point through me
                for (auto& h : my_heads)
                    m_heads[h] = hash;
                // p2pool line 319: self.tails[delta.head] = set(heads)
                m_tails[hash] = std::move(my_heads);

                fire_remove_special2(hash);         // p2pool line 321
                branch = 4;
            }
        }
        else
        {
            // p2pool line 323: raise NotImplementedError()
            // Should never happen if data structure is consistent.
            branch = 99;
        }

        if (remove_log++ < 50 || branch == 99) {
            // Diagnostic: log first 50 removals + all unexpected states
            auto heads_sz = m_heads.size();
            auto tails_sz = m_tails.size();
            auto items_sz = m_shares.size();
            std::fprintf(stderr, "[forest::remove] hash=%.16s branch=%d heads=%zu tails=%zu items=%zu\n",
                         hash.GetHex().c_str(), branch, heads_sz, tails_sz, items_sz);
        }

        // ── Cleanup (p2pool forest.py:325-330) ──

        // p2pool line 326-328: self.reverse[delta.tail].remove(delta.head)
        // Remove hash from parent's reverse entry — AFTER branch logic.
        {
            auto pr = m_reverse.find(share_tail);
            if (pr != m_reverse.end()) {
                pr->second.erase(hash);
                if (pr->second.empty()) m_reverse.erase(pr);
            }
        }
        // NOTE: Do NOT erase m_reverse[hash] — hash may now be a tail boundary
        // (branches 3/4) and its children still need reverse[hash] entries.

        // p2pool line 330: self.removed.happened(item)
        // Must fire while share is still in m_shares (c2pool handlers call
        // make_element_delta which looks up prev_hash via m_shares).
        fire_removed(hash);

        // Free share data and index (p2pool line 325: self.items.pop)
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