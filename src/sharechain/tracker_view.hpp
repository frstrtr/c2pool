#pragma once
/**
 * TrackerView — C++ implementation of p2pool forest.py TrackerView.
 *
 * Full ref-based delta caching matching p2pool EXACTLY.
 * Stores deltas in two parts: (item→ref, ref→chain_end).
 * Selective invalidation on share removal — no full cache clear.
 *
 * p2pool source: forest.py lines 96-222
 * MIT License (c2pool project)
 */

#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <cstdint>
#include <vector>
#include <atomic>

namespace chain {

template <typename HashType, typename WorkType>
struct AttributeDelta
{
    HashType head;
    HashType tail;
    int32_t height{0};
    WorkType work{};
    WorkType min_work{};

    static AttributeDelta get_none(const HashType& id) {
        AttributeDelta d;
        d.head = id;
        d.tail = id;
        return d;
    }

    AttributeDelta& operator+=(const AttributeDelta& other) {
        tail = other.tail;
        height += other.height;
        work += other.work;
        min_work += other.min_work;
        return *this;
    }

    AttributeDelta operator+(const AttributeDelta& other) const {
        auto result = *this;
        result += other;
        return result;
    }

    AttributeDelta operator-(const AttributeDelta& other) const {
        AttributeDelta result;
        if (head == other.head) {
            result.head = other.tail;
            result.tail = tail;
        } else if (tail == other.tail) {
            result.head = head;
            result.tail = other.head;
        } else {
            result.head = head;
            result.tail = tail;
        }
        result.height = height - other.height;
        result.work = work - other.work;
        result.min_work = min_work - other.min_work;
        return result;
    }
};

/**
 * TrackerView — ref-based delta caching (p2pool forest.py:96-222).
 *
 * Cache structure (matching p2pool exactly):
 *   _deltas[item_hash] = (delta_from_item_to_ref, ref_id)
 *   _delta_refs[ref_id] = delta_from_ref_to_chain_end
 *   _reverse_deltas[ref_id] = set of item_hashes using this ref
 *   _reverse_delta_refs[delta_tail] = ref_id
 *
 * This allows O(1) invalidation when a share is removed:
 *   - Only entries referencing the removed share are affected
 *   - Other entries remain valid (they reference different chain endpoints)
 */
template <typename HashType, typename WorkType, typename HasherType>
class TrackerView
{
    using hash_t = HashType;
    using work_t = WorkType;
    using hasher_t = HasherType;
    using delta_t = AttributeDelta<hash_t, work_t>;
    using ref_t = uint64_t;

    std::function<bool(const hash_t&)> m_contains_fn;
    std::function<hash_t(const hash_t&)> m_get_prev_fn;
    std::function<work_t(const hash_t&)> m_get_work_fn;
    std::function<work_t(const hash_t&)> m_get_min_work_fn;

    // p2pool: self._deltas = {}  # item_hash -> (delta, ref)
    mutable std::unordered_map<hash_t, std::pair<delta_t, ref_t>, hasher_t> m_deltas;
    // p2pool: self._reverse_deltas = {}  # ref -> set of item_hashes
    mutable std::unordered_map<ref_t, std::unordered_set<hash_t, hasher_t>> m_reverse_deltas;
    // p2pool: self._delta_refs = {}  # ref -> delta
    mutable std::unordered_map<ref_t, delta_t> m_delta_refs;
    // p2pool: self._reverse_delta_refs = {}  # delta.tail -> ref
    mutable std::unordered_map<hash_t, ref_t, hasher_t> m_reverse_delta_refs;
    // p2pool: self._ref_generator = itertools.count()
    mutable std::atomic<ref_t> m_ref_gen{0};

    delta_t make_element_delta(const hash_t& hash) const {
        delta_t d;
        d.head = hash;
        d.tail = m_get_prev_fn(hash);
        d.height = 1;
        d.work = m_get_work_fn(hash);
        d.min_work = m_get_min_work_fn(hash);
        return d;
    }

    // p2pool: _get_delta (forest.py:175-183)
    delta_t _get_delta(const hash_t& item_hash) const {
        auto it = m_deltas.find(item_hash);
        if (it != m_deltas.end()) {
            auto& [delta1, ref] = it->second;
            auto ref_it = m_delta_refs.find(ref);
            if (ref_it != m_delta_refs.end())
                return delta1 + ref_it->second;
        }
        return make_element_delta(item_hash);
    }

    // p2pool: _set_delta (forest.py:185-206)
    void _set_delta(const hash_t& item_hash, const delta_t& delta) const {
        auto other_item_hash = delta.tail;

        if (m_reverse_delta_refs.find(other_item_hash) == m_reverse_delta_refs.end()) {
            ref_t ref = m_ref_gen++;
            m_delta_refs[ref] = delta_t::get_none(other_item_hash);
            m_reverse_delta_refs[other_item_hash] = ref;
        }

        ref_t ref = m_reverse_delta_refs[other_item_hash];
        auto& ref_delta = m_delta_refs[ref];

        // Remove from old ref group if exists
        auto old_it = m_deltas.find(item_hash);
        if (old_it != m_deltas.end()) {
            ref_t prev_ref = old_it->second.second;
            m_reverse_deltas[prev_ref].erase(item_hash);
            if (m_reverse_deltas[prev_ref].empty() && prev_ref != ref) {
                m_reverse_deltas.erase(prev_ref);
                auto x_it = m_delta_refs.find(prev_ref);
                if (x_it != m_delta_refs.end()) {
                    m_reverse_delta_refs.erase(x_it->second.tail);
                    m_delta_refs.erase(x_it);
                }
            }
        }

        m_deltas[item_hash] = {delta - ref_delta, ref};
        m_reverse_deltas[ref].insert(item_hash);
    }

public:
    TrackerView() = default;

    void init(
        std::function<bool(const hash_t&)> contains_fn,
        std::function<hash_t(const hash_t&)> get_prev_fn,
        std::function<work_t(const hash_t&)> get_work_fn,
        std::function<work_t(const hash_t&)> get_min_work_fn)
    {
        m_contains_fn = std::move(contains_fn);
        m_get_prev_fn = std::move(get_prev_fn);
        m_get_work_fn = std::move(get_work_fn);
        m_get_min_work_fn = std::move(get_min_work_fn);
    }

    // p2pool: get_delta_to_last (forest.py:208-218)
    delta_t get_delta_to_last(const hash_t& item_hash) const
    {
        delta_t delta = delta_t::get_none(item_hash);
        std::vector<std::pair<hash_t, delta_t>> updates;

        while (!delta.tail.IsNull() && m_contains_fn(delta.tail))
        {
            updates.push_back({delta.tail, delta});
            delta_t this_delta = _get_delta(delta.tail);
            delta += this_delta;
        }

        // Cache intermediate results
        for (auto& [update_hash, delta_then] : updates) {
            _set_delta(update_hash, delta - delta_then);
        }

        return delta;
    }

    int32_t get_height(const hash_t& hash) const {
        return get_delta_to_last(hash).height;
    }

    work_t get_work(const hash_t& hash) const {
        return get_delta_to_last(hash).work;
    }

    work_t get_min_work(const hash_t& hash) const {
        return get_delta_to_last(hash).min_work;
    }

    hash_t get_last(const hash_t& hash) const {
        return get_delta_to_last(hash).tail;
    }

    std::pair<int32_t, hash_t> get_height_and_last(const hash_t& hash) const {
        auto d = get_delta_to_last(hash);
        return {d.height, d.tail};
    }

    delta_t get_delta(const hash_t& item, const hash_t& ancestor) const {
        return get_delta_to_last(item) - get_delta_to_last(ancestor);
    }

    // p2pool: _handle_removed (forest.py:149-159)
    void handle_removed(const hash_t& hash) {
        auto delta = make_element_delta(hash);

        auto it = m_deltas.find(delta.head);
        if (it != m_deltas.end()) {
            auto [delta1, ref] = it->second;
            m_deltas.erase(it);
            m_reverse_deltas[ref].erase(delta.head);
            if (m_reverse_deltas[ref].empty()) {
                m_reverse_deltas.erase(ref);
                auto ref_it = m_delta_refs.find(ref);
                if (ref_it != m_delta_refs.end()) {
                    m_reverse_delta_refs.erase(ref_it->second.tail);
                    m_delta_refs.erase(ref_it);
                }
            }
        }
    }

    // p2pool: _handle_remove_special (forest.py:112-135)
    void handle_remove_special(const hash_t& hash) {
        auto delta = make_element_delta(hash);

        if (m_reverse_delta_refs.find(delta.tail) == m_reverse_delta_refs.end())
            return;

        // Move delta refs referencing children down
        auto head_ref_it = m_reverse_delta_refs.find(delta.head);
        if (head_ref_it != m_reverse_delta_refs.end()) {
            auto& items = m_reverse_deltas[head_ref_it->second];
            for (auto x : std::vector<hash_t>(items.begin(), items.end()))
                get_last(x);  // forces cache rebuild through new path
        }

        if (m_reverse_delta_refs.find(delta.tail) == m_reverse_delta_refs.end())
            return;

        // Move ref pointing to this up
        ref_t ref = m_reverse_delta_refs[delta.tail];
        auto& cur_delta = m_delta_refs[ref];
        cur_delta = cur_delta - delta;
        m_reverse_delta_refs.erase(delta.tail);
        m_reverse_delta_refs[delta.head] = ref;
    }

    // p2pool: _handle_remove_special2 (forest.py:137-147)
    void handle_remove_special2(const hash_t& hash) {
        auto delta = make_element_delta(hash);

        auto tail_ref_it = m_reverse_delta_refs.find(delta.tail);
        if (tail_ref_it == m_reverse_delta_refs.end())
            return;

        ref_t ref = tail_ref_it->second;
        m_reverse_delta_refs.erase(tail_ref_it);
        m_delta_refs.erase(ref);

        auto rev_it = m_reverse_deltas.find(ref);
        if (rev_it != m_reverse_deltas.end()) {
            for (auto& x : rev_it->second)
                m_deltas.erase(x);
            m_reverse_deltas.erase(rev_it);
        }
    }

    void clear() {
        m_deltas.clear();
        m_reverse_deltas.clear();
        m_delta_refs.clear();
        m_reverse_delta_refs.clear();
    }

    size_t cache_size() const { return m_deltas.size(); }
};

} // namespace chain
