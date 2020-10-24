#ifndef SHARE_TRACKER_H
#define SHARE_TRACKER_H

#include <shareTypes.h>
#include <uint256.h>
#include <vector>
#include <map>
#include <set>
#include <tuple>
#include "events.h"
#include <memory>

using c2pool::util::events::Event;
using std::shared_ptr;
using std::vector, std::map, std::tuple, std::set;

namespace c2pool::shares
{
    class BaseShare;
}

namespace c2pool::shares::tracker
{
    //TODO: Rename по-человечески.
    class ProtoAttributeDelta
    {
    public:
        uint256 head;
        uint256 tail;
        int height;

    public:
        ProtoAttributeDelta(BaseShare item);

        ProtoAttributeDelta(uint256 head, uint256 tail, int _height);

        friend ProtoAttributeDelta operator+(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b);
        friend ProtoAttributeDelta operator-(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b);

        // ProtoAttributeDelta& operator+(const ProtoAttributeDelta& b);
        // ProtoAttributeDelta& operator-(const ProtoAttributeDelta& b);
    };

    //TODO: Rename по-человечески.
    //For OkayTracker
    class OkayProtoAttributeDelta : ProtoAttributeDelta
    {
    public:
        uint256 work;     //TODO: arith_256
        uint256 min_work; //TODO: arith_256

    public:
        OkayProtoAttributeDelta(BaseShare item);

        OkayProtoAttributeDelta(uint256 head, uint256 tail, int _height, uint256 work, uint256 min_work);

        friend OkayProtoAttributeDelta operator+(const OkayProtoAttributeDelta &a, const OkayProtoAttributeDelta &b);
        friend OkayProtoAttributeDelta operator-(const OkayProtoAttributeDelta &a, const OkayProtoAttributeDelta &b);

        // OkayProtoAttributeDelta& operator+(const OkayProtoAttributeDelta& b);
        // OkayProtoAttributeDelta& operator-(const OkayProtoAttributeDelta& b);
    };

    //TODO: Rename по-человечески.
    //For SubsetTracker
    class SubsetProtoAttributeDelta : ProtoAttributeDelta
    {
    public:
        uint256 work; //TODO: arith_256

    public:
        SubsetProtoAttributeDelta(BaseShare item);

        SubsetProtoAttributeDelta(uint256 head, uint256 tail, int _height, uint256 work);

        friend SubsetProtoAttributeDelta operator+(const SubsetProtoAttributeDelta &a, const SubsetProtoAttributeDelta &b);
        friend SubsetProtoAttributeDelta operator-(const SubsetProtoAttributeDelta &a, const SubsetProtoAttributeDelta &b);

        // SubsetProtoAttributeDelta& operator+(const SubsetProtoAttributeDelta& b);
        // SubsetProtoAttributeDelta& operator-(const SubsetProtoAttributeDelta& b);
    };
} // namespace c2pool::shares::tracker

namespace c2pool::shares::tracker
{
    template <typename delta_type>
    class Tracker
    {
    public:
        map<uint256, BaseShare> items;
        map<uint256, set<uint256>> reverse;

        map<uint256, uint256> heads;
        map<uint256, set<uint256>> tails;

        Event<BaseShare> added;
        Event<BaseShare> remove_special;
        Event<BaseShare> remove_special2;
        Event<BaseShare> removed;

        //TODO: auto get_nth_parent_hash = DistanceSkipList(self);

        //TrackerView
    public:
        map<uint256, tuple<delta_type, int>> _deltas; // item_hash -> delta, ref
        map<int, set<uint256>> _reverse_deltas = {}   // ref -> set of item_hashes

        int _ref_generator = 0;
        map<int, delta_type> _delta_refs = {};      // ref -> delta
        map<uint256, int> _reverse_delta_refs = {}; // delta.tail -> ref

        void _handle_remove_special(BaseShare item);

        void _handle_remove_special2(BaseShare item);

        void _handle_removed(BaseShare item);

        int get_height(uint256 item_hash)
        {
            return get_delta_to_last(item_hash).height;
        }

        //TODO: type
        auto get_work(uint256 item_hash)
        {
            return get_delta_to_last(item_hash).work;
        }

        uint256 get_last(uint256 item_hash)
        {
            return get_delta_to_last(item_hash).tail;
        }

        tuple<int, uint256> get_height_and_last(uint256 item_hash)
        {
            auto delta = get_delta_to_last(item_hash);
            return tuple<int, uint256>{delta.height, delta.tail};
        }

        delta_type _get_delta(uint256 item_hash)
        {
            if (deltas.find(item_hash) != deltas.end())
            {
                auto delta_ref1 = deltas[item_hash];
                auto delta2 = _delta_refs[std::get<1>(delta_ref1)];
                return std::get<0>(delta_ref1) + delta2;
            }
            else
            {
                return delta_type(items[item_hash]);
            }
            //TODO: assert res.head == item_hash
        }

        void _set_delta(uint256 item_hash, delta_type delta)
        {
            //TODO:
            // other_item_hash = delta.tail
            // if other_item_hash not in self._reverse_delta_refs:
            //     ref = self._ref_generator.next()
            //     assert ref not in self._delta_refs
            //     self._delta_refs[ref] = self._delta_type.get_none(other_item_hash)
            //     self._reverse_delta_refs[other_item_hash] = ref
            //     del ref

            // ref = self._reverse_delta_refs[other_item_hash]
            // ref_delta = self._delta_refs[ref]
            // assert ref_delta.tail == other_item_hash

            // if item_hash in self._deltas:
            //     prev_ref = self._deltas[item_hash][1]
            //     self._reverse_deltas[prev_ref].remove(item_hash)
            //     if not self._reverse_deltas[prev_ref] and prev_ref != ref:
            //         self._reverse_deltas.pop(prev_ref)
            //         x = self._delta_refs.pop(prev_ref)
            //         self._reverse_delta_refs.pop(x.tail)
            // self._deltas[item_hash] = delta - ref_delta, ref
            // self._reverse_deltas.setdefault(ref, set()).add(item_hash)
        }

        delta_type get_delta_to_last(uint256 item_hash)
        {
            //TODO:
            // assert isinstance(item_hash, (int, long, type(None)))
            // delta = self._delta_type.get_none(item_hash)
            // updates = []
            // while delta.tail in self._tracker.items:
            //     updates.append((delta.tail, delta))
            //     this_delta = self._get_delta(delta.tail)
            //     delta += this_delta
            // for update_hash, delta_then in updates:
            //     self._set_delta(update_hash, delta - delta_then)
            // return delta
        }

        delta_type get_delta(uint256 item, uint256 ancestor)
        {
            //TODO: assert self._tracker.is_child_of(ancestor, item)
            return delta_type(item) - delta_type(ancestor);
        }

        //Tracker
    public:
        Tracker();

        Tracker(vector<c2pool::shares::BaseShare> &_items);

        virtual void add(BaseShare item);

        virtual void remove(uint256 item_hash);

        //TODO: create get_chain

        bool is_child_of(uint256 item_hash, uint256 possible_child_hash);
    };

    template <typename subset_of_type>
    class SubsetTracker : Tracker<SubsetProtoAttributeDelta>
    {
    public:
        shared_ptr<subset_of_type> subset_of;

    public:
        SubsetTracker(shared_ptr<subset_of_type> _subset_of) : Tracker<SubsetProtoAttributeDelta>()
        {
            //self.get_nth_parent_hash = subset_of.get_nth_parent_hash # overwrites Tracker.__init__'s
            subset_of = _subset_of;
        }

        SubsetTracker(vector<c2pool::shares::BaseShare> &_items, subset_of_type *_subset_of) : Tracker<SubsetProtoAttributeDelta>(_items)
        {
            //self.get_nth_parent_hash = subset_of.get_nth_parent_hash # overwrites Tracker.__init__'s
            subset_of = _subset_of;
        }

        void add(BaseShare item) override
        {
            if (subset_of != nullptr)
            {
                //TODO: assert self._delta_type.get_head(item) in self._subset_of.items
            }
            Tracker<SubsetProtoAttributeDelta>::add(item);
        }

        void remove(uint256 item_hash) override
        {
            if (subset_of != nullptr)
            {
                //TODO: assert item_hash in self._subset_of.items
            }
            Tracker<SubsetProtoAttributeDelta>::remove(item_hash);
        }
    };

    class OkayTracker : Tracker<OkayProtoAttributeDelta>, std::enable_shared_from_this<OkayTracker>
    {
    public:
        shared_ptr<c2pool::config::Network> net;
        SubsetTracker<OkayTracker> verified;
        //TODO: self.get_cumulative_weights = WeightsSkipList(self)

    public:
        OkayTracker(shared_ptr<c2pool::config::Network> _net) : Tracker<OkayProtoAttributeDelta>(), verified(shared_from_this())
        {
            net = _net;

        }

        OkayTracker(vector<c2pool::shares::BaseShare> &_items) : Tracker<OkayProtoAttributeDelta>(_items), verified(shared_from_this())
        {
            //TODO:
        }

    public:
        bool attempt_verify(BaseShare share); //TODO

        //TODO: def think(self, block_rel_height_func, previous_block, bits, known_txs)

        //TODO: def score(self, share_hash, block_rel_height_func)
    };
} // namespace c2pool::shares::tracker

#endif //SHARE_TRACHER_H