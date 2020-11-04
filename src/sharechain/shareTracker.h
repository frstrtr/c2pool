#ifndef SHARE_TRACKER_H
#define SHARE_TRACKER_H

#include <shareTypes.h>
#include <share.h>
#include <uint256.h>
#include <vector>
#include <map>
#include <set>
#include <vector>
#include <tuple>
#include "events.h"
#include <memory>
#include "console.h"

using c2pool::util::events::Event;
using std::shared_ptr;
using std::vector, std::map, std::tuple, std::set, std::vector;

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

        ProtoAttributeDelta(uint256 _head, uint256 _tail, int _height);
        
        ProtoAttributeDelta(uint256 element_id); //get_none

        friend ProtoAttributeDelta operator+(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b);
        friend ProtoAttributeDelta operator-(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b);

        // ProtoAttributeDelta& operator+(const ProtoAttributeDelta& b);
        // ProtoAttributeDelta& operator-(const ProtoAttributeDelta& b);
    };

    //TODO: Rename по-человечески.
    //For OkayTracker
    class OkayProtoAttributeDelta : public ProtoAttributeDelta
    {
    public:
        uint256 work;     //TODO: arith_256
        uint256 min_work; //TODO: arith_256

    public:
        OkayProtoAttributeDelta(BaseShare item);

        OkayProtoAttributeDelta(uint256 _head, uint256 _tail, int _height, uint256 _work, uint256 _min_work);

        OkayProtoAttributeDelta(uint256 element_id); //get_none

        friend OkayProtoAttributeDelta operator+(const OkayProtoAttributeDelta &a, const OkayProtoAttributeDelta &b);
        friend OkayProtoAttributeDelta operator-(const OkayProtoAttributeDelta &a, const OkayProtoAttributeDelta &b);

        // OkayProtoAttributeDelta& operator+(const OkayProtoAttributeDelta& b);
        // OkayProtoAttributeDelta& operator-(const OkayProtoAttributeDelta& b);
    };

    //TODO: Rename по-человечески.
    //For SubsetTracker
    class SubsetProtoAttributeDelta : public ProtoAttributeDelta
    {
    public:
        uint256 work; //TODO: arith_256

    public:
        SubsetProtoAttributeDelta(BaseShare item);

        SubsetProtoAttributeDelta(uint256 _head, uint256 _tail, int _height, uint256 _work);

        SubsetProtoAttributeDelta(uint256 element_id); //get_none

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
        map<uint256, tuple<delta_type, unsigned long>> _deltas; // item_hash -> delta, ref
        map<unsigned long, set<uint256>> _reverse_deltas = {};   // ref -> set of item_hashes

        unsigned long ref_generator = 0; //TrackerView::_ref_generator
        map<unsigned long, delta_type> _delta_refs = {};      // ref -> delta
        map<uint256, unsigned long> _reverse_delta_refs = {}; // delta.tail -> ref

        void _handle_remove_special(BaseShare item);

        void _handle_remove_special2(BaseShare item);

        void _handle_removed(BaseShare item);

        int get_height(uint256 item_hash)
        {
            return get_delta_to_last(item_hash).height;
        }

        uint256 get_work(uint256 item_hash)
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
            if (_deltas.find(item_hash) != _deltas.end())
            {
                auto delta_ref1 = _deltas[item_hash];
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
            uint256 other_item_hash = delta.tail;
            if (_reverse_delta_refs.find(other_item_hash) == _reverse_delta_refs.end()){
                ref_generator++;
                if (_delta_refs.find(ref_generator) == _delta_refs.end()){
                    //TODO: assert ref_generator not in self._delta_refs
                }
                _delta_refs[ref_generator] = delta_type(other_item_hash);
                _reverse_delta_refs[other_item_hash] = ref_generator;
            }

            unsigned long _ref = _reverse_delta_refs[other_item_hash];
            delta_type ref_delta = _delta_refs[_ref];
            if (ref_delta.tail != other_item_hash){
                //TODO: assert ref_delta.tail == other_item_hash
            }

            if (_deltas.find(item_hash) != _deltas.end()){
                unsigned long prev_ref = std::get<1>(_deltas[item_hash]);
                _reverse_deltas[prev_ref].erase(item_hash);
                if  (_reverse_deltas[prev_ref].empty() && (prev_ref != _ref)){
                    _reverse_deltas.erase(prev_ref);
                    delta_type x = _delta_refs[prev_ref];
                    _delta_refs.erase(prev_ref);
                    _reverse_delta_refs.erase(x.tail);
                }
            }
            _deltas[item_hash] = std::make_tuple(delta-ref_delta, _ref);
            _reverse_deltas[_ref] = {item_hash};
        }

        delta_type get_delta_to_last(uint256 item_hash)
        {

            delta_type delta = delta_type(item_hash);
            vector<tuple<uint256, delta_type>> updates;

            while (items.find(delta.tail) != items.end()){
                updates.push_back(std::make_tuple(delta.tail, delta));
                auto this_delta = _get_delta(delta.tail);
                delta = delta + this_delta;
            }
            for (auto upd : updates){
                _set_delta(std::get<0>(upd), delta - std::get<1>(upd));
            }
            return delta;
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

        vector<BaseShare> get_chain();

        bool is_child_of(uint256 item_hash, uint256 possible_child_hash);
    };

    template <typename subset_of_type>
    class SubsetTracker : public Tracker<SubsetProtoAttributeDelta>
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

    class OkayTracker : public Tracker<OkayProtoAttributeDelta>, std::enable_shared_from_this<OkayTracker>
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
        bool attempt_verify(BaseShare share){
            if (verified.items.find(share.hash) != verified.items.end()){
                return true;
            }
            auto height_last = get_height_and_last(share.hash);
            
            //TODO:
            // if (std::get<0>(height_last) < net->CHAIN_LENGTH + 1){
            //     //TODO raise AssertionError()
            // }

            try
            {
                //share.check(shared_from_this()); //TODO
            }
            catch(const std::exception& e)
            {
                LOG_ERROR << e.what() << '\n';
                return false;
            }

            verified.add(share);
            return true;
        }

        //TODO: def think(self, block_rel_height_func, previous_block, bits, known_txs)

        //TODO: def score(self, share_hash, block_rel_height_func)
    };
} // namespace c2pool::shares::tracker

#endif //SHARE_TRACHER_H