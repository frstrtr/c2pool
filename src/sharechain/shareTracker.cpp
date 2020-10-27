#include <shareTracker.h>
#include <share.h>
#include <vector>
#include <tuple>
#include <set>
#include <map>
#include <uint256.h>
#include <share.h>
#include "events.h"

using c2pool::util::events::Event;
using std::vector, std::tuple, std::set, std::map;

//ProtoAttributeDelta //TODO: rename
namespace c2pool::shares::tracker
{
    ProtoAttributeDelta::ProtoAttributeDelta(BaseShare item)
    {
        head = item.hash;
        tail = item.previous_hash;
        height = 1;
    }

    ProtoAttributeDelta::ProtoAttributeDelta(uint256 _head, uint256 _tail, int _height)
    {
        head = _head;
        tail = _tail;
        height = _height;
    }

    ProtoAttributeDelta::ProtoAttributeDelta(uint256 element_id)
    {
        head = element_id;
        tail = element_id;
        height = 0;
    }

    //TODO: TEST

    ProtoAttributeDelta operator+(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b)
    {
        if (a.tail != b.head)
        {
            //ERROR
            //TODO: assert
        }
        return ProtoAttributeDelta(a.head, b.tail, a.height + b.height);
    }
    ProtoAttributeDelta operator-(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b)
    {
        // if (tail != b.head)
        // {
        //     //ERROR
        //     //TODO: assert
        // }

        if (a.head == b.head)
        {
            return ProtoAttributeDelta(b.tail, a.tail, a.height - b.height);
        }
        if (a.tail == b.tail)
        {
            return ProtoAttributeDelta(a.head, b.head, a.height - b.height);
        }
        //TODO: Assertion Error
    }

    //OkayProtoAttributeDelta

    OkayProtoAttributeDelta::OkayProtoAttributeDelta(BaseShare item) : ProtoAttributeDelta(item)
    {
        //TODO: work = bitcoin_data.target_to_average_attempts(item.target)
        //TODO: min_work = bitcoin_data.target_to_average_attempts(share.max_target)
    }

    OkayProtoAttributeDelta::OkayProtoAttributeDelta(uint256 _head, uint256 _tail, int _height, uint256 _work, uint256 _min_work) : ProtoAttributeDelta(_head, _tail, _height)
    {
        work = _work;
        min_work = _min_work;
    }

    OkayProtoAttributeDelta::OkayProtoAttributeDelta(uint256 element_id) : ProtoAttributeDelta(element_id)
    {
        work = 0;     //TODO: init zero
        min_work = 0; //TODO: init zero
    }

    OkayProtoAttributeDelta operator+(const OkayProtoAttributeDelta &a, const OkayProtoAttributeDelta &b)
    {
        if (a.tail != b.head)
        {
            //ERROR
            //TODO: assert
        }
        return OkayProtoAttributeDelta(a.head, b.tail, a.height + b.height, a.work + b.work, a.min_work + b.min_work);
    }
    OkayProtoAttributeDelta operator-(const OkayProtoAttributeDelta &a, const OkayProtoAttributeDelta &b)
    {
        // if (tail != b.head)
        // {
        //     //ERROR
        //     //TODO: assert
        // }

        if (a.head == b.head)
        {
            return OkayProtoAttributeDelta(b.tail, a.tail, a.height - b.height, a.work - b.work, a.min_work - b.min_work);
        }
        if (a.tail == b.tail)
        {
            return OkayProtoAttributeDelta(a.head, b.head, a.height - b.height, a.work - b.work, a.min_work - b.min_work);
        }
        //TODO: Assertion Error
    }

    //SubsetProtoAttributeDelta

    SubsetProtoAttributeDelta::SubsetProtoAttributeDelta(BaseShare item) : ProtoAttributeDelta(item)
    {
        //TODO: work = bitcoin_data.target_to_average_attempts(item.target)
    }

    SubsetProtoAttributeDelta::SubsetProtoAttributeDelta(uint256 _head, uint256 _tail, int _height, uint256 _work) : ProtoAttributeDelta(_head, _tail, _height)
    {
        work = _work;
    }

    SubsetProtoAttributeDelta::SubsetProtoAttributeDelta(uint256 element_id) : ProtoAttributeDelta(element_id)
    {
        work = 0; //TODO: init zero
    }

    SubsetProtoAttributeDelta operator+(const SubsetProtoAttributeDelta &a, const SubsetProtoAttributeDelta &b)
    {
        if (a.tail != b.head)
        {
            //ERROR
            //TODO: assert
        }
        return SubsetProtoAttributeDelta(a.head, b.tail, a.height + b.height, a.work + b.work);
    }
    SubsetProtoAttributeDelta operator-(const SubsetProtoAttributeDelta &a, const SubsetProtoAttributeDelta &b)
    {
        // if (tail != b.head)
        // {
        //     //ERROR
        //     //TODO: assert
        // }

        if (a.head == b.head)
        {
            return SubsetProtoAttributeDelta(b.tail, a.tail, a.height - b.height, a.work - b.work);
        }
        if (a.tail == b.tail)
        {
            return SubsetProtoAttributeDelta(a.head, b.head, a.height - b.height, a.work - b.work);
        }
        //TODO: Assertion Error
    }

} // namespace c2pool::shares::tracker

//TrackerView
namespace c2pool::shares::tracker
{

    /*template <typename delta_type>
    Tracker<delta_type>:: */

    template <typename delta_type>
    void Tracker<delta_type>::_handle_remove_special(BaseShare item)
    {
        //TODO
        // delta_type delta = delta_type(item);
    }

    template <typename delta_type>
    void Tracker<delta_type>::_handle_remove_special2(BaseShare item)
    {
        //TODO
        // delta_type delta = delta_type(item);
    }

    template <typename delta_type>
    void Tracker<delta_type>::_handle_removed(BaseShare item)
    {
        //TODO
        // delta_type delta = delta_type(item);
    }

} // namespace c2pool::shares::tracker

//Tracker
namespace c2pool::shares::tracker
{

    template <typename delta_type>
    Tracker<delta_type>::Tracker()
    {
        //TrackerView
        using namespace std::placeholders;
        remove_special.subscribe(&Tracker<delta_type>::_handle_remove_special, *this, _1);
        remove_special2.subscribe(&Tracker<delta_type>::_handle_remove_special2, *this, _1);
        removed.subscribe(&Tracker<delta_type>::_handle_removed, *this, _1);

        //Tracker
        //self.get_nth_parent_hash = DistanceSkipList(self) //TODO
    }

    template <typename delta_type>
    Tracker<delta_type>::Tracker(vector<c2pool::shares::BaseShare> &_items)
    {
        //TrackerView
        using namespace std::placeholders;
        remove_special.subscribe(&Tracker<delta_type>::_handle_remove_special, *this, _1);
        remove_special2.subscribe(&Tracker<delta_type>::_handle_remove_special2, *this, _1);
        removed.subscribe(&Tracker<delta_type>::_handle_removed, *this, _1);

        //Tracker
        //self.get_nth_parent_hash = DistanceSkipList(self) //TODO

        for (auto item : _items)
        {
            add(item);
        }
    }

    template <typename delta_type>
    void Tracker<delta_type>::add(BaseShare item)
    {
        delta_type delta = delta_type(item);

        if (items.find(delta.head) != items.end())
        {
            //TODO: raise ValueError('item already present')
        }

        set<uint256> _heads;

        if (tails.find(delta.head) != tails.end())
        {
            _heads = tails[delta.head];
            tails.erase(delta.head);
        }
        else
        {
            _heads = set<uint256>{delta.head};
        }

        uint256 _tail;
        if (heads.find(delta.tail) != heads.end())
        {
            _tail = heads[delta.tail];
            heads.erase(delta.tail);
        }
        else
        {
            _tail = get_last(delta.tail);
        }

        items[delta.head] = item;
        reverse[delta.tail].insert(delta.head);

        tails[_tail].insert(delta.head);
        if (tails[_tail].find(delta.tail) != tails[_tail].end())
        {
            tails[_tail].erase(delta.tail);
        }

        for (auto head : _heads)
        {
            heads[head] = _tail;
        }

        added.happened(item);
    }

    template <typename delta_type>
    void Tracker<delta_type>::remove(uint256 item_hash)
    {
        if (items.find(item_hash) == items.end())
        {
            //TODO: raise KeyError()
        }

        auto item = items[item_hash];

        delta_type delta = delta_type(item);

        set<uint256> children;
        if (reverse.find(delta.head) != reverse.end())
        {
            children = reverse[delta.head];
        }

        bool _exist_heads = (heads.find(delta.head) != heads.end());
        bool _exist_tails = (tails.find(delta.tail) != tails.end());

        if (_exist_heads && _exist_tails)
        {
            auto tail = heads[delta.head];
            heads.erase(delta.head);
            tails[tail].erase(delta.head);
            //remove empty set from tails map
            if (tails[delta.tail].empty()){
                tails.erase(delta.tail);
            }
        }
        else if (_exist_heads)
        {
            auto tail = heads[delta.head];
            heads.erase(delta.head);
            tails[tail].erase(delta.head);
            if (reverse[delta.tail] != {delta.head}){
                //has sibling
            } else {
                tails[tail].insert(delta.tail);
                heads[delta.tail] = tail;
            }
        }
        else if (_exist_tails && (reverse[delta.tail].size() <= 1))
        {
            auto _heads = tails[delta.tail];
            tails.erase(delta.tail);
            for (auto head : _heads){
                heads[head] = delta.head;
            }
            tails[delta.head] = {_heads};

            remove_special.happened(item);
        }
        else if (_exist_tails && (reverse[delta.tail].size() > 1))
        {
            set<uint256> _heads;
            for (auto x : tails[delta.tail]){
                if (is_child_of(delta.head, x)){
                    _heads.insert(x);
                    tails[delta.tail].erase(x);
                }

                if (tails[delta.tail].empty()){
                    tails.erase(delta.tail);
                }
                for (auto head : _heads){
                    heads[head] = delta.head;
                }
                //TODO: assert delta.head not in self.tails
                tails[delta.head] = _heads;

                remove_special2.happened(item);
            }

        }
        else {
            //TODO: raise NotImplementedError()
        }

        items.erase(delta.head);
        reverse[delta.tail].erase(delta.head);
        if (reverse[delta.tail].empty()){
            reverse.erase(delta.tail);
        }

        removed.happened(item);
    }
} // namespace c2pool::shares::tracker