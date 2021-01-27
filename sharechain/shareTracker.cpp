#include <shareTracker.h>
#include <share.h>
#include <vector>
#include <tuple>
#include <set>
#include <map>
#include <uint256.h>
#include <arith_uint256.h>
#include <share.h>
#include "events.h"

using c2pool::util::events::Event;
using std::vector, std::tuple, std::set, std::map;

//ProtoAttributeDelta //TODO: rename
namespace c2pool::shares::tracker
{
    template <typename item_type>
    ProtoAttributeDelta<item_type> operator+(const ProtoAttributeDelta<item_type> &a, const ProtoAttributeDelta<item_type> &b)
    {
        if (a.tail != b.head)
        {
            //ERROR
            //TODO: assert
        }
        return ProtoAttributeDelta<item_type>(a.head, b.tail, a.height + b.height);
    }

    template <typename item_type>
    ProtoAttributeDelta<item_type> operator-(const ProtoAttributeDelta<item_type> &a, const ProtoAttributeDelta<item_type> &b)
    {
        // if (tail != b.head)
        // {
        //     //ERROR
        //     //TODO: assert
        // }

        if (a.head == b.head)
        {
            return ProtoAttributeDelta<item_type>(b.tail, a.tail, a.height - b.height);
        }
        if (a.tail == b.tail)
        {
            return ProtoAttributeDelta<item_type>(a.head, b.head, a.height - b.height);
        }
        //TODO: Assertion Error
    }

    //OkayProtoAttributeDelta
    template <typename item_type>
    OkayProtoAttributeDelta<item_type> operator+(const OkayProtoAttributeDelta<item_type> &a, const OkayProtoAttributeDelta<item_type> &b)
    {
        if (a.tail != b.head)
        {
            //ERROR
            //TODO: assert
        }

        auto a_work = UintToArith256(a.work);
        auto b_work = UintToArith256(b.work);
        auto a_min_work = UintToArith256(a.min_work);
        auto b_min_work = UintToArith256(b.min_work);

        return OkayProtoAttributeDelta<item_type>(a.head, b.tail, a.height + b.height, ArithToUint256(a_work + b_work), ArithToUint256(a_min_work + b_min_work));
    }

    template <typename item_type>
    OkayProtoAttributeDelta<item_type> operator-(const OkayProtoAttributeDelta<item_type> &a, const OkayProtoAttributeDelta<item_type> &b)
    {
        // if (tail != b.head)
        // {
        //     //ERROR
        //     //TODO: assert
        // }
        auto a_work = UintToArith256(a.work);
        auto b_work = UintToArith256(b.work);
        auto a_min_work = UintToArith256(a.min_work);
        auto b_min_work = UintToArith256(b.min_work);
        if (a.head == b.head)
        {
            return OkayProtoAttributeDelta<item_type>(b.tail, a.tail, a.height - b.height, ArithToUint256(a_work - b_work), ArithToUint256(a_min_work - b_min_work));
        }
        if (a.tail == b.tail)
        {
            return OkayProtoAttributeDelta<item_type>(a.head, b.head, a.height - b.height, ArithToUint256(a_work - b_work), ArithToUint256(a_min_work - b_min_work));
        }
        //TODO: Assertion Error
    }

    //SubsetProtoAttributeDelta

    template <typename item_type>
    SubsetProtoAttributeDelta<item_type> operator+(const SubsetProtoAttributeDelta<item_type> &a, const SubsetProtoAttributeDelta<item_type> &b)
    {
        if (a.tail != b.head)
        {
            //ERROR
            //TODO: assert
        }
        auto a_work = UintToArith256(a.work);
        auto b_work = UintToArith256(b.work);
        return SubsetProtoAttributeDelta<item_type>(a.head, b.tail, a.height + b.height, ArithToUint256(a_work + b_work));
    }

    template <typename item_type>
    SubsetProtoAttributeDelta<item_type> operator-(const SubsetProtoAttributeDelta<item_type> &a, const SubsetProtoAttributeDelta<item_type> &b)
    {
        // if (tail != b.head)
        // {
        //     //ERROR
        //     //TODO: assert
        // }

        auto a_work = UintToArith256(a.work);
        auto b_work = UintToArith256(b.work);
        if (a.head == b.head)
        {
            return SubsetProtoAttributeDelta<item_type>(b.tail, a.tail, a.height - b.height, ArithToUint256(a_work - b_work));
        }
        if (a.tail == b.tail)
        {
            return SubsetProtoAttributeDelta<item_type>(a.head, b.head, a.height - b.height, ArithToUint256(a_work - b_work));
        }
        //TODO: Assertion Error
    }

} // namespace c2pool::shares::tracker

//TrackerView
namespace c2pool::shares::tracker
{

    /*template <typename delta_type>
    Tracker<delta_type>:: */

    template<template<typename> typename delta_type, typename item_type>
    void Tracker<delta_type, item_type>::_handle_remove_special(item_type item)
    {
        //TODO
        // delta_type delta = delta_type(item);
    }

    template<template<typename> typename delta_type, typename item_type>
    void Tracker<delta_type, item_type>::_handle_remove_special2(item_type item)
    {
        //TODO
        // delta_type delta = delta_type(item);
    }

    template<template<typename> typename delta_type, typename item_type>
    void Tracker<delta_type, item_type>::_handle_removed(item_type item)
    {
        //TODO
        // delta_type delta = delta_type(item);
    }

} // namespace c2pool::shares::tracker

//Tracker
namespace c2pool::shares::tracker
{

    template<template<typename> typename delta_type, typename item_type>
    Tracker<delta_type, item_type>::Tracker()
    {
        //TrackerView
        using namespace std::placeholders;

        remove_special.subscribe(&Tracker<delta_type, item_type>::_handle_remove_special, this, _1);
        remove_special2.subscribe(&Tracker<delta_type, item_type>::_handle_remove_special2, this, _1);
        removed.subscribe(&Tracker<delta_type, item_type>::_handle_removed, this, _1);

        //Tracker
        //self.get_nth_parent_hash = DistanceSkipList(self) //TODO
    }

    template<template<typename> typename delta_type, typename item_type>
    Tracker<delta_type, item_type>::Tracker(vector<item_type> &_items)
    {
        //TrackerView
        using namespace std::placeholders;

        remove_special.subscribe(&Tracker<delta_type, item_type>::_handle_remove_special, this, _1);
        remove_special2.subscribe(&Tracker<delta_type, item_type>::_handle_remove_special2, this, _1);
        removed.subscribe(&Tracker<delta_type, item_type>::_handle_removed, this, _1);

        //Tracker
        //self.get_nth_parent_hash = DistanceSkipList(self) //TODO

        for (auto item : _items)
        {
            add(item);
        }
    }

    template<template<typename> typename delta_type, typename item_type>
    void Tracker<delta_type, item_type>::add(item_type item)
    {
        DELTA_TYPE delta = DELTA_TYPE(item);

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

    template<template<typename> typename delta_type, typename item_type>
    void Tracker<delta_type, item_type>::remove(uint256 item_hash)
    {
        if (items.find(item_hash) == items.end())
        {
            //TODO: raise KeyError()
        }

        auto item = items[item_hash];

        DELTA_TYPE delta = DELTA_TYPE(item);

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
            if (tails[delta.tail].empty())
            {
                tails.erase(delta.tail);
            }
        }
        else if (_exist_heads)
        {
            auto tail = heads[delta.head];
            heads.erase(delta.head);
            tails[tail].erase(delta.head);
            
            //if (reverse[delta.tail] != {delta.head}) 
            if ((reverse[delta.tail].find(delta.head) != reverse[delta.tail].end()) && (reverse[delta.tail].size() == 1))
            {
                //has sibling
            }
            else
            {
                tails[tail].insert(delta.tail);
                heads[delta.tail] = tail;
            }
        }
        else if (_exist_tails && (reverse[delta.tail].size() <= 1))
        {
            auto _heads = tails[delta.tail];
            tails.erase(delta.tail);
            for (auto head : _heads)
            {
                heads[head] = delta.head;
            }
            tails[delta.head] = {_heads};

            remove_special.happened(item);
        }
        else if (_exist_tails && (reverse[delta.tail].size() > 1))
        {
            set<uint256> _heads;
            for (auto x : tails[delta.tail])
            {
                if (is_child_of(delta.head, x))
                {
                    _heads.insert(x);
                    tails[delta.tail].erase(x);
                }

                if (tails[delta.tail].empty())
                {
                    tails.erase(delta.tail);
                }
                for (auto head : _heads)
                {
                    heads[head] = delta.head;
                }
                //TODO: assert delta.head not in self.tails
                tails[delta.head] = _heads;

                remove_special2.happened(item);
            }
        }
        else
        {
            //TODO: raise NotImplementedError()
        }

        items.erase(delta.head);
        reverse[delta.tail].erase(delta.head);
        if (reverse[delta.tail].empty())
        {
            reverse.erase(delta.tail);
        }

        removed.happened(item);
    }
} // namespace c2pool::shares::tracker