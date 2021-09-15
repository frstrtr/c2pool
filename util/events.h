#pragma once

#include <boost/signals2.hpp>
#include <map>
#include <vector>
#include <functional>

namespace c2pool::util::events
{

    //Example:
    //Event<item_type> remove_special;
    //remove_special.subscribe(&Tracker<delta_type, item_type>::_handle_remove_special, this, _1);
    //void _handle_remove_special(item_type item);
    //remove_special.happened(item);

    template <typename... Args>
    class Event
    {
        boost::signals2::signal<void(Args...)> sig;
        int times;

    public:
        Event() {}

        template <typename _Func, typename... _BoundArgs>
        void subscribe(_Func &&__f, _BoundArgs &&...__args)
        {
            sig.connect(std::bind(__f, __args...));
        }

        //for std::function/lambda
        template <typename Lambda>
        void subscribe(Lambda _f)
        {
            sig.connect(_f);
        }

        void run_and_subscribe(std::function<void()> _f)
        {
            _f();
            subscribe(_f);
        }

        void unsubscribe()
        {
            //TODO
        }

        void happened(Args... args)
        {
            sig(args...);
            times += 1;
        }
    };
} // namespace c2pool::util::events

namespace c2pool::util::events
{
    template <typename VarType>
    class Variable
    {
    public:
        VarType value;
        Event<VarType> changed;
        Event<VarType, VarType> transitioned;

    public:
        Variable() {}

        Variable(VarType _value)
        {
            value = _value;
        }

        Variable<VarType> &operator=(const VarType &_value)
        {
            if (value != _value)
            {
                auto oldvalue = value;
                value = _value;
                changed.happened(value);
                transitioned.happened(oldvalue, value);
            }
            return *this;
        }

        /* TODO:
        @defer.inlineCallbacks
        def get_when_satisfies(self, func):
            while True:
                if func(self.value):
                    defer.returnValue(self.value)
                yield self.changed.once.get_deferred()

        def get_not_none(self):
            return self.get_when_satisfies(lambda val: val is not None)      
        */
    };

    // template <typename KeyType, typename VarType>
    // class VariableDict
    // {
    // public:
    //     VarType value;
    //     Event<VarType> added;
    //     Event<VarType> removed;

    // public:
    //     VariableDict() {}
    //     VariableDict(std::map<KeyType, VarType> _value)
    //     {
    //         value = _value;
    //     }

    //     void add(std::map<KeyType, VarType> _values)
    //     {
    //         std::map<KeyType, VarType> new_items;
    //         for (auto item : _values)
    //         {
    //             if ((value.find(item.first) == value.end()) || (value[item.first] != item.second))
    //             {
    //                 new_item[item.first] = item.second;
    //             }
    //         }
    //         value.insert(_values.begin(), _values.end());
    //         added.happened(new_items);
    //     }

    //     void remove(std::map<KeyType, VarType> _values)
    //     {
    //         //TODO: void std::map::erase (iterator first, iterator last);
    //         std::map<KeyType, VarType> gone_items;
    //         for (auto item : _values)
    //         {
    //             if (value.find(item.first) != value.end())
    //             {
    //                 gone_items[item.first] = item.second;
    //                 value.erase(item.first);
    //             }
    //         }
    //         removed.happened(gone_items)
    //     }
    // };
} // namespace c2pool::util::events