#pragma once

#include <boost/signals2.hpp>
#include <map>
#include <vector>
#include <functional>


//Example:
//Event<item_type> remove_special;
//remove_special.subscribe(&Tracker<delta_type, item_type>::_handle_remove_special, this, _1);
//void _handle_remove_special(item_type item);
//remove_special.happened(item);

template<typename... Args>
class Event
{
    boost::signals2::signal<void(Args...)> sig;
    int times;

public:
    Event()
    {}

    //for std::function/lambda
    template<typename Lambda>
    void subscribe(Lambda _f)
    {
        sig.connect(_f);
    }

    void run_and_subscribe(std::function<void()> _f)
    {
        _f();
        subscribe(_f);
    }

//	void unsubscribe()
//	{
//        //Дисконнект устроен по принципу:
//        //signals2::connection bc = w.Signal.connect(bind(&Object::doSomething, o));
//        //bc.disconnect();
//        //return bc;
//	}

    void happened(Args... args)
    {
        sig(args...);
        times += 1;
    }
};

template<typename VarType>
class Variable
{
public:
    VarType value;
    Event<VarType> changed;
    Event<VarType, VarType> transitioned;

public:
    Variable()
    {}

    Variable(const VarType &_value)
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

//TODO: test
template<typename KeyType, typename VarType>
class VariableDict : public Variable<std::map<KeyType, VarType>>
{
public:
    typedef std::map<KeyType, VarType> MapType;

public:
    Event<MapType> added;
    Event<MapType> removed;

    VariableDict()
    {}

    VariableDict(const MapType &_value) : Variable<std::map<KeyType, VarType>>(_value)
    {
    }

    void add(const MapType &_values)
    {
        MapType new_items;
        for (auto item: _values)
        {
            if ((this->value.find(item.first) == this->value.end()) || (this->value[item.first] != item.second))
            {
                new_items[item.first] = item.second;
            }
        }
        this->value.insert(new_items.begin(), new_items.end());
        added.happened(new_items);
    }

    void add(const KeyType &_key, const VarType &_value)
    {
        MapType new_items;
        auto item = std::make_pair(_key, _value);
        if ((this->value.find(item.first) == this->value.end()) || (this->value[item.first] != item.second))
        {
            new_items[item.first] = item.second;
        }
        std::map<int, int> a;
        this->value.insert(this->value.begin(), item);
        added.happened(new_items);
    }

    void remove(std::map<KeyType, VarType> _values)
    {
        std::map<KeyType, VarType> gone_items;
        for (auto item: _values)
        {
            if (this->value.find(item.first) != this->value.end())
            {
                gone_items[item.first] = item.second;
                this->value.erase(item.first);
            }
        }
        removed.happened(gone_items);
    }

    void remove(KeyType _key)
    {
        std::map<KeyType, VarType> gone_items;
        if (this->value.find(_key) != this->value.end())
        {
            gone_items[_key] = this->value[_key];
            this->value.erase(_key);
        }
        removed.happened(gone_items);
    }
};