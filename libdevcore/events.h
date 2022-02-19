#pragma once

#include <boost/signals2.hpp>
#include <map>
#include <vector>
#include <functional>
#include <memory>


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
protected:
    std::shared_ptr<VarType> _value;
public:
    std::shared_ptr<Event<VarType>> changed;
    std::shared_ptr<Event<VarType, VarType>> transitioned;

public:
    Variable()
    {
        _value = std::make_shared<VarType>();
        changed = std::make_shared<Event<VarType>>();
        transitioned = std::make_shared<Event<VarType, VarType>>();
    }

    Variable(const VarType &init_value)
    {
        _value = std::make_shared<VarType>();
        changed = std::make_shared<Event<VarType>>();
        transitioned = std::make_shared<Event<VarType, VarType>>();
        *_value = init_value;
    }

    VarType value() const
    {
        return *_value;
    }

    Variable<VarType> &operator=(const VarType &__value)
    {
        if (*_value != __value)
        {
            auto oldvalue = *_value;
            *_value = __value;
            changed->happened(*_value);
            transitioned->happened(oldvalue, *_value);
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

template<typename KeyType, typename VarType>
class VariableDict : public Variable<std::map<KeyType, VarType>>
{
public:
    typedef std::map<KeyType, VarType> MapType;

public:
    std::shared_ptr<Event<MapType>> added;
    std::shared_ptr<Event<MapType>> removed;

    VariableDict()
    {
        added = std::make_shared<Event<MapType>>();
        removed = std::make_shared<Event<MapType>>();
    }

    VariableDict(const MapType &_value) : Variable<std::map<KeyType, VarType>>(_value)
    {
        added = std::make_shared<Event<MapType>>();
        removed = std::make_shared<Event<MapType>>();
    }

    void add(const MapType &_values)
    {
        MapType new_items;
        for (auto item: _values)
        {
            if ((this->_value->find(item.first) == this->_value->end()) || ((*this->_value)[item.first] != item.second))
            {
                new_items[item.first] = item.second;
                (*this->_value)[item.first] = item.second;
            }
        }

        if (!new_items.empty())
            added->happened(new_items);
    }

    void add(const KeyType &_key, const VarType &_value)
    {
        MapType new_items;
        auto item = std::make_pair(_key, _value);
        if ((this->_value->find(item.first) == this->_value->end()) || ((*this->_value)[item.first] != item.second))
        {
            new_items[item.first] = item.second;
            this->_value->insert(item);
            added->happened(new_items);
        }
    }

    void remove(std::map<KeyType, VarType> _values)
    {
        std::map<KeyType, VarType> gone_items;
        for (auto item: _values)
        {
            if (this->_value->find(item.first) != this->_value->end())
            {
                gone_items[item.first] = item.second;
                this->_value->erase(item.first);
            } else
            {
                //TODO: throw?
            }
        }
        removed->happened(gone_items);
    }

    void remove(KeyType _key)
    {
        std::map<KeyType, VarType> gone_items;
        if (this->_value->find(_key) != this->_value->end())
        {
            gone_items[_key] = (*this->_value)[_key];
            this->_value->erase(_key);
        }
        removed->happened(gone_items);
    }
};