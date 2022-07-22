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
    std::shared_ptr<boost::signals2::signal<void(Args...)>> sig;
    std::shared_ptr<boost::signals2::signal<void()>> sig_anon; //For subs without arguments;
    std::shared_ptr<int> times;

public:
    Event()
    {
        sig = std::make_shared<boost::signals2::signal<void(Args...)>>();
        sig_anon = std::make_shared<boost::signals2::signal<void()>>();
        times = std::make_shared<int>(0);
    }

    //for std::function/lambda
    template<typename Lambda>
    void subscribe(Lambda _f)
    {
        sig->connect(_f);
    }

    void subscribe(std::function<void()> _f)
    {
        std::cout << "SUBSCRIBE" << std::endl;
        sig_anon->connect(_f);
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
        (*sig)(args...);
        (*sig_anon)();
        *times += 1;
    }

    int get_times() const
    {
        if (times)
            return *times;
        else
            return 0;
    }
};


//TODO: remove shared_ptr for Events?
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

    bool isNull() const
    {
        return _value == nullptr;
    }

    Variable<VarType> &operator=(const VarType &__value)
    {
        if (_value)
            _value = std::make_shared<VarType>();

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
        if (_values.empty())
            return;

        MapType old_value = *this->_value;

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
        {
            added->happened(new_items);
            this->changed->happened(*this->_value);
            this->transitioned->happened(old_value, *this->_value);
        }
    }

    void add(const KeyType &_key, const VarType &_value)
    {
        MapType new_items;
        new_items[_key] = _value;
        add(new_items);
    }

    void remove(std::vector<KeyType> _keys)
    {
        if (_keys.empty())
            return;

        MapType old_value = *this->_value;

        MapType gone_items;
        for (auto key: _keys)
        {
            if (this->_value->find(key) != this->_value->end())
            {
                gone_items[key] = (*this->_value)[key];
                this->_value->erase(key);
            }
        }

        if (!gone_items.empty())
        {
            removed->happened(gone_items);
            this->changed->happened(*this->_value);
            this->transitioned->happened(old_value, *this->_value);
        }
    }

    void remove(KeyType _key)
    {
        std::vector<KeyType> keys = {_key};
        remove(keys);
    }

    VariableDict<KeyType, VarType> &operator=(const MapType &__value)
    {
        if (*this->_value != __value)
        {
            auto oldvalue = *this->_value;
            *this->_value = __value;
            this->changed->happened(*this->_value);
            this->transitioned->happened(oldvalue, *this->_value);
        }
        return *this;
    }

	bool exist(KeyType key)
	{
		if (!this->isNull())
		{
			if (this->_value->find(key) != this->_value->end())
				return true;
		}
		return false;
	}
};