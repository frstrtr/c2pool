#pragma once

#include <boost/signals2.hpp>
#include <map>
#include <vector>
#include <functional>
#include <memory>

#include "common.h"
#include "deferred.h"


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

    std::shared_ptr<boost::signals2::signal<void(Args...)>> once;

    //TODO: to shared_ptr
    std::function<int()> get_id;
    std::map<int, boost::signals2::connection> unsub_by_id;

public:
    Event()
    {
        get_id = c2pool::dev::count_generator();
        sig = std::make_shared<boost::signals2::signal<void(Args...)>>();
        sig_anon = std::make_shared<boost::signals2::signal<void()>>();
        once = std::make_shared<boost::signals2::signal<void(Args...)>>();
        times = std::make_shared<int>(0);
    }

    //for std::function/lambda
    template<typename Lambda>
    int subscribe(Lambda _f)
    {
        boost::signals2::connection bc = sig->connect(_f);

        auto id = get_id();
        unsub_by_id[id] = std::move(bc);

        return id;
    }

    int subscribe(std::function<void()> _f)
    {
        std::cout << "SUBSCRIBE" << std::endl;
        boost::signals2::connection bc = sig_anon->connect(_f);

        auto id = get_id();
        unsub_by_id[id] = std::move(bc);

        return id;
    }

    template<typename Lambda>
    void subscribe_once(Lambda _f)
    {
        once->connect(_f);
    }

    int run_and_subscribe(std::function<void()> _f)
    {
        _f();
        return subscribe(_f);
    }

	void unsubscribe(int id)
	{
//        //Дисконнект устроен по принципу:
//        //signals2::connection bc = w.Signal.connect(bind(&Object::doSomething, o));
//        //bc.disconnect();
//        //return bc;
        if (unsub_by_id.find(id) != unsub_by_id.end())
        {
            unsub_by_id[id].disconnect();
        }
	}

    void happened(Args & ... args)
    {
        *times += 1;

        if (!sig->empty())
            (*sig)(args...);
        if (!sig_anon->empty())
            (*sig_anon)();
        if(!once->empty())
        {
            (*once)(args...);
            once->disconnect_all_slots();
        }
    }

    int get_times() const
    {
        if (times)
            return *times;
        else
            return 0;
    }
};


template<typename VarType>
class Variable
{
public:
    std::shared_ptr<VarType> _value;
public:
    std::shared_ptr<Event<VarType>> changed;
    std::shared_ptr<Event<VarType, VarType>> transitioned;

public:
    Variable(bool default_init = false)
    {
        if (default_init)
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

    std::shared_ptr<VarType> pvalue()
    {
        return _value;
    }

    VarType value() const
    {
        return *_value;
    }

    bool isNull() const
    {
        return _value == nullptr;
    }

    Variable<VarType> &set(VarType __value)
    {
        if (!_value)
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

    Variable<VarType> &operator=(VarType __value)
    {
        this->set(__value);
        return *this;
    }

    c2pool::deferred::shared_deferred<VarType> get_when_satisfies(std::function<bool(VarType)> when_f, c2pool::deferred::shared_deferred<VarType> def = nullptr)
    {
        if (!def)
            def = c2pool::deferred::make_deferred<VarType>();

        changed->subscribe_once([&, when_f = when_f, def = def](VarType _v)
                                {
                                    if (when_f(_v)){
                                        def->result.set_value(_v);
                                    }
                                    else{
                                        get_when_satisfies(when_f, def);
                                    }
                                });
        return def;
    }
};

template<typename KeyType, typename VarType>
class VariableDict : public Variable<std::map<KeyType, VarType>>
{
public:
    typedef std::map<KeyType, VarType> MapType;

public:
    std::shared_ptr<Event<MapType>> added;
    std::shared_ptr<Event<MapType>> removed;

    VariableDict(bool default_init = false) : Variable<std::map<KeyType, VarType>>(default_init)
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
        if (this->isNull())
            return *this;

        if (*this->_value != __value)
        {
            auto oldvalue = *this->_value;

            this->_value->clear();
            for (auto [k, v] : __value)
            {
                (*this->_value)[k] = v;
            }
//            *this->_value = __value;

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