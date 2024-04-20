#pragma once

#include <boost/signals2.hpp>
#include <map>
#include <vector>
#include <functional>
#include <memory>

#include "common.h"
#include "deferred.h"

//Example:
//Event<item_type> remove_special = make_event<item_type>();
//remove_special.subscribe(&Tracker<delta_type, item_type>::_handle_remove_special, this, _1);
//void _handle_remove_special(item_type item);
//remove_special.happened(item);

class Disposable;

class Disposables
{
public:
    std::vector<std::unique_ptr<Disposable>> dis;

    void attach(Disposable&& dispose);
    void dispose();
};

class Disposable
{
    int _id;
    std::function<void(int)> _dispose;
public:

    Disposable(int id, std::function<void(int)>&& dispose) : _id(id), _dispose(std::move(dispose))
    {
    }

    operator int() const
    {
        return _id;
    }

    void attach(Disposables& dis)
    {
        dis.attach(std::move(*this));
    }

    void dispose()
    {
        _dispose(_id);
    }
};

void Disposables::attach(Disposable&& value)
{
    dis.push_back(std::make_unique<Disposable>(std::move(value)));
}

void Disposables::dispose()
{
    for (auto& v : dis)
    {
        v->dispose();
    }
}

template<typename... Args>
class _Event
{
    boost::signals2::signal<void(Args...)> sig;
    boost::signals2::signal<void()> sig_anon; //For subs without arguments;
    int times;

    boost::signals2::signal<void(Args...)> once;

    std::function<int()> get_id;
    std::map<int, boost::signals2::connection> unsub_by_id;

private:
    _Event()
    {
        get_id = c2pool::dev::count_generator();
        sig = boost::signals2::signal<void(Args...)>();
        sig_anon = boost::signals2::signal<void()>();
        once = boost::signals2::signal<void(Args...)>();
        times = 0;
    }

public:
    //for std::function/lambda
    template<typename Lambda>
    Disposable subscribe(Lambda _f)
    {
        boost::signals2::connection bc = sig.connect(_f);

        auto id = get_id();
        unsub_by_id[id] = std::move(bc);

        return Disposable(id, [&](int _id){ unsubscribe(_id); });
    }

    Disposable subscribe(const std::function<void()>& _f)
    {
        boost::signals2::connection bc = sig_anon.connect(_f);

        auto id = get_id();
        unsub_by_id[id] = std::move(bc);

        return Disposable(id, [&](int _id){ unsubscribe(_id); });
    }

    template<typename Lambda>
    void subscribe_once(Lambda _f)
    {
        once.connect(_f);
    }

    Disposable run_and_subscribe(std::function<void()> _f)
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

    void happened(const Args & ... args)
    {
        times += 1;

        if (!sig.empty())
            sig(args...);
        if (!sig_anon.empty())
            sig_anon();
        if(!once.empty())
        {
            once(args...);
            once.disconnect_all_slots();
        }
    }

    int get_times() const
    {
        return times;
    }

    template<typename... Args2>
    friend _Event<Args2...>* make_event();
};

template<typename... Args>
inline _Event<Args...>* make_event()
{
    return new _Event<Args...>();
}

template<typename VarType>
class _Variable
{
protected:
    VarType* _value = nullptr;
public:
    _Event<VarType>* changed;
    _Event<VarType, VarType>* transitioned;

protected:
    _Variable()
    {
        changed = make_event<VarType>();
        transitioned = make_event<VarType, VarType>();
    }

    explicit _Variable(const VarType& data)
    {
        _value = new VarType(data);

        changed = make_event<VarType>();
        transitioned = make_event<VarType, VarType>();
    }

    explicit _Variable(VarType&& data)
    {
        _value = new VarType(data);

        changed = make_event<VarType>();
        transitioned = make_event<VarType, VarType>();
    }
public:
    VarType& value()
    {
        return *_value;
    }

    bool isNull() const
    {
        return _value == nullptr;
    }

    _Variable<VarType> &set(VarType value)
    {
        if (!_value)
            _value = new VarType();

        if (*_value != value)
        {
            auto oldvalue = *_value;
            *_value = value;
            changed->happened(*_value);
            transitioned->happened(oldvalue, *_value);
        }
        return *this;
    }

    c2pool::deferred::shared_deferred<VarType> get_when_satisfies(std::function<bool(VarType)> when_f, c2pool::deferred::shared_deferred<VarType> def = nullptr)
    {
        if (!def)
            def = c2pool::deferred::make_deferred<VarType>();

        if (_value && when_f(*_value))
        {
            def->result.set_value(*_value);
            return def;
        }

        changed->subscribe_once([&, when_f = when_f, def = def](VarType _v)
                                {
                                        get_when_satisfies(when_f, def);
                                });
        return def;
    }

    template<typename T>
    friend _Variable<T>* make_variable();

    template<typename T>
    friend _Variable<T>* make_variable(T&& data);

    template<typename T>
    friend _Variable<T>* make_variable(const T& data);
};

template<typename T>
inline _Variable<T>* make_variable()
{
    return new _Variable<T>();
}

template<typename T>
inline _Variable<T>* make_variable(T&& data)
{
    return new _Variable<T>(std::forward<T>(data));
}

template<typename T>
inline _Variable<T>* make_variable(const T& data)
{
    return new _Variable<T>(data);
}

template<typename KeyType, typename VarType>
class _VariableDict : public _Variable<std::map<KeyType, VarType>>
{
public:
    typedef std::map<KeyType, VarType> MapType;

public:
    _Event<MapType>* added;
    _Event<MapType>* removed;
private:

    _VariableDict() : _Variable<std::map<KeyType, VarType>>()
    {
        added = make_event<MapType>();
        removed = make_event<MapType>();
    }

    explicit _VariableDict(const MapType& data) : _Variable<MapType>(data)
    {
        added = make_event<MapType>();
        removed = make_event<MapType>();
    }

    explicit _VariableDict(MapType&& data) : _Variable<MapType>(std::forward(data))
    {
        added = make_event<MapType>();
        removed = make_event<MapType>();
    }

public:
    void add(const MapType &_values)
    {
        if (_values.empty())
            return;

        if (!this->_value)
            this->_value = new MapType();

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
            //TODO: because todo in p2pool
//            this->changed->happened(*this->_value);
//            this->transitioned->happened(old_value, *this->_value);
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
            //TODO: because todo in p2pool
//            this->changed->happened(*this->_value);
//            this->transitioned->happened(old_value, *this->_value);
        }
    }

    void remove(KeyType _key)
    {
        std::vector<KeyType> keys = {_key};
        remove(keys);
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

    template<typename K, typename T>
    friend _VariableDict<K, T>* make_vardict();

    template<typename K, typename T>
    friend _VariableDict<K, T>* make_vardict(std::map<K, T>&& data);

    template<typename K, typename T>
    friend _VariableDict<K, T>* make_vardict(const std::map<K, T>& data);
};

template<typename K, typename T>
inline _VariableDict<K, T>* make_vardict()
{
    return new _VariableDict<K, T>();
}

template<typename K, typename T>
inline _VariableDict<K, T>* make_vardict(std::map<K, T>&& data)
{
    return new _VariableDict<K, T>(data);
}

template<typename K, typename T>
inline _VariableDict<K, T>* make_vardict(const std::map<K, T>& data)
{
    return new _VariableDict<K, T>(data);
}

template<typename... Args>
using Event = _Event<Args...>*;

template <typename T>
using Variable = _Variable<T>*;

template<typename KeyType, typename VarType>
using VariableDict = _VariableDict<KeyType, VarType>*;