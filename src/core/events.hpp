#pragma once

#include <map>
#include <memory>

#include <core/common.hpp>
#include <core/disposable.hpp>

#include <boost/signals2.hpp>

class EventDisposable : public IDisposable, public std::enable_shared_from_this<EventDisposable>
{
    int m_id;
    std::function<void(int)> m_dispose_func;

public:
    EventDisposable(int id, std::function<void(int)> dispose_func) 
        : m_id(id), m_dispose_func(std::move(dispose_func))
    {
    }

    operator int() const
    {
        return m_id;
    }

    void attach(Disposables& dis) override
    {
        auto shared_this = shared_from_this();
        dis.attach(shared_this);
    }

    void dispose() override
    {
        m_dispose_func(m_id);
    }

    static std::shared_ptr<EventDisposable> make(int id, std::function<void(int)> dispose_func)
    {
        auto result = std::make_shared<EventDisposable>(id, dispose_func);
        return result;
    }
};

template <typename...Args>
class EventData
{
    // TODO: add subscribe_once?
private:
    core::Counter m_idcounter;
    uint32_t m_times;

public:
    boost::signals2::signal<void(Args...)> m_sig;
    boost::signals2::signal<void()> m_sig_anon; // For subs without args
    
    
    std::map<int, boost::signals2::connection> m_subs;

    auto get_id()
    {
        return m_idcounter();
    }

    auto get_times() const
    {
        return m_times;
    }

    void disconnect(int id)
	{
        //Дисконнект устроен по принципу:
        //signals2::connection bc = w.Signal.connect(bind(&Object::doSomething, o));
        //bc.disconnect();
        //return bc;
        if (m_subs.contains(id))
        {
            m_subs[id].disconnect();
        }
	}

    template <typename Handler, typename DisposeFunc>
    auto connect(Handler func, DisposeFunc dispose_func)
    {
        auto id = get_id();
        m_subs[id] = m_sig.connect(func);

        return EventDisposable::make(id, [this](int id) { disconnect(id); });
    }

    auto connect(std::function<void()> func)
    {
        auto id = get_id();
        m_subs[id] = m_sig_anon.connect(func);

        return EventDisposable::make(id, [this](int id) { disconnect(id); });
    }

    void call(const Args&... args)
    {
        m_times += 1;

        if (!m_sig.empty())
            m_sig(args...);
        if (!m_sig_anon.empty())
            m_sig_anon();
        // if(!once.empty())
        // {
        //     once(args...);
        //     once.disconnect_all_slots();
        // }
    }
};

template <typename...Args>
class Event
{
    using data_t = EventData<Args...>;
private:
    std::shared_ptr<data_t> m_data;

    void check_data()
    {
        if (!m_data)
            m_data = std::make_shared<data_t>();
    }

public:
    Event() { }

    template <typename Lambda>
    auto subscribe(Lambda func)
    {
        check_data();

        return m_data->connect(func);
    }

    auto subscribe(std::function<void()> func)
    {
        check_data();

        return m_data->connect(func);
    }

    auto run_subscribe(std::function<void()> func)
    {
        check_data();

        func();
        return m_data->connect(func);
    }

    void happened(Args... args)
    {
        check_data();

        m_data->call(args...);
    }

    int get_times()
    {
        check_data();

        return m_data->get_times();
    }
};

template <typename VarType>
class Variable
{
protected:
    std::shared_ptr<VarType> m_value;

public:
    Event<VarType> changed;
    Event<VarType> transitioned;

    explicit Variable(const VarType& value)
    {
        m_value = std::make_shared<VarType>(value);
    }

    explicit Variable(VarType&& value)
    {
        m_value = std::make_shared<VarType>(value);
    }

    Variable<VarType>& set(VarType value)
    {
        if (!m_value)
            m_value = std::make_shared<VarType>();

        if (*m_value != value)
        {
            auto oldvalue = *m_value;
            *m_value = value;
            
            changed->happened(*m_value);
            transitioned->happened(oldvalue, *m_value);
        }
        return *this;
    }

    auto get_value()
    {
        return *m_value;
    }

    bool is_null() const { return m_value; }

};