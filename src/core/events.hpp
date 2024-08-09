#pragma once

#include <map>
#include <memory>

#include <core/common.hpp>
#include <core/disposable.hpp>

#include <boost/asio.hpp>
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

template <typename Handler, typename...Args>
class AsyncEventWrapper
{
    boost::asio::io_context* m_context;
    Handler m_handler;

public:
    AsyncEventWrapper(boost::asio::io_context* context, const Handler& func) : m_context(context), m_handler(func)
    {
        
    }

    void operator()(Args... args)
    {
        boost::asio::dispatch(*m_context, 
            [=, *this]{ m_handler(args...); }
        );
    }
};

template <typename...Args>
class EventData
{
    // TODO: add subscribe_once?
private:
    core::Counter m_idcounter;
    uint32_t m_times;

    auto get_id()
    {
        return m_idcounter();
    }

public:
    mutable std::mutex m_mutex;
    boost::signals2::signal<void(Args...)> m_sig;
    boost::signals2::signal<void()> m_sig_anon; // For subs without args
    
    std::map<int, boost::signals2::connection> m_subs;

    auto get_times() const
    {
        std::lock_guard lock(m_mutex);
        return m_times;
    }

    void disconnect(int id)
	{
        //Дисконнект устроен по принципу:
        //signals2::connection bc = w.Signal.connect(bind(&Object::doSomething, o));
        //bc.disconnect();
        //return bc;
        std::lock_guard lock(m_mutex);
        if (m_subs.contains(id))
        {
            m_subs[id].disconnect();
        }
	}

    template <typename Handler>//, typename DisposeFunc>
    auto connect(const Handler& func)//, DisposeFunc dispose_func)
    {
        std::lock_guard lock(m_mutex);
        auto id = get_id();
        m_subs[id] = m_sig.connect(func);

        return EventDisposable::make(id, [this](int id) { disconnect(id); });
    }

    template <typename Handler>
    auto async_connect(boost::asio::io_context* context, const Handler& func)
    {
        std::lock_guard lock(m_mutex);
        auto id = get_id();
        m_subs[id] = m_sig.connect(AsyncEventWrapper<Handler, Args...>(context, func));

        return EventDisposable::make(id, [this](int id) { disconnect(id); });
    }

    auto connect(std::function<void()> func)
    {
        std::lock_guard lock(m_mutex);
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
    auto subscribe(const Lambda& func)
    {
        check_data();

        return m_data->connect(func);
    }

    template <typename Lambda>
    auto async_subscribe(boost::asio::io_context* context, const Lambda& func)
    {
        check_data();

        return m_data->async_connect(context, func);
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
struct VarWrapper
{
    VarType m_value;
    std::mutex m_mutex;

    VarWrapper(const VarType& value) : m_value(value) { }
};

// todo: check for: VarType have operator==()
template <typename VarType>
class Variable
{
    using var_t = VarType;
    using wrap_t = VarWrapper<var_t>;
protected:
    std::shared_ptr<wrap_t> m_wrapper;

public:
    Event<var_t> changed;
    Event<var_t, var_t> transitioned;

    explicit Variable() {}

    explicit Variable(const var_t& value)
    {
        m_wrapper = std::make_shared<wrap_t>(value);
    }

    explicit Variable(var_t&& value)
    {
        m_wrapper = std::make_shared<wrap_t>(value);
    }

    void set(VarType value)
    {
        std::unique_ptr<VarType> oldvalue;
        // thread-safe change value
        {
            std::lock_guard lock(m_wrapper->m_mutex);

            if (m_wrapper->m_value == value)
            {
                return;
            } else 
            {
                oldvalue = std::make_unique<VarType>(m_wrapper->m_value);
                m_wrapper->m_value = value;
            }
        }
                        
        changed.happened(value);
        transitioned.happened(*oldvalue, value);
    }

    auto value()
    {
        if (!m_wrapper)
            throw std::runtime_error("Variable wrapper is null!");
        std::lock_guard lock(m_wrapper->m_mutex);
        return m_wrapper->m_value;
    }

    bool is_null() const { return m_wrapper; } //TODO: add constexpr check for methods VarType::[isNull()/is_null()/IsNull()]

};