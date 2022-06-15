#pragma once
#include <boost/asio.hpp>
#include <iostream>
#include <future>
#include <functional>
#include <map>
#include <memory>
#include <boost/asio/spawn.hpp>
#include <functional>
#include <vector>
#include <optional>

#include "random.h"

namespace io = boost::asio;
using namespace std::chrono_literals;
using boost::system::error_code;

//TODO: documentation
namespace c2pool::deferred
{
    template <typename Fut>
    bool is_ready(Fut const &fut)
    {
        return fut.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    }

    template <typename ReturnType>
    class result_reply
    {
    private:
        std::promise<ReturnType> _promise;
        std::shared_future<ReturnType> _future;

        std::vector<std::function<void(ReturnType)>> callbacks;
    public:
        boost::asio::steady_timer await_timer;
        boost::asio::steady_timer timeout_timer;
    private:
        void cancel()
        {
            await_timer.cancel();
            timeout_timer.cancel();
        }

        void await_result(const boost::system::error_code &ec)
        {
            if (!ec.failed())
            {
                if (is_ready(_future))
                {
                    auto result = _future.get();
                    for (auto v : callbacks)
                    {
                        v(result);
                    }
                    cancel();
                    return;
                }

                await_timer.expires_from_now(100ms);
                await_timer.async_wait(std::bind(&result_reply<ReturnType>::await_result, this, std::placeholders::_1));
            }
        }

        void await_timeout(const boost::system::error_code &ec)
        {
            if (!ec)
            {
                _promise.set_exception(make_exception_ptr(std::runtime_error("ReplyMatcher timeout!")));
                cancel();
            }
        }
    public:
        // + 10 milliseconds -- tip for call await_result before await_timeout if t == timeout
        result_reply(std::shared_ptr<io::io_context> _context, time_t t) : timeout_timer(*_context, std::chrono::seconds(t) + std::chrono::milliseconds(10)),
                                                                           await_timer(*_context, 1ms)
        {
            _future = _promise.get_future().share();
        }

        void add_callback(std::function<void(ReturnType)> _callback)
        {
            callbacks.push_back(_callback);
        }

        void await()
        {
            await_timer.async_wait(std::bind(&result_reply<ReturnType>::await_result, this, std::placeholders::_1));
            timeout_timer.async_wait(std::bind(&result_reply<ReturnType>::await_timeout, this, std::placeholders::_1));
        }

        void set_value(ReturnType val)
        {
            _promise.set_value(val);
            timeout_timer.cancel();
        }


    };

    template <typename Key, typename ReturnType, typename... Args>
    struct ReplyMatcher
    {
        std::map<Key, std::shared_ptr<result_reply<ReturnType>>> result;
        std::function<void(Args...)> func;
        std::shared_ptr<io::io_context> context;
        time_t timeout_t;

        ReplyMatcher(std::shared_ptr<io::io_context> _context, std::function<void(Args...)> _func, time_t _timeout_t = 5) : context(_context), func(_func), timeout_t(_timeout_t) {}

        void operator()(Key key, Args... ARGS)
        {
            if (!result.count(key))
            {
                func(ARGS...);

                result[key] = std::make_shared<result_reply<ReturnType>>(context, timeout_t);
                result[key]->await();
            }
        }

        void got_response(Key key, ReturnType val)
        {
            result[key]->set_value(val);
        }

        void yield(Key key, std::function<void(ReturnType)> __f, Args... ARGS)
        {
            this->operator()(key, ARGS...);
            result[key]->add_callback(__f);
        }
    };

    template <typename RetType>
    class Deferred
    {
        std::shared_ptr<io::io_context> context;
        io::yield_context yield_context;

        std::vector<std::function<void(RetType)>> callbacks;
        std::promise<RetType> promise_result;
        std::optional<RetType> result;

    public:
        Deferred(std::shared_ptr<io::io_context> _context, io::yield_context _yield_context) : context(_context), yield_context(std::move(_yield_context)) //, result_timer(*context, callback_idle)
        {
        }

    private:
        // void callback_timer(const boost::system::error_code &ec)
        // {
        //     if (!ec)
        //     {
        //     }
        //     else
        //     {
        //         throw(ec);
        //     }
        // }

    public:
        void add_callback(std::function<void(RetType)> __callback)
        {
            callbacks.push_back(__callback);
        }

    private:
        std::map<unsigned long long, std::shared_ptr<io::steady_timer>> external_timers;
    public:
        //Таймер, который не блокирует yield_context
        void external_timer(std::function<void(const boost::system::error_code &ec)> __handler, const std::chrono::_V2::steady_clock::duration &expiry_time)
        {
            auto __timer = std::make_shared<io::steady_timer>(*context);
            unsigned long long _id = c2pool::random::randomNonce();
            while (external_timers.count(_id) != 0){
                _id = c2pool::random::randomNonce();
            }
            external_timers[_id] = __timer;

            __timer->expires_from_now(expiry_time);
            __timer->async_wait([&, __handler, _id] (const boost::system::error_code& ec)
                                {
                                    __handler(ec);
                                    external_timers.erase(_id);
                                });
        }

        static std::shared_ptr<Deferred<RetType>> make_deferred(std::shared_ptr<io::io_context> _context, io::yield_context _yield_context)
        {

            auto _share = std::make_shared<Deferred<RetType>>(_context, _yield_context);

            return _share;
        }

        void sleep(const std::chrono::_V2::steady_clock::duration &expiry_time)
        {
            io::steady_timer timer(*context, expiry_time);
            timer.async_wait(yield_context);
        }

        void returnValue(RetType value)
        {
            promise_result.set_value(value);
            for (auto callback : callbacks)
            {
                callback(value);
            }
        }

        static std::shared_ptr<Deferred<RetType>> yield(std::shared_ptr<io::io_context> _context, std::function<void(std::shared_ptr<Deferred<RetType>>)> __f)
        {
            std::shared_ptr<Deferred<RetType>> _share;

            io::spawn(*_context, [&](io::yield_context _yield_context)
                      {
                          _share = Deferred<RetType>::make_deferred(_context, _yield_context); // Создаётся объект Deferred

                          __f(_share); //Вызывается декорируемый метод.
                      });

            return _share;
        }
    };

    template <typename RetType>
    using shared_defer = std::shared_ptr<Deferred<RetType>>;
}