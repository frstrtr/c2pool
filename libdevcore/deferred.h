#pragma once
#include <boost/asio.hpp>
#include <iostream>
#include <future>
#include <functional>
#include <map>
#include <memory>
#include <boost/asio/spawn.hpp>
#include <functional>
#include <utility>
#include <vector>
#include <optional>

#include "random.h"

namespace io = boost::asio;
using namespace std::chrono_literals;
using boost::system::error_code;

//TODO: documentation
namespace c2pool::deferred
{
    template<typename Fut>
    bool is_ready(Fut const &fut)
    {
        return fut.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    }

    class Fiber
    {
    public:
        boost::asio::io_context* io;
        boost::asio::yield_context yield;

        Fiber(boost::asio::io_context* _io, boost::asio::yield_context &yieldContext) : io(_io), yield(std::move(yieldContext))
        {

        }

    private:
        std::map<unsigned long long, std::shared_ptr<boost::asio::steady_timer>> external_timers;
    public:
        //Таймер, который не блокирует yield_context
        void external_timer(std::function<void(const boost::system::error_code &ec)> __handler,
                            const std::chrono::steady_clock::duration &expiry_time)
        {
            auto __timer = std::make_shared<boost::asio::steady_timer>(*io);
            unsigned long long _id = external_timers.size();

            external_timers[_id] = __timer;

            __timer->expires_from_now(expiry_time);
            __timer->async_wait([&, __handler, _id](const boost::system::error_code &ec)
                                {
                                    __handler(ec);
                                    external_timers.erase(_id);
                                });
        }

        void sleep(const std::chrono::steady_clock::duration &expiry_time)
        {
            boost::asio::steady_timer timer(*io, expiry_time);
            timer.async_wait(yield);
        }

        static std::shared_ptr<Fiber> run(boost::asio::io_context* io, std::function<void(std::shared_ptr<Fiber>)> f)
        {
            std::shared_ptr<Fiber> fiber;
            boost::asio::spawn([&](boost::asio::yield_context yieldContext){
                fiber = std::make_shared<Fiber>(io, yieldContext);
                f(fiber);
            });

            return fiber;
        }
    };

    template<typename T>
    class Deferred
    {
    public:
        std::promise<T> result;

        // TODO: add timeout
        T yield(boost::asio::io_context* _context, boost::asio::yield_context &_yield)
        {
            auto future = result.get_future();
            while (!is_ready(future))
            {
                _context->post(_yield);
            }
            return future.get();
        }

        // TODO: add timeout
        T yield(const std::shared_ptr<Fiber>& fiber)
        {
            return yield(fiber->io, fiber->yield);
        }
    };

    template <typename T>
    using shared_deferred = std::shared_ptr<Deferred<T>>;

    template <typename T>
    shared_deferred<T> make_deferred()
    {
        return std::make_shared<Deferred<T>>();
    }

    template<typename ReturnType>
    class result_reply
    {
    private:
        std::promise<ReturnType> _promise;
        std::shared_future<ReturnType> _future;

        std::vector<std::function<void(ReturnType)>> callbacks;
        std::function<void(std::string)> errback;
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

                    for (auto v: callbacks)
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
    public:
        // + 10 milliseconds -- tip for call await_result before await_timeout if t == timeout
        result_reply(io::io_context* _context, time_t t) : timeout_timer(*_context, std::chrono::seconds(t) + std::chrono::milliseconds(10)), await_timer(*_context, 1ms)
        {
            _future = _promise.get_future().share();
        }

        void add_callback(std::function<void(ReturnType)> _callback)
        {
            callbacks.push_back(_callback);
        }

        void add_errback(std::function<void(std::string)> _errback)
        {
            errback = std::move(_errback);
        }

        void await()
        {
            await_timer.async_wait(std::bind(&result_reply<ReturnType>::await_result, this, std::placeholders::_1));

            timeout_timer.async_wait([&](const boost::system::error_code &ec)
                                     {
                                         if (!ec)
                                         {
                                             cancel();

                                             if (errback)
                                                 errback("timeout!");
                                         }
                                     });

        }

        void set_value(ReturnType val)
        {
            _promise.set_value(val);
            timeout_timer.cancel();
        }


    };

    template<typename Key, typename ReturnType, typename... Args>
    struct ReplyMatcher
    {
        std::map<Key, std::shared_ptr<result_reply<ReturnType>>> result;
        std::function<void(Args...)> func;
        io::io_context* context;
        time_t timeout_t;

        ReplyMatcher(io::io_context* _context, std::function<void(Args...)> _func, time_t _timeout_t = 5) : context(_context), func(_func), timeout_t(_timeout_t)
        {
        }

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
            if (result.find(key) != result.end())
            {
                result[key]->set_value(val);
            }
            else
            {
                std::cout << "ReplyMatcher doesn't store this key";
                throw std::invalid_argument("ReplyMatcher doesn't store this key!");
            }
        }

        auto &yield(Key key, std::function<void(ReturnType)> _f, Args... ARGS)
        {
            this->operator()(key, ARGS...);
            auto &res = result[key];
            res->add_callback(_f);
            return res;
        }
    };

    // in p2pool: GenericDeferrer
    template<typename ReturnType, typename... Args>
    struct QueryDeferrer
    {
        std::map<uint256, std::shared_ptr<result_reply<ReturnType>>> result;
        std::function<void(uint256, Args...)> func;
        time_t timeout_t;
        std::function<void(std::string)> timeout_func;

        QueryDeferrer(std::function<void(uint256, Args...)> _func, time_t _timeout_t = 5,
                      std::function<void(std::string)> _timeout_func = nullptr) : func(_func), timeout_t(_timeout_t),
                                                                       timeout_func(std::move(_timeout_func))
        {}

        uint256 operator()(io::io_context* _context, Args... ARGS)
        {
            uint256 id;
            do
            {
                id = c2pool::random::random_uint256();
            } while (result.count(id));

            func(id, ARGS...);

            result[id] = std::make_shared<result_reply<ReturnType>>(_context, timeout_t);
            result[id]->await();
            result[id]->add_errback(timeout_func);

            return id;
        }

        void got_response(uint256 id, ReturnType val)
        {
            result[id]->set_value(val);
        }

        void yield(io::io_context* _context, std::function<void(ReturnType)> __f, Args... ARGS)
        {
            auto id = this->operator()(_context, ARGS...);
            result[id]->add_callback(__f);
        }

        ReturnType yield(std::shared_ptr<Fiber> fiber, Args... ARGS)
        {
            shared_deferred<ReturnType> def = make_deferred<ReturnType>();

            auto id = this->operator()(fiber->io, ARGS...);
            result[id]->add_callback([&, def = def](ReturnType res){
                def->result.set_value(res);
            });

            return def->yield(fiber);
        }
    };
}