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
namespace c2pool::util::deferred
{
    template <typename Fut>
    bool is_ready(Fut const &fut)
    {
        return fut.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    }

    template <typename ReturnType>
    struct result_obj_type
    {
        std::promise<ReturnType> _reply;
        std::shared_future<ReturnType> _future;
        std::vector<std::function<void(ReturnType)>> callbacks;

        ReturnType result;
        boost::asio::steady_timer await_timer;
        boost::asio::steady_timer timeout;

        result_obj_type(std::shared_ptr<io::io_context> _context, time_t t) : timeout((*_context), std::chrono::seconds(t)), await_timer((*_context), 1ms)
        {
            _future = _reply.get_future().share();
        }

        void wait(const boost::system::error_code &ec)
        {
            if (!ec.failed())
            {
                if (is_ready(_future))
                {
                    for (auto v : callbacks)
                    {
                        v(result);
                    }
                    return;
                }
                else
                {
                    // std::cout << " (reply not ready)" << std::endl;
                }

                await_timer.expires_from_now(100ms);
                await_timer.async_wait(std::bind(&result_obj_type<ReturnType>::wait, this, std::placeholders::_1));
            }
            else
            {
                throw ec;
            }
        }
    };

    template <typename Key, typename ReturnType, typename... Args>
    struct ReplyMatcher
    {
        std::map<Key, std::shared_ptr<result_obj_type<ReturnType>>> result;
        std::function<ReturnType(Args...)> func;
        std::shared_ptr<io::io_context> _context;
        time_t timeout_t;

        ReplyMatcher(std::shared_ptr<io::io_context> context, std::function<ReturnType(Args...)> _func, time_t _timeout_t = 5) : func(_func), timeout_t(_timeout_t)
        {
            _context = context;
        }

        void operator()(Key key, Args... ARGS)
        {
            result[key] = std::make_shared<result_obj_type<ReturnType>>(_context, timeout_t);
            result[key]->result = func(ARGS...);
            result[key]->await_timer.async_wait(std::bind(&result_obj_type<ReturnType>::wait, result[key], std::placeholders::_1));
            result[key]->timeout.async_wait([&](const boost::system::error_code &ec)
                                            {
                                                if (!ec)
                                                {
                                                    try
                                                    {
                                                        throw std::runtime_error("ReplyMatcher timeout!");
                                                    }
                                                    catch (const std::exception &e)
                                                    {
                                                        result[key]->_reply.set_exception(std::current_exception());
                                                    }
                                                }
                                            });
        }

        void got_response(Key key, ReturnType val)
        {
            result[key]->_reply.set_value(val);
            result[key]->timeout.cancel();
        }

        void yield(Key key, std::function<void(ReturnType)> __f, Args... ARGS)
        {
            this->operator()(key, ARGS...);
            result[key]->callbacks.push_back(__f);
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
            unsigned long long _id = c2pool::random::RandomNonce();
            while (external_timers.count(_id) != 0){
                _id = c2pool::random::RandomNonce();
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