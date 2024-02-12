#pragma once
#include <boost/asio.hpp>

#include <functional>

namespace c2pool
{
    class Timer
    {
        boost::asio::steady_timer timer;

        time_t t; // seconds
        std::function<void()> handler;
        std::function<void()> cancel_handler;
    private:
        void timer_logic()
        {
            timer.expires_from_now(boost::asio::chrono::seconds(t));
            timer.async_wait(
                [&](const boost::system::error_code& ec)
                {
                    if (!ec)
                    {
                        handler();
                    } else
                    {
                        if (cancel_handler) 
                            cancel_handler();
                    }
                }
            );
        }
    public:
        Timer(boost::asio::io_context* context) : timer(*context)
        {
        }

        void start(time_t t_, std::function<void()> handler_, std::function<void()> cancel_ = nullptr)
        {
            t = t_;
            handler = std::move(handler_);

            if (cancel_)
                cancel_handler = std::move(cancel_);

            timer_logic();
        }

        void stop()
        {
            timer.cancel();
        }

        void restart(std::optional<time_t> new_t = std::nullopt)
        {
            if (new_t)
                t = new_t.value();

            timer_logic();
        }
    };
}