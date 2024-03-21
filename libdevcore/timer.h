#pragma once
#include <boost/asio.hpp>

#include <functional>

namespace c2pool
{
    class Timer
    {
        std::shared_ptr<bool> stoped;
        boost::asio::steady_timer timer;

        int t; // seconds
        bool repeat;
        std::function<void()> handler;
        std::function<void()> cancel_handler;
    private:
        void timer_logic()
        {
            timer.expires_from_now(boost::asio::chrono::seconds(t));
            timer.async_wait(
                [&, stoped_ = stoped](const boost::system::error_code& ec)
                {
                    if (*stoped_)
                        return;

                    if (!ec)
                    {
                        handler();

                        if (repeat)
                            restart();
                    } else
                    {
                        if (cancel_handler) 
                            cancel_handler();
                    }
                }
            );
        }
    public:
        Timer(boost::asio::io_context* context, bool repeat_ = false) : timer(*context), repeat(repeat_)
        {
            stoped = std::make_shared<bool>(false);
        }

        ~Timer()
        {
            *stoped = true;
        }

        void start(int t_, std::function<void()> handler_, std::function<void()> cancel_ = nullptr)
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

        void restart(std::optional<int> new_t = std::nullopt)
        {
            if (new_t)
                t = new_t.value();

            timer_logic();
        }

        void happened()
        {
            handler();
            if (repeat)
                restart();
        }
    };
}