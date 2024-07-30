#pragma once

#include <boost/asio.hpp>
#include <functional>
#include <optional>
#include <memory>

namespace core
{
    
class Timer
{
    using handler_t = std::function<void()>;
private:
    boost::asio::steady_timer m_timer;

    time_t m_t;
    bool m_repeat;
    std::shared_ptr<bool> m_destroyed;

    handler_t m_handler;
    handler_t m_cancel;

    void logic()
    {
        m_timer.expires_from_now(boost::asio::chrono::seconds(m_t));
        m_timer.async_wait(
            [&, destroyed = m_destroyed](const boost::system::error_code& ec)
            {
                if (*destroyed)
                    return;

                if (!ec)
                {
                    m_handler();
                    if (m_repeat)
                        restart();
                } else
                {
                    if (m_cancel)
                        m_cancel();
                }
            }
        );
    }

public:
    Timer(boost::asio::io_context* ctx, bool repeat = false) 
        : m_timer(*ctx), m_repeat(repeat) 
    {
        m_destroyed = std::make_shared<bool>(false);
    }

    ~Timer()
    {
        *m_destroyed = true;
    }

    void start(time_t t, handler_t handler, handler_t cancel = nullptr)
    {
        m_t = t;
        m_handler = std::move(handler);
        if (cancel) 
            m_cancel = std::move(cancel);
        logic();
    }

    void stop()
    {
        m_timer.cancel();
    }

    void restart(std::optional<time_t> new_t = std::nullopt)
    {
        if (new_t) 
            m_t = new_t.value();
        logic();
    }

    void happened()
    {
        m_handler();
        if (m_repeat) 
            restart();
    }
};

} // namespace core
