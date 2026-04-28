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
        if (*m_destroyed) return;
        m_timer.expires_after(boost::asio::chrono::seconds(m_t));
        // Bug-3-family UAF fix (paired with the Socket::m_node weak_ptr fix
        // c558fe92): m_handler() and m_cancel() are user callbacks that can
        // synchronously destroy *this (e.g. reply_matcher.hpp:92 erases the
        // ResponseWrapper that owns this Timer). The lambda's `[&]` capture
        // makes any post-callback this-relative access (m_repeat, m_cancel,
        // restart()) a use-after-free. Capture m_repeat by value and re-check
        // *destroyed before touching anything on this after each user callback.
        m_timer.async_wait(
            [&, destroyed = m_destroyed, repeat = m_repeat]
            (const boost::system::error_code& ec)
            {
                if (*destroyed)
                    return;

                if (!ec)
                {
                    m_handler();
                    // m_handler() may have destroyed *this — re-check before
                    // any this-relative access.
                    if (*destroyed) return;
                    if (repeat)
                        restart();
                } else
                {
                    if (m_cancel)
                        m_cancel();
                    // m_cancel() may also destroy *this; nothing else to do
                    // afterward, but documenting the invariant for future devs.
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
        if (*m_destroyed) return;
        m_timer.cancel();
    }

    void restart(std::optional<time_t> new_t = std::nullopt)
    {
        if (*m_destroyed) return;
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
