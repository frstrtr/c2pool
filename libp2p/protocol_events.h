#pragma once

#include <functional>

#include <libdevcore/events.h>

#include <boost/asio.hpp>

//TODO: удалением объекта протокола (дисконнект) -- отключать все ивенты.

class ProtocolEvents
{
    bool stopped = false;
protected:
    Event<> event_handle_message;

    bool is_stopped() const { return stopped;}

    void stop() { stopped = true; }
};

// TODO: автоматическая отправка сообщения message_ping, раз в заданное время.
class ProtocolPinger : virtual ProtocolEvents
{
private:
    time_t ping_time;
    boost::asio::steady_timer timer;
    std::function<void()> outtimeF;

    void start_ping()
    {
        timer.expires_from_now(boost::asio::chrono::seconds(ping_time));
        timer.async_wait([&](const boost::system::error_code &ec)
                         {
                             if (ec)
                             {
                                 if (ec == errc::operation_canceled)
                                 {
                                     start_ping();
                                 } else
                                 {
                                     //TODO: error
                                 }
                             } else
                             {
                                 outtimeF();
                             }
                         });
    }

    void restart_ping()
    {
        timer.cancel();
    }

public:

    ProtocolPinger(std::shared_ptr<boost::asio::io_context> _context, time_t t, std::function<void()> outtime_f)
            : ping_time(t), timer(*_context), outtimeF(std::move(outtime_f))
    {
        start_ping();
        event_handle_message.subscribe(std::bind(&ProtocolPinger::restart_ping, this));
    }

    ~ProtocolPinger() = default;
//    {
//        timer.cancel();
//    }
};