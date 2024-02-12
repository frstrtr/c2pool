#pragma once

#include <functional>
#include <libdevcore/events.h>
#include <libdevcore/timer.h>
#include <boost/asio.hpp>

class ProtocolEvents
{
public:
    Event<> event_handle_message;   // Вызывается, когда мы получаем любое сообщение.

    explicit ProtocolEvents()
    {
        event_handle_message = make_event();
    }

    ~ProtocolEvents()
    {
        delete event_handle_message;
    }
};

class Pinger
{
private:
    ProtocolEvents* events;

    time_t frequency_t; // частота отправки сообщения ping
    time_t timeout_t;   // время, через которое pinger посчитает, что peer отключён.

    c2pool::Timer timer_timeout;
    c2pool::Timer timer_ping;

public:
    Pinger(boost::asio::io_context* context, auto frequency_, auto timeout_)
        : timer_timeout(*context), timer_ping(*context), frequency_t(frequency_), timeout_t(timeout_)
    {
        timer_timeout.start(
            timeout_t,
            [&]()
            {
                timeout();
            }
        );

        timer_ping.start(
            frequency_t,
            [&]()
            {
                send_ping();
            }
        );

        event_handle_message->subscribe(
            [this]()
            { 
                timer_timeout->restart();
                timer_ping->restart();
            }
        );
    }

    virtual void timeout() = 0;
    virtual void send_ping() = 0;
};