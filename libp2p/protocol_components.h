#pragma once

#include <functional>
#include <libdevcore/events.h>
#include <libdevcore/timer.h>
#include <boost/asio.hpp>

// У каждого компонента обязательно должно быть 2 аргумента, один из которых его конфиг.
// В противном случае будет ошибка "mismatched argument pack lengths while expanding ‘TYPES’"
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
public:
    struct config
    {
        boost::asio::io_context* context;
        int frequency;
        int timeout;
    };
private:
    ProtocolEvents* events;

    int frequency_t; // частота отправки сообщения ping
    int timeout_t;   // время, через которое pinger посчитает, что peer отключён.

    c2pool::Timer timer_timeout;
    c2pool::Timer timer_ping;

public:
    Pinger(ProtocolEvents* events_, config&& config)
        : events(events_), timer_timeout(config.context), timer_ping(config.context), frequency_t(config.frequency), timeout_t(config.timeout)
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

        events->event_handle_message->subscribe(
            [this]()
            { 
                timer_timeout.restart();
                timer_ping.restart();
            }
        );
    }

    virtual void timeout() = 0;
    virtual void send_ping() = 0;
};