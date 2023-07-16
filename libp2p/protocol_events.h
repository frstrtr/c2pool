#pragma once

#include <functional>

#include <libdevcore/events.h>

#include <boost/asio.hpp>

//TODO: удалением объекта протокола (дисконнект) -- отключать все ивенты.

class ProtocolEvents
{
    bool stopped = false;
public:
    Event<> event_handle_message;   // Вызывается, когда мы получаем любое сообщение.
    Event<> event_disconnect;       // Вызывается, когда мы каким-либо образом отключаемся от пира или он от нас.

    explicit ProtocolEvents()
    {
        event_handle_message = make_event();
        event_disconnect = make_event();
    }

    ~ProtocolEvents()
    {
        delete event_handle_message;
        delete event_disconnect;
    }

protected:
    bool is_stopped() const { return stopped;}

    void stop() { stopped = true; }
};

class ProtocolPinger : virtual ProtocolEvents
{
private:
    time_t outtime_ping_time;
    boost::asio::steady_timer timer_outtime;
    std::function<void()> outtimeF;

	std::function<time_t()> send_ping_time;
	boost::asio::steady_timer timer_send_ping;
	std::function<void()> send_pingF;

    void start_outtime_ping()
    {
		timer_outtime.expires_from_now(boost::asio::chrono::seconds(outtime_ping_time));
		timer_outtime.async_wait([&](const boost::system::error_code &ec)
                         {
                             if (ec)
                             {
                                 if (ec == boost::system::errc::operation_canceled)
                                 {
									 // Если таймер был canceled, то он запускается заново без вызова outtimeF()
                                     start_outtime_ping();
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

	void start_send_ping()
	{
		timer_send_ping.expires_from_now(boost::asio::chrono::seconds(send_ping_time()));
		timer_send_ping.async_wait([&](const boost::system::error_code &ec){
			if (!ec)
			{
				send_pingF();
				start_send_ping();
			} else
			{
				// TODO: error
			}
		});
	}

    void restart_ping()
    {
		timer_outtime.cancel();
    }

public:

    ProtocolPinger(const std::shared_ptr<boost::asio::io_context>& _context, time_t outtime_t, std::function<void()> outtime_f, std::function<time_t()> send_ping_t, std::function<void()> send_ping_f)
            : outtime_ping_time(outtime_t), timer_outtime(*_context), outtimeF(std::move(outtime_f)),
			  send_ping_time(std::move(send_ping_t)), timer_send_ping(*_context), send_pingF(std::move(send_ping_f))
    {
        start_outtime_ping();
        event_handle_message->subscribe([this] { restart_ping(); });

		start_send_ping();
    }

    ~ProtocolPinger() = default;
//    {
//        timer.cancel();
//    }
};