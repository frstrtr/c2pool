#include <string>
#include <functional>
#include <map>

#include <libdevcore/events.h>
#include <libdevcore/types.h>

struct SocketEvents
{
    Event<> event_disconnect;                   // Вызывается, когда мы каким-либо образом отключаемся от пира или он от нас.
    Event<std::string> event_handle_message;    // Вызывается, когда мы получаем любое сообщение.
    Event<std::string> event_peer_receive;      // Вызывается, когда удалённый peer получает сообщение.
    Event<std::string> event_write_message;     // Вызывается, когда мы отправляем сообщение.

    explicit SocketEvents()
    {
        event_disconnect = make_event();
        event_handle_message = make_event<std::string>();
    }

    ~SocketEvents()
    {
        delete event_disconnect;
        delete event_handle_message;
    }

};

struct CustomSocketDisconnect
{
    // type for function PoolNodeServer::disconnect();
    typedef std::function<void(const NetAddress& addr)> disconnect_type;

    disconnect_type disconnect;

    CustomSocketDisconnect(disconnect_type disconnect_) 
        : disconnect(std::move(disconnect_)) 
    {
    }
};

class DebugMessages
{
private:
    SocketEvents* events;

    std::string last_message_sent; // last message sent by me and received by peer.
    std::string last_message_received; // last message sent by peer and received by me.
    std::map<std::string, int32_t> not_received; // messages sent by me and not yet received by peer

public:
    DebugMessages(SocketEvents* events_) : events(events_)
    {
        events->event_handle_message->subscribe(
            [&](std::string& command)
            {
                
            }
        );
    }

    void update_last_sent(std::string msg)
    {
        last_message_sent = msg;
    }

    void update_last_received(std::string msg)
    {
        last_message_received = msg;
    }

    void add_not_received(const std::string& key)
    {
        auto &it = not_received[key];
        it += 1;
    }

    void remove_not_received(const std::string& key)
    {
        auto &it = not_received[key];
        it -= 1;
        if (it <= 0)
            not_received.erase(key);
    }

    std::string messages_stat() const
    {
        std::stringstream   
    }
};