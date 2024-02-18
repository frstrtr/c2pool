#include <string>
#include <functional>
#include <sstream>
#include <map>

#include <libdevcore/events.h>
#include <libdevcore/types.h>

struct SocketEvents
{
    Event<> event_disconnect;                   // Вызывается, когда мы каким-либо образом отключаемся от пира или он от нас.
    Event<std::string> event_handle_message;    // Вызывается, когда мы получаем любое сообщение.
    Event<std::string> event_peer_receive;      // Вызывается, когда удалённый peer получает сообщение.
    Event<std::string> event_send_message;     // Вызывается, когда мы отправляем сообщение.

    explicit SocketEvents()
    {
        event_disconnect = make_event();
        event_handle_message = make_event<std::string>();
        event_peer_receive = make_event<std::string>();
        event_send_message = make_event<std::string>();
    }

    ~SocketEvents()
    {
        delete event_disconnect;
        delete event_handle_message;
        delete event_peer_receive;
        delete event_send_message;
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

    std::string last_message_sent_to_peer {"nothing"}; // last message sent by me and received by peer.
    std::map<std::string, int32_t> not_received_by_peer; // messages sent by me and not yet received by peer
    std::string last_message_received_by_me {"nothing"}; // last message sent by peer and received by me.

    void me_to_peer(const std::string& key)
    {
        last_message_sent_to_peer = key;
        auto &it = not_received_by_peer[key];
        it -= 1;
        if (it <= 0)
            not_received_by_peer.erase(key);
    }

    void me_not_yet_to_peer(const std::string& key)
    {
        auto &it = not_received_by_peer[key];
        it += 1;
    }

    void peer_to_me(const std::string& key)
    {
        last_message_received_by_me = key;
    }

public:
    DebugMessages(SocketEvents* events_) : events(events_)
    {
        events->event_handle_message->subscribe(
            [&](const std::string& command)
            {
                peer_to_me(command);
            }
        );

        events->event_peer_receive->subscribe(
            [&](const std::string& command)
            {
                me_to_peer(command);
            }
        );

        events->event_send_message->subscribe(
            [&](const std::string& command)
            {
                me_not_yet_to_peer(command);
            }
        );
    }

    std::string messages_stat()
    {
        std::stringstream ss;
        // TODO: change text
        ss << "Last message peer handle = " << last_message_sent_to_peer << "; Last message received = " << last_message_received_by_me << "; not_received = " << not_received_by_peer;
        return ss.str();
    }
};