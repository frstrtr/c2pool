#include <gtest/gtest.h>

#include <iostream>
#include <memory>

#include <libp2p/protocol.h>
#include <libp2p/protocol_components.h>
#include <libp2p/handler.h>

#include <boost/asio.hpp>

class TestEventProtocol : public Protocol, ProtocolPinger
{
public:
    bool flag = false;
public:
    TestEventProtocol(std::shared_ptr<boost::asio::io_context> _context, shared_ptr<Socket> _socket,
                      shared_ptr<HandlerManager> handlerManager) : Protocol(
            _socket, handlerManager),
            ProtocolPinger(_context, 3, [&]()
            {
                flag = true;
                socket->disconnect();
            })
    {

    }

    void write(std::shared_ptr<Message> msg) override
    {
        Protocol::write(msg);
    }

    void handle(std::shared_ptr<RawMessage> raw_msg) override
    {
        Protocol::handle(raw_msg);
    }

};

class TestEventSocket : public Socket
{
public:

    TestEventSocket(handler_type message_handler) : Socket(std::move(message_handler))
    { }

    void write(std::shared_ptr<Message> msg) override
    { }

    void read() override
    { }

    bool isConnected() override
    {
        return true;
    }

    void disconnect() override
    {
        std::cout << "DISCONNECTED" << std::endl;
    }

    tuple<std::string, std::string> get_addr() override
    {
        return {"_ip", "_port"};
    }
};

TEST(p2plib_events, pinger_test)
{
    std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();

    auto handlers = std::make_shared<HandlerManager>();
    auto socket = std::make_shared<TestEventSocket>([&](std::shared_ptr<RawMessage> msg){});
    auto proto = std::make_shared<TestEventProtocol>(context, socket, handlers);

    boost::asio::steady_timer timer1(*context);
    timer1.expires_from_now(2s);
    timer1.async_wait([&](auto ec){
        if (!ec){
            ASSERT_FALSE(proto->flag);
        }
    });

    boost::asio::steady_timer timer2(*context);
    timer2.expires_from_now(6s);
    timer2.async_wait([&](const boost::system::error_code &ec){
        if (!ec){
            ASSERT_TRUE(proto->flag);
        }
    });

    boost::asio::steady_timer timer3(*context);
    timer3.expires_from_now(2s);
    timer3.async_wait([&](const boost::system::error_code &ec){
        if (!ec)
        {
            auto msg = std::make_shared<RawMessage>("empty");
            proto->handle(msg);
        }
    });

    boost::asio::steady_timer timer4(*context);
    timer4.expires_from_now(4s);
    timer4.async_wait([&](const boost::system::error_code &ec){
        if (!ec){
            ASSERT_FALSE(proto->flag);
        }
    });

    context->run();

}