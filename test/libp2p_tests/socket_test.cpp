#include <gtest/gtest.h>

#include <iostream>
#include <utility>

#include <libp2p/socket.h>
#include <libp2p/message.h>

#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

class test_message2 : public Message
{
public:
    IntType(32) num;

    test_message2() : Message("test_message") { }

    test_message2(int _num) : test_message2()
    {
        num = _num;
    }

    PackStream &write(PackStream &stream) override
    {
        stream << num;
        return stream;
    }

    PackStream &read(PackStream &stream) override
    {
        stream >> num;
        return stream;
    }
};

struct PseudoProtocol
{
    std::shared_ptr<Socket> socket;

    void connect_socket(std::shared_ptr<Socket> _socket)
    {
        socket = _socket;
    }

    void get_message(std::shared_ptr<Message> msg)
    {
        PackStream stream;
        stream << *msg;

        test_message2 parsed_msg;
        stream >> parsed_msg;

//        std::cout << "PseudoProtocol get msg: " << parsed_msg.command
//                << "; Num = " << parsed_msg.num.get() << std::endl;

        ASSERT_EQ(parsed_msg.command, "test_message");
        ASSERT_EQ(parsed_msg.num.get(), 843);
    }
};

class TestSocket : public Socket
{
private:
    std::shared_ptr<PseudoProtocol> proto;
public:

    TestSocket(handler_type message_handler) : Socket(std::move(message_handler))
    { }

    void write(std::shared_ptr<Message> msg) override
    {
        if (isConnected())
        {
            proto->get_message(msg);
        }
    }

    void read() override
    { }

    bool isConnected() override
    {
        return (bool)proto;
    }

    void disconnect() override
    {
        proto = nullptr;
    }

    tuple<std::string, std::string> get_addr() override
    {
        return {"_ip", "_port"};
    }

    void connect(std::shared_ptr<PseudoProtocol> _proto)
    {
        proto = _proto;
    }

};

TEST(p2plib_socket, socket_test)
{
    auto socket = std::make_shared<TestSocket>( [&](std::shared_ptr<RawMessage> msg){});
    ASSERT_FALSE(socket->isConnected());

    auto proto = std::make_shared<PseudoProtocol>();
    socket->connect(proto);
    ASSERT_TRUE(socket->isConnected());

    proto->connect_socket(socket);

    auto msg = std::make_shared<test_message2>(843);
    socket->write(msg);
}