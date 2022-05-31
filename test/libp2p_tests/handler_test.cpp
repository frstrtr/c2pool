#include <gtest/gtest.h>

#include <iostream>
#include <string>
#include <memory>

#include <libp2p/handler.h>
#include <libp2p/protocol.h>
#include <libp2p/message.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

class TestProtocol : public Protocol
{
public:
    int version;
    std::string test_data;
};

struct test_message
{
    IntType(32) num;

    PackStream &write(PackStream &stream)
    {
        stream << num;
        return stream;
    }

    PackStream &read(PackStream &stream)
    {
        stream >> num;
        return stream;
    }
};

class p2plib_handler : public ::testing::Test
{
public:
    PackStream packed_test_message;
    std::shared_ptr<TestProtocol> protocol;

protected:
    virtual void SetUp()
    {
        IntType(32) _num(123321);
        packed_test_message << _num;

        protocol = std::make_shared<TestProtocol>();
    }

    virtual void TearDown()
    {

    }
};

TEST_F(p2plib_handler, raw_handler)
{
    auto _handler = make_handler<test_message, TestProtocol>([&](auto _msg, auto _protocol){
        _protocol->version = _msg->num.get();
    });

    _handler->invoke(packed_test_message, protocol);
    ASSERT_EQ(protocol->version, 123321);
}

TEST_F(p2plib_handler, handler_manager)
{
    const std::string msg_command = "test_message_123";
    auto mngr = std::make_shared<HandlerManager>();
    protocol->set_handler_manager(mngr);

    mngr->new_handler<test_message, TestProtocol>(msg_command, [&](auto _msg, auto _protocol){
        _protocol->version = _msg->num.get();
    });

    auto raw_msg = std::make_shared<RawMessage>(msg_command);
    packed_test_message >> *raw_msg;

    protocol->handle(raw_msg);

    ASSERT_EQ(protocol->version, 123321);
}