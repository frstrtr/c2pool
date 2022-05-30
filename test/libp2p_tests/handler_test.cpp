#include <gtest/gtest.h>

#include <iostream>
#include <string>

#include <libp2p/handler.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>


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

TEST(libp2p, raw_handler)
{
    IntType(32) _num(123321);

    PackStream _stream;
    _stream << _num;

    int result;
    auto _handler = make_handler<test_message>([&](auto msg){
        result = msg->num.get();
    });

    _handler->invoke(_stream);
    ASSERT_EQ(result, 123321);
}

TEST(libp2p, handler_manager)
{
    const std::string msg_command = "test_message_123";
    HandlerManager mngr;

    IntType(32) _num(123321);

    PackStream _stream;
    _stream << _num;

    int result;
    mngr.new_handler<test_message>(msg_command, [&](auto msg){
        result = msg->num.get();
    });

    mngr[msg_command]->invoke(_stream);

    ASSERT_EQ(result, 123321);
}