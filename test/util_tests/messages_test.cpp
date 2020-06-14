#include <gtest/gtest.h>
#include <messages.h>
#include <iostream>
#include <string>

using namespace std;

TEST(PyCode, MessagesIMessage)
{
    const char *test_prefix = "test_prefix";
    unique_ptr<c2pool::messages::IMessage> msg = make_unique<c2pool::messages::IMessage>(test_prefix);
    ASSERT_EQ(std::string(msg->prefix), std::string(test_prefix));
}

