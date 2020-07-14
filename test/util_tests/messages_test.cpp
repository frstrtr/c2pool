#include <gtest/gtest.h>
#include <messages.h>
#include <iostream>
#include <string>
#include "types.h"
#include "other.h"
#include <sstream>

//____ remove
#include <boost/asio.hpp>
#include <boost/array.hpp>
//____

using namespace std;

TEST(TestMessages, IMessage)
{
    const char *test_prefix = "test_prefix";
    unique_ptr<c2pool::messages::IMessage> msg = make_unique<c2pool::messages::IMessage>(test_prefix);
    ASSERT_EQ(std::string(msg->prefix), std::string(test_prefix));
}

TEST(TestMessages, message_version)
{
    c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
    c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
    c2pool::messages::message_version *firstMsg = new c2pool::messages::message_version(1, 2, addrs1, addrs2, 15, "16", 17, 18);
    firstMsg->send();

    char *expectedData = c2pool::str::from_bytes_to_strChar("118 101 114 115 105 111 110 0 0 0 0 0 111 0 0 0 80 249 219 9 1 0 0 0 2 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 4 5 6 7 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 10 11 12 13 0 14 15 0 0 0 0 0 0 0 2 49 54 17 0 0 0 18 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0");

    ASSERT_EQ(*firstMsg->data, *expectedData);

    c2pool::messages::message_version *secondMsg = new c2pool::messages::message_version();
    secondMsg->receive_from_data(firstMsg->data);

    // std::cout << "version " << secondMsg->version << std::endl;
    // std::cout << "services " << secondMsg->services << std::endl;
    // std::cout << "addr_to " << secondMsg->addr_to << std::endl;
    // std::cout << "addr_from " << secondMsg->addr_from << std::endl;
    // std::cout << "nonce " << secondMsg->nonce << std::endl;
    // std::cout << "sub_version " << secondMsg->sub_version << std::endl;
    // std::cout << "mode " << secondMsg->mode << std::endl;
    // std::cout << "best_share_hash " << secondMsg->best_share_hash << std::endl;

    ASSERT_EQ(firstMsg->version, secondMsg->version); 
    ASSERT_EQ(firstMsg->services, secondMsg->services); 
    ASSERT_EQ(firstMsg->addr_to, secondMsg->addr_to);
    ASSERT_EQ(firstMsg->addr_from, secondMsg->addr_from);
    ASSERT_EQ(firstMsg->nonce, secondMsg->nonce);
    ASSERT_EQ(firstMsg->sub_version, secondMsg->sub_version);
    ASSERT_EQ(firstMsg->mode, secondMsg->mode);
    ASSERT_EQ(firstMsg->best_share_hash, secondMsg->best_share_hash);
}