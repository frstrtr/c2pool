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
    const unsigned char test_prefix[4] = {0x1, 0x2, 0x3, 0x4};
    const unsigned char test_prefix2[4] = {0x1, 0x2, 0x3, 0x4};
    c2pool::messages::IMessage* msg = new c2pool::messages::IMessage(test_prefix2);
    ASSERT_EQ(*msg->prefix, *test_prefix);
}

TEST(TestMessages, message_version)
{
    //SEND
    c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
    c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
    c2pool::messages::message_version *firstMsg = new c2pool::messages::message_version(1, 2, addrs1, addrs2, 1008386737136591102, "16", 17, 18);
    firstMsg->send();

    //expected data for firstMsg->send()
    char *expectedData = c2pool::str::from_bytes_to_strChar("118 101 114 115 105 111 110 0 0 0 0 0 111 0 0 0 243 159 131 228 1 0 0 0 2 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 4 5 6 7 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 10 11 12 13 0 14 254 224 61 15 101 130 254 13 2 49 54 17 0 0 0 18 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0");

    ASSERT_EQ(*firstMsg->data, *expectedData);

    //RECEIVE
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

TEST(TestMessages, message_addrme)
{
    c2pool::messages::message_addrme *firstMsg = new c2pool::messages::message_addrme(80);
    firstMsg->send();

    //expected data for firstMsg->send() // todo check DATA
    char *expectedData = c2pool::str::from_bytes_to_strChar("97 100 100 114 109 101 0 0 0 0 0 0 2 0 0 0 78 23 246 193 80 0");

    ASSERT_EQ(*firstMsg->data, *expectedData);

    //RECEIVE
    c2pool::messages::message_addrme *secondMsg = new c2pool::messages::message_addrme();
    secondMsg->receive_from_data(firstMsg->data); //todo

    // std::cout << "port " << secondMsg->port << std::endl;

    ASSERT_EQ(firstMsg->port, secondMsg->port);
}

TEST(TestMessages, message_getaddrs)
{
    c2pool::messages::message_getaddrs *firstMsg = new c2pool::messages::message_getaddrs(3);
    firstMsg->send();

    //expected data for firstMsg->send() // todo check DATA
    char *expectedData = c2pool::str::from_bytes_to_strChar("103 101 116 97 100 100 114 115 0 0 0 0 4 0 0 0 153 83 5 29 3 0 0 0");

    ASSERT_EQ(*firstMsg->data, *expectedData);

    //RECEIVE
    c2pool::messages::message_getaddrs *secondMsg = new c2pool::messages::message_getaddrs();
    secondMsg->receive_from_data(firstMsg->data); //todo

    // std::cout << "count " << secondMsg->count << std::endl;

    ASSERT_EQ(firstMsg->count, secondMsg->count);
}

TEST(TestMessages, message_addrs)
{
    c2pool::messages::addr addr1(1, 2, "3.4.5.6", 7);
    c2pool::messages::addr addr2(8, 9, "10.11.12.13", 14);
    vector<c2pool::messages::addr> addrs = {addr1, addr2};
    
    c2pool::messages::message_addrs *firstMsg = new c2pool::messages::message_addrs(addrs);
    firstMsg->send();


    // expected data for firstMsg->send() // todo check DATA
    char *expectedData = c2pool::str::from_bytes_to_strChar("97 100 100 114 115 0 0 0 0 0 0 0 69 0 0 0 19 146 117 0 2 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 3 4 5 6 0 7 8 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 10 11 12 13 0 14");


    ASSERT_EQ(*firstMsg->data, *expectedData);
    //RECEIVE
    c2pool::messages::message_addrs *secondMsg = new c2pool::messages::message_addrs();
    secondMsg->receive_from_data(firstMsg->data); //todo
    ASSERT_EQ(firstMsg->addrs.size(), secondMsg->addrs.size());
    
    for (int i = 0; i < firstMsg->addrs.size(); i++)
    {
        //std::cout << firstMsg->addrs[i] << " | " << secondMsg->addrs[i] << std::endl;
        ASSERT_EQ(firstMsg->addrs[i], secondMsg->addrs[i]);
    }
}