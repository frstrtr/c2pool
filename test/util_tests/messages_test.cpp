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

    //packed bytes
    char *data = c2pool::messages::python::pymessage::send(firstMsg);
    char *expectedData = c2pool::str::from_bytes_to_strChar("118 101 114 115 105 111 110 0 0 0 0 0 111 0 0 0 80 249 219 9 1 0 0 0 2 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 4 5 6 7 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 10 11 12 13 0 14 15 0 0 0 0 0 0 0 2 49 54 17 0 0 0 18 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0");

    ASSERT_EQ(*data, *expectedData);

    c2pool::messages::message_version *secondMsg = new c2pool::messages::message_version();
    secondMsg->get_data(data);
    secondMsg->encode_data();

    std::stringstream ss = c2pool::messages::python::pymessage::receive(secondMsg->command, secondMsg->checksum, secondMsg->payload, secondMsg->unpacked_length);

    secondMsg->unpack(ss);

    std::cout << "version " << secondMsg->version << std::endl;
    std::cout << "services " << secondMsg->services << std::endl;
    std::cout << "addr_to " << secondMsg->addr_to << std::endl;
    std::cout << "addr_from " << secondMsg->addr_from << std::endl;
    std::cout << "nonce " << secondMsg->nonce << std::endl;
    std::cout << "sub_version " << secondMsg->sub_version << std::endl;
    std::cout << "mode " << secondMsg->mode << std::endl;
    std::cout << "best_share_hash " << secondMsg->best_share_hash << std::endl;




    // char* a1 = new char[4];
    // a1[0] = '\0';
    // a1[1] = (char) 255;
    // a1[2] = (char) 253;
    // a1[3] = (char) '\0';

    // char a2[4];
    // a2[0] = '\0';
    // a2[1] = (char) 255;
    // a2[2] = (char) 254;
    // a2[3] = (char) '\0';

    //std::cout << c2pool::str::compare_str(a1, a2, 4) << std::endl;
}