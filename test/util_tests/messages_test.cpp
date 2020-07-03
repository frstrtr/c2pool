#include <gtest/gtest.h>
#include <messages.h>
#include <iostream>
#include <string>
#include "types.h"
#include "other.h"

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
    // char *payload = c2pool::messages::python::for_test::pymessage::data_for_test_receive();
    // char *command = "version";
    // char *checksum = c2pool::messages::python::for_test::pymessage::checksum_for_test_receive();

    // std::stringstream received_data = c2pool::messages::python::pymessage::receive(command, checksum, payload);

    // c2pool::messages::message_version *msg = new c2pool::messages::message_version();
    // msg->unpack(received_data);

    // ASSERT_EQ(msg->nonce, 17);

    //______________________________
    char *command = "version";
    c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
    c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
    c2pool::messages::message_version *firstMsg = new c2pool::messages::message_version(1, 2, addrs1, addrs2, 15, "16", 17, 18);

    char *packedFirstMsg;

    char *data = c2pool::messages::python::pymessage::send(command /*TODO:firstMsg->command*/, firstMsg->pack_c_str(packedFirstMsg));

    for (int i = 0; i < 120; i++)
    {
        std::cout << "DATA[ " << i << "]" << (int)data[i] << std::endl;
    }
    c2pool::messages::message_version *secondMsg = new c2pool::messages::message_version();
    secondMsg->get_data(data);
    secondMsg->encode_data();

    for (int i = 0; i < 50; i++)
    {
        std::cout << "sym[i]: " << secondMsg->payload[i] << std::endl;
    }
    //TODO: while(sstream >> int) {int -> char}

    std::cout << "IN TEST: " << c2pool::messages::python::for_test::pymessage::test_get_bytes_from_cpp(data, 131) << std::endl;
    ;

    char *dest1 = new char[9];
    char *source = "tes\0tdata";
    strncpy(dest1, source + 3, 4);
    dest1[4] = 0;
    char *dest2;
    memcpy(dest2, source + 3, 4);
    dest2[4] = 0;

    std::cout << "dest1: " << dest1 << std::endl;
    std::cout << "dest2: " << dest2 << std::endl;

    std::cout << memcmp(dest1, dest2, 4);
}

// TEST(TestMessages, bytes_convert_test)
// {
//     // char *data1 = "a\0bcd\nefgs";
//     // boost::array<char, 100> arr = {'a', '\0', 'b', 'c', 'd', '\n', 'e', 'f', 'g'};
//     // auto buff = boost::asio::buffer(data1, 10);
//     // std::string str(data1, 10);
//     // std::cout << "test str: " << str << std::endl;
//     // std::cout << c2pool::messages::python::for_test::pymessage::test_get_bytes_from_cpp(data1) << std::endl;
//     // char *data2 = "a\\0b";
//     // std::cout << data1 << "with len: " << strlen(data1) << ", with sizeof: " << sizeof(data1)  << std::endl;
//     // ASSERT_EQ(*data1, *arr.data());

//     //____________________________________
//     // std::vector<char> vec(100);
//     // strncpy(&vec[0], "a\0bcd\nefgs", 100);
//     // std::string str(vec.begin(), vec.end());
//     // //std::string str = "a\0bcd\nefgs";
//     // std::cout << "str: " << str << std::endl;
//     // char *str_c = new char[str.length() + 1];
//     // strcpy(str_c, str.c_str());
//     // std::cout << "str_c: " << str_c << std::endl;
//     // for (int i = 0; i < str.length(); i++)
//     // {
//     //     std::cout << str_c[i];
//     // }
//     // std::cout << std::endl;
//     //__________________________

//     std::string x("pq\0rs", 5); // 5 Characters as the input is now a char array with 5 characters.
//     std::cout << x << std::endl;
//     std::cout << x.length() << std::endl;

//     char *str_c = new char[x.length() + 1];
//     memcpy(str_c, x.c_str(), 5);
//     std::cout << "str_c: " << str_c << std::endl;
//     for (int i = 0; i < x.length(); i++)
//     {
//         std::cout << i << ":" << str_c[i] << std::endl;
//     }
//     std::cout << ((char*)boost::asio::buffer(str_c, 5).data())[3] << std::endl;

//     std::string x2("pq\0rss", 5);
//     std::string x3("qq\0rs", 5);
//     std::string x4("pq\0r", 4);
//     std::cout << std::memcmp(str_c, x.c_str(), 5) << std::endl; //0
//     std::cout << std::memcmp(str_c, x2.c_str(), 5) << std::endl; //0
//     std::cout << std::memcmp(str_c, x3.c_str(), 5) << std::endl; //-1
//     std::cout << std::memcmp(str_c, x4.c_str(), 5) << std::endl; //1
// }

/* //WORK FOR MESSAGE_VERSION!
TEST(PyCode, PyReceive)
{
    char *payload = c2pool::messages::python::for_test::pymessage::data_for_test_receive();
    char *command = "version";
    char *checksum = c2pool::messages::python::for_test::pymessage::checksum_for_test_receive();

    std::stringstream received_data = c2pool::messages::python::pymessage::receive(command, checksum, payload);

    c2pool::messages::message_version *msg = new c2pool::messages::message_version();
    msg->unpack(received_data);

    ASSERT_EQ(msg->nonce, 17);
}
*/

/* for test messages:
    c2pool::messages::address_type addr(1, "test", 1);
    std::string s = "test";
    c2pool::messages::message_version* msg = new c2pool::messages::message_version(1, 1, addr, addr, 1, s, 0, 0);
*/