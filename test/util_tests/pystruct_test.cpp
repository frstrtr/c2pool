#include <gtest/gtest.h>
#include <pystruct.h>
#include <messages.h>
#include <types.h>
using namespace std;

TEST(PyCode, PyReceiveLength)
{
    int first_num = 10;

    char *first_num_chr = c2pool::messages::python::for_test::pymessage::get_packed_int(first_num);

    int second_num = c2pool::messages::python::pymessage::receive_length(first_num_chr);

    ASSERT_EQ(first_num, second_num);
}

TEST(PyCode, PyReceive)
{
    char *payload = c2pool::messages::python::for_test::pymessage::data_for_test_receive();
    char *command = "version";
    unsigned int length = c2pool::messages::python::for_test::pymessage::length_for_test_receive();
    char *checksum = c2pool::messages::python::for_test::pymessage::checksum_for_test_receive();

    std::stringstream received_data = c2pool::messages::python::pymessage::receive(command, checksum, payload, length);

    std::string res;

    std::getline(received_data, res);

    ASSERT_EQ(res, "1 2 3 4.5.6.7 8 9 10.11.12.13 14 15 16 17 18");
}

TEST(PyCode, PySend)
{
    char *command = "version";
    char *payload2 = "1;2;3,4.5.6.7,8;9,10.11.12.13,14;15;16;17;18";

    char *res = c2pool::messages::python::pymessage::send(command, payload2);

    char *realRes = c2pool::messages::python::for_test::pymessage::data_for_test_send();

    ASSERT_EQ(*res, *realRes);
}