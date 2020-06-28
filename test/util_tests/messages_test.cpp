#include <gtest/gtest.h>
#include <messages.h>
#include <iostream>
#include <string>
#include "types.h"
#include "other.h"

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

    char *data = c2pool::messages::python::pymessage::send(command/*TODO:firstMsg->command*/, firstMsg->pack_c_str(packedFirstMsg));

    std::cout << data << std::endl;

    c2pool::messages::message_version* secondMsg = new c2pool::messages::message_version();
    secondMsg->get_data(data);
    secondMsg->encode_data();

    std::cout << "len: " << secondMsg->length << std::endl;
    //TODO: while(sstream >> int) {int -> char}
}

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