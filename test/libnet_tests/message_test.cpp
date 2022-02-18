#include <gtest/gtest.h>
#include <libnet/messages.h>
#include <libnet/p2p_socket.h>
#include <memory>

using std::make_shared;
using namespace c2pool::libnet::messages;



TEST(LIBNET_MESSAGES, version)
{
    int ver = 3301;
    std::string test_sub_ver = "16";
    unsigned long long test_nonce = 6535423;
    c2pool::messages::address_type addrs1(3, "4.5.6.7", 8);
    c2pool::messages::address_type addrs2(9, "10.11.12.13", 14);
    uint256 best_hash_test_answer;
    best_hash_test_answer.SetHex("0123");
    shared_ptr<message_version> answer_msg = make_shared<message_version>(ver, 0, addrs1, addrs2, test_nonce, test_sub_ver, 18, best_hash_test_answer);


    
}