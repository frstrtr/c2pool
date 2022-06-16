#include <gtest/gtest.h>
#include <libnet2/pool_messages.h>

// TODO: tests for all messages

TEST(pool_messages, message_version)
{
    int ver = 3301;
    std::string test_sub_ver = "16";
    unsigned long long test_nonce = 6535423;
    address_type addrs1(3, "4.5.6.7", 8);
    address_type addrs2(9, "10.11.12.13", 14);
    uint256 best_hash_test_answer;
    best_hash_test_answer.SetHex("0123");
    shared_ptr <pool::messages::message_version> msg = make_shared<pool::messages::message_version>(ver, 0, addrs1, addrs2, test_nonce,
                                                                           test_sub_ver, 18, best_hash_test_answer);

    ASSERT_EQ(ver, msg->version.get());
    ASSERT_EQ(0, msg->services.get());
    ASSERT_EQ(addrs1, msg->addr_to.get());
    ASSERT_EQ(addrs2, msg->addr_from.get());
    ASSERT_EQ(test_nonce, msg->nonce.get());
    ASSERT_EQ(test_sub_ver, msg->sub_version.get());
    ASSERT_EQ(18, msg->mode.get());
    ASSERT_EQ(best_hash_test_answer, msg->best_share_hash.get());
}