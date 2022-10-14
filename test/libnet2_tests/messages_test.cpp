#include <gtest/gtest.h>
#include <libnet2/pool_messages.h>
#include <libdevcore/types.h>
#include <libcoind/p2p/coind_messages.h>

// TODO: tests for all messages

TEST(pool_messages, message_version)
{
    int ver = 3301;
    std::string test_sub_ver = "16";
    unsigned long long test_nonce = 6535423;
    address_type addrs1(3, "4.5.6.7", 8);
    address_type addrs2(9, "10.11.12.13", 14);
    uint256 best_hash_test_answer;
    best_hash_test_answer.SetHex("0");
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

TEST(coind_messages, message_inv)
{
    auto hash = uint256S("ebf5da4870d068e0fb6dab7d84f239537506bf313dd8d98bbc64a3758f8022a2");
    inventory inv(inventory_type::tx, hash);

    std::vector<inventory> inv_vec = {inv};
    auto msg_getdata = std::make_shared<coind::messages::message_getdata>(inv_vec);
    for (auto inv_stream : msg_getdata->requests.get())
    {
        std::cout << inv_stream.hash.get().GetHex() << std::endl;
        std::cout << inv_stream.type.get() << std::endl;
    }

    PackStream stream;
    stream << msg_getdata->requests;
    for (auto v : stream.data)
    {
        std::cout << (unsigned int) v << " ";
    }
    std::cout << std::endl;
}