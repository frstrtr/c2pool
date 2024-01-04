#include <iostream>
#include <utility>

#include <gtest/gtest.h>

#include <libnet/pool_handshake.h>
#include <libp2p/socket.h>

class VirtualSocket : public Socket
{
public:
    VirtualSocket() : Socket() { }
public:
    void write(std::shared_ptr<Message> msg) override
    {
        std::cout << "try to write msg" << std::endl;
    }

    void read() override
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


        PackStream stream_msg;
        stream_msg << *msg;

        shared_ptr<RawMessage> raw_msg = std::make_shared<RawMessage>(msg->command);
        stream_msg >> *raw_msg;

        handler(std::move(raw_msg));
    }

    bool isConnected() override
    {
        return true;
    }

    void disconnect() override
    {
        std::cout << "is disconnect" << std::endl;
    }

    tuple<std::string, std::string> get_addr() override
    {
        return std::tie("192.168.0.0", "1000");
    }
};

class TestPoolHandshake : public ::testing::Test
{
protected:
    std::shared_ptr<VirtualSocket> socket;
protected:
    void SetUp()
    {
        socket = std::make_shared<VirtualSocket>();
    }

    void TearDown()
    {

    }
};


TEST_F(TestPoolHandshake, handshake_client_virtual_socket)
{
    std::shared_ptr<PoolHandshakeClient> handshake = std::make_shared<PoolHandshakeClient>(
            socket,
            [&](std::shared_ptr<PoolHandshake> handshake, std::shared_ptr<pool::messages::message_version> msg)
            {
                std::cout << "HANDLED MESSAGE VERSION: " << std::endl;
                std::cout << "ip addr_to: " << msg->addr_to.get().address << std::endl;

                int ver = 3301;
                std::string test_sub_ver = "16";
                unsigned long long test_nonce = 6535423;
                address_type addrs1(3, "4.5.6.7", 8);
                address_type addrs2(9, "10.11.12.13", 14);
                uint256 best_hash_test_answer;
                best_hash_test_answer.SetHex("0123");

                ASSERT_EQ(ver, msg->version.get());
                ASSERT_EQ(0, msg->services.get());
                ASSERT_EQ(addrs1, msg->addr_to.get());
                ASSERT_EQ(addrs2, msg->addr_from.get());
                ASSERT_EQ(test_nonce, msg->nonce.get());
                ASSERT_EQ(test_sub_ver, msg->sub_version.get());
                ASSERT_EQ(18, msg->mode.get());
                ASSERT_EQ(best_hash_test_answer, msg->best_share_hash.get());
            },
            [&](std::shared_ptr<PoolHandshakeClient> handshake)
            {

            }
    );

    socket->set_message_handler([&](std::shared_ptr<RawMessage> raw_msg) {
        std::cout << raw_msg->value.size() << std::endl;
        handshake->handle_message(std::move(raw_msg));
    });

    socket->read();
}