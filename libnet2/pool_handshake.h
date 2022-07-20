#pragma once

#include <memory>

#include "pool_socket.h"
#include "pool_protocol.h"
#include "pool_messages.h"
#include "pool_protocol_data.h"
#include <libp2p/handshake.h>
#include <libdevcore/logger.h>
#include <libdevcore/types.h>

#include <boost/asio.hpp>

class PoolHandshake : public Handshake<PoolProtocol>, public PoolProtocolData
{
protected:
    std::function<void(std::shared_ptr<PoolHandshake>, std::shared_ptr<pool::messages::message_version>)> handle_message_version;

	void send_version()
	{
		address_type addrs1(3, "192.168.10.10", 8);
		address_type addrs2(9, "192.168.10.11", 9999);

		uint256 best_hash_test_answer;
		best_hash_test_answer.SetHex("06abb7263fc73665f1f5b129959d90419fea5b1fdbea6216e8847bcc286c14e9");
//            auto msg = make_message<message_version>(version, 0, addrs1, addrs2, _p2p_node->get_nonce(), "c2pool-test", 1, best_hash_test_answer);
		auto msg = make_shared<pool::messages::message_version>(version, 0, addrs1, addrs2, 254, "c2pool-test", 1,
																best_hash_test_answer);
		socket->write(msg);
	}

public:
    PoolHandshake(auto socket, std::function<void(std::shared_ptr<PoolHandshake>,
                                                  std::shared_ptr<pool::messages::message_version>)> _handler)
            : Handshake(socket), PoolProtocolData(3301), handle_message_version(std::move(_handler))
    {

    }
};

class PoolHandshakeServer : public enable_shared_from_this<PoolHandshakeServer>, public PoolHandshake
{
    std::function<void(std::shared_ptr<PoolHandshakeServer>)> handshake_finish;
public:
	PoolHandshakeServer(auto _socket, auto version_handle, auto _finish) : PoolHandshake(_socket, std::move(version_handle)), handshake_finish(std::move(_finish))
	{

	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{
		LOG_DEBUG << "Pool handshake client handle message: " << raw_msg->command;
		try
		{
			if (raw_msg->command != "version")
				throw std::runtime_error("msg != version"); //TODO: ERROR CODE FOR CONSOLE

			auto msg = std::make_shared<pool::messages::message_version>();
			raw_msg->value >> *msg;

			// Если внутри handle_message_version нет никаких ошибок, throw, то вызывается handshake_finish();
			handle_message_version(this->shared_from_this(), msg);
		} catch (const std::error_code &ec)
		{
			// TODO: disconnect
			return;
		}
		send_version();
		handshake_finish(this->shared_from_this());
	}
};

class PoolHandshakeClient : public enable_shared_from_this<PoolHandshakeClient>, public PoolHandshake
{
    std::function<void(std::shared_ptr<PoolHandshakeClient>)> handshake_finish;
public:
	PoolHandshakeClient(auto _socket, auto version_handle, auto _finish) : PoolHandshake(_socket, version_handle), handshake_finish(std::move(_finish))
	{
		send_version();
	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{
		LOG_DEBUG << "Pool handshake client handle message: " << raw_msg->command;
        try
        {
            if (raw_msg->command != "version")
                throw std::runtime_error("msg != version"); //TODO: ERROR CODE FOR CONSOLE

            auto msg = std::make_shared<pool::messages::message_version>();
            raw_msg->value >> *msg;

			// Если внутри handle_message_version нет никаких ошибок, throw, то вызывается handshake_finish();
            handle_message_version(this->shared_from_this(), msg);
        } catch (const std::error_code &ec)
        {
            // TODO: disconnect
        }
		handshake_finish(this->shared_from_this());
	}
};