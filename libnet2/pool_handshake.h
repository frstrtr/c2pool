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
    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, std::shared_ptr<PoolHandshake>)> msg_version_handler_type;

    msg_version_handler_type handle_message_version;
	void send_version()
	{
		address_type addrs1(3, "192.168.10.10", 8);
		address_type addrs2(9, "192.168.10.11", 9999);

		uint256 best_hash_test_answer;
        best_hash_test_answer.SetNull();
//		best_hash_test_answer.SetHex("06abb7263fc73665f1f5b129959d90419fea5b1fdbea6216e8847bcc286c14e9");
//            auto msg = make_message<message_version>(version, 0, addrs1, addrs2, _p2p_node->get_nonce(), "c2pool-test", 1, best_hash_test_answer);
		auto msg = make_shared<pool::messages::message_version>(version, 0, addrs1, addrs2, 254, "c2pool-test", 1,
																best_hash_test_answer);
		socket->write(msg);
	}

public:
    PoolHandshake(auto socket, msg_version_handler_type _handler)
            : Handshake(socket), PoolProtocolData(3501, c2pool::deferred::QueryDeferrer<std::vector<ShareType>, std::vector<uint256>, uint64_t, std::vector<uint256>>(
                    [_socket = socket](uint256 _id, std::vector<uint256> _hashes, unsigned long long _parents, std::vector<uint256> _stops)
                    {
                        LOG_DEBUG_POOL << "ID: " << _id.GetHex();
                        LOG_DEBUG_POOL << "Hashes: " << _hashes;
                        LOG_DEBUG_POOL << "Parents: " << _parents;
                        LOG_DEBUG_POOL << "Stops: " << _stops;

                        LOG_DEBUG_POOL << "get_shares called!";
//                        auto msg = std::make_shared<pool::messages::message_sharereq>(_id, _hashes, 10 /*_parents*/, _stops);
                        auto msg = std::make_shared<pool::messages::message_sharereq>(_id, _hashes, _parents, _stops);
                        _socket->write(msg);
                    }, 15, [_socket = socket](std::string msg){_socket->disconnect((boost::format("Timeout get_shares: %1%") % msg).str());})), handle_message_version(std::move(_handler))
    { }
};

class PoolHandshakeServer : public enable_shared_from_this<PoolHandshakeServer>, public PoolHandshake
{
    std::function<void(std::shared_ptr<PoolHandshakeServer>)> handshake_finish;
public:
	PoolHandshakeServer(auto _socket, msg_version_handler_type version_handle, auto _finish) : PoolHandshake(_socket, std::move(version_handle)), handshake_finish(std::move(_finish))
	{

	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{
        LOG_DEBUG_POOL << "Pool handshake server handle message: " << raw_msg->command;
		try
		{
			if (raw_msg->command != "version")
				throw std::runtime_error("msg != version");

			auto msg = std::make_shared<pool::messages::message_version>();
			raw_msg->value >> *msg;

			// Если внутри handle_message_version нет никаких ошибок, throw, то вызывается handshake_finish();
			handle_message_version(msg, this->shared_from_this());
		} catch (const std::runtime_error &ec)
		{
            std::string reason = "[PoolHandshakeServer] handle_message error = " + std::string(ec.what());
            disconnect(reason);
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
	PoolHandshakeClient(auto _socket, msg_version_handler_type version_handle, auto _finish) : PoolHandshake(_socket, version_handle), handshake_finish(std::move(_finish))
	{
		send_version();
	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{
        LOG_DEBUG_POOL << "Pool handshake client handle message: " << raw_msg->command;
        try
        {
            if (raw_msg->command != "version")
                throw std::runtime_error("msg != version");

            auto msg = std::make_shared<pool::messages::message_version>();
            raw_msg->value >> *msg;

			// Если внутри handle_message_version нет никаких ошибок, throw, то вызывается handshake_finish();
            handle_message_version(msg, this->shared_from_this());
        } catch (const std::runtime_error &ec)
        {
            std::string reason = "[PoolHandshakeClient] handle_message error = " + std::string(ec.what());
            disconnect(reason);
        }
		handshake_finish(this->shared_from_this());
	}
};