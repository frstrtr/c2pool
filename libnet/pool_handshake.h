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

typedef BaseHandshake<BasePoolSocket> BasePoolHandshake;

class PoolHandshake : public BasePoolHandshake, public PoolProtocolData
{
protected:
    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, PoolHandshake*)> msg_version_handler_type;

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
    PoolHandshake(auto socket, error_handler_type error_handler_, msg_version_handler_type handler_)
            : 	BasePoolHandshake(socket, error_handler_), 
				PoolProtocolData(3501, c2pool::deferred::QueryDeferrer<std::vector<ShareType>, std::vector<uint256>, uint64_t, std::vector<uint256>>(
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
                    }, 15, 
					[&](std::string msg)
					{
						error(libp2p::BAD_PEER, (boost::format("Timeout get_shares: %1%") % msg).str());
					})
				), 
				handle_message_version(std::move(handler_))
    { }
};

class PoolHandshakeServer : public PoolHandshake
{
    std::function<void(PoolHandshakeServer*)> handshake_finish;
public:
	PoolHandshakeServer(auto socket_, error_handler_type error_handler_, msg_version_handler_type version_handle_, auto finish_)
		: PoolHandshake(socket_, error_handler_, version_handle_), handshake_finish(std::move(finish_))
	{

	}

	void handle_raw(std::shared_ptr<RawMessage> raw_msg) override
	{
        LOG_DEBUG_POOL << "Pool handshake server handle message: " << raw_msg->command;
		if (raw_msg->command != "version")
			error(libp2p::BAD_PEER, "[PoolHandshakeServer] msg != version");
		try
		{
			auto msg = std::make_shared<pool::messages::message_version>();
			raw_msg->value >> *msg;

			// Если внутри handle_message_version нет никаких ошибок, throw, то вызывается handshake_finish();
			handle_message_version(msg, this);
		} catch (const std::runtime_error &ec)
		{
			error(libp2p::BAD_PEER, "[PoolHandshakeServer] handle_message error = " + std::string(ec.what()));
		}

		send_version();
		handshake_finish(this);
	}
};

class PoolHandshakeClient : public PoolHandshake
{
    std::function<void(PoolHandshakeClient*)> handshake_finish;
public:
	PoolHandshakeClient(auto socket_, error_handler_type error_handler_, msg_version_handler_type version_handle_, auto finish_)
		: PoolHandshake(socket_, error_handler_, version_handle_), handshake_finish(std::move(finish_))
	{
		send_version();
	}

	void handle_raw(std::shared_ptr<RawMessage> raw_msg) override
	{
        LOG_DEBUG_POOL << "Pool handshake client handle message: " << raw_msg->command;
        if (raw_msg->command != "version")
            error(libp2p::BAD_PEER, "[PoolHandshakeClient] msg != version");

        try
        {
            auto msg = std::make_shared<pool::messages::message_version>();
            raw_msg->value >> *msg;

			// Если внутри handle_message_version нет никаких ошибок, throw, то вызывается handshake_finish();
            handle_message_version(msg, this);
        } catch (const std::runtime_error &ec)
        {
			error(libp2p::BAD_PEER, "[PoolHandshakeClient] handle_message error = " + std::string(ec.what()));
        }
		handshake_finish(this);
	}
};