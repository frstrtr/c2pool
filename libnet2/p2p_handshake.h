#pragma once

#include <memory>

#include "p2p_socket.h"
#include "p2p_protocol.h"
#include "p2p_messages.h"
#include "p2p_protocol_data.h"
#include <libp2p/handshake.h>
#include <libdevcore/logger.h>

#include <boost/asio.hpp>

class P2PHandshake : public Handshake<P2PProtocol>, public P2PProtocolData
{
protected:
    std::function<void(std::shared_ptr<P2PHandshake>, std::shared_ptr<net::messages::message_version>)> handle_message_version;
public:

    P2PHandshake(auto socket, std::function<void(std::shared_ptr<P2PHandshake>,
                                                 std::shared_ptr<net::messages::message_version>)> _handler)
            : Handshake(socket), P2PProtocolData(3301), handle_message_version(std::move(_handler))
    {

    }
};

class P2PHandshakeServer : public enable_shared_from_this<P2PHandshakeServer>, public P2PHandshake
{
    std::function<void(std::shared_ptr<P2PHandshakeServer>)> handshake_finish;
public:
	P2PHandshakeServer(auto _socket, auto version_handle, auto _finish) : P2PHandshake(_socket, std::move(version_handle)), handshake_finish(std::move(_finish))
	{

	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{
        try
        {
            if (raw_msg->command != "version")
                throw std::runtime_error("msg != version"); //TODO: ERROR CODE FOR CONSOLE

            auto msg = std::make_shared<net::messages::message_version>();
            raw_msg->value >> *msg;

            handle_message_version(this->shared_from_this(), msg);
        } catch (const std::error_code &ec)
        {
            // TODO: disconnect
        }
	}
};

class P2PHandshakeClient : public enable_shared_from_this<P2PHandshakeClient>, public P2PHandshake
{
    std::function<void(std::shared_ptr<P2PHandshakeClient>)> handshake_finish;
public:
	P2PHandshakeClient(auto _socket, auto version_handle, auto _finish) : P2PHandshake(_socket, version_handle), handshake_finish(std::move(_finish))
	{

	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{
        try
        {
            if (raw_msg->command != "version")
                throw std::runtime_error("msg != version"); //TODO: ERROR CODE FOR CONSOLE

            auto msg = std::make_shared<net::messages::message_version>();
            raw_msg->value >> *msg;

            handle_message_version(this->shared_from_this(), msg);
        } catch (const std::error_code &ec)
        {
            // TODO: disconnect
        }
	}
};