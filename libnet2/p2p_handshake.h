#pragma once

#include <memory>

#include "p2p_socket.h"
#include "p2p_protocol.h"
#include <libp2p/handshake.h>
#include <libdevcore/logger.h>

#include <boost/asio.hpp>

class P2PHandshakeServer : public Handshake
{
	P2PHandshakeServer(auto _socket, std::function<void(std::shared_ptr<Protocol>)> _handle) : Handshake(_socket, std::move(_handle))
	{

	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{

	}
};

class P2PHandshakeClient : public Handshake
{
	P2PHandshakeClient(auto _socket, std::function<void(std::shared_ptr<Protocol>)> _handle) : Handshake(_socket, std::move(_handle))
	{

	}

	void handle_message(std::shared_ptr<RawMessage> raw_msg) override
	{

	}
};

//
//class P2PHandshake : public Handshake<P2PSocket, boost::asio::ip::tcp::resolver::results_type>
//{
//private:
//
//public:
//    P2PHandshake(std::shared_ptr<P2PSocket> _socket, HandlerManagerPtr _handler_manager) : Handshake(_socket, _handler_manager)
//    {
//    }
//
//    /// [Client] Try to connect
//    virtual void connect(endpoint_type endpoint, std::function<void(std::shared_ptr<Protocol>)> handler) override
//    {
//        // TODO: write message_version
//
//        client_connected = handler;
//        boost::asio::async_connect(socket->get_fundamental_socket(), endpoint, [&](const boost::system::error_code &ec, boost::asio::ip::tcp::endpoint ep){
//            LOG_INFO << "Connect to " << ep.address() << ":" << ep.port();
//            if (!ec)
//            {
//                std::shared_ptr<Protocol> proto = std::make_shared<P2PProtocol>(socket, handler_manager);
//                client_connected(proto);
//            }
//            else
//            {
//                LOG_ERROR << "async_connect: " << ec << " " << ec.message();
//            }
//        });
//    }
//
//    /// [Server] Try to resolve connection
//    virtual void listen_connection(std::function<void(std::shared_ptr<Protocol>)> handler) override
//    {
//        // TODO: read message_version
//        server_connected = handler;
//
//        std::shared_ptr<Protocol> proto = std::make_shared<P2PProtocol>(socket, handler_manager);
//        server_connected(proto);
//
//    }
//
//    void handle_message(std::shared_ptr<RawMessage> raw_msg)
//    {
//        //TODO:
//    }
//};