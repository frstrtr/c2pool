#pragma once

#include <memory>

#include "p2p_socket.h"
#include "p2p_protocol.h"
#include "p2p_messages.h"
#include <libp2p/handshake.h>
#include <libdevcore/logger.h>

#include <boost/asio.hpp>

void handle_message_version(std::shared_ptr<net::messages::message_version> msg)
{
    LOG_DEBUG << "handle message_version";
    LOG_INFO << "Peer " << msg->addr_from.address.get() << ":" << msg->addr_from.port.get()
             << " says protocol version is " << msg->version.get() << ", client version "
             << msg->sub_version.get();

    if (other_version != -1)
    {
        LOG_DEBUG << "more than one version message";
    }
    if (msg->version.get() < _net->MINIMUM_PROTOCOL_VERSION)
    {
        LOG_DEBUG << "peer too old";
    }

    other_version = msg->version.get();
    other_sub_version = msg->sub_version.get();
    other_services = msg->services.get();

    if (msg->nonce.get() == _p2p_node->get_nonce())
    {
        LOG_WARNING << "was connected to self";
        //TODO: assert
    }

    //detect duplicate in node->peers
    if (_p2p_node->get_peers().find(msg->nonce.get()) != _p2p_node->get_peers().end())
    {

    }
    if (_p2p_node->get_peers().count(msg->nonce.get()) != 0)
    {
        auto addr = _socket->get_addr();
        LOG_WARNING << "Detected duplicate connection, disconnecting from " << std::get<0>(addr) << ":"
                    << std::get<1>(addr);
        _socket->disconnect();
        return;
    }

    _nonce = msg->nonce.get();
    //TODO: После получения message_version, ожидание сообщения увеличивается с 10 секунд, до 100.
    //*Если сообщение не было получено в течении этого таймера, то происходит дисконект.

    _socket->ping_timer.expires_from_now(
            boost::asio::chrono::seconds((int) c2pool::random::Expovariate(1.0 / 100)));
    _socket->ping_timer.async_wait(boost::bind(&P2P_Protocol::ping_timer_func, this, _1));

    //TODO: if (p2p_node->advertise_ip):
    //TODO:     раз в random.expovariate(1/100*len(p2p_node->peers.size()+1), отправляется sendAdvertisement()

    //TODO: msg->best_share_hash != nullptr: p2p_node.handle_share_hashes(...)

    //TODO: <Методы для обработки транзакций>: send_have_tx; send_remember_tx
}

class P2PHandshakeServer : public Handshake<P2PProtocol>
{
public:
	P2PHandshakeServer(auto _socket, std::function<void(std::shared_ptr<protocol_type>)> _handle) : Handshake(_socket, std::move(_handle))
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

            handle_message_version(msg);
        } catch (const std::error_code &ec)
        {
            // TODO: disconnect
        }
	}
};

class P2PHandshakeClient : public Handshake<P2PProtocol>
{
public:
	P2PHandshakeClient(auto _socket, std::function<void(std::shared_ptr<protocol_type>)> _handle) : Handshake(_socket, std::move(_handle))
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

            handle_message_version(msg);
        } catch (const std::error_code &ec)
        {
            // TODO: disconnect
        }
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