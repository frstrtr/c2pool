#pragma once

#include <memory>
#include <functional>
#include <tuple>

#include <networks/network.h>
#include <libp2p/net_supervisor.h>
#include <libp2p/node.h>
#include <libp2p/socket.h>
#include <libdevcore/logger.h>
#include <libdevcore/exceptions.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

class CoindConnector : public Connector<BaseCoindSocket>
{
private:
	io::io_context* context;
	coind::ParentNetwork* net;
	ConnectionStatus* status;

	ip::tcp::resolver resolver;

public:
	CoindConnector(auto context_, auto net_, ConnectionStatus* status_) 
        : context(context_), net(net_), status(status_), resolver(*context) {}

	void connect_socket(boost::asio::ip::tcp::resolver::results_type endpoints)
	{
		auto tcp_socket = std::make_shared<ip::tcp::socket>(*context);
		auto socket = new CoindSocket(tcp_socket, net, connection_type::outgoing, [&](const libp2p::error& err){ error_handler(err); });

		boost::asio::async_connect(*tcp_socket, endpoints,
			[&, socket = std::move(socket)]
			(const boost::system::error_code &ec, boost::asio::ip::tcp::endpoint ep)
			{
				if (!status->is_available())
				{
					return;
				}
				
				LOG_INFO << "CoindConnector.Socket try handshake with " << ep.address() << ":" << ep.port();
				if (!ec)
				{
					socket_handler(socket);
				} else
				{
					LOG_ERROR << "async_connect: " << ec;
					delete socket;
				}
			}
		);
	}
    
    void run() override
    {

    }

	void stop() override
	{
		resolver.cancel();
	}

	void try_connect(const NetAddress& addr_) override
	{
		resolver.async_resolve(addr_.ip, addr_.port,
			[&, address = addr_]
			(const boost::system::error_code &er, boost::asio::ip::tcp::resolver::results_type endpoints)
			{
				if (!status->is_available())
					return;

				if (er)
				{
					LOG_WARNING << "P2PConnector[resolve](" << address.to_string() << "): " << er.message();
					return;
				}
				connect_socket(endpoints);
			}
		);
	}
};