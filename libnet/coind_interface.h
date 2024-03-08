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
	/*ConnectionStatus* status;*/

	ip::tcp::resolver resolver;

    void connect_socket(boost::asio::ip::tcp::resolver::results_type endpoints)
	{
		auto tcp_socket = std::make_shared<ip::tcp::socket>(*context);
		auto socket = new CoindSocket(tcp_socket, net, connection_type::outgoing, [&](const libp2p::error& err){ error_handler(err); });

		boost::asio::async_connect(*tcp_socket, endpoints,
			[&, socket = std::move(socket)]
			(const boost::system::error_code &ec, boost::asio::ip::tcp::endpoint ep)
			{
				// if (!status->is_available())
				// {
				// 	return;
				// }
				if (ec)
				{
					delete socket;
					if (ec != boost::system::errc::operation_canceled)
						error(libp2p::ASIO_ERROR, "CoindConnector::connect_socket: " + ec.message(), NetAddress{ep});
					else
						LOG_DEBUG_COIND << "CoindConnector::connect_socket canceled";
					return;
				}
				
				LOG_INFO << "CoindConnector.Socket try handshake with " << ep.address() << ":" << ep.port();
				socket->init_addr();
				socket_handler(socket);
				
			}
		);
	}

public:
	CoindConnector(auto context_, auto net_/*, ConnectionStatus* status_*/) 
        : context(context_), net(net_), /*status(status_),*/ resolver(*context)
    {
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
        LOG_DEBUG_COIND << "CoindConnector try to resolve " << addr_.to_string();
		resolver.async_resolve(addr_.ip, addr_.port,
			[&, address = addr_]
			(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::results_type endpoints)
			{
				// if (!status->is_available())
				// 	return;

				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						error(libp2p::ASIO_ERROR, "CoindConnector::try_connect: " + ec.message(), address);
					else
						LOG_DEBUG_COIND << "CoindConnector::try_connect canceled";
					return;
				}

				connect_socket(endpoints);
			}
		);
	}
};