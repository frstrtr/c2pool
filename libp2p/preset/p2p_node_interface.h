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

template <typename SocketType>
class CoindConnector : public Connector
{
private:
	io::io_context* context;
	coind::ParentNetwork* net;
	ConnectionStatus* status;

	ip::tcp::resolver resolver;

public:
	CoindConnector(auto _context, auto _net, ConnectionStatus* _status) : context(_context), net(_net), status(_status), resolver(*context) {}

	void connect_socket(boost::asio::ip::tcp::resolver::results_type endpoints)
	{
		auto tcp_socket = std::make_shared<ip::tcp::socket>(*context);
		auto socket = new SocketType(tcp_socket, net);

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

	void stop() override
	{
		resolver.cancel();
	}

	void try_connecct(NetAddress address) override
	{
		resolver.async_resolve(address.ip, address.port,
			[&, address = address]
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