#pragma once

#include <memory>
#include <functional>
#include <tuple>

//#include "p2p_socket.h"
#include <networks/network.h>
#include <libp2p/node.h>
#include <libp2p/socket.h>
#include <libdevcore/logger.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

template <typename SocketType>
class P2PListener : public Listener
{
private:
	std::shared_ptr<io::io_context> context;
	std::shared_ptr<c2pool::Network> net;

	ip::tcp::acceptor acceptor;
public:
	P2PListener(auto _context, auto _net, auto port) : context(std::move(_context)), net(std::move(_net)), acceptor(*context)
	{
		ip::tcp::endpoint listen_ep(ip::tcp::v4(), port);

		acceptor.open(listen_ep.protocol());
		acceptor.set_option(io::socket_base::reuse_address(true));
		acceptor.bind(listen_ep);
		acceptor.listen();

		LOG_INFO << "PoolNode Listener started for port: " << listen_ep.port();
	}

	void operator()(std::function<void(std::shared_ptr<Socket>)> socket_handle, std::function<void()> finish) override
	{
		acceptor.async_accept([this, handle = std::move(socket_handle), finish=std::move(finish)](boost::system::error_code ec, ip::tcp::socket _socket)
							  {
								  if (!ec)
								  {
									  auto boost_socket = std::make_shared<ip::tcp::socket>(std::move(_socket));
									  auto socket = std::make_shared<SocketType>(
											  boost_socket, net
									  );
									  handle(socket);
									  socket->read();
								  }
								  else
								  {
									  LOG_ERROR << "P2P Listener: " << ec.message();
								  }
								  finish();
							  });
	}

};

template <typename SocketType>
class P2PConnector : public Connector
{
private:
	std::shared_ptr<io::io_context> context;
	std::shared_ptr<c2pool::Network> net;

	ip::tcp::resolver resolver;

public:
	P2PConnector(auto _context, auto _net) : context(std::move(_context)), net(std::move(_net)), resolver(*context)
	{
	}

	void operator()(std::function<void(std::shared_ptr<Socket>)> socket_handle,
					std::tuple<std::string, std::string> _addr) override
	{
		auto [ip, port] = _addr;
		resolver.async_resolve(ip, port,
							   [&, _ip = ip, _port = port, _handler = socket_handle](
									   const boost::system::error_code &er,
									   const boost::asio::ip::tcp::resolver::results_type endpoints)
							   {
									if (er) {
										LOG_WARNING << "P2PConnector[resolve]: " << er.message();
									}
								   std::shared_ptr<ip::tcp::socket> _socket = std::make_shared<ip::tcp::socket>(*context);
								   auto socket = std::make_shared<SocketType>(
										   _socket, net
								   );


								   boost::asio::async_connect(*_socket, endpoints,
															  [sock = std::move(socket), handler = _handler](
																	  const boost::system::error_code &ec,
																	  boost::asio::ip::tcp::endpoint ep)
															  {
																  LOG_INFO << "Connect to " << ep.address() << ":"
																		   << ep.port();
																  if (!ec)
																  {
																	  handler(sock);
																	  sock->read();
																  } else
																  {
																	  LOG_ERROR << "async_connect: " << ec << " "
																				<< ec.message();
																  }
															  });
							   });
	}
};