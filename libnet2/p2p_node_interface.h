#pragma once

#include <memory>
#include <functional>
#include <tuple>

#include "p2p_socket.h"
#include <networks/network.h>
#include <libp2p/node.h>
#include <libp2p/socket.h>
#include <libdevcore/logger.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

class P2PListener : public Listener
{
private:
	std::shared_ptr<io::io_context> context;
	std::shared_ptr<c2pool::Network> net;

	ip::tcp::acceptor acceptor;
public:
	P2PListener(auto _context, auto _net) : context(std::move(_context)), net(std::move(_net)), acceptor(*context)
	{

	}

	void operator()(std::function<void(std::shared_ptr<Socket>)> socket_handle, std::function<void()> finish) override
	{
		acceptor.async_accept([this, handle = std::move(socket_handle), finish=std::move(finish)](boost::system::error_code ec, ip::tcp::socket _socket)
							  {
								  if (!ec)
								  {
									  auto socket = std::make_shared<P2PSocket>(std::move(_socket), net);
									  handle(std::move(socket));
								  }
								  else
								  {
									  LOG_ERROR << "P2PNode::listen: " << ec.message();
								  }
								  finish();
							  });
	}

};

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
								   ip::tcp::socket _socket(*context);
								   auto socket = std::make_shared<P2PSocket>(
										   std::move(_socket), net
								   );

								   boost::asio::async_connect(_socket, endpoints,
															  [&, handler = _handler](const boost::system::error_code &ec,
																  boost::asio::ip::tcp::endpoint ep)
															  {
																  LOG_INFO << "Connect to " << ep.address() << ":"
																		   << ep.port();
																  if (!ec)
																  {
																	  handler(socket);
//																	  std::shared_ptr<Protocol> proto = std::make_shared<P2PProtocol>(
//																			  socket, handler_manager);
//																	  client_connected(proto);
																  } else
																  {
																	  LOG_ERROR << "async_connect: " << ec << " "
																				<< ec.message();
																  }
															  });

//								   auto handshake = std::make_shared<P2PHandshakeClient>(
//										   socket, data->handler_manager);
//								   handshake->connect(endpoints, std::bind(
//										   &P2PNodeClient::client_connected, this,
//										   std::placeholders::_1));
//								   client_attempts[_ip] = std::move(handshake);
							   });
	}
};