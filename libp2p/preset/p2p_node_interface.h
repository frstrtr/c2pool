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
	io::io_context* context;
	c2pool::Network* net;

	ip::tcp::acceptor acceptor;
public:
	P2PListener(auto _context, auto _net, auto port) : context(_context), net(_net), acceptor(*context)
	{
		ip::tcp::endpoint listen_ep(ip::tcp::v4(), port);

		acceptor.open(listen_ep.protocol());
		acceptor.set_option(io::socket_base::reuse_address(true));
		acceptor.bind(listen_ep);
		acceptor.listen();

		LOG_INFO << "PoolNode Listener started for port: " << listen_ep.port();
	}

	void tick() override
	{
		acceptor.async_accept([this, handle = socket_handler, finish=finish_handler](boost::system::error_code ec, ip::tcp::socket _socket)
							  {
								  if (!ec)
								  {
									  auto tcp_socket = std::make_shared<ip::tcp::socket>(std::move(_socket));
									  auto socket = new SocketType(tcp_socket, net, connection_type::incoming);
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
	io::io_context* context;
	c2pool::Network* net;

	ip::tcp::resolver resolver;

public:
	P2PConnector(auto _context, auto _net) : context(_context), net(_net), resolver(*context)
	{
	}

	void tick(NetAddress addr) override
	{
        LOG_DEBUG_P2P << "P2PConnector try to resolve " << addr.to_string();
		resolver.async_resolve(addr.ip, addr.port,
							   [&, _addr = addr, _handler = socket_handler](
									   const boost::system::error_code &er,
									   const boost::asio::ip::tcp::resolver::results_type endpoints)
                               {
                                   if (er)
                                       error_handler(_addr, "(resolver)" + er.message());

                                   auto tcp_socket = std::make_shared<ip::tcp::socket>(*context);
                                   auto socket = new SocketType(tcp_socket, net, connection_type::outgoing);

                                   boost::asio::async_connect(*tcp_socket, endpoints,
                                                              [_addr = _addr, sock = std::move(socket), handler = _handler, err_handler = error_handler](
                                                                      const boost::system::error_code &ec,
                                                                      const boost::asio::ip::tcp::endpoint &ep)
                                                              {
                                                                  LOG_INFO << "P2PConnector.Socket try handshake with "
                                                                           << ep.address() << ":"
                                                                           << ep.port();
                                                                  if (!ec)
                                                                  {
                                                                      handler(sock);
                                                                      sock->read();
                                                                  } else
                                                                  {
                                                                      err_handler(_addr, "(async_connect)" + ec.message());
                                                                  }
                                                              });
                               });
	}
};

template <typename SocketType>
class CoindConnector : public Connector
{
private:
	io::io_context* context;
	coind::ParentNetwork* net;

	ip::tcp::resolver resolver;

public:
	CoindConnector(auto _context, auto _net) : context(_context), net(_net), resolver(*context) {}

	void tick(NetAddress _addr) override
	{
		resolver.async_resolve(_addr.ip, _addr.port,
							   [&, address = _addr, _handler = socket_handler](
									   const boost::system::error_code &er,
									   const boost::asio::ip::tcp::resolver::results_type endpoints)
							   {
								   if (er)
                                   {
									   LOG_WARNING << "P2PConnector[resolve](" << address.to_string() << "): " << er.message();
									   return;
								   }
								   std::shared_ptr<ip::tcp::socket> _socket = std::make_shared<ip::tcp::socket>(*context);
								   auto socket = new SocketType(_socket, net);


								   boost::asio::async_connect(*_socket, endpoints,
															  [sock = std::move(socket), handler = _handler](
																	  const boost::system::error_code &ec,
																	  boost::asio::ip::tcp::endpoint ep)
															  {
                                                                  LOG_INFO << "CoindConnector.Socket try handshake with " << ep.address() << ":"
                                                                           << ep.port();
																  if (!ec)
																  {
																	  handler(sock);
																	  sock->read();
																  } else
																  {
																	  LOG_ERROR << "async_connect: " << ec;
																  }
															  });
							   });
	}
};