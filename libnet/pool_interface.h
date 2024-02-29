#pragma once

#include <vector>

#include <networks/network.h>
#include <libdevcore/logger.h>
#include <libdevcore/exceptions.h>

#include <boost/asio.hpp>
namespace io = boost::asio;
namespace ip = io::ip;

class PoolListener : public Listener<BasePoolSocket>
{
private:
	io::io_context* context;
	c2pool::Network* net;

	ip::tcp::acceptor acceptor;
	ip::tcp::endpoint listen_ep;
public:
	PoolListener(auto _context, auto _net, auto port) 
		: context(_context), net(_net), acceptor(*context), listen_ep(ip::tcp::v4(), port) 
	{
	}

	void run() override
	{
		acceptor.open(listen_ep.protocol());
		acceptor.set_option(io::socket_base::reuse_address(true));
		acceptor.bind(listen_ep);
		acceptor.listen();

		async_loop();
		LOG_INFO << "PoolListener started for port: " << listen_ep.port();
	}

	void stop() override
	{
		acceptor.cancel();
	}

protected:
	void async_loop() override
	{
		acceptor.async_accept(
			[this, handle = socket_handler, finish=finish_handler]
			(boost::system::error_code ec, ip::tcp::socket socket_)
			{
				if (ec)
				{
					if (ec == boost::system::errc::operation_canceled)
					{
						LOG_DEBUG_POOL << "PoolListener canceled";
						return;
					} else 
					{
				 		throw make_except<pool_exception, NodeExcept>("[PoolListener] " + ec.message());
					}
				}

				auto tcp_socket = std::make_shared<ip::tcp::socket>(std::move(socket_));
				auto socket = new SocketType(tcp_socket, net, connection_type::incoming);
				handle(socket);
				
				// continue accept connections
				async_loop();
			}
		);
	}
};

class PoolConnector : public Connector<BasePoolSocket>
{
private:
	io::io_context* context;
	c2pool::Network* net;

	ip::tcp::resolver resolver;

public:
	PoolConnector(auto _context, auto _net) 
		: context(_context), net(_net), resolver(*context) {}

	void stop() override
	{
		resolver.cancel();
	}

	void try_connect(NetAddress addr) override
	{
        LOG_DEBUG_P2P << "P2PConnector try to resolve " << addr.to_string();
		resolver.async_resolve(addr.ip, addr.port,
							   [&, _addr = addr, _handler = socket_handler](
									   const boost::system::error_code &er,
									   const boost::asio::ip::tcp::resolver::results_type endpoints)
                               {
                                   if (er) 
								   {
										if (er != boost::system::errc::operation_canceled)
                                       		error_handler(_addr, "(resolver)" + er.message());
										return;
								   }

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