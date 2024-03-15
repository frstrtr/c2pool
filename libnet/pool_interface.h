#pragma once

#include <vector>

#include <networks/network.h>
#include <libdevcore/logger.h>

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
	PoolListener(auto context_, auto net_, auto port) 
		: context(context_), net(net_), acceptor(*context), listen_ep(ip::tcp::v4(), port) 
	{
	}

	void run() override
	{
		acceptor.open(listen_ep.protocol());
		acceptor.set_option(io::socket_base::reuse_address(true));
		acceptor.bind(listen_ep);
		acceptor.listen();

		async_loop();
		LOG_INFO << "\t\t PoolListener started for port: " << listen_ep.port();
	}

	void stop() override
	{
		// stop boost::asio::acceptor
		acceptor.cancel();
		acceptor.close();
	}

protected:
	void async_loop() override
	{
		acceptor.async_accept(
			[&]
			(boost::system::error_code ec, ip::tcp::socket socket_)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						error(libp2p::ASIO_ERROR, "PoolListener::async_loop: " + ec.message(), NetAddress{socket_.remote_endpoint()});
					else
						LOG_DEBUG_POOL << "PoolListener::async_loop canceled";
					return;
				}

				auto tcp_socket = std::make_shared<ip::tcp::socket>(std::move(socket_));
				auto socket = new PoolSocket(tcp_socket, net, connection_type::incoming, [&](const libp2p::error& err){ error_handler(err); });
				socket->init_addr();
				socket_handler(socket);
				
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

	void connect_socket(boost::asio::ip::tcp::resolver::results_type endpoints)
	{
		auto tcp_socket = std::make_shared<ip::tcp::socket>(*context);
        auto socket = new PoolSocket(tcp_socket, net, connection_type::outgoing, [&](const libp2p::error& err){ error_handler(err); });

        boost::asio::async_connect(*tcp_socket, endpoints,
            [&, socket = std::move(socket), copy_endpoints = endpoints]
			(const boost::system::error_code &ec, const boost::asio::ip::tcp::endpoint &ep)
            {
				if (ec)
				{
					delete socket;
					if (ec != boost::system::errc::operation_canceled)
						error(libp2p::ASIO_ERROR, "PoolConnector::connect_socket: " + ec.message(), NetAddress(*copy_endpoints));
					else
						LOG_DEBUG_POOL << "PoolConnector::connect_socket canceled";
					return;
				}

				socket->init_addr();
				LOG_INFO << "PoolConnector.Socket try handshake with " << ep.address() << ":" << ep.port();
                socket_handler(socket);
            }
		);
	}

public:
	PoolConnector(auto context_, auto net_) 
		: context(context_), net(net_), resolver(*context)
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
		LOG_DEBUG_POOL << "PoolConnector try to resolve " << addr_.to_string();
		resolver.async_resolve(addr_.ip, addr_.port,
			[&, address = addr_]
			(const boost::system::error_code& ec, boost::asio::ip::tcp::resolver::results_type endpoints)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						error(libp2p::ASIO_ERROR, "PoolConnector::try_connect: " + ec.message(), address);
					else
						LOG_DEBUG_POOL << "PoolConnector::try_connect canceled";
					return;
				}

				connect_socket(endpoints);
			}
		);
	}
};