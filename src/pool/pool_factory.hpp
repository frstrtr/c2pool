#pragma once
#include <boost/asio.hpp>

namespace c2pool
{

namespace pool
{
    
class Factory
{
private:
    boost::asio::io_context* m_context;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::asio::ip::tcp::acceptor m_acceptor;


private:

    void listen()
    {
        m_acceptor.async_accept(
			[&]
			(boost::system::error_code ec, boost::asio::ip::tcp::socket io_socket)
			{
				if (ec)
				{
					// if (ec != boost::system::errc::operation_canceled)
					// 	error(libp2p::ASIO_ERROR, "PoolListener::async_loop: " + ec.message(), NetAddress{socket_.remote_endpoint()});
					// else
					// 	LOG_DEBUG_POOL << "PoolListener::async_loop canceled";
					// return;
				}

				auto tcp_socket = std::make_shared<boost::asio::ip::tcp::socket>(std::move(io_socket));
				auto socket = std::make_shared<PoolSocket>(tcp_socket, net, connection_type::incoming, [&](const libp2p::error& err){ error_handler(err); });
				socket->init_addr();
				socket_handler(socket);
				
				// continue accept connections
				listen();
			}
		);
    }

public:
    Factory(boost::asio::io_context* context) : m_context(context), m_resolver(*m_context), m_acceptor(*m_context)
    {
        
    }

    void run(auto listen_port)
    {
        boost::asio::ip::tcp::endpoint listen_ep(boost::asio::ip::tcp::v4(), listen_port);

        m_acceptor.open(listen_ep.protocol());
		m_acceptor.set_option(io::socket_base::reuse_address(true));
		m_acceptor.bind(listen_ep);
		m_acceptor.listen();

		async_loop();
		LOG_INFO << "\t\t PoolListener started for port: " << listen_ep.port();
    }
};

} // namespace pool

} // namespace c2pool
