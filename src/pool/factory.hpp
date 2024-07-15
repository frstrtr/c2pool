#pragma once
#include <boost/asio.hpp>

#include <core/socket.hpp>
#include <core/node_interface.hpp>

namespace c2pool
{

namespace pool
{
    
struct INetwork
{
    virtual void connected(std::shared_ptr<Socket> socket) = 0;
    virtual void disconnect() = 0;
};

class Factory
{
private:
	INetwork* m_node;
    boost::asio::io_context* m_context;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::asio::ip::tcp::acceptor m_acceptor;

private:
    void listen()
    {
        m_acceptor.async_accept(
			[this](boost::system::error_code ec, boost::asio::ip::tcp::socket io_socket)
			{
				if (ec)
				{
					std::cout << "listen error: " << ec << " " << ec.message() << std::endl;
					// if (ec != boost::system::errc::operation_canceled)
					// 	error(libp2p::ASIO_ERROR, "PoolListener::async_loop: " + ec.message(), NetAddress{socket_.remote_endpoint()});
					// else
					// 	LOG_DEBUG_POOL << "PoolListener::async_loop canceled";
					// return;
				}

				auto tcp_socket = std::make_unique<boost::asio::ip::tcp::socket>(std::move(io_socket));
				auto communicator = dynamic_cast<ICommunicator*>(m_node);
				assert(communicator && "INetwork can't be cast to ICommunicator!");
				auto socket = std::make_shared<c2pool::Socket>(std::move(tcp_socket), connection_type::incoming, communicator);
				m_node->connected(socket);
				
				// continue accept connections
				listen();
			}
		);
    }

public:
    Factory(boost::asio::io_context* context, INetwork* node) : m_context(context), m_node(node), m_resolver(*m_context), m_acceptor(*m_context)
    {
        
    }

    void run(auto listen_port)
    {
        boost::asio::ip::tcp::endpoint listen_ep(boost::asio::ip::tcp::v4(), listen_port);

        m_acceptor.open(listen_ep.protocol());
		m_acceptor.set_option(boost::asio::socket_base::reuse_address(true));
		m_acceptor.bind(listen_ep);
		m_acceptor.listen();
		listen();

		LOG_INFO << "Factory started for port: " << listen_ep.port();
    }
};

} // namespace pool

} // namespace c2pool
