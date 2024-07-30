#pragma once
#include <boost/asio.hpp>

#include <core/log.hpp>
#include <core/socket.hpp>
#include <core/addr_store.hpp>
#include <core/node_interface.hpp>

namespace pool
{
struct INetwork
{
    virtual void connected(std::shared_ptr<core::Socket> socket) = 0;
    virtual void disconnect() = 0;
};

class Factory
{
protected:
	boost::asio::io_context* m_context;
	
private:
	INetwork* m_node;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::asio::ip::tcp::acceptor m_acceptor;
	
	core::AddrStore m_addrs;

private:
    void listen()
    {
        m_acceptor.async_accept(
			[this](boost::system::error_code ec, boost::asio::ip::tcp::socket io_socket)
			{
				if (ec)
				{
					LOG_ERROR << "listen error: " << ec.what();
					return;
					// if (ec != boost::system::errc::operation_canceled)
					// 	error(libp2p::ASIO_ERROR, "PoolListener::async_loop: " + ec.message(), NetAddress{socket_.remote_endpoint()});
					// else
					// 	LOG_DEBUG_POOL << "PoolListener::async_loop canceled";
					// return;
				}

				auto tcp_socket = std::make_unique<boost::asio::ip::tcp::socket>(std::move(io_socket));
				auto communicator = dynamic_cast<core::ICommunicator*>(m_node);
				assert(communicator && "INetwork can't be cast to ICommunicator!");
				
				auto socket = std::make_shared<core::Socket>(std::move(tcp_socket), core::connection_type::incoming, communicator);
				socket->init();
				
				m_node->connected(socket);
				
				// continue accept connections
				listen();
			}
		);
    }

public:
    Factory(boost::asio::io_context* context, std::string coin_name, INetwork* node) : m_context(context), m_addrs(coin_name), m_node(node), m_resolver(*m_context), m_acceptor(*m_context)
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

	void got_addr(NetService addr, uint64_t services, uint64_t timestamp);
	std::vector<core::AddrStorePair> get_good_peers(size_t max_count);
};

} // namespace pool
