#pragma once
#include <boost/asio.hpp>

#include <core/log.hpp>
#include <core/socket.hpp>
#include <core/addr_store.hpp>
#include <core/node_interface.hpp>

namespace io = boost::asio;

namespace pool
{
struct INetwork
{
    virtual void connected(std::shared_ptr<core::Socket> socket) = 0;
    virtual void disconnect() = 0;
};

class Server
{
private:
	INetwork* m_node;
	io::ip::tcp::acceptor m_acceptor;

protected:
	void listen()
    {
        m_acceptor.async_accept(
			[this](boost::system::error_code ec, io::ip::tcp::socket io_socket)
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

				auto tcp_socket = std::make_unique<io::ip::tcp::socket>(std::move(io_socket));
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
	Server(io::io_context* context, INetwork* node) : m_acceptor(*context), m_node(node)
	{

	}

	void run(auto listen_port)
    {
        io::ip::tcp::endpoint listen_ep(io::ip::tcp::v4(), listen_port);

        m_acceptor.open(listen_ep.protocol());
		m_acceptor.set_option(io::socket_base::reuse_address(true));
		m_acceptor.bind(listen_ep);
		m_acceptor.listen();
		listen();

		LOG_INFO << "Factory started for port: " << listen_ep.port();
    }
};

class Client
{
private:
	INetwork* m_node;
    io::ip::tcp::resolver m_resolver;

public:
	Client(io::io_context* context, INetwork* node) : m_resolver(*context), m_node(node)
	{

	}
};

template<typename T>
concept FactoryComponent = std::is_same_v<Server, T> || std::is_same_v<Client, T>;

template <FactoryComponent...Components> 
class Factory : public Components...
{
	io::io_context* m_context;
	INetwork* m_node;
	
public:
	Factory(io::io_context* context, INetwork* node) : m_context(context), m_node(node), Components(context, node)...
	{

	}

    // void run()
    // {

    // }
};

} // namespace pool
