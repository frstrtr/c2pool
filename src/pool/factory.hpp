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
	void accept()
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
				auto socket = core::make_socket(std::move(tcp_socket), core::connection_type::incoming, m_node);
				socket->init();
				
				m_node->connected(socket);
				
				// continue accept connections
				accept();
			}
		);
    }

public:
	Server(io::io_context* context, INetwork* node) : m_acceptor(*context), m_node(node)
	{

	}

	void listen(auto listen_port)
    {
        io::ip::tcp::endpoint listen_ep(io::ip::tcp::v4(), listen_port);

        m_acceptor.open(listen_ep.protocol());
		m_acceptor.set_option(io::socket_base::reuse_address(true));
		m_acceptor.bind(listen_ep);
		m_acceptor.listen();
		accept();

		LOG_INFO << "Factory started for port: " << listen_ep.port();
    }
};

class Client
{
private:
	INetwork* m_node;
	io::io_context* m_context;
    io::ip::tcp::resolver m_resolver;

	void connect_socket(boost::asio::ip::tcp::resolver::results_type endpoints)
	{
		auto tcp_socket = std::make_unique<io::ip::tcp::socket>(*m_context);
		auto socket = core::make_socket(std::move(tcp_socket), core::connection_type::outgoing, m_node);
		
		io::async_connect(*socket->raw(), endpoints, 
			[&, socket = std::move(socket)]
			(const auto& ec, boost::asio::ip::tcp::endpoint ep)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						{}//TODO: error(libp2p::ASIO_ERROR, "CoindConnector::connect_socket: " + ec.message(), NetAddress{ep});
					else
						LOG_DEBUG_COIND << "Factory::Client::connect_socket canceled";
					return;
				}

				LOG_INFO << "Factory::Client::connect_socket try handshake with " << ep.address() << ":" << ep.port();
				socket->init();

				m_node->connected(socket);
			}
		);
	}

	void resolve(const NetService& addr)
	{
		m_resolver.async_resolve(addr.address(), addr.port_str(), 
			[&, addr = addr](const auto& ec, auto endpoints)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						{}//TODO: error(libp2p::ASIO_ERROR, "CoindConnector::try_connect: " + ec.message(), address);
					else
						LOG_DEBUG_OTHER << "Factory::Client::resolve canceled";
					return;
				}

				connect_socket(endpoints);
			}
		);
	}

public:
	Client(io::io_context* context, INetwork* node) : m_context(context), m_resolver(*context), m_node(node)
	{
	}

	void connect(NetService addr)
	{
		LOG_DEBUG_OTHER << "Factory::Client try to resolve: " << addr.to_string();
		resolve(addr);
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
