// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
#include <boost/asio.hpp>
#include <optional>

#include <core/log.hpp>
#include <core/socket.hpp>
#include <core/inetwork.hpp>
#include <core/addr_store.hpp>
#include <core/node_interface.hpp>

namespace io = boost::asio;

namespace core
{
// INetwork moved to core/inetwork.hpp (included above) so socket.hpp can see
// its full definition. See that header for the Bug 3 enable_shared_from_this
// rationale.

class Server
{
private:
	INetwork* m_node;
	std::optional<io::ip::tcp::acceptor> m_acceptor;

protected:
	void accept()
    {
        // Bug 3 root-cause fix: capture m_node->weak_from_this() so the async
        // callback keeps the node alive while it dispatches connected().
        // Empty weak_ptr (LTC/DOGE pattern, node not shared_ptr-managed) →
        // fall back to raw m_node (preserves prior behavior).
        auto weak_node = m_node->weak_from_this();
        bool was_managed = weak_node.lock() != nullptr;
        m_acceptor->async_accept(
			[this, weak_node, was_managed](boost::system::error_code ec, io::ip::tcp::socket io_socket)
			{
				if (ec)
				{
					LOG_ERROR << "listen error: " << ec.what();
					return;
				}

				std::shared_ptr<INetwork> strong_node = weak_node.lock();
				if (was_managed && !strong_node) return;  // node destroyed mid-flight
				INetwork* node_ptr = strong_node ? strong_node.get() : m_node;

				auto tcp_socket = std::make_unique<io::ip::tcp::socket>(std::move(io_socket));
				auto socket = core::make_socket(std::move(tcp_socket), core::connection_type::incoming, node_ptr);
				socket->init();
				if (socket->status()) {
					node_ptr->connected(socket);
				}

				accept();
			}
		);
    }

public:
	Server(io::io_context* context, INetwork* node, const std::string& /*label*/ = "")
		: m_node(node)
	{
		// Rig-free / test construction (context == nullptr, e.g. a default-
		// constructed BaseNode used for share-admit unit tests) leaves the
		// acceptor unengaged so no null io_context is dereferenced. listen()
		// is only valid once a real io_context has been wired in.
		if (context)
			m_acceptor.emplace(*context);
	}

	void listen(auto listen_port)
    {
        if (!m_acceptor)
        {
            LOG_ERROR << "listen() called on a context-less Server";
            return;
        }
        io::ip::tcp::endpoint listen_ep(io::ip::tcp::v4(), listen_port);

        m_acceptor->open(listen_ep.protocol());
		m_acceptor->set_option(io::socket_base::reuse_address(true));
		m_acceptor->bind(listen_ep);
		m_acceptor->listen();
		accept();

		LOG_INFO << "Factory started for port: " << listen_ep.port();
    }

	uint16_t listen_port() const { return m_acceptor->local_endpoint().port(); }
};

class Client
{
private:
	INetwork* m_node;
	io::io_context* m_context;
    std::optional<io::ip::tcp::resolver> m_resolver;
    std::string m_label = "Net";  // chain/protocol label for log messages

	void connect_socket(boost::asio::ip::tcp::resolver::results_type endpoints)
	{
		auto tcp_socket = std::make_unique<io::ip::tcp::socket>(*m_context);
		auto socket = core::make_socket(std::move(tcp_socket), core::connection_type::outgoing, m_node);

		// Bug 3 root-cause fix: weak_from_this() into the async lambda so the
		// async_connect callback keeps the node alive across the in-flight
		// connect() → connected() handoff. Without this, the lambda's bare `&`
		// (this) capture meant connected() could fire on a freed NodeP2P,
		// reading garbage m_target_addr and crashing in boost::log codecvt.
		auto weak_node = m_node->weak_from_this();
		bool was_managed = weak_node.lock() != nullptr;
		io::async_connect(*socket->raw(), endpoints,
			[this, weak_node, was_managed, socket = socket]
			(const auto& ec, boost::asio::ip::tcp::endpoint ep)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						LOG_TRACE << "[" << m_label << "] Connection failed: " << ec.message();
					else
						LOG_DEBUG_COIND << "Factory::Client::connect_socket canceled";
					return;
				}

				// Lock once; the strong_node also keeps the INetwork alive
				// for the duration of the connected() dispatch below.
				std::shared_ptr<INetwork> strong_node = weak_node.lock();
				if (was_managed && !strong_node) return;  // node destroyed mid-flight
				INetwork* node_ptr = strong_node ? strong_node.get() : m_node;

				LOG_TRACE << "[" << m_label << "] Handshake with " << ep.address() << ":" << ep.port();
				socket->init();

				node_ptr->connected(socket);
			}
		);
	}

	void resolve(const NetService& addr)
	{
		// Same lifetime extension as connect_socket — weak_from_this() rides
		// the async_resolve handler so the chained connect_socket() sees a
		// live node.
		auto weak_node = m_node->weak_from_this();
		// std::weak_ptr::expired() is true both for default-constructed weak
		// (LTC/DOGE pattern, never associated) and for expired-after-managed
		// (Dash pattern, node freed). Distinguish them at registration so we
		// only enforce the alive check when there WAS a shared owner to
		// begin with.
		bool was_managed = weak_node.lock() != nullptr;
		if (!m_resolver)
		{
			LOG_ERROR << "resolve() called on a context-less Client";
			return;
		}
		m_resolver->async_resolve(addr.address(), addr.port_str(),
			[this, weak_node, was_managed, addr = addr](const auto& ec, auto endpoints)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						LOG_TRACE << "[" << m_label << "] DNS resolve failed: " << ec.message();
					else
						LOG_DEBUG_OTHER << "Factory::Client::resolve canceled";
					return;
				}

				// If the node WAS managed at registration but is now expired,
				// it has been destroyed — skip the connect to avoid the UAF
				// on m_node->connected(socket) inside connect_socket().
				if (was_managed && weak_node.expired()) return;

				connect_socket(endpoints);
			}
		);
	}

public:
	Client(io::io_context* context, INetwork* node, const std::string& label = "Net")
		: m_node(node), m_context(context), m_label(label)
	{
		// Rig-free / test construction (context == nullptr) defers the resolver
		// so no null io_context is dereferenced; resolve()/connect() are only
		// valid once a real io_context has been wired in.
		if (context)
			m_resolver.emplace(*context);
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
	Factory(io::io_context* context, INetwork* node, const std::string& label = "Net")
		: m_context(context), m_node(node), Components(context, node, label)...
	{

	}
};

} // namespace core