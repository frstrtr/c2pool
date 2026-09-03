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

// ── Dial/accept lifetime acquisition (ROBUST successor to the e527abfe guard) ──
//
// e527abfe tried to keep the node alive across an async resolve/connect/accept by
// capturing `node->weak_from_this()`. That silently no-ops for TWO real node
// shapes:
//   (a) a virtual-inheritance diamond (bip110::pool::Node : virtual NodeImpl :
//       … : core::INetwork), where the enable_shared_from_this base was never
//       enrolled through the owning control block, and
//   (b) a unique_ptr/stack-owned node (the coin NodeP2P — the DOMINANT crasher),
//       which is not shared_ptr-managed at all.
// In both cases weak_from_this() is EMPTY → was_managed=false → the guard is a
// NO-OP → make_socket() runs dynamic_cast on a dangling node vtable → SEGV. The
// e527abfe KAT used a single-inheritance make_shared StubNode, so it never
// observed either failure.
//
// The robust replacement: the OWNER explicitly hands the Factory a
// shared_ptr<INetwork> (Factory::set_lifetime) sourced from the REAL owning
// control block — never derived from esft. The Factory stores it as a weak_ptr
// at rest (a stored strong ref to its own node would be a self-cycle/leak,
// because core::Client/Server are BASE subobjects of the node) and, for the
// duration of each async op, locks it and captures the resulting STRONG ref BY
// VALUE in the handler. A pending resolve/connect therefore keeps the node alive
// until the handler runs — make_socket/dynamic_cast can NEVER touch freed memory
// — and on ioc teardown the handler is destroyed, releasing the strong ref, so
// nothing leaks and make_socket never runs.
//
// acquire_lifetime centralises the "prefer explicit handle, else fall back to
// esft" decision so Client and Server stay in lockstep:
//   * has_lifetime=true  → node was registered via set_lifetime. `strong` is a
//     STRONG ref (null only if the node is ALREADY gone). was_managed=true.
//   * has_lifetime=false → legacy path. `strong` stays null; weak_out/was_managed
//     reproduce the prior esft behavior EXACTLY (Dash: real weak_from_this;
//     LTC/DOGE: empty → guard skipped → raw m_node). Byte-identical.
inline void acquire_lifetime(INetwork* raw,
                             const std::weak_ptr<INetwork>& lifetime, bool has_lifetime,
                             std::shared_ptr<INetwork>& strong,
                             std::weak_ptr<INetwork>& weak_out, bool& was_managed)
{
	if (has_lifetime)
	{
		strong      = lifetime.lock();   // STRONG ref — capture by value to pin the node
		weak_out    = lifetime;
		was_managed = true;
		return;
	}
	// Legacy: esft (Dash) or empty (LTC/DOGE) — prior behavior, unchanged.
	weak_out    = raw->weak_from_this();
	strong.reset();
	was_managed = (weak_out.lock() != nullptr);
}

class Server
{
private:
	INetwork* m_node;
	std::optional<io::ip::tcp::acceptor> m_acceptor;

	// Explicit lifetime handle registered by the owner via Factory::set_lifetime.
	// weak_ptr at rest (self-cycle-free); locked into a strong ref per async op.
	std::weak_ptr<INetwork> m_lifetime;
	bool m_has_lifetime{false};

protected:
	void accept()
    {
        // ROBUST lifetime: prefer the explicit handle (set_lifetime), else fall
        // back to esft exactly as before. `strong`, when non-null, keeps the node
        // alive for the whole handler — make_socket()'s dynamic_cast can never
        // touch a freed node.
        std::shared_ptr<INetwork> strong;
        std::weak_ptr<INetwork> weak_node;
        bool was_managed;
        acquire_lifetime(m_node, m_lifetime, m_has_lifetime, strong, weak_node, was_managed);
        m_acceptor->async_accept(
			[this, strong, weak_node, was_managed](boost::system::error_code ec, io::ip::tcp::socket io_socket)
			{
				if (ec)
				{
					LOG_ERROR << "listen error: " << ec.what();
					return;
				}

				// strong (explicit-managed) pins the node; else re-lock esft.
				std::shared_ptr<INetwork> strong_node = strong ? strong : weak_node.lock();
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
	// Register the owner's shared_ptr<INetwork> control block. Called via
	// Factory::set_lifetime BEFORE any listen()/connect() so every async op sees
	// a real, lockable handle regardless of enable_shared_from_this enrollment.
	void register_lifetime(const std::shared_ptr<INetwork>& self)
	{
		m_lifetime    = self;
		m_has_lifetime = (self != nullptr);
	}

	// See Client::lifetime_locked — same contract for the inbound (accept) path.
	bool lifetime_locked() const { return m_has_lifetime && m_lifetime.lock() != nullptr; }

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

	/// Canonical p2p.py:110 — `if self.node.serverfactory.listen_port is not None`.
	///
	/// listen_port() above is only valid on a node that actually listens: it
	/// dereferences the optional acceptor unconditionally (empty for the
	/// rig-free `Server(nullptr, ...)` construction used by the KAT targets)
	/// and calls local_endpoint() on it, which THROWS boost::system::system_error
	/// (bad_descriptor) when the acceptor was never opened. c2pool has a real
	/// non-listening mode — DASH's `--connect` suppresses the inbound listener
	/// (src/c2pool/main_dash.cpp:566) — so an advertisement path that needs our
	/// listen port must be able to ask "are we listening at all?" without
	/// throwing. That is exactly the question canonical asks before deciding
	/// whether to advertise, and this is the accessor that answers it.
	///
	/// Additive: listen_port() is untouched, so no existing caller changes.
	std::optional<uint16_t> listen_port_or_none() const noexcept
	{
		if (!m_acceptor || !m_acceptor->is_open())
			return std::nullopt;

		boost::system::error_code ec;
		const auto ep = m_acceptor->local_endpoint(ec);
		if (ec)
			return std::nullopt;

		return ep.port();
	}
};

class Client
{
private:
	INetwork* m_node;
	io::io_context* m_context;
    std::optional<io::ip::tcp::resolver> m_resolver;
    std::string m_label = "Net";  // chain/protocol label for log messages

	// Explicit lifetime handle registered by the owner via Factory::set_lifetime.
	// weak_ptr at rest; locked into a strong ref per async op. See acquire_lifetime.
	std::weak_ptr<INetwork> m_lifetime;
	bool m_has_lifetime{false};

	// strong / weak_node / was_managed are CAPTURED BY resolve() while the node
	// was provably alive (before async_resolve) and threaded through here. Do NOT
	// re-derive them by dereferencing m_node: on the dial-teardown race m_node may
	// already be dangling. When `strong` is non-null (explicit set_lifetime path)
	// it PINS the node across this whole call and its async_connect handler.
	void connect_socket(boost::asio::ip::tcp::resolver::results_type endpoints, NetService addr,
	                    std::shared_ptr<INetwork> strong, std::weak_ptr<INetwork> weak_node,
	                    bool was_managed)
	{
		// ROBUST UAF fix (successor to e527abfe): guard node liveness BEFORE
		// make_socket(). make_socket() does dynamic_cast<ICommunicator*>(node) /
		// dynamic_cast<INetwork*>(node) (socket.hpp) which read the node's vtable
		// — if the owning node was destroyed while the async resolve was in
		// flight (e.g. ioc.stop() during teardown, or a start_p2p() redial that
		// frees the prior NodeP2P), that dereferences freed memory → SEGV.
		//
		// For an explicitly-registered node `strong` is non-null and PINS the
		// node for the whole scope below AND for the async_connect handler
		// (captured by value) — make_socket therefore always runs on a LIVE node.
		// For a legacy esft-managed node we re-lock; for a legacy unmanaged node
		// (was_managed=false) the guard is skipped and we use raw m_node, exactly
		// as before.
		std::shared_ptr<INetwork> guard_node = strong ? strong : weak_node.lock();
		if (was_managed && !guard_node)
			return;
		INetwork* live_node = guard_node ? guard_node.get() : m_node;

		auto tcp_socket = std::make_unique<io::ip::tcp::socket>(*m_context);
		auto socket = core::make_socket(std::move(tcp_socket), core::connection_type::outgoing, live_node);

		io::async_connect(*socket->raw(), endpoints,
			[this, strong, weak_node, was_managed, addr, socket = socket]
			(const auto& ec, boost::asio::ip::tcp::endpoint ep)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
					{
						LOG_TRACE << "[" << m_label << "] Connection failed: " << ec.message();
						// #940: feed the dial failure back to the node so a scored
						// peer manager can penalise the dead target (attempt++/
						// backoff) instead of re-selecting it forever. Same
						// lifetime guard as the success path below.
						std::shared_ptr<INetwork> strong_node = strong ? strong : weak_node.lock();
						if (!was_managed || strong_node)
							(strong_node ? strong_node.get() : m_node)->connect_failed(addr);
					}
					else
						LOG_DEBUG_COIND << "Factory::Client::connect_socket canceled";
					return;
				}

				// strong (explicit-managed) pins the node; else re-lock esft. The
				// resulting strong_node keeps the INetwork alive for the duration
				// of the connected() dispatch below.
				std::shared_ptr<INetwork> strong_node = strong ? strong : weak_node.lock();
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
		// ROBUST lifetime acquisition: prefer the explicit handle (set_lifetime),
		// else fall back to esft exactly as before. When has_lifetime is set,
		// `strong` PINS the node across the async_resolve handler (captured by
		// value) so the chained connect_socket() — and make_socket()'s
		// dynamic_cast — can never run on a freed node. Legacy nodes reproduce
		// the prior weak_from_this behavior byte-for-byte.
		std::shared_ptr<INetwork> strong;
		std::weak_ptr<INetwork> weak_node;
		bool was_managed;
		acquire_lifetime(m_node, m_lifetime, m_has_lifetime, strong, weak_node, was_managed);
		// Explicit-managed node already gone before we even started: nothing to dial.
		if (m_has_lifetime && !strong)
			return;
		if (!m_resolver)
		{
			LOG_ERROR << "resolve() called on a context-less Client";
			return;
		}
		m_resolver->async_resolve(addr.address(), addr.port_str(),
			[this, strong, weak_node, was_managed, addr = addr](const auto& ec, auto endpoints)
			{
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
					{
						LOG_TRACE << "[" << m_label << "] DNS resolve failed: " << ec.message();
						// #940: a resolve failure is also a dial failure — report
						// it so the target is scored (same lifetime guard).
						std::shared_ptr<INetwork> strong_node = strong ? strong : weak_node.lock();
						if (!was_managed || strong_node)
							(strong_node ? strong_node.get() : m_node)->connect_failed(addr);
					}
					else
						LOG_DEBUG_OTHER << "Factory::Client::resolve canceled";
					return;
				}

				// #910: this is the ONE resolver in the outbound path, and it
				// has just produced the answer the serializer needs. Memoise
				// the A record against the configured host string so an
				// `--addnode rov.p2p-spb.xyz:8999` seed is advertised to peers
				// by its real address instead of being rewritten to 127.0.0.1
				// in NetAddress::Write_IPV4. No second lookup is introduced,
				// so the two paths cannot disagree; the memo is skipped
				// automatically when the host is already a literal.
				for (const auto& entry : endpoints)
				{
					if (entry.endpoint().address().is_v4())
					{
						core::record_resolved_host(addr.address(),
							entry.endpoint().address().to_string());
						break;
					}
				}

				// Liveness re-check before chaining connect_socket. For the
				// explicit-managed path `strong` is held by value here, so the
				// node is provably alive; for a legacy esft node, an expired
				// weak_ptr means it was destroyed — skip to avoid the UAF on
				// m_node->connected(socket) inside connect_socket().
				if (was_managed && !(strong || !weak_node.expired())) return;

				// Thread the alive-captured strong/weak_node/was_managed into
				// connect_socket so its pre-make_socket guard uses THIS liveness
				// proof (it must not re-derive from a possibly-dangling m_node).
				connect_socket(endpoints, addr, strong, weak_node, was_managed);
			}
		);
	}

public:
	// Register the owner's shared_ptr<INetwork> control block. Called via
	// Factory::set_lifetime BEFORE any connect() so every async op sees a real,
	// lockable handle regardless of enable_shared_from_this enrollment.
	void register_lifetime(const std::shared_ptr<INetwork>& self)
	{
		m_lifetime    = self;
		m_has_lifetime = (self != nullptr);
	}

	// True iff an explicit lifetime handle was registered AND still locks —
	// i.e. the strong-ref dial guard is genuinely armed for this node. Used by
	// the flag-ON runtime assertion so a control block that fails to register
	// fails LOUDLY in CI/soak instead of SEGV'ing in prod.
	bool lifetime_locked() const { return m_has_lifetime && m_lifetime.lock() != nullptr; }

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

	// Register the owning shared_ptr<INetwork> control block with EVERY Factory
	// component (Client and/or Server), so their async dial/accept handlers can
	// pin the node with a strong ref for the op's duration. MUST be called by the
	// owner immediately after the node is constructed and BEFORE connect()/listen()
	// — this is the robust, esft-independent successor to the e527abfe guard.
	void set_lifetime(const std::shared_ptr<core::INetwork>& self)
	{
		(Components::register_lifetime(self), ...);
	}

	// True iff every component has an explicit, currently-lockable lifetime handle.
	// Drives the flag-ON runtime assertion (fail loud, not SEGV).
	bool lifetime_armed() const
	{
		return (Components::lifetime_locked() && ...);
	}
};

} // namespace core