#pragma once

#include "pool_handshake.h"
#include "pool_node_data.h"
#include <libp2p/node.h>
#include <libp2p/network_tree_node.h>

template <typename CommunicationType>
inline void base_pool_error(const libp2p::error& err, NetworkTreeNode* node, CommunicationType* communicator)
{
    switch (err.errc)
    {
    case libp2p::SYSTEM_ERROR:
        throw libp2p::node_exception(err.reason, node);
    // case libp2p::ASIO_ERROR:
        // ???
    default:
        communicator->disconnect(err.addr);
    }
}

class PoolNodeServer : public Server<BasePoolSocket>
{
    PoolNodeData* data;

    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, PoolHandshake*)> msg_version_handler_type;
    msg_version_handler_type message_version_handle;

    void handshake_handle(PoolHandshake* handshake)
    {
        LOG_DEBUG_POOL << "PoolServer has been connected to: " << handshake->get_socket();
        auto sock = handshake->get_socket();
        auto addr = sock->get_addr();
		auto protocol 
            = new PoolProtocol
                (
                    data->context, sock, data->handler_manager, handshake,
                    [&](libp2p::error err)
                    {
                        error(err);
                    }
                );
        
        data->peers[protocol->nonce] = protocol;
        server_connections[addr] = protocol;
        server_attempts.erase(addr);

        // Set PoolNode::NetworkTreeNode connected
        if ((data->peers.size() == 1) && data->net->PERSIST)
            data->connected();
    }

protected:
    std::map<NetAddress, PoolHandshakeServer*> server_attempts;
    std::map<NetAddress, PoolProtocol*> server_connections;
    
public:
	PoolNodeServer(PoolNodeData* data_, msg_version_handler_type version_handle) 
        : Server<BasePoolSocket>(), data(data_), message_version_handle(std::move(version_handle)) 
    {
    }

    void start() override
    {
        interface->run();
    }

    void stop() override
    {
        // disable listener
        interface->stop();

        // disconnect and delete all server_connections
        for (auto& [addr, protocol] : server_connections) 
        {
            if (protocol)
            {
                protocol->close();
                delete protocol;
            }            
        }
        server_connections.clear();

        // stop all server attempts
        for (auto& [socket, handshake] : server_attempts)
        {
            handshake->close();
            delete handshake;
        }
        server_attempts.clear();
    }

    void disconnect(const NetAddress& addr) override
    {
        if (server_attempts.count(addr))
        {
            auto handshake = server_attempts[addr];
            if (handshake)
            {
                handshake->close();
                delete handshake;
            }
            server_attempts.erase(addr);
        }

        if (server_connections.count(addr))
        {
            auto protocol = server_connections[addr];
            data->peers.erase(protocol->nonce);
            protocol->close();
            delete protocol;
            server_connections.erase(addr);

            if (data->peers.empty())
                throw libp2p::node_exception("All PoolNode peers are disconnected.", data);
        }
    }

protected:
    void error(const libp2p::error& err) override 
    {
        LOG_ERROR << "[Pool.server]: <" << err.errc << "/" << err.addr.to_string() << "> " << err.reason;
        base_pool_error(err, data, this);
    }

    void socket_handle(std::shared_ptr<socket_type> socket) override
    {
        server_attempts[socket->get_addr()] = 
            new PoolHandshakeServer
            (
                socket,
                [&](const libp2p::error& err)
                {
                    error(err);
                },
                message_version_handle,
                [&](PoolHandshake* _handshake)
                {
                   handshake_handle(_handshake);
                }
            );
        
        // start accept messages
        socket->read();
    }
};

class PoolNodeClient : public Client<BasePoolSocket>
{
    PoolNodeData* data;

    typedef std::function<void(std::shared_ptr<pool::messages::message_version>, PoolHandshake*)> msg_version_handler_type;
    msg_version_handler_type message_version_handle;

    c2pool::Timer connect_timer;
    const int connect_interval{1};

    void handshake_handle(PoolHandshake* handshake)
    {
        LOG_DEBUG_POOL << "PoolClient has been connected to: " << handshake->get_socket();
        auto sock = handshake->get_socket();
        auto addr = sock->get_addr();
        auto protocol 
            = new PoolProtocol
                (
                    data->context, sock, data->handler_manager, handshake,
                    [&](libp2p::error err)
                    {
                        error(err);
                    }
                );

        data->peers[protocol->nonce] = protocol;
        client_connections[addr] = protocol;
	    client_attempts.erase(addr);

        // Set PoolNode::NetworkTreeNode connected
        if ((data->peers.size() == 1) && data->net->PERSIST)
            data->connected();
    }

    void resolve_connection()
    {
        if (!((client_connections.size() < data->config->desired_conns) &&
              (data->addr_store->len() > 0) &&
              (client_attempts.size() <= data->config->max_attempts)))
            return;

        for (const auto &addr: get_good_peers(1))
        {
            if (client_attempts.count(addr) || client_connections.count(addr))
            {
//                LOG_WARNING << "Client already connected to " << addr.to_string() << "!";
                continue;
            }
            LOG_TRACE << "PoolNodeClient try to connect: " << addr.to_string();
            client_attempts[addr] = nullptr;
            interface->try_connect(addr);
        }
    }

protected:
    std::map<NetAddress, PoolHandshakeClient*> client_attempts;
    std::map<NetAddress, PoolProtocol*> client_connections;

    std::vector<NetAddress> get_good_peers(int max_count);

public:
    PoolNodeClient(PoolNodeData* data_, msg_version_handler_type version_handle)
        : Client<BasePoolSocket>(), data(data_), message_version_handle(std::move(version_handle)), connect_timer(data->context, true)
    {
    }

    void start()
    {
        interface->run();
        connect_timer.start(
            connect_interval,
            [&]()
            {
                resolve_connection();
            }
        );
    }

    void stop()
    {
        // disable connector
        interface->stop();

        // disconnect and delete all client_connections
        for (auto& [addr, protocol] : client_connections) 
        {
            if (protocol)
            {
                protocol->close();
                delete protocol;
            }            
        }
        client_connections.clear();

        // stop all client attempts
        for (auto& [socket, handshake] : client_attempts)
        {
            handshake->close();
            delete handshake;
        }
        client_attempts.clear();

        // stop auto_connect_timer
        connect_timer.stop();
    }
    
    void disconnect(const NetAddress& addr)
    {
        if (client_attempts.count(addr))
        {
            auto handshake = client_attempts[addr];
            if (handshake)
            {
                handshake->close();
                delete handshake;
            }
            client_attempts.erase(addr);
        }

        if (client_connections.count(addr))
        {
            auto protocol = client_connections[addr];
            data->peers.erase(protocol->nonce);
            protocol->close();
            delete protocol;
            client_connections.erase(addr);

            if (data->peers.empty())
                throw libp2p::node_exception("All PoolNode peers are disconnected.", data);
        }
    }

protected:
    void error(const libp2p::error& err) override 
    {
        LOG_ERROR << "[Pool.client]: <" << err.errc << "/" << err.addr.to_string() << "> " << err.reason;
        base_pool_error(err, data, this);
    }

    void socket_handle(std::shared_ptr<socket_type> socket) override
    {
        client_attempts[socket->get_addr()] =
            new PoolHandshakeClient
            (
                socket,
                [&](const libp2p::error& err)
                {
                    error(err);
                },
                message_version_handle,
                [&](PoolHandshake* _handshake)
                {
                   handshake_handle(_handshake);
                }
            );

        // start accept messages
        socket->read();
    }
};