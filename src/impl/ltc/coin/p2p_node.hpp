#pragma once

#include "p2p_messages.hpp"
#include "p2p_connection.hpp"
#include "node_interface.hpp"

#include <memory>

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/random.hpp>
#include <core/factory.hpp>
#include <core/reply_matcher.hpp>

namespace io = boost::asio;

#define ADD_HANDLER(name)\
    void handle(std::unique_ptr<ltc::coin::p2p::message_##name> msg)
namespace ltc
{
namespace coin
{

namespace p2p
{

std::string parse_net_error(const boost::system::error_code& ec);

//-core::ICommmunicator:
// void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
// void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
// void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) = 0;
// const std::vector<std::byte>& get_prefix() const = 0;
//
//-core::INetwork:
// void connected(std::shared_ptr<core::Socket> socket) = 0;
// void disconnect() = 0;

template <typename ConfigType>
class NodeP2P : public core::ICommunicator, public core::INetwork, public interfaces::Node, public core::Factory<core::Client>
{
    using config_t = ConfigType;

private:
    io::io_context* m_context;
    config_t* m_config;
    p2p::Handler m_handler;

    std::unique_ptr<Connection> m_peer; // TODO: add ping

public:
    NodeP2P(io::io_context* context, config_t* config) : core::Factory<core::Client>(context, this), m_context(context), m_config(config) 
    {
        
    }

    // INetwork
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        m_peer = std::make_unique<Connection>(m_context, socket);

        // TODO: LEGACY REWORK!

        /*
            version=70002,
            services=1,
            time=1723920793,
            addr_to=dict(
                services=1,
                address="192.168.0.1",
                port=2222,
            ),
            addr_from=dict(
                services=1,
                address="192.168.0.1",
                port=2222,
            ),
            nonce=1,
            sub_version_num='c2pool',
            start_height=0
        */

        // auto msg_version = message_version::make_raw(
        //     70002,
        //     1,
        //     1723920793,
        //     addr_t{1, NetService{"192.168.0.1", 2222}}, 
        //     addr_t{1, NetService{"192.168.0.1", 2222}},
        //     1,
        //     "c2pool",
        //     0
        // );

        auto msg_version = message_version::make_raw(
            70017,
            1,
            core::timestamp(),
            addr_t{1, m_peer->get_addr()}, 
            addr_t{1, NetService{"192.168.0.1", 12024}},
            core::random::random_nonce(),
            "c2pool",
            0
        );

        m_peer->write(msg_version);
        //=======================

        // // configure peer timeout timer
        // peer->m_timeout = std::make_unique<core::Timer>(m_context, true);
        // peer->m_timeout->start(NEW_PEER_TIMEOUT_TIME, [&, addr = peer->addr()](){ timeout(addr); });

        // LOG_INFO << socket->get_addr().to_string() << " try to connect!";
    }

    void disconnect() override
    {
        
    }

    // ICommmunicator
    void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        LOG_ERROR << "PoolNode <NetName>[" << service.to_string() << "]:";
        LOG_ERROR << "\terror: " << err;
        LOG_ERROR << "\twhere: " << where.function_name();
        if (m_peer)
        {
            m_peer.reset();
            // peer.mapped()->m_timeout->stop(); // for case: peer stored somewhere (or leak)
        }
        else
        {
            LOG_ERROR << "\tpeers not exist " << service.to_string();
        }
    }

    void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) override
    {
        error(parse_net_error(ec), service, where);
    }

    void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) override
    {
        LOG_INFO << "HANDLE: " << rmsg->m_command;
        p2p::Handler::result_t result;
        try 
        {
            result = m_handler.parse(rmsg);
        } catch (const std::runtime_error& ec)
        {
            LOG_ERROR << "NodeP2P handle: " << ec.what();
            // todo: error
            return;
        } catch (const std::out_of_range& ec)
        {
            LOG_ERROR << "NodeP2P: " << ec.what();
            return;
        }

        std::visit([&](auto& msg){ handle(std::move(msg)); }, result);
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_prefix;
    }

    //[x][x][x] void handle_message_version(std::shared_ptr<coind::messages::message_version> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_verack(std::shared_ptr<coind::messages::message_verack> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_alert(std::shared_ptr<coind::messages::message_alert> msg, CoindProtocol* protocol); // 
    //[x][x][x] void handle_message_inv(std::shared_ptr<coind::messages::message_inv> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_tx(std::shared_ptr<coind::messages::message_tx> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_block(std::shared_ptr<coind::messages::message_block> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_headers(std::shared_ptr<coind::messages::message_headers> msg, CoindProtocol* protocol); //

private:
    ADD_HANDLER(version)
    {
        LOG_INFO << "version is?: " << msg->m_command;
        auto verack_msg = message_verack::make_raw();
        m_peer->write(verack_msg);
    }

    ADD_HANDLER(verack)
    {
        m_peer->init_requests(
            [&](uint256 hash)
            {
                //TODO:
                auto getdata_msg = message_getdata::make_raw({inventory_type(inventory_type::block, hash)});
                m_peer->write(getdata_msg);
            },
            [&](uint256 hash)
            {
                auto getheaders_msg = message_getheaders::make_raw(1, {}, hash);
                m_peer->write(getheaders_msg);
            }
        );

        // TODO: PING
        // connected()
    }

    ADD_HANDLER(ping)
    {
        auto msg_pong = message_pong::make_raw(msg->m_nonce);
        m_peer->write(msg_pong);
    }
    
    ADD_HANDLER(pong)
    {
        // just handled pong
    }

    ADD_HANDLER(alert)
    {
        LOG_WARNING << "Handled message_alert signature: " << msg->m_signature;
    }

    ADD_HANDLER(inv)
    {
        std::vector<inventory_type> vinv;
        
        for (auto& inv : msg->m_invs)
        {
            switch (inv.m_type)
            {
            case inventory_type::tx:
                vinv.push_back(inv);
                break;
            case inventory_type::block:
                m_new_block.happened(inv.m_hash);
            default:
                LOG_WARNING << "Unknown inv type";
                break;
            }
        }

        if (!vinv.empty())
        {
            auto msg_getdata = message_getdata::make_raw(vinv);
            m_peer->write(msg_getdata);
        }
    }

    ADD_HANDLER(tx)
    {
        m_new_tx.happened(Transaction(msg->m_tx));
    }

    ADD_HANDLER(block)
    {
        // TODO: check
        auto header = (BlockHeaderType) msg->m_block;
        auto packed_header = pack(header); // block_type -> block_header_type
        auto blockhash = Hash(packed_header.get_span());
        m_peer->get_block(blockhash, msg->m_block);
        m_peer->get_header(blockhash, header);
    }

    ADD_HANDLER(headers)
    {
        // TODO: check
        std::vector<BlockHeaderType> vheaders;

        for (auto block : msg->m_headers)
        {
            auto header = (BlockHeaderType)block;
            auto packed_header = pack(header);
            auto blockhash = Hash(packed_header.get_span());
            m_peer->get_header(blockhash, header);
        }

        m_new_headers.happened(vheaders);
    }

    #undef ADD_HANDLER
};

} // namespace p2p

} // namespace node

} // namespace ltc
