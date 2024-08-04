#pragma once

#include "p2p_messages.hpp"

#include <memory>

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/factory.hpp>

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

struct NodeInterfaces : core::ICommunicator, core::INetwork
{
    //-core::ICommmunicator:
    // void error(const message_error_type& err, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
    // void error(const boost::system::error_code& ec, const NetService& service, const std::source_location where = std::source_location::current()) = 0;
    // void handle(std::unique_ptr<RawMessage> rmsg, const NetService& service) = 0;
    // const std::vector<std::byte>& get_prefix() const = 0;
    //
    //-core::INetwork:
    // void connected(std::shared_ptr<core::Socket> socket) = 0;
    // void disconnect() = 0;
};

template <typename ConfigType>
class P2PNode : public NodeInterfaces, private core::Factory<core::Client>
{
    using config_t = ConfigType;

private:
    io::io_context* m_context;
    config_t* m_config;
    p2p::Handler m_handler;

    std::shared_ptr<core::Socket> m_socket;

public:
    P2PNode(io::io_context* context, config_t* config) : core::Factory<core::Client>(context, this), m_context(context), m_config(config) 
    {
        
    }
    
    // INetwork
    void connected(std::shared_ptr<core::Socket> socket) override
    {
        m_socket = socket;
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
        if (m_socket)
        {
            // peer.mapped()->m_timeout->stop(); // for case: peer stored somewhere (or leak)
            m_socket->cancel();
            m_socket->close();
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
        p2p::Handler::result_t result;
        try 
        {
            result = m_handler.parse(rmsg);
        } catch (const std::runtime_error& ec)
        {
            // todo: error
            return;
        }

        std::visit([&](auto& msg){ handle(std::move(msg)); }, result);
    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_prefix;
    }

    //[x][x][x]  void handle_message_version(std::shared_ptr<coind::messages::message_version> msg, CoindProtocol* protocol); //
    //[x][x][ ] void handle_message_verack(std::shared_ptr<coind::messages::message_verack> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_ping(std::shared_ptr<coind::messages::message_ping> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_pong(std::shared_ptr<coind::messages::message_pong> msg, CoindProtocol* protocol); //
    //[x][x][x] void handle_message_alert(std::shared_ptr<coind::messages::message_alert> msg, CoindProtocol* protocol); // 
    //[x][x][x] void handle_message_inv(std::shared_ptr<coind::messages::message_inv> msg, CoindProtocol* protocol); //
    //[x][x][ ] void handle_message_tx(std::shared_ptr<coind::messages::message_tx> msg, CoindProtocol* protocol); //
    //[x][x][ ] void handle_message_block(std::shared_ptr<coind::messages::message_block> msg, CoindProtocol* protocol); //
    //[x][x][ ] void handle_message_headers(std::shared_ptr<coind::messages::message_headers> msg, CoindProtocol* protocol); //

private:
    ADD_HANDLER(version)
    {
        auto verack_msg = message_verack::make_raw();
        m_socket->write(verack_msg);
    }

    ADD_HANDLER(verack)
    {
        // TODO:
        // self.get_block = deferral.ReplyMatcher(lambda hash: self.send_getdata(requests=[dict(type='block', hash=hash)]))
        // self.get_block_header = deferral.ReplyMatcher(lambda hash: self.send_getheaders(version=1, have=[], last=hash))

        // connected()
    }

    ADD_HANDLER(ping)
    {
        auto msg_pong = message_pong::make_raw(msg->m_nonce);
        m_socket->write(msg_pong);
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
                //TODO: new_block->happened(inv.hash);
            default:
                LOG_WARNING << "Unknown inv type";
                break;
            }
        }

        if (!vinv.empty())
        {
            auto msg_getdata = message_getdata::make_raw(vinv);
            m_socket->write(msg_getdata);
        }
    }

    ADD_HANDLER(tx)
    {
        // new_tx->happened(msg->m_tx);
    }

    ADD_HANDLER(block)
    {
        // TODO: 
        // auto packed_header = pack(msg->m_block);
        // auto blockhash = Hash(packed_header.get_span()); // block_type -> block_header_type
        // get_block.got_response(blockhash, block);
        // get_block.got_response(block_hash, block['header']);
    }

    ADD_HANDLER(headers)
    {
        std::vector<BlockHeaderType> vheaders;

        for (auto block : msg->m_headers)
        {
            // auto packed_header = pack(block);
            // auto blockhash = Hash(packed_header.get_span()); // block_type -> block_header_type
            // self.get_block_header.got_response(bitcoin_data.hash256(bitcoin_data.block_header_type.pack(header)), header)
        }

        // new_headers->happened(vheaders);
    }

    #undef ADD_HANDLER
};

} // namespace p2p

} // namespace node

} // namespace ltc
