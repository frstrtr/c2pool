#pragma once

#include <boost/asio.hpp>

#include <core/config.hpp>
#include <core/factory.hpp>

namespace io = boost::asio;

namespace ltc
{
namespace coin
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

    }

    const std::vector<std::byte>& get_prefix() const override
    {
        return m_config->coin()->m_prefix;
    }
};

} // namespace node

} // namespace ltc
