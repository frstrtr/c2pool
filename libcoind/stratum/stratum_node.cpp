#include "stratum_node.h"

StratumNode::StratumNode(boost::asio::io_context* context, Worker* worker) 
    : _context(context), acceptor(*_context), _worker(worker)
{
}

void StratumNode::miner_processing(ip::tcp::socket& _socket)
{
    auto addr = NetAddress(_socket.remote_endpoint());

    if (bans.find(addr.ip) != bans.end())
    {
        LOG_DEBUG_STRATUM << "Miner " << addr.to_string() << " banned!";
        _socket.close();
        return;
    }

    LOG_INFO << "Stratum connected from: " << addr.to_string();
    if (miners.find(addr) != miners.end())
    {
        LOG_WARNING << addr.to_string() << " already connected!";
        _socket.close();
        ban(addr, 10);
        return;
    }

    auto socket = std::make_unique<ip::tcp::socket>(std::move(_socket));
    auto stratum = 
        new Stratum(
            _context,
            std::move(socket), 
            _worker,
            [&](const addr_t &addr_, std::string reason, int ban_time)
            {
                disconnect(addr_, reason, ban_time);
            }
        );
    miners[addr] = stratum;
}

void StratumNode::listen()
{
    acceptor.async_accept(
        [this](const boost::system::error_code &ec, ip::tcp::socket socket)
        {
            if (ec)
            {
                if (ec == boost::system::errc::operation_canceled)
                    return;
                else
                    throw libp2p::node_exception("Stratum node listen error: " + ec.message(), this);
            }
            miner_processing(socket);
            listen();
        }
    );
}

void StratumNode::ban(const StratumNode::addr_t& addr, int sec)
{
    auto ban_timer = std::make_unique<c2pool::Timer>(_context);
    ban_timer->start(
        sec, // default = 10 second ban
        [&, addr = addr]()
        {
            bans.erase(addr.ip);
        }
    );

    bans[addr.ip] = std::move(ban_timer);
    LOG_INFO << addr.ip << " banned in StratumNode!";
}

void StratumNode::disconnect(const addr_t& addr, std::string reason, int ban_time)
{
    LOG_WARNING << "StratumProtocol(" << addr.to_string() << ") has been disconnected for a reason: " << reason;
    if (miners.count(addr))
    {
        auto stratum = miners[addr];
        stratum->close();
        miners.erase(addr);
        if (ban_time)
            ban(addr, ban_time);
        
        _context->post(
            [stratum = stratum]
            {
                // Завершатся существующие Read/Send и только после этого удалится объект StratumProtocol.
                delete stratum;
            }
        );
    } else
    {
        throw libp2p::node_exception("StratumNode::disconnect received wrong addr = " + addr.to_string(), this);;
    }
}

