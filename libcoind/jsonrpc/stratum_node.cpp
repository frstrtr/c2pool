#include "stratum_node.h"

StratumNode::StratumNode(std::shared_ptr<boost::asio::io_context> context, std::shared_ptr<Worker> worker) : _context(std::move(context)), acceptor(*_context), resolver(*_context), _worker(std::move(worker))
{
    ip::tcp::endpoint listen_ep(ip::tcp::v4(), 1131);

    acceptor.open(listen_ep.protocol());
    acceptor.set_option(io::socket_base::reuse_address(true));
    acceptor.bind(listen_ep);
    acceptor.listen();
}


void StratumNode::listen()
{
    acceptor.async_accept([this](const boost::system::error_code &ec, ip::tcp::socket _socket)
                          {
                              if (!ec)
                              {
                                  auto _addr = std::make_tuple(_socket.remote_endpoint().address().to_string(),
                                                               _socket.remote_endpoint().port());
                                  LOG_INFO << "Stratum connected from: " << std::get<0>(_addr) << ":"
                                           << std::get<1>(_addr);

                                  if (bans.find(std::get<0>(_addr)) != bans.end())
                                  {
                                      LOG_TRACE << "BANNED!";
                                      _socket.close();
                                      listen();
                                      return;
                                  }

                                  if (miners.find(_addr) != miners.end())
                                  {
                                      LOG_WARNING << std::get<0>(_addr) << ":" << std::get<1>(_addr)
                                                  << " already connected!";
                                      _socket.close();
                                      ban(_addr);
                                      listen();
                                      return;
                                  }

                                  auto socket = std::make_shared<ip::tcp::socket>(std::move(_socket));
                                  auto stratum = std::make_shared<Stratum>(_context, std::move(socket), _worker,
                                                                           [&](const addr_t &addr)
                                                                           {
                                                                               disconnect(addr);
                                                                           });
                                  miners[_addr] = std::move(stratum);
                                  listen();
                              } else
                              {
                                  std::cout << ec.message() << std::endl;
                              }

                          });
}

void StratumNode::ban(const StratumNode::addr_t& _addr)
{
    auto _ban_timer = std::make_shared<boost::asio::steady_timer>(*_context);
    _ban_timer->expires_from_now(std::chrono::seconds(10));
    _ban_timer->async_wait([&, addr = _addr](const auto& ec){
        bans.erase(std::get<0>(addr));
    });
    bans[std::get<0>(_addr)] = std::move(_ban_timer);
    LOG_INFO << std::get<0>(_addr) << " banned for StratumNode!";
}

void StratumNode::disconnect(const addr_t& addr)
{
    if (miners.find(addr) != miners.end())
    {
        auto stratum = miners[addr];
        miners.erase(addr);
        ban(addr);
        stratum.reset();
    } else
    {
        throw std::invalid_argument("StratumNode::disconnect received wrong addr");
    }
}

