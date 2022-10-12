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
                                  LOG_INFO << "Stratum connected from: " << _socket.remote_endpoint().data();
                                  auto socket = std::make_shared<ip::tcp::socket>(std::move(_socket));
                                  auto stratum = std::make_shared<Stratum>(_context, std::move(socket), _worker,
                                                                           [&](const addr_t& addr)
                                                                           {
                                                                               disconnect(addr);
                                                                           });
                                  auto addr = stratum->get_addr();
                                  miners[addr] = std::move(stratum);
                                  listen();
                              } else
                              {
                                  std::cout << ec.message() << std::endl;
                              }

                          });
}

void StratumNode::disconnect(const addr_t& addr)
{
    if (miners.find(addr) != miners.end())
    {
        auto stratum = miners[addr];
        miners.erase(addr);
        stratum.reset();
    } else
    {
        throw std::invalid_argument("StratumNode::disconnect received wrong addr");
    }
}

