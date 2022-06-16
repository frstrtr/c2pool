#include "p2p_node.h"

#include <vector>
#include <tuple>
#include <string>

#include <libdevcore/logger.h>

// P2PNodeClient

bool P2PNodeClient::client_connected(std::shared_ptr<Protocol> protocol)
{
    auto [ip, port] = protocol->get_socket()->get_addr();
    if (client_attempts.count(ip) > 0)
    {
        client_attempts.erase(ip);

//        auto p2p_protocol = std::static_pointer_cast<P2PProtocol>(protocol);
//        client_connections.insert(p2p_protocol);
        client_connections.insert(protocol);
    } else
    {
        //TODO: Полученного подключения -- нет в попытках для подключения.
    }
}

void P2PNodeClient::auto_connect()
{
    auto_connect_timer.expires_from_now(auto_connect_interval);
    auto_connect_timer.async_wait([this](boost::system::error_code const &_ec)
                                  {
                                      if (_ec)
                                      {
                                          LOG_ERROR << "P2PNode::auto_connect: " << _ec.message();
                                          return;
                                      }

                                      if (!((client_connections.size() < data->config->desired_conns) &&
                                            (data->addr_store->len() > 0) &&
                                            (client_attempts.size() <= data->config->max_attempts)))
                                          return;

                                      for (auto addr: get_good_peers(1))
                                      {
                                          if (client_attempts.find(std::get<0>(addr)) != client_attempts.end())
                                          {
                                              //TODO: [UNCOMMENT] LOG_WARNING << "Client already connected to " << std::get<0>(addr) << ":" << std::get<1>(addr) << "!";
                                              continue;
                                          }

                                          auto [ip, port] = addr;
                                          LOG_TRACE << "try to connect: " << ip << ":" << port;

                                          resolver.async_resolve(ip, port,
                                                                 [&, _ip = ip, _port = port](
                                                                         const boost::system::error_code &er,
                                                                         const boost::asio::ip::tcp::resolver::results_type endpoints)
                                                                 {
                                                                     ip::tcp::socket _socket(*data->context);
                                                                     auto socket = std::make_shared<P2PSocket>(
                                                                             std::move(_socket), data->net
                                                                     );

                                                                     auto handshake = std::make_shared<P2PHandshake>(
                                                                             socket, data->handler_manager);
                                                                     handshake->connect(endpoints, std::bind(
                                                                             &P2PNodeClient::client_connected, this,
                                                                             std::placeholders::_1));
                                                                     client_attempts[_ip] = std::move(handshake);
                                                                 });
                                      }
                                      auto_connect();
                                  });
}

std::vector<addr_type> P2PNodeClient::get_good_peers(int max_count)
{
    int t = c2pool::dev::timestamp();

    std::vector<std::pair<float, addr_type>> values;
    for (auto kv : data->addr_store->GetAll())
    {
        values.push_back(
                std::make_pair(
                        -log(max(int64_t(3600), kv.second.last_seen - kv.second.first_seen)) / log(max(int64_t(3600), t - kv.second.last_seen)) * c2pool::random::Expovariate(1),
                        kv.first));
    }

    std::sort(values.begin(), values.end(), [](std::pair<float, addr_type> a, std::pair<float, addr_type> b)
    { return a.first < b.first; });

    values.resize(min((int)values.size(), max_count));
    std::vector<addr_type> result;
    for (auto v : values)
    {
        result.push_back(v.second);
    }
    return result;
}

// P2PNodeServer

bool P2PNodeServer::server_connected(std::shared_ptr<Protocol> protocol)
{
    auto socket_pos = server_attempts.find(protocol->get_socket());
    if (socket_pos != server_attempts.end())
    {
        server_attempts.erase(socket_pos);

        auto [ip, port] = protocol->get_socket()->get_addr();
        server_connections[ip] = protocol;
    } else
    {
        // Socket не найден в server_attempts
    }
}

void P2PNodeServer::listen()
{
    acceptor.async_accept([this](boost::system::error_code ec, ip::tcp::socket _socket)
                          {
                              if (!ec)
                              {
                                  auto socket = std::make_shared<P2PSocket>(std::move(socket),
                                                                             data->net);
                                  auto handshake = std::make_shared<P2PHandshake>(socket, data->handler_manager);
                                  handshake->listen_connection(std::bind(&P2PNodeServer::server_connected, this, std::placeholders::_1));
                                  server_attempts[socket] = handshake;
                              }
                              else
                              {
                                  LOG_ERROR << "P2PNode::listen: " << ec.message();
                              }
                              listen();
                          });
}


