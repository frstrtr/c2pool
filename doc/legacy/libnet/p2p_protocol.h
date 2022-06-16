#pragma once

#include <set>
#include <map>
#include <vector>

#include <btclibs/uint256.h>

#include <libp2p/handler.h>
#include <libp2p/protocol.h>
#include <libcoind/data.h>
#include <libcoind/transaction.h>

#include <boost/asio/io_context.hpp>

class P2PProtocol : public Protocol, ProtocolPinger, public enable_shared_from_this<P2PProtocol>
{
public:
    const int version;

    unsigned int other_version = -1;
    std::string other_sub_version;
    uint64_t other_services;
    unsigned long long _nonce;

public:
    std::set<uint256> remote_tx_hashes;
    int32_t remote_remembered_txs_size = 0;

    std::map<uint256, coind::data::stream::TransactionType_stream> remembered_txs;
    int32_t remembered_txs_size;
    std::vector<std::map<uint256, coind::data::tx_type>> known_txs_cache;
public:
    P2PProtocol(std::shared_ptr<boost::asio::io_context> _context, std::shared_ptr<Socket> _socket,
                HandlerManagerPtr _handler_manager) : Protocol(_socket,
                                                               _handler_manager),
                                                      ProtocolPinger(_context, 100, [&]()
                                                      {
                                                          //TODO: out of ping timer;
                                                          socket->disconnect();
                                                      }),
                                                      version(3301)
    {}


};