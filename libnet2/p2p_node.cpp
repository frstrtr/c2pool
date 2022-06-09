#include "p2p_node.h"

#include <libdevcore/random.h>

std::vector<addr_type> P2PNodeClient::get_good_peers(int max_count)
{
	int t = c2pool::dev::timestamp();

	std::vector<std::pair<float, addr_type>> values;
	for (auto kv : addr_store->GetAll())
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

void P2PNode::handle_message_version(std::shared_ptr<P2PHandshake> handshake,
                                     std::shared_ptr<net::messages::message_version> msg)
{
    LOG_DEBUG
        << "handle message_version";
    LOG_INFO << "Peer "
             << msg->addr_from.address.get()
             << ":"
             << msg->addr_from.port.get()
             << " says protocol version is "
             << msg->version.get()
             << ", client version "
             << msg->sub_version.get();

    if (handshake->other_version.has_value())
    {
        LOG_DEBUG
            << "more than one version message";
    }
    if (msg->version.get() <
        net->MINIMUM_PROTOCOL_VERSION)
    {
        LOG_DEBUG
            << "peer too old";
    }

    handshake->other_version = msg->version.get();
    handshake->other_sub_version = msg->sub_version.get();
    handshake->other_services = msg->services.get();

    if (msg->nonce.get() ==
        nonce)
    {
        LOG_WARNING
            << "was connected to self";
        //TODO: assert
    }

    //detect duplicate in node->peers
    if (peers.find(msg->nonce.get()) !=
        peers.end())
    {

    }
    if (peers.count(
            msg->nonce.get()) != 0)
    {
        auto addr = handshake->get_socket()->get_addr();
        LOG_WARNING
            << "Detected duplicate connection, disconnecting from "
            << std::get<0>(addr)
            << ":"
            << std::get<1>(addr);
        handshake->get_socket()->disconnect();
        return;
    }

    handshake->nonce = msg->nonce.get();
    //TODO: После получения message_version, ожидание сообщения увеличивается с 10 секунд, до 100.
    //*Если сообщение не было получено в течении этого таймера, то происходит дисконект.

//                                                                                                    socket->ping_timer.expires_from_now(
//                                                                                                            boost::asio::chrono::seconds(
//                                                                                                                    (int) c2pool::random::Expovariate(
//                                                                                                                            1.0 /
//                                                                                                                            100)));
//                                                                                                    _socket->ping_timer.async_wait(
//                                                                                                            boost::bind(
//                                                                                                                    &P2P_Protocol::ping_timer_func,
//                                                                                                                    this,
//                                                                                                                    _1));

    //TODO: if (p2p_node->advertise_ip):
    //TODO:     раз в random.expovariate(1/100*len(p2p_node->peers.size()+1), отправляется sendAdvertisement()

    //TODO: msg->best_share_hash != nullptr: p2p_node.handle_share_hashes(...)

    //TODO: <Методы для обработки транзакций>: send_have_tx; send_remember_tx
}

void P2PNode::handle(std::shared_ptr<net::messages::message_addrs> msg, std::shared_ptr<P2PProtocol> protocol)
{
    for (auto addr_record: msg->addrs.get())
    {
        auto addr = addr_record.get();
        _p2p_node->got_addr(std::make_tuple(addr.address.address, std::to_string(addr.address.port)),
                            addr.address.services, std::min((int64_t) dev::timestamp(), addr.timestamp));

        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!_p2p_node->get_peers().empty()))
        {
            auto _proto = c2pool::random::RandomChoice(_p2p_node->get_peers());
            std::vector<c2pool::messages::stream::addr_stream> _addrs{addr_record};
            _proto->write(make_message<message_addrs>(_addrs));
        }
    }
}

void P2PNode::handle(std::shared_ptr<net::messages::message_addrme> msg, std::shared_ptr<P2PProtocol> protocol)
{
    auto host = std::get<0>(_socket->get_addr());

    if (host.compare("127.0.0.1") == 0)
    {
        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!_p2p_node->get_peers().empty()))
        {
            auto _proto = c2pool::random::RandomChoice(_p2p_node->get_peers());
            _proto->write(make_message<message_addrme>(msg->port.get()));
        }
    } else
    {
        _p2p_node->got_addr(std::make_tuple(host, std::to_string(msg->port.get())), other_services,
                            dev::timestamp());
        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!_p2p_node->get_peers().empty()))
        {
            auto _proto = c2pool::random::RandomChoice(_p2p_node->get_peers());
            std::vector<c2pool::messages::addr> _addrs{
                    c2pool::messages::addr(dev::timestamp(), other_services, host, msg->port.get())
            };
            _proto->write(make_message<message_addrs>(_addrs));
        }
    }
}

void P2PNode::handle(std::shared_ptr<net::messages::message_ping> msg, std::shared_ptr<P2PProtocol> protocol)
{

}

void P2PNode::handle(std::shared_ptr<net::messages::message_getaddrs> msg, std::shared_ptr<P2PProtocol> protocol)
{
    uint32_t count = msg->count.get();
    if (count > 100)
    {
        count = 100;
    }

    std::vector<c2pool::messages::addr> _addrs;
    for (auto v: _p2p_node->get_good_peers(count))
    {
        auto _addr = _p2p_node->get_addr_store()->Get(v);
        _addrs.push_back(
                c2pool::messages::addr(_addr.last_seen,
                                       _addr.service, std::get<0>(v), dev::str_to_int<int>(std::get<1>(v)))
        );
    }

    write(make_message<message_addrs>(_addrs));
}

void P2PNode::handle(std::shared_ptr<net::messages::message_shares> msg, std::shared_ptr<P2PProtocol> protocol)
{
    //t0
    vector<tuple<ShareType, std::vector<coind::data::tx_type>>> result; //share, txs
    for (auto wrappedshare: msg->raw_shares.get())
    {
        // TODO: move all supported share version in network setting
        if (wrappedshare.type.get() < 17)
            continue;

        //TODO: optimize
        PackStream stream_wrappedshare;
        stream_wrappedshare << wrappedshare;
        auto share = load_share(stream_wrappedshare, _net, _socket->get_addr());

        std::vector<coind::data::tx_type> txs;
        if (wrappedshare.type.get() >= 13)
        {
            for (auto tx_hash: *share->new_transaction_hashes)
            {
                coind::data::tx_type tx;
                if (_p2p_node->known_txs.value().find(tx_hash) != _p2p_node->known_txs.value().end())
                {
                    tx = _p2p_node->known_txs.value()[tx_hash];
                } else
                {
                    for (auto cache : known_txs_cache)
                    {
                        if (cache.find(tx_hash) != cache.end())
                        {
                            tx = cache[tx_hash];
                            LOG_INFO << boost::format("Transaction %0% rescued from peer latency cache!") % tx_hash.GetHex();
                            break;
                        }
                    }
                }
                txs.push_back(tx);
            }
        }
        result.emplace_back(share, txs);
    }

    _p2p_node->handle_shares(result, shared_from_this());
    //t1
    //TODO: if p2pool.BENCH: print "%8.3f ms for %i shares in handle_shares (%3.3f ms/share)" % ((t1-t0)*1000., len(shares), (t1-t0)*1000./ max(1, len(shares)))
}

void P2PNode::handle(std::shared_ptr<net::messages::message_sharereq> msg, std::shared_ptr<P2PProtocol> protocol)
{
    //std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, std::tuple<std::string, std::string> peer_addr
    auto shares = _p2p_node->handle_get_shares(msg->hashes.get(), msg->parents.get(), msg->stops.get(), _socket->get_addr());

    std::vector<PackedShareData> _shares;
    try
    {
        for (auto share: shares)
        {
            //TODO: share->PackedShareData
//                    auto contents = share->to_contents();
//                    share_type _share(share->SHARE_VERSION, contents.write());
//                    _shares.push_back(_share);
        }
        auto reply_msg = make_message<message_sharereply>(msg->id.get(), good, _shares);
        write(reply_msg);
    }
    catch (const std::invalid_argument &e)
    {
        auto reply_msg = make_message<message_sharereply>(msg->id.get(), too_long, _shares);
        write(reply_msg);
    }
}

void P2PNode::handle(std::shared_ptr<net::messages::message_sharereply> msg, std::shared_ptr<P2PProtocol> protocol)
{
    std::vector<ShareType> res;
    if (msg->result.get() == ShareReplyResult::good)
    {
        for (auto content: msg->shares.get())
        {
            if (content.type.get() >= 17) //TODO: 17 = minimum share version; move to macros
            {
                //TODO: optimize
                PackStream stream_content;
                stream_content << content;
                ShareType _share = load_share(stream_content, _net, _socket->get_addr());
                res.push_back(_share);
            }
        }
    } else
    {
        //TODO: res = failure.Failure(self.ShareReplyError(result))
    }
    //TODO: self.get_shares.got_response(id, res)
}

void P2PNode::handle(std::shared_ptr<net::messages::message_bestblock> msg, std::shared_ptr<P2PProtocol> protocol)
{
    _p2p_node->handle_bestblock(msg->header);
}

void P2PNode::handle(std::shared_ptr<net::messages::message_have_tx> msg, std::shared_ptr<P2PProtocol> protocol)
{
    remote_tx_hashes.insert(msg->tx_hashes.get().begin(), msg->tx_hashes.get().end());
    if (remote_tx_hashes.size() > 10000)
    {
        remote_tx_hashes.erase(remote_tx_hashes.begin(),
                               std::next(remote_tx_hashes.begin(), remote_tx_hashes.size() - 10000));
    }
}

void P2PNode::handle(std::shared_ptr<net::messages::message_losing_tx> msg, std::shared_ptr<P2PProtocol> protocol)
{
    //remove all msg->txs hashes from remote_tx_hashes
    std::set<uint256> losing_txs;
    losing_txs.insert(msg->tx_hashes.get().begin(), msg->tx_hashes.get().end());

    std::set<uint256> diff_txs;
    std::set_difference(remote_tx_hashes.begin(), remote_tx_hashes.end(),
                        losing_txs.begin(), losing_txs.end(),
                        std::inserter(diff_txs, diff_txs.begin()));

    remote_tx_hashes = diff_txs;
}

void P2PNode::handle(std::shared_ptr<net::messages::message_remember_tx> msg, std::shared_ptr<P2PProtocol> protocol)
{
    for (auto tx_hash: msg->tx_hashes.get())
    {
        if (remembered_txs.find(tx_hash) != remembered_txs.end())
        {
            LOG_WARNING << "Peer referenced transaction twice, disconnecting";
            _socket->disconnect();
            return;
        }

        coind::data::stream::TransactionType_stream tx;
        if (_p2p_node->known_txs.value().find(tx_hash) != _p2p_node->known_txs.value().end())
        {
            tx = _p2p_node->known_txs.value()[tx_hash];
        } else
        {
            for (auto cache : known_txs_cache)
            {
                if (cache.find(tx_hash) != cache.end())
                {
                    tx = cache[tx_hash];
                    LOG_INFO << "Transaction " << tx_hash.ToString() << " rescued from peer latency cache!";
                    break;
                } else
                {
                    LOG_WARNING << "Peer referenced unknown transaction " << tx_hash.ToString() << " disconnecting";
                    _socket->disconnect();
                    return;
                }
            }
        }
    }

//            if (remembered_txs_size >= max_remembered_txs_size)
//            {
//                throw std::runtime_error("too much transaction data stored!");
//            }
}

void P2PNode::handle(std::shared_ptr<net::messages::message_forget_tx> msg, std::shared_ptr<P2PProtocol> protocol)
{
    for (auto tx_hash : msg->tx_hashes.get())
    {
        PackStream stream;
        stream << remembered_txs[tx_hash];
        remembered_txs_size -= 100 + stream.size();
        assert(remembered_txs_size >= 0);
        remembered_txs.erase(tx_hash);
    }
}
