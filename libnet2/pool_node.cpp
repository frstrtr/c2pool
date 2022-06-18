#include "pool_node.h"

#include <libdevcore/random.h>
#include <libdevcore/common.h>
#include <libdevcore/types.h>
#include <sharechains/share.h>

using namespace pool::messages;

std::vector<ShareType> PoolNodeData::handle_get_shares(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops,
                                                       addr_type peer_addr)
{
    parents = std::min(parents, 1000/hashes.size());
    std::vector<ShareType> shares;
    for (auto share_hash : hashes)
    {
        uint64_t n = std::min(parents+1, (uint64_t)tracker->get_height(share_hash));
        auto get_chain_func = tracker->get_chain(share_hash, n);

        uint256 _hash;
        while(get_chain_func(_hash))
        {
            if (std::find(stops.begin(), stops.end(), _hash) != stops.end())
                break;
            shares.push_back(tracker->get(_hash));
        }
    }

    if (shares.size() > 0)
    {
        LOG_INFO << "Sending " << shares.size() << " shares to " << std::get<0>(peer_addr) << ":" << std::get<1>(peer_addr);
    }
    return shares;
}

void PoolNodeData::handle_bestblock(coind::data::stream::BlockHeaderType_stream header)
{
    PackStream packed_header;
    packed_header << header;

    if (net->parent->POW_FUNC(packed_header) > header.bits.bits.target())
    {
        throw std::invalid_argument("received block header fails PoW test");
    }

    auto _header = coind::data::BlockHeaderType();
    _header.set_stream(header);

    //TODO: _coind_node->handle_header(_header);
}

void PoolNodeData::handle_shares(vector<tuple<ShareType, std::vector<coind::data::tx_type>>> shares,
                                 std::shared_ptr<PoolProtocol> peer)
{
    //TODO: finish
}

std::vector<addr_type> PoolNodeClient::get_good_peers(int max_count)
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

void PoolNode::handle_message_version(std::shared_ptr<PoolHandshake> handshake,
                                     std::shared_ptr<pool::messages::message_version> msg)
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

void PoolNode::handle(std::shared_ptr<pool::messages::message_addrs> msg, std::shared_ptr<PoolProtocol> protocol)
{
    for (auto addr_record: msg->addrs.get())
    {
        auto addr = addr_record.get();
        got_addr(std::make_tuple(addr.address.address, std::to_string(addr.address.port)),
                            addr.address.services, std::min((int64_t) c2pool::dev::timestamp(), addr.timestamp));

        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!peers.empty()))
        {
            auto _proto = c2pool::random::RandomChoice(peers);
            std::vector<::stream::addr_stream> _addrs{addr_record};
            _proto->write(std::make_shared<message_addrs>(_addrs));
        }
    }
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_addrme> msg, std::shared_ptr<PoolProtocol> protocol)
{
    auto host = std::get<0>(protocol->get_addr());

    if (host.compare("127.0.0.1") == 0)
    {
        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!peers.empty()))
        {
            auto _proto = c2pool::random::RandomChoice(peers);
            _proto->write(std::make_shared<message_addrme>(msg->port.get()));
        }
    } else
    {
        got_addr(std::make_tuple(host, std::to_string(msg->port.get())), protocol->other_services,
                            c2pool::dev::timestamp());
        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!peers.empty()))
        {
            auto _proto = c2pool::random::RandomChoice(peers);
            std::vector<addr> _addrs{
                    addr(c2pool::dev::timestamp(), protocol->other_services, host, msg->port.get())
            };
            _proto->write(std::make_shared<message_addrs>(_addrs));
        }
    }
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_ping> msg, std::shared_ptr<PoolProtocol> protocol)
{

}

void PoolNode::handle(std::shared_ptr<pool::messages::message_getaddrs> msg, std::shared_ptr<PoolProtocol> protocol)
{
    uint32_t count = msg->count.get();
    if (count > 100)
    {
        count = 100;
    }

    std::vector<addr> _addrs;
    for (auto v: get_good_peers(count))
    {
        auto _addr = addr_store->Get(v);
        _addrs.push_back(
                addr(_addr.last_seen,
                                       _addr.service, std::get<0>(v), c2pool::dev::str_to_int<int>(std::get<1>(v)))
        );
    }

    protocol->write(std::make_shared<message_addrs>(_addrs));
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_shares> msg, std::shared_ptr<PoolProtocol> protocol)
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
        auto share = load_share(stream_wrappedshare, net, protocol->get_addr());

        std::vector<coind::data::tx_type> txs;
        if (wrappedshare.type.get() >= 13)
        {
            for (auto tx_hash: *share->new_transaction_hashes)
            {
                coind::data::tx_type tx;
                if (known_txs.value().find(tx_hash) != known_txs.value().end())
                {
                    tx = known_txs.value()[tx_hash];
                } else
                {
                    for (auto cache : protocol->known_txs_cache)
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

    handle_shares(result, protocol);
    //t1
    //TODO: if p2pool.BENCH: print "%8.3f ms for %i shares in handle_shares (%3.3f ms/share)" % ((t1-t0)*1000., len(shares), (t1-t0)*1000./ max(1, len(shares)))
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_sharereq> msg, std::shared_ptr<PoolProtocol> protocol)
{
    //std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, std::tuple<std::string, std::string> peer_addr
    auto shares = handle_get_shares(msg->hashes.get(), msg->parents.get(), msg->stops.get(), protocol->get_addr());

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
        auto reply_msg = std::make_shared<message_sharereply>(msg->id.get(), good, _shares);
        protocol->write(reply_msg);
    }
    catch (const std::invalid_argument &e)
    {
        auto reply_msg = std::make_shared<message_sharereply>(msg->id.get(), too_long, _shares);
        protocol->write(reply_msg);
    }
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_sharereply> msg, std::shared_ptr<PoolProtocol> protocol)
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
                ShareType _share = load_share(stream_content, net, protocol->get_addr());
                res.push_back(_share);
            }
        }
    } else
    {
        //TODO: res = failure.Failure(self.ShareReplyError(result))
    }
    //TODO: self.get_shares.got_response(id, res)
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_bestblock> msg, std::shared_ptr<PoolProtocol> protocol)
{
    handle_bestblock(msg->header);
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_have_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    protocol->remote_tx_hashes.insert(msg->tx_hashes.get().begin(), msg->tx_hashes.get().end());
    if (protocol->remote_tx_hashes.size() > 10000)
    {
        protocol->remote_tx_hashes.erase(protocol->remote_tx_hashes.begin(),
                               std::next(protocol->remote_tx_hashes.begin(), protocol->remote_tx_hashes.size() - 10000));
    }
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_losing_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    //remove all msg->txs hashes from remote_tx_hashes
    std::set<uint256> losing_txs;
    losing_txs.insert(msg->tx_hashes.get().begin(), msg->tx_hashes.get().end());

    std::set<uint256> diff_txs;
    std::set_difference(protocol->remote_tx_hashes.begin(), protocol->remote_tx_hashes.end(),
                        losing_txs.begin(), losing_txs.end(),
                        std::inserter(diff_txs, diff_txs.begin()));

    protocol->remote_tx_hashes = diff_txs;
}

void PoolNode::handle(std::shared_ptr<pool::messages::message_remember_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    for (auto tx_hash: msg->tx_hashes.get())
    {
        if (protocol->remembered_txs.find(tx_hash) != protocol->remembered_txs.end())
        {
            LOG_WARNING << "Peer referenced transaction twice, disconnecting";
            protocol->get_socket()->disconnect();
            return;
        }

        coind::data::stream::TransactionType_stream tx;
        if (known_txs.value().find(tx_hash) != known_txs.value().end())
        {
            tx = known_txs.value()[tx_hash];
        } else
        {
            for (auto cache : protocol->known_txs_cache)
            {
                if (cache.find(tx_hash) != cache.end())
                {
                    tx = cache[tx_hash];
                    LOG_INFO << "Transaction " << tx_hash.ToString() << " rescued from peer latency cache!";
                    break;
                } else
                {
                    LOG_WARNING << "Peer referenced unknown transaction " << tx_hash.ToString() << " disconnecting";
                    protocol->get_socket()->disconnect();
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

void PoolNode::handle(std::shared_ptr<pool::messages::message_forget_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    for (auto tx_hash : msg->tx_hashes.get())
    {
        PackStream stream;
        stream << protocol->remembered_txs[tx_hash];
        protocol->remembered_txs_size -= 100 + stream.size();
        assert(protocol->remembered_txs_size >= 0);
        protocol->remembered_txs.erase(tx_hash);
    }
}
