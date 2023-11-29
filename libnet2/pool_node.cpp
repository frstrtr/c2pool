#include "pool_node.h"

#include <algorithm>

#include <libdevcore/random.h>
#include <libdevcore/common.h>
#include <libdevcore/types.h>
#include <libdevcore/deferred.h>
#include <sharechains/share.h>

#include "coind_node_data.h"

using namespace pool::messages;

std::vector<NetAddress> PoolNodeClient::get_good_peers(int max_count)
{
	int t = c2pool::dev::timestamp();

	std::vector<std::pair<float, NetAddress>> values;
	for (auto kv : addr_store->GetAll())
	{
		values.push_back(
				std::make_pair(
						-log(max(int64_t(3600), kv.second.last_seen - kv.second.first_seen)) / log(max(int64_t(3600), t - kv.second.last_seen)) * c2pool::random::Expovariate(1),
						kv.first));
	}

	std::sort(values.begin(), values.end(), [](const std::pair<float, NetAddress>& a, std::pair<float, NetAddress> b)
	{ return a.first < b.first; });

	values.resize(min((int)values.size(), max_count));
	std::vector<NetAddress> result;
	for (const auto& v : values)
	{
		result.push_back(v.second);
	}
	return result;
}

void PoolNode::DownloadShareManager::start(const std::shared_ptr<PoolNode> &_node)
{
    node = _node;
    strand = std::make_shared<boost::asio::io_service::strand>(*node->context);
    node->coind_node->desired->changed->subscribe([&](const std::vector<std::tuple<NetAddress, uint256>>& new_value){
        if (new_value.empty())
            return;

        if (is_processing)
        {
            cache_desired = new_value;
            return;
        }

        is_processing = true;
        request_shares(new_value);
    });
}

void PoolNode::handle_message_version(std::shared_ptr<pool::messages::message_version> msg, std::shared_ptr<PoolHandshake> handshake)
{
    LOG_DEBUG_POOL << "handle message_version";
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
        LOG_DEBUG_POOL
			<< "more than one version message";
	}
	if (msg->version.get() < net->MINIMUM_PROTOCOL_VERSION)
	{
        LOG_DEBUG_POOL << "peer too old";
	}

	handshake->other_version = msg->version.get();
	handshake->other_sub_version = msg->sub_version.get();
	handshake->other_services = msg->services.get();

	if (msg->nonce.get() == nonce)
	{
		LOG_WARNING
			<< "was connected to self";
		//TODO: assert
	}

	//detect duplicate in node->peers
	if (peers.find(msg->nonce.get()) != peers.end())
	{

	}
	if (peers.count(msg->nonce.get()) != 0)
	{
		auto addr = handshake->get_socket()->get_addr();
		std::string reason =
			 "[handle_message_version] Detected duplicate connection, disconnecting from "
			+ addr.to_string();
        handshake->disconnect(reason);
		return;
	}

	handshake->nonce = msg->nonce.get();
	//TODO: После получения message_version, ожидание сообщения увеличивается с 10 секунд, до 100.
	//*Если сообщение не было получено в течении этого таймера, то происходит дисконект.


	//TODO: if (p2p_node->advertise_ip):
	//TODO:     раз в random.expovariate(1/100*len(p2p_node->peers.size()+1), отправляется sendAdvertisement()

	auto best_hash = msg->best_share_hash.get();
	if (!best_hash.IsNull())
	{
        LOG_INFO << "Best share hash for " << msg->addr_from.address.get() << ":" << msg->addr_from.port.get() << " = " << best_hash;
		handle_share_hashes({best_hash}, handshake, handshake->get_addr());
	}

    if (coind_node->cur_share_version >= 34)
        return;

    // add_to_remote_view_of_my_known_txs
    auto id_add_to_remote_view_of_my_known_txs = known_txs->added->subscribe([&, _socket = handshake->get_socket()](std::map<uint256, coind::data::tx_type> added){
        if (!added.empty())
        {
            std::vector<uint256> tx_hashes;
            for (auto v : added)
            {
                tx_hashes.push_back(v.first);
            }

            auto msg_have_tx = std::make_shared<message_have_tx>(tx_hashes);
            _socket->write(msg_have_tx);
        }
    });
    handshake->event_disconnect->subscribe([&, _id = id_add_to_remote_view_of_my_known_txs](){ known_txs->added->unsubscribe(_id); });

    // remove_from_remote_view_of_my_known_txs
    auto id_remove_from_remote_view_of_my_known_txs = known_txs->removed->subscribe([&, _socket = handshake->get_socket()](std::map<uint256, coind::data::tx_type> removed)
    {
        if (!removed.empty())
        {
            std::vector<uint256> tx_hashes;
            for (auto v: removed)
            {
                tx_hashes.push_back(v.first);
            }

            auto msg_losing_tx = std::make_shared<message_losing_tx>(tx_hashes);
            _socket->write(msg_losing_tx);

//            // cache forgotten txs here for a little while so latency of "losing_tx" packets doesn't cause problems
//            auto key = std::max_element(handshake->known_txs_cache.begin(), handshake->known_txs_cache.end(), [&](const auto &a, const auto &b){
//               return UintToArith256(a.first) < UintToArith256(b.first);
//            });

            //TODO: ???
            /*
                    # cache forgotten txs here for a little while so latency of "losing_tx" packets doesn't cause problems
                    key = max(self.known_txs_cache) + 1 if self.known_txs_cache else 0
                    self.known_txs_cache[key] = removed #dict((h, before[h]) for h in removed)
                    reactor.callLater(20, self.known_txs_cache.pop, key)
             */
        }
    });
    handshake->event_disconnect->subscribe([&, _id = id_remove_from_remote_view_of_my_known_txs](){ known_txs->removed->unsubscribe(_id); });

    auto id_update_remote_view_of_my_known_txs = known_txs->transitioned->subscribe([&, peer = std::shared_ptr<PoolProtocolData>(handshake), _socket = handshake->get_socket()](std::map<uint256, coind::data::tx_type> before, std::map<uint256, coind::data::tx_type> after){
        std::map<uint256, coind::data::tx_type> added;
        std::set_difference(after.begin(), after.end(), before.begin(), before.end(), std::inserter(added, added.begin()));

        std::map<uint256, coind::data::tx_type> removed;
        std::set_difference(before.begin(), before.end(), after.begin(), after.end(), std::inserter(removed, removed.begin()));

        // ADDED
        if (!added.empty())
        {
            std::vector<uint256> tx_hashes;
            for (auto v : added)
            {
                tx_hashes.push_back(v.first);
            }

            auto msg_have_tx = std::make_shared<message_have_tx>(tx_hashes);
            _socket->write(msg_have_tx);
        }

        // REMOVED
        if (!removed.empty())
        {
            std::vector<uint256> tx_hashes;
            for (auto v: removed)
            {
                tx_hashes.push_back(v.first);
            }

            auto msg_losing_tx = std::make_shared<message_losing_tx>(tx_hashes);
            _socket->write(msg_losing_tx);

            // cache forgotten txs here for a little while so latency of "losing_tx" packets doesn't cause problems
            uint64_t key;
            if (peer->known_txs_cache.empty()){
                key = 0;
            } else
            {
                key = std::max_element(peer->known_txs_cache.begin(), peer->known_txs_cache.end(),
                                               [&](const auto &a, const auto &b)
                                               {
                                                   return a.first < b.first;
                                               })->first + 1;
            }

            std::map<uint256, coind::data::tx_type> value_for_key;
            for (auto h : removed)
            {
                value_for_key[h.first] = before[h.first];
            }
            peer->known_txs_cache[key] = value_for_key;
            // TODO: reactor.callLater(20, self.known_txs_cache.pop, key)
        }
    });
    handshake->event_disconnect->subscribe([&, _id = id_update_remote_view_of_my_known_txs](){ known_txs->transitioned->unsubscribe(_id); });

    {
        std::vector<uint256> tx_hashes;
        for (auto v : known_txs->value())
        {
            tx_hashes.push_back(v.first);
        }
        auto msg_have_tx = std::make_shared<message_have_tx>(tx_hashes);

        handshake->get_socket()->write(msg_have_tx);
    }

    auto id_update_remote_view_of_my_mining_txs = mining_txs->transitioned->subscribe([&, peer = std::shared_ptr<PoolProtocolData>(handshake), socket = handshake->get_socket()] (std::map<uint256, coind::data::tx_type> before, std::map<uint256, coind::data::tx_type> after){
        std::map<uint256, coind::data::tx_type> added;
        std::set_difference(after.begin(), after.end(), before.begin(), before.end(), std::inserter(added, added.begin()));

        std::map<uint256, coind::data::tx_type> removed;
        std::set_difference(before.begin(), before.end(), after.begin(), after.end(), std::inserter(removed, removed.begin()));

        // REMOVED
        if (!removed.empty())
        {
            std::vector<uint256> tx_hashes;
            for (auto v: removed)
            {
                tx_hashes.push_back(v.first);
            }

            auto msg_forget_tx = std::make_shared<message_forget_tx>(tx_hashes);
            socket->write(msg_forget_tx);

            for (auto x : removed)
            {
                PackStream stream;
                coind::data::stream::TransactionType_stream packed_tx(x.second);
                stream << packed_tx;
                peer->remote_remembered_txs_size -= 100 + stream.size();
            }
        }

        // ADDED
        if (!added.empty())
        {
            for (auto x : added)
            {
                PackStream stream;
                coind::data::stream::TransactionType_stream packed_tx(x.second);
                stream << packed_tx;

                peer->remote_remembered_txs_size += 100 + stream.size();
            }

            assert(peer->remote_remembered_txs_size <= peer->max_remembered_txs_size);

            std::vector<uint256> _tx_hashes;
            std::vector<coind::data::tx_type> _txs;

            for (auto x : added)
            {
                if (peer->remote_tx_hashes.find(x.first) != peer->remote_tx_hashes.end())
                {
                    _tx_hashes.push_back(x.first);
                } else {
                    _txs.push_back(x.second);
                }
            }
            LOG_DEBUG_POOL << "_tx_hashes: " << _tx_hashes;
            LOG_DEBUG_POOL << "_txs: " << _txs;
            auto msg_remember_tx = std::make_shared<message_remember_tx>(_tx_hashes, _txs);
            socket->write(msg_remember_tx);
        }
    });
    handshake->event_disconnect->subscribe([&, _id = id_update_remote_view_of_my_mining_txs](){ mining_txs->transitioned->unsubscribe(_id); });

    for (auto x : mining_txs->value())
    {
        PackStream stream;
        coind::data::stream::TransactionType_stream packed_tx(x.second);
        stream << packed_tx;

        handshake->remote_remembered_txs_size += 100 + stream.size();
        assert(handshake->remote_remembered_txs_size <= handshake->max_remembered_txs_size);
    }

    std::vector<uint256> _tx_hashes;
    std::vector<coind::data::tx_type> _txs;

    for (auto x : mining_txs->value())
    {
        _txs.push_back(x.second);
    }
    auto msg_remember_tx = std::make_shared<message_remember_tx>(_tx_hashes, _txs);
    handshake->get_socket()->write(msg_remember_tx);
}

void PoolNode::handle_message_addrs(std::shared_ptr<pool::messages::message_addrs> msg, std::shared_ptr<PoolProtocol> protocol)
{
    for (auto addr_record: msg->addrs.get())
    {
        auto addr = addr_record.get();
        got_addr(NetAddress(addr.address.address, addr.address.port),
                            addr.address.services, std::min((uint32_t) c2pool::dev::timestamp(), addr.timestamp));

        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!peers.empty()))
        {
            auto _proto = c2pool::random::RandomChoice(peers);
            std::vector<::stream::addr_stream> _addrs{addr_record};
            _proto->write(std::make_shared<message_addrs>(_addrs));
        }
    }
}

void PoolNode::handle_message_addrme(std::shared_ptr<pool::messages::message_addrme> msg, std::shared_ptr<PoolProtocol> protocol)
{
    auto host = protocol->get_addr().ip;

    if (host.compare("127.0.0.1") == 0)
    {
        if ((c2pool::random::RandomFloat(0, 1) < 0.8) && (!peers.empty()))
        {
            auto _proto = c2pool::random::RandomChoice(peers);
            _proto->write(std::make_shared<message_addrme>(msg->port.get()));
        }
    } else
    {
        got_addr(NetAddress(host, msg->port.get()), protocol->other_services,
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

void PoolNode::handle_message_ping(std::shared_ptr<pool::messages::message_ping> msg, std::shared_ptr<PoolProtocol> protocol)
{
}

void PoolNode::handle_message_getaddrs(std::shared_ptr<pool::messages::message_getaddrs> msg, std::shared_ptr<PoolProtocol> protocol)
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
                addr(_addr.last_seen, _addr.service, v.ip, v.get_port())
        );
    }

    auto answer_msg = std::make_shared<message_addrs>(_addrs);

//    LOG_TRACE << _addrs[0].address.address << " " << _addrs[0].address.port << " " << _addrs[0].address.services << " " << _addrs[0].timestamp;

    protocol->write(answer_msg);
}

void PoolNode::handle_message_shares(std::shared_ptr<pool::messages::message_shares> msg, std::shared_ptr<PoolProtocol> protocol)
{
    HandleSharesData result; //share, txs
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
        if (wrappedshare.type.get() >= 13 && wrappedshare.type.get() < 34)
        {
            for (auto tx_hash: *share->new_transaction_hashes)
            {
                coind::data::tx_type tx;
                if (known_txs->value().find(tx_hash) != known_txs->value().end())
                {
                    tx = known_txs->value()[tx_hash];
                } else
                {
                    bool flag = true;
                    for (const auto& cache : protocol->known_txs_cache)
                    {
                        if (cache.second.find(tx_hash) != cache.second.end())
                        {
                            tx = cache.second.at(tx_hash);
                            LOG_INFO << boost::format("Transaction %1% rescued from peer latency cache!") % tx_hash.GetHex();
                            flag = false;
                            break;
                        }
                    }
                    if (flag)
                    {
                        std::string reason = (boost::format("Peer referenced unknown transaction %1%, disconnecting") % tx_hash.GetHex()).str();
                        protocol->disconnect(reason);
                        return;
                    }
                }
                txs.push_back(tx);
            }
        }
        result.add(share, txs);
    }

    handle_shares(result, protocol->get_addr());
    //t1
    //TODO: if p2pool.BENCH: print "%8.3f ms for %i shares in handle_shares (%3.3f ms/share)" % ((t1-t0)*1000., len(shares), (t1-t0)*1000./ max(1, len(shares)))
}

void PoolNode::handle_message_sharereq(std::shared_ptr<pool::messages::message_sharereq> msg, std::shared_ptr<PoolProtocol> protocol)
{
    //std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, std::tuple<std::string, std::string> peer_addr
    auto shares = handle_get_shares(msg->hashes.get(), msg->parents.get(), msg->stops.get(), protocol->get_addr());

    std::vector<PackedShareData> _shares;
    try
    {
        for (auto share: shares)
        {
			PackedShareData _data = pack_share(share);
			_shares.push_back(_data);
        }
        auto reply_msg = std::make_shared<message_sharereply>(msg->id.get(), good, _shares);
        protocol->write(reply_msg);
    }
    catch (const std::invalid_argument &e)
    {
		// TODO: check for too_long
        auto reply_msg = std::make_shared<message_sharereply>(msg->id.get(), too_long, std::vector<PackedShareData>{});
        protocol->write(reply_msg);
    }
}

void PoolNode::handle_message_sharereply(std::shared_ptr<pool::messages::message_sharereply> msg, std::shared_ptr<PoolProtocol> protocol)
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
	protocol->get_shares.got_response(msg->id.get(), res);
}

void PoolNode::handle_message_bestblock(std::shared_ptr<pool::messages::message_bestblock> msg, std::shared_ptr<PoolProtocol> protocol)
{
    handle_bestblock(msg->header);
}

void PoolNode::handle_message_have_tx(std::shared_ptr<pool::messages::message_have_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
	auto tx_hashes = msg->tx_hashes.get();
    protocol->remote_tx_hashes.insert(tx_hashes.begin(), tx_hashes.end());
    if (protocol->remote_tx_hashes.size() > 10000)
    {
        protocol->remote_tx_hashes.erase(protocol->remote_tx_hashes.begin(),
                               std::next(protocol->remote_tx_hashes.begin(), protocol->remote_tx_hashes.size() - 10000));
    }
}

void PoolNode::handle_message_losing_tx(std::shared_ptr<pool::messages::message_losing_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    //remove all msg->txs hashes from remote_tx_hashes
    std::set<uint256> losing_txs;
	auto tx_hashes = msg->tx_hashes.get();
    losing_txs.insert(tx_hashes.begin(), tx_hashes.end());

    std::set<uint256> diff_txs;
    std::set_difference(protocol->remote_tx_hashes.begin(), protocol->remote_tx_hashes.end(),
                        losing_txs.begin(), losing_txs.end(),
                        std::inserter(diff_txs, diff_txs.begin()));

    protocol->remote_tx_hashes = diff_txs;
}

void PoolNode::handle_message_remember_tx(std::shared_ptr<pool::messages::message_remember_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    for (auto tx_hash: msg->tx_hashes.get())
    {
        if (protocol->remembered_txs.find(tx_hash) != protocol->remembered_txs.end())
        {
            std::string reason = "[handle_message_remember_tx] Peer referenced transaction twice, disconnecting";
            protocol->disconnect(reason);
            return;
        }

        coind::data::stream::TransactionType_stream tx;
        if (known_txs->value().count(tx_hash))
        {
            tx = known_txs->value()[tx_hash];
        } else
        {
			bool founded_cache = false;
            for (const auto& cache : protocol->known_txs_cache)
            {
                if (cache.second.find(tx_hash) != cache.second.end())
                {
                    tx = cache.second.at(tx_hash);
                    LOG_INFO << "Transaction " << tx_hash.ToString() << " rescued from peer latency cache!";
					founded_cache = true;
                    break;
                }
            }

			if (!founded_cache)
			{
                std::string reason = "[handle_message_remember_tx] Peer referenced unknown transaction " + tx_hash.ToString() + " disconnecting";
                protocol->disconnect(reason);
				return;
			}
        }

		protocol->remembered_txs[tx_hash] = tx;
		PackStream stream;
		stream << tx;
		protocol->remembered_txs_size += 100 + pack<coind::data::stream::TransactionType_stream>(tx).size();
    }

	std::map<uint256, coind::data::tx_type> added_known_txs;
	bool warned = false;
	for (auto _tx : msg->txs.value)
	{
		PackStream stream;
		stream << _tx;
		auto _tx_size = stream.size();
		auto tx_hash = coind::data::hash256(stream, true);

		if (protocol->remembered_txs.find(tx_hash) != protocol->remembered_txs.end())
		{
            std::string reason = "[handle_message_remember_tx] Peer referenced transaction twice, disconnecting";
            protocol->disconnect(reason);
			return;
		}

		if (known_txs->exist(tx_hash) && !warned)
		{
			LOG_WARNING << "Peer sent entire transaction " << tx_hash.ToString() << " that was already received";
			warned = true;
		}

		protocol->remembered_txs[tx_hash] = _tx;
		protocol->remembered_txs_size += 100 + _tx_size;
		added_known_txs[tx_hash] = _tx.get();
	}
    known_txs->add(added_known_txs);

	if (protocol->remembered_txs_size >= protocol->max_remembered_txs_size)
	{
		throw std::runtime_error("too much transaction data stored"); // TODO: custom error
	}
}

void PoolNode::handle_message_forget_tx(std::shared_ptr<pool::messages::message_forget_tx> msg, std::shared_ptr<PoolProtocol> protocol)
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

void PoolNode::start()
{
    LOG_DEBUG_POOL << "PoolNode started!";
    for (const auto &item: tracker->items)
    {
        shared_share_hashes.insert(item.first);
    }
    //TODO: self.node.tracker.removed.watch_weakref(self, lambda self, share: self.shared_share_hashes.discard(share.hash))

    //TODO: if DEBUG_MODE -- WANRING; else -- THROW!
    if (!coind_node)
    {
        LOG_WARNING << "PoolNode::download_shares -- coind_node == nullptr";
        return;
    }

    download_share_manager.start(shared_from_this());

    coind_node->best_block_header->changed->subscribe([&](coind::data::BlockHeaderType header){
        for (auto _peer : peers)
        {
            auto _msg = std::make_shared<message_bestblock>(*header.get());
            _peer.second->write(_msg);
        }
    });

    coind_node->best_share->changed->subscribe([&](uint256 _best_share){
        broadcast_share(_best_share);
    });

    /* TODO
        @self.node.tracker.verified.added.watch
        def _(share):
            if not (share.pow_hash <= share.header['bits'].target):
                return

            def spread():
                if (self.node.get_height_rel_highest(share.header['previous_block']) > -5 or
                    self.node.bitcoind_work.value['previous_block'] in [share.header['previous_block'], share.header_hash]):
                    self.broadcast_share(share.hash)
            spread()
            reactor.callLater(5, spread) # so get_height_rel_highest can update
     */
}

//void PoolNode::download_shares()
//{
//    _download_shares_fiber = c2pool::deferred::Fiber::run(context, [&](const std::shared_ptr<c2pool::deferred::Fiber> &fiber)
//    {
//        auto _node = shared_from_this();
//        LOG_DEBUG_POOL << "Start download_shares!";
//        while (true)
//        {
//            auto desired = _node->coind_node->desired->get_when_satisfies([&](const auto &desired)
//                                                                         {
//                                                                             LOG_DEBUG_POOL << "desired.size() != 0: " << (desired.size() != 0);
//                                                                             return desired.size() != 0;
//                                                                         })->yield(fiber);
//            LOG_DEBUG_POOL << "DOWNLOAD SHARE1";
//            auto [peer_addr, share_hash] = c2pool::random::RandomChoice(desired);
//
//            if (_node->peers.size() == 0)
//            {
//                LOG_WARNING << "download_shares: peers.size() == 0";
//                fiber->sleep(1s);
//                continue;
//            }
//            auto peer = c2pool::random::RandomChoice(_node->peers);
//            auto [peer_ip, peer_port] = peer->get_addr();
//
//            LOG_INFO << "Requesting parent share " << share_hash.GetHex() << " from " << peer_ip << ":" << peer_port;
//
//            std::vector<ShareType> shares;
////            try
////            {
//                std::vector<uint256> stops;
//                {
//                    std::set<uint256> _stops;
//                    for (const auto& s : _node->tracker->heads)
//                    {
//                        _stops.insert(s.first);
//                    }
//
//                    for (const auto& s : _node->tracker->heads)
//                    {
//                        uint256 stop_hash = _node->tracker->get_nth_parent_key(s.first, std::min(std::max(0, _node->tracker->get_height_and_last(s.first).height - 1), 10));
//                        _stops.insert(stop_hash);
//                    }
//                    stops = vector<uint256>{_stops.begin(), _stops.end()};
//                }
//
//                LOG_TRACE << "Stops: " << stops;
//
//                shares = peer->get_shares.yield(fiber,
//                                                     std::vector<uint256>{share_hash},
//                                                     (uint64_t)c2pool::random::RandomInt(0, 500), //randomize parents so that we eventually get past a too large block of shares
//                                                     stops
//                                                     );
////            }
//            //TODO: catch: timeout/any error
//
//            if (shares.empty())
//            {
//                fiber->sleep(1s);
//                continue;
//            }
//
//            HandleSharesData _shares;
//            for (auto& _share : shares)
//            {
//                _shares.add(_share, {});
//            }
//
////            PreparedList prepare_shares(shares);
////            for (auto& fork : prepare_shares.forks)
////            {
////                auto share_node = fork->tail;
////                while (share_node)
////                {
////                    post_shares.add(share_node->value, {});
////                    share_node = share_node->next;
////                }
////            }
//
//            _node->handle_shares(_shares, peer->get_addr());
//            fiber->sleep(500ms);
//        }
//    });
//}

void PoolNode::init_web_metrics()
{
    LOG_DEBUG_POOL << "PoolNode::init_web_metrics -- started: " << c2pool::dev::timestamp();

    //---> add metrics
//    peers_metric = net->web->add<peers_metric_type>("peers", nlohmann::json{{"in", 0}, {"out", 0}});
    peers_metric = net->web->add<peers_metric_type>("peers", [&](auto& j){
        int in = 0, out = 0;
        for (const auto&[k, v]:peers)
        {
            switch (v->get_socket()->get_type())
            {
                case connection_type::incoming:
                    ++in;
                    break;
                case connection_type::outgoing:
                    ++out;
                    break;
                default:
                    break;
            }
        }
        j["in"] = in;
        j["out"] = out;
    });

    current_payouts_metric = net->web->add<current_payouts_metric_type>("current_payouts", [&](nlohmann::json &j){
        for (const auto &[script, value] : tracker->get_expected_payouts(best_share->value(), FloatingInteger(coind_node->coind_work->value().bits).target(), coind_node->coind_work->value().subsidy))
        {
            LOG_INFO.stream() << "script: " << script << ", value: " << value;
            j[coind::data::script2_to_address(PackStream{script}, net->parent->ADDRESS_VERSION, -1, net)] = (value/1e8);
        }
    });
//    stale_counts_metric = net->web->add<stale_counts_metric_type>("stale_counts");
//    stale_rate_metric = net->web->add<stale_rate_metric_type>("stale_rate");

    //---> subs for metrics
//    best_share.changed->subscribe([&](const uint256& hash){
//        auto share = tracker->get(hash);
//        if (!share)
//        {
//            LOG_ERROR << hash << " not found in tracker";
//            return;
//        }
//
//        shares_stale_count el;
//        auto avg_attempts = coind::data::target_to_average_attempts(share->target);
//
//        el.good = avg_attempts;
//        if (*share->stale_info != unk)
//        {
//            switch (*share->stale_info)
//            {
//                case orphan:
//                    el.orphan = avg_attempts;
//                    break;
//                case doa:
//                    el.doa = avg_attempts;
//                    break;
//                default:
//                    break;
//            }
//        }
//
//        //------> stale_count
//        stale_counts_metric->add(el);
//        //------> stale_rate
//        stale_rate_metric->add(el, *share->timestamp);
//
//    });


    LOG_DEBUG_POOL << "PoolNode::init_web_metrics -- finished: " << c2pool::dev::timestamp();
}
