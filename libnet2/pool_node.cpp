#include "pool_node.h"

#include <algorithm>

#include <libdevcore/random.h>
#include <libdevcore/common.h>
#include <libdevcore/types.h>
#include <libdevcore/deferred.h>
#include <sharechains/share.h>

#include "coind_node_data.h"

using namespace pool::messages;

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
	LOG_DEBUG << "handle message_version";
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
	if (msg->version.get() < net->MINIMUM_PROTOCOL_VERSION)
	{
		LOG_DEBUG << "peer too old";
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


	//TODO: if (p2p_node->advertise_ip):
	//TODO:     раз в random.expovariate(1/100*len(p2p_node->peers.size()+1), отправляется sendAdvertisement()

	auto best_hash = msg->best_share_hash.get();
	if (!best_hash.IsNull())
	{
        LOG_INFO << "Best share hash for " << msg->addr_from.address.get() << ":" << msg->addr_from.port.get() << " = " << best_hash;
		handle_share_hashes({best_hash}, handshake, handshake->get_addr());
	}

    // add_to_remote_view_of_my_known_txs
    auto id_add_to_remote_view_of_my_known_txs = known_txs.added->subscribe([&, _socket = handshake->get_socket()](std::map<uint256, coind::data::tx_type> added){
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

    //TODO: EVENT for connection_lost: self.connection_lost_event.watch(lambda: self.node.known_txs_var.added.unwatch(watch_id0))

    // remove_from_remote_view_of_my_known_txs
    auto id_remove_from_remote_view_of_my_known_txs = known_txs.removed->subscribe([&, _socket = handshake->get_socket()](std::map<uint256, coind::data::tx_type> removed)
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

    //TODO: EVENT for connection_lost: self.connection_lost_event.watch(lambda: self.node.known_txs_var.removed.unwatch(watch_id1))


    auto id_update_remote_view_of_my_known_txs = known_txs.transitioned->subscribe([&, _socket = handshake->get_socket()](std::map<uint256, coind::data::tx_type> before, std::map<uint256, coind::data::tx_type> after){
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
            if (handshake->known_txs_cache.empty()){
                key = 0;
            } else
            {
                key = std::max_element(handshake->known_txs_cache.begin(), handshake->known_txs_cache.end(),
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
            handshake->known_txs_cache[key] = value_for_key;
            // TODO: reactor.callLater(20, self.known_txs_cache.pop, key)
        }
    });

    //TODO: EVENT for connection_lost: self.connection_lost_event.watch(lambda: self.node.known_txs_var.transitioned.unwatch(watch_id2))


    {
        std::vector<uint256> tx_hashes;
        for (auto v : known_txs.value())
        {
            tx_hashes.push_back(v.first);
        }
        auto msg_have_tx = std::make_shared<message_have_tx>(tx_hashes);

        handshake->get_socket()->write(msg_have_tx);
    }

    auto id_update_remote_view_of_my_mining_txs = mining_txs.transitioned->subscribe([&, socket = handshake->get_socket()] (std::map<uint256, coind::data::tx_type> before, std::map<uint256, coind::data::tx_type> after){
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

                handshake->remote_remembered_txs_size -= 100 + stream.size();
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

                handshake->remote_remembered_txs_size += 100 + stream.size();
            }

            assert(handshake->remote_remembered_txs_size <= handshake->max_remembered_txs_size);

            std::vector<uint256> _tx_hashes;
            std::vector<coind::data::tx_type> _txs;

            for (auto x : added)
            {
                if (handshake->remote_tx_hashes.find(x.first) != handshake->remote_tx_hashes.end())
                {
                    _tx_hashes.push_back(x.first);
                } else {
                    _txs.push_back(x.second);
                }
            }
            auto msg_remember_tx = std::make_shared<message_remember_tx>(_tx_hashes, _txs);
            socket->write(msg_remember_tx);
        }
    });
    //TODO: EVENT for connection_lost: self.connection_lost_event.watch(lambda: self.node.mining_txs_var.transitioned.unwatch(watch_id2))

    for (auto x : mining_txs.value())
    {
        PackStream stream;
        coind::data::stream::TransactionType_stream packed_tx(x.second);
        stream << packed_tx;

        handshake->remote_remembered_txs_size += 100 + stream.size();
        assert(handshake->remote_remembered_txs_size <= handshake->max_remembered_txs_size);
    }

    std::vector<uint256> _tx_hashes;
    std::vector<coind::data::tx_type> _txs;

    for (auto x : mining_txs.value())
    {
        _txs.push_back(x.second);
    }
    auto msg_remember_tx = std::make_shared<message_remember_tx>(_tx_hashes, _txs);
    handshake->get_socket()->write(msg_remember_tx);
}

void PoolNode::handle_message_addrs(std::shared_ptr<pool::messages::message_addrs> msg, std::shared_ptr<PoolProtocol> protocol)
{
	LOG_TRACE << "HANDLE MESSAGE_ADDRS";
    for (auto addr_record: msg->addrs.get())
    {
        auto addr = addr_record.get();
        got_addr(std::make_tuple(addr.address.address, std::to_string(addr.address.port)),
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

void PoolNode::handle_message_ping(std::shared_ptr<pool::messages::message_ping> msg, std::shared_ptr<PoolProtocol> protocol)
{
	LOG_DEBUG << "PING!";
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
                addr(_addr.last_seen,
                                       _addr.service, std::get<0>(v), c2pool::dev::str_to_int<int>(std::get<1>(v)))
        );
    }

    auto answer_msg = std::make_shared<message_addrs>(_addrs);

    std::cout << _addrs[0].address.address << " " << _addrs[0].address.port << " " << _addrs[0].address.services << " " << _addrs[0].timestamp << std::endl;

    protocol->write(answer_msg);
}

void PoolNode::handle_message_shares(std::shared_ptr<pool::messages::message_shares> msg, std::shared_ptr<PoolProtocol> protocol)
{
//    return;
    //t0

    LOG_INFO << "HANDLESHARES";
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
                if (known_txs._value->find(tx_hash) != known_txs._value->end())
                {
                    std::cout << tx_hash.GetHex() << std::endl;
                    std::cout << "known_txs: " << std::endl;
                    for (auto v : *known_txs._value)
                        std::cout << v.first.GetHex() << std::endl;
                    tx = known_txs._value->at(tx_hash);
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
                        LOG_ERROR << boost::format("Peer referenced unknown transaction %1%, disconnecting") % tx_hash.GetHex();
                        //TODO: disconnect
                        return;
                    }
                }
                txs.push_back(tx);
            }
        }
        result.emplace_back(share, txs);
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
    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        if (!v.second.tx)
            assert(false);
    }

	auto tx_hashes = msg->tx_hashes.get();
    protocol->remote_tx_hashes.insert(tx_hashes.begin(), tx_hashes.end());
    if (protocol->remote_tx_hashes.size() > 10000)
    {
        protocol->remote_tx_hashes.erase(protocol->remote_tx_hashes.begin(),
                               std::next(protocol->remote_tx_hashes.begin(), protocol->remote_tx_hashes.size() - 10000));
    }

    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        if (!v.second.tx)
            assert(false);
    }
}

void PoolNode::handle_message_losing_tx(std::shared_ptr<pool::messages::message_losing_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        if (!v.second.tx)
            assert(false);
    }

    //remove all msg->txs hashes from remote_tx_hashes
    std::set<uint256> losing_txs;
	auto tx_hashes = msg->tx_hashes.get();
    losing_txs.insert(tx_hashes.begin(), tx_hashes.end());

    std::set<uint256> diff_txs;
    std::set_difference(protocol->remote_tx_hashes.begin(), protocol->remote_tx_hashes.end(),
                        losing_txs.begin(), losing_txs.end(),
                        std::inserter(diff_txs, diff_txs.begin()));

    protocol->remote_tx_hashes = diff_txs;

    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        if (!v.second.tx)
            assert(false);
    }
}

void PoolNode::handle_message_remember_tx(std::shared_ptr<pool::messages::message_remember_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        if (!v.second.tx)
            assert(false);
    }

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
				LOG_WARNING << "Peer referenced unknown transaction " << tx_hash.ToString() << " disconnecting";
				protocol->get_socket()->disconnect();
				return;
			}
        }

        if (!tx.get())
            assert(false);

		protocol->remembered_txs[tx_hash] = tx;
		PackStream stream;
		stream << tx;
		protocol->remembered_txs_size += 100 + stream.size();
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
			LOG_WARNING << "Peer referenced transaction twice, disconnecting";
			protocol->get_socket()->disconnect();
			return;
		}

		if (known_txs.exist(tx_hash) && !warned)
		{
			LOG_WARNING << "Peer sent entire transaction " << tx_hash.ToString() << " that was already received";
			warned = true;
		}

        if (!_tx.get())
            assert(false);

		protocol->remembered_txs[tx_hash] = _tx;
		protocol->remembered_txs_size += 100 + _tx_size;
		added_known_txs[tx_hash] = _tx.get();
	}

	if (protocol->remembered_txs_size >= protocol->max_remembered_txs_size)
	{
		throw std::runtime_error("too much transaction data stored"); // TODO: custom error
	}

    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        if (!v.second.tx)
            assert(false);
    }
}

void PoolNode::handle_message_forget_tx(std::shared_ptr<pool::messages::message_forget_tx> msg, std::shared_ptr<PoolProtocol> protocol)
{
    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        LOG_INFO << "\n" <<  v.first.GetHex() << "\n";
        if (!v.second.tx)
            assert(false);
    }

    for (auto tx_hash : msg->tx_hashes.get())
    {
        PackStream stream;
        LOG_INFO << "FOR DEBUG TX_HASH = " << tx_hash.GetHex();
        stream << protocol->remembered_txs[tx_hash];
        protocol->remembered_txs_size -= 100 + stream.size();
        assert(protocol->remembered_txs_size >= 0);
        protocol->remembered_txs.erase(tx_hash);
    }

    LOG_INFO << "PROTOCOL: " << protocol.get();
    for (auto v : protocol->remembered_txs)
    {
        if (!v.second.tx)
            assert(false);
    }
}

void PoolNode::start()
{
    LOG_DEBUG << "PoolNode started!";
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

    download_shares();

    coind_node->best_block_header.changed->subscribe([&](coind::data::BlockHeaderType header){
        for (auto _peer : peers)
        {
            auto _msg = std::make_shared<message_bestblock>(*header.get());
            _peer.second->write(_msg);
        }
    });

    coind_node->best_share.changed->subscribe([&](uint256 _best_share){
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

void PoolNode::download_shares()
{
    std::cout << "===============================" <<  this << " " << (this == nullptr) << " " << this->nonce << std::endl;
    _download_shares_fiber = c2pool::deferred::Fiber::run(context, [&](const std::shared_ptr<c2pool::deferred::Fiber> &fiber)
    {
        auto _node = shared_from_this();
        LOG_DEBUG << "Start download_shares!";
        while (true)
        {
            std::cout << _node << " " << (_node == nullptr) << " " << _node->nonce << std::endl;
            auto desired = _node->coind_node->desired.get_when_satisfies([&](const auto &desired)
                                                                  {
                std::cout << "SATISFIES!" << std::endl;
                                                                      return desired.size() != 0;
                                                                  })->yield(fiber);
            auto [peer_addr, share_hash] = c2pool::random::RandomChoice(desired);
            std::cout << _node << " " << (_node == nullptr) << " " << _node->nonce << std::endl;

            if (_node->peers.size() == 0)
            {
                LOG_WARNING << "download_shares: peers.size() == 0";
                fiber->sleep(1s);
                continue;
            }
            auto peer = c2pool::random::RandomChoice(_node->peers);
            auto [peer_ip, peer_port] = peer->get_addr();

            LOG_INFO << "Requesting parent share " << share_hash.GetHex() << " from " << peer_ip << ":" << peer_port;

            std::vector<ShareType> shares;
//            try
//            {
                std::vector<uint256> stops;
                {
                    std::set<uint256> _stops;
                    for (auto s : _node->tracker->heads)
                    {
                        _stops.insert(s.first);
                    }

                    for (auto s : _node->tracker->heads)
                    {
                        uint256 stop_hash = _node->tracker->get_nth_parent_key(s.first, std::min(std::max(0, std::get<0>(_node->tracker->get_height_and_last(s.first)) - 1), 10));
                        _stops.insert(stop_hash);
                    }
                    stops = vector<uint256>{_stops.begin(), _stops.end()};
                }

                shares = peer->get_shares.yield(fiber,
                                                     std::vector<uint256>{share_hash},
                                                     (uint64_t)c2pool::random::RandomInt(0, 500), //randomize parents so that we eventually get past a too large block of shares
                                                     stops
                                                     );
//            }
            //TODO: catch: timeout/any error

            if (shares.empty())
            {
                fiber->sleep(1s);
                continue;
            }

            vector<tuple<ShareType, std::vector<coind::data::tx_type>>> post_shares;
            for (const auto& _share : shares)
            {
                post_shares.emplace_back(_share, std::vector<coind::data::tx_type>{});
            }

            _node->handle_shares(post_shares, peer->get_addr());
        }
    });

}
