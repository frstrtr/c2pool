#include "pool_node_data.h"

#include "coind_node_data.h"
#include <sharechains/share.h>

PoolNodeData* PoolNodeData::set_coind_node(std::shared_ptr<CoindNodeData> _coind_node)
{
    coind_node = std::move(_coind_node);

    known_txs = coind_node->known_txs;
    mining_txs = coind_node->mining_txs;
    best_share = coind_node->best_share;

    return this;
}

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

	arith_uint256 pow_func = UintToArith256(net->parent->POW_FUNC(packed_header));
	arith_uint256 bits_target = UintToArith256(header.bits.bits.target());
	if (pow_func > bits_target)
	{
		throw std::invalid_argument("received block header fails PoW test");
	}

	auto _header = coind::data::BlockHeaderType();
	_header.set_stream(header);

    if (coind_node)
	    coind_node->handle_header(_header);
    else
        LOG_WARNING << "COIND NODE = NULL IN POOL NODE!";
}

void PoolNodeData::handle_shares(vector<tuple<ShareType, std::vector<coind::data::tx_type>>> shares,
                                 std::tuple<std::string, std::string> addr)
{
	if (shares.size() > 5)
	{
		LOG_INFO << "Processing " << shares.size() << " shares from " << std::get<0>(addr) << ":" << std::get<1>(addr) << "...";
	}

	int32_t new_count = 0;
	std::map<uint256, coind::data::tx_type> all_new_txs;
	for (auto [share, new_txs] : shares)
	{
		if (!new_txs.empty())
		{
			for (const auto& new_tx : new_txs)
			{
				coind::data::stream::TransactionType_stream _tx(new_tx);
				PackStream packed_tx;
				packed_tx << _tx;

				all_new_txs[coind::data::hash256(packed_tx)] = new_tx;
			}
		}

		if (tracker->exist(share->hash))
		{
            LOG_WARNING << "Got duplicate share, ignoring. Hash: " << share->hash.ToString();
			continue;
		}

		new_count++;
		tracker->add(share);
	}

	known_txs.add(all_new_txs);

	if (new_count)
	{
		coind_node->set_best_share();
	}

	if (shares.size() > 5)
	{
		LOG_INFO << "... done processing " << shares.size() << " shares. New: " << new_count << " Have: " << tracker->items.size() << "/~" << 2*net->CHAIN_LENGTH;
//        std::this_thread::sleep_for(0.2s);
	}
}

void PoolNodeData::handle_share_hashes(std::vector<uint256> hashes, std::shared_ptr<PoolProtocolData> peer, std::tuple<std::string, std::string> addr)
{
	std::vector<uint256> new_hashes;
	for (auto x : hashes)
	{
		if (!tracker->exist(x))
			new_hashes.push_back(x);
	}

	if (new_hashes.empty())
		return;

	peer->get_shares.yield(context, [&, _peer = peer, _addr = addr](std::vector<ShareType> shares)
	{
		vector<tuple<ShareType, std::vector<coind::data::tx_type>>> _shares;
		for (const auto& _share: shares)
		{
			_shares.push_back({_share, {}});
		}
		handle_shares(_shares, _addr);
	}, new_hashes, 0, {});
}

void PoolNodeData::broadcast_share(uint256 share_hash)
{
	std::vector<uint256> shares;

	auto get_chain_f = tracker->get_chain(share_hash, std::min(5, tracker->get_height(share_hash)));

	uint256 chain_hash;
	while(get_chain_f(chain_hash))
	{
		if (shared_share_hashes.count(chain_hash))
			break;

		shared_share_hashes.insert(chain_hash);
		shares.push_back(chain_hash);
	}

	for (auto peer : peers)
	{
		send_shares(peer.second, shares, {share_hash});
	}

}


void PoolNodeData::send_shares(std::shared_ptr<PoolProtocol> peer, std::vector<uint256> share_hashes, std::vector<uint256> include_txs_with)
{
	auto t0 = c2pool::dev::timestamp();
	std::set<uint256> tx_hashes;
	auto _known_txs = known_txs.value();

	// Share list
	std::vector<ShareType> shares;
	std::for_each(share_hashes.begin(), share_hashes.end(), [&](const uint256 &hash){
		auto share = tracker->get(hash);
		if (share->peer_addr != peer->get_addr())
			shares.push_back(std::move(share));
	});

	// Check shares
	for (auto share : shares)
	{
		if (share->VERSION >= 13)
		{
			//# send full transaction for every new_transaction_hash that peer does not know
			for (auto tx_hash : *share->new_transaction_hashes)
			{
				if (!_known_txs.count(tx_hash))
				{
					std::set<uint256> newset(share->new_transaction_hashes->begin(), share->new_transaction_hashes->end());

					for (auto _tx : _known_txs)
					{
						if (_known_txs.find(_tx.first) != _known_txs.end())
							newset.erase(_tx.first);
						//"Missing %i of %i transactions for broadcast" % (len(missing), len(newset))
						LOG_WARNING << "Missing " << newset.size() << " of " << share->new_transaction_hashes->size() << " transactions for broadcast";
						assert(_known_txs.find(tx_hash) != _known_txs.end()); // tried to broadcast share without knowing all its new transactions'
						if (!peer->remote_tx_hashes.count(tx_hash))
							tx_hashes.insert(tx_hash);
					}
				}
			}
			continue;
		}

		if (std::find(include_txs_with.begin(), include_txs_with.end(), share->hash) != include_txs_with.end())
		{
			auto x = tracker->get_other_tx_hashes(share);
			if (x.size())
				tx_hashes.insert(x.begin(), x.end());
		}

		/* For debug
			 hashes_to_send = [x for x in tx_hashes if x not in self.node.mining_txs_var.value and x in known_txs]
			all_hashes = share.share_info['new_transaction_hashes']
			new_tx_size = sum(100 + bitcoin_data.tx_type.packed_size(known_txs[x]) for x in hashes_to_send)
			all_tx_size = sum(100 + bitcoin_data.tx_type.packed_size(known_txs[x]) for x in all_hashes)
			print "Sending a share with %i txs (%i new) totaling %i msg bytes (%i new)" % (len(all_hashes), len(hashes_to_send), all_tx_size, new_tx_size)
		 */
	}

	// Calculate tx_size and generate hashes_to_send
	std::vector<uint256> hashes_to_send;
	uint32_t new_tx_size = 0;
	for (auto x : tx_hashes)
	{
		if (!coind_node->mining_txs.exist(x) && known_txs.exist(x))
		{
			// hashes_to_send
			hashes_to_send.push_back(x);

			// new_tx_size calculate
			coind::data::stream::TransactionType_stream _tx(known_txs._value->at(x));
			PackStream packed_tx;
			packed_tx << _tx;

			new_tx_size += 100 + packed_tx.size();
		}
	}

	// Remote remembered txs
	auto new_remote_remembered_txs_size = peer->remote_remembered_txs_size + new_tx_size;
	if (new_remote_remembered_txs_size > peer->max_remembered_txs_size)
		throw("share have too many txs");
    std::cout << "remote_remembered_txs_size(before new_remote_remembered_txs_size): " << peer->remote_remembered_txs_size;
	peer->remote_remembered_txs_size = new_remote_remembered_txs_size;
    std::cout << "remote_remembered_txs_size(new_remote_remembered_txs_size): " << peer->remote_remembered_txs_size << "/" << peer->max_remembered_txs_size << ".\n";

	// Send messages

	// 		Send remember tx
	{
		std::vector<uint256> _tx_hashes;
		std::vector<coind::data::tx_type> _txs;

		for (auto x : hashes_to_send)
		{
			if (peer->remote_tx_hashes.count(x))
				_tx_hashes.push_back(x);
			else
				_txs.push_back(known_txs.value()[x]);
		}

		auto msg_remember_tx = std::make_shared<pool::messages::message_remember_tx>(_tx_hashes, _txs);
        LOG_DEBUG_POOL << "SEND SHARES REMEMBER TX!";
		peer->write(msg_remember_tx);
	}
	// 		Send shares
	{
		std::vector<PackedShareData> _shares;
		for (auto share : shares)
		{
			auto packed_share = pack_share(share);
			_shares.push_back(std::move(packed_share));
		}

		auto msg_shares = std::make_shared<pool::messages::message_shares>(_shares);
		peer->write(msg_shares);
	}

	//		Send forget tx
	{
		auto msg_forget_tx = std::make_shared<pool::messages::message_forget_tx>(hashes_to_send);
		peer->write(msg_forget_tx);
	}

    std::cout << "remote_remembered_txs_size(before send_shares): " << peer->remote_remembered_txs_size;
	peer->remote_remembered_txs_size -= new_tx_size;
    std::cout << "remote_remembered_txs_size(send_shares): " << peer->remote_remembered_txs_size << "/" << peer->max_remembered_txs_size << ".\n";
	auto t1 = c2pool::dev::timestamp();
}
