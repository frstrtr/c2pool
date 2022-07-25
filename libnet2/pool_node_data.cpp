#include "pool_node_data.h"

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

//	LOG_TRACE << "[HANDLE_BESTBLOCK]: header.bits.bits.target() = " << header.bits.bits.target();
//	LOG_TRACE << "[HANDLE_BESTBLOCK]: net->parent->POW_FUNC(packed_header) = " << net->parent->POW_FUNC(packed_header);
//	LOG_TRACE << "[HANDLE_BESTBLOCK]: header.previous_block = " << header.previous_block.get().ToString();
//	LOG_TRACE << "[HANDLE_BESTBLOCK]: header.bits = " << header.bits.get();
//	LOG_TRACE << "[HANDLE_BESTBLOCK]: header.bits.bits = " << header.bits.bits.get();

	arith_uint256 pow_func = UintToArith256(net->parent->POW_FUNC(packed_header));
	arith_uint256 bits_target = UintToArith256(header.bits.bits.target());
	if (pow_func > bits_target)
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
	if (shares.size() > 5)
	{
		auto addr = peer->get_addr();
		LOG_INFO << "Processing " << shares.size() << "shares from " << std::get<0>(addr) << ":" << std::get<1>(addr) << "...";
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

		if (tracker->exists(share->hash))
		{
//			#print 'Got duplicate share, ignoring. Hash: %s' % (p2pool_data.format_hash(share.hash),)
//			continue
		}

		new_count++;
		tracker->add(share);
	}

	known_txs.add(all_new_txs);

	if (new_count)
	{
		// TODO: self.node.set_best_share()
	}

	if (shares.size() > 5)
	{
		auto addr = peer->get_addr();
		LOG_INFO << "... done processing " << shares.size() << "shares. New: " << new_count << " Have: " << tracker->items.size() << "/~" << 2*net->CHAIN_LENGTH;
	}
}

void PoolNodeData::handle_share_hashes(std::vector<uint256> hashes, std::shared_ptr<PoolProtocol> peer)
{
	std::vector<uint256> new_hashes;
	for (auto x : hashes)
	{
		if (!tracker->exists(x))
			new_hashes.push_back(x);
	}

	if (new_hashes.empty())
		return;

	//TODO: deferred request for shares to peer
	/*
	 * try:
            shares = yield peer.get_shares(
                hashes=new_hashes,
                parents=0,
                stops=[],
            )
        except:
            log.err(None, 'in handle_share_hashes:')
        else:
            self.handle_shares([(share, []) for share in shares], peer)
	 */
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
		//TODO: write sendShares in PoolProtocol
//		peer.second->sendShares();
	}

}
