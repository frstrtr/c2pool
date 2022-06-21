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