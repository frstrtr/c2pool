#include "node.hpp"

#include <core/common.hpp>
#include <core/hash.hpp>
#include <sharechain/prepared_list.hpp>

namespace ltc
{

pool::PeerConnectionType NodeImpl::handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    LOG_DEBUG_POOL << "handle message_version";
	std::unique_ptr<ltc::message_version> msg;
	try
	{
		msg = ltc::message_version::make(rmsg->m_data);
	}
	catch(const std::exception& e)
	{
		error(e.what(), peer->addr());
		return pool::PeerConnectionType::unknown;
	}
	
	LOG_INFO << "Peer "
		 << msg->m_addr_from.m_endpoint.to_string()
		 << " says protocol version is "
		 << msg->m_version
		 << ", client version "
		 << msg->m_subversion;

	if (peer->m_other_version.has_value())
	{
        LOG_DEBUG_POOL << "more than one version message";
		throw std::runtime_error("more than one version message"); // TODO:
	}
	// TODO: 
	// if (msg->version.get() < net->MINIMUM_PROTOCOL_VERSION)
	// {
    //     LOG_DEBUG_POOL << "peer too old";
	// }

	peer->m_other_version = msg->m_version;
	peer->m_other_subversion = msg->m_subversion;
	peer->m_other_services = msg->m_services;

	if (m_nonce == msg->m_nonce)
	{
		LOG_WARNING << "was connected to self";
		throw std::runtime_error("was connected to self"); //TODO:
	}

	if (m_peers.contains(msg->m_nonce))
	{
		std::string reason = "[handle_message_version] Detected duplicate connection, disconnecting from " + peer->addr().to_string();
		LOG_ERROR << reason;
		throw std::runtime_error(reason);
        // TODO: handshake->error(libp2p::BAD_PEER, reason);
	}

	peer->m_nonce = msg->m_nonce;


    return pool::PeerConnectionType::legacy; 
}
    
void NodeImpl::processing_shares(HandleSharesData& data, NetService addr)
{
    // auto t1 = core::debug_timestamp();
    chain::PreparedList<uint256, ShareType> prepare_shares(data.m_items);
    std::vector<ShareType> shares = prepare_shares.build_list();

    if (shares.size() > 5)
    {
        LOG_INFO << "Processing " << shares.size() << " shares from " << addr.to_string() << "...";
    }

    int32_t new_count = 0;
	std::map<uint256, ltc::MutableTransaction> all_new_txs;
	for (auto& share : shares)
	{
        auto& new_txs = data.m_txs[share.hash()];
		if (!new_txs.empty())
		{
			for (auto& new_tx : new_txs)
			{
                PackStream packed_tx = pack(ltc::TX_WITH_WITNESS(new_tx)); //TODO: WITH_WITNESS?
				all_new_txs[Hash(packed_tx.get_span())] = new_tx;
			}
		}

		if (m_chain->contains(share.hash()))
		{
            LOG_WARNING << "Got duplicate share, ignoring. Hash: " << share.hash().ToString();
			continue;
		}

		new_count++;
		m_chain->add(share);
	}
}

std::vector<ltc::ShareType> NodeImpl::handle_get_share(std::vector<uint256> hashes, uint64_t parents, std::vector<uint256> stops, NetService peer_addr)
{
    parents = std::min(parents, (uint64_t)1000/hashes.size());
	std::vector<ltc::ShareType> shares;
	for (const auto& handle_hash : hashes)
	{
		uint64_t n = std::min(parents+1, (uint64_t) m_chain->get_height(handle_hash));
		for (auto& [hash, data] : m_chain->get_chain(handle_hash, n))
        {
			if (std::find(stops.begin(), stops.end(), hash) != stops.end())
				break;
			shares.push_back(data.share);
		}
	}

	if (!shares.empty())
	{
		LOG_INFO << "Sending " << shares.size() << " shares to " << peer_addr.to_string();
	}
	return shares;
}

} // namespace ltc
