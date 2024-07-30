#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/random.hpp>
#include <core/common.hpp>

namespace ltc
{

void Legacy::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    std::cout << "c2pool msg " << rmsg->m_command << std::endl;
}

void Legacy::HANDLER(addrs) 
{
    for (auto addr : msg->m_addrs)
    {
        addr.m_timestamp = std::min((uint64_t) core::timestamp(), addr.m_timestamp);
        got_addr(addr.m_endpoint, addr.m_services, addr.m_timestamp);

        if ((core::random::RandomFloat(0, 1) < 0.8) && (!m_peers.empty()))
        {
            auto wpeer = core::random::RandomChoice(m_peers);
            auto rmsg = message_addrs::make_raw({addr});
            wpeer->write(std::move(rmsg));
        }
    }
}

void Legacy::HANDLER(addrme)
{
    // TODO:
}

void Legacy::HANDLER(ping)
{
}

void Legacy::HANDLER(getaddrs)
{
    if (msg->m_count > 100)
        msg->m_count = 100;

    std::vector<addr_record_t> addrs;
    for (const auto& pair : get_good_peers(msg->m_count))
    {
        addrs.push_back({pair.value.m_last_seen, pair.addr});
    }

    auto rmsg = message_addrs::make_raw({addrs});
    peer->write(std::move(rmsg));
}

void Legacy::HANDLER(shares)
{
    ltc::HandleSharesData result; //share, txs

    for (auto wrappedshare : msg->m_shares)
    {
        ltc::ShareType share;
        try
        {
            share = ltc::load(wrappedshare, peer->addr());
        }
        catch(const std::invalid_argument& e)
        {
            continue;
        }

        std::vector<ltc::MutableTransaction> txs;
        share.ACTION
        ({
            if constexpr (share_t::version >= 13 && share_t::version < 34) 
            for (auto tx_hash : obj->m_tx_info.m_new_transaction_hashes)
            {
                /* TODO:
                
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
                        protocol->error(libp2p::BAD_PEER, reason);
                        return;
                    }
                }
                txs.push_back(tx);
                
                */
            }
        });
        
        result.add(share, txs);
    }

    processing_shares(result, peer->addr());
}

void Legacy::HANDLER(sharereq)
{
    auto shares = handle_get_share(msg->m_hashes, msg->m_parents, msg->m_stops, peer->addr());
    std::vector<chain::RawShare> rshares;

    try
    {
        for (auto& share : shares)
        {
            rshares.emplace_back(share.version(), pack(share));
        }
        auto reply_msg = message_sharereply::make_raw(msg->m_id, ltc::ShareReplyResult::good, rshares);
        peer->write(std::move(reply_msg));
    }
    catch (const std::invalid_argument &e)
    {
		// TODO: check for too_long
        auto reply_msg = message_sharereply::make_raw(msg->m_id, ltc::ShareReplyResult::too_long, {});
        peer->write(std::move(reply_msg));
        LOG_INFO << "second try";
    }
    
}

void Legacy::HANDLER(sharereply)
{
    std::vector<ltc::ShareType> result;
    if (msg->m_result == ShareReplyResult::good)
    {
        for (auto& rshare : msg->m_shares)
        {
            auto share = ltc::load(rshare, peer->addr());
            result.push_back(share);
        }
    } else 
    {
        //TODO: res = failure.Failure(self.ShareReplyError(result))
    }
    //TODO: protocol->get_shares.got_response(msg->id.get(), res);
}

void Legacy::HANDLER(bestblock)
{

}

void Legacy::HANDLER(have_tx)
{
    peer->m_remote_txs.insert(msg->m_tx_hashes.begin(), msg->m_tx_hashes.end());
    if (peer->m_remote_txs.size() > 10000)
    {
        peer->m_remote_txs.erase(peer->m_remote_txs.begin(), std::next(peer->m_remote_txs.begin(), peer->m_remote_txs.size() - 10000));
    }
}

void Legacy::HANDLER(losing_tx)
{
    //remove all msg->txs hashes from remote_tx_hashes
    std::set<uint256> losing_txs;
    losing_txs.insert(msg->m_tx_hashes.begin(), msg->m_tx_hashes.end());

    std::set<uint256> diff_txs;
    std::set_difference(peer->m_remote_txs.begin(), peer->m_remote_txs.end(),
                        losing_txs.begin(), losing_txs.end(),
                        std::inserter(diff_txs, diff_txs.begin()));

    peer->m_remote_txs = diff_txs;
}

void Legacy::HANDLER(remember_tx)
{
    for (auto tx_hash : msg->m_tx_hashes)
    {
        if (peer->m_remembered_txs.contains(tx_hash))
        {
            /*TODO:
            std::string reason = "[handle_message_remember_tx] Peer referenced transaction twice, disconnecting";
            protocol->error(libp2p::BAD_PEER, reason);
            return;
            */
        }

        /*TODO:
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
                protocol->error(libp2p::BAD_PEER, reason);
				return;
			}
        }

        protocol->remembered_txs[tx_hash] = tx;
		PackStream stream;
		stream << tx;
		protocol->remembered_txs_size += 100 + pack<coind::data::stream::TransactionType_stream>(tx).size();
        */
    }

    std::map<uint256, ltc::Transaction> added_known_txs;
    bool warned = false;
    for (auto tx : msg->m_txs)
	{
		// PackStream stream;
		// stream << tx;
		// auto tx_size = stream.size();
		// TODO: auto tx_hash = Hash(stream);

		// if (peer->m_remembered_txs.contains(tx_hash))
		{
            //TODO:
            // std::string reason = "[handle_message_remember_tx] Peer referenced transaction twice, disconnecting";
            // protocol->error(libp2p::BAD_PEER, reason);
			// return;
		}

        //TODO:
		// if (known_txs->exist(tx_hash) && !warned)
		// {
		// 	LOG_WARNING << "Peer sent entire transaction " << tx_hash.ToString() << " that was already received";
		// 	warned = true;
		// }

		// peer->m_remembered_txs[tx_hash] = ltc::Transaction(tx);
        // TODO:
		// peer->m_remembered_txs_size += 100 + _tx_size;
		// added_known_txs[tx_hash] = _tx.get();
	}
    // TODO: known_txs->add(added_known_txs);

    // TODO:
    // if (protocol->remembered_txs_size >= protocol->max_remembered_txs_size)
	// {
	// 	throw std::runtime_error("too much transaction data stored"); // TODO: custom error
	// }
}

void Legacy::HANDLER(forget_tx)
{
    for (auto tx_hash : msg->m_tx_hashes)
    {
        // PackStream stream;
        // stream << peer->m_remembered_txs[tx_hash];
        // TODO: 
        // peer->m_remembered_txs_size -= 100 + stream.size();
        // assert(protocol->remembered_txs_size >= 0);
        peer->m_remembered_txs.erase(tx_hash);
    }
}

} // namespace ltc