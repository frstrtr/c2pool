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

struct HandleSharesData
{
    std::vector<ShareType> m_items;
    std::map<uint256, std::vector<ltc::MutableTransaction>> m_txs;

    void add(const ShareType& share, std::vector<ltc::MutableTransaction> txs)
    {
        m_items.push_back(share);
        m_txs[share.hash()] = std::move(txs);
    }
};

void Legacy::HANDLER(shares)
{
    HandleSharesData result; //share, txs

    for (auto wrappedshare : msg->m_shares)
    {
        ltc::ShareType share;
        try
        {
            share = ltc::load(wrappedshare.type, wrappedshare.contents, peer->addr());
        }
        catch(const std::invalid_argument& e)
        {
            continue;
        }

        std::vector<ltc::MutableTransaction> txs;
        share.ACTION
        ({
            if constexpr (share_t::version < 13 && share_t::version >= 34) 
                return;
            else for (auto tx_hash : obj->m_tx_info.m_new_transaction_hashes)
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

    //TODO: handle_shares(result, protocol->get_addr());
}

void Legacy::HANDLER(sharereq)
{
    auto shares = handle_get_share(msg->m_hashes, msg->m_parents, msg->m_stops, peer->addr());
    std::vector<chain::RawShare> rshares;

    try
    {
        for (auto& share : shares)
        {
            share.ACTION({
                rshares.emplace_back(share_t::version, pack(share));
            });
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
            auto share = ltc::load(rshare.type, rshare.contents, peer->addr());
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

}

void Legacy::HANDLER(losing_tx)
{

}

void Legacy::HANDLER(remember_tx)
{

}

void Legacy::HANDLER(forget_tx)
{

}

} // namespace ltc