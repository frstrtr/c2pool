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
        share.ACTION({
            // for (auto tx_hash : obj->new_transaction_hashes)
        });
        
        
    }
}

void Legacy::HANDLER(sharereq)
{

}

void Legacy::HANDLER(sharereply)
{

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