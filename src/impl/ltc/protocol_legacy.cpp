#include "node.hpp"
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
        //TODO: got_addr(addr);

        if ((core::random::RandomFloat(0, 1) < 0.8) && (!peers.empty()))
        {
            auto wpeer = core::random::RandomChoice(peers);
            auto rmsg = message_addrs::make_raw({addr});
            wpeer->write(std::move(rmsg));
        }
    }
}

void Legacy::HANDLER(addrme)
{

}

void Legacy::HANDLER(ping)
{

}

void Legacy::HANDLER(getaddrs)
{

}

void Legacy::HANDLER(shares)
{

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