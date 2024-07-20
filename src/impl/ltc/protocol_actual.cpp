#include "node.hpp"

namespace ltc
{
    
void Actual::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{ 
    std::cout << "c2pool msg " << rmsg->m_command << std::endl;
}

void Actual::HANDLER(addrs) 
{
    
}

void Actual::HANDLER(addrme)
{

}

void Actual::HANDLER(ping)
{

}

void Actual::HANDLER(getaddrs)
{

}

void Actual::HANDLER(shares)
{

}

void Actual::HANDLER(sharereq)
{

}

void Actual::HANDLER(sharereply)
{

}

void Actual::HANDLER(bestblock)
{

}

void Actual::HANDLER(have_tx)
{

}

void Actual::HANDLER(losing_tx)
{

}

void Actual::HANDLER(remember_tx)
{

}

void Actual::HANDLER(forget_tx)
{

}

} // namespace ltc
