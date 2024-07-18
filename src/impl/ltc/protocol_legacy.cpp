#include "node.hpp"

namespace ltc
{

void Legacy::handle_message(std::unique_ptr<RawMessage> rmsg, NodeImpl::peer_ptr peer)
{
    std::cout << "c2pool msg " << rmsg->m_command << std::endl;
}



} // namespace ltc