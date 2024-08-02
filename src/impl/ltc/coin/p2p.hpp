#pragma once

#include <boost/asio.hpp>

namespace io = boost::asio;

namespace ltc
{
    
namespace coin
{
    
class P2PNode
{
private:
    io::io_context* m_context;
    io::ip::tcp::resolver m_resolver;

public:
    P2PNode(io::io_context* context) : m_context(context), m_resolver(*context) { }
    
};

} // namespace node

} // namespace ltc
