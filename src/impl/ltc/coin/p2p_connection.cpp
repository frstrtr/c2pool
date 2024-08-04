#include "p2p_connection.hpp"

namespace ltc
{
    
namespace coin
{

namespace p2p
{

void Connection::request_block(uint256 id, uint256 hash, std::function<void(BlockType)> handler)
{
    if (m_get_block)
        m_get_block->request(id, handler, hash);
}

void Connection::get_block(uint256 id, BlockType response)
{
    if (m_get_block)
        m_get_block->got_response(id, response);
}

void Connection::request_header(uint256 id, uint256 hash, std::function<void(BlockHeaderType)> handler)
{
    if (m_get_header)
        m_get_header->request(id, handler, hash);
}

void Connection::get_header(uint256 id, BlockHeaderType response)
{
    if (m_get_header)
        m_get_header->got_response(id, response);
}

} // namespace p2p

} // namespace coin

} // namespace ltc
