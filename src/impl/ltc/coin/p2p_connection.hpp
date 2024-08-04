#pragma once

#include "block.hpp"

#include <core/uint256.hpp>
#include <core/socket.hpp>
#include <core/reply_matcher.hpp>

namespace ltc
{
    
namespace coin
{

namespace p2p
{
    
class Connection
{
// TODO: add timeout
    using get_block_t = ReplyMatcher::ID<uint256>::RESPONSE<BlockType>::REQUEST<uint256>;
    using get_header_t = ReplyMatcher::ID<uint256>::RESPONSE<BlockHeaderType>::REQUEST<uint256>;
private:
    boost::asio::io_context* m_context;
    std::shared_ptr<core::Socket> m_socket;

    get_block_t* m_get_block;
    get_header_t* m_get_header;

public:

    Connection(boost::asio::io_context* context, std::shared_ptr<core::Socket> socket) : m_context(context), m_socket(socket)
    {

    }

    ~Connection()
    {
        if (m_get_block)
            delete m_get_block;
        if (m_get_header)
            delete m_get_header;
        
        if (m_socket)
        {
            m_socket->cancel();
            m_socket->close();
        }
    }

    void init_requests(std::function<void(uint256)> block_req, std::function<void(uint256)> header_req)
    {
        m_get_block = new get_block_t(m_context, block_req);
        m_get_header = new get_header_t(m_context, header_req);
    }

    void request_block(uint256 id, uint256 hash, std::function<void(BlockType)> handler);
    void get_block(uint256 id, BlockType response);

    void request_header(uint256 id, uint256 hash, std::function<void(BlockHeaderType)> handler);
    void get_header(uint256 id, BlockHeaderType response);

    void write(std::unique_ptr<RawMessage>& rmsg)
    {
        m_socket->write(std::move(rmsg));
    }
};

} // namespace p2p

} // namespace coin

} // namespace ltc
