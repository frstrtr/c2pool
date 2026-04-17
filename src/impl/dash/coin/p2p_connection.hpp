#pragma once

#include "block.hpp"

#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/socket.hpp>
#include <core/reply_matcher.hpp>

namespace dash
{
namespace coin
{
namespace p2p
{

class Connection
{
    static constexpr int REQUEST_TIMEOUT_SEC = 15;
    using get_block_t = ReplyMatcher::ID<uint256>::RESPONSE<BlockType>::REQUEST<uint256>;
    using get_header_t = ReplyMatcher::ID<uint256>::RESPONSE<BlockHeaderType>::REQUEST<uint256>;

    boost::asio::io_context* m_context{};
    std::shared_ptr<core::Socket> m_socket;

    get_block_t* m_get_block{};
    get_header_t* m_get_header{};

public:
    Connection(boost::asio::io_context* context, std::shared_ptr<core::Socket> socket)
        : m_context(context), m_socket(socket) {}

    ~Connection()
    {
        delete m_get_block;
        delete m_get_header;
        if (m_socket) {
            m_socket->cancel();
            m_socket->close();
            m_socket.reset();
        }
    }

    void init_requests(std::function<void(uint256)> block_req, std::function<void(uint256)> header_req)
    {
        m_get_block = new get_block_t(m_context, block_req, REQUEST_TIMEOUT_SEC);
        m_get_header = new get_header_t(m_context, header_req, REQUEST_TIMEOUT_SEC);
    }

    void request_block(uint256 id, uint256 hash, std::function<void(BlockType)> handler)
    {
        m_get_block->request(id, handler, hash);
    }

    void get_block(uint256 id, BlockType response)
    {
        m_get_block->got_response(id, response);
    }

    void request_header(uint256 id, uint256 hash, std::function<void(BlockHeaderType)> handler)
    {
        m_get_header->request(id, handler, hash);
    }

    void get_header(uint256 id, BlockHeaderType response)
    {
        m_get_header->got_response(id, response);
    }

    void write(std::unique_ptr<RawMessage>& rmsg)
    {
        if (!m_socket) return;
        try {
            m_socket->write(std::move(rmsg));
        } catch (const std::exception&) {
            m_socket.reset();
        }
    }

    auto get_addr() const
    {
        return m_socket ? m_socket->get_addr() : NetService{};
    }
};

} // namespace p2p
} // namespace coin
} // namespace dash
