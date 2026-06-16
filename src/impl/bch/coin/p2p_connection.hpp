#pragma once

// BCH p2p Connection (M3 slice 11) — per-peer request/reply matcher + socket
// write path. Structurally identical to btc: the BCH wire divergences
// (no-witness serialization, txid-based short IDs, wtxid==txid) live entirely
// in p2p_messages.hpp + compact_blocks.hpp. The handshake / version negotiation
// (where wtxidrelay is deliberately NOT offered for BCH) lives in p2p_node.hpp,
// NOT here. This carrier therefore has no BCH-specific logic.

#include "block.hpp"

#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/socket.hpp>
#include <core/reply_matcher.hpp>

namespace bch
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

private:
    boost::asio::io_context* m_context{};
    std::shared_ptr<core::Socket> m_socket;

    get_block_t* m_get_block{};
    get_header_t* m_get_header{};

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
            m_socket.reset();  // prevent use-after-close
        }
    }

    void init_requests(std::function<void(uint256)> block_req, std::function<void(uint256)> header_req)
    {
        m_get_block = new get_block_t(m_context, block_req, REQUEST_TIMEOUT_SEC);
        m_get_header = new get_header_t(m_context, header_req, REQUEST_TIMEOUT_SEC);
    }

    void request_block(uint256 id, uint256 hash, std::function<void(BlockType)> handler);
    void get_block(uint256 id, BlockType response);

    void request_header(uint256 id, uint256 hash, std::function<void(BlockHeaderType)> handler);
    void get_header(uint256 id, BlockHeaderType response);

    void write(std::unique_ptr<RawMessage>& rmsg)
    {
        if (!m_socket) return;  // peer disconnected or destroyed
        try {
            m_socket->write(std::move(rmsg));
        } catch (const std::exception& e) {
            // Socket may be closed/broken — don't crash
            m_socket.reset();
        }
    }

    auto get_addr() const
    {
        if (m_socket)
            return m_socket->get_addr();
        else
            return NetService{};
    }
};

} // namespace p2p

} // namespace coin

} // namespace bch
