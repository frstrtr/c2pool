// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include "block.hpp"

#include <core/log.hpp>
#include <core/uint256.hpp>
#include <core/socket.hpp>
#include <core/reply_matcher.hpp>
#include <cstdint>

namespace bip110
{
    
namespace coin
{

namespace p2p
{
    
class Connection
{
public:
    // Per-request reply timeout. Public so the BTC-family NodeP2P idle-window
    // static_assert can prove its 100s eviction backstop is >> this value.
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

    // --- idle-progress eviction inputs (consumed by NodeP2P::sample_idle_gate) ---
    // A block/header request is outstanding iff either reply matcher still has a
    // watcher. This is the m_watchers discriminator: an evicted peer must be one
    // we asked something of that never delivered.
    bool has_pending() const
    {
        return (m_get_block  && !m_get_block->m_watchers.empty())
            || (m_get_header && !m_get_header->m_watchers.empty());
    }

    // Monotonic count of REAL answers across both matchers. Only got_response()
    // (a genuine peer reply) advances this; a per-request timeout does not -- so
    // a rising epoch is FORWARD PROGRESS, not mere inbound bytes.
    uint64_t progress_epoch() const
    {
        uint64_t e = 0;
        if (m_get_block)  e += m_get_block->m_progress;
        if (m_get_header) e += m_get_header->m_progress;
        return e;
    }
};

} // namespace p2p

} // namespace coin

} // namespace bip110