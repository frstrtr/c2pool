// SPDX-License-Identifier: AGPL-3.0-or-later
#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/random.hpp>
#include <core/common.hpp>

namespace dash
{

void Legacy::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    dash::Handler::result_t result;
    try 
    {
        result = m_handler.parse(rmsg);
    } catch (const std::exception& ec)
    {
        LOG_WARNING << "Failed to parse message '" << rmsg->m_command << "' from "
                    << peer->addr().to_string() << ": " << ec.what();
        return;
    }

    try
    {
        std::visit([&](auto& msg){ handle(std::move(msg), peer); }, result);
    }
    catch (const std::exception& ec)
    {
        LOG_WARNING << "Handler error for '" << rmsg->m_command << "' from "
                    << peer->addr().to_string() << ": " << ec.what();
        return;
    }
}

void Legacy::HANDLER(addrs) 
{
    for (auto& addr : msg->m_addrs)
    {
        addr.m_timestamp = std::min((uint64_t) core::timestamp(), addr.m_timestamp);
        got_addr(addr.m_endpoint, addr.m_services, addr.m_timestamp);

        if ((core::random::random_float(0, 1) < 0.8) && (!m_connections.empty()))
        {
            auto wpeer = core::random::random_choice(m_connections);
            auto rmsg = message_addrs::make_raw({addr});
            wpeer->write(std::move(rmsg));
        }
    }
}

void Legacy::HANDLER(addrme)
{
    // #882 — the loopback HOST address, not the loopback NETWORK address.
    // Canonical p2p.py:281 compares `host == '127.0.0.1'`, and so does the
    // Actual generation (protocol_actual.cpp:57). Legacy shipped "127.0.0.0",
    // the /8 network address, which no peer can ever present as its source IP,
    // so this branch was unreachable and EVERY addrme — including one arriving
    // over loopback — fell into the else arm below: it recorded
    // 127.0.0.1:<port> in our AddrStore as if it were a routable peer and then
    // gossiped that loopback record onward in an addrs message. Legacy is the
    // only generation live on DASH today. Related to #910, which fixes the
    // other end of the same subsystem (a hostname serialising AS 127.0.0.1).
    if (peer->addr().address() == "127.0.0.1")
    {
        if (!m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = dash::message_addrme::make_raw(msg->m_port);
            random_peer->write(std::move(rmsg));
        }
    } else
    {
        auto endpoint = NetService{peer->addr().address(), msg->m_port};
        got_addr(endpoint, peer->m_other_services, core::timestamp());
        if (!m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = dash::message_addrs::make_raw({addr_record_t{peer->m_other_services, endpoint, core::timestamp()} });
            random_peer->write(std::move(rmsg));
        }
    }
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
        // #910: never advertise an address we cannot render on the wire. A
        // DNS-named seed that the outbound-connect resolver has not resolved
        // yet used to serialize as 127.0.0.1, pointing every peer that learned
        // it from us back at itself. Skip it; the next sweep re-offers it once
        // a dial has resolved the name.
        if (!pair.addr.is_wire_advertisable())
            continue;
        addrs.push_back({pair.value.m_service, pair.addr, pair.value.m_last_seen});
    }

    auto rmsg = message_addrs::make_raw({addrs});
    peer->write(std::move(rmsg));
}

void Legacy::HANDLER(shares)
{
    try {
        dash::HandleSharesData result; //share, txs

        for (auto wrappedshare : msg->m_shares)
        {
            dash::ShareType share;
            try
            {
                share = dash::load_share(wrappedshare, peer->addr());
            }
            catch(const std::exception& e)
            {
                LOG_WARNING << "Failed to load share (type=" << wrappedshare.type
                            << ") from " << peer->addr().to_string() << ": " << e.what();
                continue;
            }

            std::vector<coin::MutableTransaction> txs;
            share.ACTION
            ({
                if constexpr (share_t::version >= 13 && share_t::version < 34)
                for (auto tx_hash : obj->m_new_transaction_hashes)
                {
                    auto it = m_known_txs.find(tx_hash);
                    if (it != m_known_txs.end())
                    {
                        txs.emplace_back(it->second);
                    }
                    else
                    {
                        LOG_WARNING << "Peer referenced unknown transaction " << tx_hash.ToString();
                    }
                }
            });

            result.add(share, txs);
        }

        processing_shares(result, peer->addr());
    } catch (const std::exception& e) {
        LOG_ERROR << "[Pool] shares handler exception: " << e.what();
    }
}

void Legacy::HANDLER(sharereq)
{
    // Debug: log what's being requested
    {
        static int dbg_req = 0;
        if (dbg_req < 20)
        {
            ++dbg_req;
            std::string req_hashes;
            for (auto& h : msg->m_hashes) req_hashes += h.ToString().substr(0, 16) + " ";
            LOG_WARNING << "SHAREREQ #" << dbg_req << " from " << peer->addr().to_string()
                        << " hashes=[" << req_hashes << "] parents=" << msg->m_parents
                        << " stops=" << msg->m_stops.size();
        }
    }

    auto shares = handle_get_share(msg->m_hashes, msg->m_parents, msg->m_stops, peer->addr());

    // Debug: log what we're returning
    {
        static int dbg_rep = 0;
        if (dbg_rep < 20)
        {
            ++dbg_rep;
            LOG_WARNING << "SHAREREPLY #" << dbg_rep << " returning " << shares.size() << " shares";
            for (size_t i = 0; i < std::min(shares.size(), (size_t)3); ++i)
            {
                LOG_WARNING << "  share[" << i << "] hash=" << shares[i].hash().ToString().substr(0, 16);
            }
        }
    }

    std::vector<chain::RawShare> rshares;

    try
    {
        for (auto& share : shares)
        {
            rshares.emplace_back(share.version(), pack(share));
        }
        auto reply_msg = message_sharereply::make_raw(msg->m_id, dash::ShareReplyResult::good, rshares);
        peer->write(std::move(reply_msg));
    }
    catch (const std::invalid_argument &e)
    {
        // Serialization overflow: the packed shares exceeded the P2P message
        // size limit (32 MB). Reply with too_long so the peer requests a
        // smaller batch. This is the correct behavior per Python p2pool.
        LOG_WARNING << "Share reply too large, sending too_long: " << e.what();
        auto reply_msg = message_sharereply::make_raw(msg->m_id, dash::ShareReplyResult::too_long, {});
        peer->write(std::move(reply_msg));
    }

    // #1130: free the OWNED copies handle_get_share cloned for us. Both the
    // good and too_long paths fall through to here (no early return), and each
    // variant owns independent heap from clone(), so this destroy() frees our
    // copies WITHOUT ever touching the pointers the sharechain still owns.
    for (auto& share : shares) share.destroy();
}

void Legacy::HANDLER(sharereply)
{
    dash::ShareReplyData result;
    if (msg->m_result == ShareReplyResult::good)
    {
        result.m_items.reserve(msg->m_shares.size());
        result.m_raw_items.reserve(msg->m_shares.size());
        for (auto& rshare : msg->m_shares)
        {
            try
            {
                auto share = dash::load_share(rshare, peer->addr());
                result.m_items.push_back(share);
                result.m_raw_items.push_back(rshare);
            }
            catch(const std::exception& e)
            {
                LOG_WARNING << "Failed to deserialize share (type=" << rshare.type
                            << ") from " << peer->addr().to_string() << ": " << e.what();
                continue;
            }
        }
    }
    // Resolve the async request that originally sent the sharereq
    got_share_reply(msg->m_id, result);
}

void Legacy::HANDLER(bestblock)
{
    try {
        auto header_hash = Hash(pack(msg->m_header).get_span());
        LOG_INFO << "[Pool] New best block from peer " << peer->addr().to_string()
                 << ": " << header_hash.ToString();

        // p2pool does NOT relay bestblock — each node broadcasts only from its own
        // block source (bitcoind_work.changed → best_block_header.changed).
        // Relaying creates an amplification loop: A→B→C→A with alternating hashes.
        if (m_on_bestblock) m_on_bestblock(header_hash);
    } catch (const std::exception& e) {
        LOG_WARNING << "[Pool] bestblock handler exception: " << e.what();
    }
}

void Legacy::HANDLER(have_tx)
{
    peer->m_remote_txs.insert(msg->m_tx_hashes.begin(), msg->m_tx_hashes.end());
    if (peer->m_remote_txs.size() > 10000)
    {
        peer->m_remote_txs.erase(peer->m_remote_txs.begin(), std::next(peer->m_remote_txs.begin(), peer->m_remote_txs.size() - 10000));
    }
}

void Legacy::HANDLER(losing_tx)
{
    //remove all msg->txs hashes from remote_tx_hashes
    std::set<uint256> losing_txs;
    losing_txs.insert(msg->m_tx_hashes.begin(), msg->m_tx_hashes.end());

    std::set<uint256> diff_txs;
    std::set_difference(peer->m_remote_txs.begin(), peer->m_remote_txs.end(),
                        losing_txs.begin(), losing_txs.end(),
                        std::inserter(diff_txs, diff_txs.begin()));

    peer->m_remote_txs = diff_txs;
}

void Legacy::HANDLER(remember_tx)
{
    // Phase 1: tx_hashes — peer tells us to remember these by hash (must be in known_txs)
    for (auto tx_hash : msg->m_tx_hashes)
    {
        if (peer->m_remembered_txs.contains(tx_hash))
        {
            LOG_WARNING << "Peer referenced transaction twice: " << tx_hash.ToString();
            continue;
        }

        auto it = m_known_txs.find(tx_hash);
        if (it != m_known_txs.end())
        {
            peer->m_remembered_txs.insert_or_assign(tx_hash, it->second);
        }
        else
        {
            LOG_WARNING << "Peer referenced unknown transaction " << tx_hash.ToString();
        }
    }

    // Phase 2: txs — peer sends full transactions (compute hash, store)
    for (auto& tx : msg->m_txs)
    {
        auto packed = pack(coin::TX_WITH_WITNESS(tx));
        auto tx_hash = Hash(packed.get_span());

        if (peer->m_remembered_txs.contains(tx_hash))
        {
            LOG_WARNING << "Peer sent duplicate transaction: " << tx_hash.ToString();
            continue;
        }

        coin::Transaction full_tx(tx);
        peer->m_remembered_txs.insert_or_assign(tx_hash, full_tx);

        if (!m_known_txs.contains(tx_hash))
            m_known_txs.emplace(tx_hash, std::move(full_tx));
    }
}

void Legacy::HANDLER(forget_tx)
{
    for (auto tx_hash : msg->m_tx_hashes)
    {
        peer->m_remembered_txs.erase(tx_hash);
    }
}

// #157 M2: route a peer's tx-injection through the SAME submit_inject gate as the
// local --embedded-tx-inject-hex loader (all M1 validity checks), then first-see
// fan it out. The whole policy lives in NodeImpl::handle_peer_tx_inject so the
// Legacy/Actual bodies stay byte-identical (only the dispatch table differs).
void Legacy::HANDLER(tx_inject)
{
    handle_peer_tx_inject(*msg, peer);
}

} // namespace dash