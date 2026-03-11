#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/random.hpp>
#include <core/common.hpp>

#include <iomanip>
#include <sstream>
#include <cstring>

namespace ltc
{
    
void Actual::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    ltc::Handler::result_t result;
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

    std::cout << "c2pool msg " << rmsg->m_command << std::endl;
}

void Actual::HANDLER(addrs) 
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

void Actual::HANDLER(addrme)
{
    if (peer->addr().address() == "127.0.0.1")
    {
        if (!m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = ltc::message_addrme::make_raw(msg->m_port);
            random_peer->write(std::move(rmsg));
        }
    } else
    {
        auto endpoint = NetService{peer->addr().address(), msg->m_port};
        got_addr(endpoint, peer->m_other_services, core::timestamp());
        if (!m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = ltc::message_addrs::make_raw({addr_record_t{peer->m_other_services, endpoint, core::timestamp()} });
            random_peer->write(std::move(rmsg));
        }
    }
}

void Actual::HANDLER(ping)
{
}

void Actual::HANDLER(getaddrs)
{
    if (msg->m_count > 100)
        msg->m_count = 100;

    std::vector<addr_record_t> addrs;
    for (const auto& pair : get_good_peers(msg->m_count))
    {
        addrs.push_back({pair.value.m_service, pair.addr, pair.value.m_last_seen});
    }

    auto rmsg = message_addrs::make_raw({addrs});
    peer->write(std::move(rmsg));
}

void Actual::HANDLER(shares)
{
    ltc::HandleSharesData result;

    for (auto wrappedshare : msg->m_shares)
    {
        // Save a copy of the original raw bytes before deserialization consumes them
        chain::RawShare raw_copy(wrappedshare.type,
                                 BaseScript(wrappedshare.contents.m_data));

        ltc::ShareType share;
        try
        {
            share = ltc::load_share(wrappedshare, peer->addr());
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
            for (auto tx_hash : obj->m_tx_info.m_new_transaction_hashes)
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
        
        // Round-trip diagnostic: re-serialize and compare with original bytes
        {
            PackStream reser = pack(share);
            auto orig_span = raw_copy.contents.m_data;
            auto reser_span = reser.get_span();
            bool match = (orig_span.size() == (size_t)reser_span.size()) &&
                         std::memcmp(orig_span.data(), reser_span.data(), orig_span.size()) == 0;
            if (!match) {
                static int rt_dbg = 0;
                if (rt_dbg < 10) {
                    ++rt_dbg;
                    LOG_WARNING << "ROUND-TRIP MISMATCH #" << rt_dbg
                                << " type=" << raw_copy.type
                                << " orig_len=" << orig_span.size()
                                << " reser_len=" << reser_span.size();
                    // Find first differing byte
                    size_t min_len = std::min(orig_span.size(), (size_t)reser_span.size());
                    for (size_t b = 0; b < min_len; ++b) {
                        if (orig_span[b] != (unsigned char)reser_span[b]) {
                            LOG_WARNING << "  first diff at byte " << b
                                        << " orig=0x" << std::hex << (int)orig_span[b]
                                        << " reser=0x" << (int)(unsigned char)reser_span[b] << std::dec;
                            // Show a few bytes of context around the diff
                            size_t ctx_start = (b > 8) ? b - 8 : 0;
                            size_t ctx_end = std::min(b + 16, min_len);
                            std::ostringstream oss_o, oss_r;
                            for (size_t c = ctx_start; c < ctx_end; ++c)
                                oss_o << std::hex << std::setfill('0') << std::setw(2) << (int)orig_span[c];
                            for (size_t c = ctx_start; c < ctx_end; ++c)
                                oss_r << std::hex << std::setfill('0') << std::setw(2) << (int)(unsigned char)reser_span[c];
                            LOG_WARNING << "  orig[" << ctx_start << ".." << ctx_end << "]: " << oss_o.str();
                            LOG_WARNING << "  resr[" << ctx_start << ".." << ctx_end << "]: " << oss_r.str();
                            break;
                        }
                    }
                }
            }
        }

        result.add(share, txs, raw_copy);
    }

    processing_shares(result, peer->addr());
}

void Actual::HANDLER(sharereq)
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
                        << " hashes=[" << req_hashes << "] parents=" << msg->m_parents;
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
        auto reply_msg = message_sharereply::make_raw(msg->m_id, ltc::ShareReplyResult::good, rshares);
        peer->write(std::move(reply_msg));
    }
    catch (const std::invalid_argument &e)
    {
        auto reply_msg = message_sharereply::make_raw(msg->m_id, ltc::ShareReplyResult::too_long, {});
        peer->write(std::move(reply_msg));
    }
}

void Actual::HANDLER(sharereply)
{
    std::vector<ltc::ShareType> result;
    if (msg->m_result == ShareReplyResult::good)
    {
        for (auto& rshare : msg->m_shares)
        {
            try
            {
                auto share = ltc::load_share(rshare, peer->addr());
                result.push_back(share);
            }
            catch(const std::exception& e)
            {
                LOG_WARNING << "Failed to deserialize share (type=" << rshare.type
                            << ") from " << peer->addr().to_string() << ": " << e.what();
                continue;
            }
        }
    }
    got_share_reply(msg->m_id, result);
}

void Actual::HANDLER(bestblock)
{
    auto header_hash = Hash(pack(msg->m_header).get_span());
    LOG_INFO << "New best block from peer " << peer->addr().to_string()
             << ": " << header_hash.ToString();

    for (auto& [nonce, wpeer] : m_peers)
    {
        if (wpeer != peer)
            wpeer->write(message_bestblock::make_raw(msg->m_header));
    }
    if (m_on_bestblock) m_on_bestblock();
}

void Actual::HANDLER(have_tx)
{
    peer->m_remote_txs.insert(msg->m_tx_hashes.begin(), msg->m_tx_hashes.end());
    if (peer->m_remote_txs.size() > 10000)
    {
        peer->m_remote_txs.erase(peer->m_remote_txs.begin(), std::next(peer->m_remote_txs.begin(), peer->m_remote_txs.size() - 10000));
    }
}

void Actual::HANDLER(losing_tx)
{
    std::set<uint256> losing_txs;
    losing_txs.insert(msg->m_tx_hashes.begin(), msg->m_tx_hashes.end());

    std::set<uint256> diff_txs;
    std::set_difference(peer->m_remote_txs.begin(), peer->m_remote_txs.end(),
                        losing_txs.begin(), losing_txs.end(),
                        std::inserter(diff_txs, diff_txs.begin()));

    peer->m_remote_txs = diff_txs;
}

void Actual::HANDLER(remember_tx)
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

void Actual::HANDLER(forget_tx)
{
    for (auto tx_hash : msg->m_tx_hashes)
    {
        peer->m_remembered_txs.erase(tx_hash);
    }
}

} // namespace ltc
