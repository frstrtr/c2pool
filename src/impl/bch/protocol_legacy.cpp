// BCH legacy-protocol dispatch router (broadcaster-gate / pool p2p ingress).
//
// Mirror of btc::Legacy::handle_message with the namespace swapped to bch.
// Conformance anchor: p2poolBCH @6603b79 + btc oracle protocol_legacy.cpp.
// Routing contract (matches oracle exactly, the thing reviewers diff):
//   parse RawMessage via m_handler -> std::visit-dispatch to the typed
//   handle(msg, peer) HANDLER overload for the command. Unknown/over-old
//   peers are gated upstream by NodeBridge via handle_version (require-version
//   before any command routes here). Parse and handler faults are logged and
//   swallowed per-message — never tear down the peer loop on one bad frame.
//
// Router skeleton (handle_message) + peer-book HANDLER cluster
// (addrs/addrme/ping/getaddrs) land here; share/tx HANDLER bodies
// (shares/sharereq/...) follow in later slices.
#include "node.hpp"
#include "share.hpp"

#include <core/uint256.hpp>
#include <core/random.hpp>
#include <core/common.hpp>

#include <set>
#include <algorithm>
#include <iterator>

namespace bch
{

void Legacy::handle_message(std::unique_ptr<RawMessage> rmsg, peer_ptr peer)
{
    bch::Handler::result_t result;
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

// ---------------------------------------------------------------------------
// Peer-book HANDLER cluster (addrs / addrme / ping / getaddrs).
//
// Mechanical mirror of btc::Legacy peer-book handlers (oracle protocol_legacy
// .cpp), namespace-swapped btc -> bch. Pure pool-p2p address-book maintenance:
// gossip-relay learned peers, answer getaddrs from get_good_peers, no-op ping.
// p2pool-merged-v36 surface: NONE (no share / PPLNS / coinbase / AuxPoW bytes;
// peer discovery only). Share/tx HANDLER bodies (shares/sharereq/...) follow in
// later slices; routed via the same std::visit dispatcher in handle_message().
// ---------------------------------------------------------------------------

void Legacy::HANDLER(addrs)
{
    for (auto& addr : msg->m_addrs)
    {
        addr.m_timestamp = std::min((uint64_t) core::timestamp(), addr.m_timestamp);
        got_addr(addr.m_endpoint, addr.m_services, addr.m_timestamp);

        if ((core::random::random_float(0, 1) < 0.8) && (!m_connections.empty()))
        {
            auto wpeer = core::random::random_choice(m_connections);
            auto rmsg = bch::message_addrs::make_raw({addr});
            wpeer->write(std::move(rmsg));
        }
    }
}

void Legacy::HANDLER(addrme)
{
    if (peer->addr().address() == "127.0.0.0")
    {
        if (m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = bch::message_addrme::make_raw(msg->m_port);
            random_peer->write(std::move(rmsg));
        }
    } else
    {
        auto endpoint = NetService{peer->addr().address(), msg->m_port};
        got_addr(endpoint, peer->m_other_services, core::timestamp());
        if (m_peers.empty() && (core::random::random_float(0, 1) < 0.8))
        {
            auto random_peer = core::random::random_choice(m_peers);
            auto rmsg = bch::message_addrs::make_raw({addr_record_t{peer->m_other_services, endpoint, core::timestamp()} });
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
        addrs.push_back({pair.value.m_service, pair.addr, pair.value.m_last_seen});
    }

    auto rmsg = bch::message_addrs::make_raw({addrs});
    peer->write(std::move(rmsg));
}


// ---------------------------------------------------------------------------
// Share / tx HANDLER cluster (shares / sharereq / sharereply / bestblock /
// have_tx / losing_tx / remember_tx / forget_tx).
//
// Mechanical mirror of btc::Legacy share/tx handlers (oracle protocol_legacy
// .cpp), namespace-swapped btc -> bch, with the two STANDING BCH divergences
// applied at the type seam (not new policy -- both already established in
// messages.hpp / peer.hpp / node.hpp):
//   1. tx-info presence is probed via `requires { obj->m_tx_info; }` (the BCH
//      idiom already used by node.hpp reconstruct), NOT btc's hard-coded
//      `version >= 13 && version < 34` range. BCH shares carry m_tx_info by
//      type; the SFINAE probe is version-agnostic and segwit-free.
//   2. remember_tx hashes each tx via plain `pack(tx)` -- BCH has NO witness,
//      so there is no TX_WITH_WITNESS wrapper (messages.hpp remember_tx field
//      + peer.hpp note). On BCH wtxid == txid, so the hash is unchanged.
// Debug-only SHAREREQ/SHAREREPLY trace counters from the oracle are omitted
// (logging scaffolding, zero behavior).
//
// p2pool-merged-v36 surface: NONE. Pure P2P transport/dispatch (share ingest
// -> processing_shares, sharereq -> handle_get_share serve, tx-relay book-
// keeping). Share-format / PPLNS / coinbase / AuxPoW bytes are untouched;
// serialization + PPLNS conformance already landed verified vs p2poolBCH
// @6603b79. STOP-and-flag fence held -- no oracle byte diverges here.
// ---------------------------------------------------------------------------

void Legacy::HANDLER(shares)
{
    try {
        bch::HandleSharesData result; // share, txs

        for (auto wrappedshare : msg->m_shares)
        {
            bch::ShareType share;
            try
            {
                share = bch::load_share(wrappedshare, peer->addr());
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
                if constexpr (requires { obj->m_tx_info; })
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

            result.add(share, txs);
        }

        processing_shares(result, peer->addr());
    } catch (const std::exception& e) {
        LOG_ERROR << "[Pool] shares handler exception: " << e.what();
    }
}

void Legacy::HANDLER(sharereq)
{
    auto shares = handle_get_share(msg->m_hashes, msg->m_parents, msg->m_stops, peer->addr());

    std::vector<chain::RawShare> rshares;

    try
    {
        for (auto& share : shares)
        {
            rshares.emplace_back(share.version(), pack(share));
        }
        auto reply_msg = bch::message_sharereply::make_raw(msg->m_id, bch::ShareReplyResult::good, rshares);
        peer->write(std::move(reply_msg));
    }
    catch (const std::invalid_argument &e)
    {
        // Serialization overflow: the packed shares exceeded the P2P message
        // size limit. Reply too_long so the peer requests a smaller batch
        // (matches Python p2pool behavior).
        LOG_WARNING << "Share reply too large, sending too_long: " << e.what();
        auto reply_msg = bch::message_sharereply::make_raw(msg->m_id, bch::ShareReplyResult::too_long, {});
        peer->write(std::move(reply_msg));
    }
}

void Legacy::HANDLER(sharereply)
{
    bch::ShareReplyData result;
    if (msg->m_result == ShareReplyResult::good)
    {
        result.m_items.reserve(msg->m_shares.size());
        result.m_raw_items.reserve(msg->m_shares.size());
        for (auto& rshare : msg->m_shares)
        {
            try
            {
                auto share = bch::load_share(rshare, peer->addr());
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

        // p2pool does NOT relay bestblock -- each node broadcasts only from its
        // own block source. Relaying creates an A->B->C->A amplification loop.
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
        peer->m_remote_txs.erase(peer->m_remote_txs.begin(),
                                 std::next(peer->m_remote_txs.begin(),
                                           peer->m_remote_txs.size() - 10000));
    }
}

void Legacy::HANDLER(losing_tx)
{
    // Remove every msg tx hash from the peer's advertised-tx set.
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
    // Phase 1: tx_hashes -- peer references txs to remember by hash (must be
    // present in m_known_txs already).
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

    // Phase 2: txs -- peer sends full transaction bodies; compute hash + store.
    // BCH divergence: plain pack(tx) -- no TX_WITH_WITNESS (no witness on BCH).
    for (auto& tx : msg->m_txs)
    {
        auto packed = pack(tx);
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

} // namespace bch
