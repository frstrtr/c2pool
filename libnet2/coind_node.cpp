#include "coind_node.h"

#include <libdevcore/deferred.h>

void CoindNodeData::handle_header(coind::data::BlockHeaderType new_header)
{
    auto packed_new_header = new_header.get_pack();
    arith_uint256 hash_header = UintToArith256(parent_net->POW_FUNC(packed_new_header));
    //check that header matches current target
    if (!(hash_header <= UintToArith256(coind_work.value().bits.target())))
        return;

    auto coind_best_block = coind_work.value().previous_block;

    if (best_block_header.isNull() ||
        ((new_header->previous_block == coind_best_block) && (coind::data::hash256(packed_new_header) == coind_best_block)) ||
        ((coind::data::hash256(packed_new_header) == coind_best_block) && (best_block_header.value()->previous_block != coind_best_block)))
    {
        best_block_header = new_header;
    }
}

void CoindNodeData::set_best_share()
{
    auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker->think(get_height_rel_highest, coind_work.value().previous_block, coind_work.value().bits.get(), known_txs.value());

    best_share = _best;
    desired = _desired;

    //TODO: p2p_node connect
//    if (p2p_node)
//    {
//        for (auto bad_addr : _bad_peer_addresses)
//        {
//            //TODO: O(n) -- wanna for optimize
//            for (auto peer : p2p_node->get_peers())
//            {
//                if (peer.second->get_addr())
//                {
//
//                }
//            }
//        }
//    }

    //TODO: Проверка подключения на p2p_node.
    // if (_node_manager->p2pNode() != nullptr)
    // {
    //     for (auto bad_peer_address : bad_peer_addresses)
    //     {
    //         for (auto peer : _node_manager->p2pNode()->peers)
    //         {
    //             if (peer.addr == bad_peer_address)
    //             {
    //                 peer.badPeerHappened();
    //                 break;
    //             }
    //         }
    //     }
    // }
}

void CoindNodeData::clean_tracker()
{
//TODO:
    auto [_best, _desired, _decorated_heads, _bad_peer_addresses] = tracker->think(get_height_rel_highest, coind_work.value().previous_block, coind_work.value().bits.get(), known_txs.value());

    // if (decorated_heads.size() > 0)
    // {
    //     for (int i = 0; i < 1000; i++)
    //     {
    //         bool skip_flag = false;
    //         std::set<uint256> to_remove;
    //         for (auto head : tracker.heads)
    //         {
    //             for (int h = decorated_heads.size() - 5; h < decorated_heads.size(); h++)
    //             {
    //                 if (decorated_heads[h] == head.share_hash)
    //                 {
    //                     skip_flag = true;
    //                 }
    //             }

    //             if (tracker.items[head.share_hash].time_seen > c2pool::time::timestamp() - 300)
    //             {
    //                 skip_flag = true;
    //             }

    //             if (tracker.verified.items.find(head.share_hash) == tracker.verified.items.end())
    //             {
    //                 skip_flag = true;
    //             }

    //             //TODO:
    //             //if max(self.tracker.items[after_tail_hash].time_seen for after_tail_hash in self.tracker.reverse.get(tail)) > time.time() - 120: # XXX stupid
    //             //  continue

    //             if (!skip_flag)
    //             {
    //                 to_remove.insert(head.share_hash);
    //             }
    //         }
    //         if (to_remove.size() == 0)
    //         {
    //             break;
    //         }
    //         for (auto share_hash : to_remove)
    //         {
    //             if (tracker.verified.items.find(share_hash) != tracker.verified.items.end())
    //             {
    //                 tracker.verified.items.erase(share_hash);
    //             }
    //             tracker.remove(share_hash);
    //         }
    //     }
    // }

    // for (int i = 0; i < 1000; i++)
    // {
    //     bool skip_flag = false;
    //     std::set<uint256, set<uint256>> to_remove;

    //     for (auto tail : tracker.tails)
    //     {
    //         int min_height = INT_MAX;
    //         for (auto head : tail.heads)
    //         {
    //             min_height = std::min(min_height, tracker.get_heigth(head));
    //             if (min_height < 2 * tracker->net->CHAIN_LENGTH + 10)
    //             {
    //                 continue
    //             }
    //             to_remove.insert(tracker.reverse.get(head.tail, set<uint256>()));
    //         }
    //     }

    //     if (to_remove.size() == 0)
    //     {
    //         break;
    //     }

    //     //# if removed from this, it must be removed from verified
    //     for (auto aftertail : to_remove)
    //     {
    //         if (tracker.tails.find(tracker.items[aftertail].previous_hash) == tracker.tails.end())
    //         {
    //             continue;
    //         }
    //         if (tracker.verified.items.find(aftertail) != tracker.verified.items.end())
    //         {
    //             tracker.verified.remove(aftertail);
    //         }
    //         tracker.remove(aftertail);
    //     }
    // }

    set_best_share();
}

void CoindNode::work_poller()
{
    coind_work = coind->getwork(txidcache, known_txs.value());
    work_poller_t.expires_from_now(boost::posix_time::seconds(15));
    work_poller_t.async_wait(bind(&CoindNode::work_poller, this));
}

void CoindNode::poll_header()
{
    if (!protocol)
        return;
    //TODO update protocol: handle_header(protocol->get_block_header(coind_work.value().previous_block));
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_version> msg, std::shared_ptr<CoindProtocol> protocol)
{
    auto verack = std::make_shared<coind::messages::message_verack>();
    protocol->write(verack);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_verack> msg, std::shared_ptr<CoindProtocol> protocol)
{
    protocol->get_block = std::make_shared<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockType, uint256>>(context, [&](uint256 hash) -> void {
        auto _msg = std::make_shared<coind::messages::message_getdata>(std::vector<inventory>{{block, hash}});
        protocol->write(_msg);
    });

    protocol->get_block_header = std::make_shared<c2pool::deferred::ReplyMatcher<uint256, coind::data::types::BlockHeaderType, uint256>> (context, [&](uint256 hash){
        auto  _msg = std::make_shared<coind::messages::message_getheaders>(1, std::vector<uint256>{}, hash);
        protocol->write(_msg);
    });

//    pinger(30); //TODO: wanna for this?
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_ping> msg, std::shared_ptr<CoindProtocol> protocol)
{
    auto msg_pong = std::make_shared<coind::messages::message_pong>(msg->nonce.get());
    protocol->write(msg_pong);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_pong> msg, std::shared_ptr<CoindProtocol> protocol)
{
    LOG_DEBUG << "Handle_PONG";
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_alert> msg, std::shared_ptr<CoindProtocol> protocol)
{
    LOG_WARNING << "Handled message_alert signature: " << msg->signature.get();
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_getaddr> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_addr> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_inv> msg, std::shared_ptr<CoindProtocol> protocol)
{
    for (auto _inv : msg->invs.get())
    {
        auto inv = _inv.get();
        switch (inv.type)
        {
            case inventory_type::tx:
            {
                LOG_TRACE << "HANDLED TX";
                std::vector<inventory> inv_vec = {inv};
                auto msg_getdata = std::make_shared<coind::messages::message_getdata>(inv_vec);
                protocol->write(msg_getdata);
            }
                break;
            case inventory_type::block:
                LOG_TRACE << "HANDLED BLOCK, with hash: " << inv.hash.GetHex();
                new_block.happened(inv.hash); //self.factory.new_block.happened(inv['hash'])
                break;
            default:
                //when Unkown inv type
                LOG_WARNING << "Unknown inv type";
                break;
        }
    }
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_getdata> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_reject> msg, std::shared_ptr<CoindProtocol> protocol)
{
// if p2pool.DEBUG:
    //      print >>sys.stderr, 'Received reject message (%s): %s' % (message, reason)
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_getblocks> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_getheaders> msg, std::shared_ptr<CoindProtocol> protocol)
{
// empty
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_tx> msg, std::shared_ptr<CoindProtocol> protocol)
{
    new_tx.happened(msg->tx.tx);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_block> msg, std::shared_ptr<CoindProtocol> protocol)
{
    PackStream packed_header;
    packed_header << msg->block;
    auto block_hash = coind::data::hash256(packed_header);

    coind::data::BlockTypeA block;
    block.set_stream(msg->block);

    protocol->get_block->got_response(block_hash, *block.get());
    protocol->get_block_header->got_response(block_hash, block.get()->header);
}

void CoindNode::handle(std::shared_ptr<coind::messages::message_headers> msg, std::shared_ptr<CoindProtocol> protocol)
{
    std::vector<coind::data::types::BlockHeaderType> _new_headers;

    for (auto _block : msg->headers.get())
    {
        coind::data::BlockTypeA block;
        block.set_stream(_block);

        PackStream packed_header;
        packed_header << _block;
        auto block_hash = coind::data::hash256(packed_header);

        protocol->get_block_header->got_response(block_hash, block->header);

        _new_headers.push_back(block->header);
    }

    new_headers.happened(_new_headers);
}
