#include "coind_node_data.h"

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