#include "coind_node_data.h"

void CoindNodeData::handle_header(coind::data::BlockHeaderType new_header)
{
	auto packed_new_header = new_header.get_pack();
	uint256 hash_header = parent_net->POW_FUNC(packed_new_header);
	//check that header matches current target
	if (!(hash_header <= coind_work->value().bits.target()))
		return;

	auto coind_best_block = coind_work->value().previous_block;

	if (best_block_header->isNull() ||
		((new_header->previous_block == coind_best_block) && (coind::data::hash256(packed_new_header) == coind_best_block)) ||
		((coind::data::hash256(packed_new_header) == coind_best_block) && (best_block_header->value()->previous_block != coind_best_block)))
	{
		best_block_header->set(new_header);
	}
}

void CoindNodeData::set_best_share()
{
    auto t1 = c2pool::dev::timestamp();
	auto [_best, _desired, _decorated_heads, _bad_peer_addresses, punish] = tracker->think(get_height_rel_highest.ref_func(), coind_work->value().previous_block, coind_work->value().bits.get(), known_txs->value());

    /* TODO for punish?
     if self.punish and not oldpunish and best == self.best_share_var.value: # need to reissue work with lower difficulty
            self.best_share_var.changed.happened(best) # triggers wb.new_work_event to reissue work
     */

    auto t2 = c2pool::dev::timestamp();
	best_share->set(_best);
    LOG_DEBUG_COIND << "new best_share: " << best_share->value().GetHex();
    if (!best_share->value().IsNull())
        LOG_DEBUG_COIND << "REAL NEW BEST SHARE: " << best_share->value().GetHex();
	desired->set(_desired);
    auto t3 = c2pool::dev::timestamp();

    if (tracker->exist(_best))
        cur_share_version = tracker->get(_best)->VERSION;
    else
        cur_share_version = 0; //BaseShare.Version

	if (pool_node)
	{
		for (auto bad_peer_address : _bad_peer_addresses)
		{
			for (auto peer : pool_node->peers)
			{
				if (peer.second->get_addr() == bad_peer_address)
				{
					//TODO: UPDATE FOR BAN BAD PEER
					// peer.second->bad_peer_happened();
					break;
				}
			}
		}
	}
    auto t4 = c2pool::dev::timestamp();
//    LOG_INFO << "SET_BEST_SHARE TIME:";
//    LOG_INFO << "\t" << "t2-t1:" << c2pool::dev::format_date(t2-t1);
//    LOG_INFO << "\t" << "t3-t2:" << c2pool::dev::format_date(t3-t2);
//    LOG_INFO << "\t" << "t4-t3:" << c2pool::dev::format_date(t4-t3);
}

void CoindNodeData::clean_tracker()
{
	// TODO?: Подумать, нужно ли это или очистка шар будет проходить по нашему алгоритму?
	auto [_best, _desired, _decorated_heads, _bad_peer_addresses, punish] = tracker->think(get_height_rel_highest.ref_func(), coind_work->value().previous_block, coind_work->value().bits.get(), known_txs->value());

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

void CoindNodeData::submit_block(coind::data::types::BlockType &block, bool ignore_failure)
{
    // P2P
    if (!is_connected())
    {
        //TODO: add net.PARENT.BLOCK_EXPLORER_URL_PREFIX
        LOG_ERROR << "No bitcoind connection when block submittal attempted!"; //<< /*net.PARENT.BLOCK_EXPLORER_URL_PREFIX <<*/ /*bitcoin_data.hash256(bitcoin_data.block_header_type.pack(block['header'])))*/
        // TODO: raise deferral.RetrySilentlyException()
        throw std::runtime_error("No bitcoind connection in submit_block");
    }
    //---send_block
    send_block(block);

    // RPC
    bool segwit_activated = false;
    {
        segwit_activated += std::any_of(coind_work->value().rules.begin(), coind_work->value().rules.end(), [](const auto &v){ return v == "segwit";});
        segwit_activated += std::any_of(coind_work->value().rules.begin(), coind_work->value().rules.end(), [](const auto &v){ return v == "!segwit";});
    }

    coind->submit_block(block, coind_work->value().mweb, /*coind_work._value->use_getblocktemplate,*/ ignore_failure, segwit_activated);
}