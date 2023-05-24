#include "share_tracker.h"

#include <btclibs/uint256.h>
#include <algorithm>

ShareTracker::ShareTracker(shared_ptr<c2pool::Network> _net) : BaseShareTracker(), verified(*this), net(_net), parent_net(_net->parent), share_store(_net)
{

}

void ShareTracker::init(const std::vector<ShareType>& _shares, const std::vector<uint256>& known_verified_share_hashes)
{
    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- init shares started: " << c2pool::dev::timestamp();

    PreparedList prepare_shares(_shares);

    for (auto& fork : prepare_shares.forks)
    {
        auto share_node = fork->tail;
        while (share_node)
        {
            add(share_node->value);
            share_node = share_node->next;
        }
    }

//    for (auto& _share : _shares)
//    {
//        add(_share);
//    }
    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- init shares finished: " << c2pool::dev::timestamp();

    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- known shares started: " << c2pool::dev::timestamp();

    {
        std::vector<ShareType> _verified_shares;

        for (auto &share_hash: known_verified_share_hashes)
        {
            if (exist(share_hash))
                _verified_shares.push_back(items.at(share_hash));
        }

        PreparedList prepare_verified_shares(_verified_shares);

        for (auto& fork : prepare_verified_shares.forks)
        {
            auto share_node = fork->tail;
            while (share_node)
            {
                verified.add(share_node->value);
                share_node = share_node->next;
            }
        }
    }

//    for (auto& share_hash : known_verified_share_hashes)
//    {
//        if (exist(share_hash))
//            verified.add(items.at(share_hash));
//    }
    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- known shares finished: " << c2pool::dev::timestamp();

    // Set DOA rule
    //TODO
//    doa_element_type::set_rules([&](ShareType share){
////        my_count=lambda share: 1 if share.hash in self.my_share_hashes else 0,
////            my_doa_count=lambda share: 1 if share.hash in self.my_doa_share_hashes else 0,
////            my_orphan_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'orphan' else 0,
////            my_dead_announce_count=lambda share: 1 if share.hash in self.my_share_hashes and share.share_data['stale_info'] == 'doa' else 0,
////        auto result = std::make_tuple(
////                my_sh
////                );
//
//        return std::make_tuple<int32_t, int32_t, int32_t, int32_t>(0, 0, 0, 0);
//    });
}

ShareType ShareTracker::get(uint256 hash)
{
    try
    {
        auto share = items.at(hash);
        return share;
    }
    catch (const std::out_of_range &e)
    {
        LOG_WARNING << "ShareTracker.get(" << hash.GetHex() << "): out of range!";
        return nullptr;
    }
}

void ShareTracker::add(ShareType share)
{
    if (!share)
    {
        LOG_WARNING << "ShareTracker::add called, when share = nullptr!";
        return;
    }

    if (!exist(share->hash))
    {
        BaseShareTracker::add(share);
    } else
    {
        LOG_WARNING << share->hash.ToString() << " item already present";
    }
}

void ShareTracker::remove(uint256 hash)
{
    auto res = get(hash);
    //TODO:
    removed.happened(res);
}

bool ShareTracker::attempt_verify(ShareType share)
{
    if (verified.exist(share->hash))
    {
        return true;
    }

    auto [height, last] = get_height_and_last(share->hash);
    if (height < net->CHAIN_LENGTH + 1 && !last.IsNull())
        throw std::invalid_argument("");

    try
    {
        share->check(shared_from_this());
    }
    catch (const std::invalid_argument &e)
    {
        LOG_WARNING << "Share check failed (" << e.what() << "): " << share->hash << " -> " << (share->previous_hash->IsNull() ? uint256::ZERO.GetHex() : share->previous_hash->GetHex());
        return false;
    }

    verified.add(share);
    return true;
}

TrackerThinkResult ShareTracker::think(const std::function<int32_t(uint256)> &block_rel_height_func, uint256 previous_block, uint32_t bits, std::map<uint256, coind::data::tx_type> known_txs)
{
    std::set<desired_type> desired;
    std::set<std::tuple<std::string, std::string>> bad_peer_addresses;

    std::vector<uint256> bads;

    for (auto [head, tail] : heads)
    {
        // only unverified heads
        if (verified.heads.find(head) != verified.heads.end())
            continue;

        auto [head_height, last] = get_height_and_last(head);
        LOG_TRACE << "head1 = " << head << " tail1 = " << tail << std::endl;
        LOG_TRACE << "head_height = " << head_height << ", last = " << last.GetHex();

        auto get_chain_f = get_chain(head, last.IsNull() ? head_height : std::min(5, std::max(0, head_height -
                                                                                                 net->CHAIN_LENGTH)));

        uint256 _hash;
        bool _verified = false;
        while (get_chain_f(_hash))
        {
            LOG_TRACE << "GET_CHAIN hash = " << _hash.GetHex();
            if (attempt_verify(get(_hash)))
            {
                _verified = true;
                break;
            }
            bads.push_back(_hash);
        }

        if (!_verified && !last.IsNull())
        {
            uint32_t desired_timestamp = *items[head]->timestamp;
            uint256 desired_target = items[head]->target;

            uint256 temp_hash;
            auto get_chain_f2 = get_chain(head, std::min(head_height, 5));
            while (get_chain_f2(temp_hash))
            {
                desired_timestamp = std::max(desired_timestamp, *items[temp_hash]->timestamp);
                desired_target = std::min(desired_target, items[temp_hash]->target);
            }

            std::tuple<std::string, std::string> _peer_addr = c2pool::random::RandomChoice(
                    reverse[last])->second->peer_addr;

            desired.insert({
                                   _peer_addr,
                                   last,
                                   desired_timestamp,
                                   desired_target
                           });
        }
    }

    for (auto bad : bads)
    {
        if (verified.items.count(bad) != 0)
            throw std::invalid_argument("verified.items.count(bad) != 0");

        auto bad_share = items[bad];
        bad_peer_addresses.insert(bad_share->peer_addr);

        try
        {
            remove(bad);
        } catch (const std::error_code &ec)
        {
            LOG_ERROR << "BAD REMOVE ERROR:  " << ec.message();
        }
    }

    for (auto [head, tail] : verified.heads)
    {
        LOG_TRACE << "head2 = " << head << " tail2 = " << tail << std::endl;
        auto [head_height, last_hash] = verified.get_height_and_last(head);
        auto [last_height, last_last_hash] = get_height_and_last(last_hash);

        // XXX: review boundary conditions
        auto want = std::max(net->CHAIN_LENGTH - head_height, 0);
        auto can = last_last_hash.IsNull() ? last_height : std::max(last_height - 1 - net->CHAIN_LENGTH, 0);
        auto _get = std::min(want, can);

        uint256 share_hash;
        auto get_chain_f = get_chain(last_hash, _get);
        while(get_chain_f(share_hash))
        {
            if (!attempt_verify(get(share_hash)))
                break;
        }

        if (head_height < net->CHAIN_LENGTH && !last_last_hash.IsNull())
        {
            uint32_t desired_timestamp = *items[head]->timestamp;
            uint256 desired_target = items[head]->target;

            uint256 temp_hash;
            auto get_chain_f2 = get_chain(head, std::min(head_height, 5));
            while (get_chain_f2(temp_hash))
            {
                desired_timestamp = std::max(desired_timestamp, *items[temp_hash]->timestamp);
                desired_target = std::min(desired_target, items[temp_hash]->target);
            }

            std::tuple<std::string, std::string> _peer_addr = c2pool::random::RandomChoice(
                    verified.reverse[last_hash])->second->peer_addr;

            desired.insert({
                                   _peer_addr,
                                   last_last_hash,
                                   desired_timestamp,
                                   desired_target
                           });
        }
    }

    std::vector<std::tuple<std::tuple<int32_t, arith_uint288>, arith_uint256>> decorated_tails;
    for (auto [tail_hash, head_hashes] : verified.tails)
    {
        LOG_TRACE << "tail_hash = " << tail_hash << " head_hashes = [ "; std::for_each(head_hashes.begin(), head_hashes.end(), [](const auto& v){std::cout << v << " ";}); std::cout << "]" << std::endl;
        auto max_el = std::max_element(head_hashes.begin(), head_hashes.end(),
                                       [&](const auto &a, const auto &b)
                                       {
                                           return UintToArith256(verified.get_work(a->head)) < UintToArith256(verified.get_work(b->head));
                                       });

        auto _score = std::make_tuple(score((*max_el)->head, block_rel_height_func), UintToArith256(tail_hash));
        decorated_tails.push_back(_score);
    }
    std::sort(decorated_tails.begin(), decorated_tails.end());
    auto [best_tail_score, _best_tail] = decorated_tails.empty() ? std::make_tuple(std::make_tuple(0, UintToArith288(uint288())), UintToArith256(uint256::ZERO)) : decorated_tails.back();
    auto best_tail = ArithToUint256(_best_tail);
//    if (c2pool.DEBUG)
//    {
    LOG_DEBUG_SHARETRACKER << decorated_tails.size() << " tails";
    for (auto [score, tail_hash] : decorated_tails)
    {
        LOG_DEBUG_SHARETRACKER << tail_hash.GetHex() << " (" << std::get<0>(score) << ", " << std::get<1>(score).GetHex() << ")";
    }
//    }

    std::vector<std::tuple<std::tuple<arith_uint256, int32_t, int32_t>, arith_uint256>> decorated_heads;
    if (verified.tails.find(best_tail) != verified.tails.end())
    {
        for (auto h : verified.tails[best_tail])
        {
            LOG_TRACE << "h = " << h << std::endl;
            auto el = std::make_tuple(
                    UintToArith256(verified.get_work(
                            verified.get_nth_parent_key(h->head, std::min(5, verified.get_height(h->head))))),
                    -std::get<0>(should_punish_reason(items[h->head], previous_block, bits, known_txs)),
                    -items[h->head]->time_seen
            );
            decorated_heads.emplace_back(el, UintToArith256(h->head));
        }
        std::sort(decorated_heads.begin(), decorated_heads.end());
    }
    auto [best_head_score, _best] = decorated_heads.empty() ? std::make_tuple(std::make_tuple(UintToArith256(uint256::ZERO), 0, 0), UintToArith256(uint256::ZERO)) : decorated_heads.back();
    auto best = ArithToUint256(_best);

//    if (c2pool.DEBUG))
//    {
    LOG_DEBUG_SHARETRACKER << decorated_heads.size() << " heads. Top 10:";
    int i = decorated_heads.size() - 11;
    if (i < 0)
        i = 0;
    for (; i < decorated_heads.size(); i++)
    {
        auto _score = std::get<0>(decorated_heads[i]);
        LOG_DEBUG_SHARETRACKER << "\t" << std::get<1>(decorated_heads[i]).GetHex() << " " << items[ArithToUint256(std::get<1>(decorated_heads[i]))]->previous_hash->GetHex() << " " << ArithToUint256(std::get<0>(_score)) << " " << std::get<1>(_score) << " " << std::get<2>(_score);
    }
//    }

    uint32_t timestamp_cutoff;
    arith_uint288 target_cutoff;

    if (!best.IsNull())
    {
        auto best_share = items[best];
        auto [punish,  punish_reason] = should_punish_reason(best_share, previous_block, bits, known_txs);
        if (punish > 0)
        {
            LOG_INFO << "Punishing share for " << punish_reason << "! Jumping from " << best.ToString() << " to " << best_share->previous_hash->ToString() << "!";
            best = *best_share->previous_hash;
        }

        timestamp_cutoff = std::min((uint32_t)c2pool::dev::timestamp(), *best_share->timestamp) - 3600;

        if (std::get<1>(best_tail_score).IsNull())
        {
            target_cutoff.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        } else
        {
            target_cutoff.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            target_cutoff /= (std::get<1>(best_tail_score) * net->SHARE_PERIOD + 1) * 2;
        }
    } else
    {
        timestamp_cutoff = c2pool::dev::timestamp() - 24*60*60;
        target_cutoff.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    //    if (c2pool.DEBUG))
//    {
    LOG_DEBUG_SHARETRACKER << "Desire " << desired.size() << " shares. Cutoff: " << c2pool::dev::timestamp() - timestamp_cutoff << " old diff>" << coind::data::target_to_difficulty(uint256S(target_cutoff.GetHex()));
    for (const auto &[peer_addr, hash, ts, targ] : desired)
    {
        LOG_DEBUG_SHARETRACKER << "\t"
                               << std::get<0>(peer_addr) << ":" << std::get<1>(peer_addr)
                               << " " << hash << " " << (c2pool::dev::timestamp() - ts) << " " << coind::data::target_to_difficulty(targ)
                               << " " << (ts >= timestamp_cutoff) << " " << (Uint256ToArith288(targ) <= target_cutoff);
    }
//    }

    std::vector<std::tuple<std::tuple<std::string, std::string>, uint256>> desired_result;
    for (auto [peer_addr, hash, ts, targ] : desired)
    {
        if (ts >= timestamp_cutoff)
            desired_result.emplace_back(peer_addr, hash);
    }
    LOG_TRACE << "desired_result = " << desired_result.size();
    return {best, desired_result, decorated_heads, bad_peer_addresses};
}

arith_uint288 ShareTracker::get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work)
{
    assert(("get_pool_attempts_per_second: assert for dist >= 2", dist >= 2));
    auto near = get(previous_share_hash);
    auto far = get(get_nth_parent_key(previous_share_hash,dist - 1));
    auto attempts_delta = get_sum(near->hash, far->hash);

    auto time = *near->timestamp - *far->timestamp;
    if (time <= 0)
    {
        time = 1;
    }

    arith_uint288 res;
    if (min_work)
    {
        res = attempts_delta.min_work;
    } else
    {
        res = attempts_delta.work;
    }
    res /= time;
    return res;
}

std::vector<uint256> ShareTracker::get_other_tx_hashes(ShareType share)
{
    uint64_t parents_needed = 0;
    if (!(*share->share_info)->transaction_hash_refs.empty())
    {
        for (auto [share_count, tx_count]: (*share->share_info)->transaction_hash_refs)
        {
            parents_needed = std::max(parents_needed, share_count);
        }
    }
    auto parents = get_height(share->hash);
    if (parents < parents_needed)
        return {};

    std::vector<ShareType> last_shares;

    uint256 last_share_hash;
    auto get_chain_f = get_chain(share->hash, parents_needed + 1);
    while (get_chain_f(last_share_hash))
    {
        last_shares.push_back(get(last_share_hash));
    }

    std::vector<uint256> result;
    for (auto [share_count, tx_count]: (*share->share_info)->transaction_hash_refs)
    {
        result.push_back(last_shares[share_count]->share_info->get()->new_transaction_hashes[tx_count]);
    }
    return result;
}

std::vector<coind::data::tx_type> ShareTracker::_get_other_txs(ShareType share, const std::map<uint256, coind::data::tx_type> &known_txs)
{
    auto other_tx_hashes = get_other_tx_hashes(share);

    if (other_tx_hashes.empty())
    {
        return {}; // not all parents present
    }

    if (!std::all_of(other_tx_hashes.begin(), other_tx_hashes.end(), [&](uint256 tx_hash) { return known_txs.count(tx_hash) > 0; }))
    {
        return {}; // not all txs present
    }

    std::vector<coind::data::tx_type> result;
    std::for_each(other_tx_hashes.begin(), other_tx_hashes.end(), [&](uint256 &tx_hash){
        result.push_back(known_txs.at(tx_hash));
    });

    return result;
}

std::tuple<bool, std::string> ShareTracker::should_punish_reason(ShareType share, uint256 previous_block, uint32_t bits,
                                                                 const std::map<uint256, coind::data::tx_type> &known_txs)
{
    if (UintToArith256(share->pow_hash) <= UintToArith256(share->header.stream()->bits.bits.target()))
        return {-1, "block_solution"};

    auto other_txs = _get_other_txs(share, known_txs);
    if (!other_txs.empty())
    {
        // Оптимизация?: два all_txs_size; stripped_txs_size -- за один цикл, а не два.
        auto all_txs_size = std::accumulate(other_txs.begin(), other_txs.end(), 0, [&](const int32_t &a, coind::data::tx_type tx)-> int32_t{
            coind::data::stream::TransactionType_stream packed_tx = tx;

            PackStream stream;
            stream << packed_tx;
            return a + stream.size();
        });

        auto stripped_txs_size = std::accumulate(other_txs.begin(), other_txs.end(), 0, [&](const int32_t &a, coind::data::tx_type tx)-> int32_t{
            auto stream_txid = coind::data::stream::TxIDType_stream(tx->version,tx->tx_ins, tx->tx_outs, tx->lock_time);
            PackStream stream;
            stream << stream_txid;

            return a + stream.size();
        });

        if ((all_txs_size + 3 * stripped_txs_size + 4*80 + share->gentx_weight) > net->BLOCK_MAX_WEIGHT)
            return {true, "txs over block weight limit"};
        if ((stripped_txs_size + 80 + share->gentx_size) > net->BLOCK_MAX_SIZE)
            return {true, "txs over block size limit"};
    }
    return {false, ""};
}