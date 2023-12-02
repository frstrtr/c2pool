#include "share_tracker.h"

#include <btclibs/uint256.h>
#include <algorithm>

ShareTracker::ShareTracker(shared_ptr<c2pool::Network> _net) : BaseShareTracker(), verified(*this), net(_net), parent_net(_net->parent), share_store(_net)
{

}

void ShareTracker::init(const std::vector<ShareType>& _shares, const std::vector<uint256>& known_verified_share_hashes)
{
    init_web_metrics();

    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- init shares started: " << c2pool::dev::timestamp();

    PreparedList prepare_shares;
    prepare_shares.add(_shares);

    for (const auto &share : prepare_shares.build_list())
        add(share);

    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- init shares finished: " << c2pool::dev::timestamp();

    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- known shares started: " << c2pool::dev::timestamp();

    {
        std::vector<ShareType> _verified_shares;

        for (auto &share_hash: known_verified_share_hashes)
        {
            if (exist(share_hash))
                _verified_shares.push_back(items.at(share_hash));
        }

        PreparedList prepare_verified_shares;
        prepare_verified_shares.add(_verified_shares);

        for (const auto &share : prepare_verified_shares.build_list())
            verified.add(share);
    }

//    for (auto& share_hash : known_verified_share_hashes)
//    {
//        if (exist(share_hash))
//            verified.add(items.at(share_hash));
//    }
    LOG_DEBUG_SHARETRACKER << "ShareTracker::init -- known shares finished: " << c2pool::dev::timestamp();
}

void ShareTracker::init_web_metrics()
{
    LOG_DEBUG_SHARETRACKER << "ShareTracker::init_web_metrics -- started: " << c2pool::dev::timestamp();

    //---> add metrics
//    stale_counts_metric = net->web->add<stale_counts_metric_type>("stale_counts");
    share_param_metric = net->web->add<share_param_metric_type>("share", [&](nlohmann::json& j, const nlohmann::json& param)
    {
        if (param.empty())
            return j = nullptr;

        auto hash = param.get<std::string>();
        auto result = get_json(uint256S(hash));;
        LOG_INFO << result.dump();
        j = result;
    });

    tracker_info_metric = net->web->add<tracker_info_metric_type>("tracker_info", [&](nlohmann::json& j){
//        j["verified_heads"] = verified.heads
    });

    //---> subs for metrics
/*    added.subscribe([&](const ShareType& share){
        shares_stale_count el;

        el.good = coind::data::target_to_average_attempts(share->target);
        if (*share->stale_info != unk)
        {
            switch (*share->stale_info)
            {
                case orphan:
                    el.orphan = coind::data::target_to_average_attempts(share->target);
                    break;
                case doa:
                    el.doa = coind::data::target_to_average_attempts(share->target);
                    break;
                default:
                    break;
            }
        }
        stale_counts_metric->add(el);
    });*/

//    added.subscribe([&](const ShareType& share){
//        auto lookbehind = std::min(120, get_height( node.best_share_var.value));
//    });


    LOG_DEBUG_SHARETRACKER << "ShareTracker::init_web_metrics -- finished: " << c2pool::dev::timestamp();
}

ShareType ShareTracker::get(uint256 hash)
{
    try
    {
        auto share = get_item(hash);
        return share;
    }
    catch (const std::out_of_range &e)
    {
        if (!hash.IsNull())
            LOG_WARNING << "ShareTracker.get(" << hash.GetHex() << "): out of range!";
        return nullptr;
    }
}

nlohmann::json ShareTracker::get_json(uint256 hash)
{
    auto share = get(hash);
    nlohmann::json j;

    if (share)
        j = share->json();
    else
        return nullptr;

//    result["children"] = reverse[share->hash];
    j["local"]["verified"] = verified.exist(share->hash);
    j["block"]["other_transaction_hashes"] = get_other_tx_hashes(share);

    return j;
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
    removed->happened(res);
}

bool ShareTracker::attempt_verify(ShareType share)
{
    auto t1 = c2pool::dev::debug_timestamp();
    if (verified.exist(share->hash))
    {
        return true;
    }
    auto t2 = c2pool::dev::debug_timestamp();

    auto [height, last] = get_height_and_last(share->hash);
    if (height < net->CHAIN_LENGTH + 1 && !last.IsNull())
        throw std::invalid_argument("attempt_verify error");
    auto t3 = c2pool::dev::debug_timestamp();
    try
    {
        share->check(shared_from_this());
    }
    catch (const std::invalid_argument &e)
    {
        LOG_WARNING << "Share check failed (" << e.what() << "): " << share->hash << " -> " << (share->previous_hash->IsNull() ? uint256::ZERO.GetHex() : share->previous_hash->GetHex());
        return false;
    }
    auto t4 = c2pool::dev::debug_timestamp();

    verified.add(share);
    auto final = c2pool::dev::debug_timestamp();
//    LOG_INFO << "\tATTEMPT_VERIFY TIME: " << final-t1;
//    LOG_INFO << "\t\t" << "t2-t1:" << c2pool::dev::format_date(t2-t1);
//    LOG_INFO << "\t\t" << "t3-t2:" << c2pool::dev::format_date(t3-t2);
//    LOG_INFO << "\t\t" << "t4-t3:" << c2pool::dev::format_date(t4-t3);
//    LOG_INFO << "\t\t" << "final-t4:" << c2pool::dev::format_date(final-t4);
    return true;
}

TrackerThinkResult ShareTracker::think(const std::function<int32_t(uint256)> &block_rel_height_func, uint256 previous_block, uint32_t bits, std::map<uint256, coind::data::tx_type> known_txs)
{
    auto t1 = c2pool::dev::debug_timestamp();
    std::set<desired_type> desired;
    std::set<NetAddress> bad_peer_addresses;

    std::vector<uint256> bads;
    for (auto [head, tail] : heads)
    {
        // only unverified heads
        if (verified.heads.find(head) != verified.heads.end())
            continue;

        auto [head_height, last] = get_height_and_last(head);
        if (head_height <= 1)
        {
            LOG_INFO << "BUG2!";
            auto [head_height2, last2] = get_height_and_last(head);
        }
        auto get_chain_f = get_chain(head, last.IsNull() ? head_height : std::min(5, std::max(0, head_height - net->CHAIN_LENGTH)));

        bool _verified = false;
        uint256 _hash;
        while (get_chain_f(_hash))
        {
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

            NetAddress _peer_addr = c2pool::random::RandomChoice(reverse[last])->second->peer_addr;

            LOG_INFO << "DESIRED1: " << _verified << "; " << last;
            desired.insert({
                                   _peer_addr,
                                   last,
                                   desired_timestamp,
                                   desired_target
                           });
        }
    }
    auto t2 = c2pool::dev::debug_timestamp();

    for (const auto& bad : bads)
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
    auto t3 = c2pool::dev::debug_timestamp();

    for (auto [head, tail] : verified.heads)
    {
        auto t31 = c2pool::dev::debug_timestamp();
        auto [head_height, last_hash] = verified.get_height_and_last(head);
        auto [last_height, last_last_hash] = get_height_and_last(last_hash);

        auto t32 = c2pool::dev::debug_timestamp();
        // XXX: review boundary conditions
        auto want = std::max(net->CHAIN_LENGTH - head_height, 0);
        auto can = last_last_hash.IsNull() ? last_height : std::max(last_height - 1 - net->CHAIN_LENGTH, 0);
        auto _get = std::min(want, can);
        auto t33 = c2pool::dev::timestamp();

        uint256 share_hash;
        auto get_chain_f = get_chain(last_hash, _get);
        while(get_chain_f(share_hash))
        {
            if (!attempt_verify(get(share_hash)))
                break;
        }
        auto t34 = c2pool::dev::debug_timestamp();

        if (head_height < net->CHAIN_LENGTH && !last_last_hash.IsNull())
        {
            LOG_INFO << "DESIRED2";
            auto t35 = c2pool::dev::debug_timestamp();
            uint32_t desired_timestamp = *items[head]->timestamp;
            uint256 desired_target = items[head]->target;

            uint256 temp_hash;
            auto get_chain_f2 = get_chain(head, std::min(head_height, 5));
            while (get_chain_f2(temp_hash))
            {
                desired_timestamp = std::max(desired_timestamp, *items[temp_hash]->timestamp);
                desired_target = std::min(desired_target, items[temp_hash]->target);
            }
            auto t36 = c2pool::dev::timestamp();

            NetAddress _peer_addr = c2pool::random::RandomChoice(
                    verified.reverse[last_hash])->second->peer_addr;

            desired.insert({
                                   _peer_addr,
                                   last_last_hash,
                                   desired_timestamp,
                                   desired_target
                           });
//            LOG_INFO << "\t\t\t" << "t35-t34:" << c2pool::dev::format_date(t35-t34);
//            LOG_INFO << "\t\t\t" << "t36-t35:" << c2pool::dev::format_date(t36-t35);
        }
//        LOG_INFO << "\t\t\t" << "t31-t3:" << c2pool::dev::format_date(t31-t3);
//        LOG_INFO << "\t\t\t" << "t32-t31:" << c2pool::dev::format_date(t32-t31);
//        LOG_INFO << "\t\t\t" << "t33-t32:" << c2pool::dev::format_date(t33-t32);
//        LOG_INFO << "\t\t\t" << "t34-t33:" << c2pool::dev::format_date(t34-t33);

    }
    auto t4 = c2pool::dev::debug_timestamp();

    std::vector<decorated_data<tail_score>> decorated_tails;
    for (auto [tail_hash, head_hashes] : verified.tails)
    {
//        LOG_TRACE << "tail_hash = " << tail_hash << " head_hashes = [ "; std::for_each(head_hashes.begin(), head_hashes.end(), [](const auto& v){std::cout << v << " ";}); std::cout << "]" << std::endl;
        auto max_el = std::max_element(head_hashes.begin(), head_hashes.end(),
                                       [&](const auto &a, const auto &b)
                                       {
                                           return verified.get_work(a->head) < verified.get_work(b->head);
                                       });

        auto _score = decorated_data<tail_score>{{score((*max_el)->head, block_rel_height_func)}, tail_hash};
        decorated_tails.push_back(_score);
    }
    std::sort(decorated_tails.begin(), decorated_tails.end());
    auto [best_tail_score, _best_tail] = decorated_tails.empty() ? decorated_data<tail_score>{{0, uint288()}, uint256::ZERO} : decorated_tails.back();
    auto best_tail = _best_tail;

    auto t5 = c2pool::dev::debug_timestamp();
//    if (c2pool.DEBUG)
//    {
    LOG_DEBUG_SHARETRACKER << decorated_tails.size() << " tails";
    for (auto [score, tail_hash] : decorated_tails)
    {
        LOG_DEBUG_SHARETRACKER << tail_hash.GetHex() << " (" << tail_hash << ", [" << score.chain_len << "; " << score.hashrate.GetHex() << "])";
    }
//    }

    std::vector<decorated_data<head_score>> decorated_heads;
    if (verified.tails.find(best_tail) != verified.tails.end())
    {
        for (const auto& h : verified.tails[best_tail])
        {
            uint288 work_score = verified.get_work(
                    verified.get_nth_parent_key(h->head, std::min(5, verified.get_height(h->head)))
            );
            work_score -= min(should_punish_reason(items[h->head], previous_block, bits, known_txs).punish, 1) * coind::data::target_to_average_attempts(items[h->head]->target);

            auto score = decorated_data<head_score>{
                    {
                            work_score,
                            should_punish_reason(items[h->head], previous_block, bits, known_txs).punish,
                            items[h->head]->time_seen
                    },
                    h->head
            };
            decorated_heads.push_back(score);
        }
        // Правило сортировки задано в head_score::operator<(...)
        std::sort(decorated_heads.begin(), decorated_heads.end());
    }
    auto t6 = c2pool::dev::debug_timestamp();

    // traditional
    std::vector<decorated_data<traditional_score>> traditional_sort;
    if (verified.tails.find(best_tail) != verified.tails.end())
    {
        for (const auto& h : verified.tails[best_tail])
        {
            auto score = decorated_data<traditional_score>{
                    {
                            verified.get_work(
                                    verified.get_nth_parent_key(h->head, std::min(5, verified.get_height(h->head)))
                            ),
                            items[h->head]->time_seen, //assume they can't tell we should punish this share and will be sorting based on time
                            should_punish_reason(items[h->head], previous_block, bits, known_txs).punish
                    },
                    h->head
            };
            traditional_sort.push_back(score);
        }
        // Правило сортировки задано в traditional_score::operator<(...)
        std::sort(traditional_sort.begin(), traditional_sort.end());
    }
    auto punish_aggressively = traditional_sort.empty() ? false : traditional_sort.back().score.reason;
    auto t7 = c2pool::dev::debug_timestamp();

//    if (c2pool.DEBUG))
//    {
    LOG_DEBUG_SHARETRACKER << "tracker data: heads = " << heads.size() << ", tails = " << tails.size() << "; verified: heads = " << verified.heads.size() << ", tails = " << verified.tails.size();
    LOG_DEBUG_SHARETRACKER << decorated_heads.size() << " heads. Top 10:";
    for (auto i = (decorated_heads.size() > 10 ? decorated_heads.size() - 11 : 0); //std::max(decorated_heads.size() - 11, size_t{0});
        i < decorated_heads.size(); i++)
    {
        auto _score = decorated_heads[i].score;
        LOG_DEBUG_SHARETRACKER << "\t" << decorated_heads[i].hash.GetHex() << " " << items[decorated_heads[i].hash]->previous_hash->GetHex() << " " << _score.work << " " << _score.reason << " " << _score.time_seen;
    }
    LOG_DEBUG_SHARETRACKER << "Traditional sort:";
    for (auto i = (traditional_sort.size() > 10 ? traditional_sort.size() - 11 : 0);//std::max(traditional_sort.size() - 11, size_t{0});
        i < traditional_sort.size(); i++)
    {
        auto _score = traditional_sort[i].score;
        LOG_DEBUG_SHARETRACKER << "\t" << traditional_sort[i].hash.GetHex() << " " << items[traditional_sort[i].hash]->previous_hash->GetHex() << " " << _score.work << " " << _score.reason << " " << _score.time_seen;
    }
//    }

    auto [best_head_score, best] = decorated_heads.empty() ? decorated_data<head_score>{{uint256::ZERO, 0, 0}, uint256::ZERO} : decorated_heads.back();

    auto t8 = c2pool::dev::debug_timestamp();

    uint32_t timestamp_cutoff;
    uint288 target_cutoff;

    if (!best.IsNull())
    {
        auto best_share = items[best];
        auto [punish,  punish_reason] = should_punish_reason(best_share, previous_block, bits, known_txs);
        if (punish > 0)
        {
            LOG_INFO << "Punishing share for " << punish_reason << "! Jumping from " << best.ToString() << " to " << best_share->previous_hash->ToString() << "!";
            best = *best_share->previous_hash;
        }

        /* TODO?
            while punish > 0:
                print 'Punishing share for %r! Jumping from %s to %s!' % (punish_reason, format_hash(best), format_hash(best_share.previous_hash))
                best = best_share.previous_hash
                best_share = self.items[best]
                punish, punish_reason = best_share.should_punish_reason(previous_block, bits, self, known_txs)
                if not punish:
                    def best_descendent(hsh, limit=20):
                        child_hashes = self.reverse.get(hsh, set())
                        best_kids = sorted((best_descendent(child, limit-1) for child in child_hashes if not self.items[child].naughty))
                        if not best_kids or limit<0: # in case the only children are naughty
                            return 0, hsh
                        return (best_kids[-1][0]+1, best_kids[-1][1])
                    try:
                        gens, hsh = best_descendent(best)
                        if p2pool.DEBUG: print "best_descendent went %i generations for share %s from %s" % (gens, format_hash(hsh), format_hash(best))
                        best = hsh
                        best_share = self.items[best]
                    except:
                        traceback.print_exc()
         */

        timestamp_cutoff = std::min((uint32_t)c2pool::dev::timestamp(), *best_share->timestamp) - 3600;

        if (best_tail_score.hashrate.IsNull())
        {
            target_cutoff.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        } else
        {
            target_cutoff.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            target_cutoff /= (best_tail_score.hashrate * net->SHARE_PERIOD + 1) * 2; //TODO: accuracy?
        }

        /*TODO?
            # Hard fork logic:
            # If our best share is v34 or higher, we will correctly zero-pad output scripts
            # Otherwise, we preserve a bug in order to avoid a chainsplit
            self.net.PARENT.padding_bugfix = (best_share.VERSION >= 35)
         */
    } else
    {
        timestamp_cutoff = c2pool::dev::timestamp() - 24*60*60;
        target_cutoff.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }
    auto t9 = c2pool::dev::debug_timestamp();

    //    if (c2pool.DEBUG))
//    {
    LOG_DEBUG_SHARETRACKER << "Desire " << desired.size() << " shares. Cutoff: " << c2pool::dev::format_date(c2pool::dev::timestamp() - timestamp_cutoff) << " old diff>" << coind::data::target_to_difficulty(target_cutoff);
    for (const auto &[peer_addr, hash, ts, targ] : desired)
    {
        LOG_DEBUG_SHARETRACKER << "\t"
                               << peer_addr.to_string() << " " << hash << " " << (c2pool::dev::timestamp() - ts)
                               << " " << coind::data::target_to_difficulty(targ)
                               << " " << (ts >= timestamp_cutoff) << " " << (convert_uint<uint288>(targ) <= target_cutoff);
    }
//    }

    std::vector<std::tuple<NetAddress, uint256>> desired_result;
    for (auto [peer_addr, hash, ts, targ] : desired)
    {
        if (ts >= timestamp_cutoff)
            desired_result.emplace_back(peer_addr, hash);
    }
//    LOG_TRACE << "desired_result = " << desired_result.size();
    auto final = c2pool::dev::debug_timestamp();
//    LOG_INFO << "\tSET_BEST_SHARE TIME: " << final-t1;
//    LOG_INFO << "\t\t" << "t2-t1:" << t2-t1;
//    LOG_INFO << "\t\t" << "t3-t2:" << t3-t2;
//    LOG_INFO << "\t\t" << "t4-t3:" << t4-t3;
//    LOG_INFO << "\t\t" << "t5-t4:" << t5-t4;
//    LOG_INFO << "\t\t" << "t6-t5:" << t6-t5;
//    LOG_INFO << "\t\t" << "t7-t6:" << t7-t6;
//    LOG_INFO << "\t\t" << "t8-t7:" << t8-t7;
//    LOG_INFO << "\t\t" << "t9-t8:" << t9-t8;
//    LOG_INFO << "\t\t" << "final-t9:" << final-t9;
    return {best, desired_result, decorated_heads, bad_peer_addresses, punish_aggressively};
}

uint288 ShareTracker::get_pool_attempts_per_second(uint256 previous_share_hash, int32_t dist, bool min_work)
{
    assert(("get_pool_attempts_per_second: assert for dist >= 2", dist >= 2));
    auto _near = get(previous_share_hash);
    auto _far = get(get_nth_parent_key(previous_share_hash,dist - 1));
    auto attempts_delta = get_sum(_near->hash, _far->hash);

    auto time = *_near->timestamp - *_far->timestamp;
    if (time <= 0)
    {
        time = 1;
    }

    uint288 res;
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
    int parents_needed = 0;
    if ((*share->share_info)->share_tx_info.has_value())
    {
        for (auto [share_count, tx_count]: (*share->share_info)->share_tx_info->transaction_hash_refs)
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
    for (auto [share_count, tx_count]: (*share->share_info)->share_tx_info->transaction_hash_refs)
    {
        if (last_shares[share_count]->share_info->get()->share_tx_info.has_value())
            result.push_back(last_shares[share_count]->share_info->get()->share_tx_info->new_transaction_hashes[tx_count]);
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

punish_reason ShareTracker::should_punish_reason(ShareType share, uint256 previous_block, uint32_t bits,
                                                                 const std::map<uint256, coind::data::tx_type> &known_txs)
{
    if (share->pow_hash <= share->header.stream()->bits.bits.target())
        return punish_reason{-1, "block_solution"};

    std::vector<coind::data::tx_type> other_txs;
    if (share->VERSION < 34)
        other_txs = _get_other_txs(share, known_txs);
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
            return punish_reason{true, "txs over block weight limit"};
        if ((stripped_txs_size + 80 + share->gentx_size) > net->BLOCK_MAX_SIZE)
            return punish_reason{true, "txs over block size limit"};
    }
    return punish_reason{false, ""};
}

float ShareTracker::get_average_stale_prop(uint256 share_hash, uint64_t lookbehind)
{
    float res = 0;

    auto chain_f = get_chain(share_hash, lookbehind);

    uint256 hash;
    while (chain_f(hash))
    {
        if (*get_item(hash)->stale_info != unk)
            res += 1;
    }

    return res/(res + lookbehind);
}

std::map<std::vector<unsigned char>, double>
ShareTracker::get_expected_payouts(uint256 best_share_hash, uint256 block_target, uint64_t subsidy)
{
    std::map<std::vector<unsigned char>, double> res;
    double sum = 0;

    auto [weights, total_weight, donation_weight] = get_cumulative_weights(best_share_hash, min(get_height(best_share_hash), net->REAL_CHAIN_LENGTH), coind::data::target_to_average_attempts(block_target) * net->SPREAD * 65535);
    for (const auto &[address, weight] : weights)
    {
        //TODO: optimize .getdouble()?
        auto payout = subsidy * (weight.getdouble()/total_weight.getdouble());

        res[address] = payout;
        sum += payout;
    }

    auto _donation_address = coind::data::donation_script_to_address(net);
    std::vector<unsigned char> donation_address{_donation_address.begin(), _donation_address.end()};

    res[donation_address] = (res.count(donation_address) ? res[donation_address] : 0) + subsidy - sum;

    return res;
}
