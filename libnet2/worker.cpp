#include "worker.h"

#include <utility>
#include <vector>
#include <tuple>
#include <algorithm>
#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>

#include "pool_node_data.h"
#include "coind_node_data.h"
#include <btclibs/uint256.h>
#include <btclibs/script/script.h>
#include <libdevcore/random.h>
#include <sharechains/data.h>
#include <sharechains/share_adapters.h>
#include <sharechains/generate_tx.h>
#include <libcoind/jsonrpc/results.h>
#include <sharechains/tree_tracker/rules.h>

using std::vector;

Work Work::from_jsonrpc_data(const coind::getwork_result& data)
{
    Work result{};

    result.version = data.version;
    result.previous_block = data.previous_block;
    result.bits = data.bits.get();
    result.coinbaseflags = data.coinbaseflags.data;
    result.height = data.height;
    result.timestamp = data.time;
    result.transactions = data.transactions;
    for (auto v: data.transaction_fees)
    {
        if (v.has_value())
        {
            result.transaction_fees.push_back(v.value());
        } else
        {
            result.transaction_fees.push_back(0);
        }
    }
    result.subsidy = data.subsidy;
    result.last_update = data.last_update;

    return result;
}

bool Work::operator==(const Work &value) const
{
	return  std::tie(version, previous_block, bits, coinbaseflags, height, timestamp, transactions, transaction_fees, merkle_link, subsidy) ==
			std::tie(value.version, value.previous_block, value.bits, value.coinbaseflags, value.height, value.timestamp, value.transactions, value.transaction_fees, value.merkle_link, value.subsidy);
}

bool Work::operator!=(const Work &value) const
{
    return !(*this == value);
}

Worker::Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<PoolNodeData> pool_node,
               shared_ptr<CoindNodeData> coind_node, std::shared_ptr<ShareTracker> tracker) : _net(std::move(net)),
                                                                                                          current_work(make_variable<Work>(Work{})),
                                                                                                          new_work(make_event()),
                                                                                                          share_received(make_event()),
                                                                                                          pseudoshare_received(make_event()),
                                                                                                          removed_unstales(make_variable<std::tuple<int32_t, int32_t, int32_t>>(std::make_tuple(0,0,0))),
                                                                                                          removed_doa_unstales(make_variable<int32_t>(0)),
                                                                                                          _pool_node(std::move(pool_node)),
                                                                                                          _coind_node(std::move(coind_node)),
                                                                                                          _tracker(std::move(tracker)),
                                                                                                          local_rate_monitor(10 * 60),
                                                                                                          local_addr_rate_monitor(10 * 60)

{
    // DOA Rule for PrefsumShare
    _tracker->rules.add("doa", [&](const ShareType &share)
    {
        if (!share)
        {
            LOG_WARNING << "NULLPTR SHARE IN DOAElement MAKE!";
            return DOAElement{};
        }
        int32_t my_count = 0;
        if (my_share_hashes.count(share->hash))
            my_count = 1;

        int32_t my_doa_count = 0;
        if (my_doa_share_hashes.count(share->hash))
            my_doa_count = 1;

        int32_t my_orphan_announce_count = 0;
        if (my_share_hashes.count(share->hash) && (*share->share_data)->stale_info == orphan)
            my_orphan_announce_count = 1;


        int32_t my_dead_announce_count = 0;
        if (my_share_hashes.count(share->hash) && (*share->share_data)->stale_info == doa)
            my_dead_announce_count = 1;

        return DOAElement{my_count, my_doa_count, my_orphan_announce_count, my_dead_announce_count};
    },[]()
    {
        return DOAElement{};
    },[](shares::Rule& l, const shares::Rule& r)
    {
        auto _l = std::any_cast<DOAElement>(&l.value);
        auto _r = std::any_cast<DOAElement>(&r.value);
        *_l += *_r;
    }, [](shares::Rule& l, const shares::Rule& r)
    {
        auto _l = std::any_cast<DOAElement>(&l.value);
        auto _r = std::any_cast<DOAElement>(&r.value);
        *_l -= *_r;
    });

    _tracker->verified.rules.add("doa", [&](const ShareType &share)
    {
        if (!share)
        {
            LOG_WARNING << "NULLPTR SHARE IN DOAElement MAKE!";
            return DOAElement{};
        }
        int32_t my_count = 0;
        if (my_share_hashes.count(share->hash))
            my_count = 1;

        int32_t my_doa_count = 0;
        if (my_doa_share_hashes.count(share->hash))
            my_doa_count = 1;

        int32_t my_orphan_announce_count = 0;
        if (my_share_hashes.count(share->hash) && (*share->share_data)->stale_info == orphan)
            my_orphan_announce_count = 1;


        int32_t my_dead_announce_count = 0;
        if (my_share_hashes.count(share->hash) && (*share->share_data)->stale_info == doa)
            my_dead_announce_count = 1;

        return DOAElement{my_count, my_doa_count, my_orphan_announce_count, my_dead_announce_count};
    },[]()
    {
        return DOAElement();
    }, [](shares::Rule& l, const shares::Rule& r)
    {
        auto _l = std::any_cast<DOAElement>(&l.value);
        auto _r = std::any_cast<DOAElement>(&r.value);
        *_l += *_r;
    }, [](shares::Rule& l, const shares::Rule& r)
    {
        auto _l = std::any_cast<DOAElement>(&l.value);
        auto _r = std::any_cast<DOAElement>(&r.value);
        *_l -= *_r;
    });


    // sub for removed_unstales Variable's
    _tracker->removed->subscribe([&](ShareType share)
                                {
                                    auto [count, orphan, doa] = removed_unstales->value();
                                    if (my_share_hashes.count(share->hash) &&
                                        tracker->is_child_of(share->hash, _coind_node->best_share->value()))
                                    {
                                        removed_unstales->set(std::make_tuple(
                                                count + 1,
                                                orphan + ((*share->share_data)->stale_info == orphan ? 1 : 0),
                                                doa + ((*share->share_data)->stale_info == doa ? 1 : 0)
                                        ));
                                    }

                                    if (my_doa_share_hashes.count(share->hash) &&
                                        _tracker->is_child_of(share->hash, _coind_node->best_share->value()))
                                    {
                                        removed_doa_unstales->value() += 1;
                                    }
                                });

    /* TODO
     * # MERGED WORK

    self.merged_work = variable.Variable({})

    @defer.inlineCallbacks
    def set_merged_work(merged_url, merged_userpass):
        merged_proxy = jsonrpc.HTTPProxy(merged_url, dict(Authorization='Basic ' + base64.b64encode(merged_userpass)))
        while self.running:
            auxblock = yield deferral.retry('Error while calling merged getauxblock on %s:' % (merged_url,), 30)(merged_proxy.rpc_getauxblock)()
            target = auxblock['target'] if 'target' in auxblock else auxblock['_target']
            self.merged_work.set(math.merge_dicts(self.merged_work.value, {auxblock['chainid']: dict(
                hash=int(auxblock['hash'], 16),
                target='p2pool' if target == 'p2pool' else pack.IntType(256).unpack(target.decode('hex')),
                merged_proxy=merged_proxy,
            )}))
            yield deferral.sleep(1)
    for merged_url, merged_userpass in merged_urls:
        set_merged_work(merged_url, merged_userpass)

    @self.merged_work.changed.watch
    def _(new_merged_work):
        print 'Got new merged mining work!'
     */

    // COMBINE WORK

    _coind_node->coind_work->changed->subscribe([&](const auto &work){ compute_work(); });
    _coind_node->best_block_header->changed->subscribe([&](const auto &block_header){ compute_work(); });
    compute_work();


    current_work->transitioned->subscribe([&](const auto& before, const auto& after){
//        LOG_TRACE << "CURRENT WORK.TRANSITIONED:";
//        LOG_TRACE << "\tBefore: " << before;
//        LOG_TRACE << "\tafter: " << after;
        //  # trigger LP if version/previous_block/bits changed or transactions changed from nothing
        if ((std::tie(before.version, before.previous_block, before.bits) != std::tie(after.version, after.previous_block, after.bits)) || (before.transactions.empty() && !after.transactions.empty()))
        {
            new_work->happened();
        }
    });

    _coind_node->best_share->changed->subscribe([&](const auto &value)
    {
       new_work->happened();
    });

    init_web_metrics();
}

worker_get_work_result
Worker::get_work(uint160 pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target)
{
    //1
    if ((!_pool_node || !_pool_node->is_connected()) && _net->PERSIST)
    {
        throw std::runtime_error("c2pool is not connected to any peers"); //TODO: to jsonrpc_error
    }

    if (_pool_node->best_share->value().IsNull() && _net->PERSIST)
    {
        throw std::runtime_error("c2pool is downloading shares"); //TODO: to jsonrpc_error
    }

	// Check softforks
	std::set<std::string> unknown_rules;
	{
		std::set<std::string> coind_rules;
		for (auto rule: _coind_node->coind_work->value().rules)
		{
			if (rule.rfind("!", 0) == 0)
			{
				rule.erase(0, 1);
				coind_rules.insert(rule);
			}
		}
		std::set_intersection(coind_rules.begin(), coind_rules.end(), _net->SOFTFORKS_REQUIRED.begin(),
							  _net->SOFTFORKS_REQUIRED.end(), std::inserter(unknown_rules, unknown_rules.begin()));
	}
	if (!unknown_rules.empty())
	{
		//TODO: LOG unknown softforks found -> <list unknown_rules>
		//TODO: raise jsonrpc.Error_for_code(-12345)(u'unknown rule activated')
	}

    //2
    //TODO: check for merged mining

    //3
    std::vector<uint256> tx_hashes;
    for (const auto& tx: current_work->value().transactions)
    {
        coind::data::stream::TransactionType_stream _tx(tx);
        PackStream packed_tx;
        packed_tx << _tx;

        tx_hashes.push_back(coind::data::hash256(packed_tx, true));
    }

    std::map<uint256, coind::data::tx_type> tx_map;
    {
        uint256 _tx_hash;
        coind::data::tx_type _tx;

        BOOST_FOREACH(boost::tie(_tx_hash, _tx), boost::combine(tx_hashes, current_work->value().transactions))
                    {
                        tx_map[_tx_hash] = _tx;
                    }
    }

    //TODO???: self.node.mining2_txs_var.set(tx_map) # let node.py know not to evict these transactions

    //4
    uint64_t share_version;

    ShareType prev_share;
    if (!_pool_node->best_share->value().IsNull())
    {
        prev_share = _tracker->get(_pool_node->best_share->value());
    }

    if (!prev_share)
    {
        share_version = SHARE_VERSION;
    } else
    {
        share_version = prev_share->VERSION;
        // TODO: Share -> NewShare only valid if 95% of hashes in [net.CHAIN_LENGTH*9//10, net.CHAIN_LENGTH] for new version
    }

    //5
	int64_t block_subsidy;
	if (desired_share_target.IsNull())
	{
        auto local_hash_rates = get_local_addr_rates();
//		desired_share_target = bitcoin_data.difficulty_to_target(float(1.0 / self.node.net.PARENT.DUMB_SCRYPT_DIFF))
        LOG_DEBUG_STRATUM << "_net->parent->DUMB_SCRYPT_DIFF: " << _net->parent->DUMB_SCRYPT_DIFF.GetHex();
		desired_share_target = coind::data::difficulty_to_target_1(_net->parent->DUMB_SCRYPT_DIFF);

        LOG_DEBUG_STRATUM << "coind::data::difficulty_to_target_1(_net->parent->DUMB_SCRYPT_DIFF): " << coind::data::difficulty_to_target_1(_net->parent->DUMB_SCRYPT_DIFF);

		auto local_hash_rate = local_hash_rates.count(pubkey_hash) > 0 ? UintToArith288(local_hash_rates[pubkey_hash]) : arith_uint288();
		if (local_hash_rate > 0)
		{
            LOG_DEBUG_STRATUM << "LOCAL_HASH_RATE: " << local_hash_rate.GetHex();
            // TODO: CHECK
			// limit to 1.67% of pool shares by modulating share difficulty
			desired_share_target = std::min(desired_share_target, coind::data::average_attempts_to_target(
					local_hash_rate * _net->SHARE_PERIOD / 60)); // in p2pool:  /0.0167, not /60
		}
		auto lookbehind = 3600 / _net->SHARE_PERIOD;
		block_subsidy = _coind_node->coind_work->value().subsidy;
		if (prev_share && _tracker->get_height(prev_share->hash) > lookbehind)
		{
			//TODO (from p2pool): doesn't use global stale rate to compute pool hash
			auto expected_payout_per_block = local_hash_rate / _tracker->get_pool_attempts_per_second(_coind_node->best_share->value(), lookbehind) * block_subsidy * (100 - donation_percentage) / 100; //(1 - donation_percentage/100);
			if (expected_payout_per_block < _net->parent->DUST_THRESHOLD)
			{
				auto temp1 = coind::data::target_to_average_attempts(_coind_node->coind_work->value().bits.target()) * _net->SPREAD;
				auto temp2 = temp1 * _net->parent->DUST_THRESHOLD / block_subsidy;
				desired_share_target = std::min(desired_share_target, coind::data::average_attempts_to_target(temp2));
			}
		}
	}
    LOG_DEBUG_STRATUM << "desired_share_target = " << desired_share_target.GetHex();

    //6
//    LOG_DEBUG_STRATUM << "Before generate share transaction: " << current_work.value().bits << " " << FloatingInteger(current_work.value().bits).target();
    auto generate_transaction = std::make_shared<shares::GenerateShareTransaction>(_tracker);
    generate_transaction->
            set_block_target(FloatingInteger(current_work->value().bits).target()).
            set_desired_timestamp(c2pool::dev::timestamp()).
            set_desired_target(desired_share_target).
            set_ref_merkle_link(coind::data::MerkleLink({}, 0)).
            set_base_subsidy(_net->parent->SUBSIDY_FUNC(current_work->value().height)).
            set_known_txs(tx_map);

//    LOG_TRACE << "DESIRED TIMESTAMP CALCULATE = " << c2pool::dev::timestamp() << " (" << (uint32_t) c2pool::dev::timestamp() << ") + " << 0.5f << " = " << (c2pool::dev::timestamp() + 0.5f) << " / " << (uint32_t)(c2pool::dev::timestamp() + 0.5f);

    {
        std::vector<std::tuple<uint256, std::optional<int32_t>>> desired_other_transaction_hashes_and_fees;
        uint256 _tx_hash;
        int32_t _fee;

        BOOST_FOREACH(boost::tie(_tx_hash, _fee), boost::combine(tx_hashes, current_work->value().transaction_fees))
                    {
                        desired_other_transaction_hashes_and_fees.emplace_back(_tx_hash, std::make_optional(_fee));
                    }
        generate_transaction->set_desired_other_transaction_hashes_and_fees(
                desired_other_transaction_hashes_and_fees);
    }
    // ShareData
    {
        std::vector<unsigned char> coinbase;
		{
			CScript _coinbase;
			_coinbase << current_work->value().height;
			// _coinbase << mm_data // TODO: FOR MERGED MINING
			_coinbase << current_work->value().coinbaseflags;
			coinbase = ToByteVector(_coinbase);
            if (coinbase.size() > 100)
                coinbase.resize(100);
		}
        uint16_t donation = 65535 * donation_percentage / 100; //TODO: test for "math.perfect_round"
        StaleInfo stale_info;
		{
			auto v = get_stale_counts();
			if (std::get<0>(v.orph_doa) > std::get<0>(v.recorded_in_chain))
				stale_info = orphan;
			else if (std::get<1>(v.orph_doa) > std::get<1>(v.recorded_in_chain))
				stale_info = doa;
			else
				stale_info = unk;
		}

        shares::types::ShareData _share_data(
                _pool_node->best_share->value(),
                coinbase,
                c2pool::random::randomNonce(),
                pubkey_hash,
                current_work->value().subsidy,
                donation,
                stale_info,
                share_version
        );

        generate_transaction->set_share_data(_share_data);
    }

    auto gen_sharetx_res = (*generate_transaction)(share_version);

    //7
    PackStream packed_gentx;
    {
        coind::data::stream::TxIDType_stream _gentx(gen_sharetx_res->gentx->version, gen_sharetx_res->gentx->tx_ins, gen_sharetx_res->gentx->tx_outs, gen_sharetx_res->gentx->lock_time);
        packed_gentx << _gentx;
    }

    std::vector<coind::data::tx_type> other_transactions;
    {
        for (auto tx_hash: gen_sharetx_res->other_transaction_hashes)
        {
            other_transactions.push_back(tx_map[tx_hash]);
        }
    }

    //8
    //TODO: part for merged mining
    arith_uint256 a_target;
    if (desired_pseudoshare_target.IsNull())
    {
//		target = bitcoin_data.difficulty_to_target(float(1.0 / self.node.net.PARENT.DUMB_SCRYPT_DIFF))
        a_target = coind::data::difficulty_to_target_1(_net->parent->DUMB_SCRYPT_DIFF);
		auto local_hash_rate = _estimate_local_hash_rate();
		if (!local_hash_rate.IsNull())
		{
			//in p2pool: target = bitcoin_data.average_attempts_to_target(local_hash_rate * 1)
			// target 10 share responses every second by modulating pseudoshare difficulty
            a_target = coind::data::average_attempts_to_target(local_hash_rate);
		} else
        {
            //TODO: TEST
            //# If we don't yet have an estimated node hashrate, then we still need to not undershoot the difficulty.
            //# Otherwise, we might get 1 PH/s of hashrate on difficulty settings appropriate for 1 GH/s.
            //# 1/3000th the difficulty of a full share should be a reasonable upper bound. That way, if
            //# one node has the whole p2pool hashrate, it will still only need to process one pseudoshare
            //# every ~0.01 seconds.

            arith_uint288 avg_attempts = coind::data::target_to_average_attempts(_coind_node->coind_work->value().bits.target());
            avg_attempts *= _net->SPREAD;
            avg_attempts *= _net->parent->DUST_THRESHOLD;
            avg_attempts/block_subsidy;

            auto target_from_avg = Uint256ToArith288(coind::data::average_attempts_to_target(avg_attempts));

            target_from_avg *= 3000;

            if (target_from_avg < Arith256ToArith288(a_target))
            {
                a_target = ArithToUint256(target_from_avg);
            }
        }
    } else
    {
        a_target = desired_pseudoshare_target;
    }

    auto bits_target = UintToArith256(FloatingInteger(gen_sharetx_res->share_info->bits).target());
    if (a_target < bits_target)
    {
        a_target = bits_target;
    }

    // TODO: part for merged mining

    a_target = math::clip(a_target, _net->parent->SANE_TARGET_RANGE_MIN, _net->parent->SANE_TARGET_RANGE_MAX);
    auto target = ArithToUint256(a_target);
    LOG_DEBUG_STRATUM << "target =  " << a_target.GetHex();


    //9
    auto getwork_time = c2pool::dev::timestamp();
    auto lp_count = new_work->get_times();

    coind::data::MerkleLink merkle_link;
    if (!gen_sharetx_res->share_info->segwit_data.has_value())
    {
        std::vector<uint256> _copy_for_link{uint256::ZERO};
        _copy_for_link.insert(_copy_for_link.end(), gen_sharetx_res->other_transaction_hashes.begin(),
                              gen_sharetx_res->other_transaction_hashes.end());

        merkle_link = coind::data::calculate_merkle_link(_copy_for_link, 0);
    } else
    {
        merkle_link = gen_sharetx_res->share_info->segwit_data->txid_merkle_link;
    }

    //TODO: for debug INFO
//        if print_throttle is 0.0:
//            print_throttle = time.time()
//        else:
//            current_time = time.time()
//            if (current_time - print_throttle) > 5.0:
//                print 'New work for %s! Diff: %.02f Share diff: %.02f Block value: %.2f %s (%i tx, %.0f kB)' % (
//                        bitcoin_data.pubkey_hash_to_address(pubkey_hash, self.node.net.PARENT),
//                                bitcoin_data.target_to_difficulty(target),
//                                bitcoin_data.target_to_difficulty(share_info['bits'].target),
//                                self.current_work.value['subsidy']*1e-8, self.node.net.PARENT.SYMBOL,
//                                len(self.current_work.value['transactions']),
//                                sum(map(bitcoin_data.tx_type.packed_size, self.current_work.value['transactions']))/1000.,
//                )
//                print_throttle = time.time()

    //TODO: for stats: self.last_work_shares.value[bitcoin_data.pubkey_hash_to_address(pubkey_hash, self.node.net.PARENT)]=share_info['bits']

    //10
    NotifyData ba = {
            std::max(current_work->value().version, (uint64_t) 536870912),
            current_work->value().previous_block,
            merkle_link,
            std::vector<unsigned char>(packed_gentx.data.begin(), packed_gentx.data.end() - COINBASE_NONCE_LENGTH - 4),
			std::vector<unsigned char>(packed_gentx.data.end()-4, packed_gentx.data.end()),
            current_work->value().timestamp,
            current_work->value().bits,
            target
    };

    // TODO: received_header_hashes = set()
    uint256 test_num = uint256S("1337");
    std::vector<unsigned char> fake_data = pack<IntType(256)>(test_num);

    PackStream block_header_packed;
    {
        coind::data::types::BlockHeaderType header(37, uint256S("7b"), 50000, FloatingInteger::from_target_upper_bound(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).get(),555, uint256S("141"));
        coind::data::stream::BlockHeaderType_stream _block_header_value(header);
        block_header_packed << _block_header_value;
        LOG_INFO << "FAKE_HEADER POW: " << _net->parent->POW_FUNC(block_header_packed);
    }


    PackStream fake_packed_data(fake_data);
    LOG_INFO << "CHECK: " << _net->parent->POW_FUNC(fake_packed_data);

    worker_get_work_result res = {
            ba,
            [=, _gen_sharetx_res = std::move(gen_sharetx_res), _new_work = new_work, _lp_count = lp_count](const coind::data::types::BlockHeaderType& header, std::string user, IntType(64) coinbase_nonce)
            {
                auto t0 = c2pool::dev::timestamp();
                LOG_DEBUG_STRATUM << "HEADER get_work_result: " << header;
                PackStream new_packed_gentx;
                if (coinbase_nonce.value != 0)
                {
                    new_packed_gentx.data.insert(new_packed_gentx.data.end(), packed_gentx.data.begin(), packed_gentx.data.end() - COINBASE_NONCE_LENGTH-4);
                    new_packed_gentx << coinbase_nonce;
                    new_packed_gentx.data.insert(new_packed_gentx.data.end(), packed_gentx.data.end()-4, packed_gentx.data.end());
                } else
                {
                    new_packed_gentx << packed_gentx;
                }

                coind::data::tx_type new_gentx;
                {
                    PackStream nonce_packed;
                    nonce_packed << coinbase_nonce;

//                    if (all_of(nonce_packed.data.begin(), nonce_packed.data.end(), [](unsigned char v)
//                    { return v == '\0'; }))
                    if (coinbase_nonce.value != 0)
                    {
                        auto new_packed_gentx_copy = new_packed_gentx;
                        coind::data::stream::TransactionType_stream temp;
                        new_packed_gentx_copy >> temp;
                        new_gentx = temp.tx;
                    } else
                    {
                        new_gentx = _gen_sharetx_res->gentx;
                    }

                    // reintroduce witness data to the gentx produced by stratum miners
                    if (coind::data::is_segwit_tx(_gen_sharetx_res->gentx))
                    {
                        new_gentx->wdata = std::make_optional<coind::data::WitnessTransactionData>(0,
                                                                                                   _gen_sharetx_res->gentx->wdata->flag,
                                                                                                   _gen_sharetx_res->gentx->wdata->witness);
                    }
                }

                PackStream block_header_packed;
                {
                    coind::data::stream::BlockHeaderType_stream _block_header_value(header);
                    block_header_packed << _block_header_value;
                }

                auto header_hash = coind::data::hash256(block_header_packed, true);
                auto pow_hash = _net->parent->POW_FUNC(block_header_packed);

                LOG_DEBUG_STRATUM << "header_hash = " << header_hash;
                LOG_DEBUG_STRATUM << "header.bits = " << header.bits;
                LOG_DEBUG_STRATUM << "FloatingInteger(header.bits).target() = " << FloatingInteger(header.bits).target();
                LOG_DEBUG_STRATUM << "pow_hash = " << pow_hash;
                LOG_DEBUG_STRATUM << "_gen_sharetx_res->share_info->bits = " << _gen_sharetx_res->share_info->bits;
                LOG_DEBUG_STRATUM << "FloatingInteger(_gen_sharetx_res->share_info->bits).target() = " << FloatingInteger(_gen_sharetx_res->share_info->bits).target();
                LOG_DEBUG_STRATUM << "target = " << target;

                try
                {
                    if (UintToArith256(pow_hash) <= UintToArith256(FloatingInteger(header.bits).target()))
                    {
                        coind::data::types::BlockType new_block(header, {new_gentx});
                        new_block.txs.insert(new_block.txs.end(), other_transactions.begin(), other_transactions.end());

                        _coind_node->submit_block(new_block, false);

                        //TODO: add self.node.net.PARENT.BLOCK_EXPLORER_URL_PREFIX
                        LOG_INFO << "GOT BLOCK FROM MINER! Passing to bitcoind! " << header_hash.GetHex() << "\n";
                    }
                } catch (const std::error_code &ec)
                {
                    LOG_ERROR << "Error while processing potential block: " << ec.message();
                }

                auto user_detail = get_user_details(user);

                assert(header.previous_block == ba.previous_block);
                auto check_merkle_link1 = coind::data::check_merkle_link(coind::data::hash256(new_packed_gentx, true), merkle_link);
                assert(header.merkle_root == check_merkle_link1);
                assert(header.bits == ba.bits);

                bool on_time = _new_work->get_times() == _lp_count;
                //TODO: merged mining
//                    for aux_work, index, hashes in mm_later:
//                        try:
//                            if pow_hash <= aux_work['target'] or p2pool.DEBUG:
//                                df = deferral.retry('Error submitting merged block: (will retry)', 10, 10)(aux_work['merged_proxy'].rpc_getauxblock)(
//                                    pack.IntType(256, 'big').pack(aux_work['hash']).encode('hex'),
//                                    bitcoin_data.aux_pow_type.pack(dict(
//                                        merkle_tx=dict(
//                                            tx=new_gentx,
//                                            block_hash=header_hash,
//                                            merkle_link=merkle_link,
//                                        ),
//                                        merkle_link=bitcoin_data.calculate_merkle_link(hashes, index),
//                                        parent_block_header=header,
//                                    )).encode('hex'),
//                                )
//                                @df.addCallback
//                                def _(result, aux_work=aux_work):
//                                    if result != (pow_hash <= aux_work['target']):
//                                        print >>sys.stderr, 'Merged block submittal result: %s Expected: %s' % (result, pow_hash <= aux_work['target'])
//                                    else:
//                                        print 'Merged block submittal result: %s' % (result,)
//                                @df.addErrback
//                                def _(err):
//                                    log.err(err, 'Error submitting merged block:')
//                        except:
//                            log.err(None, 'Error while processing merged mining POW:')


                // TODO: and header_hash not in received_header_hashes:
                if (UintToArith256(pow_hash) <=
                    UintToArith256(FloatingInteger(_gen_sharetx_res->share_info->bits).target()))
                {
                    auto last_txout_nonce = coinbase_nonce.get();
                    auto share = _gen_sharetx_res->get_share(header, last_txout_nonce);

                    LOG_INFO << "GOT SHARE! " << user << ", " << share->hash
                             << ", prev = " << (share->previous_hash ? share->previous_hash->GetHex() : "null") << ", age " << c2pool::dev::timestamp() - getwork_time
                             << "s, " << (!on_time ? "DEAD OR ARRIVAL" : "");

                    // XXX: ???
                    //# node.py will sometimes forget transactions if bitcoind's work has changed since this stratum
                    //# job was assigned. Fortunately, the tx_map is still in in our scope from this job, so we can use that
                    //# to refill it if needed.

                    auto known_txs = _coind_node->known_txs->value();

                    std::map<uint256, coind::data::tx_type> missing;
                    for (auto [_hash, _value]: tx_map)
                        if (known_txs.count(_hash) == 0)
                        {
                            missing[_hash] = _value;
                        }

                    if (!missing.empty())
                    {
                        LOG_WARNING << missing.size()
                                    << " transactions were erroneously evicted from known_txs_var. Refilling now.";
                        _coind_node->known_txs->add(missing);
                    }

                    my_share_hashes.insert(share->hash);
                    my_share_hashes_metric->set(my_share_hashes); //TODO: can be optimize, make: metric array

                    if (!on_time)
                    {
                        my_doa_share_hashes.insert(share->hash);
                    }

                    _tracker->add(share);
                    LOG_INFO << "Tracker items count = " << _tracker->items.size();

                    _coind_node->set_best_share();

                    try
                    {
                        if (UintToArith256(pow_hash) <= UintToArith256(FloatingInteger(header.bits).target()) && _pool_node)
                        {
							_pool_node->broadcast_share(share->hash);
                        }
                    } catch (const std::error_code &ec)
                    {
                        LOG_ERROR << "Error forwarding block solution: " << ec.message();
                    }

                    //for web_static
                    //self.share_received.happened(bitcoin_data.target_to_average_attempts(share.target), not on_time, share.hash)
                    share_received->happened();
                }

                if (pow_hash > target)
                {
                    LOG_INFO << "Worker " << user << " submitted share with hash > target";
                    LOG_INFO << "Hash: " << pow_hash.GetHex();
                    LOG_INFO << "Target: " << target.GetHex();
                }
                    //TODO:
                    //elif header_hash in received_header_hashes:
                    //    print >>sys.stderr, 'Worker %s submitted share more than once!' % (user,)
                else
                {
                    LOG_TRACE << "pseudoshare_received!!!";
                    // TODO: received_header_hashes.add(header_hash)
                    // TODO: for web static: self.pseudoshare_received.happened(bitcoin_data.target_to_average_attempts(target), not on_time, user)
                    recent_shares_ts_work.emplace_back(c2pool::dev::timestamp(), ArithToUint288(coind::data::target_to_average_attempts(target)));
                    if (recent_shares_ts_work.size() > 50)
                    {
                        recent_shares_ts_work.erase(recent_shares_ts_work.begin(),
                                                    recent_shares_ts_work.end() - 50);
                    }
                    local_rate_monitor.add_datum(
                            {
                                    coind::data::target_to_average_attempts(target),
                                    !on_time,
                                    user,
                                    FloatingInteger(_gen_sharetx_res->share_info->bits).target()
                            }
                    );

                    local_addr_rate_monitor.add_datum(
                            {
                                    ArithToUint288(coind::data::target_to_average_attempts(target)),
                                    pubkey_hash
                            }
                    );
                }
                auto t1 = c2pool::dev::timestamp();

                LOG_DEBUG_STRATUM << "END OF GOT RESPONSE";
                return on_time;
            }
    };

    return res;
}

local_rates Worker::get_local_rates()
{
    std::map<std::string, arith_uint288> miner_hash_rates;
    std::map<std::string, arith_uint288> miner_dead_hash_rates;

    auto [datums, dt] = local_rate_monitor.get_datums_in_last();
    for (const auto& datum: datums)
    {
        {
            miner_hash_rates[datum.user] += datum.work / dt;
        }

        if (datum.dead)
        {
            miner_dead_hash_rates[datum.user] += datum.work / dt;
        }
    }

    return {miner_hash_rates, miner_dead_hash_rates};
}

std::map<uint160, uint288> Worker::get_local_addr_rates()
{
    std::map<uint160, uint288> addr_hash_rates;
    auto [datums, dt] = local_addr_rate_monitor.get_datums_in_last();

    for (auto datum: datums)
    {
        arith_uint288 temp;
        temp = ((addr_hash_rates.find(datum.pubkey_hash) != addr_hash_rates.end()) ? UintToArith288(addr_hash_rates[datum.pubkey_hash])
                                                                                   : UintToArith288(uint288()));
        temp += UintToArith288(datum.work) / dt;

        addr_hash_rates[datum.pubkey_hash] = ArithToUint288(temp);
    }

    return addr_hash_rates;
};

stale_counts Worker::get_stale_counts()
{
    auto my_shares = my_share_hashes.size();
    auto my_doa_shares = my_doa_share_hashes.size();

    auto [_removed_unstales, _removed_unstales_orphans, _removed_unstales_doa] = removed_unstales->value();

    DOAElement delta{};
    if (_coind_node->best_share->value().IsNull())
        delta = DOAElement{0,0,0,0};
    else
        delta = *(std::get<0>(_tracker->get_sum_to_last(_coind_node->best_share->value())).rules.get<DOAElement>("doa"));

    auto my_shares_in_chain = delta.my_count + _removed_unstales;
    auto my_doa_shares_in_chain = delta.my_doa_count + removed_doa_unstales->value();
    auto orphans_recorded_in_chain = delta.my_orphan_announce_count + _removed_unstales_orphans;
    auto doas_recorded_in_chain = delta.my_dead_announce_count + _removed_unstales_doa;

    auto my_shares_not_in_chain = my_shares - my_shares_in_chain;
    auto my_doa_shares_not_in_chain = my_doa_shares - my_doa_shares_in_chain;

    return {{my_shares_not_in_chain - my_doa_shares_not_in_chain, my_doa_shares_not_in_chain}, (int32_t) my_shares,
            {orphans_recorded_in_chain, doas_recorded_in_chain}};
}

// TODO: check
user_details Worker::get_user_details(std::string username)
{
    LOG_DEBUG_STRATUM << "username: " << username;

    user_details result;
    result.desired_pseudoshare_target = uint256::ZERO;
    result.desired_share_target = uint256::ZERO;

    std::vector<std::string> contents;
    boost::char_separator<char> sep("+", "/");
    boost::tokenizer<boost::char_separator<char>> tokens(username, sep);
    for (std::string t: tokens)
    {
        contents.push_back(t);
    }
//        boost::split(contents, username, boost::is_any_of("+/"));
    if (contents.empty())
        contents.push_back("");

    if (contents.size() % 2 != 1)
    {
        throw std::invalid_argument("Worker::get_user_details(std::__cxx11::string): 'contents.size() % 2 == 1' failed.");
    }

    result.user = boost::trim_copy(contents[0]);
    contents.erase(contents.begin(), contents.begin() + 1);

    for (int i = 0; i < (contents.size() - contents.size() % 2); i += 2)
    {
        std::string symbol = contents[i];
        std::string parameter = contents[i + 1];

        if (symbol == "+")
        {
            result.desired_pseudoshare_target = coind::data::difficulty_to_target(uint256S(parameter));
        } else if (symbol == "/")
        {
            result.desired_share_target = coind::data::difficulty_to_target(uint256S(parameter));
        }
    }

    //TODO: parse args
//        if self.args.address == 'dynamic':
//            i = self.pubkeys.weighted()
//            pubkey_hash = self.pubkeys.keys[i]
//
//            c = time.time()
//            if (c - self.pubkeys.stamp) > self.args.timeaddresses:
//                self.freshen_addresses(c)

/*TODO:    if (c2pool::random::RandomFloat(0, 100) < worker_fee)
 *              pubkey_hash = self.my_pubkey_hash
 *         else :
 */
    try
    {
        result.pubkey_hash = coind::data::address_to_pubkey_hash(result.user, _net);
    } catch (...)
    {
        /* TODO:
         * if self.args.address != 'dynamic':
         *      pubkey_hash = self.my_pubkey_hash
        */
        result.pubkey_hash.SetHex("78ecd67a8695aa4adc55b70f87c2fa3279cee6d0");
    }

    return result;
}

user_details Worker::preprocess_request(std::string username)
{
    if ((!_pool_node || _pool_node->peers.size() == 0) && _net->PERSIST)
    {
        throw std::runtime_error("c2pool is not connected to any peers");
        //TODO: raise jsonrpc.Error_for_code(-12345)(u'p2pool is not connected to any peers')
    }
    if (c2pool::dev::timestamp() > current_work->value().last_update + 60)
    {
        throw std::runtime_error("lost contact with coind");
        //TODO: raise jsonrpc.Error_for_code(-12345)(u'lost contact with bitcoind')
    }

    return get_user_details(username);
}

void Worker::compute_work()
{
    Work t = Work::from_jsonrpc_data(_coind_node->coind_work->value());
    if (!_coind_node->best_block_header->isNull())
    {
        // TODO: test
        auto bb = _coind_node->best_block_header->value();
        PackStream packed_block_header = bb.get_pack();

        if (bb->previous_block == t.previous_block &&
            UintToArith256(_net->parent->POW_FUNC(packed_block_header)) <=
            UintToArith256(FloatingInteger(t.bits).target()))
        {
            LOG_INFO << "Skipping from block " << bb->previous_block.GetHex() << " to block"
                     << coind::data::hash256(packed_block_header) << "!";

            t = {
                    bb->version,
                    coind::data::hash256(packed_block_header),
                    bb->bits,
					{},
                    t.height + 1,
                    (int32_t) std::max((uint32_t) c2pool::dev::timestamp(), bb->timestamp + 1),
                    {},
                    {},
                    coind::data::calculate_merkle_link({uint256::ZERO}, 0),
                    _net->parent->SUBSIDY_FUNC(_coind_node->coind_work->value().height),
                    (int32_t) _coind_node->coind_work->value().last_update
            };
//                t = coind::getwork_result()
        }
    }
//    LOG_DEBUG_STRATUM << "New current_work!: " << t;
    current_work->set(t);
}

void Worker::init_web_metrics()
{
    //---> add metrics
    //------> shares
    shares_metric = _net->web->add<shares_metric_type>("shares", [&](nlohmann::json& j){
        auto _stale = get_stale_counts();

        //---------> total/orphan/doa
        j["total"] = _stale.total;
        j["orphan"] = std::get<0>(_stale.orph_doa);
        j["doa"] = std::get<1>(_stale.orph_doa);

        //---------> efficiency
        if (_stale.total)
        {
            auto lookbehind = min(_tracker->get_height(_pool_node->best_share->value()), 3600/_net->SHARE_PERIOD);
            //TODO: test
            float efficiency = (1 - (std::get<0>(_stale.orph_doa) + std::get<1>(_stale.orph_doa))/_stale.total) / (1 - _tracker->get_average_stale_prop(_pool_node->best_share->value(), lookbehind));
            j["efficiency"] = efficiency;
        } else{
            j["efficiency"] = nullptr;
        }
    });

    //------> local_rate
    local_rate_metric = _net->web->add<local_rate_metric_type>("local", [&](nlohmann::json& j){
        auto [miner_hash_rates, miner_dead_hash_rates] = get_local_rates();

        arith_uint288 local;
        for (const auto& v : miner_hash_rates)
            local += v.second;

        arith_uint288 local_dead;
        for (const auto& v : miner_dead_hash_rates)
            local_dead += v.second;

        j["miner_hash_rates"] = miner_hash_rates;
        j["miner_dead_hash_rates"] = miner_dead_hash_rates;

        j["rate"] = local;
        j["doa"] = local.IsNull() ? arith_uint288{} : local_dead/local;

        if (local.IsNull())
            j["time_to_share"] = nullptr;
        else
            j["time_to_share"] = (coind::data::target_to_average_attempts(_tracker->get(_pool_node->best_share->value())->max_target) / local).GetLow64();

        j["block_value"] = _coind_node->coind_work->value().subsidy * 1e-8;
        j["attempts_to_block"] = coind::data::target_to_average_attempts(_coind_node->coind_work->value().bits.target());
    });

    //------> pool_rate
    pool_rate_metric = _net->web->add<pool_rate_metric_type>("pool", [&](nlohmann::json& j){
        if (_tracker->get_height(_pool_node->best_share->value()) < 10)
            return j = nlohmann::json{
                    {"rate", "?"},
                    {"nonstale_rate", "?"},
                    {"stale_prop", "?"},
                    {"difficulty", "?"},
                    {"block_difficulty", "?"},
                    {"network_hashrate", "?"}
            };

        auto lookbehind = min(_tracker->get_height(_pool_node->best_share->value()), 3600/_net->SHARE_PERIOD);

        auto nonstale_hash_rate = _tracker->get_pool_attempts_per_second(_pool_node->best_share->value(), lookbehind);
        auto stale_prop = _tracker->get_average_stale_prop(_pool_node->best_share->value(), lookbehind);
        auto diff = coind::data::target_to_difficulty(FloatingInteger(current_work->value().bits).target());

        j["rate"] = (nonstale_hash_rate*100)/(100 - 100*stale_prop);
        j["nonstale_rate"] = nonstale_hash_rate;
        j["stale_prop"] = stale_prop;
        j["difficulty"] = coind::data::target_to_difficulty(_tracker->get(_pool_node->best_share->value())->max_target);
        j["block_difficulty"] = diff;
        j["network_hashrate"] = (diff * pow(2, 32)) / _net->parent->BLOCK_PERIOD;
    });

    //------> payout_addr
    payout_addr_metric = _net->web->add("payout_addr", coind::data::pubkey_hash_to_address(my_pubkey_hash, _net));
    //------> my_share_hashes
    my_share_hashes_metric = _net->web->add("my_share_hashes", my_share_hashes);
}