#include "worker.h"

#include <vector>
#include <tuple>
#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>

#include "p2p_node.h"
#include "coind_node.h"
#include <btclibs/uint256.h>
#include <libdevcore/random.h>
#include <sharechains/data.h>

using std::vector;

namespace c2pool::libnet
{
    Worker::Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<c2pool::libnet::p2p::P2PNode> p2p_node,
                   shared_ptr<c2pool::libnet::CoindNode> coind_node, std::shared_ptr<ShareTracker> tracker) : _net(net),
                                                                                                              _p2p_node(p2p_node),
                                                                                                              _coind_node(coind_node),
                                                                                                              _tracker(tracker),
                                                                                                              local_rate_monitor(10*60),
                                                                                                              local_addr_rate_monitor(10*60)
    {

    }

    worker_get_work_result Worker::get_work(uint160 pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target)
    {
        //1
        if ((!_p2p_node || _p2p_node->get_peers().empty()) && _net->PERSIST)
        {
            throw std::runtime_error("c2pool is not connected to any peers"); //TODO: to jsonrpc_error
        }
        if (_p2p_node->best_share.isNull() && _net->PERSIST)
        {
            throw std::runtime_error("c2pool is downloading shares"); //TODO: to jsonrpc_error
        }

        // TODO: Check softforks
//		unknown_rules = set(r[1:] if r.startswith('!') else r for r in self.node.bitcoind_work.value['rules']) - set(getattr(self.node.net, 'SOFTFORKS_REQUIRED', []))
//		if unknown_rules:
//			print "Unknown softforks found: ", unknown_rules
//		raise jsonrpc.Error_for_code(-12345)(u'unknown rule activated')

        //2
        //TODO: check for merged mining

        //3
        std::vector<uint256> tx_hashes;
        for (auto tx: current_work.value().transactions)
        {
            coind::data::stream::TransactionType_stream _tx(tx);
            PackStream packed_tx;
            packed_tx << _tx;

            tx_hashes.push_back(coind::data::hash256(packed_tx));
        }

        std::map<uint256, coind::data::tx_type> tx_map;
        {
            uint256 _tx_hash;
            coind::data::tx_type _tx;

            BOOST_FOREACH(boost::tie(_tx_hash, _tx), boost::combine(tx_hashes, current_work.value().transactions))
                        {
                            tx_map[_tx_hash] = _tx;
                        }
        }

        //TODO???: self.node.mining2_txs_var.set(tx_map) # let node.py know not to evict these transactions

        //4
        uint64_t share_version;

        ShareType prev_share;
        if (!_p2p_node->best_share.isNull())
            prev_share = _tracker->get(_p2p_node->best_share.value());

        if (!prev_share)
        {
            share_version = SHARE_VERSION;
        } else
        {
            //TODO: Succsessor
        }

        //5

//		local_addr_rates = self.get_local_addr_rates()
//
//		if desired_share_target is None:
//			desired_share_target = bitcoin_data.difficulty_to_target(float(1.0 / self.node.net.PARENT.DUMB_SCRYPT_DIFF))
//			local_hash_rate = local_addr_rates.get(pubkey_hash, 0)
//			if local_hash_rate > 0.0:
//			desired_share_target = min(desired_share_target,
//									   bitcoin_data.average_attempts_to_target(local_hash_rate * self.node.net.SHARE_PERIOD / 0.0167)) # limit to 1.67% of pool shares by modulating share difficulty
//
//			lookbehind = 3600//self.node.net.SHARE_PERIOD
//			block_subsidy = self.node.bitcoind_work.value['subsidy']
//			if previous_share is not None and self.node.tracker.get_height(previous_share.hash) > lookbehind:
//			expected_payout_per_block = local_addr_rates.get(pubkey_hash, 0)/p2pool_data.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
//      	              * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
//			if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
//			desired_share_target = min(desired_share_target,
//									   bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
//			)

        int64_t block_subsidy = 0;
        if (desired_share_target.IsNull())
        {
            arith_uint256 diff;
            diff.SetHex("1");
            desired_share_target = coind::data::difficulty_to_target(
                    ArithToUint256(diff / _net->parent->DUMB_SCRYPT_DIFF));

            //TODO: local_hash_rate

            auto lookbehind = 3600 / _net->SHARE_PERIOD;
            block_subsidy = _coind_node->coind_work.value().subsidy;
            if (!prev_share && _tracker->get_height(prev_share->hash) > lookbehind)
            {
                //TODO:
//                expected_payout_per_block = local_addr_rates.get(pubkey_hash, 0)/p2pool_data.get_pool_attempts_per_second(self.node.tracker, self.node.best_share_var.value, lookbehind) \
//                    * block_subsidy*(1-self.donation_percentage/100) # XXX doesn't use global stale rate to compute pool hash
//                if expected_payout_per_block < self.node.net.PARENT.DUST_THRESHOLD:
//                desired_share_target = min(desired_share_target,
//                                           bitcoin_data.average_attempts_to_target((bitcoin_data.target_to_average_attempts(self.node.bitcoind_work.value['bits'].target)*self.node.net.SPREAD)*self.node.net.PARENT.DUST_THRESHOLD/block_subsidy)
//                )
            }
        }

        //6
        shares::GenerateShareTransaction generate_transaction(_tracker);
        generate_transaction.
                set_block_target(FloatingInteger(current_work.value().bits).target()).
                set_desired_timestamp(dev::timestamp() + 0.5f).
                set_desired_target(desired_share_target).
                set_ref_merkle_link(coind::data::MerkleLink({}, 0)).
                set_base_subsidy(_net->parent->SUBSIDY_FUNC(current_work.value().height)).
                set_known_txs(tx_map);

        {
            std::vector<std::tuple<uint256, std::optional<int32_t>>> desired_other_transaction_hashes_and_fees;
            uint256 _tx_hash;
            int32_t _fee;

            BOOST_FOREACH(boost::tie(_tx_hash, _fee), boost::combine(tx_hashes, current_work.value().transaction_fees))
                        {
                            desired_other_transaction_hashes_and_fees.push_back(
                                    std::make_tuple(_tx_hash, std::make_optional(_fee)));
                        }
            generate_transaction.set_desired_other_transaction_hashes_and_fees(
                    desired_other_transaction_hashes_and_fees);
        }
        // ShareData
        {
            std::string coinbase; //TODO: init
            uint16_t donation = 65535 * donation_percentage / 100; //TODO: check
            StaleInfo stale_info; //TODO: init

            types::ShareData _share_data(
                    _p2p_node->best_share.value(),
                    coinbase,
                    c2pool::random::randomNonce(),
                    pubkey_hash,
                    current_work.value().subsidy,
                    donation,
                    stale_info,
                    share_version
            );

            generate_transaction.set_share_data(_share_data);
        }

        auto gen_sharetx_res = generate_transaction(share_version);

        //7
        PackStream packed_tx;
        {
            coind::data::stream::TransactionType_stream _gentx(gen_sharetx_res.gentx);
            packed_tx << _gentx;
        }

        std::vector<coind::data::tx_type> other_transactions;
        {
            for (auto tx_hash: gen_sharetx_res.other_transaction_hashes)
            {
                other_transactions.push_back(tx_map[tx_hash]);
            }
        }

        //8
        //TODO: part for merged mining
        uint256 target;
        target.SetHex("1");
        if (desired_pseudoshare_target.IsNull())
        {
            target = coind::data::difficulty_to_target(
                    target); //TODO: float(1.0 / self.node.net.PARENT.DUMB_SCRYPT_DIFF)

            //TODO: local_hash_rate = self._estimate_local_hash_rate()
            //if local_hash_rate is not None:
            //target = bitcoin_data.average_attempts_to_target(local_hash_rate * 1) # target 10 share responses every second by modulating pseudoshare difficulty
            //else
            {
                //# If we don't yet have an estimated node hashrate, then we still need to not undershoot the difficulty.
                //# Otherwise, we might get 1 PH/s of hashrate on difficulty settings appropriate for 1 GH/s.
                //# 1/3000th the difficulty of a full share should be a reasonable upper bound. That way, if
                //# one node has the whole p2pool hashrate, it will still only need to process one pseudoshare
                //# every ~0.01 seconds.
                arith_uint256 temp_target;

                arith_uint256 temp_target3;
                temp_target3 = coind::data::average_attempts_to_target(_coind_node->coind_work.value().bits.target());
                temp_target3 *= _net->SPREAD;

                arith_uint256 temp_target2;
                temp_target2 = temp_target2 * _net->parent->DUST_THRESHOLD / block_subsidy;

                temp_target =
                        UintToArith256(coind::data::average_attempts_to_target(ArithToUint256(temp_target2))) * 3000;

                if (temp_target < UintToArith256(target))
                    target = ArithToUint256(temp_target);
            }
        } else
        {
            target = desired_pseudoshare_target;
        }

        auto bits_target = FloatingInteger(gen_sharetx_res.share_info->bits).target();
        if (target < bits_target)
        {
            target = bits_target;
        }

        // TODO: part for merged mining

        target = c2pool::math::clip(target, _net->parent->SANE_TARGET_RANGE_MIN, _net->parent->SANE_TARGET_RANGE_MAX); //TODO: check

        //9
        auto getwork = dev::timestamp();
        auto lp_count = new_work.get_times();

        coind::data::MerkleLink merkle_link;
        if (gen_sharetx_res.share_info->segwit_data.has_value())
        {
            std::vector<uint256> _copy_for_link{uint256()};
            _copy_for_link.insert(_copy_for_link.begin(), gen_sharetx_res.other_transaction_hashes.begin(), gen_sharetx_res.other_transaction_hashes.end());

            merkle_link = coind::data::calculate_merkle_link(_copy_for_link, 0);
        } else
        {
            merkle_link = gen_sharetx_res.share_info->segwit_data->txid_merkle_link;
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
        worker_get_work_result res = {
                {
                        std::max(current_work.value().version, 0x20000000),
                        current_work.value().previous_block,
                        merkle_link,
                        std::string(),//TODO: init: packed_gentx[:-self.COINBASE_NONCE_LENGTH-4],
                        std::string(),//TODO: init: packed_gentx[-4:]
                        current_work.value().timestamp,
                        current_work.value().bits,
                        target
                },
                [=](){
                    //TODO:
                    return 1;
                }
        };

        return res;
    }

    local_rates Worker::get_local_rates()
    {
        std::map<std::string, uint256> miner_hash_rates;
        std::map<std::string, uint256> miner_dead_hash_rates;

        auto [datums, dt] = local_rate_monitor.get_datums_in_last();
        for (auto datum : datums)
        {
            {
                arith_uint256 temp;
                temp = ((miner_hash_rates.find(datum.user) != miner_hash_rates.end()) ? miner_hash_rates[datum.user]
                                                                                      : uint256::ZERO);
                temp += UintToArith256(datum.work) / dt;

                miner_hash_rates[datum.user] = ArithToUint256(temp);
            }

            if (datum.dead)
            {
                arith_uint256 temp;
                temp = ((miner_dead_hash_rates.find(datum.user) != miner_dead_hash_rates.end()) ? miner_dead_hash_rates[datum.user]
                                                                                      : uint256::ZERO);
                temp += UintToArith256(datum.work) / dt;
                miner_dead_hash_rates[datum.user] = ArithToUint256(temp);
            }
        }

        return {miner_hash_rates, miner_dead_hash_rates};
    }

    std::map<uint160, uint256> Worker::get_local_addr_rates()
    {
        std::map<uint160, uint256> addr_hash_rates;
        auto [datums, dt] = local_addr_rate_monitor.get_datums_in_last();

        for (auto datum : datums)
        {
            arith_uint256 temp;
            temp = ((addr_hash_rates.find(datum.pubkey_hash) != addr_hash_rates.end()) ? addr_hash_rates[datum.pubkey_hash]
                                                                                  : uint256::ZERO);
            temp += UintToArith256(datum.work) / dt;

            addr_hash_rates[datum.pubkey_hash] = ArithToUint256(temp);
        }

        return addr_hash_rates;
    };
}