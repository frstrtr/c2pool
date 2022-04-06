#include "data.h"

#include <algorithm>

#include "tracker.h"
#include "share_adapters.h"
#include <networks/network.h>
#include <libdevcore/stream_types.h>

namespace shares
{
    bool is_segwit_activated(int version, shared_ptr<c2pool::Network> net)
    {
        return version >= net->SEGWIT_ACTIVATION_VERSION;
    }

    //TODO: test
    uint256 check_hash_link(shared_ptr<::HashLinkType> hash_link, PackStream &data, string const_ending)
    {
        uint64_t extra_length = (*hash_link)->length % (512 / 8);
        assert((*hash_link)->extra_data.size() == max(extra_length - const_ending.size(), (uint64_t)0));

        auto extra = (*hash_link)->extra_data + const_ending;
        {
            int32_t len = (*hash_link)->extra_data.size() + const_ending.length() - extra_length;
            extra = string(extra, len, extra.length() - len);
        }
        assert(extra.size() == extra_length);

        IntType(256) result;

        //TODO: SHA256 test in p2pool
        //TODO: return pack.IntType(256).unpack(hashlib.sha256(sha256.sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest())

        return result.get();
    }

    GenerateShareTransaction::GenerateShareTransaction(std::shared_ptr<ShareTracker> _tracker) : tracker(_tracker), net(_tracker->net)
    {

    }

    //TODO: Test
    GeneratedShare GenerateShareTransaction::operator()(uint64_t version)
    {
        //t0
		ShareType previous_share = tracker->get(_share_data.previous_share_hash);

		//height, last
		auto get_height_and_last = tracker->get_height_and_last(_share_data.previous_share_hash);
		auto height = std::get<0>(get_height_and_last);
		auto last = std::get<1>(get_height_and_last);
        assert((height >= net->REAL_CHAIN_LENGTH) || last.IsNull());

		arith_uint256 _pre_target3;
		if (height < net->TARGET_LOOKBEHIND)
		{
			_pre_target3 = net->MAX_TARGET;
		} else
		{
			auto attempts_per_second = tracker->get_pool_attempts_per_second(_share_data.previous_share_hash, net->TARGET_LOOKBEHIND, true);

            arith_uint256 pre_target;
            pre_target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            if (attempts_per_second != 0)
            {
                //equal: 2**256/(net.SHARE_PERIOD*attempts_per_second) - 1
                pre_target -= attempts_per_second*net->SHARE_PERIOD;
                pre_target /= attempts_per_second*net->SHARE_PERIOD;
            }

            arith_uint256 pre_target2;
            {
                arith_uint256 _max_target_div10 = UintToArith256(previous_share->max_target)/10;
                arith_uint256 _min_clip = _max_target_div10*9;
                arith_uint256 _max_clip = _max_target_div10*11;
                pre_target2 = c2pool::math::clip(pre_target, _min_clip, _max_clip);
            }

            _pre_target3 = c2pool::math::clip(pre_target2, UintToArith256(net->MIN_TARGET), UintToArith256(net->MAX_TARGET));
		}
        uint256 pre_target3 = ArithToUint256(_pre_target3);

        FloatingInteger max_bits = FloatingInteger::from_target_upper_bound(pre_target3);
        FloatingInteger bits;
        {
            arith_uint256 __desired_target = UintToArith256(_desired_target);
            arith_uint256 _pre_target3_div30 = _pre_target3/30;
            bits = FloatingInteger::from_target_upper_bound(
                    ArithToUint256(c2pool::math::clip(__desired_target, _pre_target3_div30, _pre_target3))
            );
        }

		vector<uint256> new_transaction_hashes;
		int32_t all_transaction_stripped_size = 0;
		int32_t new_transaction_weight = 0;
		int32_t all_transaction_weight = 0;
		vector<tuple<uint64_t, uint64_t>> transaction_hash_refs;
		vector<uint256> other_transaction_hashes;

		//t1

		auto past_shares_generator = tracker->get_chain(previous_share->hash, std::min(height, 100));
		map<uint256, tuple<int, int>> tx_hash_to_this;

		{
			uint256 _hash;
			int32_t i = 0;
			while (past_shares_generator(_hash))
			{
				auto _share = tracker->get(_hash);
				for (int j = 0; j < _share->new_transaction_hashes->size(); j++)
				{
					auto tx_hash = (*_share->new_transaction_hashes)[j];
					if (tx_hash_to_this.find(tx_hash) == tx_hash_to_this.end())
					{
						tx_hash_to_this[tx_hash] = std::make_tuple(1 + i, j);
					}
				}
				i += 1;
			}
		}

		//t2
        //TODO: test
		for (auto item: _desired_other_transaction_hashes_and_fees)
		{
			auto tx_hash = std::get<0>(item);
			auto fee = std::get<1>(item);

			int32_t this_stripped_size = 0;
			int32_t this_real_size = 0;
			int32_t this_weight = 0;
			if (!_known_txs.empty())
			{
                auto _tx = _known_txs[tx_hash];
                // this_stripped_size
                {

                    PackStream temp_txid;
                    auto stream_txid = coind::data::stream::TxIDType_stream(_tx->version,_tx->tx_ins, _tx->tx_outs, _tx->lock_time);
                    temp_txid << stream_txid;
                    this_stripped_size = temp_txid.size();
                }
                // this_real_size
                {
                    PackStream temp_tx;
                    auto stream_tx = coind::data::stream::TransactionType_stream(_tx);
                    temp_tx << stream_tx;
                    this_real_size = temp_tx.size();
                }
				this_weight = this_real_size + 3 * this_stripped_size;
			}

			if (all_transaction_stripped_size + this_stripped_size + 80 + Share::gentx_size + 500 >
				net->BLOCK_MAX_SIZE)
				break;
			if (all_transaction_weight + this_weight + 4 * 80 + Share::gentx_size + 2000 >
				net->BLOCK_MAX_WEIGHT)
				break;

			tuple<int, int> _this;
			all_transaction_stripped_size += this_stripped_size;
			//all_transaction_real_size += this_real_size;
			all_transaction_weight += this_weight;
			if (tx_hash_to_this.find(tx_hash) != tx_hash_to_this.end())
			{
				_this = tx_hash_to_this[tx_hash];
			} else
			{
				//new_transaction_size += this_real_size;
				new_transaction_weight += this_weight;

				new_transaction_hashes.push_back(tx_hash);
				_this = std::make_tuple(0, new_transaction_hashes.size() - 1);
			}
			transaction_hash_refs.push_back(_this);
			other_transaction_hashes.push_back(tx_hash);
		}

		//t3

		// Тут в питон-коде проводятся махинации с упаковкой в типы C, для оптимизации памяти. Нам, по идее, это не нужно.
		// if transaction_hash_refs and max(transaction_hash_refs) < 2**16:
		//     transaction_hash_refs = array.array('H', transaction_hash_refs)
		// elif transaction_hash_refs and max(transaction_hash_refs) < 2**32: # in case we see blocks with more than 65536 tx
		//     transaction_hash_refs = array.array('L', transaction_hash_refs)

		//t4

		// if all_transaction_stripped_size:
		//     print "Generating a share with %i bytes, %i WU (new: %i B, %i WU) in %i tx (%i new), plus est gentx of %i bytes/%i WU" % (
		//         all_transaction_real_size,
		//         all_transaction_weight,
		//         new_transaction_size,
		//         new_transaction_weight,
		//         len(other_transaction_hashes),
		//         len(new_transaction_hashes),
		//         cls.gentx_size,
		//         cls.gentx_weight)
		//     print "Total block stripped size=%i B, full size=%i B,  weight: %i WU" % (
		//         80+all_transaction_stripped_size+cls.gentx_size,
		//         80+all_transaction_real_size+cls.gentx_size,
		//         3*80+all_transaction_weight+cls.gentx_weight)

		set<uint256> included_transactions = set<uint256>(other_transaction_hashes.begin(),
														  other_transaction_hashes.end());

		vector<boost::optional<int32_t>> removed_fee;
		int32_t removed_fee_sum;
		int32_t definite_fees;
		bool fees_none_contains = false;
		for (auto item: _desired_other_transaction_hashes_and_fees)
		{
			auto tx_hash = std::get<0>(item);
			auto fee = std::get<1>(item);
			if (!fee.has_value())
				fees_none_contains = true;

			if (included_transactions.find(tx_hash) == included_transactions.end())
			{
				removed_fee.push_back(fee);
				if (fee.has_value())
					removed_fee_sum += fee.get();
			} else
			{
				if (fee.has_value())
					definite_fees += fee.get();
				else
					definite_fees += 0;
			}
		}

		if (!fees_none_contains)
		{
			_share_data.subsidy += removed_fee_sum;
		} else
		{
			_share_data.subsidy = _base_subsidy + definite_fees;
		}


		std::map<std::vector<unsigned char>, arith_uint256> weights;
		arith_uint256 total_weight;
		arith_uint256 donation_weight;
		{
			uint256 start_hash;
			if (previous_share)
				start_hash = *previous_share->previous_hash;
			else
				start_hash.SetNull();

			int32_t max_shares = max(0, min(height, net->REAL_CHAIN_LENGTH) - 1);

			arith_uint256 desired_weight =
					UintToArith256(coind::data::target_to_average_attempts(_block_target)) * 65535 * net->SPREAD;

			auto weights_result = tracker->get_cumulative_weights(start_hash, max_shares, desired_weight);
			weights = std::get<0>(weights_result);
			total_weight = std::get<1>(weights_result);
			donation_weight = std::get<2>(weights_result);
		}

		//assert
		{
			arith_uint256 sum_weights;
			sum_weights.SetHex("0");
			for (auto v : weights)
			{
				sum_weights += v.second;
			}

			assert(total_weight == (sum_weights + donation_weight));
		}

		// 99.5% goes according to weights prior to this share
		std::map<std::vector<unsigned char>, arith_uint256> amounts;
		for (auto v : weights)
		{
			amounts[v.first] = v.second*199*_share_data.subsidy/(200*total_weight);
		}

		//this script reward; 0.5% goes to block finder
		{
			std::vector<unsigned char> this_script = coind::data::pubkey_hash_to_script2(_share_data.pubkey_hash).data;
			auto _this_amount = amounts.find(this_script);
			if (_this_amount == amounts.end())
				amounts[this_script] = 0;
			amounts[this_script] += _share_data.subsidy/200;
		}

		std::vector<unsigned char> DONATION_SCRIPT; //TODO:
		//all that's left over is the donation weight and some extra satoshis due to rounding
		{
			auto _donation_amount = amounts.find(DONATION_SCRIPT);
			if (_donation_amount == amounts.end())
				amounts[DONATION_SCRIPT] = 0;

			arith_uint256 sum_amounts;
			sum_amounts.SetHex("0");
			for (auto v: amounts)
			{
				sum_amounts += v.second;
			}

			amounts[DONATION_SCRIPT] += _share_data.subsidy - sum_amounts;
		}
//TODO: check
//		if sum(amounts.itervalues()) != share_data['subsidy'] or any(x < 0 for x in amounts.itervalues()):
//			raise ValueError()

//		dests = sorted(amounts.iterkeys(), key=lambda script: (script == DONATION_SCRIPT, amounts[script], script))[-4000:] # block length limit, unlikely to ever be hit
		std::vector<std::pair<std::vector<unsigned char>, arith_uint256>> dests(amounts.begin(),amounts.end());
		std::sort(dests.begin(), dests.end(), [&](std::pair<std::vector<unsigned char>, arith_uint256> a, std::pair<std::vector<unsigned char>, arith_uint256> b){
			if (a.first == DONATION_SCRIPT)
				return false;

			return a.second != b.second ? a.second < b.second : a.first < b.first;
		});

		bool segwit_activated = is_segwit_activated(version, net);
    	if (!_segwit_data.has_value() && _known_txs.empty())
		{
			segwit_activated = false;
		}

		bool segwit_tx = false;
		for (auto _tx_hash: other_transaction_hashes)
		{
			if (coind::data::is_segwit_tx(_known_txs[_tx_hash]))
				segwit_tx = true;
		}
		if (!(segwit_activated || _known_txs.empty()) && segwit_tx)
		{
			throw "segwit transaction included before activation";
		}

		//	share_txs = [(known_txs[h], bitcoin_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
		//  segwit_data = dict(txid_merkle_link=bitcoin_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=bitcoin_data.merkle_hash([0] + [bitcoin_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
		if (segwit_activated && !_known_txs.empty())
		{
			struct __share_tx{
				std::shared_ptr<coind::data::TransactionType> tx;
				uint256 txid;
				uint256 h; //hash

				__share_tx() = default;
				__share_tx(std::shared_ptr<coind::data::TransactionType> _tx, uint256 _txid, uint256 _h)
				{
					tx = _tx;
					txid = _txid;
					h = _h;
				}
			};
			std::vector<__share_tx> share_txs;
			std::vector<uint256> txids;
			for (auto h : other_transaction_hashes)
			{
				auto txid = coind::data::get_txid(_known_txs[h]);
				share_txs.emplace_back(_known_txs[h], txid, h);
				txids.push_back(txid);
			}
		}

//		/*TODO:
//		if segwit_activated and known_txs is not None:
//			share_txs = [(known_txs[h], bitcoin_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
//			segwit_data = dict(txid_merkle_link=bitcoin_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=bitcoin_data.merkle_hash([0] + [bitcoin_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
//		if segwit_activated and segwit_data is not None:
//			witness_reserved_value_str = '[P2Pool]'*4
//			witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
//			witness_commitment_hash = bitcoin_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)
//	*/
//
//        unique_ptr<ShareInfo> share_info;
//        {
//            uint256 far_share_hash;
//            if (last.IsNull() && height < 99)
//                far_share_hash.SetNull();
//            else
//                far_share_hash = tracker->get_nth_parent_hash(_share_data.previous_share_hash, 99);
//
//            int32_t result_timestamp;
//
//            if (previous_share != nullptr)
//            {
//                if (version < 32)
//                    result_timestamp = std::clamp(_desired_timestamp, *previous_share->timestamp + 1,
//                                                  *previous_share->timestamp + net->SHARE_PERIOD * 2 - 1);
//                else
//                    result_timestamp = std::max(_desired_timestamp, *previous_share->timestamp + 1);
//            } else
//            {
//                result_timestamp = _desired_timestamp;
//            }
//
//            unsigned long absheight = 1;
//            if (previous_share)
//            {
//                absheight += *previous_share->absheight;
//            }
//            absheight %= 4294967296; //% 2**32
//
//            uint128 abswork;
//            if (previous_share)
//            {
//                abswork = *previous_share->abswork;
//            }
//            //TODO: abswork=((previous_share.abswork if previous_share is not None else 0) + bitcoin_data.target_to_average_attempts(bits.target)) % 2**128,
//
//            share_info = std::make_unique<ShareInfo>(
//                    far_share_hash,
//                    max_bits.get(),
//                    bits.get(),
//                    result_timestamp,
//                    new_transaction_hashes,
//                    transaction_hash_refs,
//                    absheight,
//                    abswork
//                    );
//        }
//
//		if (previous_share)
//		{
//			if (_desired_timestamp > (*previous_share->timestamp + 180))
//			{
//				LOG_WARNING << (boost::format("Warning: Previous share's timestamp is %1% seconds old.\n \
//                            Make sure your system clock is accurate, and ensure that you're connected to decent peers.\n \
//                            If your clock is more than 300 seconds behind, it can result in orphaned shares.\n \
//                            (It's also possible that this share is just taking a long time to mine.)") %
//								(_desired_timestamp - *previous_share->timestamp))
//							.str();
//			}
//
//			if (*previous_share->timestamp > (c2pool::dev::timestamp() + 3))
//			{
//				LOG_WARNING << (boost::format("WARNING! Previous share's timestamp is %1% seconds in the future. This is not normal.\n"
//                                              "Make sure your system clock is accurate.Errors beyond 300 sec result in orphaned shares.") %
//								(*previous_share->timestamp - c2pool::dev::timestamp()))
//							.str();
//			}
//		}
//
//        // gentx
//		coind::data::tx_type gentx;
//        {
//            vector<coind::data::TxInType> tx_ins; //TODO: init
//            vector<coind::data::TxOutType> tx_outs; //TODO: init
//
//            if (segwit_activated)
//            {
//                vector<ListType<StrType>> witness; //TODO: init
//                gentx = std::make_shared<coind::data::WitnessTransactionType>(1, 0, 1, tx_ins, tx_outs, witness, 0);
//            }
//            else
//                gentx = std::make_shared<coind::data::TransactionType>(1, tx_ins, tx_outs, 0);
//        }
//
//
//		get_share_method get_share([=](SmallBlockHeaderType header, unsigned long long last_txout_nonce)
//								   {
//									   auto min_header = header;
//									   ShareType share = std::make_shared<ShareType>(); //TODO: GENERATE SHARE IN CONSTUCTOR
//								   });
//
//		/*
//		 TODO: TIMER?
//		t5 = time.time()
//		if p2pool.BENCH: print "%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
//			(t5-t0)*1000.,
//			(t1-t0)*1000.,
//			(t2-t1)*1000.,
//			(t3-t2)*1000.,
//			(t4-t3)*1000.,
//			(t5-t4)*1000.)
//	    */
//
//        //TODO:
//        //if segwit_activated:
//        //            share_info['segwit_data'] = segwit_data
//
//		return {share_info, gentx, other_transaction_hashes, get_share};
    }
}