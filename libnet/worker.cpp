#include "worker.h"

#include <vector>
#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>

#include "p2p_node.h"
#include <btclibs/uint256.h>
#include <sharechains/data.h>

using std::vector;

namespace c2pool::libnet
{
	Worker::Worker(std::shared_ptr<c2pool::Network> net, std::shared_ptr<c2pool::libnet::p2p::P2PNode> p2p_node, std::shared_ptr<ShareTracker> tracker) : _net(net), _p2p_node(p2p_node), _tracker(tracker)
	{

	}

	void Worker::get_work(uint160 pubkey_hash, uint256 desired_share_target, uint256 desired_pseudoshare_target)
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
		for (auto tx : current_work.value().transactions)
		{
			 coind::data::stream::TransactionType_stream _tx(tx);
			 PackStream packed_tx;
			 packed_tx << _tx;

			 tx_hashes.push_back(coind::data::hash256(packed_tx));
		}

		uint256 _tx_hash;
		coind::data::tx_type _tx;

		std::map<uint256, coind::data::tx_type> tx_map;
		BOOST_FOREACH(boost::tie(_tx_hash, _tx), boost::combine(tx_hashes, current_work.value().transactions))
		{
			tx_map[_tx_hash] = _tx;
		}

		//TODO???: self.node.mining2_txs_var.set(tx_map) # let node.py know not to evict these transactions

		//4
		//TODO: check for share_version

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

		if (desired_share_target.IsNull())
		{
			//TODO: DUMB_SCRYPT_DIFF to parent network
//			desired_share_target = coind::data::difficulty_to_target(1/_net->parent->DUMB)
		}

		//6
		shares::GenerateShareTransaction generate_transaction(_tracker);
		generate_transaction.
				//TODO: set_share_data()
				set_block_target(FloatingInteger(current_work.value().bits).target()).
				set_desired_timestamp(dev::timestamp()+0.5f).
				set_desired_target(desired_share_target).
				//TODO: set_ref_merkle_link
				//TODO: set_desired_other_transaction_hashes_and_fees
				//TODO: set_base_subsidy
				set_known_txs(tx_map);

//		auto generate_tx_result = generate_transaction()

		//7
//		coind::data::stream::TransactionType_stream packed_gentx(generate_transaction);
//		PackStream packed_tx;
//		packed_tx << _tx;
	}
}