#include "share.h"

#include <univalue.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <libdevcore/addrStore.h>
#include "tracker.h"
#include <stdexcept>
#include <tuple>
#include <set>

using namespace std;

#include <boost/format.hpp>
//
//bool BaseShare::check(shared_ptr<ShareTracker> tracker /*, TODO: other_txs = None???*/)
//{
//	if (timestamp > (c2pool::dev::timestamp() + 600))
//	{
//		throw std::invalid_argument(
//				(boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} %
//				 (timestamp - c2pool::dev::timestamp())).str());
//	}
//
//	if (!previous_hash.IsNull()) //TODO: or pack in share_data
//	{
//		auto previous_share = tracker->get(previous_hash);
//		//if (tracker->get_height(previous_hash))
//	}
//	//TODO:
//}
//
////void BaseShare::contents_load(UniValue contents)
////{
////	min_header = contents["min_header"].get_obj();
////
////	auto share_info = contents["share_info"].get_obj();
////	auto share_data = share_info["share_data"].get_obj();
////
////	previous_hash.SetHex(share_data["previous_share_hash"].get_str());
////	coinbase = share_data["coinbase"].get_str();
////	nonce = share_data["nonce"].get_int();
////	pubkey_hash.SetHex(share_data["pubkey_hash"].get_str());
////	subsidy = share_data["subsidy"].get_uint64();
////	donation = share_data["donation"].get_int();
////
////	int stale_info_temp = share_data["stale_info"].get_int();
////	if (stale_info_temp == 253 || stale_info_temp == 254)
////	{
////		stale_info = (StaleInfo) stale_info_temp;
////	} else
////	{
////		stale_info = StaleInfo::unk;
////	}
////
////	desired_version = share_data["desired_version"].get_uint64();
////
////	for (auto item: share_info["new_transaction_hashes"].getValues())
////	{
////		uint256 tx_hash;
////		tx_hash.SetHex(item.get_str());
////		new_transaction_hashes.push_back(tx_hash);
////	}
////
////	for (auto tx_hash_ref: share_info["transaction_hash_refs"].getValues())
////	{
////		transaction_hash_refs.push_back(std::make_tuple<int, int>(tx_hash_ref[0].get_int(), tx_hash_ref[1].get_int()));
////	}
////
////	far_share_hash.SetHex(share_info["far_share_hash"].get_str());
////	max_target.SetHex(share_info["max_bits"].get_str());
////	target.SetHex(share_info["bits"].get_str());
////	timestamp = share_info["timestamp"].get_int();
////	absheight = share_info["absheight"].get_int();
////	abswork.SetHex(share_info["abswork"].get_str());
////
////	ref_merkle_link = contents["ref_merkle_link"].get_obj();
////	last_txout_nonce = contents["last_txout_nonce"].get_uint64();
////	hash_link = contents["hash_link"].get_obj();
////	merkle_link = contents["merkle_link"].get_obj();
////}
////
////UniValue BaseShare::to_contents()
////{
////	UniValue result;
////	result.pushKV("min_header", (UniValue) min_header);
////
////	//START: share_info
////	UniValue share_info(UniValue::VOBJ);
////	//START: share_info::share_data
////	UniValue share_data(UniValue::VOBJ);
////
////	share_data.pushKV("previous_share_hash", previous_hash.GetHex());
////	share_data.pushKV("coinbase", coinbase);
////	share_data.pushKV("nonce", (int) nonce);
////	share_data.pushKV("pubkey_hash", pubkey_hash.GetHex());
////	share_data.pushKV("subsidy", subsidy);
////	share_data.pushKV("donation", donation);
////	share_data.pushKV("stale_info", (int) stale_info);
////	share_data.pushKV("desired_version", desired_version);
////
////	share_info.pushKV("share_data", share_data);
////	//END: share_info::share_data
////
////	UniValue _new_transaction_hashes(UniValue::VARR);
////	for (auto item: new_transaction_hashes)
////	{
////		_new_transaction_hashes.push_back(item.GetHex());
////	}
////	share_info.pushKV("new_transaction_hashes", _new_transaction_hashes);
////
////	UniValue _transaction_hash_refs(UniValue::VARR);
////	for (auto _tx_hash_ref: transaction_hash_refs)
////	{
////		UniValue _tx_ref(UniValue::VARR);
////		_tx_ref.push_back(std::get<0>(_tx_hash_ref));
////		_tx_ref.push_back(std::get<1>(_tx_hash_ref));
////		_transaction_hash_refs.push_back(_tx_ref);
////	}
////	share_info.pushKV("transaction_hash_refs", _transaction_hash_refs);
////	share_info.pushKV("far_share_hash", far_share_hash.GetHex());
////	share_info.pushKV("max_bits", max_target.GetHex());
////	share_info.pushKV("bits", target.GetHex());
////	share_info.pushKV("timestamp", timestamp);
////	share_info.pushKV("absheight", absheight);
////	share_info.pushKV("abswork", abswork.GetHex());
////	//END: share_info
////
////	result.pushKV("share_info", share_info);
////	result.pushKV("ref_merkle_link", (UniValue) ref_merkle_link);
////	result.pushKV("last_txout_nonce", last_txout_nonce);
////	result.pushKV("hash_link", (UniValue) hash_link);
////	result.pushKV("merkle_link", (UniValue) merkle_link);
////
////	return result;
////}
//
//BaseShare::BaseShare(int VERSION, shared_ptr<c2pool::Network> _net, tuple<string, string> _peer_addr, UniValue _contents)
//		: SHARE_VERSION(VERSION), net(_net), peer_addr(_peer_addr), contents(_contents)
//{
//	contents_load(contents);
//
//	bool segwit_activated = is_segwit_activated();
//
//	if (!(2 <= coinbase.length() && coinbase.length() <= 100))
//	{
//		throw std::runtime_error((boost::format("bad coinbase size! %1 bytes") % coinbase.length()).str());
//	}
//
//	if (merkle_link.branch.size() > 16 && !is_segwit_activated())
//	{
//		throw std::runtime_error("merkle branch too long!");
//	}
//
//	//TODO: need???  assert not self.hash_link['extra_data'], repr(self.hash_link['extra_data'])
//
//	if (net->net_name == "bitcoin" && absheight > 3927800 && desired_version == 16)
//	{
//		throw std::runtime_error("This is not a hardfork-supporting share!");
//	}
//
//	{
//		set<int> n;
//
//		for (auto tx_hash_ref: transaction_hash_refs)
//		{
//			int share_count = std::get<0>(tx_hash_ref);
//			int tx_count = std::get<1>(tx_hash_ref);
//			assert(share_count < 110);
//			if (share_count == 0)
//			{
//				n.insert(tx_count);
//			}
//		}
//		set<int> set_new_tx_hashes;
//		for (int i = 0; i < new_transaction_hashes.size(); i++)
//		{
//			set_new_tx_hashes.insert(i);
//		}
//		assert(set_new_tx_hashes == n);
//	}
//
//
//	//TODO:
//	// auto _ref_hash = BaseShare::get_ref_hash(net, share_info, contents["ref_merkle_link"]); //TODO: contents remake
//	// _ref_hash << IntType(64)(contents.last_txout_nonce) << IntType(32)(0);
//
//	// gentx_hash = check_hash_link(
//	//     hash_link,
//	//     _ref_hash,
//	//     gentx_before_refhash
//	// );
//	/*
//	TODO:
//
//	self.gentx_hash = check_hash_link(
//		self.hash_link,
//		self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
//		self.gentx_before_refhash,
//	)
//	merkle_root = bitcoin_data.check_merkle_link(self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)
//	self.header = dict(self.min_header, merkle_root=merkle_root)
//	self.pow_hash = net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(self.header))
//	self.hash = self.header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(self.header))
//
//	*/
//
//	if (target.Compare(net->MAX_TARGET) > 0)
//	{
//		throw std::runtime_error("share target invalid");
//	}
//
//	if (pow_hash.Compare(target) > 0)
//	{
//		throw std::runtime_error("share PoW invalid");
//	}
//
//	time_seen = c2pool::dev::timestamp();
//}
//
//void Share::contents_load(UniValue contents)
//{
//	BaseShare::contents_load(contents);
//}
//
//void PreSegwitShare::contents_load(UniValue contents)
//{
//	BaseShare::contents_load(contents);
//	if (is_segwit_activated())
//		segwit_data = contents["share_info"]["segwit_data"].get_obj();
//}
//
//#define MAKE_SHARE(CLASS)                                                           \
//    share_result = make_shared<CLASS>(net, peer_addr, share["contents"].get_obj()); \
//    break;


std::shared_ptr<Share> load_share(PackStream &stream, shared_ptr<c2pool::Network> net, c2pool::libnet::addr peer_addr)
{
	PackedShareData packed_share;
	stream >> packed_share;

	PackStream _stream(packed_share.contents.value);

	ShareDirector director(net);
	switch (packed_share.type.value)
	{
		case 17:
			return director.make_Share(packed_share.type.value, _stream);
		case 32:
			return director.make_PreSegwitShare(packed_share.type.value, _stream);
		default:
			if (packed_share.type.value < 17)
				throw std::runtime_error("sent an obsolete share");
			else
				throw std::runtime_error((boost::format("unkown share type: %1") % packed_share.type.value).str());
			break;
	}
}


//shared_ptr<BaseShare> load_share(UniValue share, shared_ptr<c2pool::Network> net, c2pool::libnet::addr peer_addr)
//{
//	shared_ptr<BaseShare> share_result;
//	int type_version;
//	if (share.exists("type"))
//	{
//		type_version = share["type"].get_int();
//	} else
//	{
//		throw std::runtime_error("share data in load_share() without type!");
//	}
//
//	switch (type_version)
//	{
//		case 17:
//		MAKE_SHARE(Share) //TODO: TEST
//		case 32:
//		MAKE_SHARE(PreSegwitShare) //TODO: TEST
//		default:
//			if (type_version < 17)
//				throw std::runtime_error("sent an obsolete share");
//			else
//				throw std::runtime_error((boost::format("unkown share type: %1") % type_version).str());
//			break;
//	}
//
//	return share_result;
//}



#undef MAKE_SHARE