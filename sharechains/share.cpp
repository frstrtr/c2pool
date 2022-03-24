#include "share.h"

#include <univalue.h>
#include <libdevcore/logger.h>
#include <libdevcore/common.h>
#include <libdevcore/addrStore.h>
#include "tracker.h"
#include "data.h"
#include <stdexcept>
#include <tuple>
#include <set>

using namespace std;

#include <boost/format.hpp>

#define CheckShareRequirement(field_name)               \
    if (field_name)                                     \
        throw std::runtime_error(#field_name " == NULL");

void Share::init()
{
    CheckShareRequirement(min_header);
    CheckShareRequirement(share_data);
    CheckShareRequirement(share_info);
    CheckShareRequirement(ref_merkle_link);
    CheckShareRequirement(hash_link);
    CheckShareRequirement(merkle_link);

    bool segwit_activated = shares::is_segwit_activated(VERSION, net);

    if (!(coinbase->size() >= 2 && coinbase->size() <= 100))
    {
        throw std::runtime_error((boost::format("bad coinbase size! %1% bytes.") % coinbase->size()).str());
    }

    if ((*merkle_link)->branch.size() > 16)
    {
        throw std::runtime_error("Merkle branch too long#1!");
    }

    if (segwit_activated)
        if ((*segwit_data)->txid_merkle_link.branch.size() > 16)
            throw std::runtime_error("Merkle branch too long#1!");

    assert(hash_link->get()->extra_data.empty());

    new_script = coind::data::pubkey_hash_to_script2((*share_data)->pubkey_hash);

    if (net->net_name == "bitcoin" && *absheight > 3927800 && *desired_version == 16)
    {
        throw std::runtime_error("This is not a hardfork-supporting share!");
    }

//TODO: check txs
//    std::set<int32_t> n;
//    for share_count, tx_count in self.iter_transaction_hash_refs():
//      assert share_count < 110
//      if share_count == 0:
//          n.add(tx_count)
//    assert n == set(range(len(self.share_info['new_transaction_hashes'])))


    //TODO: GENTX
//    gentx_hash =  shares::check_hash_link(
//            hash_link,
//
//            );

     //TODO: header
     //TODO: pow_hash
     //TODO: hash

    if (target > net->MAX_TARGET)
    {
        throw std::runtime_error("Share target invalid!"); //TODO: remake for c2pool::p2p::exception_from_peer
    }

    if (pow_hash > target)
    {
        throw std::runtime_error("Share PoW indalid!"); //TODO: remake for c2pool::p2p::exception_from_peer
    }
}
#undef CheckShareRequirement

void Share::check(std::shared_ptr<ShareTracker> _tracker)
{
    if (*timestamp > (c2pool::dev::timestamp() + 600))
    {
        throw std::invalid_argument((boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} % (*timestamp - c2pool::dev::timestamp())).str());
    }

    std::map<uint64_t, uint256> counts;

    if (!previous_hash->IsNull())
    {
        auto previous_share = _tracker->get(*previous_hash);
        if (_tracker->get_height(*previous_hash) >= net->CHAIN_LENGTH)
        {
            //tracker.get_nth_parent_hash(previous_share.hash, self.net.CHAIN_LENGTH*9//10), self.net.CHAIN_LENGTH//10
            counts = _tracker->get_desired_version_counts(_tracker->get_nth_parent_hash(previous_share->hash, net->CHAIN_LENGTH*9/10), net->CHAIN_LENGTH/10);
        }
    }
}


std::shared_ptr<Share> load_share(PackStream &stream, shared_ptr<c2pool::Network> net, c2pool::libnet::addr peer_addr)
{
	PackedShareData packed_share;
	stream >> packed_share;

	PackStream _stream(packed_share.contents.value);

	ShareDirector director(net);
	switch (packed_share.type.value)
	{
		case 17:
			return director.make_Share(packed_share.type.value, peer_addr, _stream);
		case 32:
			return director.make_PreSegwitShare(packed_share.type.value, peer_addr, _stream);
		default:
			if (packed_share.type.value < 17)
				throw std::runtime_error("sent an obsolete share");
			else
				throw std::runtime_error((boost::format("unkown share type: %1") % packed_share.type.value).str());
			break;
	}
}