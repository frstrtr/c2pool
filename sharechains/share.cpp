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

void Share::check(std::shared_ptr<ShareTracker> _tracker)
{
    if (*timestamp > (c2pool::dev::timestamp() + 600))
    {
        throw std::invalid_argument((boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} % (*timestamp - c2pool::dev::timestamp())).str());
    }

    std::map<uint64_t, uint64_t> counts;

    if (!previous_hash->IsNull())
    {
        auto previous_share = _tracker->get(*previous_hash);
        //TODO: remove comments, when updated tracker
//        if (_tracker->get_height(*previous_hash) >= net->CHAIN_LENGTH)
//        {
//            //tracker.get_nth_parent_hash(previous_share.hash, self.net.CHAIN_LENGTH*9//10), self.net.CHAIN_LENGTH//10
//            counts = _tracker->get_desired_version_counts(_tracker->get_nth_parent_hash(*previous_share->hash, net->CHAIN_LENGTH*9/10), net->CHAIN_LENGTH/10);
//        }
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