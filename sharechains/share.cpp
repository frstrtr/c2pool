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