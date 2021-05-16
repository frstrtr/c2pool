#include "share.h"

#include <univalue.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include "tracker.h"

#include <boost/format.hpp>

namespace c2pool::shares::share
{
    std::string BaseShare::SerializeJSON()
    {
        UniValue json(UniValue::VOBJ);

        //TODO:
        // json.pushKV("TYPE", (int)TYPE);
        // json.pushKV("contents", contents);

        return json.write();
    }
    void BaseShare::DeserializeJSON(std::string json)
    {
        //TODO:
        UniValue ShareValue(UniValue::VOBJ);
        ShareValue.read(json);

        // TYPE = (ShareVersion)ShareValue["TYPE"].get_int();
        // LOG_DEBUG << TYPE;
        // contents = ShareValue["contents"].get_obj();
    }

    void BaseShare::check(shared_ptr<c2pool::shares::tracker::ShareTracker> tracker /*, TODO: other_txs = None???*/)
    {
        if (timestamp > (c2pool::dev::timestamp() + 600))
        {
            throw std::invalid_argument((boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} % (timestamp - c2pool::dev::timestamp())).str());
        }

        if (!previous_hash.IsNull()) //TODO: or pack in share_data
        {
            auto previous_share = tracker->get(previous_hash);
            if (tracker->get_height(share_data.previous_hash))
        }
    }
}