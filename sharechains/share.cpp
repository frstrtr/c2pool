#include "share.h"

#include <univalue.h>
#include <devcore/logger.h>
#include <sharechains/tracker.h>

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

   operator c2pool::shares::tracker::PrefixSumShare() const{
       return {hash, coind::data::target_to_average_attempts(share->target), coind::data::target_to_average_attempts(share->max_target), 1};
   }
}