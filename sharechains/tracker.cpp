#include "tracker.h"
#include "share.h"
using namespace c2pool::shares::share;

#include <lib/univalue/include/univalue.h>
#include <btclibs/uint256.h>
#include <devcore/logger.h>

#include <map>
#include <queue>
#include <memory>
using std::map;
using std::queue;
using std::shared_ptr;



namespace c2pool::shares::tracker
{
    void ShareTracker::add(shared_ptr<BaseShare> share)
    {
        if (items.find(share->hash) != items.end()){
            items[share->hash] = share;
        } else {
            LOG_WARNING << share->hash.ToString() << " item already present";
        }
        
        lookbehind_items.push(share);
    }
}