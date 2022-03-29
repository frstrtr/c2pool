#include "prefsum_weights.h"
#include "tracker.h"

namespace shares::weight
{
    PrefsumWeights::PrefsumWeights(std::shared_ptr<ShareTracker> tracker) : _tracker(tracker)
    {
        tracker->removed.subscribe([&](ShareType share){
//TODO:            remove(share);
        });
    }
}