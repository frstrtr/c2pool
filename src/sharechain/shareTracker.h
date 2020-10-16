#ifndef SHARE_TRACKER_H
#define SHARE_TRACKER_H

#include <shareTypes.h>
#include <uint256.h>
#include <vector>
#include <map>


using std::vector, std::map;

namespace c2pool::shares{
    class BaseShare;
}

namespace c2pool::shares::tracker
{
    class Tracker
    {
    public:
        map<uint256, BaseShare>  items;
        auto reverse;

        auto heads;
        auto tails;

        auto added;
        auto remove_special;
        auto remove_special2;
        auto removed;

        auto get_nth_parent_hash = DistanceSkipList(self);

        auto delta_type = delta_type;
        auto default_view = TrackerView(self, delta_type);

    public:
        Tracker(vector<c2pool::shares::BaseShare> _items, auto /*TODO: type*/ _delta_type);

        void add(BaseShare item);

        void remove(uint256 item_hash); //TODO: type for item_hash
    };
} // namespace c2pool::shares::tracker

#endif //SHARE_TRACHER_H