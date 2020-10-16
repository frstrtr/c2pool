#include <shareTracker.h>
#include <share.h>
#include <vector>
using std::vector;

namespace c2pool::shares::tracker
{
    Tracker::Tracker(vector<c2pool::shares::BaseShare> _items, auto /*TODO: type*/ _delta_type)
    {
    }

    void Tracker::add(BaseShare item)
    {
        //TODO: delta = self._delta_type.from_element(item)

        //TODO: add delta
        // if delta.head in self.items:
        //     raise ValueError('item already present')

        // if delta.head in self.tails:
        //     heads = self.tails.pop(delta.head)
        // else:
        //     heads = set([delta.head])

        // if delta.tail in self.heads:
        //     tail = self.heads.pop(delta.tail)
        // else:
        //     tail = self.get_last(delta.tail)

        // self.items[delta.head] = item
        // self.reverse.setdefault(delta.tail, set()).add(delta.head)

        // self.tails.setdefault(tail, set()).update(heads)
        // if delta.tail in self.tails[tail]:
        //     self.tails[tail].remove(delta.tail)

        // for head in heads:
        //     self.heads[head] = tail

        // self.added.happened(item)
    }

    void remove(uint256 item_hash)
    {
        //TODO
    }
} // namespace c2pool::shares::tracker