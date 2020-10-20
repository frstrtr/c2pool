#include <shareTracker.h>
#include <share.h>
#include <vector>
#include <uint256.h>
#include <share.h>

using std::vector;

namespace c2pool::shares::tracker
{
    ProtoAttributeDelta::ProtoAttributeDelta(BaseShare item)
    {
        head = item.hash;
        tail = item.previous_hash;
        height = 1;
    }

    ProtoAttributeDelta::ProtoAttributeDelta(uint256 _head, uint256 _tail, int _height)
    {
        head = _head;
        tail = _tail;
        height = _height;
    }

    //TODO: TEST

    ProtoAttributeDelta operator+(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b)
    {
        if (a.tail != b.head)
        {
            //ERROR
            //TODO: assert
        }
        return ProtoAttributeDelta(a.head, b.tail, a.height + b.height);
    }
    ProtoAttributeDelta operator-(const ProtoAttributeDelta &a, const ProtoAttributeDelta &b)
    {
        // if (tail != b.head)
        // {
        //     //ERROR
        //     //TODO: assert
        // }

        if (a.head == b.head)
        {
            return ProtoAttributeDelta(b.tail, a.tail, a.height-b.height);
        }
        if (a.tail == b.tail)
        {
            return ProtoAttributeDelta(a.head, b.head, a.height-b.height);
        }
        //TODO: Assertion Error
    }

    // ProtoAttributeDelta& ProtoAttributeDelta::operator+=(const ProtoAttributeDelta& b){
    //     if (tail != b.head){
    //         //ERROR
    //         //TODO: assert
    //     }
    //     tail = b.tail;
    //     height = b.height;
    //     return *this;
    // }

    // ProtoAttributeDelta& ProtoAttributeDelta::operator-=(const ProtoAttributeDelta& b){
    //     if (tail != b.head){
    //         //ERROR
    //         //TODO: assert
    //     }
    //     tail = b.tail;
    //     height = b.height;
    //     return *this;

    //     if (head == b.head){

    //     }
    //     if (tail == b.tail){

    //     }
    //     //TODO: Assertion Error
    // }
} // namespace c2pool::shares::tracker

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