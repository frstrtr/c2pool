# import tracker
import tracker

class PresudoShare:
    
    def __init__(self, item, _i):
        # print(item[1])
        self.hash = item[0]
        self.previous_hash = item[1]
        self.i = _i

    def __repr__(self):
        return '(hash = {0}, prev = {1})'.format(self.hash, self.previous_hash)

    def __str__(self):
        return '(hash = {0}, prev = {1})'.format(self.hash, self.previous_hash)

def write_ht(track):
    print('heads: {0}'.format(track.heads))
    print('tails: {0}\n'.format(track.tails))

track = tracker.Tracker(delta_type=tracker.get_attributedelta_type(dict(tracker.AttributeDelta.attrs,
            i = lambda share: share.i
        )))

first = PresudoShare([2, 0], 100)
track.add(first)

second = PresudoShare([3, 2], 200)
track.add(second)

second2 = PresudoShare([33, 2], 233)
track.add(second2)

second22 = PresudoShare([44, 33], 67)
track.add(second22)

first2 = PresudoShare([10, 9], 900)
track.add(first2)

third = PresudoShare([4, 3], 300)
track.add(third)
write_ht(track)

#(0=None)->2->33->44    |    (9->10)
#          |            |
#          |            |
#          ->3->4       |

#1
print(track.is_child_of(2,2))
assert(track.is_child_of(2,2) == True)
#2
print(track.get_nth_parent_hash(2,0))
assert(track.get_nth_parent_hash(2,0) == 2)
#3.1
t31 = [x for x in track.get_chain(2, 0)]
print(t31)
assert(t31 == [])
#3.2
t32 = [x for x in track.get_chain(33, 0)]
print(t32)
assert(t32 == [])
#3.3
t33 = [x.hash for x in track.get_chain(33, 2)]
print(t33)
assert(t33 == [33, 2])
#4.1
t41 = track.get_delta(2, 2)
print(t41)
assert(t41.head == 0)
assert(t41.tail == 0)
assert(t41.height == 0)
#4.2
t42 = track.get_delta(10, 10)
print(t42)
assert(t42.head == 9)
assert(t42.tail == 9)
assert(t42.height == 0)
#4.3
t43 = track.get_delta(44, 2)
print(t43)
assert(t43.head == 44)
assert(t43.tail == 2)
assert(t43.height == 2)
assert(t43.i == 300)
#4.4
t44 = track.get_delta(44, 0)
print(t44)
assert(t44.head == 44)
assert(t44.tail == 0)
assert(t44.height == 3)

