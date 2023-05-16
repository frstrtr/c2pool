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

testNoneTail = PresudoShare([678, None], 1000)
track.add(testNoneTail)

testNoneTail2 = PresudoShare([679, 678], 1000)
track.add(testNoneTail2)
write_ht(track)

track.add(PresudoShare([19, 18], 190))
track.add(PresudoShare([20, 19], 100))
track.add(PresudoShare([21, 20], 200))
                                                            # (0  -> 190 -> 290 -> 490]
#(0=None)->2->33->44    | (9=None)->10 | (None)->678->679   | (18=None)->19->20->21
#          |            |              |                    |
#          |            |              |                    |
#          ->3->4       |              |                    |

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
assert(t44.i == 400)
#4.5.1
t451 = track.get_delta(678, None)
print('t4.5.1 = {0}'.format(t451))
#4.5.2
t452 = track.get_delta(679, None)
print('t4.5.2 = {0}'.format(t452))
#4.5.3
t453 = track.get_delta(679, 678)
print('t4.5.3 = {0}'.format(t453))
#4.6
t46 = track.get_delta(10, 9)
print('t4.6 = {0}'.format(t46))

#5.1
t51 = track.get_delta_to_last(10)
print(t51)
#5.2
t52 = track.get_delta_to_last(44)
print(t52)
#5.3
t53 = track.get_delta_to_last(678)
print('t5.3 = {0}'.format(t53))

#6
t6 = track.get_height_and_last(678)
print(t6)

#Get nth parent
print('\nGet nth parent:')
print(track.get_nth_parent_hash(0,0))
try:
    print(track.get_nth_parent_hash(33,5))
except KeyError:
    print('(33,5) -- exception')

#is child of:
print('\nIs child of:')
print(track.is_child_of(0, 0))
print(track.is_child_of(-23, -23))
print(track.is_child_of(2, -1))
print(track.is_child_of(-1, 2))
print(track.is_child_of(0, 2))
print(track.is_child_of(2, 0))
print(track.is_child_of(44, 0))
print(track.is_child_of(44, 2))

#get_chain
# for i in track.get_chain(44, 4):
#     print(i)

for i in track.get_chain(44, 0):
    print(i)

print('\nGet sum')
print(track.get_delta(21, 20))
print(track.get_delta(21, 19))