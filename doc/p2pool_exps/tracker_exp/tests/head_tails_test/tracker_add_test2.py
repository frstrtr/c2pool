import tracker

class PresudoShare:
    
    def __init__(self, item):
        # print(item[1])
        self.hash = item[0]
        self.previous_hash = item[1]

def write_ht(track):
    print('heads: {0}'.format(track.heads))
    print('tails: {0}'.format(track.tails))

track = tracker.Tracker()
write_ht(track)

first = PresudoShare([1,0])
track.add(first)
write_ht(track)

second = PresudoShare([3,2])
track.add(second)
write_ht(track)

third = PresudoShare([2,1])
track.add(third)
write_ht(track)

new_end = PresudoShare([-2, 3])
track.add(new_end)
write_ht(track)

fork = PresudoShare([-4, 2])
track.add(fork)
write_ht(track)

#(0=None)->1->2->3->-2
#      |
#      |
#      ->-4

