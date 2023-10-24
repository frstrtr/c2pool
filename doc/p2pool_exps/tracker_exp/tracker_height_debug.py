# import tracker
import tracker

def hash(int_hash):
    return hex(int_hash)

def num(hex_hash):
    return int(hex_hash, 16)

class PresudoShare:

    def __init__(self, item, _i):
        # print(item[1])
        self.hash = int(item[0], 16)
        self.previous_hash = int(item[1][:-1], 16)
        self.i = _i

    def __repr__(self):
        return '(hash = {0}, prev = {1})'.format(hash(self.hash), hash(self.previous_hash))

    def __str__(self):
        return '(hash = {0}, prev = {1})'.format(hash(self.hash), hash(self.previous_hash))

def write_ht(track):
    print('heads: {0}'.format(track.heads))
    print('tails: {0}\n'.format(track.tails))

track = tracker.Tracker(delta_type=tracker.get_attributedelta_type(dict(tracker.AttributeDelta.attrs,
                                                                        i = lambda share: share.i
                                                                        )))

f = open("added_shares_cut.txt", 'r')
for line in f:
    loaded_share = PresudoShare(line.split(' '), 100)
    track.add(loaded_share)

write_ht(track)


item = num("d44220af7fbb4269d7bdb5d82bc094c60bfb9092ef70dd249e33ea280cc45354")
possible_child = num('88a43ff1490f9dc626cb478b03a6ca6bf572cb6c346a508d9b7d4ff7883344d6')

is_child = track.is_child_of(item, possible_child)
print(is_child)

height, last = track.get_height_and_last(item)
child_height, child_last = track.get_height_and_last(possible_child)

print('item = {0}: height = {1}; last = {2}'.format(hash(item), height, hash(last)))
print('possible_child = {0}: child_height = {1}; child_last = {2}'.format(hash(possible_child), child_height, hash(child_last)))