heads = {} # head hash -> tail_hash
tails = {} # tail hash -> set of head hashes

class Delta:
    def __init__(self, item):
        self.head = item[0]
        self.tail = item[1]

def add(item):
    delta = Delta(item)

    #1
    if delta.head in tails:
        _heads = tails.pop(delta.head)
    else:
        _heads = set([delta.head])

    #2
    if delta.tail in heads:
       tail = heads.pop(delta.tail)
    elif delta.head is 3:
       tail = 0
    else:
        tail = delta.tail#self.get_last(delta.tail)

    #3
    tails.setdefault(tail, set()).update(_heads)
    #4
    if delta.tail in tails[tail]:
        tails[tail].remove(delta.tail)

    #5
    for head in _heads:
        heads[head] = tail

add([1,0])
print('heads: {0}'.format(heads))
print('tails: {0}'.format(tails))

add([3,2])
print('heads: {0}'.format(heads))
print('tails: {0}'.format(tails))

add([2,1])
print('heads: {0}'.format(heads))
print('tails: {0}'.format(tails))