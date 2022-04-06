from functools import reduce

hashes = [None] + [i for i in range(1, 5)]
index = 0

hash_list = [(lambda _h=h: _h, i == index, []) for i, h in enumerate(hashes)]

print(hashes)
print("zip = {0}".format(zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])))

while len(hash_list) > 1:
    hash_list = [
        (
            lambda _left=left, _right=right: _left() + _right(),
            left_f or right_f,
            (left_l if left_f else right_l) + [dict(side=1, hash=right) if left_f else dict(side=0, hash=left)],
        )
        for (left, left_f, left_l), (right, right_f, right_l) in
        zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])
    ]

def _sum(a):
    return a['left']+a['right']

def check_merkle_link(tip_hash, link):
    if link['index'] >= 2**len(link['branch']):
        raise ValueError('index too large')
    return reduce(lambda c, e: _sum(
        dict(left=e[1], right=c) if (link['index'] >> e[0]) & 1 else
        dict(left=c, right=e[1])
    ), enumerate(link['branch']), tip_hash)

print(hash_list)

res = [x['hash']() for x in hash_list[0][2]]
print(res)

check = check_merkle_link(2,dict(branch=res, index=index))
print(check)
