#python2!!!
import hashlib

# tip_hash = bitcoin_data.hash256 = int256
#link = ref_merkle_link
def check_merkle_link(tip_hash, link):
    if link['index'] >= 2**len(link['branch']):
        raise ValueError('index too large')
    return reduce(lambda c, (i, h): hash256(merkle_record_type.pack(
        dict(left=h, right=c) if (link['index'] >> i) & 1 else
        dict(left=c, right=h)
    )), enumerate(link['branch']), tip_hash)
#=========================================================================

def hash256(obj):
    return hashlib.sha256(bytes(obj)).digest()

def test_link(link, tip_hash):

    return reduce(lambda c, (i, h): 
        dict(left=h, right=c) if (link['index'] >> i) & 1 else
        dict(left=c, right=h)
    , enumerate(link['branch']), tip_hash)

def test_link2(link, tip_hash):
    cur = tip_hash
    for i, h in enumerate(link['branch']):
        if (link['index'] >> i) & 1:
            cur = dict(left=h, right=cur)
        else:
            cur = dict(left=cur, right=h)
    return cur

_link = {
    "branch" : [10,20,30,40,50,60],
    "index" : 0
}

print(test_link(_link, 1000))
print(test_link2(_link, 1000))