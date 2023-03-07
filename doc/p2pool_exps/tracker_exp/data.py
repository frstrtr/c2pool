import time

# from p2pool.bitcoin import data as bitcoin_data, script, sha256
import math, pack #, forest
import sha256, hashlib
import share as p2pool_share

# hashlink

hash_link_type = pack.ComposedType([
    ('state', pack.FixedStrType(32)),
    ('extra_data', pack.FixedStrType(0)), # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    ('length', pack.VarIntType()),
])

def prefix_to_hash_link(prefix, const_ending=''):
    assert prefix.endswith(const_ending), (prefix, const_ending)
    x = sha256.sha256(prefix)
    return dict(state=x.state, extra_data=x.buf[:max(0, len(x.buf)-len(const_ending))], length=x.length//8)

def check_hash_link(hash_link, data, const_ending=''):
    extra_length = hash_link['length'] % (512//8)
    assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
    extra = (hash_link['extra_data'] + const_ending)[len(hash_link['extra_data']) + len(const_ending) - extra_length:]
    assert len(extra) == extra_length
    return pack.IntType(256).unpack(hashlib.sha256(sha256.sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest())

share_type = pack.ComposedType([
    ('type', pack.VarIntType()),
    ('contents', pack.VarStrType()),
])

def load_share(share, net, peer_addr):
    assert peer_addr is None or isinstance(peer_addr, tuple)
    if share['type'] in p2pool_share.share_versions:
        return p2pool_share.share_versions[share['type']](net, peer_addr, p2pool_share.share_versions[share['type']].get_dynamic_types(net)['share_type'].unpack(share['contents']))

    elif share['type'] < p2pool_share.Share.VERSION:
        print('sent an obsolete share')
    else:
        raise ValueError('unknown share type: %r' % (share['type'],))


class ShareStore(object):
    def __init__(self, net, path_shares, share_cb, verified_hash_cb):
        start = time.time()

        load_tracker = False # false -- empty tracker

        known = {}
        if load_tracker:
            filenames = [path_shares]
        else:
            filenames = []
        for filename in filenames:
            share_hashes, verified_hashes = known.setdefault(filename, (set(), set()))
            with open(filename, 'rb') as f:
                i = 0
                for line in f:
                    # if i >= 3457:
                    if i >= 17508:
                        break
                    i += 1
                    # try:
                    type_id_str, data_hex = line.strip().split(' ')
                    type_id = int(type_id_str)
                    if type_id == 0:
                        pass
                    elif type_id == 1:
                        pass
                    elif type_id == 2:
                        verified_hash = int(data_hex, 16)
                        verified_hash_cb(verified_hash)
                        verified_hashes.add(verified_hash)
                        # print(data_hex)
                    elif type_id == 5:
                        raw_share = share_type.unpack(data_hex.decode('hex'))
                        if raw_share['type'] < p2pool_share.Share.VERSION:
                            continue
                        share = load_share(raw_share, net, None)
                        # print(share)
                        share_cb(share)
                        share_hashes.add(share.hash)
                        # print('share_hash: {0}'.format(hex(share.hash)))
                    else:
                        raise NotImplementedError("share type %i" % (type_id,))
                    # except Exception:
                    #     print("HARMLESS error while reading saved shares, continuing where left off:")
        
        self.known = known # filename -> (set of share hashes, set of verified hashes)
        self.known_desired = dict((k, (set(a), set(b))) for k, (a, b) in known.iteritems())

        print("Share loading took %.3f seconds" % (time.time() - start))