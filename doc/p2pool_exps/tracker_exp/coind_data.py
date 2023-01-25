import pack
import hashlib
import math,  p2pool_math
import random


def target_to_average_attempts(target):
    assert 0 <= target and isinstance(target, (int, long)), target
    if target >= 2 ** 256: print('target >= 2**256!')
    return 2 ** 256 // (target + 1)


def average_attempts_to_target(average_attempts):
    assert average_attempts > 0
    return min(int(2 ** 256 / average_attempts - 1 + 0.5), 2 ** 256 - 1)


def target_to_difficulty(target):
    assert 0 <= target and isinstance(target, (int, long)), target
    if target >= 2 ** 256: print('target >= 2**256!')
    return (0xffff0000 * 2 ** (256 - 64) + 1) / (target + 1)


def difficulty_to_target(difficulty):
    assert difficulty >= 0
    if difficulty == 0: return 2 ** 256 - 1
    return min(int((0xffff0000 * 2 ** (256 - 64) + 1) / difficulty - 1 + 0.5), 2 ** 256 - 1)

def hash256(data):
    return pack.IntType(256).unpack(hashlib.sha256(hashlib.sha256(data).digest()).digest())

def hash160(data):
    if data == '04ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b'.decode('hex'):
        return 0x384f570ccc88ac2e7e00b026d1690a3fca63dd0 # hack for people who don't have openssl - this is the only value that p2pool ever hashes
    return pack.IntType(160).unpack(hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest())



def is_segwit_tx(tx):
    return tx.get('marker', -1) == 0 and tx.get('flag', -1) >= 1

tx_in_type = pack.ComposedType([
    ('previous_output', pack.PossiblyNoneType(dict(hash=0, index=2**32 - 1), pack.ComposedType([
        ('hash', pack.IntType(256)),
        ('index', pack.IntType(32)),
    ]))),
    ('script', pack.VarStrType()),
    ('sequence', pack.PossiblyNoneType(2**32 - 1, pack.IntType(32))),
])

tx_out_type = pack.ComposedType([
    ('value', pack.IntType(64)),
    ('script', pack.VarStrType()),
])

tx_id_type = pack.ComposedType([
    ('version', pack.IntType(32)),
    ('tx_ins', pack.ListType(tx_in_type)),
    ('tx_outs', pack.ListType(tx_out_type)),
    ('lock_time', pack.IntType(32))
])

class TransactionType(pack.Type):
    _int_type = pack.IntType(32)
    _varint_type = pack.VarIntType()
    _witness_type = pack.ListType(pack.VarStrType())
    _wtx_type = pack.ComposedType([
        ('flag', pack.IntType(8)),
        ('tx_ins', pack.ListType(tx_in_type)),
        ('tx_outs', pack.ListType(tx_out_type))
    ])
    _ntx_type = pack.ComposedType([
        ('tx_outs', pack.ListType(tx_out_type)),
        ('lock_time', _int_type)
    ])
    _write_type = pack.ComposedType([
        ('version', _int_type),
        ('marker', pack.IntType(8)),
        ('flag', pack.IntType(8)),
        ('tx_ins', pack.ListType(tx_in_type)),
        ('tx_outs', pack.ListType(tx_out_type))
    ])

    def read(self, file):
        version = self._int_type.read(file)
        marker = self._varint_type.read(file)
        if marker == 0:
            next = self._wtx_type.read(file)
            witness = [None]*len(next['tx_ins'])
            for i in xrange(len(next['tx_ins'])):
                witness[i] = self._witness_type.read(file)
            locktime = self._int_type.read(file)
            return dict(version=version, marker=marker, flag=next['flag'], tx_ins=next['tx_ins'], tx_outs=next['tx_outs'], witness=witness, lock_time=locktime)
        else:
            tx_ins = [None]*marker
            for i in xrange(marker):
                tx_ins[i] = tx_in_type.read(file)
            next = self._ntx_type.read(file)
            return dict(version=version, tx_ins=tx_ins, tx_outs=next['tx_outs'], lock_time=next['lock_time'])
    
    def write(self, file, item):
        if is_segwit_tx(item):
            assert len(item['tx_ins']) == len(item['witness'])
            self._write_type.write(file, item)
            for w in item['witness']:
                self._witness_type.write(file, w)
            self._int_type.write(file, item['lock_time'])
            return
        return tx_id_type.write(file, item)

tx_type = TransactionType()


block_header_type = pack.ComposedType([
    ('version', pack.IntType(32)),
    ('previous_block', pack.PossiblyNoneType(0, pack.IntType(256))),
    ('merkle_root', pack.IntType(256)),
    ('timestamp', pack.IntType(32)),
    ('bits', pack.FloatingIntegerType()),
    ('nonce', pack.IntType(32)),
])

block_type = pack.ComposedType([
    ('header', block_header_type),
    ('txs', pack.ListType(tx_type)),
])

stripped_block_type = pack.ComposedType([
    ('header', block_header_type),
    ('txs', pack.ListType(tx_id_type)),
])


# human addresses

class ChecksummedType(pack.Type):
    def __init__(self, inner, checksum_func=lambda data: hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]):
        self.inner = inner
        self.checksum_func = checksum_func
    
    def read(self, file):
        start = file.tell()
        obj = self.inner.read(file)
        end = file.tell()
        file.seek(start)
        data = file.read(end - start)
        
        calculated_checksum = self.checksum_func(data)
        checksum = file.read(len(calculated_checksum))
        if checksum != calculated_checksum:
            raise ValueError('invalid checksum')
        
        return obj
    
    def write(self, file, item):
        data = self.inner.pack(item)
        file.write(data)
        file.write(self.checksum_func(data))
        #return (file, data), self.checksum_func(data)

base58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(bindata):
    bindata2 = bindata.lstrip(chr(0))
    return base58_alphabet[0]*(len(bindata) - len(bindata2)) + p2pool_math.natural_to_string(p2pool_math.string_to_natural(bindata2), base58_alphabet)

def base58_decode(b58data):
    b58data2 = b58data.lstrip(base58_alphabet[0])
    return chr(0)*(len(b58data) - len(b58data2)) + p2pool_math.natural_to_string(p2pool_math.string_to_natural(b58data2, base58_alphabet))

human_address_type = ChecksummedType(pack.ComposedType([
    ('version', pack.IntType(8)),
    ('pubkey_hash', pack.IntType(160)),
]))

def pubkey_hash_to_address(pubkey_hash, net):
    return base58_encode(human_address_type.pack(dict(version=net.ADDRESS_VERSION, pubkey_hash=pubkey_hash)))

def pubkey_to_address(pubkey, net):
    return pubkey_hash_to_address(hash160(pubkey), net)

def address_to_pubkey_hash(address, net):
    x = human_address_type.unpack(base58_decode(address))
    if x['version'] != net.ADDRESS_VERSION:
        raise ValueError('address not for this net!')
    return x['pubkey_hash']


# merkle trees

merkle_record_type = pack.ComposedType([
    ('left', pack.IntType(256)),
    ('right', pack.IntType(256)),
])

def merkle_hash(hashes):
    if not hashes:
        return 0
    hash_list = list(hashes)
    while len(hash_list) > 1:
        hash_list = [hash256(merkle_record_type.pack(dict(left=left, right=right)))
            for left, right in zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])]
    return hash_list[0]

def calculate_merkle_link(hashes, index):
    hash_list = [(lambda _h=h: _h, i == index, []) for i, h in enumerate(hashes)]
    
    while len(hash_list) > 1:
        hash_list = [
            (
                lambda _left=left, _right=right: hash256(merkle_record_type.pack(dict(left=_left(), right=_right()))),
                left_f or right_f,
                (left_l if left_f else right_l) + [dict(side=1, hash=right) if left_f else dict(side=0, hash=left)],
            )
            for (left, left_f, left_l), (right, right_f, right_l) in
                zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])
        ]
    
    res = [x['hash']() for x in hash_list[0][2]]
    
    assert hash_list[0][1]
    if False:
        new_hashes = [random.randrange(2**256) if x is None else x
            for x in hashes]
        assert check_merkle_link(new_hashes[index], dict(branch=res, index=index)) == merkle_hash(new_hashes)
    assert index == sum(k*2**i for i, k in enumerate([1-x['side'] for x in hash_list[0][2]]))
    
    return dict(branch=res, index=index)

# def calculate_merkle_link(hashes, index):
#     # XXX optimize this

#     def hash_check(h):
#         try:
#             return hex(h()) if h() is None else None
#         except:
#             return None

    
#     hash_list = [(lambda _h=h: _h, i == index, []) for i, h in enumerate(hashes)]
#     i = 0
#     while len(hash_list) > 1:
#         hash_list = [
#             (
#                 lambda _left=left, _right=right: hash256(merkle_record_type.pack(dict(left=_left(), right=_right()))),
#                 left_f or right_f,
#                 (left_l if left_f else right_l) + [dict(side=1, hash=right) if left_f else dict(side=0, hash=left)],
#             )
#             for (left, left_f, left_l), (right, right_f, right_l) in
#                 zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])
#         ]

#         print('{0}: {1}'.format(i, [(hash_check(v), f, [(hex(x['hash']()), x['side']) for x in l]) for (v, f, l) in hash_list]))
#         i += 1
    
    


#     res = [hex(x['hash']()) for x in hash_list[0][2]]


#     # hash_list = [(h, i == index, []) for i, h in enumerate(hashes)]
#     # i = 0
#     # while len(hash_list) > 1:
#     #     hash_list = [
#     #         (
#     #             hash256(merkle_record_type.pack(dict(left=left, right=right))),
#     #             left_f or right_f,
#     #             (left_l if left_f else right_l) + [dict(side=1, hash=right) if left_f else dict(side=0, hash=left)],
#     #         )
#     #         for (left, left_f, left_l), (right, right_f, right_l) in
#     #             zip(hash_list[::2], hash_list[1::2] + [hash_list[::2][-1]])
#     #     ]

#     #     print('{0}: {1}'.format(i, hash_list))
#     #     i += 1

#     # res = [x['hash'] for x in hash_list[0][2]]
    
#     assert hash_list[0][1]
#     # if p2pool.DEBUG:
#     #     new_hashes = [random.randrange(2**256) if x is None else x
#     #         for x in hashes]
#     #     assert check_merkle_link(new_hashes[index], dict(branch=res, index=index)) == merkle_hash(new_hashes)
#     assert index == sum(k*2**i for i, k in enumerate([1-x['side'] for x in hash_list[0][2]]))
    
#     return dict(branch=res, index=index)

def check_merkle_link(tip_hash, link):
    if link['index'] >= 2**len(link['branch']):
        raise ValueError('index too large')
    return reduce(lambda c, (i, h): hash256(merkle_record_type.pack(
        dict(left=h, right=c) if (link['index'] >> i) & 1 else
        dict(left=c, right=h)
    )), enumerate(link['branch']), tip_hash)


# transactions

def get_witness_commitment_hash(witness_root_hash, witness_reserved_value):
    return hash256(merkle_record_type.pack(dict(left=witness_root_hash, right=witness_reserved_value)))

def get_wtxid(tx, txid=None, txhash=None):
    has_witness = False
    if is_segwit_tx(tx):
        assert len(tx['tx_ins']) == len(tx['witness'])
        has_witness = any(len(w) > 0 for w in tx['witness'])
    if has_witness:
        return hash256(tx_type.pack(tx)) if txhash is None else txhash
    else:
        return hash256(tx_id_type.pack(tx)) if txid is None else txid

def get_txid(tx):
    return hash256(tx_id_type.pack(tx))

def pubkey_to_script2(pubkey):
    assert len(pubkey) <= 75
    return (chr(len(pubkey)) + pubkey) + '\xac'

def pubkey_hash_to_script2(pubkey_hash):
    return '\x76\xa9' + ('\x14' + pack.IntType(160).pack(pubkey_hash)) + '\x88\xac'