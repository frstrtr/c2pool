import binascii
import struct
import hashlib

def shift_left(n, m):
    # python: :(
    if m >= 0:
        return n << m
    return n >> -m

class EarlyEnd(Exception):
    pass

class LateEnd(Exception):
    pass

def read((data, pos), length):
    data2 = data[pos:pos + length]
    if len(data2) != length:
        raise EarlyEnd()
    return data2, (data, pos + length)

def size((data, pos)):
    return len(data) - pos

class Type(object):
    __slots__ = []

    def __hash__(self):
        rval = getattr(self, '_hash', None)
        if rval is None:
            try:
                rval = self._hash = hash((type(self), frozenset(self.__dict__.items())))
            except:
                print self.__dict__
                raise
        return rval

    def __eq__(self, other):
        return type(other) is type(self) and other.__dict__ == self.__dict__

    def __ne__(self, other):
        return not (self == other)

    def _unpack(self, data, ignore_trailing=False):
        obj, (data2, pos) = self.read((data, 0))

        assert data2 is data

        if pos != len(data) and not ignore_trailing:
            raise LateEnd()

        return obj

    def _pack(self, obj):
        f = self.write(None, obj)

        res = []
        while f is not None:
            res.append(f[1])
            f = f[0]
        res.reverse()
        return ''.join(res)


    def unpack(self, data, ignore_trailing=False):
        obj = self._unpack(data, ignore_trailing)

        return obj

    def pack(self, obj):
        # No check since obj can have more keys than our type
        return self._pack(obj)

    def packed_size(self, obj):
        if hasattr(obj, '_packed_size') and obj._packed_size is not None:
            type_obj, packed_size = obj._packed_size
            if type_obj is self:
                return packed_size

        packed_size = len(self.pack(obj))

        if hasattr(obj, '_packed_size'):
            obj._packed_size = self, packed_size

        return packed_size

class VarIntType(Type):
    def read(self, file):
        data, file = read(file, 1)
        first = ord(data)
        if first < 0xfd:
            return first, file
        if first == 0xfd:
            desc, length, minimum = '<H', 2, 0xfd
        elif first == 0xfe:
            desc, length, minimum = '<I', 4, 2**16
        elif first == 0xff:
            desc, length, minimum = '<Q', 8, 2**32
        else:
            raise AssertionError()
        data2, file = read(file, length)
        res, = struct.unpack(desc, data2)
        if res < minimum:
            raise AssertionError('VarInt not canonically packed')
        return res, file

    def write(self, file, item):
        if item < 0xfd:
            return file, struct.pack('<B', item)
        elif item <= 0xffff:
            return file, struct.pack('<BH', 0xfd, item)
        elif item <= 0xffffffff:
            return file, struct.pack('<BI', 0xfe, item)
        elif item <= 0xffffffffffffffff:
            return file, struct.pack('<BQ', 0xff, item)
        else:
            raise ValueError('int too large for varint')

class VarStrType(Type):
    _inner_size = VarIntType()

    def read(self, file):
        length, file = self._inner_size.read(file)
        return read(file, length)

    def write(self, file, item):
        return self._inner_size.write(file, len(item)), item

class EnumType(Type):
    def __init__(self, inner, pack_to_unpack):
        self.inner = inner
        self.pack_to_unpack = pack_to_unpack

        self.unpack_to_pack = {}
        for k, v in pack_to_unpack.iteritems():
            if v in self.unpack_to_pack:
                raise ValueError('duplicate value in pack_to_unpack')
            self.unpack_to_pack[v] = k

    def read(self, file):
        data, file = self.inner.read(file)
        if data not in self.pack_to_unpack:
            raise ValueError('enum data (%r) not in pack_to_unpack (%r)' % (data, self.pack_to_unpack))
        return self.pack_to_unpack[data], file

    def write(self, file, item):
        if item not in self.unpack_to_pack:
            raise ValueError('enum item (%r) not in unpack_to_pack (%r)' % (item, self.unpack_to_pack))
        return self.inner.write(file, self.unpack_to_pack[item])

class ListType(Type):
    _inner_size = VarIntType()

    def __init__(self, type, mul=1):
        self.type = type
        self.mul = mul

    def read(self, file):
        length, file = self._inner_size.read(file)
        length *= self.mul
        res = [None]*length
        for i in xrange(length):
            res[i], file = self.type.read(file)
        return res, file

    def write(self, file, item):
        assert len(item) % self.mul == 0
        file = self._inner_size.write(file, len(item)//self.mul)
        for subitem in item:
            file = self.type.write(file, subitem)
        return file

class StructType(Type):
    __slots__ = 'desc length'.split(' ')

    def __init__(self, desc):
        self.desc = desc
        self.length = struct.calcsize(self.desc)

    def read(self, file):
        data, file = read(file, self.length)
        return struct.unpack(self.desc, data)[0], file

    def write(self, file, item):
        return file, struct.pack(self.desc, item)

class IntType(Type):
    __slots__ = 'bytes step format_str max'.split(' ')

    def __new__(cls, bits, endianness='little'):
        assert bits % 8 == 0
        assert endianness in ['little', 'big']
        if bits in [8, 16, 32, 64]:
            return StructType(('<' if endianness == 'little' else '>') + {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}[bits])
        else:
            return Type.__new__(cls, bits, endianness)

    def __init__(self, bits, endianness='little'):
        assert bits % 8 == 0
        assert endianness in ['little', 'big']
        self.bytes = bits//8
        self.step = -1 if endianness == 'little' else 1
        self.format_str = '%%0%ix' % (2*self.bytes)
        self.max = 2**bits

    def read(self, file, b2a_hex=binascii.b2a_hex):
        if self.bytes == 0:
            return 0, file
        data, file = read(file, self.bytes)
        return int(b2a_hex(data[::self.step]), 16), file

    def write(self, file, item, a2b_hex=binascii.a2b_hex):
        if self.bytes == 0:
            return file
        if not 0 <= item < self.max:
            raise ValueError('invalid int value - %r' % (item,))
        return file, a2b_hex(self.format_str % (item,))[::self.step]

class IPV6AddressType(Type):
    def read(self, file):
        data, file = read(file, 16)
        if data[:12] == '00000000000000000000ffff'.decode('hex'):
            return '.'.join(str(ord(x)) for x in data[12:]), file
        return ':'.join(data[i*2:(i+1)*2].encode('hex') for i in xrange(8)), file

    def write(self, file, item):
        if ':' in item:
            data = ''.join(item.replace(':', '')).decode('hex')
        else:
            bits = map(int, item.split('.'))
            if len(bits) != 4:
                raise ValueError('invalid address: %r' % (bits,))
            data = '00000000000000000000ffff'.decode('hex') + ''.join(chr(x) for x in bits)
        assert len(data) == 16, len(data)
        return file, data

_record_types = {}

def get_record(fields):
    fields = tuple(sorted(fields))
    if 'keys' in fields or '_packed_size' in fields:
        raise ValueError()
    if fields not in _record_types:
        class _Record(object):
            __slots__ = fields + ('_packed_size',)
            def __init__(self):
                self._packed_size = None
            def __repr__(self):
                return repr(dict(self))
            def __getitem__(self, key):
                return getattr(self, key)
            def __setitem__(self, key, value):
                setattr(self, key, value)
            #def __iter__(self):
            #    for field in fields:
            #        yield field, getattr(self, field)
            def keys(self):
                return fields
            def get(self, key, default=None):
                return getattr(self, key, default)
            def __eq__(self, other):
                if isinstance(other, dict):
                    return dict(self) == other
                elif isinstance(other, _Record):
                    for k in fields:
                        if getattr(self, k) != getattr(other, k):
                            return False
                    return True
                elif other is None:
                    return False
                raise TypeError()
            def __ne__(self, other):
                return not (self == other)
        _record_types[fields] = _Record
    return _record_types[fields]

class ComposedType(Type):
    def __init__(self, fields):
        self.fields = list(fields)
        self.field_names = set(k for k, v in fields)
        self.record_type = get_record(k for k, v in self.fields)

    def read(self, file):
        item = self.record_type()
        for key, type_ in self.fields:
            item[key], file = type_.read(file)
        return item, file

    def write(self, file, item):
        assert set(item.keys()) >= self.field_names
        for key, type_ in self.fields:
            file = type_.write(file, item[key])
        return file

class PossiblyNoneType(Type):
    def __init__(self, none_value, inner):
        self.none_value = none_value
        self.inner = inner

    def read(self, file):
        value, file = self.inner.read(file)
        return None if value == self.none_value else value, file

    def write(self, file, item):
        if item == self.none_value:
            raise ValueError('none_value used')
        return self.inner.write(file, self.none_value if item is None else item)

class FixedStrType(Type):
    def __init__(self, length):
        self.length = length

    def read(self, file):
        return read(file, self.length)

    def write(self, file, item):
        if len(item) != self.length:
            raise ValueError('incorrect length item!')
        return file, item

address_type = ComposedType([
    ('services', IntType(64)),
    ('address', IPV6AddressType()),
    ('port', IntType(16, 'big')),
])

message_version = ComposedType([
    ('version', IntType(32)),
    ('services', IntType(64)),
    ('addr_to', address_type),
    ('addr_from', address_type),
    ('nonce', IntType(64)),
    ('sub_version', VarStrType()),
    ('mode', IntType(32)), # always 1 for legacy compatibility
    ('best_share_hash', PossiblyNoneType(0, IntType(256))),
])

tx_type = ComposedType([
    ('version', IntType(32)),
    ('tx_ins', ListType(ComposedType([
        ('previous_output', PossiblyNoneType(dict(hash=0, index=2**32 - 1), ComposedType([
            ('hash', IntType(256)),
            ('index', IntType(32)),
        ]))),
        ('script', VarStrType()),
        ('sequence', PossiblyNoneType(2**32 - 1, IntType(32))),
    ]))),
    ('tx_outs', ListType(ComposedType([
        ('value', IntType(64)),
        ('script', VarStrType()),
    ]))),
    ('lock_time', IntType(32)),
])

def hash256(data):
    return IntType(256).unpack(hashlib.sha256(hashlib.sha256(data).digest()).digest())

def pubkey_hash_to_script2(pubkey_hash):
    return '\x76\xa9' + ('\x14' + IntType(160).pack(pubkey_hash)) + '\x88\xac'

"""
addrs1 = dict(services=3, address="192.168.10.10", port=8)
addrs2 = dict(services=9, address="192.168.10.11", port=9999)
best_share_hash = int("06abb7263fc73665f1f5b129959d90419fea5b1fdbea6216e8847bcc286c14e9", 16)
# addr = address_type.pack(dict(services=1, address="192.168.10.10", port=1))
msg = message_version.pack(dict(version=3301, services=0, addr_to=addrs1, addr_from=addrs2, nonce=254, sub_version="c2pool-test", mode=1, best_share_hash=best_share_hash))
print(msg)
res = []
res_str = ""
for c in msg:
    res += [ord(c)]
    res_str += str(ord(c)) + " "
# print(res)
print(res_str)

hash = hashlib.sha256

checksum = hash(hash(msg).digest()).digest()
hex_checksum = hash(hash(msg).digest()).hexdigest();
print(hex_checksum)

print("checksum:")
res_str = ""
for c in checksum:
    res += [ord(c)]
    res_str += str(ord(c)) + " "
print(res_str)
# print(checksum)
print (checksum[:4])
# print(msg)
"""


#c2pool
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 8 0 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 14 0 21 205 91 7 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6
#p2pool
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 0 14 21 205 91 7 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6


#========
#Without big endian
#c2pool
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 8 0 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 15 39 254 0 0 0 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6
#p2pool
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 8 0 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 15 39 254 0 0 0 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6

#========
#After fix:
#c2pool:
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 39 15 254 0 0 0 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6
#p2pool:
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 39 15 254 0 0 0 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6

#=======
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 39 15 254 0 0 0 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6
#229 12 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 10 0 8 9 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 192 168 10 11 39 15 254 0 0 0 0 0 0 0 11 99 50 112 111 111 108 45 116 101 115 116 1 0 0 0 233 20 108 40 204 123 132 232 22 98 234 219 31 91 234 159 65 144 157 149 41 177 245 241 101 54 199 63 38 183 171 6

#=======
#checksum
#c2pool
#202 129 170 188 195 123 105 117 227 142 244 158 47 69 25 8 112 64 14 54 56 211 106 63 207 27 165 41 65 70 138 248
#p2pool [True]
#21 102 66 235 221 222 11 88 186 181 186 213 103 112 141 227 218 158 162 171 230 24 239 175 202 203 234 35 156 35 113 14

#====================
#
# tx = tx_type.pack(dict(
#     version=1,
#     tx_ins=[dict(
#         previous_output=None,
#         sequence=None,
#         script='70736a0468860e1a0452389500522cfabe6d6d2b2f33cf8f6291b184f1b291d24d82229463fcec239afea0ee34b4bfc622f62401000000000000004d696e656420627920425443204775696c6420ac1eeeed88'.decode('hex'),
#     )],
#     tx_outs=[dict(
#         value=5003880250,
#         script=pubkey_hash_to_script2(IntType(160).unpack('ca975b00a8c203b8692f5a18d92dc5c2d2ebc57b'.decode('hex'))),
#     )],
#     lock_time=0,
# ))
#
# l_tx = []
# for i in tx:
#     l_tx += [ord(i)]
#
# print(str(l_tx).replace(',', ''))
#
# #===========================================================
# tx_type2 = ComposedType([
#     ('version', IntType(32)),
#     ('tx_ins', ListType(ComposedType([
#         ('previous_output', PossiblyNoneType(dict(hash=0, index=2**32 - 1), ComposedType([
#             ('hash', IntType(256)),
#             ('index', IntType(32)),
#         ]))),
#         ('script', VarStrType()),
#         ('sequence', PossiblyNoneType(2**32 - 1, IntType(32))),
#     ])))
# ])
#
# tx2 = tx_type2.pack(dict(
#     version=1,
#     tx_ins=[dict(
#         previous_output=None,
#         sequence=None,
#         script='70736a0468860e1a0452389500522cfabe6d6d2b2f33cf8f6291b184f1b291d24d82229463fcec239afea0ee34b4bfc622f62401000000000000004d696e656420627920425443204775696c6420ac1eeeed88'.decode('hex'),
#     )]
# ))
#
# l_tx2 = []
# for i in tx2:
#     l_tx2 += [ord(i)]
#
# print(str(l_tx2).replace(',', ''))

#==================================

def is_segwit_tx(tx):
    return tx.get('marker', -1) == 0 and tx.get('flag', -1) >= 1

tx_in_type = ComposedType([
    ('previous_output', PossiblyNoneType(dict(hash=0, index=2**32 - 1), ComposedType([
        ('hash', IntType(256)),
        ('index', IntType(32)),
    ]))),
    ('script', VarStrType()),
    ('sequence', PossiblyNoneType(2**32 - 1, IntType(32))),
])

tx_out_type = ComposedType([
    ('value', IntType(64)),
    ('script', VarStrType()),
])

tx_id_type = ComposedType([
    ('version', IntType(32)),
    ('tx_ins', ListType(tx_in_type)),
    ('tx_outs', ListType(tx_out_type)),
    ('lock_time', IntType(32))
])

class TransactionType(Type):
    _int_type = IntType(32)
    _varint_type = VarIntType()
    _witness_type = ListType(VarStrType())
    _wtx_type = ComposedType([
        ('flag', IntType(8)),
        ('tx_ins', ListType(tx_in_type)),
        ('tx_outs', ListType(tx_out_type))
    ])
    _ntx_type = ComposedType([
        ('tx_outs', ListType(tx_out_type)),
        ('lock_time', _int_type)
    ])
    _write_type = ComposedType([
        ('version', _int_type),
        ('marker', IntType(8)),
        ('flag', IntType(8)),
        ('tx_ins', ListType(tx_in_type)),
        ('tx_outs', ListType(tx_out_type))
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

tx_type2 = TransactionType()

#=====================
# tx1 = dict(
#     version=1,
#     tx_ins=[dict(
#         previous_output=None,
#         sequence=None,
#         script='70736a0468860e1a0452389500522cfabe6d6d2b2f33cf8f6291b184f1b291d24d82229463fcec239afea0ee34b4bfc622f62401000000000000004d696e656420627920425443204775696c6420ac1eeeed88'.decode('hex'),
#     )],
#     tx_outs=[dict(
#         value=5003880250,
#         script=pubkey_hash_to_script2(IntType(160).unpack('ca975b00a8c203b8692f5a18d92dc5c2d2ebc57b'.decode('hex'))),
#     )],
#     lock_time=0,
# )
#
# a = tx_type.pack(tx1)
#
# l_tx2 = []
# for i in a:
#     l_tx2 += [ord(i)]
#
# print(str(l_tx2).replace(',', ''))
#
# b = 'asdb3'
# b2 = (hash256(b)+1)
# print('hash: {0}, hex: {1}'.format(hash256(b), hex(hash256(b))))
# print('hash: {0}, hex: {1}'.format(b2, hex(b2)))


################################################################################
# gentx = dict(
#     version=4294967295,
#     tx_ins=[dict(
#         previous_output=None,
#         sequence=None,
#         script='015d5d52ad85411c47a5a8c71b8de0a39835891c26539eb2170eee693f08681a0302042800000003205b41960f08035d9b1ced05be46f7f8621053f1d362341dee2b9ada51abb3cf47',
#     )],
#     tx_outs=([dict(value=0, script='\x6a\x24\xaa\x21\xa9\xed' + IntType(256).pack(1234567))]),
#     lock_time=0,
# )
#
# gentx['marker'] = 3
# gentx['flag'] = 2
# gentx['witness'] = [["c2pool"*4]]
#
# def postprocess(data):
#     return [ord(x) for x in data]
#
# packed_gentx = tx_id_type.pack(gentx)
# print(postprocess(packed_gentx))
# print(postprocess(packed_gentx[:-32]))

class FloatingInteger(object):
    __slots__ = ['bits', '_target']

    # @classmethod
    # def from_target_upper_bound(cls, target):
    #     n = natural_to_string(target)
    #     if n and ord(n[0]) >= 128:
    #         n = '\x00' + n
    #     bits2 = (chr(len(n)) + (n + 3*chr(0))[:3])[::-1]
    #     bits = IntType(32).unpack(bits2)
    #     return cls(bits)

    def __init__(self, bits, target=None):
        self.bits = bits
        self._target = None
        if target is not None and self.target != target:
            raise ValueError('target does not match')

    @property
    def target(self):
        res = self._target
        if res is None:
            res = self._target = shift_left(self.bits & 0x00ffffff, 8 * ((self.bits >> 24) - 3))

            v = self.bits & 0x00ffffff
            # v << (8 * ((v >> 24) - 3))
            print('Test bits: {0}').format(self.bits)
            print('Test_target: {0}'.format(v))
            # value.value & );
            #
            # res << (8 * ((value.value >> 24) - 3));
        return res

    def __hash__(self):
        return hash(self.bits)

    def __eq__(self, other):
        return self.bits == other.bits

    def __ne__(self, other):
        return not (self == other)

    def __cmp__(self, other):
        assert False

    def __repr__(self):
        return 'FloatingInteger(bits=%s, target=%s)' % (hex(self.bits), hex(self.target))

class FloatingIntegerType(Type):
    _inner = IntType(32)

    def read(self, file):
        bits = self._inner.read(file)
        return FloatingInteger(bits)

    def write(self, file, item):
        return self._inner.write(file, item.bits)

block_header_type = ComposedType([
    ('version', IntType(32)),
    ('previous_block', PossiblyNoneType(0, IntType(256))),
    ('merkle_root', IntType(256)),
    ('timestamp', IntType(32)),
    ('bits', FloatingIntegerType()),
    ('nonce', IntType(32)),
])

share_type = ComposedType([
    ('type', VarIntType()),
    ('contents', VarStrType()),
])

# x = '01000000013ccaa9d380b87652929e5fe06c7c6ea08e16118c0a4749d0391fbe98ab6e549f00000000d74730440220197724619b7a57853c6ce6a04d933a83057629e4323ae301562b817904b321280220598f71b813045fcf500352e701b9b7cab75a5694eab374d6cdec13fd2efd8e4f0120949c9ff1f7fa8268128832fd123535ef3eae4d01c7c1aa3fa74ec38692878129004c6b630480feea62b1752102f70d90df545d767a53daa25e07875b4b588c476cba465a28dcafc4b6b792cf94ac6782012088a9142323cb36c535e5121c3409e371c1ae15011b5faf88210315d9c51c657ab1be4ae9d3ab6e76a619d3bccfe830d5363fa168424c0d044732ac68ffffffff01c40965f0020000001976a9141462c3dd3f936d595c9af55978003b27c250441f88ac80feea62'
# # print(IntType(32).unpack('01000000013c'))#3ccaa9d380b87652929e5fe06c7c6ea08e16118c0a4749d0391fbe98ab6e549f00000000d74730440220197724619b7a57853c6ce6a04d933a83057629e4323ae301562b817904b321280220598f71b813045fcf500352e701b9b7cab75a5694eab374d6cdec13fd2efd8e4f0120949c9ff1f7fa8268128832fd123535ef3eae4d01c7c1aa3fa74ec38692878129004c6b630480feea62b1752102f70d90df545d767a53daa25e07875b4b588c476cba465a28dcafc4b6b792cf94ac6782012088a9142323cb36c535e5121c3409e371c1ae15011b5faf88210315d9c51c657ab1be4ae9d3ab6e76a619d3bccfe830d5363fa168424c0d044732ac68ffffffff01c40965f0020000001976a9141462c3dd3f936d595c9af55978003b27c250441f88ac80feea62')
# # tx_type2.unpack(x)
# print('Version: {0}'.format(IntType(32).unpack(b'\x01\x00\x00\x00')))
# version_packed = IntType(32).pack(1)
# print("len: {0}".format(len(version_packed)))
# print('Version2: {0}'.format(IntType(32).unpack(version_packed)))
# num_packed = []
# for _d in version_packed:
#     num_packed += [ord(_d)]
# print(num_packed)
#
# start_tx_data = ComposedType([
#     ('version', IntType(32)),
#     ('marker', VarIntType())])
# #######################
#
#
# x = "0100000002".decode('hex')
# __x = []
# for c in x:
#     __x += [ord(c)]
# print(__x)
# print(start_tx_data.unpack(x))
#
# #################################
# second_tx_data = ComposedType([
#     ('version', IntType(32)),
#     ('marker', VarIntType()),
#     ('tx_in', tx_in_type)])
#
#
# x = '01000000013ccaa9d380b87652929e5fe06c7c6ea08e16118c0a4749d0391fbe98ab6e549f00000000d74730440220197724619b7a57853c6ce6a04d933a83057629e4323ae301562b817904b321280220598f71b813045fcf500352e701b9b7cab75a5694eab374d6cdec13fd2efd8e4f0120949c9ff1f7fa8268128832fd123535ef3eae4d01c7c1aa3fa74ec38692878129004c6b630480feea62b1752102f70d90df545d767a53daa25e07875b4b588c476cba465a28dcafc4b6b792cf94ac6782012088a9142323cb36c535e5121c3409e371c1ae15011b5faf88210315d9c51c657ab1be4ae9d3ab6e76a619d3bccfe830d5363fa168424c0d044732ac68ffffffff'.decode('hex')
# print(second_tx_data.unpack(x))

def arr_bytes_to_data(bytes):
    bytes = bytes.split(' ')
    res = b''
    for x in bytes:
        res += chr((int(x)))
    return res

# x = '11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6'
# x = '21fd4301fe020000206201af0a6930f520a4e89c2a024731e401b2d9cf976e4d0a82dcf9c206c1370b4ce02763d1f5001b03e0d41cfb866ba9fec6e8c456dd721b850a1b012b923dbbe9aa615a6de390230eebb5f53d04a9e9f0002cfabe6d6d4644c9e477f93b03c5c33cd6d61f16165c57f360325d75630d58dddac2ab635301000000000000000a5f5f6332706f6f6c5f5fd0ba3068bb351fc9fbbd8e1f40942130e77131978df6de41541d0d1e0a0000000000002100000000000000000000000000000000000000000000000000000000000000000000007c943b346fed7bc58a33254406d6a67c55c8b3759f8b87e11de3513cd5e67c12ee83021ee476151d4de02763d4aa0000502cdf03b40000000000000000000000000000000001000000e1a45914351179267e8d373f31778ba4792ef4227f68752459acff124bb965b7fd7a0100'
# raw_share = share_type.unpack(x.decode('hex'))

# x = arr_bytes_to_data('33 253 67 1 254 2 0 0 32 98 1 175 10 105 48 245 32 164 232 156 42 2 71 49 228 1 178 217 207 151 110 77 10 130 220 249 194 6 193 55 11 76 224 39 99 209 245 0 27 3 224 212 28 251 134 107 169 254 198 232 196 86 221 114 27 133 10 27 1 43 146 61 187 233 170 97 90 109 227 144 35 14 235 181 245 61 4 169 233 240 0 44 250 190 109 109 70 68 201 228 119 249 59 3 197 195 60 214 214 31 22 22 92 87 243 96 50 93 117 99 13 88 221 218 194 171 99 83 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 208 186 48 104 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 84 29 13 30 10 0 0 0 0 0 0 33 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 124 148 59 52 111 237 123 197 138 51 37 68 6 214 166 124 85 200 179 117 159 139 135 225 29 227 81 60 213 230 124 18 238 131 2 30 228 118 21 29 77 224 39 99 212 170 0 0 80 44 223 3 180 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 225 164 89 20 53 17 121 38 126 141 55 63 49 119 139 164 121 46 244 34 127 104 117 36 89 172 255 18 75 185 101 183 253 122 1 0')
# x = arr_bytes_to_data('33 253 173 2 254 2 0 0 32 57 204 82 243 225 65 44 227 224 220 253 60 83 206 15 139 98 237 236 221 130 180 172 59 69 180 131 220 250 75 113 209 53 26 40 99 143 210 0 27 51 90 178 111 54 38 234 253 206 232 59 177 172 87 183 87 167 247 60 233 25 208 105 9 100 179 97 249 113 113 204 50 203 44 171 152 61 4 116 237 240 0 44 250 190 109 109 221 91 216 243 54 14 232 155 132 161 127 15 211 4 70 165 98 8 136 217 52 45 93 73 209 37 85 39 237 108 190 245 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 52 118 35 201 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 50 136 16 30 10 0 0 0 0 0 254 33 3 29 48 193 135 246 126 77 65 164 224 105 246 72 65 56 101 197 208 147 222 85 42 134 208 155 216 20 128 193 196 218 81 105 184 124 196 90 109 235 240 131 35 146 22 93 230 99 152 58 94 109 173 198 195 192 215 137 251 104 84 125 30 43 47 2 16 190 166 210 169 150 152 180 44 214 42 113 194 118 155 207 40 169 225 118 236 62 231 243 230 177 183 119 133 167 147 87 239 188 53 130 84 2 16 5 80 236 27 161 156 218 63 1 178 95 252 85 135 172 201 15 75 205 210 153 142 26 68 5 184 12 127 69 45 109 132 98 144 202 101 183 92 175 33 170 124 254 8 103 43 194 15 131 217 181 90 62 232 127 237 108 43 88 183 92 30 179 74 238 68 145 43 234 248 18 152 166 152 28 210 115 54 196 7 245 48 247 26 30 200 164 7 144 225 145 73 100 86 1 166 43 234 249 68 43 118 85 123 143 164 135 103 187 141 175 34 211 210 106 140 146 43 139 189 173 211 169 46 186 105 61 236 177 19 69 85 106 73 21 169 31 90 12 7 41 96 211 185 125 162 117 176 154 120 21 166 57 242 52 109 36 2 126 99 234 147 105 48 115 183 10 194 151 20 243 182 237 142 223 109 70 219 113 31 185 159 36 158 3 5 0 0 0 1 0 2 0 3 0 4 216 18 219 138 225 249 8 166 139 247 7 33 83 202 49 159 36 122 134 214 253 138 159 34 24 211 18 84 79 113 185 125 194 156 7 30 104 245 64 29 59 26 40 99 155 172 0 0 21 101 7 120 181 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 9 85 126 125 158 83 174 178 39 133 10 85 211 35 16 165 124 100 116 79 24 162 210 195 98 232 62 204 149 5 16 46 253 122 1 3 184 12 127 69 45 109 132 98 144 202 101 183 92 175 33 170 124 254 8 103 43 194 15 131 217 181 90 62 232 127 237 108 105 184 124 196 90 109 235 240 131 35 146 22 93 230 99 152 58 94 109 173 198 195 192 215 137 251 104 84 125 30 43 47 2 16 190 166 210 169 150 152 180 44 214 42 113 194 118 155 207 40 169 225 118 236 62 231 243 230 177 183 119 133 167 147')
# x = arr_bytes_to_data('33 253 7 2 254 2 0 0 32 70 39 80 200 238 52 157 92 223 100 79 47 56 126 174 94 131 240 156 81 109 128 246 183 191 246 187 80 119 244 146 207 80 28 40 99 130 208 0 27 51 96 9 223 192 91 179 32 105 56 112 238 82 243 27 26 122 205 245 159 214 42 6 48 76 34 38 236 113 55 46 45 216 16 56 68 61 4 171 237 240 0 44 250 190 109 109 187 152 153 156 97 155 1 54 15 95 120 251 117 115 97 40 10 15 198 216 110 100 175 57 136 60 212 195 44 27 180 31 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 234 250 139 25 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 197 188 13 30 10 0 0 0 0 0 0 33 2 186 96 167 17 67 215 155 52 206 39 99 104 141 45 196 116 49 105 158 148 108 251 163 188 9 240 83 141 177 108 36 118 3 245 253 84 98 143 149 36 199 129 106 19 191 220 187 41 75 251 249 16 200 86 221 109 40 103 227 254 167 94 111 240 250 87 91 39 75 133 111 152 224 78 46 78 19 125 26 236 111 247 58 195 171 225 1 152 185 226 164 202 206 187 50 166 2 186 96 167 17 67 215 155 52 206 39 99 104 141 45 196 116 49 105 158 148 108 251 163 188 9 240 83 141 177 108 36 118 31 102 246 202 57 231 105 100 231 198 109 45 108 224 192 245 58 65 194 64 194 26 192 31 159 28 167 168 141 58 64 83 2 0 0 0 1 229 65 218 34 183 219 5 63 188 108 220 212 92 244 235 211 123 23 112 76 72 69 252 201 171 65 240 31 248 94 147 94 120 238 8 30 59 55 76 29 82 28 40 99 167 172 0 0 14 242 226 161 181 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 132 152 70 177 63 201 127 41 48 253 168 192 121 134 101 21 235 134 254 209 23 162 110 192 217 26 71 64 110 28 170 222 253 122 1 2 186 96 167 17 67 215 155 52 206 39 99 104 141 45 196 116 49 105 158 148 108 251 163 188 9 240 83 141 177 108 36 118 3 245 253 84 98 143 149 36 199 129 106 19 191 220 187 41 75 251 249 16 200 86 221 109 40 103 227 254 167 94 111 240')
x = arr_bytes_to_data('33 253 75 2 254 2 0 0 32 148 236 161 176 19 196 52 177 80 176 66 137 93 89 221 53 127 47 79 102 29 209 50 220 131 120 116 2 195 135 74 85 179 77 64 99 94 160 0 27 0 219 127 171 176 82 74 17 113 215 247 29 132 40 94 118 244 242 251 116 46 41 225 178 156 138 153 115 49 251 60 218 176 211 203 250 61 4 220 139 242 0 44 250 190 109 109 42 25 180 137 88 196 39 34 175 92 154 76 199 161 111 253 137 95 97 61 73 202 190 72 181 164 77 145 144 243 235 67 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 91 240 236 111 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 173 100 38 1 10 0 0 0 0 0 0 33 3 97 103 101 46 18 162 234 197 19 115 207 38 144 238 5 183 32 206 52 149 94 236 5 163 33 100 202 214 254 18 43 145 75 219 174 177 140 128 232 149 88 169 119 207 164 252 206 165 132 252 161 26 15 181 160 163 174 235 241 194 160 244 161 193 251 189 242 152 76 251 142 147 168 191 48 212 86 207 0 24 223 191 219 61 249 80 12 129 251 238 146 169 152 40 99 211 182 221 45 21 254 38 193 176 122 169 240 29 180 129 4 23 218 62 21 245 110 92 32 62 35 185 57 5 52 233 191 239 2 30 176 69 208 76 74 133 118 9 41 248 24 172 252 8 19 236 1 140 220 87 10 80 30 96 159 178 247 189 75 53 33 31 96 142 29 135 80 54 250 116 247 204 129 77 140 209 162 136 53 128 107 52 146 20 226 202 130 41 190 129 197 57 253 4 1 0 1 1 0 0 0 1 238 99 138 229 175 83 230 15 115 145 95 161 228 8 184 87 185 181 176 182 199 153 205 201 105 191 249 139 241 168 116 97 21 160 5 30 185 0 48 29 180 77 64 99 129 120 1 0 239 56 158 24 143 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 26 190 103 25 96 253 88 195 199 208 183 59 138 138 179 139 113 238 133 242 7 211 132 118 243 193 251 11 69 25 210 255 253 122 1 3 229 192 23 217 217 42 225 253 30 59 154 147 29 232 173 101 133 128 155 227 178 117 56 201 49 153 165 169 43 48 111 111 228 40 130 32 10 72 10 71 163 109 177 41 43 165 86 81 118 68 183 12 218 64 211 169 206 236 110 6 42 54 135 79 56 35 199 233 146 30 169 228 65 6 217 87 89 70 123 98 159 19 205 157 188 132 122 149 251 145 138 175 24 180 48 110')
raw_share = share_type.unpack(x)
print('encoded to hex = {0}.'.format(x.encode('hex')))

print(raw_share.type)

share_bytes = []
for _b in raw_share.contents:
    share_bytes += [ord(_b)]

print(''.join(str(share_bytes).split(',')))

# a = b''
# for _x in '254 2 0 0 32'.split(' '):
#     a += chr(int(_x))
#
# i = VarIntType().unpack('11'.decode('hex'))
# print(i)

# share info type

hash_link_type = ComposedType([
    ('state', FixedStrType(32)),
    ('extra_data', FixedStrType(0)), # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    ('length', VarIntType()),
])

small_block_header_type = ComposedType([
    ('version', VarIntType()),
    ('previous_block', PossiblyNoneType(0, IntType(256))),
    ('timestamp', IntType(32)),
    ('bits', IntType(32)), #FloatingIntegerType()),
    ('nonce', IntType(32)),
])

segwit_data = ('segwit_data', PossiblyNoneType(dict(txid_merkle_link=dict(branch=[], index=0), wtxid_merkle_root=2**256-1), ComposedType([
    ('txid_merkle_link', ComposedType([
        ('branch', ListType(IntType(256))),
        ('index', IntType(0)), # it will always be 0
    ])),
    ('wtxid_merkle_root', IntType(256))
])))

share_info_type = ComposedType([
    ('share_data', ComposedType([
        ('previous_share_hash', PossiblyNoneType(0, IntType(256))),
        ('coinbase', VarStrType()),
        ('nonce', IntType(32)),
        ('pubkey_hash', IntType(160)),
        ('subsidy', IntType(64)),
        ('donation', IntType(16)),
        ('stale_info', EnumType(IntType(8), dict((k, {0: None, 253: 'orphan', 254: 'doa'}.get(k, 'unk%i' % (k,))) for k in xrange(256)))),
        ('desired_version', VarIntType()),
    ]))] + [segwit_data] + [
    ('new_transaction_hashes', ListType(IntType(256))),
    ('transaction_hash_refs', ListType(VarIntType(), 2)), # pairs of share_count, tx_count
    ('far_share_hash', PossiblyNoneType(0, IntType(256))),
    ('max_bits', IntType(32)), #FloatingIntegerType()),
    ('bits', IntType(32)), #FloatingIntegerType()),
    ('timestamp', IntType(32)),
    ('absheight', IntType(32)),
    ('abswork', IntType(128)),
])

share_type = ComposedType([
    ('min_header', small_block_header_type),
    ('share_info', share_info_type),
    ('ref_merkle_link', ComposedType([
        ('branch', ListType(IntType(256))),
        ('index', IntType(0)),
    ])),
    ('last_txout_nonce', IntType(64)),
    ('hash_link', hash_link_type),
    ('merkle_link', ComposedType([
        ('branch', ListType(IntType(256))),
        ('index', IntType(0)), # it will always be 0
    ])),
])

share = share_type.unpack(raw_share.contents)
print(share.min_header.version)
print('Nonce = {0}'.format(share.min_header.nonce))
print(share)

# Share construct
DONATION_SCRIPT = '522102ed2a267bb573c045ef4dbe414095eeefe76ab0c47726078c9b7b1c496fee2e6221023052352f04625282ffd5e5f95a4cef52107146aedb434d6300da1d34946320ea52ae'.decode('hex')

gentx_before_refhash = VarStrType().pack(DONATION_SCRIPT) + IntType(64).pack(0) + VarStrType().pack('\x6a\x28' + IntType(256).pack(0) + IntType(64).pack(0))[:3]


gtx = []
for _b in gentx_before_refhash:
    gtx += [ord(_b)]

print(''.join(str(gtx).split(',')))

print(len(gentx_before_refhash))