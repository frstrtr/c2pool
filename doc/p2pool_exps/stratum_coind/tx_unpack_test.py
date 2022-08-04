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

# res = block_header_type.pack(dict(
#     version=1,
#     previous_block=0xd928d3066613d1c9dd424d5810cdd21bfeef3c698977e81ec1640e1084950073,
#     merkle_root=0x03f4b646b58a66594a182b02e425e7b3a93c8a52b600aa468f1bc5549f395f16,
#     timestamp=1327807194,
#     bits=FloatingInteger(0x1d01b56f),
#     nonce=20736,
# ))
#
# POW_FUNC = lambda data: IntType(256).unpack(__import__('ltc_scrypt').getPoWHash(data))
# print(FloatingInteger(0x1d01b56f).target)
# pow_func_res = POW_FUNC(res)
# print(pow_func_res < int("400000000000000000000000000000000000000000000000000000000", 16))
# print(hex(pow_func_res))
#
# res_arr = ""
# for x in res:
#     res_arr += str(ord(x)) + " "
# print(res_arr)

# 0x1312dc20ce5aa3ee622f5562dfb2593ec51436aab739ef0d02189e18f
# 8fe18921d0f09e73ab6a4351ec9325fb2d56f522e63eaae50cc22d3101000000
# 00000001312dc20ce5aa3ee622f5562dfb2593ec51436aab739ef0d02189e18f
# 00000001312dc20ce5aa3ee622f5562dfb2593ec51436aab739ef0d02189e18f

class TransactionTypeForTest(Type):
    # _int_type = IntType(32)
    # _varint_type = VarIntType()
    # _witness_type = ListType(VarStrType())
    # _wtx_type = ComposedType([
    #     ('flag', IntType(8)),
    #     ('tx_ins', ListType(tx_in_type)),
    #     ('tx_outs', ListType(tx_out_type))
    # ])
    # _ntx_type = ComposedType([
    #     ('tx_outs', ListType(tx_out_type)),
    #     ('lock_time', _int_type)
    # ])
    # _write_type = ComposedType([
    #     ('version', _int_type),
    #     ('marker', IntType(8)),
    #     ('flag', IntType(8)),
    #     ('tx_ins', ListType(tx_in_type)),
    #     ('tx_outs', ListType(tx_out_type))
    # ])

    def read(self, file):
        _version = IntType(32).read(file)
        _marker = VarIntType().read(file)
        # if marker == 0:
        #     next = self._wtx_type.read(file)
        #     witness = [None]*len(next['tx_ins'])
        #     for i in xrange(len(next['tx_ins'])):
        #         witness[i] = self._witness_type.read(file)
        #     locktime = self._int_type.read(file)
        #     return dict(version=version, marker=marker, flag=next['flag'], tx_ins=next['tx_ins'], tx_outs=next['tx_outs'], witness=witness, lock_time=locktime)
        # else:
        #     tx_ins = [None]*marker
        #     for i in xrange(marker):
        #         tx_ins[i] = tx_in_type.read(file)
        #     next = self._ntx_type.read(file)
        #     return dict(version=version, tx_ins=tx_ins, tx_outs=next['tx_outs'], lock_time=next['lock_time'])
        return dict(version=_version, marker=_marker)

    def write(self, file, item):
        pass
        # if is_segwit_tx(item):
        #     assert len(item['tx_ins']) == len(item['witness'])
        #     self._write_type.write(file, item)
        #     for w in item['witness']:
        #         self._witness_type.write(file, w)
        #     self._int_type.write(file, item['lock_time'])
        #     return
        # return tx_id_type.write(file, item)

x = '01000000013ccaa9d380b87652929e5fe06c7c6ea08e16118c0a4749d0391fbe98ab6e549f00000000d74730440220197724619b7a57853c6ce6a04d933a83057629e4323ae301562b817904b321280220598f71b813045fcf500352e701b9b7cab75a5694eab374d6cdec13fd2efd8e4f0120949c9ff1f7fa8268128832fd123535ef3eae4d01c7c1aa3fa74ec38692878129004c6b630480feea62b1752102f70d90df545d767a53daa25e07875b4b588c476cba465a28dcafc4b6b792cf94ac6782012088a9142323cb36c535e5121c3409e371c1ae15011b5faf88210315d9c51c657ab1be4ae9d3ab6e76a619d3bccfe830d5363fa168424c0d044732ac68ffffffff01c40965f0020000001976a9141462c3dd3f936d595c9af55978003b27c250441f88ac80feea62'
# print(IntType(32).unpack('01000000013c'))#3ccaa9d380b87652929e5fe06c7c6ea08e16118c0a4749d0391fbe98ab6e549f00000000d74730440220197724619b7a57853c6ce6a04d933a83057629e4323ae301562b817904b321280220598f71b813045fcf500352e701b9b7cab75a5694eab374d6cdec13fd2efd8e4f0120949c9ff1f7fa8268128832fd123535ef3eae4d01c7c1aa3fa74ec38692878129004c6b630480feea62b1752102f70d90df545d767a53daa25e07875b4b588c476cba465a28dcafc4b6b792cf94ac6782012088a9142323cb36c535e5121c3409e371c1ae15011b5faf88210315d9c51c657ab1be4ae9d3ab6e76a619d3bccfe830d5363fa168424c0d044732ac68ffffffff01c40965f0020000001976a9141462c3dd3f936d595c9af55978003b27c250441f88ac80feea62')
# tx_type2.unpack(x)
print('Version: {0}'.format(IntType(32).unpack(b'\x01\x00\x00\x00')))
version_packed = IntType(32).pack(1)
print("len: {0}".format(len(version_packed)))
print('Version2: {0}'.format(IntType(32).unpack(version_packed)))
num_packed = []
for _d in version_packed:
    num_packed += [ord(_d)]
print(num_packed)

start_tx_data = ComposedType([
    ('version', IntType(32)),
    ('marker', VarIntType())])

_x = b'01000'
print(start_tx_data.unpack(_x))
#######################


x = "0100000002".decode('hex')
__x = []
for c in x:
    __x += [ord(c)]
print(__x)
print(start_tx_data.unpack(x))