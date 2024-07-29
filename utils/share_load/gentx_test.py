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

x = '11fda501fe02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8daae2ceb62979e001bc0006d6200000000000000000000000000000000000000000000000000000000000000003d043edaec002cfabe6d6d08d3533a81ca356a7ac1c85c9b0073aebcca7182ad83849b9498377c9a1cd8a701000000000000000a5f5f6332706f6f6c5f5f3e9922fe9ad7bdd0e20eb7f64fa6dd42734dd4f43275cc26fd4d483b0a00000000000021012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d61f2bae86d664294b8850df3f580ec9e4fb2170fe8dbae492b5159af73834eba4012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d60100000000000000000000000000000000000000000000000000000000000000000000ffff0f1effff0f1eae2ceb6201000000010010000000000000000000000000000000000000000000001fcbf0a89045913d394db52949e986b8c6385b0060cbaebf3cf7806ff1df96affd7a01012f85ab444002e4ffec67106f9f0ee77405296818a224f641a0b2bbfe9f8d22d6'
raw_share = share_type.unpack(x.decode('hex'))
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

ref_type = ComposedType([
    ('identifier', FixedStrType(64//8)),
    ('share_info', share_info_type),
])

merkle_record_type = ComposedType([
    ('left', IntType(256)),
    ('right', IntType(256)),
])

def check_merkle_link(tip_hash, link):
    if link['index'] >= 2**len(link['branch']):
        raise ValueError('index too large')
    return reduce(lambda c, (i, h): hash256(merkle_record_type.pack(
        dict(left=h, right=c) if (link['index'] >> i) & 1 else
        dict(left=c, right=h)
    )), enumerate(link['branch']), tip_hash)

def bytes_to_data(bytes):
    res = []
    for x in bytes:
        res += [ord(x)]
    #
    # test_bytes = []
    # for x in res:
    #     test_bytes += [ord(x)]
    # print(test_bytes)
    return str(res).replace(', ', ' ')

def get_ref_hash(share_info, ref_merkle_link):
    IDENTIFIER = '1c017dc97693f7d5'.decode('hex')
    # print('share_info: {0}'.format(share_info))
    print(bytes_to_data(ref_type.pack(dict(
        identifier=IDENTIFIER,
        share_info=share_info,
    ))))
    hash_ref_type = hash256(ref_type.pack(dict(
        identifier=IDENTIFIER,
        share_info=share_info,
    )))
    print('hash_ref_type: {0}'.format(bytes_to_data(IntType(256).pack(hash_ref_type))))
    _check_merkle_link = check_merkle_link(hash_ref_type, ref_merkle_link)
    print('_check_merkle_link: {0}'.format(bytes_to_data(IntType(256).pack(_check_merkle_link))))
    return IntType(256).pack(_check_merkle_link)

#p2pool-dgb-sha256-350/p2pool/bitcoin/sha256.py

# from __future__ import division

import struct
import random
import hashlib


k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

def process(state, chunk):
    def rightrotate(x, n):
        return (x >> n) | (x << 32 - n) % 2**32

    w = list(struct.unpack('>16I', chunk))
    for i in xrange(16, 64):
        s0 = rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) % 2**32)

    a, b, c, d, e, f, g, h = start_state = struct.unpack('>8I', state)
    for k_i, w_i in zip(k, w):
        t1 = (h + (rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)) + ((e & f) ^ (~e & g)) + k_i + w_i) % 2**32

        a, b, c, d, e, f, g, h = (
            (t1 + (rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) % 2**32,
            a, b, c, (d + t1) % 2**32, e, f, g,
        )

    return struct.pack('>8I', *((x + y) % 2**32 for x, y in zip(start_state, [a, b, c, d, e, f, g, h])))


initial_state = struct.pack('>8I', 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

class sha256(object):
    digest_size = 256//8
    block_size = 512//8

    def __init__(self, data='', _=(initial_state, '', 0)):
        self.state, self.buf, self.length = _
        self.update(data)

    def update(self, data):
        state = self.state
        buf = self.buf + data

        chunks = [buf[i:i + self.block_size] for i in xrange(0, len(buf) + 1, self.block_size)]
        for chunk in chunks[:-1]:
            state = process(state, chunk)

        self.state = state
        self.buf = chunks[-1]

        # print('update_buf: {0}'.format([ord(x) for x in self.buf]))
        # print('update_state: {0}'.format([ord(x) for x in self.state]))
        self.length += 8*len(data)

    def copy(self, data=''):
        return self.__class__(data, (self.state, self.buf, self.length))

    def digest(self):
        state = self.state
        buf = self.buf + '\x80' + '\x00'*((self.block_size - 9 - len(self.buf)) % self.block_size) + struct.pack('>Q', self.length)
        # print([ord(x) for x in buf])
        for chunk in [buf[i:i + self.block_size] for i in xrange(0, len(buf), self.block_size)]:
            state = process(state, chunk)
        # print('state:')
        # print([ord(x) for x in state])
        return state

    def hexdigest(self):
        return self.digest().encode('hex')

###########################

def random_bytes(length):
    return ''.join(chr(random.randrange(2**8)) for i in xrange(length))

def prefix_to_hash_link(prefix, const_ending=''):
    assert prefix.endswith(const_ending), (prefix, const_ending)
    x = sha256(prefix)
    # print('buff len: {0}'.format(len(x.buf)))
    # print('buff: {0}'.format(x.buf))
    # print('digest x:')
    # print_bytes(x.digest())
    # print(x.hexdigest())
    # print(x.hexdigest())
    return dict(state=x.state, extra_data=x.buf[:max(0, len(x.buf)-len(const_ending))], length=x.length//8)

def check_hash_link(hash_link, data, const_ending=''):
    extra_length = hash_link['length'] % (512//8)
    assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
    extra = (hash_link['extra_data'] + const_ending)[len(hash_link['extra_data']) + len(const_ending) - extra_length:]
    assert len(extra) == extra_length
    # return hashlib.sha256(sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest()
    return IntType(256).unpack(hashlib.sha256(sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest())

###############################################3333

share = share_type.unpack(raw_share.contents)
# print(share.min_header.version)
# print('Nonce = {0}'.format(share.min_header.nonce))
print(share)

# Share construct
DONATION_SCRIPT = '522102ed2a267bb573c045ef4dbe414095eeefe76ab0c47726078c9b7b1c496fee2e6221023052352f04625282ffd5e5f95a4cef52107146aedb434d6300da1d34946320ea52ae'.decode('hex')

gentx_before_refhash = VarStrType().pack(DONATION_SCRIPT) + IntType(64).pack(0) + VarStrType().pack('\x6a\x28' + IntType(256).pack(0) + IntType(64).pack(0))[:3]


# gtx = []
# for _b in gentx_before_refhash:
#     gtx += [ord(_b)]
#
# print(''.join(str(gtx).split(',')))
#
# print(len(gentx_before_refhash))

ref_hash = get_ref_hash(share.share_info, share.ref_merkle_link) + IntType(64).pack(share.last_txout_nonce) + IntType(32).pack(0)
print(ref_hash)

print(bytes_to_data(ref_hash))

gentx_hash = check_hash_link(
    share.hash_link,
    get_ref_hash(share.share_info, share.ref_merkle_link) + IntType(64).pack(share.last_txout_nonce) + IntType(32).pack(0),
    gentx_before_refhash,
    )

print('share.hash_link = {0}'.format(share.hash_link))
print('share.hash_link.state = {0}'.format(bytes_to_data(share.hash_link.state)))
print('gentx_before_refhash = {0}'.format(bytes_to_data(gentx_before_refhash)))
print('gentx_hash = {0}'.format(gentx_hash))
print('gentx_hash = {0}'.format(hex(gentx_hash)))
print('gentx_hash(INTTYPE) = {0}'.format(bytes_to_data(IntType(256).pack(gentx_hash))))

print('link: {0}'.format(share.share_info.segwit_data.txid_merkle_link))
merkle_root = check_merkle_link(gentx_hash, share.share_info.segwit_data.txid_merkle_link)
print('merkle_root = {0}'.format(hex(merkle_root)))

