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
    ('bits', IntType(32)),
    ('nonce', IntType(32)),
])

share_type = ComposedType([
    ('type', VarIntType()),
    ('contents', VarStrType()),
])

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

block_type = ComposedType([
    ('header', block_header_type),
    ('txs', ListType(tx_type)),
])

def arr_bytes_to_data(bytes):
    bytes = bytes.split(' ')
    res = b''
    for x in bytes:
        res += chr((int(x)))
    return res

def _swap4(s):
    if len(s) % 4:
        raise ValueError()
    return ''.join(s[x:x+4][::-1] for x in xrange(0, len(s), 4))

print('swap result: {0}'.format(_swap4(IntType(256).pack(123456789)).encode('hex')))

#MSG_ADDRS
# message_addrs = ComposedType([
#     ('addrs', ListType(ComposedType([
#         ('timestamp', IntType(64)),
#         ('address', address_type),
#     ]))),
# ])

# address_type = ComposedType([
#     ('services', IntType(64)),
#     ('address', IPV6AddressType()),
#     ('port', IntType(16, 'big')),
# ])

# pack_addrs_msg = message_addrs.pack(dict(addrs=[dict(timestamp=1663541470, address=dict(services=0, address="217.72.4.157", port=5024))]))
# print(pack_addrs_msg)
# print(message_addrs.unpack(pack_addrs_msg))
# print([ord(i) for i in pack_addrs_msg])

# addrs(list size): [1,
# timestamp: 222, 160, 39, 99, 0, 0, 0, 0;
# services: 0, 0, 0, 0, 0, 0, 0, 0;
# address: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 217, 72, 4, 157;
# port: 19, 160]

# [1, 222, 160, 39, 99, 0, 0, 0, 0; 0, 0, 0, 0, 0, 0, 0, 0; 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 217, 72, 4, 157; 19, 160]
# [231, 245, 156, 92; 1, 222, 160, 39, 99, 0, 0, 0; 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 217, 72, 4, 157, 19, 160]
# packed_addrs_msg = arr_bytes_to_data('231 245 156 92 1 222 160 39 99 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 255 255 217 72 4 157 19 160')
# msg_addr = message_addrs.unpack(packed_addrs_msg )
# print(msg_addr)

#MSG_SHARES

# MSG BYTES: 1 33 253 67 1 254 2 0 0 32 98 1 175 10 105 48 245 32 164 232 156 42 2 71 49 228 1 178 217 207 151 110 77 10 130 220 249 194 6 193 55 11 76 224 39 99 209 245 0 27 3 224 212 28 251 134 107 169 254 198 232 196 86 221 114 27 133 10 27 1 43 146 61 187 233 170 97 90 109 227 144 35 14 235 181 245 61 4 169 233 240 0 44 250 190 109 109 70 68 201 228 119 249 59 3 197 195 60 214 214 31 22 22 92 87 243 96 50 93 117 99 13 88 221 218 194 171 99 83 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 208 186 48 104 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 84 29 13 30 10 0 0 0 0 0 0 33 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 124 148 59 52 111 237 123 197 138 51 37 68 6 214 166 124 85 200 179 117 159 139 135 225 29 227 81 60 213 230 124 18 238 131 2 30 228 118 21 29 77 224 39 99 212 170 0 0 80 44 223 3 180 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 225 164 89 20 53 17 121 38 126 141 55 63 49 119 139 164 121 46 244 34 127 104 117 36 89 172 255 18 75 185 101 183 253 122 1 0


# #MSG_REMEMBER_TX
#
# message_remember_tx = ComposedType([
#     ('tx_hashes', ListType(IntType(256))),
#     ('txs', ListType(tx_type)),
# ])
#
# packed_remember_tx_msg = arr_bytes_to_data('0 0 0 0 1 1 16 93 255 110 88 240 242 59 220 35 37 231 174 147 72 255 76 157 123 72 173 238 30 55 86 77 30 102 227 10 214 82 0 0 0 0 0 254 255 255 255 1 117 193 244 88 32 0 0 0 23 169 20 183 93 106 35 234 123 56 4 7 118 25 205 120 9 241 60 42 24 5 166 135 2 71 48 68 2 32 68 21 70 81 75 76 158 117 186 106 124 213 46 112 45 167 220 109 85 151 81 61 134 33 220 110 138 210 15 188 225 253 2 32 96 78 195 160 58 124 129 81 53 9 216 235 218 121 87 75 113 139 243 172 22 79 153 182 93 230 21 21 102 0 36 0 1 33 3 219 199 183 87 27 78 119 80 133 106 9 202 202 103 229 252 185 20 94 65 255 94 89 144 214 54 124 253 32 99 181 202 0 0 0 0 1 0 0 0 0 1 1 179 155 201 224 210 207 221 206 81 11 75 179 79 118 244 65 200 173 174 70 182 188 119 43 209 203 221 122 205 158 112 35 1 0 0 0 0 255 255 255 255 2 0 42 117 21 0 0 0 0 22 0 20 71 168 121 65 250 157 190 115 97 121 4 80 172 204 183 235 198 204 188 97 156 95 176 202 0 0 0 0 22 0 20 145 100 127 213 22 61 198 113 95 233 24 70 222 65 103 188 163 80 51 54 2 72 48 69 2 33 0 146 167 71 189 70 230 171 107 228 164 165 253 129 194 242 132 62 26 130 156 201 85 100 127 235 124 190 32 103 220 117 91 2 32 1 77 244 216 132 146 147 90 255 207 1 106 38 14 114 167 190 194 202 115 206 125 57 175 84 93 34 106 83 250 142 70 1 33 3 164 144 86 57 188 158 232 30 0 191 67 50 103 251 157 11 54 9 175 200 192 112 48 118 192 107 35 140 0 43 37 184 0 0 0 0 1 0 0 0 0 1 1 247 85 211 65 70 95 255 159 20 15 21 242 176 147 185 91 137 148 134 202 64 252 194 243 212 247 18 191 118 88 57 200 1 0 0 0 0 255 255 255 255 2 0 0 0 0 0 0 0 0 83 106 76 80 229 141 172 126 132 143 230 66 19 121 49 57 44 41 169 66 120 152 91 34 211 170 96 66 206 100 237 137 147 212 77 66 220 11 179 131 148 121 180 65 172 99 188 164 211 254 183 65 174 59 64 112 30 64 128 65 110 78 134 121 161 148 76 65 81 33 237 0 243 218 192 65 1 0 0 0 0 0 240 127 176 127 131 56 0 0 0 0 22 0 20 253 163 127 183 36 159 226 17 129 202 161 120 116 49 242 191 157 73 184 33 2 71 48 68 2 32 80 93 118 54 238 80 233 51 226 117 57 171 98 232 13 81 118 189 203 244 98 231 36 204 113 225 184 254 17 37 123 46 2 32 66 32 113 182 255 198 247 179 25 180 125 7 14 208 144 146 196 112 104 134 210 153 211 113 215 71 110 81 110 13 29 212 1 33 3 74 109 112 14 31 207 206 180 117 64 178 93 115 157 217 28 132 209 3 49 145 84 188 224 109 45 235 90 97 241 42 65 0 0 0 0 1 0 0 0 0 1 1 34 55 255 89 157 119 165 34 27 42 248 72 16 64 188 138 194 137 76 213 171 156 227 69 29 250 24 83 56 177 82 231 1 0 0 0 0 255 255 255 255 2 0 0 0 0 0 0 0 0 83 106 76 80 57 35 95 227 234 169 252 65 119 171 235 197 149 111 3 66 209 235 1 31 255 217 2 66 27 229 152 108 213 30 5 66 183 33 206 237 60 93 249 65 205 166 92 218 211 90 145 65 77 105 69 102 190 183 213 65 123 245 200 125 25 194 192 65 249 1 13 110 87 197 221 65 184 145 132 13 104 203 3 66 176 127 131 56 0 0 0 0 22 0 20 228 205 120 248 249 250 228 169 13 194 237 33 34 160 108 229 13 198 214 44 2 71 48 68 2 32 122 224 178 77 51 30 55 5 38 220 206 250 157 190 205 231 168 82 28 247 243 77 232 124 151 16 42 215 119 160 219 23 2 32 114 229 143 167 120 45 51 203 139 132 35 65 156 175 242 162 109 27 115 62 22 2 193 128 148 167 68 61 149 8 128 221 1 33 2 251 97 113 186 160 154 144 26 167 87 120 58 3 254 49 8 52 158 93 92 133 163 116 24 168 124 159 27 58 131 29 155 0 0 0 0 2 0 0 0 1 170 124 223 78 128 44 205 2 82 32 223 185 242 167 203 226 247 81 32 82 230 39 23 6 137 165 26 194 70 56 217 18 2 0 0 0 107 72 48 69 2 33 0 175 186 224 221 229 93 78 157 108 10 12 155 145 49 250 39 64 45 97 43 231 113 80 149 238 136 49 13 161 168 151 176 2 32 16 58 114 50 65 102 105 51 192 45 99 156 143 57 10 3 224 123 156 30 198 187 226 61 182 171 228 182 232 135 174 4 1 33 3 18 127 139 165 182 217 37 48 41 176 72 231 121 214 115 60 147 88 242 216 236 142 98 178 106 76 8 70 239 25 168 35 255 255 255 255 3 170 176 40 0 0 0 0 0 25 118 169 20 206 218 39 246 85 215 97 204 242 191 100 206 139 230 108 91 75 231 130 45 136 172 0 0 0 0 0 0 0 0 35 106 33 119 105 116 104 100 114 97 119 110 32 102 114 111 109 32 119 119 119 46 100 105 103 105 102 97 117 99 101 116 46 111 114 103 214 249 14 102 8 0 0 0 25 118 169 20 94 27 66 154 31 153 42 240 33 18 8 143 172 6 157 230 253 53 181 102 136 172 0 0 0 0')
# remember_tx_msg = message_remember_tx.unpack(packed_remember_tx_msg)


# MSG SHAREREQ
message_sharereq = ComposedType([
    ('id', IntType(256)),
    ('hashes', ListType(IntType(256))),
    ('parents', VarIntType()),
    ('stops', ListType(IntType(256))),
])

packed_sharereq_msg = arr_bytes_to_data('115 104 97 114 101 114 101 113 0 0 0 0 67 0 0 0 177 242 140 148 209 118 128 71 216 142 129 19 66 84 184 190 68 93 103 205 90 224 123 175 16 106 104 79 87 219 55 169 61 90 7 56 1 147 207 57 147 71 195 44 221 238 100 5 0 165 251 174 8 57 146 172 21 57 4 22 153 31 56 141 110 213 108 107 25 0 0')
command = packed_sharereq_msg[:12].rstrip('\0')
length = struct.unpack('<I', packed_sharereq_msg[12:16])
checksum = packed_sharereq_msg[16:20]
sharereq_msg = message_sharereq.unpack(packed_sharereq_msg[20:])

print(command)
print(length)
print(checksum)
print(sharereq_msg)

# # c2pool: 115 104 97 114 101 114 101 113 0 0 0 0 67 0 0 0 177 242 140 148 209 118 128 71 216 142 129 19 66 84 184 190 68 93 103 205 90 224 123 175 16 106 104 79 87 219 55 169 61 90 7 56 1 147 207 57 147 71 195 44 221 238 100 5 0 165 251 174 8 57 146 172 21 57 4 22 153 31 56 141 110 213 108 107 25 0 0
# # p2pool: 209 118 128 71 216 142 129 19 66 84 184 190 68 93 103 205 90 224 123 175 16 106 104 79 87 219 55 169 61 90 7 56 1 147 207 57 147 71 195 44 221 238 100 5 0 165 251 174 8 57 146 172 21 57 4 22 153 31 56 141 110 213 108 107 25 0 0
# sharereq = dict(id=int('38075a3da937db574f686a10af7be05acd675d44beb8544213818ed8478076d1', 16), hashes=[int('196b6cd56e8d381f9916043915ac923908aefba5000564eedd2cc3479339cf93', 16)], parents=0, stops=[])
# packed_sharereq_msg2 = message_sharereq.pack(sharereq)
# print(packed_sharereq_msg2)
# s = ''
# for i in packed_sharereq_msg2:
#     s += str(ord(i)) + " "
# print(s)