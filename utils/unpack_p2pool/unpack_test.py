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
    ('bits', FloatingIntegerType()),
    ('nonce', IntType(32)),
])

share_type = ComposedType([
    ('type', VarIntType()),
    ('contents', VarStrType()),
])

def arr_bytes_to_data(bytes):
    bytes = bytes.split(' ')
    res = b''
    for x in bytes:
        res += chr((int(x)))
    return res

def print_bytes(data):
    print(str([ord(x) for x in data])[1:-1].replace(',',''))
        

x = '23fd9601fe00000020654f11363698fc9a54e43f126f294bd1a33b650148e8b6bb532fc08500cb6966e8103066140b041db0022a77e3af9c1de80a16583bed2a6179b63ed410b890b113cfd0fcd68bafa4096779b90503fd823100731a92d3226d6839617a4b44785235374766374a575a756e6e43324a7a37325351747746544b68dec14025000000000000fe2302a41fb37f52f6747afbbeae61462feaa40b8b3655f8fb7af60843111101ec5f958e93b9a76bb46536bf807b1caef9635f432d982bd907eb5050130b6ec00aeabc2bb9ca34c5f1ba0bd332fc3d217d9853754fe42797e32cf9ddddcab6f66ab8056f1b64efa2157281c406fc6a5d9de6db5e2adf63c86646a4edc91c51f86d74c707c0221e8828011ef310306675b3210073990593df0d00000000000000000000000100000000000000c357550d5a390b342f665a3d853c039a626b803bb37976c20ba0b5ee5a56fceedc0220e67c088987582af73218c99820276bbf0004c5c18f7dd691f9c4326bfd9930d5567a6d109fec00f4eca887c42e80ddaa57df9bda8db8b277110a50a9a268b6'
# raw_share = share_type.unpack(x.decode('hex'))

# x = arr_bytes_to_data('33 253 67 1 254 2 0 0 32 98 1 175 10 105 48 245 32 164 232 156 42 2 71 49 228 1 178 217 207 151 110 77 10 130 220 249 194 6 193 55 11 76 224 39 99 209 245 0 27 3 224 212 28 251 134 107 169 254 198 232 196 86 221 114 27 133 10 27 1 43 146 61 187 233 170 97 90 109 227 144 35 14 235 181 245 61 4 169 233 240 0 44 250 190 109 109 70 68 201 228 119 249 59 3 197 195 60 214 214 31 22 22 92 87 243 96 50 93 117 99 13 88 221 218 194 171 99 83 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 208 186 48 104 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 84 29 13 30 10 0 0 0 0 0 0 33 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 124 148 59 52 111 237 123 197 138 51 37 68 6 214 166 124 85 200 179 117 159 139 135 225 29 227 81 60 213 230 124 18 238 131 2 30 228 118 21 29 77 224 39 99 212 170 0 0 80 44 223 3 180 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 225 164 89 20 53 17 121 38 126 141 55 63 49 119 139 164 121 46 244 34 127 104 117 36 89 172 255 18 75 185 101 183 253 122 1 0')
# x = arr_bytes_to_data('33 253 173 2 254 2 0 0 32 57 204 82 243 225 65 44 227 224 220 253 60 83 206 15 139 98 237 236 221 130 180 172 59 69 180 131 220 250 75 113 209 53 26 40 99 143 210 0 27 51 90 178 111 54 38 234 253 206 232 59 177 172 87 183 87 167 247 60 233 25 208 105 9 100 179 97 249 113 113 204 50 203 44 171 152 61 4 116 237 240 0 44 250 190 109 109 221 91 216 243 54 14 232 155 132 161 127 15 211 4 70 165 98 8 136 217 52 45 93 73 209 37 85 39 237 108 190 245 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 52 118 35 201 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 50 136 16 30 10 0 0 0 0 0 254 33 3 29 48 193 135 246 126 77 65 164 224 105 246 72 65 56 101 197 208 147 222 85 42 134 208 155 216 20 128 193 196 218 81 105 184 124 196 90 109 235 240 131 35 146 22 93 230 99 152 58 94 109 173 198 195 192 215 137 251 104 84 125 30 43 47 2 16 190 166 210 169 150 152 180 44 214 42 113 194 118 155 207 40 169 225 118 236 62 231 243 230 177 183 119 133 167 147 87 239 188 53 130 84 2 16 5 80 236 27 161 156 218 63 1 178 95 252 85 135 172 201 15 75 205 210 153 142 26 68 5 184 12 127 69 45 109 132 98 144 202 101 183 92 175 33 170 124 254 8 103 43 194 15 131 217 181 90 62 232 127 237 108 43 88 183 92 30 179 74 238 68 145 43 234 248 18 152 166 152 28 210 115 54 196 7 245 48 247 26 30 200 164 7 144 225 145 73 100 86 1 166 43 234 249 68 43 118 85 123 143 164 135 103 187 141 175 34 211 210 106 140 146 43 139 189 173 211 169 46 186 105 61 236 177 19 69 85 106 73 21 169 31 90 12 7 41 96 211 185 125 162 117 176 154 120 21 166 57 242 52 109 36 2 126 99 234 147 105 48 115 183 10 194 151 20 243 182 237 142 223 109 70 219 113 31 185 159 36 158 3 5 0 0 0 1 0 2 0 3 0 4 216 18 219 138 225 249 8 166 139 247 7 33 83 202 49 159 36 122 134 214 253 138 159 34 24 211 18 84 79 113 185 125 194 156 7 30 104 245 64 29 59 26 40 99 155 172 0 0 21 101 7 120 181 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 9 85 126 125 158 83 174 178 39 133 10 85 211 35 16 165 124 100 116 79 24 162 210 195 98 232 62 204 149 5 16 46 253 122 1 3 184 12 127 69 45 109 132 98 144 202 101 183 92 175 33 170 124 254 8 103 43 194 15 131 217 181 90 62 232 127 237 108 105 184 124 196 90 109 235 240 131 35 146 22 93 230 99 152 58 94 109 173 198 195 192 215 137 251 104 84 125 30 43 47 2 16 190 166 210 169 150 152 180 44 214 42 113 194 118 155 207 40 169 225 118 236 62 231 243 230 177 183 119 133 167 147')
# x = arr_bytes_to_data('33 253 7 2 254 2 0 0 32 70 39 80 200 238 52 157 92 223 100 79 47 56 126 174 94 131 240 156 81 109 128 246 183 191 246 187 80 119 244 146 207 80 28 40 99 130 208 0 27 51 96 9 223 192 91 179 32 105 56 112 238 82 243 27 26 122 205 245 159 214 42 6 48 76 34 38 236 113 55 46 45 216 16 56 68 61 4 171 237 240 0 44 250 190 109 109 187 152 153 156 97 155 1 54 15 95 120 251 117 115 97 40 10 15 198 216 110 100 175 57 136 60 212 195 44 27 180 31 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 234 250 139 25 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 197 188 13 30 10 0 0 0 0 0 0 33 2 186 96 167 17 67 215 155 52 206 39 99 104 141 45 196 116 49 105 158 148 108 251 163 188 9 240 83 141 177 108 36 118 3 245 253 84 98 143 149 36 199 129 106 19 191 220 187 41 75 251 249 16 200 86 221 109 40 103 227 254 167 94 111 240 250 87 91 39 75 133 111 152 224 78 46 78 19 125 26 236 111 247 58 195 171 225 1 152 185 226 164 202 206 187 50 166 2 186 96 167 17 67 215 155 52 206 39 99 104 141 45 196 116 49 105 158 148 108 251 163 188 9 240 83 141 177 108 36 118 31 102 246 202 57 231 105 100 231 198 109 45 108 224 192 245 58 65 194 64 194 26 192 31 159 28 167 168 141 58 64 83 2 0 0 0 1 229 65 218 34 183 219 5 63 188 108 220 212 92 244 235 211 123 23 112 76 72 69 252 201 171 65 240 31 248 94 147 94 120 238 8 30 59 55 76 29 82 28 40 99 167 172 0 0 14 242 226 161 181 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 132 152 70 177 63 201 127 41 48 253 168 192 121 134 101 21 235 134 254 209 23 162 110 192 217 26 71 64 110 28 170 222 253 122 1 2 186 96 167 17 67 215 155 52 206 39 99 104 141 45 196 116 49 105 158 148 108 251 163 188 9 240 83 141 177 108 36 118 3 245 253 84 98 143 149 36 199 129 106 19 191 220 187 41 75 251 249 16 200 86 221 109 40 103 227 254 167 94 111 240')
# x = arr_bytes_to_data('33 253 75 2 254 2 0 0 32 148 236 161 176 19 196 52 177 80 176 66 137 93 89 221 53 127 47 79 102 29 209 50 220 131 120 116 2 195 135 74 85 179 77 64 99 94 160 0 27 0 219 127 171 176 82 74 17 113 215 247 29 132 40 94 118 244 242 251 116 46 41 225 178 156 138 153 115 49 251 60 218 176 211 203 250 61 4 220 139 242 0 44 250 190 109 109 42 25 180 137 88 196 39 34 175 92 154 76 199 161 111 253 137 95 97 61 73 202 190 72 181 164 77 145 144 243 235 67 1 0 0 0 0 0 0 0 10 95 95 99 50 112 111 111 108 95 95 91 240 236 111 187 53 31 201 251 189 142 31 64 148 33 48 231 113 49 151 141 246 222 65 173 100 38 1 10 0 0 0 0 0 0 33 3 97 103 101 46 18 162 234 197 19 115 207 38 144 238 5 183 32 206 52 149 94 236 5 163 33 100 202 214 254 18 43 145 75 219 174 177 140 128 232 149 88 169 119 207 164 252 206 165 132 252 161 26 15 181 160 163 174 235 241 194 160 244 161 193 251 189 242 152 76 251 142 147 168 191 48 212 86 207 0 24 223 191 219 61 249 80 12 129 251 238 146 169 152 40 99 211 182 221 45 21 254 38 193 176 122 169 240 29 180 129 4 23 218 62 21 245 110 92 32 62 35 185 57 5 52 233 191 239 2 30 176 69 208 76 74 133 118 9 41 248 24 172 252 8 19 236 1 140 220 87 10 80 30 96 159 178 247 189 75 53 33 31 96 142 29 135 80 54 250 116 247 204 129 77 140 209 162 136 53 128 107 52 146 20 226 202 130 41 190 129 197 57 253 4 1 0 1 1 0 0 0 1 238 99 138 229 175 83 230 15 115 145 95 161 228 8 184 87 185 181 176 182 199 153 205 201 105 191 249 139 241 168 116 97 21 160 5 30 185 0 48 29 180 77 64 99 129 120 1 0 239 56 158 24 143 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 26 190 103 25 96 253 88 195 199 208 183 59 138 138 179 139 113 238 133 242 7 211 132 118 243 193 251 11 69 25 210 255 253 122 1 3 229 192 23 217 217 42 225 253 30 59 154 147 29 232 173 101 133 128 155 227 178 117 56 201 49 153 165 169 43 48 111 111 228 40 130 32 10 72 10 71 163 109 177 41 43 165 86 81 118 68 183 12 218 64 211 169 206 236 110 6 42 54 135 79 56 35 199 233 146 30 169 228 65 6 217 87 89 70 123 98 159 19 205 157 188 132 122 149 251 145 138 175 24 180 48 110')
# raw_share = share_type.unpack(x)

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
        ] + ([('address', VarStrType())]
                if True else [('pubkey_hash', IntType(160))]) + [
        ('subsidy', IntType(64)),
        ('donation', IntType(16)),
        ('stale_info', EnumType(IntType(8), dict((k, {0: None, 253: 'orphan', 254: 'doa'}.get(k, 'unk%i' % (k,))) for k in xrange(256)))),
        ('desired_version', VarIntType()),
    ]))] + ([segwit_data] if True else []) + ([ #is_segwit_activated(cls.VERSION, net)
    ('new_transaction_hashes', ListType(IntType(256))),
    ('transaction_hash_refs', ListType(VarIntType(), 2)), # pairs of share_count, tx_count
    ] if False else []) + [
    ('far_share_hash', PossiblyNoneType(0, IntType(256))),
    ('max_bits', IntType(32)),
    ('bits', IntType(32)),
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

message_version = ComposedType([
    ('version', IntType(32)),
    ('services', IntType(64)),
    ('time', IntType(64)),
    ('addr_to', address_type),
    ('addr_from', address_type),
    ('nonce', IntType(64)),
    ('sub_version_num', VarStrType()),
    ('start_height', IntType(32)),
])

payload = message_version.pack(
    dict(
            version=70002,
            services=1,
            time=1723920793,
            addr_to=dict(
                services=1,
                address="192.168.0.1",
                port=2222,
            ),
            addr_from=dict(
                services=1,
                address="192.168.0.1",
                port=2222,
            ),
            nonce=1,
            sub_version_num='c2pool',
            start_height=0
    )
)

def simulate_message(payload):
    prefix = b'\xfd\xd2\xc8\xf1'
    command = 'version'
    
    print(hashlib.sha256(hashlib.sha256(payload).digest()).hexdigest())
    print_bytes(hashlib.sha256(hashlib.sha256(payload).digest()).digest())
    print_bytes(hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])

    data = prefix + struct.pack('<12sI', command, len(payload)) + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] + payload

    return data

print_bytes(simulate_message(payload))

