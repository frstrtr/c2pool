import binascii
import struct
import cStringIO as StringIO
import os

class EarlyEnd(Exception):
    pass

class LateEnd(Exception):
    pass

def remaining(sio):
    here = sio.tell()
    sio.seek(0, os.SEEK_END)
    end  = sio.tell()
    sio.seek(here)
    return end - here


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
        obj = self.read(data)
        if not ignore_trailing and remaining(data):
            raise LateEnd()
        return obj

    def _pack(self, obj):
        f = StringIO.StringIO()
        self.write(f, obj)
        return f.getvalue()

    def unpack(self, data, ignore_trailing=False):
        if not type(data) == StringIO.InputType:
            data = StringIO.StringIO(data)
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


class StructType(Type):
    __slots__ = 'desc length'.split(' ')

    def __init__(self, desc):
        self.desc = desc
        self.length = struct.calcsize(self.desc)

    def read(self, file):
        data = file.read(self.length)
        return struct.unpack(self.desc, data)[0]

    def write(self, file, item):
        file.write(struct.pack(self.desc, item))

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
            return 0
        data = file.read(self.bytes)
        return int(b2a_hex(data[::self.step]), 16)

    def write(self, file, item, a2b_hex=binascii.a2b_hex):
        if self.bytes == 0:
            return None
        if not 0 <= item < self.max:
            raise ValueError('invalid int value - %r' % (item,))
        file.write(a2b_hex(self.format_str % (item,))[::self.step])



def shift_left(n, m):
    # python: :(
    if m >= 0:
        return n << m
    return n >> -m


class FloatingInteger(object):
    __slots__ = ['bits', '_target']

    @classmethod
    def from_target_upper_bound(cls, target):
        n = math.natural_to_string(target)
        if n and ord(n[0]) >= 128:
            n = '\x00' + n
        bits2 = (chr(len(n)) + (n + 3*chr(0))[:3])[::-1]
        bits = pack.IntType(32).unpack(bits2)
        return cls(bits)

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

POW_FUNC = lambda data: IntType(256).unpack(__import__('ltc_scrypt').getPoWHash(data))

# v = FloatingInteger(123456789)
# print(v.target)
# print(POW_FUNC(hex(123456789)))

b_data = '2 0 0 32 112 117 36 166 74 160 130 3 5 97 35 87 174 13 39 68 105 92 139 161 139 142 20 2 220 78 25 155 94 27 248 218 212 185 220 86 183 20 0 180 58 20 184 233 33 183 74 66 189 207 34 9 63 16 98 239 1 223 153 223 225 209 220 0 174 44 235 98 151 158 0 27 192 0 109 98'
b = b_data.split(' ')
print(b)
data_arr = [int(x) for x in b]
data = b''
for x in data_arr:
    data += chr(x)
print('bytes data: {0}'.format(data))

res = POW_FUNC(data)
print(res)

# print(hex(POW_FUNC(data)))

# print(hex(POW_FUNC(hex(int('02000020707524a64aa0820305612357ae0d2744695c8ba18b8e1402dc4e199b5e1bf8da42589653fe1f1e38130608349531927ba084b0f539489f6b27b61bfbcd16a61fae2ceb62979e001bc0006d62', 16)))))
#123456789 -> 25839712958676992