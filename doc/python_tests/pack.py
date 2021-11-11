import binascii
import struct

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



print(IPV6AddressType().unpack(IPV6AddressType().pack("192.168.10.10")))