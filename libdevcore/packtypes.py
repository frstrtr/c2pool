from __future__ import absolute_import, division
print("used py script") #FOR DEBUG
import itertools

import codecs
import binascii
import struct
import io as StringIO
from io import BytesIO
import os
import hashlib
import json

#global vars
SEGWIT_ACTIVATION_VERSION = 17

#============

# -------------------------------------------p2pool util/math---------------------------------------


#import __builtin__
import math
import random
import time


def median(x, use_float=True):
    # there exist better algorithms...
    y = sorted(x)
    if not y:
        raise ValueError('empty sequence!')
    left = (len(y) - 1)//2
    right = len(y)//2
    sum = y[left] + y[right]
    if use_float:
        return sum/2
    else:
        return sum//2


def mean(x):
    total = 0
    count = 0
    for y in x:
        total += y
        count += 1
    return total/count


def shuffled(x):
    x = list(x)
    random.shuffle(x)
    return x


def shift_left(n, m):
    # python: :(
    if m >= 0:
        return n << m
    return n >> -m

# def clip(x, (low, high)):
#     if x < low:
#         return low
#     elif x > high:
#         return high
#     else:
#         return x

# add_to_range = lambda x, (low, high): (min(low, x), max(high, x))


def nth(i, n=0):
    i = iter(i)
    for _ in range(n):
        i.next()
    return i.next()


def geometric(p):
    if p <= 0 or p > 1:
        raise ValueError('p must be in the interval (0.0, 1.0]')
    if p == 1:
        return 1
    return int(math.log1p(-random.random()) / math.log1p(-p)) + 1


def add_dicts_ext(add_func=lambda a, b: a+b, zero=0):
    def add_dicts(*dicts):
        res = {}
        for d in dicts:
            for k, v in d.iteritems():
                res[k] = add_func(res.get(k, zero), v)
        return dict((k, v) for k, v in res.iteritems() if v != zero)
    return add_dicts


add_dicts = add_dicts_ext()


def mult_dict(c, x): return dict((k, c*v) for k, v in x.iteritems())


def format(x, add_space=False):
    prefixes = 'kMGTPEZY'
    count = 0
    while x >= 100000 and count < len(prefixes) - 2:
        x = x//1000
        count += 1
    s = '' if count == 0 else prefixes[count - 1]
    if add_space and s:
        s = ' ' + s
    return '%i' % (x,) + s


def format_dt(dt):
    for value, name in [
        (365.2425*60*60*24, 'years'),
        (60*60*24, 'days'),
        (60*60, 'hours'),
        (60, 'minutes'),
        (1, 'seconds'),
    ]:
        if dt > value:
            break
    return '%.01f %s' % (dt/value, name)


def perfect_round(x): return int(x + random.random())


def erf(x):
    # save the sign of x
    sign = 1
    if x < 0:
        sign = -1
    x = abs(x)

    # constants
    a1 = 0.254829592
    a2 = -0.284496736
    a3 = 1.421413741
    a4 = -1.453152027
    a5 = 1.061405429
    p = 0.3275911

    # A&S formula 7.1.26
    t = 1.0/(1.0 + p*x)
    y = 1.0 - (((((a5*t + a4)*t) + a3)*t + a2)*t + a1)*t*math.exp(-x*x)
    return sign*y  # erf(-x) = -erf(x)


def find_root(y_over_dy, start, steps=10, bounds=(None, None)):
    guess = start
    for i in xrange(steps):
        prev, guess = guess, guess - y_over_dy(guess)
        if bounds[0] is not None and guess < bounds[0]:
            guess = bounds[0]
        if bounds[1] is not None and guess > bounds[1]:
            guess = bounds[1]
        if guess == prev:
            break
    return guess


def ierf(z):
    return find_root(lambda x: (erf(x) - z)/(2*math.e**(-x**2)/math.sqrt(math.pi)), 0)


def binomial_conf_interval(x, n, conf=0.95):
    assert 0 <= x <= n and 0 <= conf < 1
    if n == 0:
        left = random.random()*(1 - conf)
        return left, left + conf
    # approximate - Wilson score interval
    z = math.sqrt(2)*ierf(conf)
    p = x/n
    topa = p + z**2/2/n
    topb = z * math.sqrt(p*(1-p)/n + z**2/4/n**2)
    bottom = 1 + z**2/n
    return [clip(x, (0, 1)) for x in add_to_range(x/n, [(topa - topb)/bottom, (topa + topb)/bottom])]


def minmax(x): return (min(x), max(x))


def format_binomial_conf(x, n, conf=0.95, f=lambda x: x):
    if n == 0:
        return '???'
    left, right = minmax(map(f, binomial_conf_interval(x, n, conf)))
    return '~%.1f%% (%.f-%.f%%)' % (100*f(x/n), math.floor(100*left), math.ceil(100*right))


def reversed(x):
    try:
        return __builtin__.reversed(x)
    except TypeError:
        return reversed(list(x))


class Object(object):
    def __init__(self, **kwargs):
        for k, v in kwargs.iteritems():
            setattr(self, k, v)


def add_tuples(res, *tuples):
    for t in tuples:
        if len(t) != len(res):
            raise ValueError('tuples must all be the same length')
        res = tuple(a + b for a, b in zip(res, t))
    return res


def flatten_linked_list(x):
    while x is not None:
        x, cur = x
        yield cur


def weighted_choice(choices):
    choices = list((item, weight) for item, weight in choices)
    target = random.randrange(sum(weight for item, weight in choices))
    for item, weight in choices:
        if weight > target:
            return item
        target -= weight
    raise AssertionError()


def natural_to_string(n, alphabet=None):
    if n < 0:
        raise TypeError('n must be a natural')
    if alphabet is None:
        s = ('%x' % (n,)).lstrip('0')
        if len(s) % 2:
            s = '0' + s
        return s.decode('hex')
    else:
        assert len(set(alphabet)) == len(alphabet)
        res = []
        while n:
            n, x = divmod(n, len(alphabet))
            res.append(alphabet[x])
        res.reverse()
        return ''.join(res)


def string_to_natural(s, alphabet=None):
    if alphabet is None:
        assert not s.startswith('\x00')
        return int(s.encode('hex'), 16) if s else 0
    else:
        assert len(set(alphabet)) == len(alphabet)
        assert not s.startswith(alphabet[0])
        return sum(alphabet.index(char) * len(alphabet)**i for i, char in enumerate(reversed(s)))


class RateMonitor(object):
    def __init__(self, max_lookback_time):
        self.max_lookback_time = max_lookback_time

        self.datums = []
        self.first_timestamp = None

    def _prune(self):
        start_time = time.time() - self.max_lookback_time
        for i, (ts, datum) in enumerate(self.datums):
            if ts > start_time:
                del self.datums[:i]
                return

    def get_datums_in_last(self, dt=None):
        if dt is None:
            dt = self.max_lookback_time
        assert dt <= self.max_lookback_time
        self._prune()
        now = time.time()
        return [datum for ts, datum in self.datums if ts > now - dt], min(dt, now - self.first_timestamp) if self.first_timestamp is not None else 0

    def add_datum(self, datum):
        self._prune()
        t = time.time()
        if self.first_timestamp is None:
            self.first_timestamp = t
        else:
            self.datums.append((t, datum))


def merge_dicts(*dicts):
    res = {}
    for d in dicts:
        res.update(d)
    return res


# ------------------------------------------p2pool memoize------------------------------------------


class LRUDict(object):
    def __init__(self, n):
        self.n = n
        self.inner = {}
        self.counter = itertools.count()

    def get(self, key, default=None):
        if key in self.inner:
            x, value = self.inner[key]
            self.inner[key] = self.counter.next(), value
            return value
        return default

    def __setitem__(self, key, value):
        self.inner[key] = self.counter.next(), value
        while len(self.inner) > self.n:
            self.inner.pop(min(self.inner, key=lambda k: self.inner[k][0]))


_nothing = object()


def memoize_with_backing(backing, has_inverses=set()):
    def a(f):
        def b(*args):
            res = backing.get((f, args), _nothing)
            if res is not _nothing:
                return res

            res = f(*args)

            backing[(f, args)] = res
            for inverse in has_inverses:
                backing[(inverse, args[:-1] + (res,))] = args[-1]

            return res
        return b
    return a


class cdict2(dict):
    def __init__(self, func):
        dict.__init__(self)
        self._func = func

    def __missing__(self, key):
        value = self._func(*key)
        self[key] = value
        return value


def fast_memoize_multiple_args(func):
    f = cdict2(func).__getitem__
    return lambda *args: f(args)

# ------------------------------------------p2pool pack-TYPES------------------------------------------
# TODO: remove unnecessary


class EarlyEnd(Exception):
    pass


class LateEnd(Exception):
    pass


def remaining(sio):
    here = sio.tell()
    sio.seek(0, os.SEEK_END)
    end = sio.tell()
    sio.seek(here)
    return end - here


class Type(object):
    __slots__ = []

    def __hash__(self):
        rval = getattr(self, '_hash', None)
        if rval is None:
            try:
                rval = self._hash = hash(
                    (type(self), frozenset(self.__dict__.items())))
            except:
                print(self.__dict__)
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
        # print(obj)
        # if isinstance(obj,bytes):
        f = BytesIO()
        # else:
        #    f = StringIO.StringIO()
        self.write(f, obj)
        return f.getvalue()

    def unpack(self, data, ignore_trailing=False):
        if isinstance(data, (str, bytes)):
            data = StringIO.BytesIO(data)
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

#0 < VarIntType < 2^64


class VarIntType(Type):
    def read(self, file):
        data = file.read(1)
        first = ord(data)
        if first < 0xfd:
            return first
        if first == 0xfd:
            desc, length, minimum = '<H', 2, 0xfd
        elif first == 0xfe:
            desc, length, minimum = '<I', 4, 2**16
        elif first == 0xff:
            desc, length, minimum = '<Q', 8, 2**32
        else:
            raise AssertionError()
        data2 = file.read(length)
        res, = struct.unpack(desc, data2)
        if res < minimum:
            raise AssertionError('VarInt not canonically packed')
        return res

    def write(self, file, item):
        if item < 0xfd:
            return file.write(struct.pack('<B', item))
        elif item <= 0xffff:
            return file.write(struct.pack('<BH', 0xfd, item))
        elif item <= 0xffffffff:
            return file.write(struct.pack('<BI', 0xfe, item))
        elif item <= 0xffffffffffffffff:
            return file.write(struct.pack('<BQ', 0xff, item))
        else:
            raise ValueError('int too large for varint')


class VarStrType(Type):
    _inner_size = VarIntType()

    def read(self, file):
        length = self._inner_size.read(file)
        return file.read(length)#.decode('utf-8')

    def write(self, file, item):
        self._inner_size.write(file, len(item))
        file.write(item.encode())#.encode('cp1251')#.encode())

class FixedStrType(Type):
    def __init__(self, length):
        self.length = length

    def read(self, file):
        return file.read(self.length).decode('cp1251')#.decode('ascii')

    def write(self, file, item):
        if len(item) != self.length:
            raise ValueError('incorrect length item!')
        file.write(item).encode('cp1251')

class EnumType(Type):
    def __init__(self, inner, pack_to_unpack):
        self.inner = inner
        self.pack_to_unpack = pack_to_unpack

        self.unpack_to_pack = {}
        for k, v in pack_to_unpack.items():
            if v in self.unpack_to_pack:
                raise ValueError('duplicate value in pack_to_unpack')
            self.unpack_to_pack[v] = k

    def read(self, file):
        data = self.inner.read(file)
        if data not in self.pack_to_unpack:
            raise ValueError('enum data (%r) not in pack_to_unpack (%r)' % (
                data, self.pack_to_unpack))
        return self.pack_to_unpack[data]

    def write(self, file, item):
        if item not in self.unpack_to_pack:
            raise ValueError('enum item (%r) not in unpack_to_pack (%r)' % (
                item, self.unpack_to_pack))
        self.inner.write(file, self.unpack_to_pack[item])


class ListType(Type):
    _inner_size = VarIntType()

    def __init__(self, type, mul=1):
        self.type = type
        self.mul = mul

    def read(self, file):
        length = self._inner_size.read(file)
        length *= self.mul
        res = [self.type.read(file) for i in range(length)]
        return res

    def write(self, file, item):
        assert len(item) % self.mul == 0
        self._inner_size.write(file, len(item)//self.mul)
        for subitem in item:
            self.type.write(file, subitem)


class StructType(Type):
    __slots__ = 'desc length'.split(' ')

    def _pack(self, obj):
        f = BytesIO()  # StringIO.StringIO()
        self.write(f, obj)
        return f.getvalue()

    def __init__(self, desc):
        self.desc = desc
        self.length = struct.calcsize(self.desc)

    def read(self, file):
        data = file.read(self.length)
        result = struct.unpack(self.desc, data)[0]
        if (self.length == 8):
            result = str(result)
        return result

    def write(self, file, item):
        file.write(struct.pack(self.desc, item))


@fast_memoize_multiple_args
class IntType(Type):
    __slots__ = 'bytes step format_str max'.split(' ')

    def _pack(self, obj):
        f = BytesIO()  # StringIO.StringIO()
        # print('_pack int type')
        self.write(f, obj)
        return f.getvalue()

    def __new__(cls, bits, endianness='little'):
        assert bits % 8 == 0
        assert endianness in ['little', 'big']
        if bits in [8, 16, 32, 64]:
            return StructType(('<' if endianness == 'little' else '>') + {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}[bits])
        else:
            return Type.__new__(cls)

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
        return str(int(b2a_hex(data[::self.step]), 16))

    def write(self, file, item, a2b_hex=binascii.a2b_hex):
        if self.bytes == 0:
            return None
        if not 0 <= item < self.max:
            raise ValueError('invalid int value - %r' % (item,))
        file.write(a2b_hex(self.format_str % (item,))[::self.step])


class IPV6AddressType(Type):
    def read(self, file):
        data = file.read(16)
        if data[:12] == codecs.decode('00000000000000000000ffff', 'hex'):
            return '.'.join(str(x) for x in data[12:])
        return ':'.join(data[i*2:(i+1)*2].encode('hex') for i in range(8))

    def write(self, file, item):
        if ':' in item:
            data = codecs.decode(''.join(item.replace(':', '')), 'hex')
        else:
            bits = list(map(int, item.split('.')))
            if len(bits) != 4:
                raise ValueError('invalid address: %r' % (bits,))

            dataA = bytes()
            for x in [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255]:
                dataA += chr(x).encode('latin-1')
            dataB = bytes()
            for x in bits:
                dataB += struct.pack('B', x)
            data = dataA + dataB
        assert len(data) == 16, len(data)
        file.write(data)


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
            # def __iter__(self):
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
            item[key] = type_.read(file)
        return item

    def write(self, file, item):
        assert set(item.keys()) >= self.field_names
        for key, type_ in self.fields:
            type_.write(file, item[key])


class PossiblyNoneType(Type):
    def __init__(self, none_value, inner):
        self.none_value = none_value
        self.inner = inner

    def read(self, file):
        value = self.inner.read(file)
        return None if value == self.none_value else value

    def write(self, file, item):
        if item == self.none_value:
            raise ValueError('none_value used')
        self.inner.write(file, self.none_value if item is None else item)


class FloatingInteger(object):
    __slots__ = ['bits', '_target']

    @classmethod
    def from_target_upper_bound(cls, target):
        n = natural_to_string(target)
        if n and ord(n[0]) >= 128:
            n = '\x00' + n
        bits2 = (chr(len(n)) + (n + 3*chr(0))[:3])[::-1]
        bits = IntType(32).unpack(bits2)
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
            res = self._target = shift_left(
                self.bits & 0x00ffffff, 8 * ((self.bits >> 24) - 3))
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
        # return 'FloatingInteger(bits=%s, target=%s)' % (hex(self.bits), hex(self.target))
        return '{\"bits\":\"%s\", \"target\":\"%s\"}' % (hex(self.bits), hex(self.target))

class FloatingIntegerType(Type):
    _inner = IntType(32)

    def read(self, file):
        bits = self._inner.read(file)
        return FloatingInteger(bits)

    def write(self, file, item):
        return self._inner.write(file, item.bits)

# ---new


def is_segwit_tx(tx):
    return tx.get('marker', -1) == 0 and tx.get('flag', -1) >= 1

# tx's---------------------
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
            next = self._wtx_type.read(file)  # _wtx_type
            witness = [None]*len(next['tx_ins'])
            for i in range(len(next['tx_ins'])):
                witness[i] = self._witness_type.read(file)
            locktime = self._int_type.read(file)
            return dict(version=version, marker=marker, flag=next['flag'], tx_ins=next['tx_ins'], tx_outs=next['tx_outs'], witness=witness, lock_time=locktime)
        else:
            tx_ins = [None]*marker
            for i in range(marker):
                tx_ins[i] = tx_in_type.read(file)
            next = self._ntx_type.read(file)  # _ntx_type
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

merkle_record_type = ComposedType([
    ('left', IntType(256)),
    ('right', IntType(256)),
])

# ------------------------------------------ Share Types --------------------------------------------
hash_link_type = ComposedType([
    ('state', FixedStrType(32)),
    ('extra_data', FixedStrType(0)), # bit of a hack, but since the donation script is at the end, const_ending is long enough to always make this empty
    ('length', VarIntType()),
])

def is_segwit_activated(version):
    segwit_activation_version = SEGWIT_ACTIVATION_VERSION
    return version >= segwit_activation_version and segwit_activation_version > 0

class BaseShare(object):
    VERSION = 0

    small_block_header_type = ComposedType([
        ('version', VarIntType()),
        ('previous_block', PossiblyNoneType(0, IntType(256))),
        ('timestamp', IntType(32)),
        ('bits', FloatingIntegerType()),
        ('nonce', IntType(32)),
    ])

    cached_types = None

    @classmethod
    def get_dynamic_types(cls):
        if not cls.cached_types == None:
            return cls.cached_types
        t = dict(share_info_type=None, share_type=None, ref_type=None)
        segwit_data = ('segwit_data', PossiblyNoneType(dict(txid_merkle_link=dict(branch=[], index=0), wtxid_merkle_root=2**256-1), ComposedType([
            ('txid_merkle_link', ComposedType([
                ('branch', ListType(IntType(256))),
                ('index', IntType(0)), # it will always be 0
            ])),
            ('wtxid_merkle_root', IntType(256))
        ])))
        t['share_info_type'] = ComposedType([
            ('share_data', ComposedType([
                ('previous_share_hash', PossiblyNoneType(0, IntType(256))),
                ('coinbase', VarStrType()),
                ('nonce', IntType(32)),
                ('pubkey_hash', IntType(160)),
                ('subsidy', IntType(64)),
                ('donation', IntType(16)),
                ('stale_info', EnumType(IntType(8), dict((k, {0: None, 253: 'orphan', 254: 'doa'}.get(k, 'unk%i' % (k,))) for k in range(256)))),
                ('desired_version', VarIntType()),
            ]))] + ([segwit_data] if is_segwit_activated(cls.VERSION) else []) + [
            ('new_transaction_hashes', ListType(IntType(256))),
            ('transaction_hash_refs', ListType(VarIntType(), 2)), # pairs of share_count, tx_count
            ('far_share_hash', PossiblyNoneType(0, IntType(256))),
            ('max_bits', FloatingIntegerType()),
            ('bits', FloatingIntegerType()),
            ('timestamp', IntType(32)),
            ('absheight', IntType(32)),
            ('abswork', IntType(128)),
        ])
        t['share_type'] = ComposedType([
            ('min_header', cls.small_block_header_type),
            ('share_info', t['share_info_type']),
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
        t['ref_type'] = ComposedType([
            ('identifier', FixedStrType(64//8)),
            ('share_info', t['share_info_type']),
        ])
        cls.cached_types = t
        return t

class NewShare(BaseShare):
    VERSION = 33


class PreSegwitShare(BaseShare):
    VERSION = 32

class Share(BaseShare):
    VERSION = 17

share_versions = {s.VERSION:s for s in [NewShare, PreSegwitShare, Share]}

# ------------------------------------------messages and types---------------------------------------
# TODO:
# block_header_type = ComposedType([
#     ('version', IntType(32)),
#     ('previous_block', PossiblyNoneType(0, IntType(256))),
#     ('merkle_root', IntType(256)),
#     ('timestamp', IntType(32)),
#     ('bits', FloatingIntegerType()),  # todo Check this new type
#     ('nonce', IntType(32)),
# ])
# -------------------------------------------Global-Type----------------------------------------------
class TYPE:

    tx_type = TransactionType()
    # messages and types-------

    address_type = ComposedType([
        ('services', IntType(64)),
        ('address', IPV6AddressType()),
        ('port', IntType(16, 'big')),
    ])

    share_type = ComposedType([
        ('type', VarIntType()),
        ('contents', VarStrType()),
    ])

    message_error = ComposedType([
        ('issue', VarStrType())
    ])

    message_version = ComposedType([
        ('version', IntType(32)),
        ('services', IntType(64)),
        ('addr_to', address_type),
        ('addr_from', address_type),
        ('nonce', IntType(64)),
        ('sub_version', VarStrType()),
        ('mode', IntType(32)),  # always 1 for legacy compatibility
        ('best_share_hash', PossiblyNoneType(0, IntType(256))),
    ])

    message_ping = ComposedType([])

    message_addrme = ComposedType([('port', IntType(16))])

    message_addrs = ComposedType([
        ('addrs', ListType(ComposedType([
            ('timestamp', IntType(64)),
            ('address', address_type),  # todo check it out
        ]))),
    ])

    message_getaddrs = ComposedType([
        ('count', IntType(32)),
    ])

    #new

    message_shares = ComposedType([
        ('shares', ListType(share_type)),
    ])

    message_command_number = {
        'error': 9990,
        'version': 0,
        'ping': 1,
        'addrme': 2,
        'addrs': 3,
        'getaddrs': 4,
        #new:
        'shares' : 5, 
        'sharereq' : 6,
        'sharereply': 7,
        'best_block' : 8, #todo
        'have_tx' : 9,
        'losing_tx' : 10
    }

    @classmethod
    def get_type(cls, name_type):
        return getattr(cls, name_type, None)

#==============================

    @classmethod
    def get_value_version(cls, json_value):
        json_value["best_share_hash"] = int(json_value["best_share_hash"], 16)
        return json_value

    # @classmethod
    # def get_value_shares(cls, json_value):

    #     return json_value
#==============================

    @classmethod
    def get_json_dict(cls, raw_json):
        '''
            json_str -> dict
            +
            Пост-обработка спецефичных структур
        '''
        _json_dict = json.loads(raw_json)
        name_type = _json_dict["name_type"]
        value_func = getattr(cls, "get_value_" + name_type, None)

        value = {}
        if value_func is None:
            print("value_func is None!")
            value = _json_dict["value"]
        else:
            value = value_func(_json_dict["value"])

        return name_type, value

    # @classmethod
    # def
#===============================|
############shares##############|
#===============================|

    @classmethod
    def error_load_share(cls, error_data):
        return {"error":error_data}

    @classmethod
    def load_share(cls, share):
        if share['type'] in share_versions:
            return share_versions[share['type']].get_dynamic_types()['share_type'].unpack(share['contents'])
        elif share['type'] < 17:
            return cls.error_load_share("sent an obsolete share")
        else:
            return cls.error_load_share("unknown share type: {0}".format(share['type']))

    @classmethod
    def post_process_shares(cls, value):
        result = []
        for _share in value["shares"]:
            result_share = dict()
            result_share["type"] = _share["type"]
            result_share["contents"] = cls.load_share(_share)
            #result_share["contents"]["hash_link"]["state"] = list(bytearray(result_share["contents"]["hash_link"]["state"])) #decode('cp1251')???
            result_share["contents"]["share_info"]["share_data"]["coinbase"] = result_share["contents"]["share_info"]["share_data"]["coinbase"].decode("cp1251")
            result_share["contents"]["share_info"]["share_data"]["stale_info"] = {None:0, 'orphan':253 , 'doa':254 }.get(result_share["contents"]["share_info"]["share_data"]["stale_info"], 0)
            result += [result_share]

        return result

#==============================

    @classmethod
    def post_process(cls, name_type, value):
        '''
        Обработка сообщений p2pool -> c2pool
        '''
        post_process_func = getattr(cls, "post_process_" + name_type, None)
        if post_process_func:
            value = post_process_func(value)
        else:
            pass
            #print("post_process_func is None!")

        return value



#==============================
# -------------------------------------------Methods--------------------------------------------------


def bytes_to_char_stringstream(_bytes):
    chars = [str(byte) for byte in _bytes]
    return ' '.join(chars)


def serialize(raw_json):
    _json = TYPE.get_json_dict(raw_json)
    _type = TYPE.get_type(json['name_type'])
    if _type is None:
        return 'error_type'
    result = bytes_to_char_stringstream(_type.pack(_json['value']))
    return result


def serialize_msg(raw_json):
    """
        called when we send msg from c2pool to p2pool
    """
    # print("serialize_msg started")
    name_type, value = TYPE.get_json_dict(raw_json)
    # print("name_type = {0}, value = {1}".format(name_type, value))
    _type = TYPE.get_type("message_"+name_type)

    # if error command
    if _type is None:
        return 'ERROR'
    command = bytes(name_type, encoding='ISO-8859-1')

    payload = _type.pack(value)

    # print('SEND_PAYLOAD: {0}'.format(payload))

    result = struct.pack('<12sI', command, len(
        payload)) + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] + payload
    # print('FROM_PYTHON: send [result]: {0}, len: {1}'.format(result, len(result)))
    # print('py_send result: {0}, after convert: {1}, len: {2}'.format(result, bytes_to_char_stringstream(result), len(result)))
    return bytes_to_char_stringstream(result)

#test
#print(serialize_msg("{\"name_type\":\"version\",\"value\":{\"version\":3301,\"services\":0,\"addr_to\":{\"services\":3,\"address\":\"4.5.6.7\",\"port\":8},\"addr_from\":{\"services\":9,\"address\":\"10.11.12.13\",\"port\":14},\"nonce\":6535423,\"sub_version\":\"16\",\"mode\":18,\"best_share_hash\":\"0000000000000000000000000000000000000000000000000000000000000123\"}}"))

def generate_error_json(command, error_text):
    return str({"command":command, "error_text":error_text}).replace("\'", "\"")

def deserialize(name_type, _bytes_array):
    _type = TYPE.get_type(name_type)
    if _type is None:
        return 'error_type'
    _obj_dict = _type.unpack(_bytes_array)
    result = str(_obj_dict)
    return result

def deserialize_msg(_command, checksum, payload):
    # print('_command = {0}'.format(_command))
    # print('checksum = {0}'.format(checksum))
    # print('payload = {0}'.format(payload))

    command = _command.rstrip('\0')
    # payload = bytes(_payload, encoding = 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')
    # checksum = bytes(checksum, encoding = 'ISO-8859-1').decode('unicode-escape').encode('ISO-8859-1')

    # checksum check
    if not checksum is None:
        if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
            print("getted payload checksum:'{0}'; getted checksum:'{1}'; real checksum:'{2}'".format(
                hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4], checksum, checksum_for_test_receive()))
            return generate_error_json(command, "checksum check = false")
    # ------------

    type_ = TYPE.get_type('message_' + command)
    if type_ is None:
        print("type not found")
        return generate_error_json(command, "message type not founded")

    value = TYPE.post_process(command, type_.unpack(payload))

    result = {
        'name_type': TYPE.message_command_number[command],
        'value': value
    }
    #print(result)
    return str(result).replace("\'", "\"")

#print(deserialize_msg("version", b"\x95Y\xa8R", b'\xe5\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\n\n\n\x01\x9b\xdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\n\n\n\n\x13\xa0\x1cinfK\x03\xa8%\x14fa6c7cd-dirty-c2pool\x01\x00\x00\x00\x87^\xbd\xf1\x1c\x93y\xe9x\x1a\x16\xa6\xa8\x0b\x049\x99\xfe\x91\xf4\xe6xqW%"tT\x05p\x1a\x0e'))

def packed_size(raw_json):
    _json = TYPE.get_json_dict(raw_json)
    _type = TYPE.get_type(_json['name_type'])
    if _type is None:
        return 'error_type'
    result = _type.packed_size(_json['value'])
    return result


def payload_length(raw_json):
    _json = TYPE.get_json_dict(raw_json)
    _type = TYPE.get_type(json['name_type'])
    if _type is None:
        return '-1'  # todo: обработка
    result = len(_type.pack(_json['value']))
    return str(result)


def receive_length(msg):
    # print("receive_length")
    # print(msg)
    length, = struct.unpack('<I', msg)
    # print('length = {0}'.format(length))
    return str(length)

# ------------------------------------------FOR C++ DEBUG----------------------------------

def debug_log(char_array):
    print("debug_log: {0}".format(str(char_array)))

def is_worked():
    return 9001
# ------------------------------------------FOR-UNIT-TESTS-C++-----------------------------

def IntType256_test(value_hex):
    num = int(value_hex, 16)
    packed = IntType(256).pack(num)
    return bytes_to_char_stringstream(packed)

#print(IntType256_test("fffffff"))


# ------------------------------------------TESTS------------------------------------------
"""
def TEST_PACK_UNPACK():
    arrAddrs = [(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)]

    addrs = [
        dict(
            timestamp=int(host+port),
            address=dict(
                services=host,
                address='192.168.1.1',
                port=port,),) for host, port in arrAddrs]

    test_message = ComposedType([
        ('version', IntType(32)),
        ('services', IntType(64)),
        ('sub_version', VarStrType()),
        ('best_share_hash', PossiblyNoneType(0, IntType(256))),
        ('addrs', ListType(ComposedType([
            ('timestamp', IntType(64)),
            ('address', address_type),
        ])))
    ])

    dict_test_message = {'version': 1,
                         'services': 2,
                         'sub_version': "STRING",
                         'best_share_hash': 3,
                         'addrs': addrs
                         }

    packed = test_message.pack(dict_test_message)
    print(packed)
    unpacked = test_message.unpack(packed)
    print(unpacked)
    print(dict(unpacked).values())


def TEST_SHA256():
    import hashlib
    data = 'As Bitcoin relies on 80 byte header hashes, we want to have an example for that.'.encode(
        'utf-8')
    print(hashlib.sha256(data).hexdigest() ==
          '7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743')


def TEST_UNPACKRES():
    t = UnpackResult()

    t += 123
    t += 'test123test'
    t += (123, 'asd')
    t += {1: '23', '23': 1}

    print(t)

# TEST_SHA256()
# TEST_PACK_UNPACK()
# TEST_UNPACKRES()
"""


# debug_log('\x83\xe6],\x81\xbfmhversion\x00\x00\x00\x00\x00\x7f\x00\x00\x00\xeeoH\xb7\xe5\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xb0q\xed\xa2\xe8\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xc0\xa8\n\n\x13\xa0\xdeD(\x9f#\xb3oz\x128222e87-c2pool.bit\x01\x00\x00\x00\tc\x9d\x1c*\xad\x84I\xe4\xa8L\xb7\xa7D\x94\x0b\x0e\xc7\x01Q\xa7\xcdZ^\x9d\x18a3Rc\x82\xd2')
# print(send('version','1;2;3,4.5.6.7,8;9,10.11.12.13,14;1008386737136591102;16;17;18'))
# print(send('addrme','80'))
# print(send('getaddrs','3'))
# print(send('addrs','1;2,3.4.5.6,7+8;9,10.11.12.13,14'))
# print(payload_length('addrs','1;2,3.4.5.6,7+8;9,10.11.12.13,14'))
# res = b''
# for i in send('version','1;2;3,4.5.6.7,8;9,10.11.12.13,14;15;16;17;18').split(' '):
#     res += bytes(chr(int(i)), encoding = 'utf-8')
# print(res)

# print(data_for_test_receive())
# print(checksum_for_test_receive())
# print(length_for_test_receive())


# print(VarIntType().pack(2**64-1))

# FI = FloatingInteger(2**32-1)
# print(FI)
# print(FloatingIntegerType().pack(FI))
# print(FixedStrType(0).pack(b"1233"))

# print(IntType(0).pack(0))

#print(PossiblyNoneType(0, IntType(8)).pack(0))

#print(ListType(VarIntType(), 2).pack([12,23,23,23]))
'''
tx_type = TYPE.get_type("tx_type")
tx_packed = tx_type.pack({
    'version':1, 
    'tx_outs': [{
        'value':2,
        'script':'test_script'}],
    'tx_ins': [{
        'sequence':1,
        'script':'tx_ins_test_script',
        'previous_output':{
            'hash':123,
            'index':321}}],
    'lock_time':199,
})
print(tx_packed)
tx_unpacked = tx_type.unpack(tx_packed)
print(tx_unpacked)

segwit_tx_packed = tx_type.pack({
    'version':1, 
    'tx_outs': [{
        'value':2,
        'script':'test_script'}],
    'tx_ins': [{
        'sequence':1,
        'script':'tx_ins_test_script',
        'previous_output':{
            'hash':123,
            'index':321}}],
    'lock_time':199,
    
    'marker': 0,
    'flag': 1,
    'witness':[{'test_witness'}]
})
print('____________')
print(segwit_tx_packed)
segwit_tx_unpacked = tx_type.unpack(segwit_tx_packed)
print(type(segwit_tx_unpacked))
print(tx_type.packed_size({
    'version':1, 
    'tx_outs': [{
        'value':2,
        'script':'test_script'}],
    'tx_ins': [{
        'sequence':1,
        'script':'tx_ins_test_script',
        'previous_output':{
            'hash':123,
            'index':321}}],
    'lock_time':199,
    
    'marker': 0,
    'flag': 1,
    'witness':[{'test_witne2323ss'}]
}))
'''
#print(IntType(256).unpack(b'[P2POOL][P2POOL][P2POOL][P2POOL]'))

#===============================================================
#message_shares test:
''' 
Share:
21fd4301fe02000020f51da17b9b389c625fb68d63ececb186766af63f683870c9bc11626880a9f1213c92a9601bc07b1a0390d63c234a52db85860ff68e83b3291e4d9b08b16c6c39131a8d3f41fa83ac18b587413d042134c6002cfabe6d6d907d3076c59502c2afeef8f5ccd99382468eaa27e7b1f62c606d6b2bbecc7ff201000000000000000a5f5f6332706f6f6c5f5f93a04c5a8a641f36c1dcdd259b5a57c1e695337c32ae5ac79c8b801b0c0000000000002100000000000000000000000000000000000000000000000000000000000000000000007774782ad351e8c18e6fe1449482475a1e73709d77180af2b5b35c45f6336bcd5925011d3ec7091c3c92a960ea750b00a77f8f057902c201000000000000000000000000000f00000064abd00beb727b99596c96bd7c89722196b8589aa7ef932368426e563aebb7adfdce0200


share_data = "21fd4301fe02000020f51da17b9b389c625fb68d63ececb186766af63f683870c9bc11626880a9f1213c92a9601bc07b1a0390d63c234a52db85860ff68e83b3291e4d9b08b16c6c39131a8d3f41fa83ac18b587413d042134c6002cfabe6d6d907d3076c59502c2afeef8f5ccd99382468eaa27e7b1f62c606d6b2bbecc7ff201000000000000000a5f5f6332706f6f6c5f5f93a04c5a8a641f36c1dcdd259b5a57c1e695337c32ae5ac79c8b801b0c0000000000002100000000000000000000000000000000000000000000000000000000000000000000007774782ad351e8c18e6fe1449482475a1e73709d77180af2b5b35c45f6336bcd5925011d3ec7091c3c92a960ea750b00a77f8f057902c201000000000000000000000000000f00000064abd00beb727b99596c96bd7c89722196b8589aa7ef932368426e563aebb7adfdce0200"
bytes_share_data = bytes.fromhex(share_data)

print(type(share_data))
print(share_data)

share_type_data = TYPE.share_type.unpack(bytes_share_data)
print("share_type_data:\n {0}".format(share_type_data))

msg_shares = TYPE.message_shares.pack({"shares":[share_type_data]})
manual_msg_shares = b"\x01!\xfdC\x01\xfe\x02\x00\x00 \xf5\x1d\xa1{\x9b8\x9cb_\xb6\x8dc\xec\xec\xb1\x86vj\xf6?h8p\xc9\xbc\x11bh\x80\xa9\xf1!<\x92\xa9`\x1b\xc0{\x1a\x03\x90\xd6<#JR\xdb\x85\x86\x0f\xf6\x8e\x83\xb3)\x1eM\x9b\x08\xb1ll9\x13\x1a\x8d?A\xfa\x83\xac\x18\xb5\x87A=\x04!4\xc6\x00,\xfa\xbemm\x90}0v\xc5\x95\x02\xc2\xaf\xee\xf8\xf5\xcc\xd9\x93\x82F\x8e\xaa'\xe7\xb1\xf6,`mk+\xbe\xcc\x7f\xf2\x01\x00\x00\x00\x00\x00\x00\x00\n__c2pool__\x93\xa0LZ\x8ad\x1f6\xc1\xdc\xdd%\x9bZW\xc1\xe6\x953|2\xaeZ\xc7\x9c\x8b\x80\x1b\x0c\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00wtx*\xd3Q\xe8\xc1\x8eo\xe1D\x94\x82GZ\x1esp\x9dw\x18\n\xf2\xb5\xb3\\E\xf63k\xcdY%\x01\x1d>\xc7\t\x1c<\x92\xa9`\xeau\x0b\x00\xa7\x7f\x8f\x05y\x02\xc2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00d\xab\xd0\x0b\xebr{\x99Yl\x96\xbd|\x89r!\x96\xb8X\x9a\xa7\xef\x93#hBnV:\xeb\xb7\xad\xfd\xce\x02\x00"
if msg_shares == manual_msg_shares:
    print("EQUAL!!!")
print("msg_shares:\n {0}".format(msg_shares))


manual_msg_shares = b"\x01!\xfdC\x01\xfe\x02\x00\x00 \xf5\x1d\xa1{\x9b8\x9cb_\xb6\x8dc\xec\xec\xb1\x86vj\xf6?h8p\xc9\xbc\x11bh\x80\xa9\xf1!<\x92\xa9`\x1b\xc0{\x1a\x03\x90\xd6<#JR\xdb\x85\x86\x0f\xf6\x8e\x83\xb3)\x1eM\x9b\x08\xb1ll9\x13\x1a\x8d?A\xfa\x83\xac\x18\xb5\x87A=\x04!4\xc6\x00,\xfa\xbemm\x90}0v\xc5\x95\x02\xc2\xaf\xee\xf8\xf5\xcc\xd9\x93\x82F\x8e\xaa'\xe7\xb1\xf6,`mk+\xbe\xcc\x7f\xf2\x01\x00\x00\x00\x00\x00\x00\x00\n__c2pool__\x93\xa0LZ\x8ad\x1f6\xc1\xdc\xdd%\x9bZW\xc1\xe6\x953|2\xaeZ\xc7\x9c\x8b\x80\x1b\x0c\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00wtx*\xd3Q\xe8\xc1\x8eo\xe1D\x94\x82GZ\x1esp\x9dw\x18\n\xf2\xb5\xb3\\E\xf63k\xcdY%\x01\x1d>\xc7\t\x1c<\x92\xa9`\xeau\x0b\x00\xa7\x7f\x8f\x05y\x02\xc2\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\x00\x00\x00d\xab\xd0\x0b\xebr{\x99Yl\x96\xbd|\x89r!\x96\xb8X\x9a\xa7\xef\x93#hBnV:\xeb\xb7\xad\xfd\xce\x02\x00"
deserialized_msg_shares = deserialize_msg("shares", None, manual_msg_shares)
print('deserialized_msg_shares:\n {0}'.format(deserialized_msg_shares))

# json_deserialized_msg_shares = json.loads(deserialized_msg_shares)
# print(type(json_deserialized_msg_shares))

#print("VarStrType coinbase unpack:\n {0}".format(VarStrType.unpack(deserialized_msg_shares["value"][0]["contents"]["share_data"]["coinbase"])))
'''
#===============================================================
# import hashlib
# _data = b"1"
# res_pow_func_test = IntType(256).unpack(hashlib.sha256(hashlib.sha256(_data).digest()).digest())
# print(res_pow_func_test)
#===============================================================

# packed_int256 = IntType(256).pack(int('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc', 16))
# res = b''
# for x in packed_int256:
#     print(int(x))
# print(" ")
# for x in '252 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 15'.split(' '):
#     print(int(x, 10))
#     print(bytes([int(x,10)]))
#     res += bytes([int(x,10)])
# print(res)
# print(packed_int256)
# print('Equal: {0}'.format(res == packed_int256))
# print(IntType(256).unpack(res))
# print(IntType(256).unpack(packed_int256))
#===============================================================

# first = int("fffffffffffffffffffffffffffffffffffffffffffffffff", 16)
# second = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16)
# _packed = merkle_record_type.pack(dict(left=first, right=second))
# res = []

# for x in _packed:
#     res += [x]
# print(res)

# #p2pool
# res1 = ' '.join([str(x) for x in res])
# #c2pool
# res2 = "255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 15 0 0 0 0 0 0 0 252 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 255 0"
# res_b = res2.split(" ")
# print(res1 == res2)

# print(res1)
# print(res2)

#print([ x for x in IntType(16).pack(100)])

# print(IntType(0).pack(2**568))
# print(FixedStrType(1).pack(b"s"))