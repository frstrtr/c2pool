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

        self.length += 8*len(data)

    def copy(self, data=''):
        return self.__class__(data, (self.state, self.buf, self.length))

    def digest(self):
        state = self.state
        buf = self.buf + '\x80' + '\x00'*((self.block_size - 9 - len(self.buf)) % self.block_size) + struct.pack('>Q', self.length)
        print([ord(x) for x in buf])
        for chunk in [buf[i:i + self.block_size] for i in xrange(0, len(buf), self.block_size)]:
            state = process(state, chunk)

        return state

    def hexdigest(self):
        return self.digest().encode('hex')

###########################

def random_bytes(length):
    return ''.join(chr(random.randrange(2**8)) for i in xrange(length))

def prefix_to_hash_link(prefix, const_ending=''):
    assert prefix.endswith(const_ending), (prefix, const_ending)
    x = sha256(prefix)
    print('buff len: {0}'.format(len(x.buf)))
    print('buff: {0}'.format(x.buf))
    return dict(state=x.state, extra_data=x.buf[:max(0, len(x.buf)-len(const_ending))], length=x.length//8)

def check_hash_link(hash_link, data, const_ending=''):
    extra_length = hash_link['length'] % (512//8)
    assert len(hash_link['extra_data']) == max(0, extra_length - len(const_ending))
    extra = (hash_link['extra_data'] + const_ending)[len(hash_link['extra_data']) + len(const_ending) - extra_length:]
    assert len(extra) == extra_length
    return hashlib.sha256(sha256(data, (hash_link['state'], extra, 8*hash_link['length'])).digest()).digest()

# d = random_bytes(random.randrange(2048))
# print(d)
# x = prefix_to_hash_link(d)
# print(x)
# res = check_hash_link(x, '')
# print(res)
# revert_res = prefix_to_hash_link(res)
# print(revert_res)

_initial_state = struct.pack('>8I', 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd12)

data = "123456789"

#(initial_state, '', 0)
_t1 = sha256(data, (_initial_state, '', 0))
t1 = _t1.digest()
print(t1)
t2 = hashlib.sha256(data).digest()
print(t2)
print(t1 == t2)
#####################################################
print("#"*16)
print("t1:")
print("digest: {0}".format(_t1.digest()))
print("state: {0}".format((_t1.state)))
print("buf: {0}".format((_t1.buf)))
print("length: {0}".format((_t1.length)))
_t3 = sha256(data, (initial_state, '1337', 0))
print("t3:")
print("digest: {0}".format(_t3.digest()))
print("state: {0}".format(_t3.state))
print("buf: {0}".format(_t3.buf))
print("length: {0}".format(_t3.length))
_t4 = sha256(data, (_initial_state, '1337', 100))
print("t4:")
print("digest: {0}".format(_t4.digest()))
print("state: {0}".format(_t4.state))
print("buf: {0}".format(_t4.buf))
print("length: {0}".format(_t4.length))

print("#"*16)
print("#"*16)
print("#"*16)

a = sha256("123456789")
print(a.hexdigest())
print('15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225')

b = sha256("1234567890", (_initial_state, '', 0))
print(b.hexdigest())
print('23de2ce70e77d80ba1c110071462e90e96710fd0b0ee3faa81b1d04b7fb58535')

print(b.buf)
print(b.length)

c = sha256("123456789", (_initial_state, '1234567890', 80))
print(c.hexdigest())
print('7c3c79a815ce2b9b7d0e6e7a0f3ec415903ca435ef0a9f55cdd7bad317f8f225')

initial_state2 = struct.pack('>8I', 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05644c, 0x1f83d9ab, 0x5be0cd12)
d = sha256("12345678901234ac", (initial_state2, '12345678901234ac', 128))
print(d.buf)
print(d.length)

print(hashlib.sha256(d.digest()).hexdigest())
print('209c335d5b5d3f5735d44b33ec1706091969060fddbdb26a080eb3569717fb9e')

##########################################################################
print("\n\nrand_test:")

rand_bytes = random_bytes(2048)
print("rand_bytes[hex]:")
print(rand_bytes.encode('hex'))

int_rand_bytes = []
for _i in rand_bytes:
    int_rand_bytes += [ord(_i)]

print(int_rand_bytes)

x = prefix_to_hash_link(rand_bytes)
print("x:")
print(x)

# print("//////////////////////")
# d1 = random_bytes(random.randrange(2048))
# d2 = random_bytes(random.randrange(2048))
# print(d1.encode('hex'))
# print(d2.encode('hex'))
# print((d1+d2).encode('hex'))