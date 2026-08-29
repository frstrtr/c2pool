#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <vector>

#include <boost/range/combine.hpp>
#include <boost/foreach.hpp>

#define POW2_32 4294967296

namespace c2pool::sha256
{
    std::vector<uint32_t> inline get_k()
    {
        std::vector<uint32_t> res{
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };

        return res;
    }

    uint32_t rightrotate(uint32_t x, uint32_t n)
    {
        return (x >> n) | (x << 32 - n) % POW2_32;
    }

    std::vector<unsigned char> process(auto state, auto chunk)
    {
        std::vector<uint32_t> w;
        //TODO: w = list(struct.unpack('>16I', chunk))

        for (int i = 16; i < 64; i++)
        {
            auto s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            auto s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w.push_back((w[i - 16] + s0 + w[i - 7] + s1) % POW2_32);
        }

        uint32_t a, b, c, d, e, f, g, h; //TODO: init
        std::vector<uint32_t> start_state; //TODO: init

        uint32_t k_i, w_i;
        BOOST_FOREACH(boost::tie(k_i, w_i), boost::combine(get_k(), w))
                    {
                        uint32_t t1 = (h + (rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)) +
                                       ((e & f) ^ (~e & g)) + k_i + w_i) % POW2_32;

                        a = (t1 + (rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) % POW2_32;
                        b = a;
                        c = b;
                        d = c;
                        e = (d + t1) % POW2_32;
                        f = e;
                        g = f;
                        h = g;
                    }

        std::vector<unsigned char> result; //TODO: init: struct.pack('>8I', *((x + y) % 2**32 for x, y in zip(start_state, [a, b, c, d, e, f, g, h])))

        return result;
    }

    void inline Initialize(uint32_t* s, uint32_t* custom_init_state = nullptr)
    {
        if (custom_init_state)
        {
            for (int i = 0; i < 8; i++, custom_init_state++)
            {
                s[i] = *custom_init_state;
            }
            return;
        }
        s[0] = 0x6a09e667ul;
        s[1] = 0xbb67ae85ul;
        s[2] = 0x3c6ef372ul;
        s[3] = 0xa54ff53aul;
        s[4] = 0x510e527ful;
        s[5] = 0x9b05688cul;
        s[6] = 0x1f83d9abul;
        s[7] = 0x5be0cd19ul;
    }

    class SHA256
    {
        const int digest_size = 256/8; // 32
        const int block_size = 512/8;  // 64

        std::vector<unsigned char> state;
        std::vector<unsigned char> buf;
        size_t length;

        void update(std::vector<unsigned char> _data)
        {
            auto _state = state;
            auto _buf = buf;
            _buf.insert(_buf.end(), _data.begin(), _data.end());

            state = _state;
            buf = _buf;

            length += 8*_data.size();
        }

        SHA256(std::vector<unsigned char> _data = {}, std::vector<unsigned char> _init_state = {}, std::vector<unsigned char> _buf = {}, size_t _length = 0)
        {
            state = _init_state;
            buf = _buf;
            length = _length;

            update(_data);
        }
    };
}

#undef POW2_32