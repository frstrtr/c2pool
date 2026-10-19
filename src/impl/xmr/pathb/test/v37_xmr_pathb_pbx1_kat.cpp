// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/v37_xmr_pathb_pbx1_kat.cpp
// PBX1 coinbase tx_extra:
//   (1) v16: 01 R[32] 02 04 n[4] 03 21 00 root[32], 74 B, byte by byte;
//   (2) v17 n = 1: same layout with D_e; v17 n >= 2: 04 varint(n) D_e..,
//       size 42 + V(n) + 32 n for n in {2, 127, 128, 511, 2342, 10000};
//   (3) round trips; mm_root of a side_data_v3 carried through;
//   (4) refused: 04 form at v16, 04 with n 0 / 1 / 10001, count above the
//       bytes present (before allocation), wrong nonce tag / length, wrong
//       merge-mining tag / length / depth, trailing byte, every truncation,
//       input above the cap; encoder refusals.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_pbx1.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

pb::Pbx1 make_pbx1(std::size_t n, std::uint8_t seed) {
    pb::Pbx1 x;
    for (std::size_t i = 0; i < n; ++i) x.keys.push_back(seq32(static_cast<std::uint8_t>(seed + i)));
    x.extra_nonce = {0xA1, 0xA2, 0xA3, 0xA4};
    x.mm_root = seq32(static_cast<std::uint8_t>(seed + 0x80));
    return x;
}

pb::Pbx1Error dec(std::uint8_t hf, const std::vector<std::uint8_t>& b, pb::Pbx1* out = nullptr) {
    pb::Pbx1 x;
    pb::Pbx1Error e = pb::decode_pbx1(hf, b.data(), b.size(), x);
    if (out) *out = x;
    return e;
}

std::vector<std::uint8_t> enc(std::uint8_t hf, const pb::Pbx1& x) {
    std::vector<std::uint8_t> out;
    pb::encode_pbx1(hf, x, out);
    return out;
}

bool layout_74(const std::vector<std::uint8_t>& b, const pb::Pbx1& x) {
    if (b.size() != 74) return false;
    if (b[0] != 0x01) return false;
    for (std::size_t i = 0; i < 32; ++i)
        if (b[1 + i] != x.keys[0][i]) return false;
    if (b[33] != 0x02 || b[34] != 0x04) return false;
    for (std::size_t i = 0; i < 4; ++i)
        if (b[35 + i] != x.extra_nonce[i]) return false;
    if (b[39] != 0x03 || b[40] != 0x21 || b[41] != 0x00) return false;
    for (std::size_t i = 0; i < 32; ++i)
        if (b[42 + i] != x.mm_root[i]) return false;
    return true;
}

}  // namespace

int main() {
    std::printf("v37_xmr_pathb_pbx1_kat\n");
    const std::uint8_t v16 = 16;
    const std::uint8_t v17 = 17;

    // (1) v16
    {
        const pb::Pbx1 x = make_pbx1(1, 0x10);
        const std::vector<std::uint8_t> b = enc(v16, x);
        check(layout_74(b, x), "v16 extra = 01 R[32] 02 04 n[4] 03 21 00 root[32] (74 B)");
        check(pb::pbx1_size(v16, 1) == 74, "pbx1_size(16, 1) = 74");
        pb::Pbx1 back;
        check(dec(v16, b, &back) == pb::Pbx1Error::None && back == x, "v16 round trip");
    }

    // (2) v17
    {
        const pb::Pbx1 x = make_pbx1(1, 0x20);
        const std::vector<std::uint8_t> b = enc(v17, x);
        check(layout_74(b, x), "v17 n = 1 extra = 01 D_e[32] 02 04 n[4] 03 21 00 root[32] (74 B)");
        check(pb::pbx1_size(v17, 1) == 74, "pbx1_size(17, 1) = 74");
        pb::Pbx1 back;
        check(dec(v17, b, &back) == pb::Pbx1Error::None && back == x, "v17 n = 1 round trip");

        for (std::size_t n : {2u, 127u, 128u, 511u, 2342u, 10000u}) {
            const pb::Pbx1 xn = make_pbx1(n, 0x30);
            const std::vector<std::uint8_t> bn = enc(v17, xn);
            const std::uint64_t want = 42 + pb::varint_len(n) + 32 * n;
            check(bn.size() == want && pb::pbx1_size(v17, n) == want,
                  "v17 n = " + std::to_string(n) + " size 42 + V(n) + 32 n");
            check(bn[0] == 0x04, "v17 n = " + std::to_string(n) + " starts with tag 04");
            const std::size_t vn = pb::varint_len(n);
            const std::size_t tail = 1 + vn + 32 * n;
            check(bn[tail] == 0x02 && bn[tail + 1] == 0x04 && bn[tail + 6] == 0x03 && bn[tail + 7] == 0x21
                          && bn[tail + 8] == 0x00,
                  "v17 n = " + std::to_string(n) + " nonce and merge-mining fields follow the keys");
            pb::Pbx1 bk;
            check(dec(v17, bn, &bk) == pb::Pbx1Error::None && bk == xn, "v17 n = " + std::to_string(n) + " round trip");
        }
        check(pb::varint_len(127) == 1 && pb::varint_len(128) == 2, "V(127) = 1, V(128) = 2");
    }

    // (3) mm_root of side data carried through PBX1
    {
        pb::Pbx1 x = make_pbx1(1, 0x40);
        const std::optional<pb::Hash32> mm = pb::mm_root_of(golden_side());
        check(mm.has_value(), "mm_root of the golden side data");
        x.mm_root = *mm;
        pb::Pbx1 back;
        check(dec(v16, enc(v16, x), &back) == pb::Pbx1Error::None && back.mm_root == *mm,
              "mm_root carried through the 03 field");
    }

    // (4) refusals
    {
        const std::vector<std::uint8_t> b16 = enc(v16, make_pbx1(1, 0x50));
        const std::vector<std::uint8_t> b17 = enc(v17, make_pbx1(3, 0x50));
        check(dec(v16, b17) != pb::Pbx1Error::None, "04 form refused at v16 (above the v16 cap)");
        std::vector<std::uint8_t> short04 = {0x04, 0x02};
        short04.insert(short04.end(), 64, 0x33);
        check(dec(v16, short04) == pb::Pbx1Error::KeyTag, "04 tag refused at v16");
        check(dec(v16, b16) == pb::Pbx1Error::None && dec(v17, b16) == pb::Pbx1Error::None,
              "01 form accepted at v16 and v17");

        std::vector<std::uint8_t> m = b17;
        m[1] = 1;  // n = 1 in the 04 form
        check(dec(v17, m) != pb::Pbx1Error::None, "04 form with n = 1 refused");
        m = {0x04, 0x01};
        m.insert(m.end(), 32, 0x11);
        m.insert(m.end(), b16.begin() + 33, b16.end());
        check(dec(v17, m) == pb::Pbx1Error::KeyCount, "04 form with n = 1 (consistent bytes) refused");
        m = {0x04, 0x00};
        m.insert(m.end(), b16.begin() + 33, b16.end());
        check(dec(v17, m) == pb::Pbx1Error::KeyCount, "04 form with n = 0 refused");
        m = {0x04, 0x91, 0x4e};  // n = 10001
        check(dec(v17, m) == pb::Pbx1Error::KeyCount, "04 form with n = 10001 refused before allocation");
        m = {0x04, 0x05};  // n = 5, three keys present
        m.insert(m.end(), 96, 0x22);
        check(dec(v17, m) == pb::Pbx1Error::Truncated, "count above the keys present refused before allocation");
        m = {0x05};
        m.insert(m.end(), b16.begin() + 1, b16.end());
        check(dec(v17, m) == pb::Pbx1Error::KeyTag, "unknown first tag refused");

        m = b16;
        m[33] = 0x03;
        check(dec(v16, m) == pb::Pbx1Error::NonceTag, "wrong nonce tag refused");
        m = b16;
        m[34] = 0x08;
        check(dec(v16, m) == pb::Pbx1Error::NonceLength, "nonce length 8 refused");
        m = b16;
        m[39] = 0x02;
        check(dec(v16, m) == pb::Pbx1Error::MergeMiningTag, "wrong merge-mining tag refused");
        m = b16;
        m[40] = 0x22;
        check(dec(v16, m) == pb::Pbx1Error::MergeMiningLength, "merge-mining length 0x22 refused");
        m = b16;
        m[41] = 0x01;
        check(dec(v16, m) == pb::Pbx1Error::MergeMiningDepth, "merge-mining depth 1 refused");
        m = b16;
        m.push_back(0);
        check(dec(v16, m) != pb::Pbx1Error::None, "trailing byte refused (v16 cap)");
        m = b17;
        m.push_back(0);
        check(dec(v17, m) == pb::Pbx1Error::Trailing, "trailing byte refused (v17)");

        bool trunc = true;
        for (const auto* src : {&b16, &b17}) {
            for (std::size_t n = 0; n < src->size(); ++n) {
                std::vector<std::uint8_t> t(src->begin(), src->begin() + static_cast<std::ptrdiff_t>(n));
                if (dec(v17, t) == pb::Pbx1Error::None) trunc = false;
            }
        }
        check(trunc, "every truncation refused");

        std::vector<std::uint8_t> huge(pb::pbx1_size(v17, pb::FCMP_PLUS_PLUS_MAX_MINER_OUTPUTS) + 1, 0);
        check(dec(v17, huge) == pb::Pbx1Error::OverCap, "input above the v17 cap refused");
        check(dec(v16, std::vector<std::uint8_t>(75, 0)) == pb::Pbx1Error::OverCap, "input above 74 B refused at v16");

        std::vector<std::uint8_t> sink;
        check(pb::encode_pbx1(v16, make_pbx1(2, 1), sink) == pb::Pbx1Error::Unencodable && sink.empty(),
              "encoder refuses two keys at v16");
        check(pb::encode_pbx1(v17, make_pbx1(0, 1), sink) == pb::Pbx1Error::Unencodable && sink.empty(),
              "encoder refuses zero keys");
        check(pb::encode_pbx1(v17, make_pbx1(10001, 1), sink) == pb::Pbx1Error::Unencodable && sink.empty(),
              "encoder refuses 10001 keys");
    }

    return finish("v37_xmr_pathb_pbx1_kat");
}
