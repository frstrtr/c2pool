// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_coinbase_extra_layout_kat (pathb_pbx1.hpp / pathb_miner_tx.hpp /
// pathb_emission.hpp, K24, PBX1): the hf 16 extra == 01 R[32] 02 04 nonce[4]
// 03 21 00 root[32] (74 B); the hf-16 miner tx serialized and weighed: weight
// (prefix + RCT type byte) <= OVH(16) + n x OUT(16, S_A) for n in {1, 127, 128,
// 511, 3747, 10000}, every amount at the largest varint S_A allows (== at n >=
// 128, the 2-byte vout count); hf 17 FORMAT: the 0x01 form for n = 1 and
// 04 varint(n) D_e.. 02 04 .. 03 21 00 .. for n >= 2, the weight bound as the
// format arithmetic OVH(17) + n x OUT(17); out_size(16,6e11) = 40,
// out_size(17,6e11) = 90, out_size(16,2^42) = 41; 16 mainnet miner txs of the
// tag shape 01[32] 02[4] 03[33] keep 88 / 89 bytes outside the outputs, their
// tx hashes recompute, the strict PBX1 decoder accepts the depth-0 extras and
// refuses the depth-8 ones.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_miner_tx.hpp"
#include "impl/xmr/pathb/pathb_pbx1.hpp"
#include "pathb_cb_sample.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

bool rd_varint(const std::vector<std::uint8_t>& b, std::size_t& pos, std::uint64_t& v) {
    v = 0;
    for (int shift = 0; shift < 64 && pos < b.size(); shift += 7) {
        const std::uint8_t c = b[pos++];
        v |= static_cast<std::uint64_t>(c & 0x7f) << shift;
        if (!(c & 0x80)) return true;
    }
    return false;
}

// The weight of an hf-16 miner tx with n outputs of amount `amount` at height h.
std::size_t weigh(std::uint64_t h, std::uint64_t n, std::uint64_t amount) {
    std::vector<pb::MinerOut> outs(n);
    for (std::uint64_t i = 0; i < n; ++i) {
        outs[i].amount = amount;
        outs[i].key = seq32(static_cast<std::uint8_t>(i));
        outs[i].view_tag = static_cast<std::uint8_t>(i);
    }
    const std::vector<std::uint8_t> extra =
            pb::canonical_tx_extra_hf16(seq32(0x11), {1, 2, 3, 4}, seq32(0x22));
    return pb::serialize_miner_tx_prefix(h, outs, extra).size() + 1;  // + RCT type byte
}

}  // namespace

int main() {
    pb::Hash32 r_tx = seq32(0x11), mm = seq32(0x22);
    std::array<std::uint8_t, pb::kExtraNonceBytes> nonce{0xDE, 0xAD, 0xBE, 0xEF};
    const std::vector<std::uint8_t> extra = pb::canonical_tx_extra_hf16(r_tx, nonce, mm);

    // the hf 16 byte form (74 B).
    check(extra.size() == 74, "hf16 PBX1 extra == 74 bytes");
    check(extra[0] == 0x01, "tag 0x01 TX_EXTRA_TAG_PUBKEY");
    bool rok = true;
    for (int i = 0; i < 32; ++i) rok = rok && extra[1 + i] == r_tx[i];
    check(rok, "R_tx[32] follows 0x01");
    check(extra[33] == 0x02 && extra[34] == 0x04, "0x02 TX_EXTRA_NONCE, length 4");
    bool nok = true;
    for (int i = 0; i < 4; ++i) nok = nok && extra[35 + i] == nonce[i];
    check(nok, "nonce[4] follows 02 04");
    check(extra[39] == 0x03 && extra[40] == 0x21 && extra[41] == 0x00, "0x03 MM tag, len 0x21, depth 0");
    bool mok = true;
    for (int i = 0; i < 32; ++i) mok = mok && extra[42 + i] == mm[i];
    check(mok, "mm_root[32] closes the extra");

    // out_size per hf / S_A (ruling 17 H-3 / 20 Q-G).
    const std::uint64_t s6e11 = 600000000000ull;
    const std::uint64_t s2p42 = std::uint64_t{1} << 42;
    check(pb::out_size(16, s6e11) == 40, "out_size(16, 6e11) == 40");
    check(pb::out_size(17, s6e11) == 90, "out_size(17, 6e11) == 90");
    check(pb::out_size(16, s2p42) == 41, "out_size(16, 2^42) == 41");

    // the hf-16 miner tx serialized and weighed (K24): every amount at the largest
    // value of S_A's varint length, h at mainnet scale.
    const std::uint64_t h = 3800000;
    for (const std::uint64_t s_a : {s6e11, s2p42}) {
        const std::uint64_t amount = (std::uint64_t{1} << (7 * pb::varint_len(s_a))) - 1;
        check(pb::varint_len(amount) == pb::varint_len(s_a), "the largest amount of S_A's varint length");
        for (const std::uint64_t n : {std::uint64_t{1}, std::uint64_t{127}, std::uint64_t{128}, std::uint64_t{511},
                                      std::uint64_t{3747}, std::uint64_t{10000}}) {
            const std::size_t weight = weigh(h, n, amount);
            const std::uint64_t bound = pb::ovh(16) + n * pb::out_size(16, s_a);
            const std::string tag = "hf16 n " + std::to_string(n) + ", S_A " + std::to_string(s_a);
            check(weight <= bound, tag + ": weight <= OVH + n x OUT");
            if (n >= 128)
                check(weight == bound, tag + ": weight == OVH + n x OUT (2-byte vout count)");
            else
                check(weight + 1 == bound, tag + ": weight == OVH + n x OUT - 1 (1-byte vout count)");
        }
    }

    // hf 17 FORMAT (R-7: no Carrot coinbase serialized before O-01).
    {
        pb::Pbx1 one;
        one.keys = {seq32(0xD0)};
        one.extra_nonce = nonce;
        one.mm_root = mm;
        std::vector<std::uint8_t> e1;
        check(pb::encode_pbx1(17, one, e1) == pb::Pbx1Error::None && e1.size() == 74 && e1[0] == 0x01
                      && e1.size() == pb::pbx1_size(17, 1),
              "hf17 n = 1: 01 D_e[32] 02 04 nonce 03 21 00 mm_root (74 B)");
        for (const std::uint64_t n : {std::uint64_t{2}, std::uint64_t{128}}) {
            pb::Pbx1 x;
            for (std::uint64_t i = 0; i < n; ++i) x.keys.push_back(seq32(static_cast<std::uint8_t>(0x30 + i)));
            x.extra_nonce = nonce;
            x.mm_root = mm;
            std::vector<std::uint8_t> e;
            const bool ok = pb::encode_pbx1(17, x, e) == pb::Pbx1Error::None;
            std::size_t pos = 1;
            std::uint64_t count = 0;
            const bool head = ok && e[0] == pb::TX_EXTRA_TAG_ADDITIONAL_PUBKEYS && rd_varint(e, pos, count) && count == n;
            const std::size_t tail = pos + 32 * n;
            const bool keys = head && std::memcmp(e.data() + pos, x.keys[0].data(), 32) == 0
                              && std::memcmp(e.data() + tail - 32, x.keys[n - 1].data(), 32) == 0;
            const bool rest = keys && e.size() == tail + 6 + 35 && e[tail] == 0x02 && e[tail + 1] == 0x04
                              && e[tail + 6] == 0x03 && e[tail + 7] == 0x21 && e[tail + 8] == 0x00
                              && e.size() == pb::pbx1_size(17, n);
            check(rest, "hf17 n " + std::to_string(n) + ": 04 varint(n) D_e.. 02 04 .. 03 21 00 ..");
            pb::Pbx1 back;
            check(pb::decode_pbx1(17, e.data(), e.size(), back) == pb::Pbx1Error::None && back == x,
                  "hf17 n " + std::to_string(n) + ": decode(encode) round trip");
        }
        for (const std::uint64_t n : {std::uint64_t{1}, std::uint64_t{127}, std::uint64_t{128}, std::uint64_t{511},
                                      std::uint64_t{3747}, std::uint64_t{10000}}) {
            const std::uint64_t w16 = pb::ovh(16) + n * pb::out_size(16, s6e11);
            const std::uint64_t w17 = pb::ovh(17) + n * pb::out_size(17, s6e11);
            check(w16 == 89 + n * 40, "hf16 coinbase weight bound OVH + n x OUT");
            check(w17 == 61 + n * 90, "hf17 coinbase weight bound OVH + n x OUT (format arithmetic)");
        }
    }

    // 16 mainnet miner txs of the tag shape 01[32] 02[4] 03[33].
    std::size_t depth0 = 0, depth8 = 0, big = 0;
    for (const cb_sample::MinerTxSample& s : cb_sample::kSample) {
        const std::string tag = "mainnet " + std::to_string(s.height);
        const std::vector<std::uint8_t> tx = unhex(s.miner_tx);
        std::size_t pos = 0;
        std::uint64_t v = 0, unlock = 0, vin = 0, height = 0, n = 0;
        bool ok = rd_varint(tx, pos, v) && v == 2 && rd_varint(tx, pos, unlock) && rd_varint(tx, pos, vin) && vin == 1
                  && pos < tx.size() && tx[pos++] == 0xff && rd_varint(tx, pos, height) && height == s.height
                  && unlock == height + pb::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW && rd_varint(tx, pos, n);
        std::size_t out_bytes = 0;
        std::vector<pb::MinerOut> outs;
        for (std::uint64_t i = 0; ok && i < n; ++i) {
            const std::size_t start = pos;
            pb::MinerOut o;
            ok = rd_varint(tx, pos, o.amount) && pos + 34 <= tx.size() && tx[pos] == 0x03;
            if (!ok) break;
            std::memcpy(o.key.data(), tx.data() + pos + 1, 32);
            o.view_tag = tx[pos + 33];
            pos += 34;
            out_bytes += pos - start;
            outs.push_back(o);
        }
        std::uint64_t ne = 0;
        ok = ok && rd_varint(tx, pos, ne) && pos + ne + 1 == tx.size() && tx.back() == 0x00;
        check(ok, tag + ": parses (prefix || RCT type 0)");
        if (!ok) continue;
        const std::vector<std::uint8_t> ex(tx.begin() + static_cast<std::ptrdiff_t>(pos),
                                           tx.begin() + static_cast<std::ptrdiff_t>(pos + ne));
        check(ex.size() == 74 && ex[0] == 0x01 && ex[33] == 0x02 && ex[34] == 4 && ex[39] == 0x03 && ex[40] == 33,
              tag + ": tag / length shape 01[32] 02[4] 03[33]");
        const std::size_t outside = tx.size() - out_bytes;
        check(outside == (n >= 128 ? 89u : 88u), tag + ": " + std::to_string(outside) + " bytes outside the outputs");
        const std::vector<std::uint8_t> pre = pb::serialize_miner_tx_prefix(height, outs, ex);
        check(pre.size() + 1 == tx.size() && std::equal(pre.begin(), pre.end(), tx.begin()),
              tag + ": serialize_miner_tx_prefix == the chain's prefix");
        check(hex32(pb::miner_tx_hash(pb::miner_tx_prefix_hash(pre))) == s.tx_hash, tag + ": tx hash recomputes");
        pb::Pbx1 x;
        const pb::Pbx1Error e = pb::decode_pbx1(16, ex.data(), ex.size(), x);
        if (ex[41] == 0x00) {
            ++depth0;
            check(e == pb::Pbx1Error::None, tag + ": depth 0 -> strict PBX1 accepts");
        } else {
            ++depth8;
            check(ex[41] == 0x08 && e == pb::Pbx1Error::MergeMiningDepth, tag + ": depth 8 -> MergeMiningDepth");
        }
        if (n >= 128) ++big;
    }
    check(depth0 == 4 && depth8 == 12 && big == 2, "sample: 4 depth-0, 12 depth-8, 2 with >= 128 outputs");

    return finish("v37_xmr_coinbase_extra_layout_kat");
}
