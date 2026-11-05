// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_coinbase_output_order_kat (pathb_window.hpp / pathb_miner_tx.hpp /
// pathb_coinbase_split.hpp, A-9, ruling 20 H-1 replaced): hf 16 window outputs
// are ordered by payee identity ascending; there is NO fee output in any case
// (ruling 20 H-1 replaced, v37_xmr_fee_output_kat RETIRED); fees change amounts,
// never the order or the keys; swapping two payees changes the tx hash.
// hf 17 (format only): all outputs by Ko strictly ascending (memcmp), the 0x04
// D_e list in the same order; the produced order passes Monero's strict check,
// the input order fails it; two equal Ko have no order (Unbuildable, REFUSE);
// n = 1 is the 0x01 form.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>

#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_miner_tx.hpp"
#include "impl/xmr/pathb/pathb_pbx1.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

static pb::Hash32 id_of(std::uint64_t i) {
    pb::Hash32 h{};
    for (int b = 0; b < 8; ++b) h[31 - b] = static_cast<std::uint8_t>(i >> (8 * b));
    return h;
}

static pb::Hash32 first_byte(std::uint8_t b0, std::uint8_t rest, std::uint8_t last) {
    pb::Hash32 h{};
    h.fill(rest);
    h[0] = b0;
    h[31] = last;
    return h;
}

int main() {
    // a window of 64 payees, out of identity order in the map insertion.
    pb::Window w;
    Rng rng(0x0A9);
    for (std::uint64_t i = 0; i < 64; ++i) {
        const std::uint64_t id = 1 + rng.below(1000000);
        w.weight[id_of(id)] = pb::Work(1000 + rng.below(5000));
    }
    for (const auto& [k, v] : w.weight) w.W += v;

    const std::uint64_t base = 600000000000ull, fees = 123456789ull;
    const auto a = pb::hf16_outputs(base, w);
    const auto b = pb::hf16_outputs(base + fees, w);  // more fees

    // hf 16 outputs by identity ascending.
    bool ordered = true;
    for (std::size_t i = 1; i < a.size(); ++i)
        if (!(a[i - 1].payee < a[i].payee)) ordered = false;
    check(ordered, "hf16 outputs ordered by payee identity ascending");

    // NO fee output: outputs == window payees, no extra slot.
    check(a.size() == w.weight.size(), "no fee output: one output per window payee");

    // fees change amounts, not the order or the payee set (no key change).
    bool same = a.size() == b.size();
    for (std::size_t i = 0; same && i < a.size(); ++i)
        if (!(a[i].payee == b[i].payee)) same = false;
    check(same, "fees do not change the output order or the payee / key set");

    // hf 16: swapping two payees of the self-golden changes the tx hash.
    {
        const pb::XmrKeyRef X = ref_from_secrets(11, 13), Y = ref_from_secrets(17, 19);
        const std::array<std::uint8_t, pb::kExtraNonceBytes> nonce{1, 2, 3, 4};
        const std::vector<pb::MinerPayee> yx{{Y, 273401000000ull}, {X, 328081200000ull}};
        const std::vector<pb::MinerPayee> xy{{X, 328081200000ull}, {Y, 273401000000ull}};
        const auto t1 = pb::build_miner_tx_hf16(seq32(0x01), seq32(0x21), seq32(0x41), 3800000, yx, nonce, seq32(0x61));
        const auto t2 = pb::build_miner_tx_hf16(seq32(0x01), seq32(0x21), seq32(0x41), 3800000, xy, nonce, seq32(0x61));
        check(t1 && t2 && hex32(t1->tx_hash) == "4011ea0878ca51e420772efedff6d8ce079105cb157805c4e0770726283cc3ae"
                      && !(t1->tx_hash == t2->tx_hash),
              "hf16: the identity order gives tx hash 4011ea08..; swapping two payees changes it");
    }

    // ---- hf 17 FORMAT: Ko strictly ascending (memcmp) ----
    const pb::Hash32 k0 = first_byte(0x80, 0x00, 0x00);  // 80 00..00
    const pb::Hash32 k1 = first_byte(0x01, 0x00, 0x00);  // 01 00..00
    const pb::Hash32 k2 = first_byte(0x7f, 0xff, 0xff);  // 7f ff..ff
    const std::vector<pb::Hash32> ko{k0, k1, k2};
    const auto perm = pb::carrot_output_order(ko);
    check(perm && *perm == std::vector<std::size_t>{1, 2, 0}, "Ko [80.., 01.., 7f ff..] -> vout order [1, 2, 0]");
    const std::vector<pb::Hash32> d_e{seq32(0xD0), seq32(0xD1), seq32(0xD2)};
    if (perm) {
        const std::vector<pb::Hash32> d_sorted = pb::in_vout_order(d_e, *perm);
        check(d_sorted == std::vector<pb::Hash32>{d_e[1], d_e[2], d_e[0]}, "D_e [d0, d1, d2] -> 0x04 list [d1, d2, d0]");
        const std::vector<pb::Hash32> ko_sorted = pb::in_vout_order(ko, *perm);
        check(pb::miner_outputs_strictly_sorted(ko_sorted), "the produced order passes the strict check");
        check(!pb::miner_outputs_strictly_sorted(ko), "the input order fails the strict check");
        pb::Pbx1 x;
        x.keys = d_sorted;
        x.extra_nonce = {1, 2, 3, 4};
        x.mm_root = seq32(0x61);
        std::vector<std::uint8_t> extra;
        check(pb::encode_pbx1(17, x, extra) == pb::Pbx1Error::None && extra.size() == pb::pbx1_size(17, 3)
                      && extra[0] == pb::TX_EXTRA_TAG_ADDITIONAL_PUBKEYS && extra[1] == 3
                      && std::equal(d_e[1].begin(), d_e[1].end(), extra.begin() + 2)
                      && std::equal(d_e[2].begin(), d_e[2].end(), extra.begin() + 34)
                      && std::equal(d_e[0].begin(), d_e[0].end(), extra.begin() + 66),
              "hf17 0x04 varint(3) D_e list in Ko order");
    }
    // two equal Ko: no order -> Unbuildable -> REFUSE.
    {
        const std::vector<pb::Hash32> eq{k0, k2, k0};
        check(!pb::carrot_output_order(eq).has_value(), "two equal Ko -> no order");
        const std::optional<pb::CoinbaseCheck> c = pb::carrot_order_refusal(eq);
        check(c && *c == pb::CoinbaseCheck::Unbuildable, "two equal Ko -> Unbuildable");
        check(!pb::carrot_order_refusal(ko).has_value(), "distinct Ko -> no refusal");
        bool rx = false;
        const pb::TailResult t = pb::admit_coinbase_then_randomx(*c, [&] { rx = true; return true; });
        check(t.verdict == pb::AdmitVerdict::Refuse && pb::strike_tokens(t.verdict) == 0 && !rx,
              "Unbuildable -> REFUSE, no token, no ban, RandomX not called");
        check(!pb::miner_outputs_strictly_sorted(std::vector<pb::Hash32>{k1, k1}), "equal Ko fail the strict check");
    }
    // memcmp, not a little-endian integer: a = 01 00..00, b = 00 00..01.
    {
        const pb::Hash32 a1 = first_byte(0x01, 0x00, 0x00), b1 = first_byte(0x00, 0x00, 0x01);
        const auto p = pb::carrot_output_order(std::vector<pb::Hash32>{a1, b1});
        check(p && *p == std::vector<std::size_t>{1, 0}, "a = 01 00..00, b = 00 00..01 -> memcmp order [b, a]");
        check(pb::ko_less(b1, a1) && !pb::ko_less(a1, b1), "ko_less is memcmp (a > b although LE(a) < LE(b))");
    }
    // n = 1: the 0x01 form.
    {
        pb::Pbx1 x;
        x.keys = {seq32(0xD0)};
        x.extra_nonce = {1, 2, 3, 4};
        x.mm_root = seq32(0x61);
        std::vector<std::uint8_t> extra;
        check(pb::encode_pbx1(17, x, extra) == pb::Pbx1Error::None && extra.size() == 74
                      && extra[0] == pb::TX_EXTRA_TAG_PUBKEY,
              "hf17 n = 1 -> the 0x01 form (74 B)");
    }

    return finish("v37_xmr_coinbase_output_order_kat");
}
