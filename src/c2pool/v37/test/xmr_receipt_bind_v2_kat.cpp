// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// xmr_receipt_bind_v2_kat -- the PoW binding of a Path B v3 receipt (side_data_v3 in the PoW preimage through the
// canonical coinbase; impl/xmr/pathb/pathb_admit.hpp admit_receipt, S2.3):
//   B1  a v3 receipt on a held tip is admitted PENDING (row 30) after one RandomX call
//   B2  every change to what the PoW commits is refused before RandomX (no RandomX call):
//         payee_ref of another key under side.payee           -> STRIKE row 15 (ID-1)
//         side.pool_id of another pool                        -> STRIKE row 16
//         payee swapped (ref and identity of another payee)   -> BAN row 26 (canonical coinbase)
//         give_author_bp changed                              -> BAN row 26
//         window_root changed                                 -> BAN (rows 26 / 27)
//         extra_nonce changed                                 -> BAN row 26
//         the blob's tree root flipped                        -> BAN row 26
//         a tree-branch sibling added (tx_count 1)            -> STRIKE row 23 (header fields)
//         t_origin != d_at(tip)                               -> STRIKE row 25
//       a different nonce changes only the receipt id: it reaches RandomX
//   B3  the exact PoW rule check_hash against hand-computed edges
//   B4  (XMR_BUILD_RANDOMX) real RandomX: a nonce ground on a v3 hashing blob under a real seed meets d; a verifier
//       re-hashing the blob gets the same hash; the rule agrees with meets_difficulty_64 on 64 real hashes
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_check_hash.hpp"
#include "impl/xmr/pathb/test/pathb_kat_admit.hpp"
#if defined(GAP2_WITH_RANDOMX)
#include "impl/xmr/pow/randomx_verify.hpp"
#endif

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;
using pb::AdmitVerdict;
using pb::RowId;

namespace {

const std::uint64_t kJ0 = pb::admit_j0(pb::kRuledLaneParams);

std::vector<pb::Hash32> chain_of(KatNode& n, std::uint64_t count) {
    std::vector<pb::Hash32> out;
    pb::Hash32 prev = n.tree.best().id;
    const std::uint64_t base = n.node(prev).pos;
    for (std::uint64_t i = 1; i <= count; ++i) {
        const pb::CarrierBodyV3 c = carrier_on(n, prev, h_pos(base + i), {}, (base + i) % 4, 1 + base + i);
        const Admitted a = admit_place(n, c);
        if (!a.placed) {
            check(false, "chain: carrier not placed at " + std::to_string(base + i) + ": " + desc(a.r));
            break;
        }
        prev = pb::receipt_id(c.own);
        out.push_back(prev);
    }
    return out;
}

bool is(const pb::AdmitResult& r, AdmitVerdict v, RowId row) { return r.verdict == v && r.row == row; }

void b1_b2() {
    std::printf("-- B1 / B2 a v3 receipt and every change to what its PoW commits\n");
    KatNet net;
    KatNode n(net, kJ0);
    const std::vector<pb::Hash32> chain = chain_of(n, 12);
    if (chain.empty()) return;
    const pb::Hash32 tip = chain.back();
    const std::uint64_t ht = h_pos(13);

    const pb::ReceiptBodyV3 r = body_on(n, tip, ht, 1, 7001);
    std::uint64_t rx0 = n.rx_calls;
    const pb::AdmitResult a = pb::admit_receipt(n.env(), bytes_of(r), pb::Role::Pending);
    check(is(a, AdmitVerdict::AdmitPending, RowId::R30) && n.rx_calls == rx0 + 1 && a.id == pb::receipt_id(r),
          "B1 the v3 receipt is admitted PENDING (row 30) after one RandomX call: " + desc(a));

    const auto refused = [&](pb::ReceiptBodyV3 t, AdmitVerdict v, std::initializer_list<RowId> rows, const std::string& what) {
        const std::uint64_t rx = n.rx_calls;
        const pb::AdmitResult x = pb::admit_receipt(n.env(), bytes_of(t), pb::Role::Pending);
        bool row_ok = false;
        for (RowId w : rows) row_ok = row_ok || x.row == w;
        check(x.verdict == v && row_ok && n.rx_calls == rx && !x.randomx_called,
              "B2 " + what + " -> " + desc(x) + ", no RandomX");
    };
    { pb::ReceiptBodyV3 t = r; t.payee = net.refs[2];
      refused(t, AdmitVerdict::Strike, {RowId::R15}, "payee_ref of another key under side.payee"); }
    { pb::ReceiptBodyV3 t = r; t.side.pool_id = seq32(0x66);
      refused(t, AdmitVerdict::Strike, {RowId::R16}, "side.pool_id of another pool"); }
    { pb::ReceiptBodyV3 t = r; t.payee = net.refs[2]; t.side.payee = net.ids[2];
      refused(t, AdmitVerdict::Ban, {RowId::R26}, "payee swapped (ref and identity of another payee)"); }
    { pb::ReceiptBodyV3 t = r; t.side.give_author_bp = 20;
      refused(t, AdmitVerdict::Ban, {RowId::R26}, "give_author_bp 10 -> 20"); }
    { pb::ReceiptBodyV3 t = r; t.side.window_root[0] ^= 1;
      refused(t, AdmitVerdict::Ban, {RowId::R26, RowId::R27}, "window_root changed"); }
    { pb::ReceiptBodyV3 t = r; t.extra_nonce[0] ^= 1;
      refused(t, AdmitVerdict::Ban, {RowId::R26}, "extra_nonce changed"); }
    { pb::ReceiptBodyV3 t = r; t.blob.tree_root[0] ^= 1;
      refused(t, AdmitVerdict::Ban, {RowId::R26}, "the blob's tree root flipped"); }
    { pb::ReceiptBodyV3 t = r; t.branch.push_back(seq32(0x44));
      refused(t, AdmitVerdict::Strike, {RowId::R23}, "a tree-branch sibling added (tx_count 1)"); }
    { pb::ReceiptBodyV3 t = r; t.side.t_origin = r.side.t_origin * 2;
      refused(t, AdmitVerdict::Strike, {RowId::R25}, "t_origin != d_at(tip)"); }
    {
        pb::ReceiptBodyV3 t = r;
        t.blob.nonce ^= 0x80;
        rx0 = n.rx_calls;
        const pb::AdmitResult x = pb::admit_receipt(n.env(), bytes_of(t), pb::Role::Pending);
        check(pb::receipt_id(t) != pb::receipt_id(r) && x.randomx_called && n.rx_calls == rx0 + 1,
              "B2 a different nonce is another receipt id and reaches RandomX: " + desc(x));
    }
}

void b3_rule() {
    std::printf("-- B3 the PoW rule (check_hash)\n");
    std::array<unsigned char, 32> z{};
    const auto ok = [](const std::array<unsigned char, 32>& h, std::uint64_t d) {
        return ::xmr::coin::check_hash(*reinterpret_cast<const unsigned char(*)[32]>(h.data()), d);
    };
    check(ok(z, ~0ull), "B3 hash 0 meets any difficulty");
    std::array<unsigned char, 32> ff;
    ff.fill(0xff);
    check(!ok(ff, 2) && ok(ff, 1), "B3 hash 2^256-1 meets only difficulty 1");
    std::array<unsigned char, 32> half{};
    half[31] = 0x80;  // 2^255
    check(ok(half, 1) && !ok(half, 2), "B3 2^255: difficulty 1 yes, 2 no (2^256 is not < 2^256)");
    std::array<unsigned char, 32> just{};
    just[31] = 0x7f;
    for (int i = 0; i < 31; ++i) just[i] = 0xff;  // 2^255-1
    check(ok(just, 2) && !ok(just, 3), "B3 2^255-1: difficulty 2 yes, 3 no");
}

void b4_randomx() {
#if defined(GAP2_WITH_RANDOMX)
    std::printf("-- B4 real RandomX on a v3 hashing blob\n");
    ::c2pool::xmr::LightVerifier vm;
    ::c2pool::xmr::VerifierOptions o;
    o.use_jit = true;
    bool ok = vm.init(o);
    if (!ok) {
        o.use_jit = false;
        ok = vm.init(o);
    }
    check(ok, "B4 RandomX light verifier initialised");
    std::array<std::uint8_t, 32> seed{};
    for (int i = 0; i < 32; ++i) seed[i] = static_cast<std::uint8_t>(0xa0 + i);
    ok = ok && vm.prefetch_epoch(seed, std::nullopt);
    check(ok && vm.seed_resident(seed), "B4 seed resident");
    KatNet net;
    KatNode n(net, kJ0);
    const pb::ReceiptBodyV3 r = body_on(n, n.tree.best().id, h_pos(1), 1, 0);
    const std::uint64_t d = 16;
    bool hit = false;
    std::array<std::uint8_t, 32> pow{};
    pb::HashingBlob found = r.blob;
    for (std::uint32_t nonce = 0; ok && nonce < 4000 && !hit; ++nonce) {
        pb::HashingBlob b = r.blob;
        b.nonce = nonce;
        std::vector<std::uint8_t> bytes;
        pb::encode_hashing_blob(b, bytes);
        if (!vm.hash(bytes.data(), bytes.size(), seed, pow.data())) break;
        if (::xmr::coin::check_hash(*reinterpret_cast<const unsigned char(*)[32]>(pow.data()), d)) {
            hit = true;
            found = b;
        }
    }
    check(hit, "B4 ground a nonce meeting d = 16 under real RandomX");
    std::vector<std::uint8_t> bytes;
    pb::encode_hashing_blob(found, bytes);
    std::array<std::uint8_t, 32> again{};
    check(hit && vm.hash(bytes.data(), bytes.size(), seed, again.data()) && again == pow,
          "B4 a verifier re-hashing the blob gets the same hash and accepts it");
    check(hit && !::xmr::coin::check_hash(*reinterpret_cast<const unsigned char(*)[32]>(pow.data()), ~0ull >> 1),
          "B4 the same hash is refused at a 2^63 difficulty");
    bool agree = true;
    for (std::uint32_t k = 0; k < 64; ++k) {
        pb::HashingBlob b = r.blob;
        b.nonce = 100000 + k;
        std::vector<std::uint8_t> v;
        pb::encode_hashing_blob(b, v);
        std::uint8_t out[32];
        if (!vm.hash(v.data(), v.size(), seed, out)) { agree = false; break; }
        for (std::uint64_t dd : {1ull, 2ull, 16ull, 1000ull, 123456789ull})
            if (::xmr::coin::check_hash(out, dd) != ::c2pool::xmr::meets_difficulty_64(out, dd)) agree = false;
    }
    check(agree, "B4 check_hash == meets_difficulty_64 on 64 real hashes x 5 difficulties");
#else
    std::printf("  [SKIP] B4 real RandomX (build with -DXMR_BUILD_RANDOMX=ON)\n");
#endif
}

}  // namespace

int main() {
    std::printf("== xmr_receipt_bind_v2_kat ==\n");
    b1_b2();
    b3_rule();
    b4_randomx();
    return finish("xmr_receipt_bind_v2_kat");
}
