// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// xmr_receipt_bind_v2_kat -- GAP-2 stage 1, KAT 2: the PoW-verify half.
//
//   B1  mint -> structural accept (bind=none) on today's coinbase layout; the
//       same receipt is REFUSED at the Bind stage under bind=rbind (the template
//       does not write rbind yet: SEAM-1 is the operator's hand)
//   B2  a SEAM-1 layout coinbase ([extra_nonce | rbind | pad | tail]) passes
//       bind=rbind; then every tamper is caught STRUCTURALLY (before RandomX):
//         payee swapped (identity re-derived)        -> Bind
//         give_author changed, info_digest kept      -> InfoDigest
//         give_author changed, info_digest re-made   -> Bind
//         t_origin != share_diff                     -> R1
//         one tx_extra byte flipped                  -> Opening
//         tree-branch sibling flipped                -> Opening
//         identity != identity_key(payee)            -> Identity
//         chain_id != lane                           -> Chain
//         a receipt whose tx_extra lacks the 0x03    -> ExtraShape
//   B3  the exact PoW rule meets_share_diff against hand-computed edges
//   B4  (XMR_BUILD_RANDOMX) REAL RandomX: grind a nonce on the synthetic blob
//       under a real seed, the receipt verifies at share_diff; a nonce that
//       misses a large difficulty is rejected at the RandomX stage; the rule
//       agrees with the library's meets_difficulty_64 on 64 real hashes.
#include <cstdlib>

#include "xmr_relay_test_util.hpp"
#if defined(GAP2_WITH_RANDOMX)
#include "impl/xmr/pow/randomx_verify.hpp"
#endif

using namespace gap2test;

int main() {
    Checker C;
    std::printf("== xmr_receipt_bind_v2_kat ==\n");
    const u32 chain = 7; const u64 sd = 2000;
    const ::v37::ScriptRef payA = payee_of("A"), payB = payee_of("B");
    CheckCtx none; none.lane_chain = chain; none.share_diff = sd; none.bind = BindMode::None;
    CheckCtx rb = none; rb.bind = BindMode::Rbind;

    // ── B1 ──────────────────────────────────────────────────────────────────
    {
        const SynthBlock sb = make_block(200, b32_of(21), 9, nullptr, 3, 2);
        FbReceipt r; std::string why;
        C(mint_on(sb, 5, payA, chain, sd, r, &why), "B1 mint on today's layout " + why);
        C(check_structural(r, none).ok(), "B1 bind=none: structural ACCEPT");
        const auto cr = check_structural(r, rb);
        C(cr.stage == CheckStage::Bind, std::string("B1 bind=rbind on a pre-SEAM-1 coinbase: refused at ") + to_string(cr.stage));
        C(cr.id == receipt_id(r) && check_structural(r, none).prev_id == b32_of(21), "B1 result carries receipt_id + prev_id (the bin key)");
    }

    // ── B2 SEAM-1 layout ────────────────────────────────────────────────────
    {
        const SideDataV2 sideA = side_for(payA, chain, sd, 3);
        const bytes32 rbA = rbind_v1(chain, sideA);
        const SynthBlock sb = make_block(201, b32_of(22), 10, &rbA, 4, 3);
        FbReceipt r; std::string why;
        C(mint_receipt(sb.full_blob, with_nonce(sb, 1), sideA, payA, r, &why), "B2 mint on the SEAM-1 layout " + why);
        C(check_structural(r, rb).ok(), "B2 bind=rbind: ACCEPT when 0x02[4..36) == rbind_v1(chain, side)");
        C(check_structural(r, none).ok(), "B2 bind=none also accepts it (the binding is extra, not different)");
        auto expect = [&](FbReceipt t, CheckStage st, const std::string& what) {
            const auto res = check_structural(t, rb);
            C(res.stage == st, "B2 " + what + " -> " + to_string(res.stage) + (res.why.empty() ? "" : " (" + res.why + ")"));
        };
        { FbReceipt t = r; t.payee = payB; t.side.identity = ::v37::xmr::xmr_identity_key(payB); t.receipt.info_digest = side_digest_v2(t.side);
          expect(t, CheckStage::Bind, "payee swapped to B (identity + info_digest re-made)"); }
        { FbReceipt t = r; t.side.give_author = 4; expect(t, CheckStage::InfoDigest, "give_author changed, info_digest stale"); }
        { FbReceipt t = r; t.side.give_author = 4; t.receipt.info_digest = side_digest_v2(t.side);
          expect(t, CheckStage::Bind, "give_author changed, info_digest re-made"); }
        { FbReceipt t = r; t.side.t_lo = sd * 2; t.receipt.info_digest = side_digest_v2(t.side);
          expect(t, CheckStage::R1, "t_origin != lane share_diff"); }
        { FbReceipt t = r; t.receipt.coinbase_opening.tx_extra[40] ^= 1; expect(t, CheckStage::Opening, "one tx_extra byte flipped"); }
        { FbReceipt t = r; if (!t.receipt.tree_branch.path.empty()) t.receipt.tree_branch.path[0][0] ^= 1;
          expect(t, CheckStage::Opening, "tree-branch sibling flipped"); }
        { FbReceipt t = r; t.side.identity[0] ^= 1; t.receipt.info_digest = side_digest_v2(t.side);
          expect(t, CheckStage::Identity, "side.identity != identity_key(payee)"); }
        { FbReceipt t = r; t.side.chain_id = chain + 1; t.receipt.info_digest = side_digest_v2(t.side);
          expect(t, CheckStage::Chain, "side.chain_id != lane"); }
        { FbReceipt t = r; t.side.reserved = 1; t.receipt.info_digest = side_digest_v2(t.side);
          expect(t, CheckStage::Reserved, "side.reserved != 0"); }
        { FbReceipt t = r; t.receipt.hashing_blob.bytes[sb.nonce_offset] ^= 0x80;
          C(check_structural(t, rb).ok(), "B2 a different nonce is structurally fine (only RandomX can judge it)"); }
    }
    {   // a coinbase with no 0x03 lane tag: build the receipt by hand around a raw prefix
        const SynthBlock sb = make_block(202, b32_of(23), 11, nullptr, 0, 4);
        FbReceipt r; mint_on(sb, 1, payA, chain, sd, r);
        FbReceipt t = r;
        auto& ex = t.receipt.coinbase_opening.tx_extra;
        ex.resize(ex.size() - 35);   // drop the 03 21 00 root tag -> opening no longer reproduces the root, AND shape fails
        const auto res = check_structural(t, none);
        C(!res.ok(), std::string("B2 a receipt without the 0x03 lane tag is refused (") + to_string(res.stage) + ")");
    }

    // ── B3 the PoW rule ─────────────────────────────────────────────────────
    {
        bytes32 z{}; C(meets_share_diff(z, ~0ull), "B3 hash 0 meets any difficulty");
        bytes32 ff; ff.fill(0xff); C(!meets_share_diff(ff, 2) && meets_share_diff(ff, 1), "B3 hash 2^256-1 meets only difficulty 1");
        bytes32 half{}; half[31] = 0x80;      // 2^255
        C(meets_share_diff(half, 1) && !meets_share_diff(half, 2), "B3 2^255: diff 1 yes, diff 2 no (2^256 is not < 2^256)");
        bytes32 just{}; just[31] = 0x7f; for (int i = 0; i < 31; ++i) just[i] = 0xff;   // 2^255-1
        C(meets_share_diff(just, 2) && !meets_share_diff(just, 3), "B3 2^255-1: diff 2 yes, diff 3 no");
        C(!meets_share_diff(z, 0), "B3 difficulty 0 never passes");
    }

#if defined(GAP2_WITH_RANDOMX)
    {
        ::c2pool::xmr::LightVerifier vm;
        ::c2pool::xmr::VerifierOptions o; o.use_jit = true;
        bool ok = vm.init(o);
        if (!ok) { o.use_jit = false; ok = vm.init(o); }
        C(ok, "B4 RandomX light verifier initialised");
        std::array<std::uint8_t, 32> seed{}; for (int i = 0; i < 32; ++i) seed[i] = static_cast<std::uint8_t>(0xa0 + i);
        ok = ok && vm.prefetch_epoch(seed, std::nullopt);
        C(ok && vm.seed_resident(seed), "B4 seed resident (Argon2d cache init)");
        const u64 small = 16;
        const SynthBlock sb = make_block(300, b32_of(31), 12, nullptr, 2, 5);
        FbReceipt found; bool hit = false; bytes32 pow{};
        for (std::uint32_t n = 0; ok && n < 4000 && !hit; ++n) {
            const auto hb = with_nonce(sb, n);
            std::uint8_t out[32];
            if (!vm.hash(hb.data(), hb.size(), seed, out)) break;
            std::memcpy(pow.data(), out, 32);
            if (meets_share_diff(pow, small)) { hit = mint_on(sb, n, payA, chain, small, found); }
        }
        C(hit, "B4 ground a nonce meeting share_diff 16 under real RandomX");
        CheckCtx c16 = none; c16.share_diff = small;
        C(hit && check_structural(found, c16).ok(), "B4 that receipt is structurally valid at share_diff 16");
        std::uint8_t again[32];
        C(hit && vm.hash(found.receipt.hashing_blob.bytes.data(), found.receipt.hashing_blob.bytes.size(), seed, again) &&
              std::memcmp(again, pow.data(), 32) == 0 && meets_share_diff(pow, small),
          "B4 a verifier re-hashing the receipt's blob gets the same PoW and ACCEPTS");
        C(hit && !meets_share_diff(pow, ~0ull >> 1), "B4 the same PoW is REJECTED at a 2^63 difficulty (RandomX stage)");
        bool agree = true;
        for (std::uint32_t n = 0; n < 64; ++n) {
            const auto hb = with_nonce(sb, 100000 + n);
            std::uint8_t out[32];
            if (!vm.hash(hb.data(), hb.size(), seed, out)) { agree = false; break; }
            bytes32 h; std::memcpy(h.data(), out, 32);
            for (u64 d : {1ull, 2ull, 16ull, 1000ull, 123456789ull})
                if (meets_share_diff(h, d) != ::c2pool::xmr::meets_difficulty_64(out, d)) agree = false;
        }
        C(agree, "B4 meets_share_diff == librandomx-side meets_difficulty_64 on 64 real hashes x 5 difficulties");
    }
#else
    std::printf("  [SKIP] B4 real RandomX (build with -DXMR_BUILD_RANDOMX=ON)\n");
#endif
    return C.done("xmr_receipt_bind_v2_kat");
}
