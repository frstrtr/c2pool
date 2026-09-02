// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_extend_mint_kat — F2 EXTEND-OFF-REAL-TIP known-answer test for M3 PR-C.
//
// The genesis mint-KAT (bip110_pool_mint_kat) proves mint/verify SYMMETRY with a
// FAKE coinbase whose OP_RETURN ref_hash is arbitrary — it never checks that the
// committed ref_hash equals what a PEER recomputes off the share fields. THAT gap
// (F1) is exactly the PR-C blocker: an M2 share commits no real ref, so peers
// REJECT it (ref/coinbase mismatch). This KAT closes the loop for a share that
// EXTENDS a real (non-genesis) sharechain tip:
//
//   1. Seed a GENESIS share into a ShareTracker (the tip).
//   2. Walk the tracker off that tip for the frozen chain-position fields exactly
//      as main_bip110's ref_hash_fn does (absheight=2, abswork=prev+aps, clipped
//      timestamp, far_share_hash), compute the intended ref_hash via the lane SSOT
//      bip110::pool::compute_ref_hash_for_work, and assemble a REAL coinbase via
//      bip110::coin::assemble_gentx_coinbase whose OP_RETURN is the true
//      {0x6a,0x28, ref_hash[32], last_txout_nonce[8]} commitment (the byte layout
//      build_connection_coinbase now emits on the flag-ON path).
//   3. Mint via create_local_share(prev = the tip, has_frozen = TRUE) — the
//      extend-off-real-tip path (NOT genesis).
//   4. Assert:
//      (a) the coinbase's last-44 tail carries the computed ref_hash (commitment
//          present — the M2 {0x6a,0x00} empty-commitment failure is gone);
//      (b) the minted share EXTENDS the tip: m_prev_hash == tip, m_absheight == 2;
//      (c) MINT/VERIFY hash symmetry: compute_share_hash(minted small-header,
//          reconstructed merkle) == stored m_hash == returned hash;
//      (d) PEER ref/coinbase CONSISTENCY — the whole point of F1: recompute the
//          ref_hash from the STORED share fields (read back out of the tracker,
//          via compute_ref_hash_for_work) and assert it equals the coinbase-
//          embedded ref_hash; THEN run the peer's own reconstruction
//          (check_hash_link -> check_merkle_link -> compute_share_hash, the exact
//          share_init_verify path share_check.hpp:664-730) using that recomputed
//          ref and assert it reproduces the stored share hash. This proves the
//          ref/coinbase (hash_link) half of peer verification — the F1 blocker
//          (empty {0x6a,0x00} commitment) is closed.
//
//      SCOPE NOTE (F1b, NOT proven here): full share_check peer acceptance ALSO
//      runs generate_share_transaction (share_check.hpp:1840-1952) and THROWS if
//      the coinbase outputs != the PPLNS distribution. That requires
//      build_connection_coinbase to serve a PPLNS-distributed coinbase (btc's
//      set_pplns_fn / get_expected_payouts pattern), which is a separate
//      consensus payout surface tracked as the PR-C companion gap. This KAT
//      deliberately proves ONLY the ref/hash_link consistency F1 targets.

#include "../share_tracker.hpp"        // ShareTracker -> share_check.hpp (create_local_share,
                                       // compute_ref_hash_for_work, check_hash_link,
                                       // check_merkle_link, compute_gentx_before_refhash)
#include "../config_pool.hpp"
#include "../../coin/block.hpp"        // coin::BlockHeaderType
#include "../../coin/gentx_coinbase.hpp"  // assemble_gentx_coinbase (SSOT)

#include <core/uint256.hpp>          // uint256 + uint128
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/target_utils.hpp>      // chain::bits_to_target / target_to_average_attempts

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

void expect_eq_hex(const std::string& name, const std::string& got, const std::string& want)
{
    if (got == want) std::printf("  [ok]   %s\n", name.c_str());
    else {
        std::printf("  [FAIL] %s\n         got : %s\n         want: %s\n",
                    name.c_str(), got.c_str(), want.c_str());
        ++g_fail;
    }
}

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

// REAL BIP-110 block 961640 v2 header (flags/clear_bits/xor_key = 0). Same carrier
// the identity + genesis mint KATs use; we grind its nonce for the easy target.
const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";

const uint32_t EASY_BITS = 0x207fffffu;  // ~2^255 share target (a few nonce grinds)
const uint64_t SUBSIDY    = 312500000ULL;

// A 25-byte P2PKH payout script (deterministic pubkey_hash/type identity).
const std::vector<unsigned char> PAYOUT_SCRIPT = {
    0x76, 0xa9, 0x14,
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
    0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,
    0x88, 0xac };

// Mint a genesis-branch tip so the extend share has a REAL non-genesis prev.
uint256 seed_genesis_tip(bip110::pool::ShareTracker& tracker,
                         const bip110::coin::BlockHeaderType& carrier)
{
    using namespace bip110::pool;
    BaseScript coinbase_bs;
    coinbase_bs.m_data = { 0x03, 0x28,0xab,0x0e, 0x00, 0x00, 0x2f, 0x67, 0x65,
                           0x6e, 0x2f, 0x00, 0x00, 0x00, 0x00 };
    // Fake but well-formed coinbase tail (ref[32]+nonce[8]+locktime[4]); the tip's
    // own peer-consistency is not under test — only that it exists as a prev.
    std::vector<unsigned char> cb(80, 0xCD);
    for (int i = 0; i < 32; ++i) cb[cb.size() - 44 + i] = (unsigned char)(0x20 + i);
    const uint64_t gnonce = 0x1111222233334444ULL;
    std::memcpy(cb.data() + cb.size() - 12, &gnonce, 8);
    cb[cb.size()-4]=cb[cb.size()-3]=cb[cb.size()-2]=cb[cb.size()-1]=0;

    bip110::coin::BlockHeaderType full = carrier;
    for (uint32_t g = 0; g < 200000; ++g) {
        full.m_nonce = g;
        uint256 h;
        try {
            h = create_local_share(
                tracker, full, coinbase_bs, SUBSIDY, /*prev (genesis)*/ uint256(),
                std::vector<uint256>{}, PAYOUT_SCRIPT, /*donation*/ 66, {},
                StaleInfo::none, /*segwit_active*/ true, /*witness_commitment*/ std::string{},
                {}, /*actual_coinbase*/ cb, /*witness_root*/ uint256(),
                /*override_max_bits*/ EASY_BITS, /*override_bits*/ EASY_BITS,
                /*frozen_absheight*/ 1, /*frozen_abswork*/ uint128(1234),
                /*frozen_far*/ uint256(), /*frozen_timestamp*/ full.m_timestamp,
                /*frozen_merged_payout*/ uint256(), /*has_frozen*/ true,
                std::vector<uint256>{}, uint256(), std::vector<unsigned char>{},
                /*share_version*/ 36, /*desired_version*/ 36);
        } catch (const std::exception&) { break; }
        if (!h.IsNull()) return h;
    }
    return uint256();
}

} // namespace

int main()
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    std::printf("bip110_extend_mint_kat: F2 extend-off-real-tip + peer ref/coinbase consistency\n");

    ShareTracker tracker;

    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType carrier;
    { PackStream ps(hdr_bytes); ps >> carrier; }

    // ── Step 1: seed the tip ─────────────────────────────────────────────────
    uint256 tip = seed_genesis_tip(tracker, carrier);
    expect_true("[1] genesis tip minted + tracked", !tip.IsNull() && tracker.chain.contains(tip));
    if (tip.IsNull() || !tracker.chain.contains(tip)) {
        std::printf("RESULT: FAIL — could not seed a tip.\n"); return 1;
    }

    // Read the tip's abswork/timestamp — the extend share's frozen fields build on them.
    uint128 tip_abswork; uint32_t tip_ts = 0; uint32_t tip_absheight = 0;
    tracker.chain.get(tip).share.invoke([&](auto* s) {
        tip_abswork = s->m_abswork; tip_ts = s->m_timestamp; tip_absheight = s->m_absheight;
    });

    // ── Step 2: frozen fields for the EXTEND share (mirror main_bip110 ref_hash_fn) ─
    const uint32_t block_bits = carrier.m_bits;   // GBT block bits from the carrier header
    RefHashParams p;
    p.share_version   = 36;
    p.desired_version = 36;
    p.prev_share      = tip;
    p.coinbase_scriptSig = { 0x03, 0x29,0xab,0x0e, 0x00, 0x00, 0x2f, 0x62, 0x69,
                             0x70, 0x31, 0x31, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x00 };
    p.share_nonce     = 0;
    p.subsidy         = SUBSIDY;
    p.donation        = 66;
    p.stale_info      = 0;
    // pubkey from PAYOUT_SCRIPT (P2PKH).
    std::memcpy(p.pubkey_hash.data(), PAYOUT_SCRIPT.data() + 3, 20);
    p.pubkey_type = 0;
    // segwit (coinbase-only): real witness merkle root ZERO (merkle([0]), python
    // v36 data.py:1090) — MUST match create_local_share's segwit-active coinbase-only
    // store (ZERO root, NOT the 0xff None-sentinel) or the recomputed ref diverges.
    p.has_segwit  = true;
    p.segwit_data = SegwitDataDefault::get();
    p.segwit_data.m_wtxid_merkle_root = uint256();  // ZERO
    // chain position off the real tip.
    p.absheight      = tip_absheight + 1;                 // == 2
    p.timestamp      = (carrier.m_timestamp <= tip_ts) ? (tip_ts + 1) : carrier.m_timestamp;
    p.far_share_hash = uint256::ZERO;                     // prev_height 0 (<99)
    p.bits = EASY_BITS; p.max_bits = EASY_BITS;           // == the override the mint applies
    {
        auto attempts = chain::target_to_average_attempts(chain::bits_to_target(EASY_BITS));
        p.abswork = uint128((tip_abswork + uint128(attempts.GetLow64())).GetLow64());
    }
    try {
        p.merged_payout_hash = tracker.compute_merged_payout_hash(
            tip, chain::bits_to_target(block_bits));
    } catch (const std::exception&) { p.merged_payout_hash = uint256(); }

    auto [intended_ref, intended_nonce] = compute_ref_hash_for_work(p);
    expect_true("[2] compute_ref_hash_for_work produced a non-null ref", !intended_ref.IsNull());

    // ── Step 2b: assemble a REAL coinbase carrying the ref commitment ─────────
    // OP_RETURN = 6a 28 ref_hash[32] last_txout_nonce[8]  (the flag-ON build layout).
    std::vector<unsigned char> op_return = {0x6a, 0x28};
    op_return.insert(op_return.end(), intended_ref.data(), intended_ref.data() + 32);
    { const auto* np = reinterpret_cast<const unsigned char*>(&intended_nonce);
      op_return.insert(op_return.end(), np, np + 8); }

    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts = {
        { PAYOUT_SCRIPT, SUBSIDY } };
    // Donation output script MUST be the canonical p2pool donation — it forms the
    // hash_link const-ending (compute_gentx_before_refhash(36)) the peer re-supplies.
    std::vector<unsigned char> donation_script = PoolConfig::get_donation_script(36);
    auto cbres = coin::assemble_gentx_coinbase(
        p.coinbase_scriptSig, /*segwit_commit*/ std::nullopt,
        payouts, /*donation_amt*/ 0, donation_script, op_return);
    const std::vector<unsigned char>& coinbase = cbres.bytes;

    // (a) coinbase tail carries the intended ref_hash.
    expect_true("[a] coinbase > 44 bytes (has a ref tail)", coinbase.size() > 44);
    {
        uint256 tail_ref;
        std::memcpy(tail_ref.data(), coinbase.data() + coinbase.size() - 44, 32);
        expect_eq_hex("[a] coinbase last-44 ref_hash == compute_ref_hash_for_work",
                      tail_ref.GetHex(), intended_ref.GetHex());
    }

    // ── Step 3: mint the extend share (has_frozen=TRUE, prev = tip) ──────────
    BaseScript coinbase_bs; coinbase_bs.m_data = p.coinbase_scriptSig;
    uint256 minted; uint32_t grind = 0;
    coin::BlockHeaderType full = carrier;
    for (; grind < 400000; ++grind) {
        full.m_nonce = grind;
        uint256 h;
        try {
            h = create_local_share(
                tracker, full, coinbase_bs, SUBSIDY, /*prev*/ tip,
                std::vector<uint256>{}, PAYOUT_SCRIPT, /*donation*/ 66, {},
                StaleInfo::none, /*segwit_active*/ true, /*witness_commitment*/ std::string{},
                {}, /*actual_coinbase*/ coinbase, /*witness_root*/ uint256(),
                /*override_max_bits*/ EASY_BITS, /*override_bits*/ EASY_BITS,
                /*frozen_absheight*/ p.absheight, /*frozen_abswork*/ p.abswork,
                /*frozen_far*/ p.far_share_hash, /*frozen_timestamp*/ p.timestamp,
                /*frozen_merged_payout*/ p.merged_payout_hash, /*has_frozen*/ true,
                std::vector<uint256>{}, uint256(), std::vector<unsigned char>{},
                /*share_version*/ 36, /*desired_version*/ 36);
        } catch (const std::exception& e) {
            std::printf("  [FAIL] extend create_local_share threw: %s\n", e.what());
            ++g_fail; break;
        }
        if (!h.IsNull()) { minted = h; break; }
    }
    expect_true("[3] extend share minted (non-null under easy target)", !minted.IsNull());
    expect_true("[3] extend share landed in the tracker", !minted.IsNull() && tracker.chain.contains(minted));
    if (minted.IsNull() || !tracker.chain.contains(minted)) {
        std::printf("RESULT: FAIL — extend mint produced no tracked share.\n"); return 1;
    }
    std::printf("  [info] extend minted after %u grind(s): %s\n", grind, minted.GetHex().c_str());

    // gentx_hash for the merkle reconstruction (same derivation as mint/verify).
    uint256 gentx_hash = Hash(std::span<const unsigned char>(coinbase.data(), coinbase.size()));
    auto gentx_before_refhash = compute_gentx_before_refhash(int64_t(36));

    tracker.chain.get(minted).share.invoke([&](auto* s) {
        // (b) EXTEND (not genesis).
        expect_eq_hex("[b] minted m_prev_hash == the tip", s->m_prev_hash.GetHex(), tip.GetHex());
        expect_true("[b] minted m_absheight == 2 (extend, NOT genesis)", s->m_absheight == 2);

        // (c) mint/verify hash symmetry.
        uint256 mr = check_merkle_link(gentx_hash, s->m_merkle_link);
        uint256 recomputed = compute_share_hash(s->m_min_header, mr);
        expect_eq_hex("[c] compute_share_hash(minted small-header, merkle) == stored m_hash",
                      recomputed.GetHex(), s->m_hash.GetHex());
        expect_eq_hex("[c] stored m_hash == returned mint hash", s->m_hash.GetHex(), minted.GetHex());
        expect_true("[c] m_pow_hash == m_hash (self-validation passed)", s->m_pow_hash == s->m_hash);

        // (d) PEER ref/coinbase consistency — recompute ref from the STORED fields.
        RefHashParams pv;
        pv.share_version   = 36;
        pv.desired_version = s->m_desired_version;
        pv.prev_share      = s->m_prev_hash;
        pv.coinbase_scriptSig = s->m_coinbase.m_data;
        pv.share_nonce     = s->m_nonce;
        pv.pubkey_hash     = s->m_pubkey_hash;
        pv.pubkey_type     = s->m_pubkey_type;
        pv.subsidy         = s->m_subsidy;
        pv.donation        = s->m_donation;
        pv.stale_info      = static_cast<uint8_t>(s->m_stale_info);
        pv.has_segwit      = s->m_segwit_data.has_value();
        if (s->m_segwit_data.has_value()) pv.segwit_data = s->m_segwit_data.value();
        pv.merged_addresses = s->m_merged_addresses;
        pv.far_share_hash  = s->m_far_share_hash;
        pv.max_bits        = s->m_max_bits;
        pv.bits            = s->m_bits;
        pv.timestamp       = s->m_timestamp;
        pv.absheight       = s->m_absheight;
        pv.abswork         = s->m_abswork;
        pv.merged_coinbase_info = s->m_merged_coinbase_info;
        pv.merged_payout_hash   = s->m_merged_payout_hash;
        pv.message_data    = s->m_message_data;

        auto [peer_ref, _pn] = compute_ref_hash_for_work(pv);
        expect_eq_hex("[d] ref recomputed from STORED share fields == coinbase ref",
                      peer_ref.GetHex(), intended_ref.GetHex());

        // (d) full peer reconstruction (share_check.hpp:664-730) with the peer ref.
        std::vector<unsigned char> hld;
        hld.insert(hld.end(), peer_ref.data(), peer_ref.data() + 32);
        { uint64_t n = s->m_last_txout_nonce;
          const auto* pp = reinterpret_cast<const unsigned char*>(&n);
          hld.insert(hld.end(), pp, pp + 8); }
        { uint32_t z = 0; const auto* pp = reinterpret_cast<const unsigned char*>(&z);
          hld.insert(hld.end(), pp, pp + 4); }
        uint256 peer_gentx = check_hash_link(s->m_hash_link, hld, gentx_before_refhash);
        // Segwit-active: verify uses segwit_data.txid_merkle_link (empty branch here).
        uint256 peer_mr = s->m_segwit_data.has_value()
            ? check_merkle_link(peer_gentx, s->m_segwit_data->m_txid_merkle_link)
            : check_merkle_link(peer_gentx, s->m_merkle_link);
        uint256 peer_share_hash = compute_share_hash(s->m_min_header, peer_mr);
        expect_eq_hex("[d] peer reconstruction (hash_link->merkle->BLAKE2b) == stored m_hash",
                      peer_share_hash.GetHex(), s->m_hash.GetHex());
    });

    if (g_fail == 0) {
        std::printf("RESULT: PASS — extend-off-real-tip share carries a real ref "
                    "commitment; a peer reconstructs the exact share hash from it "
                    "(ref/hash_link consistency, the F1 blocker closed). Full PPLNS "
                    "coinbase acceptance = F1b (separate).\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
