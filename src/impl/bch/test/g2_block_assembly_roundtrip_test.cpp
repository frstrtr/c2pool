// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// G2 won-block assembly round-trip test.
//
// Pins the gate that closes the G2 zero-blocks failure: the live pool accepted
// ~774k solutions and produced ZERO blocks because every relayed body was a
// 155-byte
//
//     80 header + 1 tx-count + 74 generation transaction
//
// whose generation transaction was
//
//     62 first-coinbase-segment + 8 extranonce + 4 locktime
//
// with the 62-byte segment terminating at an OUTPUT COUNT OF ZERO -- so the
// miner's extranonce was spliced AFTER the (empty) output vector rather than
// inside a commitment output. Nothing downstream could decode what the miner
// hashed, the recomputed transaction root never matched the header, and the
// node rejected every block `bad-txnmrklroot`.
//
// What this test pins:
//   1. ROUND TRIP -- a well-formed won block frames, re-deserializes from its
//      own wire bytes, and its recomputed transaction root matches the header.
//      Holds for the coinbase-only case and with other transactions present.
//   2. G2 REGRESSION -- the exact historical 155-byte shape is REFUSED, by
//      name, before it can reach either broadcast sink.
//   3. DEGRADED: REFERENCE HASH ABSENT -- a header built without a usable
//      reference hash carries a root that cannot match the transactions; the
//      self-check catches it as a mismatch instead of relaying.
//   4. DEGRADED: GENERATION VALUE ZERO -- a coinbase paying zero satoshis is
//      still STRUCTURALLY valid (it has an output), so it must round-trip and
//      pass. Zero value is an economics question; zero OUTPUTS is a framing
//      defect. The test pins that the gate distinguishes them.
//   5. JOB-BUILDER INVARIANT -- coinb1_ends_in_commitment_slot() accepts a
//      hardened job's coinb1 and rejects the G2 62-byte segment, so the
//      extranonce slot provably sits inside a real commitment output.
//   6. TRUNCATION / TRAILING BYTES -- a short read or extra tail is refused
//      rather than silently accepted.
//
// Build posture matches the other bch seam tests: header-only over coin/*.hpp
// plus coin/transaction.cpp for the MutableTransaction ctors; impl_bch is NOT
// linked, so per-coin isolation stays clean. p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <vector>

#include "../coin/block.hpp"
#include "../coin/block_assembly.hpp"
#include "../coin/mempool.hpp"
#include "../coin/merkle.hpp"
#include "../coin/reconstruct_won_block.hpp"
#include "../coin/transaction.hpp"
#include "../stratum/coinbase_slot_guard.hpp"

namespace {

int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::cerr << "FAIL: " #cond " @ line " << __LINE__ << "\n"; ++failures; } } while (0)

using bch::coin::MutableTransaction;
using bch::coin::TxIn;
using bch::coin::TxOut;

// ---------------------------------------------------------------------------
// Byte-level builders. These deliberately emit RAW BYTES rather than reusing
// the struct serializers, because the whole point of the G2 failure was that
// the bytes on the wire and the objects in memory disagreed.
// ---------------------------------------------------------------------------

void push_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t(x)); v.push_back(uint8_t(x >> 8));
    v.push_back(uint8_t(x >> 16)); v.push_back(uint8_t(x >> 24));
}
void push_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t(x >> (8 * i)));
}

/// The first coinbase segment a Stratum job hands out, up to the extranonce
/// seam. `n_payout_outputs` payout outputs, then -- when `commitment` is set --
/// the OP_RETURN commitment output truncated at its 8-byte extranonce slot.
/// With `commitment == false` and no payouts this reproduces the G2 shape
/// exactly: 62 bytes ending in an output count of 0x00.
std::vector<uint8_t> build_coinb1(size_t n_payout_outputs, bool commitment,
                                  int64_t payout_value = 625000000,
                                  const uint8_t* ref_hash32 = nullptr)
{
    static const uint8_t kScriptSig[15] = {
        0x03, 0x40, 0x0d, 0x0e, 0x08, 0x2f, 0x63, 0x32,
        0x70, 0x6f, 0x6f, 0x6c, 0x2d, 0x62, 0x63 };
    static const uint8_t kZeroRef[32] = {0};
    if (!ref_hash32) ref_hash32 = kZeroRef;

    std::vector<uint8_t> c;
    push_u32_le(c, 1);                      // tx version
    c.push_back(0x01);                      // vin count = 1
    c.insert(c.end(), 32, 0x00);            // null prevout hash
    push_u32_le(c, 0xFFFFFFFFu);            // prevout index
    c.push_back(uint8_t(sizeof(kScriptSig)));
    c.insert(c.end(), kScriptSig, kScriptSig + sizeof(kScriptSig));
    push_u32_le(c, 0xFFFFFFFFu);            // sequence
    c.push_back(uint8_t(n_payout_outputs + (commitment ? 1 : 0)));  // output count

    for (size_t i = 0; i < n_payout_outputs; ++i) {
        push_u64_le(c, uint64_t(payout_value));
        c.push_back(0x19);                  // P2PKH script length (25)
        const uint8_t p2pkh[25] = {0x76, 0xa9, 0x14,
            0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
            0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,
            0x88, 0xac};
        c.insert(c.end(), p2pkh, p2pkh + 25);
    }
    if (commitment) {
        push_u64_le(c, 0);                  // 0 sats
        c.push_back(0x2a);                  // script length 42
        c.push_back(0x6a);                  // OP_RETURN
        c.push_back(0x28);                  // PUSH_40
        c.insert(c.end(), ref_hash32, ref_hash32 + 32);
        // stops here: the 8-byte extranonce slot is what the miner supplies
    }
    return c;
}

/// coinb1 || en1 || en2 || coinb2 -- exactly what a miner submits back.
std::vector<uint8_t> splice_coinbase(const std::vector<uint8_t>& coinb1)
{
    std::vector<uint8_t> tx = coinb1;
    const uint8_t extranonce[8] = {0xde,0xad,0xbe,0xef, 0x01,0x02,0x03,0x04};
    tx.insert(tx.end(), extranonce, extranonce + 8);
    push_u32_le(tx, 0);                     // coinb2 == locktime
    return tx;
}

uint256 txid_of_bytes(const std::vector<uint8_t>& tx_bytes)
{
    return Hash(std::span<const uint8_t>(tx_bytes.data(), tx_bytes.size()));
}

/// The 80-byte header the miner solves, over an explicit transaction root.
std::vector<unsigned char> header_over(const uint256& root)
{
    uint256 prev;
    prev.SetHex("000000000000000001dfb1f2a4c0e0ecb0f7a1c2d3e4f5061728394a5b6c7d8e");
    return bch::coin::serialize_block_header80(
        /*version=*/0x20000000, prev, root,
        /*timestamp=*/1753200000u, /*bits=*/0x1a0ffff0u, /*nonce=*/0x0badf00du);
}

MutableTransaction make_other_tx(const char* prev_hex, uint32_t idx, int64_t value)
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash.SetHex(prev_hex);
    in.prevout.index = idx;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    static const unsigned char op_true[1] = {0x51};  // OP_TRUE
    out.scriptPubKey = OPScript(op_true, op_true + 1);
    tx.vout.push_back(out);
    return tx;
}

// ---------------------------------------------------------------------------

/// 1 + 4: a well-formed won block round-trips; coinbase-only and populated.
void test_roundtrip_ok()
{
    for (int64_t payout_value : {int64_t(625000000), int64_t(0)}) {
        // Coinbase-only: root == the coinbase txid.
        auto gentx = splice_coinbase(build_coinb1(1, /*commitment=*/true, payout_value));
        const uint256 gentx_hash = txid_of_bytes(gentx);
        auto hdr = header_over(gentx_hash);
        CHECK(hdr.size() == 80);

        std::vector<const MutableTransaction*> none;
        bch::coin::BlockSelfCheck check;
        auto blk = bch::coin::reconstruct_won_block_from_parts(
            std::span<const unsigned char>(hdr.data(), hdr.size()),
            std::span<const unsigned char>(gentx.data(), gentx.size()),
            none, &check);

        CHECK(blk.has_value());
        CHECK(check.ok);
        CHECK(std::string(check.reason).empty());
        CHECK(check.tx_count == 1);
        CHECK(check.gentx_outputs == 2);   // payout + commitment
        CHECK(check.computed_merkle_root == check.header_merkle_root);
        if (blk) {
            CHECK(blk->bytes.size() == 80 + 1 + gentx.size());
            CHECK(blk->hex.size() == blk->bytes.size() * 2);
        }
    }

    // Populated: root over [coinbase, tx1, tx2].
    auto gentx = splice_coinbase(build_coinb1(2, /*commitment=*/true));
    const uint256 gentx_hash = txid_of_bytes(gentx);
    auto t1 = make_other_tx("11" "00000000000000000000000000000000000000000000000000000000000000", 0, 1000);
    auto t2 = make_other_tx("22" "00000000000000000000000000000000000000000000000000000000000000", 1, 2000);

    std::vector<uint256> ids{gentx_hash,
                             bch::coin::compute_txid(t1),
                             bch::coin::compute_txid(t2)};
    auto hdr = header_over(bch::coin::compute_merkle_root(ids));

    std::vector<const MutableTransaction*> others{&t1, &t2};
    bch::coin::BlockSelfCheck check;
    auto blk = bch::coin::reconstruct_won_block_from_parts(
        std::span<const unsigned char>(hdr.data(), hdr.size()),
        std::span<const unsigned char>(gentx.data(), gentx.size()),
        others, &check);

    CHECK(blk.has_value());
    CHECK(check.ok);
    CHECK(check.tx_count == 3);
    CHECK(check.gentx_outputs == 3);
    CHECK(check.computed_merkle_root == check.header_merkle_root);
}

/// 2: the historical G2 body is refused, by name, and its size is the one that
/// was observed on the wire.
void test_g2_zero_output_body_refused()
{
    auto coinb1 = build_coinb1(0, /*commitment=*/false);
    CHECK(coinb1.size() == 62);                      // the observed first segment

    auto gentx = splice_coinbase(coinb1);
    CHECK(gentx.size() == 74);                       // 62 + 8 extranonce + 4 locktime

    // The miner hashes these bytes, so the header's root is "consistent" with
    // them -- which is exactly why a root check alone against the miner's own
    // buffer would NOT have caught this. Only re-deserializing does.
    auto hdr = header_over(txid_of_bytes(gentx));

    std::vector<const MutableTransaction*> none;
    bch::coin::BlockSelfCheck check;
    auto blk = bch::coin::reconstruct_won_block_from_parts(
        std::span<const unsigned char>(hdr.data(), hdr.size()),
        std::span<const unsigned char>(gentx.data(), gentx.size()),
        none, &check);

    CHECK(!blk.has_value());                          // REFUSED -- not relayed
    CHECK(!check.ok);

    // Pin the total: 80 + 1 + 74 == 155, the body seen on the live pool.
    auto framed = bch::coin::frame_won_block(
        std::span<const unsigned char>(hdr.data(), hdr.size()),
        std::span<const unsigned char>(gentx.data(), gentx.size()),
        none);
    CHECK(framed.size() == 155);
    auto verdict = bch::coin::verify_assembled_block(
        std::span<const unsigned char>(framed.data(), framed.size()));
    CHECK(!verdict.ok);
    // Either the decoder chokes on the extranonce sitting where the locktime
    // should be, or it decodes a zero-output coinbase. Both are refusals; the
    // gate must never let this body through.
    CHECK(std::string(verdict.reason).find("ZERO outputs") != std::string::npos ||
          std::string(verdict.reason).find("re-deserialize") != std::string::npos ||
          std::string(verdict.reason).find("trailing bytes") != std::string::npos);
    std::cerr << "note: G2 155-byte body refused -- " << verdict.reason << "\n";
}

/// 3: reference hash absent -> the header cannot describe the transactions.
void test_degraded_reference_hash_absent()
{
    // Commitment output present but its reference hash is all zeros: the job
    // was published without a usable reference, so the header the pool rebuilds
    // (from the share's merkle link over a DIFFERENT coinbase) will not match.
    auto gentx_published = splice_coinbase(build_coinb1(1, /*commitment=*/true));
    auto gentx_rebuilt   = splice_coinbase(build_coinb1(2, /*commitment=*/true));

    // Header over the published coinbase; body carries the rebuilt one.
    auto hdr = header_over(txid_of_bytes(gentx_published));

    std::vector<const MutableTransaction*> none;
    bch::coin::BlockSelfCheck check;
    auto blk = bch::coin::reconstruct_won_block_from_parts(
        std::span<const unsigned char>(hdr.data(), hdr.size()),
        std::span<const unsigned char>(gentx_rebuilt.data(), gentx_rebuilt.size()),
        none, &check);

    CHECK(!blk.has_value());
    CHECK(!check.ok);
    CHECK(std::string(check.reason).find("does not match") != std::string::npos);
    CHECK(check.computed_merkle_root != check.header_merkle_root);
}

/// 5: the job-builder invariant is machine-checkable.
void test_job_builder_commitment_slot_invariant()
{
    // Hardened job: commitment output present, coinb1 stops at the slot.
    CHECK(bch::stratum::coinb1_ends_in_commitment_slot(build_coinb1(1, true)));
    CHECK(bch::stratum::coinb1_ends_in_commitment_slot(build_coinb1(4, true)));
    // A payout-free job STILL has the commitment output after hardening.
    CHECK(bch::stratum::coinb1_ends_in_commitment_slot(build_coinb1(0, true)));

    // The G2 shape: no commitment output, coinb1 ends at the output count.
    CHECK(!bch::stratum::coinb1_ends_in_commitment_slot(build_coinb1(0, false)));
    // Payout outputs but no commitment: the seam still falls outside a script.
    CHECK(!bch::stratum::coinb1_ends_in_commitment_slot(build_coinb1(2, false)));

    // A coinb1 that already includes the extranonce leaves no slot to fill.
    CHECK(!bch::stratum::coinb1_ends_in_commitment_slot(splice_coinbase(build_coinb1(1, true))));
    // Truncated garbage.
    CHECK(!bch::stratum::coinb1_ends_in_commitment_slot({}));
    CHECK(!bch::stratum::coinb1_ends_in_commitment_slot({0x01, 0x00, 0x00}));
}

/// 6: truncation and trailing bytes are refusals, not silent passes.
void test_truncation_and_trailing_bytes()
{
    auto gentx = splice_coinbase(build_coinb1(1, true));
    auto hdr = header_over(txid_of_bytes(gentx));
    std::vector<const MutableTransaction*> none;

    auto good = bch::coin::frame_won_block(
        std::span<const unsigned char>(hdr.data(), hdr.size()),
        std::span<const unsigned char>(gentx.data(), gentx.size()),
        none);
    CHECK(bch::coin::verify_assembled_block(
        std::span<const unsigned char>(good.data(), good.size())).ok);

    auto truncated = good;
    truncated.resize(truncated.size() - 5);
    CHECK(!bch::coin::verify_assembled_block(
        std::span<const unsigned char>(truncated.data(), truncated.size())).ok);

    auto trailing = good;
    trailing.push_back(0xff);
    auto v = bch::coin::verify_assembled_block(
        std::span<const unsigned char>(trailing.data(), trailing.size()));
    CHECK(!v.ok);
    CHECK(std::string(v.reason).find("trailing bytes") != std::string::npos);

    // Header-only body (no transactions at all).
    std::vector<unsigned char> headerless(hdr.begin(), hdr.end());
    headerless.push_back(0x00);   // tx count = 0
    auto hv = bch::coin::verify_assembled_block(
        std::span<const unsigned char>(headerless.data(), headerless.size()));
    CHECK(!hv.ok);
    CHECK(std::string(hv.reason).find("no transactions") != std::string::npos);
}

} // namespace

int main()
{
    test_roundtrip_ok();
    test_g2_zero_output_body_refused();
    test_degraded_reference_hash_absent();
    test_job_builder_commitment_slot_invariant();
    test_truncation_and_trailing_bytes();

    if (failures) {
        std::cerr << failures << " CHECK(s) failed\n";
        return 1;
    }
    std::cout << "g2_block_assembly_roundtrip_test: all checks passed\n";
    return 0;
}
