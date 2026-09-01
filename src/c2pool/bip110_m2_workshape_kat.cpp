// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_m2_workshape_kat — the KILLER known-answer test for BIP-110 M2 mining
// (template -> serve -> share -> submit -> block-arm). Two proofs, both network-
// free, both over the SAME SSOT fold the live work source uses
// (src/impl/bip110/stratum/pseudoheader.hpp):
//
//   (A) WORK-SHAPE. From the real 164-byte v2 header of live fork block 961640
//       (the first BLAKE2b block; a Knots checkpoint), reconstruct the Stratum
//       mapping and prove it reproduces the CANONICAL block hash:
//         * compute h1/h2 from the frozen header fields
//         * wire_coinb1 == u32(0) || h2 || u32(0) || u32(0)   (the coinb1 a miner
//           receives; parse_h2_from_wire_coinb1 round-trips it)
//         * root == BLAKE2b256(u32(0) || h2 || extranonce16)   (== pow.hpp b1)
//         * the 80-byte profile-0 buffer (prevblock_hidden || nNonce || nonce2 ||
//           time_offset || nonce3 || root) BLAKE2b256 -> reversed == canonical.
//       This is the byte-exact proof the Sv1 work-shape IS the chain's own hash.
//
//   (B) SUBMIT ROUNDTRIP. Build a coinbase-only job (block_version 0xA0000000,
//       subsidy 3.125 BTC exact, txcount 1, flags/xor_key zero — R10), freeze
//       h1/h2 over the real coinbase txid, CPU-grind nNonce to a TRIVIAL local
//       target, run the submit fold (rebuild the 164-byte header from the freeze
//       + the winning nonce/extranonce), and prove:
//         * the reassembled header re-hashes to the SAME PoW the grinder found,
//         * PoW <= the trivial target (a "block" is found),
//         * the block-arm bytes = header(164) || varint(txcount) || coinbase, and
//           re-slicing header from those bytes re-hashes to the same PoW,
//         * the rebuild is byte-exact deterministic (R2 nonce split pinned).
//
// R10: pow.hpp THROWS on flags!=0 / xor_key!=0, so M2 must always emit zeros —
// asserted here. R2: the 8-byte nonce/ntime split (nNonce||m_nonce2,
// time||m_nonce3) is PINNED by the roundtrip; a wrong split fails this KAT.

#include <impl/bip110/pow.hpp>
#include <impl/bip110/stratum/pseudoheader.hpp>
#include <impl/bip110/coin/gentx_coinbase.hpp>   // SSOT coinbase (same path as the live work source)
#include <impl/bip110/crypto/blake2b.h>

#include <core/uint256.hpp>

#include <btclibs/crypto/sha256.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace {

using bip110::stratum::Bytes32;
using bip110::stratum::HeaderFreeze;
using bip110::stratum::from_hex;
using bip110::stratum::to_hex;

int g_fail = 0;

void expect(const std::string& what, bool ok)
{
    std::printf(ok ? "  [ok]   %s\n" : "  [FAIL] %s\n", what.c_str());
    if (!ok) ++g_fail;
}

void expect_eq(const std::string& what, const std::string& got, const std::string& exp)
{
    if (got == exp) { std::printf("  [ok]   %s = %s\n", what.c_str(), got.c_str()); }
    else { std::printf("  [FAIL] %s\n         got %s\n         exp %s\n",
                       what.c_str(), got.c_str(), exp.c_str()); ++g_fail; }
}

// double-SHA256 (Bitcoin txid), returns internal (LE) byte order.
Bytes32 sha256d(const unsigned char* p, size_t n)
{
    unsigned char a[32], b[32];
    CSHA256().Write(p, n).Finalize(a);
    CSHA256().Write(a, 32).Finalize(b);
    Bytes32 out; std::memcpy(out.data(), b, 32); return out;
}

std::array<unsigned char, 8> u64be(uint64_t v)
{
    std::array<unsigned char, 8> o{};
    for (int i = 7; i >= 0; --i) { o[i] = static_cast<unsigned char>(v & 0xff); v >>= 8; }
    return o;
}

// Build the LIVE coinbase shape via the SSOT assembler — the SAME code path the
// work source uses (bip110::coin::assemble_gentx_coinbase). This is deliberately
// NOT a test-local reimplementation: emission (block-arm) and verification (this
// KAT) MUST share ONE coinbase path so a witness/serialization defect cannot hide
// behind a divergent test shape (DEFECT 3). The coinbase carries the BIP141
// witness-commitment output, so cb.block_bytes is the BIP144 witness form (with
// the 1x32-byte reserved value) while cb.txid/cb.bytes stay non-witness.
bip110::coin::GentxCoinbase build_live_coinbase(uint32_t height, uint64_t subsidy_sat)
{
    // scriptSig = BIP34 minimal-push of height + "/c2pool-bip110/" tag (mirrors
    // work_source.cpp build_connection_coinbase).
    std::vector<unsigned char> cb_script;
    {
        uint32_t h = height;
        std::vector<unsigned char> he;
        while (h) { he.push_back(h & 0xff); h >>= 8; }
        if (he.empty() || (he.back() & 0x80)) he.push_back(0x00);
        cb_script.push_back(static_cast<unsigned char>(he.size()));
        cb_script.insert(cb_script.end(), he.begin(), he.end());
        const char* tag = "/c2pool-bip110/";
        for (const char* c = tag; *c; ++c) cb_script.push_back((unsigned char)*c);
    }

    // Witness commitment over a zero witness-merkle-root (coinbase-only): header
    // 6a24aa21a9ed || SHA256d(witness_merkle_root(0) || reserved(0*32)).
    std::vector<unsigned char> wroot(32, 0);
    {
        std::vector<unsigned char> pre(64, 0);
        unsigned char a[32], b[32];
        CSHA256().Write(pre.data(), pre.size()).Finalize(a);
        CSHA256().Write(a, 32).Finalize(b);
        std::memcpy(wroot.data(), b, 32);
    }
    std::vector<unsigned char> sc = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    sc.insert(sc.end(), wroot.begin(), wroot.end());
    std::optional<std::vector<unsigned char>> segwit_commit = sc;

    // P2PKH payout of the whole subsidy, empty-ish donation placeholder, OP_RETURN.
    std::vector<unsigned char> spk = {0x76,0xa9,0x14};
    for (int i=0;i<20;++i) spk.push_back(0x11);
    spk.push_back(0x88); spk.push_back(0xac);
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payouts;
    payouts.emplace_back(spk, subsidy_sat);
    std::vector<unsigned char> donation = {0x6a};       // OP_RETURN placeholder (0-value)
    std::vector<unsigned char> op_return = {0x6a, 0x00};

    return bip110::coin::assemble_gentx_coinbase(
        cb_script, segwit_commit, payouts, /*donation_amount=*/0, donation, op_return);
}

// Verify a BIP144 coinbase (block_bytes) exposes exactly one 32-byte witness
// element on its single input (the reserved value), i.e. it will PASS Knots/Core
// CheckWitnessMalleation. Returns true iff the structure is
//   version(4) | 0x00 0x01 | vin | vout | 0x01 0x20 32*00 | locktime(4)
// and captures the witness stack hex (should be "012000..00").
bool witness_nonce_ok(const std::vector<unsigned char>& blk, std::string& witness_hex)
{
    if (blk.size() < 4 + 2 + 1 + 2 + 32 + 4) return false;
    if (blk[4] != 0x00 || blk[5] != 0x01) return false;    // segwit marker+flag
    // The witness for the single coinbase input sits immediately before the
    // 4-byte locktime: [count=0x01][len=0x20][32 bytes].
    const size_t wend = blk.size() - 4;                    // start of locktime
    const size_t wstart = wend - (1 + 1 + 32);
    if (blk[wstart] != 0x01) return false;                 // exactly one stack item
    if (blk[wstart + 1] != 0x20) return false;             // element length 32
    for (size_t i = 0; i < 32; ++i)
        if (blk[wstart + 2 + i] != 0x00) return false;     // reserved value = 0*32
    witness_hex = bip110::stratum::to_hex(
        std::vector<unsigned char>(blk.begin() + wstart, blk.begin() + wend));
    return true;
}

// ── (A) WORK-SHAPE against real block 961640 ────────────────────────────────
void test_workshape_961640()
{
    std::printf("[A] work-shape reproduces canonical block hash of live fork 961640:\n");
    const std::string header_hex =
        "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000";
    const std::string canonical =
        "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";
    std::vector<unsigned char> H = from_hex(header_hex);

    // Sanity: pow.hpp itself reproduces the canonical hash (M1 gate).
    uint256 pow_hash = bip110::pow::blake2b_block_hash(std::span<const unsigned char>(H.data(), H.size()));
    expect_eq("pow.hpp block hash", pow_hash.GetHex(), canonical);

    // Parse the header fields into a freeze and derive h1/h2 via the SSOT.
    const bip110::pow::HeaderV2 hv = bip110::pow::parse_header_v2(H);
    HeaderFreeze f;
    std::memcpy(f.version.data(), hv.version, 4);
    std::memcpy(f.prev.data(),    hv.prev, 32);
    std::memcpy(f.merkle.data(),  hv.merkle, 32);
    std::memcpy(f.time.data(),    hv.time, 4);
    std::memcpy(f.nbits.data(),   hv.nbits, 4);
    f.txcount    = (uint16_t)(hv.txcount[0] | (hv.txcount[1] << 8));
    f.flags      = hv.flags[0];
    f.clear_bits = hv.clear_bits[0];
    std::memcpy(f.xor_key.data(), hv.xor_key, 16);
    f.height     = (uint32_t)(hv.height[0] | (hv.height[1]<<8) | (hv.height[2]<<16) | ((uint32_t)hv.height[3]<<24));
    std::memcpy(f.mm_rhs.data(),  hv.mm_rhs, 32);
    bip110::stratum::compute_h1_h2(f);

    // wire coinb1 == u32(0) || h2 || u32(0) || u32(0), and h2 round-trips.
    auto coinb1 = bip110::stratum::wire_coinb1_bytes(f.h2);
    std::string expect_coinb1 = "00000000" + to_hex(f.h2) + "0000000000000000";
    expect_eq("wire_coinb1", to_hex(coinb1), expect_coinb1);
    Bytes32 h2_rt = bip110::stratum::parse_h2_from_wire_coinb1(coinb1);
    expect("parse_h2_from_wire_coinb1 round-trips", h2_rt == f.h2);

    // root == BLAKE2b(u32(0) || h2 || real-extranonce16)
    std::array<unsigned char, 16> ex16{};
    std::memcpy(ex16.data(), hv.extranonce, 16);
    Bytes32 root = bip110::stratum::compute_root(f.h2, ex16);

    // 80-byte profile-0 buffer from the header's real rolled fields -> canonical.
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), f.prevblock_hidden.begin(), f.prevblock_hidden.end());
    buf.insert(buf.end(), hv.nonce, hv.nonce + 4);
    buf.insert(buf.end(), hv.nonce2, hv.nonce2 + 4);
    buf.insert(buf.end(), hv.time_offset, hv.time_offset + 4);
    buf.insert(buf.end(), hv.nonce3, hv.nonce3 + 4);
    buf.insert(buf.end(), root.begin(), root.end());
    expect("profile-0 buffer is 80 bytes", buf.size() == 80);
    bip110::pow::Bytes32 b2 = bip110::pow::blake2b256(buf.data(), buf.size());
    // canonical display hash == hex(b2) directly when xor_key is null (pow.hpp:
    // internal[31-i]=b2[i], GetHex() reverses internal back to b2 order).
    expect_eq("SSOT profile-0 -> canonical hash",
              to_hex(std::span<const unsigned char>(b2.data(), 32)), canonical);
}

// ── (B) SUBMIT ROUNDTRIP: build -> grind -> submit -> block-arm ─────────────
void test_submit_roundtrip()
{
    std::printf("[B] submit roundtrip (build -> grind -> submit -> block-arm):\n");

    const uint32_t height = 961700;
    const uint64_t subsidy = 312500000ULL;   // 3.125 BTC exact (post-fork era)

    // Coinbase-only template built via the LIVE SSOT path (with witness
    // commitment). merkle field = coinbase txid over the NON-witness bytes.
    bip110::coin::GentxCoinbase cb = build_live_coinbase(height, subsidy);
    const std::vector<unsigned char>& coinbase       = cb.bytes;        // non-witness (txid/merkle)
    const std::vector<unsigned char>& coinbase_block = cb.block_bytes;  // BIP144 witness (block body)
    Bytes32 cb_txid;
    std::memcpy(cb_txid.data(), cb.txid.data(), 32);
    // Independent cross-check: txid is the double-SHA256 of the non-witness bytes.
    expect("cb.txid == sha256d(non-witness bytes)", cb_txid == sha256d(coinbase.data(), coinbase.size()));
    // The witness form MUST differ from the non-witness form (it carries the
    // reserved-value witness) and MUST be longer by exactly marker+flag+witness.
    expect("block_bytes carries a witness (differs from non-witness bytes)",
           coinbase_block != coinbase);
    expect("block_bytes length == non-witness + 2 (marker/flag) + 34 (witness)",
           coinbase_block.size() == coinbase.size() + 2 + 34);

    HeaderFreeze f;
    // block_version 0xA0000000 = bit31 v2 flag | 0x20000000, little-endian on wire.
    f.version = { 0x00, 0x00, 0x00, 0xA0 };
    // A plausible prev (the 961640 canonical hash, internal order = reverse(display)).
    {
        auto d = from_hex("0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb");
        for (int i = 0; i < 32; ++i) f.prev[i] = d[31 - i];
    }
    f.merkle = cb_txid;
    f.time   = { 0x00, 0xa9, 0xc9, 0x42 };       // arbitrary wire time area
    // Trivial nBits so a "block" is grindable in-process: exponent 0x1f, huge target.
    f.nbits  = { 0xff, 0xff, 0x00, 0x1f };        // 0x1f00ffff LE on wire
    f.txcount = 1;
    f.flags = 0; f.clear_bits = 0;                // R10 zeros
    f.height = height;
    bip110::stratum::compute_h1_h2(f);

    // R10: flags/xor_key must be zero (compute_h1_h2 throws otherwise — proven by
    // reaching here without exception; assert the fields too).
    expect("R10: flags == 0", f.flags == 0);
    expect("R10: clear_bits == 0", f.clear_bits == 0);
    bool xk0 = true; for (unsigned char b : f.xor_key) if (b) xk0 = false;
    expect("R10: xor_key null", xk0);

    // Server-side gateway extranonce1 (4 B) + miner extranonce2 (4 B).
    std::array<unsigned char, 4> en1 = { 0xde, 0xad, 0xbe, 0xef };
    std::array<unsigned char, 4> en2 = { 0x00, 0x00, 0x00, 0x00 };

    // TRIVIAL local target: 2 leading zero bytes (display-hex compare).
    const std::string trivial_target = "0000" + std::string(60, 'f');

    // CPU-grind nNonce (via the 8-byte submit nonce low half) until PoW <= target.
    std::array<unsigned char, 8> ntime8{};       // no ntime roll (R3): m_nonce3/time-area 0 here
    std::array<unsigned char, 8> nonce8{};
    std::string found_hash;
    std::vector<unsigned char> won_header;
    uint32_t winning_nonce = 0;
    bool found = false;
    for (uint32_t n = 0; n < 5'000'000u; ++n) {
        nonce8 = u64be((uint64_t)n);             // low 4 -> nNonce, high 4 -> m_nonce2 (=0)
        auto hdr = bip110::stratum::rebuild_header_v2(f, en1, en2, nonce8, ntime8);
        uint256 pw = bip110::pow::blake2b_block_hash(std::span<const unsigned char>(hdr.data(), hdr.size()));
        if (pw.GetHex() <= trivial_target) {
            found = true; winning_nonce = n; found_hash = pw.GetHex();
            won_header = std::move(hdr); break;
        }
    }
    expect("grind found a block <= trivial target", found);
    if (!found) return;
    std::printf("         winning nNonce=%u  h2=%s\n         found hash=%s\n",
                winning_nonce, to_hex(f.h2).c_str(), found_hash.c_str());

    // ── SUBMIT FOLD (what work_source.mining_submit does independently) ──
    // Rebuild the header from the freeze + the miner's submitted nonce/extranonce
    // and recompute the PoW — never trust a miner-reported hash.
    auto resubmit_hdr = bip110::stratum::rebuild_header_v2(f, en1, en2, nonce8, ntime8);
    expect("submit rebuild is byte-exact deterministic", resubmit_hdr == won_header);
    uint256 pw2 = bip110::pow::blake2b_block_hash(std::span<const unsigned char>(resubmit_hdr.data(), resubmit_hdr.size()));
    expect_eq("submit recompute == grind PoW", pw2.GetHex(), found_hash);
    expect("recomputed PoW <= block target", pw2.GetHex() <= trivial_target);
    expect("won header is 164 bytes", won_header.size() == 164);

    // ── BLOCK ARM: header(164) || varint(txcount=1) || BIP144 witness coinbase ──
    // The block body MUST carry the witness coinbase (coinbase_block), exactly as
    // work_source.cpp mining_submit does — shipping the non-witness form with the
    // commitment output present is bad-witness-nonce-size (DEFECT 1).
    std::vector<unsigned char> block;
    block.insert(block.end(), won_header.begin(), won_header.end());
    block.push_back(0x01);                        // varint txcount = 1
    block.insert(block.end(), coinbase_block.begin(), coinbase_block.end());

    // Re-slice the header from the assembled block and re-hash -> same PoW.
    std::vector<unsigned char> reslice(block.begin(), block.begin() + 164);
    expect("block[0:164] == won header", reslice == won_header);
    uint256 pw3 = bip110::pow::blake2b_block_hash(std::span<const unsigned char>(reslice.data(), reslice.size()));
    expect_eq("block-arm re-hash == PoW", pw3.GetHex(), found_hash);

    // The header's merkle field commits the coinbase txid (over the NON-witness
    // bytes — the witness does NOT change the txid, the segwit invariant).
    expect("header merkle == coinbase txid (non-witness)",
           std::memcmp(reslice.data() + 36, cb_txid.data(), 32) == 0);

    // ── DEFECT 1 GATE: the reassembled block's coinbase has a VALID witness nonce
    // (one 32-byte reserved-value element) whenever a commitment output exists —
    // the CheckWitnessMalleation-equivalent assertion. This is the check that the
    // old test-local plain-P2PKH coinbase could never make (DEFECT 3).
    std::string witness_hex;
    expect("BIP144 witness nonce valid (0x01 0x20 32*00) — CheckWitnessMalleation",
           witness_nonce_ok(coinbase_block, witness_hex));
    expect_eq("coinbase witness stack", witness_hex,
              std::string("0120") + std::string(64, '0'));

    std::printf("         reassembled block: %zu bytes (164 hdr + 1 varint + %zu witness-coinbase)\n",
                block.size(), coinbase_block.size());
    std::printf("         header hex: %s\n", to_hex(won_header).c_str());
    std::printf("         witness-coinbase hex: %s\n", to_hex(coinbase_block).c_str());
    std::printf("         witness stack: %s (count=01 len=20 reserved=32*00)\n", witness_hex.c_str());
}

} // namespace

int main()
{
    std::printf("=== bip110_m2_workshape_kat ===\n");
    test_workshape_961640();
    test_submit_roundtrip();
    if (g_fail == 0) {
        std::printf("RESULT: PASS — M2 work-shape + submit-roundtrip reproduced end to end.\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
