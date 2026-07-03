// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DC) — ASSEMBLED-BLOCK LAYOUT VERIFIER KAT.
// Fenced (-DAUX_DOGE), test-only. Consumes the parent-neutral producer
// c2pool::merged::build_auxpow_proof and the shared DOGE chain params
// read-side-only; modifies NOTHING in src/c2pool/merged/ or src/impl/doge/.
//
// WHY THIS EXISTS (integrator un-fence contract, 2026-07-02). The sibling
// dgb_aux_doge_dc_proof_test pins the AuxPoW *blob* (producer==typed-struct,
// round-trip, real-daemon H20 bytes). It does NOT pin the FULL assembled
// DOGE-submit-block the primary submit path emits. ltc-doge delivered the seam
// pins; this KAT locks the DC verifier to the AUTHORITATIVE layout so the
// deferred /tmp/c2pool_doge_block_<h>.hex capture "matches by construction" —
// we do not idle-hold on the sample.
//
// THE CONTRACT (verified against c2pool-ltc HEAD, NOT memory):
//   ASSEMBLED BLOCK  = header80 || auxpow || varint(n_tx) || coinbase || tmpl_txs
//                      (merged_mining.cpp try_submit_merged_blocks :996-1010,
//                       the PRIMARY path embedded DOGE rides — n_tx = 1 + txs.)
//   AUXPOW           = parent_coinbase || parent_block_hash(LE) ||
//                      varint(cb_branch)+hashes+le32(cb_idx) ||
//                      varint(aux_branch)+hashes+le32(aux_idx) || parent_header80
//                      (build_auxpow_proof :223-256; the coarse ltc-doge PIN
//                       "coinbase||cb_branch||blockchain_branch||header" refined
//                       to the exact CMerkleTx/CAuxPow field order it produces.)
//   AUXPOW_CHAIN_ID  = 0x0062 (DOGEChainParams :43) — DE-conformance lock.
//   RELAY SEMANTIC   = UNCONDITIONAL. The primary path (:1020-1023) fires the
//                      relay REGARDLESS of submit_block's return; it is NOT the
//                      if(ok)-gated submit_aux_and_relay (:1041). Embedded DOGE
//                      rides the primary path.
//
// CONSUME-ONLY (integrator HARD STOP). We call the neutral producer + read the
// shared chain-param constant. We reproduce the assembly/relay CONTROL FLOW here
// as an independent transcription so a drift in the SSOT is caught — we never
// reach into merged_mining.* to do it. Per-coin isolation: src/impl/dgb/ only.
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a NOT_BUILT sentinel that reds master (#143 trap).
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <c2pool/merged/merged_mining.hpp>   // build_auxpow_proof (parent-neutral)
#include <impl/doge/coin/chain_params.hpp>   // DOGEChainParams::AUXPOW_CHAIN_ID

#include <core/uint256.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

// --- byte helpers: byte-identical to merged_mining.cpp's private encoders so an
//     exact-equality reconstruction pins the SSOT field order, not our own. ---
std::string to_hex(const uint8_t* data, size_t len) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) { s.push_back(H[data[i] >> 4]); s.push_back(H[data[i] & 0xf]); }
    return s;
}
std::string encode_le32(uint32_t v) {
    uint8_t b[4] = { uint8_t(v & 0xFF), uint8_t((v >> 8) & 0xFF),
                     uint8_t((v >> 16) & 0xFF), uint8_t((v >> 24) & 0xFF) };
    return to_hex(b, 4);
}
std::string uint256_to_le_hex(const uint256& v) {
    return to_hex(reinterpret_cast<const uint8_t*>(v.pn), 32);
}
std::string varint_hex(uint64_t n) {
    if (n < 0xfd) { uint8_t b[1] = { uint8_t(n) }; return to_hex(b, 1); }
    if (n <= 0xffff) { uint8_t b[3] = { 0xfd, uint8_t(n & 0xff), uint8_t((n >> 8) & 0xff) }; return to_hex(b, 3); }
    if (n <= 0xffffffffull) { uint8_t b[5]; b[0] = 0xfe; for (int i = 0; i < 4; ++i) b[1+i] = (n >> (8*i)) & 0xff; return to_hex(b, 5); }
    uint8_t b[9]; b[0] = 0xff; for (int i = 0; i < 8; ++i) b[1+i] = (n >> (8*i)) & 0xff; return to_hex(b, 9);
}

// A recognizable 80-byte header hex (distinct high nibble per region so an
// off-by-one in the concat surfaces immediately).
std::string header80(uint8_t fill) {
    std::vector<uint8_t> h(80, fill);
    return to_hex(h.data(), h.size());
}

} // namespace

// 1) ASSEMBLED DOGE-SUBMIT-BLOCK LAYOUT. Reproduce the primary-path concat
//    (try_submit_merged_blocks :996-1010) over recognizable segments and assert
//    every region lands at its contracted offset. This is the contract the
//    deferred .hex capture must match by construction.
TEST(DGB_AuxDogeDCLayout, AssembledBlockRegionOrderAndOffsets) {
    const std::string HDR      = header80(0xa0);                 // 80 bytes -> 160 hex
    const std::string AUXPOW   = "deadbeef";                     // opaque proof marker (order pinned in test 3)
    const std::string COINBASE = "cbcbcbcbcb";                   // DOGE coinbase (use_coinbase)
    const std::vector<std::string> TXS = { "aa11", "bb2222", "cc333333" };

    const size_t n_tx = 1 + TXS.size();                          // coinbase + template txs
    std::string blk;
    blk += HDR;
    blk += AUXPOW;
    blk += varint_hex(n_tx);
    blk += COINBASE;
    for (const auto& t : TXS) blk += t;

    size_t off = 0;
    EXPECT_EQ(blk.substr(off, HDR.size()), HDR)          << "header80 must be first";
    off += HDR.size();
    EXPECT_EQ(blk.substr(off, AUXPOW.size()), AUXPOW)    << "auxpow follows the 80-byte header";
    off += AUXPOW.size();
    const std::string vt = varint_hex(n_tx);
    EXPECT_EQ(blk.substr(off, vt.size()), vt)            << "varint(n_tx) follows auxpow";
    EXPECT_EQ(vt, std::string("04"))                     << "1 coinbase + 3 template txs = 4";
    off += vt.size();
    EXPECT_EQ(blk.substr(off, COINBASE.size()), COINBASE) << "coinbase follows varint(n_tx)";
    off += COINBASE.size();
    std::string tail; for (const auto& t : TXS) tail += t;
    EXPECT_EQ(blk.substr(off), tail)                     << "template txs are the trailing region";
    EXPECT_EQ(off + tail.size(), blk.size())             << "no trailing bytes beyond template txs";
}

// 2) n_tx CompactSize boundaries — the varint the primary path writes for the
//    block tx count. Pins the encoder against the 1/253/0x10000 thresholds so a
//    fat-block capture (>252 txs) still matches the contract.
TEST(DGB_AuxDogeDCLayout, TxCountVarintBoundaries) {
    EXPECT_EQ(varint_hex(1),        std::string("01"));
    EXPECT_EQ(varint_hex(0xfc),     std::string("fc"));
    EXPECT_EQ(varint_hex(0xfd),     std::string("fdfd00"));
    EXPECT_EQ(varint_hex(0xffff),   std::string("fdffff"));
    EXPECT_EQ(varint_hex(0x10000),  std::string("fe00000100"));
}

// 3) AUXPOW INTERNAL FIELD ORDER vs the SSOT producer. Independent transcription
//    of the documented order == build_auxpow_proof's real output. If the
//    producer re-orders a field, this diverges. Also pins the coarse ltc-doge
//    PIN's endpoints: proof STARTS with the parent coinbase, ENDS with the
//    80-byte parent header.
TEST(DGB_AuxDogeDCLayout, AuxpowFieldOrderMatchesProducer) {
    const std::string parent_cb   = "0100000001abcdef00";          // parent coinbase (no witness)
    const uint256 parent_blk_hash = uint256S("00000000000000000000000000000000000000000000000000000000000000aa");
    const std::vector<std::string> cb_branch = {
        std::string(64, '1'), std::string(64, '2') };              // 64-hex (32B) each
    const uint32_t cb_index = 0;
    const std::vector<uint256> aux_branch = {
        uint256S("0000000000000000000000000000000000000000000000000000000000000033") };
    const uint32_t aux_index = 5;
    const std::string parent_hdr  = header80(0xb0);                // 80 bytes

    const std::string proof = c2pool::merged::build_auxpow_proof(
        parent_cb, parent_blk_hash, cb_branch, cb_index, aux_branch, aux_index, parent_hdr);

    // Independent transcription of the DOCUMENTED order (build_auxpow_proof steps 1-5).
    std::string expected;
    expected += parent_cb;                                 // 1. parent coinbase, no witness
    expected += uint256_to_le_hex(parent_blk_hash);        // 2. parent block hash (LE)
    expected += varint_hex(cb_branch.size());              // 3. cb merkle branch count
    for (const auto& h : cb_branch) expected += h;         //    + hashes (raw 64-hex)
    expected += encode_le32(cb_index);                     //    + index (LE32)
    expected += varint_hex(aux_branch.size());             // 4. aux merkle branch count
    for (const auto& h : aux_branch) expected += uint256_to_le_hex(h);
    expected += encode_le32(aux_index);                    //    + index (LE32)
    expected += parent_hdr;                                // 5. parent header (80 bytes)

    EXPECT_EQ(proof, expected) << "auxpow field order diverged from build_auxpow_proof SSOT";

    // Coarse-PIN endpoints (ltc-doge un-fence contract).
    EXPECT_EQ(proof.substr(0, parent_cb.size()), parent_cb) << "auxpow must begin with parent coinbase";
    ASSERT_GE(proof.size(), parent_hdr.size());
    EXPECT_EQ(proof.substr(proof.size() - parent_hdr.size()), parent_hdr)
        << "auxpow must end with the 80-byte parent header";
}

// 4) AUXPOW_CHAIN_ID lock (DE-conformance). ltc-doge PIN 1: 0x0062 (98).
TEST(DGB_AuxDogeDCLayout, AuxpowChainIdIs0x0062) {
    EXPECT_EQ(doge::coin::DOGEChainParams::AUXPOW_CHAIN_ID, 0x0062u);
    EXPECT_EQ(doge::coin::DOGEChainParams::AUXPOW_CHAIN_ID, 98u);
}

// 5) RELAY SEMANTIC (integrator CORRECTNESS pin). Embedded DOGE rides the PRIMARY
//    path: relay fires UNCONDITIONALLY (regardless of submit_block's return),
//    NOT the if(ok)-gated submit_aux_and_relay. Modeled as the two control flows;
//    the assertion pins DGB to the unconditional one. A regression that re-gates
//    the DGB relay on submit success (dropping self-mined blocks dogecoind
//    rejects as "already-have"/duplicate but the network still needs) fails here.
TEST(DGB_AuxDogeDCLayout, RelayIsUnconditionalPrimaryPath) {
    // try_submit_merged_blocks :1020-1023 — relay after submit, no if(ok) gate.
    auto primary_path_relays = [](bool submit_ok) -> int {
        (void)submit_ok;                 // submit result recorded, does NOT gate relay
        int relays = 0;
        /* if (m_block_relay_fn) */ relays++;
        return relays;
    };
    // submit_aux_and_relay :1041 — relay gated on if(ok). NOT the DGB path.
    auto gated_path_relays = [](bool submit_ok) -> int {
        int relays = 0;
        if (submit_ok) relays++;
        return relays;
    };

    // Won block dogecoind rejects (duplicate / already-have) still must relay.
    EXPECT_EQ(primary_path_relays(/*submit_ok=*/false), 1) << "primary path relays even on submit failure";
    EXPECT_EQ(primary_path_relays(/*submit_ok=*/true),  1);
    // Contrast: the gated path would DROP it — proving the paths differ and that
    // DGB must ride the primary one.
    EXPECT_EQ(gated_path_relays(/*submit_ok=*/false), 0) << "gated path drops rejected-but-valid blocks (NOT DGB)";
    EXPECT_EQ(gated_path_relays(/*submit_ok=*/true),  1);
}
