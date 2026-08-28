// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// NMC embedded AuxPoW header-feed golden KAT (issue #980).
//
// Locks the three compounding layers + the two consensus-gate defects that made
// the embedded NMC lane emit no work (AuxChainEmbedded::get_work_template()
// empty forever because the header chain never synced):
//
//   * parse_nmc_headers_message (headers_wire.hpp) — the AuxPoW-carrying parser
//     that recovers the merge-mining proof the shared 80-byte seam drops;
//   * D1 — optional-auxpow post-activation admission + own-PoW for plain headers
//     (check_activation_gate / connect_locked, header_chain.hpp);
//   * D2 — the legacy no-magic commitment branch in scan_mm_commitment;
//   * D3 — anchor-relative activation height (the fixture seeds h19150 as index 0,
//     so the real activation 19200 becomes index 50).
//
// Golden SSOT: nmc_headers_golden_h19150_h19460.hpp — real Namecoin MAINNET P2P
// 'headers' wire, captured 2026-08-28 from public peer 23.106.38.114:8334. 311
// entries / 252 with AuxPoW, spanning the activation crossing (19200), plain
// post-activation blocks (first 19204), marker auxpow, and legacy no-magic
// auxpow (first 19414). Hermetic — no network at test time.
//
// RED on unpatched master: parse_nmc_headers_message does not exist (compile
// red); and even stubbed, h19204 hits REJECT_MISSING_AUXPOW and h19414 hits the
// ABSENT-commitment reject. GREEN with the fix.
//
// Per-coin isolation: src/impl/nmc/ only. MUST appear in BOTH test/CMakeLists.txt
// AND the build.yml --target allowlist or it becomes a NOT_BUILT sentinel.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <optional>
#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/opscript.hpp>
#include <core/target_utils.hpp>

#include "../coin/header_chain.hpp"
#include "../coin/headers_wire.hpp"
#include "nmc_headers_golden_h19150_h19460.hpp"

namespace {

using nmc::coin::AuxPow;
using nmc::coin::BlockHeaderType;
using nmc::coin::HeaderChain;
using nmc::coin::MutableTransaction;
using nmc::coin::NMCChainParams;
using nmc::coin::WireHeader;
using nmc::coin::block_hash;
using nmc::coin::parse_nmc_headers_message;
using nmc::coin::pow_hash;

static uint256 hex256(const char* h) { uint256 u; u.SetHex(h); return u; }

// Pinned display-order block hashes at fixture landmarks (golden_pins.json /
// fixture_pins.json). SetHex(display) == block_hash(header) is proven by the
// sibling auxpow_wire_test genesis KAT, so the comparison is order-safe.
static const char* PIN_H19150 = "00000000000049abf4fc0e93296bacec92677e901440c47a6fa16f5ef6859012";
static const char* PIN_H19200 = "d8a7c3e01e1e95bcee015e6fcc7583a2ca60b79e5a3aa0a171eddd344ada903d";
static const char* PIN_H19204 = "000000000000122ff239e71146bf57aee28ad913931d672cd124255e91351660";
static const char* PIN_H19414 = "5fb89c3b18c27bc38d351d516177cbd3504c95ca0494cbbbbd52f2fb5f2ff1ec";
static const char* PIN_H19460 = "50a6a09a5567eab58a1c2fdd4965cfd271ddb420c467980bac8fef742954ec8a";

// Fixture-relative indices (fixture index 0 == real height 19150).
static constexpr size_t IDX_H19200 = 50;   // activation crossing (auxpow)
static constexpr size_t IDX_H19204 = 54;   // plain post-activation  (D1)
static constexpr size_t IDX_H19414 = 264;  // legacy no-magic auxpow (D2)

static std::vector<WireHeader> parse_golden() {
    return parse_nmc_headers_message(
        nmc::test::NMC_HEADERS_GOLDEN_H19150_H19460,
        nmc::test::NMC_HEADERS_GOLDEN_H19150_H19460_LEN);
}

// ── KAT-1: parser byte-faithfulness ───────────────────────────────────────
// 311 entries, 252 with AuxPoW; pinned landmark hashes; and a FULL-batch
// re-serialization round-trip (count + each header + optional AuxPoW + tx_count)
// that reproduces the captured payload byte-for-byte — proving the AuxPoW proof
// survives the parse intact, not merely the 80-byte base header.
TEST(NmcHeaderSyncGolden, ParserByteFaithful) {
    auto parsed = parse_golden();
    ASSERT_EQ(parsed.size(), 311u);

    size_t auxpow_count = 0;
    for (auto& wh : parsed) if (wh.auxpow) ++auxpow_count;
    EXPECT_EQ(auxpow_count, 252u);

    EXPECT_EQ(block_hash(parsed.front().header), hex256(PIN_H19150));
    EXPECT_EQ(block_hash(parsed[IDX_H19200].header), hex256(PIN_H19200));
    EXPECT_EQ(block_hash(parsed[IDX_H19204].header), hex256(PIN_H19204));
    EXPECT_EQ(block_hash(parsed[IDX_H19414].header), hex256(PIN_H19414));
    EXPECT_EQ(block_hash(parsed.back().header),  hex256(PIN_H19460));

    // Landmark version bits: plain vs auxpow.
    EXPECT_EQ(parsed[IDX_H19200].auxpow.has_value(), true);   // 0x10101
    EXPECT_EQ(parsed[IDX_H19204].auxpow.has_value(), false);  // 0x10001 plain
    EXPECT_EQ(parsed[IDX_H19414].auxpow.has_value(), true);   // 0x10101

    // Full-batch re-serialization == captured payload (byte-faithful round-trip).
    PackStream out;
    WriteCompactSize(out, parsed.size());
    for (auto& wh : parsed) {
        ::Serialize(out, wh.header);
        if (wh.auxpow)
            ::Serialize(out, *wh.auxpow);
        WriteCompactSize(out, 0);  // tx_count — always 0 in a 'headers' message
    }
    ASSERT_EQ(out.size(), nmc::test::NMC_HEADERS_GOLDEN_H19150_H19460_LEN);
    EXPECT_EQ(0, std::memcmp(out.data(),
                             nmc::test::NMC_HEADERS_GOLDEN_H19150_H19460,
                             out.size()));
}

// Params: mainnet() copy but activation ANCHOR-RELATIVE to the fixture (D3).
// fixture index 0 = real h19150, so real 19200 = index 50.
static NMCChainParams golden_params() {
    NMCChainParams p = NMCChainParams::mainnet();
    p.auxpow_activation_height = static_cast<int32_t>(IDX_H19200);  // = 50
    return p;
}

// ── KAT-2: admission crosses activation (locks L3 + D1 + D2 + D3) ──────────
// Feed all 311 real entries in order (auxpow via add_auxpow_header, plain via
// add_header). ALL must admit: the tip advances past the activation index, the
// plain post-activation block h19204 ADMITs (D1), the legacy no-magic auxpow
// block h19414 ADMITs (D2), and the tip lands on the pinned h19460.
TEST(NmcHeaderSyncGolden, AdmissionCrossesActivation) {
    HeaderChain chain(golden_params());
    auto parsed = parse_golden();

    int accepted = 0;
    for (auto& wh : parsed) {
        bool ok = wh.auxpow ? chain.add_auxpow_header(wh.header, *wh.auxpow)
                            : chain.add_header(wh.header);
        if (ok) ++accepted;
    }

    EXPECT_EQ(accepted, 311);
    EXPECT_EQ(chain.size(), 311u);
    EXPECT_EQ(chain.height(), 310u);          // index 310 == real h19460

    // D1: the plain post-activation header is in the chain (own-PoW admitted).
    EXPECT_TRUE(chain.has_header(hex256(PIN_H19204)));
    // D2: the legacy no-magic auxpow header is in the chain (commitment matched).
    EXPECT_TRUE(chain.has_header(hex256(PIN_H19414)));
    // activation crossing + tip.
    EXPECT_TRUE(chain.has_header(hex256(PIN_H19200)));
    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    EXPECT_EQ(tip->block_hash, hex256(PIN_H19460));
}

// Contrast leg (D1 corrected optional-auxpow semantics): a plain-header COPY of a
// real auxpow block, re-fed after stripping the proof, is REJECTED — its plain
// header does NOT clear its own target (auxpow blocks demonstrate PoW on the
// parent, so the aux header hash exceeds its own bits). Proves the own-PoW gate
// is real, not a rubber stamp.
TEST(NmcHeaderSyncGolden, StrippedAuxpowPlainCopyFailsOwnPoW) {
    HeaderChain chain(golden_params());
    auto parsed = parse_golden();

    // Seed the chain up to just before the activation-crossing auxpow block.
    for (size_t i = 0; i < IDX_H19200; ++i)
        ASSERT_TRUE(chain.add_header(parsed[i].header));

    // Feed h19200's BASE header alone (auxpow dropped) via add_header: at/after
    // activation the gate ADMITs, but connect_locked's own-PoW check rejects it
    // because a merge-mined block's own hash does not clear its own target.
    ASSERT_TRUE(parsed[IDX_H19200].auxpow.has_value());
    EXPECT_FALSE(chain.add_header(parsed[IDX_H19200].header));
    EXPECT_FALSE(chain.has_header(hex256(PIN_H19200)));

    // And the real path (with the proof) admits it — same header, real AuxPoW.
    EXPECT_TRUE(chain.add_auxpow_header(parsed[IDX_H19200].header,
                                        *parsed[IDX_H19200].auxpow));
    EXPECT_TRUE(chain.has_header(hex256(PIN_H19200)));
}

// ── KAT-3: is_synced() flips (locks the 24h wall-clock gate, no time bomb) ──
// A capture from 2011 can never assert is_synced()==true off static fixtures
// (DEFAULT_MAX_TIP_AGE = 24h). Instead: after KAT-2 the tip is stale (2011
// timestamp) so is_synced()==false; append ONE synthetic auxpow header with
// timestamp = now and a test-built valid four-leg proof at easy bits, and
// is_synced() must flip to true.
// ---------------------------------------------------------------------------
// Minimal self-contained proof builder (mirrors the auxpow_merkle_test helpers,
// replicated here to keep this KAT independent).
using nmc::coin::TxIn;
using nmc::coin::TxOut;
using nmc::coin::parent_coinbase_txid;
using nmc::coin::aux_merkle_root;

static uint256 leaf_of(unsigned char b) { uint256 u; u.SetNull(); *(u.begin()) = b; return u; }
static uint256 combine(const uint256& l, const uint256& r) {
    PackStream ps; ps << l; ps << r;
    return Hash(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ps.data()), ps.size()));
}
static void put_le32(std::vector<unsigned char>& v, uint32_t x) {
    v.push_back(uint8_t(x & 0xff));       v.push_back(uint8_t((x >> 8) & 0xff));
    v.push_back(uint8_t((x >> 16) & 0xff)); v.push_back(uint8_t((x >> 24) & 0xff));
}
static std::vector<unsigned char> root_reversed(uint256 r) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(r.begin());
    std::vector<unsigned char> v(p, p + uint256::BYTES);
    std::reverse(v.begin(), v.end());
    return v;
}
static const unsigned char MM_MAGIC[4] = {0xfa, 0xbe, 'm', 'm'};
static std::vector<unsigned char> mm_script(const std::vector<unsigned char>& rr,
                                            uint32_t size, uint32_t nonce) {
    std::vector<unsigned char> s = {0x03, 0x11, 0x22, 0x33};
    s.insert(s.end(), MM_MAGIC, MM_MAGIC + 4);
    s.insert(s.end(), rr.begin(), rr.end());
    put_le32(s, size); put_le32(s, nonce);
    return s;
}
static MutableTransaction coinbase_with_script(const std::vector<unsigned char>& script) {
    MutableTransaction tx; tx.version = 1; tx.locktime = 0;
    TxIn in; in.prevout.hash.SetNull(); in.prevout.index = 0xffffffffu;
    in.scriptSig = OPScript(script.data(), script.data() + script.size());
    in.sequence = 0xffffffffu; tx.vin.push_back(in);
    TxOut out; out.value = 5000000000LL; tx.vout.push_back(out);
    tx.vin[0].scriptWitness.stack.assign(1, std::vector<unsigned char>(32, 0x00));
    return tx;
}
static AuxPow complete_proof(uint256 aux, uint32_t parent_own_bits) {
    uint256 sib  = leaf_of(0x55);
    uint256 root = combine(aux, sib);
    auto    script = mm_script(root_reversed(root), 2, 1);
    AuxPow ap;
    ap.parent_coinbase     = coinbase_with_script(script);
    ap.chain_merkle_branch = {sib};
    ap.chain_merkle_index  = 0;
    uint256 cbid = parent_coinbase_txid(ap.parent_coinbase);
    uint256 sib2 = leaf_of(0x77);
    ap.parent_coinbase_branch = {sib2};
    ap.parent_coinbase_index  = 0;
    ap.parent_header.m_merkle_root = combine(cbid, sib2);
    ap.parent_header.m_bits        = parent_own_bits;
    return ap;
}
static bool mine_parent(AuxPow& ap, const uint256& target) {
    for (uint32_t n = 0; n < 200000u; ++n) {
        ap.parent_header.m_nonce = n;
        if (!(pow_hash(ap.parent_header) > target)) return true;
    }
    return false;
}

TEST(NmcHeaderSyncGolden, IsSyncedFlipsOnFreshAuxpowTip) {
    HeaderChain chain(golden_params());
    auto parsed = parse_golden();
    for (auto& wh : parsed) {
        if (wh.auxpow) chain.add_auxpow_header(wh.header, *wh.auxpow);
        else           chain.add_header(wh.header);
    }
    ASSERT_EQ(chain.height(), 310u);

    // Off the 2011 fixtures the tip is far older than 24h -> NOT synced.
    EXPECT_FALSE(chain.is_synced());

    // Build a synthetic FRESH auxpow header connecting to the current tip.
    auto tip = chain.tip();
    ASSERT_TRUE(tip.has_value());
    const uint32_t aux_bits = 0x207fffffu;   // regtest-style easy target
    BlockHeaderType h{};
    h.m_version        = 0x10100;            // auxpow flag set, chain_id 1
    h.m_previous_block = tip->block_hash;
    h.m_timestamp      = static_cast<uint32_t>(std::time(nullptr));
    h.m_bits           = aux_bits;
    h.m_nonce          = 0;
    uint256 aux = block_hash(h);
    AuxPow ap = complete_proof(aux, /*parent_own_bits=*/0x1d00ffffu);
    ASSERT_TRUE(mine_parent(ap, chain::bits_to_target(aux_bits)));

    ASSERT_TRUE(chain.add_auxpow_header(h, ap));
    EXPECT_EQ(chain.height(), 311u);
    EXPECT_EQ(chain.tip()->block_hash, aux);

    // Fresh tip timestamp -> synced flips true. (Locks the 24h wall-clock gate
    // WITHOUT a static-fixture time bomb.)
    EXPECT_TRUE(chain.is_synced());
}

}  // namespace
