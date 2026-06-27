// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DB) — AuxPoW commitment-IN-COINBASE LOCATE +
// VALIDITY KAT.  Fenced / test-only — consumes the DGB connection-coinbase
// assembler and the cross-coin commitment SSOT, modifies nothing.
//
// WHY THIS EXISTS (the gap).  Three sibling KATs already pin the PRODUCER side
// of the DGB-as-DOGE-parent path:
//   * aux_doge_mm_commitment_test.cpp   — the 44-byte blob byte-LAYOUT + SSOT
//     delegation (fabe6d6d || root32 BE || size4 LE || nonce4 LE).
//   * connection_coinbase_test.cpp (E1/E2) — embed-at-mint APPENDS that blob to
//     the coinbase scriptSig and grows the gentx by exactly 44 bytes.
//   * aux_parent_coinbase_parity_test.cpp — parent-coinbase serialization parity.
// NONE of them exercises the CONSUMER/verifier side: that an aux verifier
// scanning a won DGB block's coinbase scriptSig can LOCATE the merged-mining
// header, RECOVER (aux_root, tree_size, nonce) bit-for-bit, and apply the
// canonical Dogecoin/Namecoin CheckAuxPow coinbase rules — exactly-once magic
// (a duplicate header is INVALID) and a complete 40-byte trailing commitment
// (a truncated header is INVALID).  A won block that embeds a commitment the
// DOGE side cannot decode is a silent merged-mining failure; this KAT closes
// that round-trip.
//
// NON-CIRCULAR.  The scanner here is an INDEPENDENT positional parser written
// to the canonical AuxPoW coinbase contract — it does NOT call the builder.
// The recovered (root,size,nonce) are compared against the RAW inputs handed to
// the assembler, not against the builder's own output, so a re-shaped builder
// cannot self-confirm.  One case additionally pins the located payload to the
// cross-coin SSOT c2pool::merged::build_auxpow_commitment as a drift guard.
//
// Per-coin isolation: this links the DGB OBJECT-lib set and CONSUMES the shared
// merged primitive; it touches no src/impl/doge/coin/ file.  MUST appear in
// BOTH test/CMakeLists.txt AND the build.yml --target allowlist or it becomes a
// NOT_BUILT sentinel that reds master (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/connection_coinbase.hpp>   // build_connection_coinbase_from_pplns (embed path)
#include <c2pool/merged/merged_mining.hpp>          // SSOT drift-guard: build_auxpow_commitment
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace {

using Script = std::vector<unsigned char>;

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> v; v.reserve(h.size() / 2);
    auto nyb = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nyb(h[i]) << 4) | nyb(h[i + 1])));
    return v;
}
std::string tohex(const std::vector<unsigned char>& v) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (unsigned char b : v) { s.push_back(H[b >> 4]); s.push_back(H[b & 0xf]); }
    return s;
}

// --- inputs shared verbatim with connection_coinbase_test.cpp ---------------
const Script CB  = unhex("03a1b2c3041122334455667788");          // BIP34 height + pool tag
const Script P1  = unhex(std::string("76a914") + std::string(40, '1') + "88ac");
const Script P2  = unhex(std::string("76a914") + std::string(40, '2') + "88ac");
const Script DON = unhex("4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac");
const uint64_t NONCE = 0x0102030405060708ull;

// Assemble a DGB won-block coinbase via the REAL embed-at-mint path.  aux_mm is
// appended to the coinbase scriptSig iff present (the -DAUX_DOGE producer seam).
dgb::coin::ConnCoinbaseParts assemble(const std::optional<Script>& aux_mm) {
    dgb::coin::ConnCoinbasePplnsInputs in;
    in.coinbase_script          = CB;
    in.segwit_commitment_script = std::nullopt;
    in.weights                  = std::map<Script, uint288>{{P1, uint288(3)}, {P2, uint288(1)}};
    in.total_weight             = uint288(4);
    in.subsidy                  = 10000;
    in.use_v36_pplns            = true;
    in.donation_script          = DON;
    in.ref_hash                 = uint256(std::vector<unsigned char>(32, 0xab));
    in.last_txout_nonce         = NONCE;
    in.aux_mm_commitment        = aux_mm;
    return dgb::coin::build_connection_coinbase_from_pplns(in);
}

// CompactSize reader (sufficient for <0x100000000 lengths).
uint64_t read_cs(const Script& b, size_t& pos) {
    uint8_t ch = b.at(pos++);
    if (ch < 253) return ch;
    if (ch == 253) { uint64_t v = b.at(pos) | (uint64_t(b.at(pos + 1)) << 8); pos += 2; return v; }
    if (ch == 254) {
        uint64_t v = 0; for (int i = 0; i < 4; ++i) v |= uint64_t(b.at(pos + i)) << (8 * i);
        pos += 4; return v;
    }
    uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(b.at(pos + i)) << (8 * i);
    pos += 8; return v;
}

// Extract the coinbase txin scriptSig from a serialized (witness-stripped) gentx:
//   version(4) | vin_count(CS) | prevout(36) | scriptlen(CS) | scriptSig | ...
Script coinbase_scriptsig(const Script& gentx) {
    size_t pos = 4;                         // skip version
    uint64_t vin = read_cs(gentx, pos);     // coinbase has exactly 1 input
    EXPECT_EQ(vin, 1u);
    pos += 36;                              // null prevout (32 hash + 4 index)
    uint64_t slen = read_cs(gentx, pos);
    return Script(gentx.begin() + pos, gentx.begin() + pos + slen);
}

// --- canonical AuxPoW merged-mining coinbase scanner (verifier side) --------
// Mirrors Dogecoin/Namecoin CAuxPow::check coinbase rules:
//   * the 4-byte magic (fa be 6d 6d) must appear EXACTLY ONCE; >1 == invalid
//     ("Multiple merged mining headers in coinbase").
//   * a complete 40-byte commitment (root32 || size4 || nonce4) must follow the
//     magic; a truncated tail == invalid.
// INDEPENDENT of the builder — pure positional scan.
struct MmScan {
    int    count   = 0;        // occurrences of the magic
    bool   present = false;    // count >= 1
    bool   valid   = false;    // exactly one + complete 40-byte commitment
    size_t offset  = 0;        // magic offset within scriptSig
    Script payload;            // 40 bytes after the magic
};
MmScan scan_mm_header(const Script& s) {
    static const Script MAGIC{0xfa, 0xbe, 0x6d, 0x6d};
    MmScan r;
    for (size_t i = 0; i + MAGIC.size() <= s.size(); ++i) {
        if (std::equal(MAGIC.begin(), MAGIC.end(), s.begin() + i)) {
            if (r.count == 0) r.offset = i;
            ++r.count;
        }
    }
    r.present = r.count >= 1;
    if (r.count != 1) return r;             // 0 -> not merged; >1 -> invalid
    const size_t data = r.offset + 4;
    if (data + 40 > s.size()) return r;     // truncated commitment -> invalid
    r.payload.assign(s.begin() + data, s.begin() + data + 40);
    r.valid = true;
    return r;
}

// Decode helpers off the 40-byte commitment payload.
Script   dec_root_le(const MmScan& m) { Script r(m.payload.begin(), m.payload.begin() + 32);
                                        std::reverse(r.begin(), r.end()); return r; }  // BE -> internal LE
uint32_t dec_u32_le(const Script& p, size_t off) {
    return uint32_t(p[off]) | (uint32_t(p[off + 1]) << 8) | (uint32_t(p[off + 2]) << 16) | (uint32_t(p[off + 3]) << 24);
}

} // namespace

// (1) ROUND-TRIP: embed a commitment for fixed (root,size,nonce), scan the
//     assembled coinbase scriptSig, and recover the inputs bit-for-bit.  This
//     is the consumer-side mirror of the producer KATs: a real DOGE verifier
//     can decode what c2pool-dgb minted.
TEST(AuxCommitmentCoinbaseLocate, RoundTripRecoversInputs) {
    Script root_le; for (int i = 0; i < 32; ++i) root_le.push_back(static_cast<unsigned char>(i));
    const uint256 aux_root(root_le);
    const uint32_t size = 0x04030201u, nonce = 0xdeadbeefu;
    const auto tag = c2pool::merged::build_auxpow_commitment(aux_root, size, nonce);
    ASSERT_EQ(tag.size(), size_t{44});

    const auto parts = assemble(tag);
    const auto ss    = coinbase_scriptsig(parts.gentx.bytes);
    const auto scan  = scan_mm_header(ss);

    ASSERT_TRUE(scan.present);
    EXPECT_EQ(scan.count, 1);               // exactly-once rule
    ASSERT_TRUE(scan.valid);                // complete 40-byte commitment
    // recovered fields == RAW inputs (non-circular: not the builder's output).
    EXPECT_EQ(tohex(dec_root_le(scan)), tohex(root_le));
    EXPECT_EQ(uint256(dec_root_le(scan)), aux_root);
    EXPECT_EQ(dec_u32_le(scan.payload, 32), size);
    EXPECT_EQ(dec_u32_le(scan.payload, 36), nonce);
    // the magic sits AFTER the original BIP34/pool-tag scriptSig prefix (CB).
    EXPECT_EQ(scan.offset, CB.size());
}

// (2) LOCATED PAYLOAD == cross-coin SSOT blob (drift guard).  The 40 bytes the
//     scanner lifts out of the live coinbase must equal the canonical builder's
//     blob minus its magic — ties the locate to the one SSOT producer.
TEST(AuxCommitmentCoinbaseLocate, LocatedPayloadMatchesSsotBlob) {
    const uint256 aux_root(std::vector<unsigned char>(32, 0x11));
    const auto tag = c2pool::merged::build_auxpow_commitment(aux_root, /*size=*/7, /*nonce=*/0x11223344u);
    const auto parts = assemble(tag);
    const auto scan  = scan_mm_header(coinbase_scriptsig(parts.gentx.bytes));

    ASSERT_TRUE(scan.valid);
    const Script ssot_payload(tag.begin() + 4, tag.end());   // strip the magic
    EXPECT_EQ(tohex(scan.payload), tohex(ssot_payload));
}

// (3) STANDALONE parent (nullopt) carries NO merged-mining header — the
//     verifier-side guarantee behind the byte-identical default build.
TEST(AuxCommitmentCoinbaseLocate, StandaloneHasNoMmHeader) {
    const auto parts = assemble(std::nullopt);
    const auto scan  = scan_mm_header(coinbase_scriptsig(parts.gentx.bytes));
    EXPECT_FALSE(scan.present);
    EXPECT_EQ(scan.count, 0);
    EXPECT_FALSE(scan.valid);
}

// (4) DUPLICATE header is INVALID (canonical "multiple merged mining headers"
//     rule).  Two concatenated tags reach the scriptSig; the scanner must see
//     count==2 and refuse to treat it as a valid commitment.
TEST(AuxCommitmentCoinbaseLocate, DuplicateMagicRejected) {
    const uint256 aux_root(std::vector<unsigned char>(32, 0x22));
    const auto tag = c2pool::merged::build_auxpow_commitment(aux_root, 1, 0);
    Script doubled = tag; doubled.insert(doubled.end(), tag.begin(), tag.end());  // tag||tag

    const auto parts = assemble(doubled);
    const auto scan  = scan_mm_header(coinbase_scriptsig(parts.gentx.bytes));
    EXPECT_TRUE(scan.present);
    EXPECT_EQ(scan.count, 2);
    EXPECT_FALSE(scan.valid);               // duplicate -> rejected
}

// (5) TRUNCATED commitment is INVALID.  Magic present once but fewer than 40
//     trailing bytes -> the verifier cannot recover (root,size,nonce).
TEST(AuxCommitmentCoinbaseLocate, TruncatedCommitmentRejected) {
    Script stub{0xfa, 0xbe, 0x6d, 0x6d};                    // magic only ...
    for (int i = 0; i < 20; ++i) stub.push_back(0xcc);      // ... + 20 of 40 bytes

    const auto parts = assemble(stub);
    const auto scan  = scan_mm_header(coinbase_scriptsig(parts.gentx.bytes));
    EXPECT_TRUE(scan.present);
    EXPECT_EQ(scan.count, 1);
    EXPECT_FALSE(scan.valid);               // incomplete -> rejected
}
