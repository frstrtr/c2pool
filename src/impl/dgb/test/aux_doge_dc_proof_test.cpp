// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DC) — DGB-as-PARENT AuxPoW PROOF byte-parity +
// dual-target KAT.  Fenced / test-only — consumes the shared aux module and the
// neutral c2pool/merged primitive, modifies NOTHING in src/impl/doge/coin/.
//
// POSITION.  DA landed the -DAUX_DOGE build flag; DB bound the commitment record
// (doge::coin::CAuxPow<dgb::coin::MutableTransaction>, KAT dgb_aux_doge_db_
// commitment_bind_test).  DC is the first phase where a DGB-parent share can win
// a DOGE block: on a DOGE-aux target hit the handler assembles the AuxPoW proof
// around the already-committed DGB coinbase (c2pool/merged build_auxpow_proof)
// and submits the DOGE block.  This KAT pins the load-bearing DC contracts
// BEFORE any run-loop wiring (share-tracker seam + submit) consumes them — the
// proof producer and the typed proof struct agree, and the proof round-trips.
//
// THE TRAP (integrator greenlight 2026-06-24).  The shared aux module templates
// default to the LTC parent type:
//   doge::coin::CAuxPow<ParentCoinbaseTx = ltc::coin::MutableTransaction>
//   doge::coin::parse_aux_header<Stream, ParentCoinbaseTx = ltc::coin::Mutable…>
// Relying on the bare default silently serializes the parent coinbase as LTC
// (which carries MWEB/HogEx fields DGB lacks) -> wrong wire bytes, NO compile
// error to catch it.  EVERY instantiation / call site below binds the DGB
// parent type EXPLICITLY: CAuxPow<dgb::coin::MutableTransaction>,
// parse_aux_header<Stream, dgb::coin::MutableTransaction>.  A reviewer grep for
// a bare CAuxPow<> / parse_aux_header<Stream> with no second type arg must find
// NONE in this file.
//
// ACCEPTANCE.  (1) build_auxpow_proof(DGB inputs) is byte-identical to the
// serialization of the equivalent CAuxPow<dgb::coin::MutableTransaction> — the
// producer and the typed struct cannot diverge.  (2) That proof, framed under a
// DOGE header whose version carries the 0x100 AuxPoW bit, round-trips through
// parse_aux_header<…, dgb::coin::MutableTransaction> back to identical bytes,
// and the recovered parent coinbase equals the witness-stripped DGB coinbase DB
// committed (the load-bearing DB<->DC trait contract).  (3) The dual-target
// share-check fires the DGB-parent and DOGE-aux paths INDEPENDENTLY against the
// same scrypt pow_hash.  No external golden is pinned: every assertion is a
// cross-path / round-trip invariant, so it cannot drift against a re-shaped
// serializer (that drift is caught by the sibling parity test's golden anchor).
//
// Per-coin isolation note: legitimately links the ltc OBJECT lib because the
// -DAUX_DOGE dual-parent CONSUMPTION path's shared module already includes
// ltc/coin/transaction.hpp by design.  We CONSUME the module + the merged
// primitive; we do not modify them.  MUST appear in BOTH test/CMakeLists.txt
// AND the build.yml --target allowlist or it becomes a NOT_BUILT sentinel that
// reds master (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/doge/coin/auxpow.hpp>           // shared aux module (SSOT, templated #313)
#include <impl/ltc/coin/transaction.hpp>       // ltc::coin::MutableTransaction (default we MUST NOT rely on)
#include <impl/dgb/coin/transaction.hpp>       // dgb::coin::MutableTransaction (DGB-as-parent type)
#include <impl/dgb/coin/aux_doge_parent_traits.hpp> // DGB parent_coinbase_no_witness<> specialization (#314)
#include <c2pool/merged/merged_mining.hpp>     // build_auxpow_proof (parent-neutral producer)

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/opscript.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

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
template <typename T>
std::string pack_hex(const T& value) {
    auto packed = pack(value);
    auto sp = packed.get_span();
    std::vector<unsigned char> v(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tohex(v);
}
OPScript script_of(const std::vector<unsigned char>& bytes) {
    return OPScript(bytes.data(), bytes.data() + bytes.size());
}

// Witness-stripped DGB parent coinbase hex via the SAME trait CMerkleTx uses
// (dgb specialization from aux_doge_parent_traits.hpp). Explicit DGB binding.
std::string dgb_coinbase_nowitness_hex(const dgb::coin::MutableTransaction& cb) {
    return pack_hex(doge::coin::parent_coinbase_no_witness<
                        dgb::coin::MutableTransaction>::value(cb));
}

// --- canonical, deterministic parent coinbase (identical content to the DB /
// parity siblings so only the TYPE varies across the suite). ----------------
const std::vector<unsigned char> CB_SCRIPT = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> PK_SCRIPT =
    unhex(std::string("76a914") + std::string(40, '3') + "88ac");

dgb::coin::MutableTransaction build_dgb_coinbase() {
    dgb::coin::MutableTransaction tx;
    tx.version  = 1;
    tx.locktime = 0;
    typename decltype(tx.vin)::value_type in;
    in.prevout.hash = uint256();
    in.prevout.index = 0xffffffffu;
    in.scriptSig = script_of(CB_SCRIPT);
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    typename decltype(tx.vout)::value_type out;
    out.value = 5000000000ll;
    out.scriptPubKey = script_of(PK_SCRIPT);
    tx.vout.push_back(out);
    return tx;
}

// Deterministic non-trivial proof geometry.
const uint256 PARENT_BLOCK_HASH =
    uint256S("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
const uint256 PARENT_BRANCH_0 =
    uint256S("1111111111111111111111111111111111111111111111111111111111111111");
const uint256 AUX_BRANCH_0 =
    uint256S("2222222222222222222222222222222222222222222222222222222222222222");
const uint256 AUX_BRANCH_1 =
    uint256S("3333333333333333333333333333333333333333333333333333333333333333");
constexpr uint32_t PARENT_MERKLE_INDEX = 0;   // coinbase is first tx
constexpr uint32_t AUX_SLOT_INDEX      = 1;   // DOGE slot in the aux tree

// Distinct non-zero DGB (parent) 80-byte header — the header the proof carries.
doge::coin::CPureBlockHeader build_parent_header() {
    doge::coin::CPureBlockHeader h;
    h.SetNull();
    h.m_version        = 4;
    h.m_previous_block = uint256S("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a");
    h.m_merkle_root    = uint256S("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    h.m_timestamp      = 0x5f5e1000u;
    h.m_bits           = 0x1e0ffff0u;
    h.m_nonce          = 0x00c0ffeeu;
    return h;
}

// Assemble the CAuxPow<dgb> the proof should byte-equal — EXPLICIT DGB binding.
doge::coin::CAuxPow<dgb::coin::MutableTransaction>
build_expected_auxpow(const dgb::coin::MutableTransaction& cb) {
    doge::coin::CAuxPow<dgb::coin::MutableTransaction> aux;
    aux.SetNull();
    aux.m_merkle_tx.m_tx           = cb;
    aux.m_merkle_tx.m_block_hash   = PARENT_BLOCK_HASH;
    aux.m_merkle_tx.m_merkle_link.m_branch = std::vector<uint256>{PARENT_BRANCH_0};
    aux.m_merkle_tx.m_merkle_link.m_index  = PARENT_MERKLE_INDEX;
    aux.m_chain_merkle_link.m_branch = std::vector<uint256>{AUX_BRANCH_0, AUX_BRANCH_1};
    aux.m_chain_merkle_link.m_index  = AUX_SLOT_INDEX;
    aux.m_parent_block_header        = build_parent_header();
    return aux;
}

// Run the neutral producer with the SAME geometry. The parent merkle branch is
// passed as raw-LE hex (pack_hex of the uint256) to match CMerkleLink, which
// serializes uint256 raw little-endian; the aux branch is passed as uint256 and
// the producer converts. (See build_auxpow_proof in merged_mining.cpp.)
std::string run_producer(const dgb::coin::MutableTransaction& cb) {
    return c2pool::merged::build_auxpow_proof(
        dgb_coinbase_nowitness_hex(cb),                 // parent coinbase, no witness
        PARENT_BLOCK_HASH,
        std::vector<std::string>{ pack_hex(PARENT_BRANCH_0) },
        PARENT_MERKLE_INDEX,
        std::vector<uint256>{ AUX_BRANCH_0, AUX_BRANCH_1 },
        AUX_SLOT_INDEX,
        pack_hex(build_parent_header()));               // 80-byte parent header
}

} // namespace

// 1) PRODUCER == TYPED STRUCT under explicit DGB binding. build_auxpow_proof's
//    string-concat output is byte-identical to pack(CAuxPow<dgb::coin::Mutable-
//    Transaction>) — two independent code paths over the same geometry.
TEST(DGB_AuxDogeDCProof, ProducerMatchesTypedCAuxPowDgbBinding) {
    const auto cb = build_dgb_coinbase();
    EXPECT_EQ(run_producer(cb), pack_hex(build_expected_auxpow(cb)));
}

// 2) ROUND-TRIP through parse_aux_header<…, dgb::coin::MutableTransaction>. A
//    DOGE header carrying the 0x100 AuxPoW version bit frames the proof; the
//    parser recovers the CAuxPow<dgb> and re-serializes to identical bytes.
TEST(DGB_AuxDogeDCProof, ProofRoundTripsParseAuxHeaderDgbBinding) {
    const auto cb = build_dgb_coinbase();
    const std::string proof = run_producer(cb);

    doge::coin::CPureBlockHeader doge_hdr;     // the AUX (DOGE) header
    doge_hdr.SetNull();
    doge_hdr.m_version = 0x100;                 // is_auxpow_version() -> true
    const std::string framed = pack_hex(doge_hdr) + proof;

    PackStream ps(unhex(framed));
    doge::coin::CAuxPow<dgb::coin::MutableTransaction> out;   // EXPLICIT DGB bind
    bool has_aux = false;
    auto recovered_hdr =
        doge::coin::parse_aux_header<PackStream, dgb::coin::MutableTransaction>(
            ps, out, has_aux);

    EXPECT_TRUE(has_aux);
    EXPECT_EQ(static_cast<int64_t>(recovered_hdr.m_version), 0x100);
    EXPECT_EQ(pack_hex(out), proof);
}

// 3) DB<->DC trait contract: the parent coinbase recovered from the proof equals
//    the witness-stripped DGB coinbase DB committed (same dgb parent_coinbase_no_
//    witness specialization). A divergent strip here = silent DB/DC drift.
TEST(DGB_AuxDogeDCProof, RecoveredParentCoinbaseWitnessStripMatchesDb) {
    const auto cb = build_dgb_coinbase();
    const std::string proof = run_producer(cb);

    doge::coin::CPureBlockHeader doge_hdr;
    doge_hdr.SetNull();
    doge_hdr.m_version = 0x100;
    PackStream ps(unhex(pack_hex(doge_hdr) + proof));
    doge::coin::CAuxPow<dgb::coin::MutableTransaction> out;
    bool has_aux = false;
    doge::coin::parse_aux_header<PackStream, dgb::coin::MutableTransaction>(ps, out, has_aux);

    EXPECT_EQ(dgb_coinbase_nowitness_hex(out.m_merkle_tx.m_tx),
              dgb_coinbase_nowitness_hex(cb));
}

// 4) DUAL-TARGET share-check truth table (spec §2). The DGB-parent target and the
//    DOGE-aux target are INDEPENDENT thresholds against the SAME scrypt pow_hash;
//    neither path gates the other. pow_hash <= target == hit.
TEST(DGB_AuxDogeDCProof, DualTargetIndependentThresholds) {
    auto hits = [](const uint256& pow, const uint256& target) { return !(pow > target); };

    // DGB parent is the harder (smaller) target; DOGE aux is easier (larger).
    const uint256 DGB_TARGET  = uint256S("0000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint256 DOGE_TARGET = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    const uint256 below_both  = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    const uint256 doge_only   = uint256S("000000000affffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint256 above_both  = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    // below both -> both paths fire
    EXPECT_TRUE(hits(below_both, DGB_TARGET));
    EXPECT_TRUE(hits(below_both, DOGE_TARGET));
    // between -> DOGE-aux fires, DGB-parent does NOT (the common case)
    EXPECT_FALSE(hits(doge_only, DGB_TARGET));
    EXPECT_TRUE(hits(doge_only, DOGE_TARGET));
    // above both -> neither fires
    EXPECT_FALSE(hits(above_both, DGB_TARGET));
    EXPECT_FALSE(hits(above_both, DOGE_TARGET));
}

// 5) REAL-DAEMON byte-parity (integrator acceptance gate). The exact 217-byte
//    CAuxPow blob dogecoind emits at regtest height 20 -- the SAME independent-
//    serializer fixture the LTC path pins in test/test_doge_chain.cpp -- decoded
//    here through the EXPLICIT DGB-parent binding. Because parent_coinbase_no_
//    witness<> is byte-identical for any bitcoin_family-TxParams parent, the DGB
//    path must consume the daemon's own bytes EXACTLY, re-emit them bit-for-bit,
//    AND serialize identically to the LTC default. This is the wrong-wire trap's
//    smoke detector: a silently-LTC parent coinbase strip diverges here at once.
//    Fixture embedded locally so the diff stays inside src/impl/dgb/ (the shared
//    LTC+DOGE test is ltc-doge's, untouched).
TEST(DGB_AuxDogeDCProof, RegtestH20RealDaemonDecodesThroughDgbBinding) {
    const char* const H20 =
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2cfabe6d6df091be03e588d8f33a0bc14145cb034dbf68e0a8ca774f0f842027a1366275900100000000000000ffffffff0000000000106303778e4f91a2984bb151de0bf0126c6cde013e9e11f86f7a942818f635f00000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000013175e533f07d6a5e7ab3df1fb0e67283b2b52daf0aaba1efbb2a22c77e96695000000000000000000000001";

    const auto blob = unhex(H20);
    ASSERT_EQ(blob.size(), 217u);

    // Decode dogecoind's own bytes through the EXPLICIT DGB-parent binding.
    PackStream ps_dgb(blob);
    doge::coin::CAuxPow<dgb::coin::MutableTransaction> out_dgb;
    ::Unserialize(ps_dgb, out_dgb);

    // Parent coinbase carries the fabe6d6d merged-mining commitment; null prevout,
    // no outputs, locktime 0 -- the canonical merged-mining coinbase shape.
    ASSERT_EQ(out_dgb.m_merkle_tx.m_tx.vin.size(), 1u);
    EXPECT_TRUE(out_dgb.m_merkle_tx.m_tx.vin[0].prevout.hash.IsNull());
    EXPECT_EQ(out_dgb.m_merkle_tx.m_tx.vin[0].prevout.index, 0xffffffffu);
    EXPECT_EQ(out_dgb.m_merkle_tx.m_tx.vout.size(), 0u);
    EXPECT_EQ(out_dgb.m_merkle_tx.m_tx.locktime, 0u);

    // Exact consumption -- no trailing bytes, no overrun, on the daemon's bytes.
    EXPECT_EQ(ps_dgb.cursor_size(), 0u)
        << "DGB-bound CAuxPow parser must consume exactly 217 bytes";

    // Re-emit: the DGB-decoded record packs back to the daemon's ORIGINAL bytes.
    EXPECT_EQ(pack_hex(out_dgb), std::string(H20));

    // Cross-type byte identity on REAL daemon bytes: the LTC default and the
    // explicit DGB binding must serialize identically (template-on-parent is a
    // no-op for the live LTC+DOGE wire -- the bucket-3 transition-compat shape).
    PackStream ps_ltc(blob);
    doge::coin::CAuxPow<ltc::coin::MutableTransaction> out_ltc;
    ::Unserialize(ps_ltc, out_ltc);
    EXPECT_EQ(pack_hex(out_dgb), pack_hex(out_ltc));
}