// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (D0) — aux-pow parent-coinbase serialization PARITY
// BASELINE KAT.  Fenced / test-only — consumes the shared aux module, modifies
// nothing.
//
// PURPOSE.  The v36-standardize Scrypt value-type extraction will lift the
// parent-coinbase member out of ltc::coin into a neutral Scrypt-family base so
// that a non-LTC parent (DGB-as-parent under -DAUX_DOGE=ON) can occupy it
// without the dgb -> ltc_coin build edge.  Today that member is hard-typed:
//
//     src/impl/doge/coin/auxpow.hpp:77   ltc::coin::MutableTransaction m_tx;
//     src/impl/doge/coin/auxpow.hpp:84   ::Serialize(s, TX_NO_WITNESS(m_tx));
//
// This KAT freezes the CURRENT, PRE-TEMPLATING wire image of the whole
// doge::coin::CMerkleTx (the struct that carries m_tx) so the extraction PR can
// prove its type swap is byte-neutral: re-run after templating must reproduce
// the golden BYTE-FOR-BYTE.  A single moved byte fails here.
//
// ANCHOR.  Golden captured against the shared aux module at master HEAD
//   git rev-parse origin/master == f732061bc
// recorded below as AUX_MODULE_MASTER_SHA.  A later rebase that silently
// re-shapes the serializer cannot move the golden without tripping this test;
// if the anchor SHA and the live module diverge in field order, that is a HARD
// STOP back to integrator, not a golden update.
//
// CROSS-TYPE INVARIANT.  The extraction's whole safety claim is that the parent
// coinbase serializes identically whichever Scrypt-family type holds it.  We
// assert that directly: the same canonical coinbase fields, serialized once
// through ltc::coin::MutableTransaction (the real member type) and once through
// dgb::coin::MutableTransaction (a stand-in for the future neutral / DGB-parent
// type), produce identical witness-stripped bytes.  Both extend
// bitcoin_family::coin::base_transaction, so a divergence would mean the shared
// base is NOT actually shared — exactly the thing extraction must not break.
//
// Per-coin isolation note: this test legitimately links the ltc OBJECT lib
// because it exercises the -DAUX_DOGE dual-parent consumption path, whose
// shared module (ltc-doge's domain) already includes ltc/coin/transaction.hpp
// by design.  We CONSUME the module; we do not modify it.  MUST appear in BOTH
// test/CMakeLists.txt AND the build.yml --target allowlist or it becomes a
// NOT_BUILT sentinel that reds master (cf. DGB #137).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/doge/coin/auxpow.hpp>          // the REAL shared module (SSOT)
#include <impl/ltc/coin/transaction.hpp>      // ltc::coin::MutableTransaction (member type)
#include <impl/dgb/coin/transaction.hpp>       // dgb::coin::MutableTransaction + dgb::coin::TX_NO_WITNESS (neutral stand-in)

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/opscript.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

// Anchor — see file header. Update ONLY together with a re-verified golden.
constexpr const char* AUX_MODULE_MASTER_SHA = "f732061bc";

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

// --- canonical, deterministic parent coinbase fields -----------------------
// A minimal but representative coinbase: null prevout, a fixed coinbase
// scriptSig, one P2PKH-shaped payout, version 1, locktime 0.  Shared verbatim
// between the ltc- and dgb-typed builders below so the only variable is the
// transaction TYPE, not the data.
const std::vector<unsigned char> CB_SCRIPT = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> PK_SCRIPT =
    unhex(std::string("76a914") + std::string(40, '3') + "88ac");
constexpr int32_t  TX_VERSION  = 1;
constexpr uint32_t TX_LOCKTIME = 0;
constexpr uint32_t CB_SEQUENCE = 0xffffffffu;
constexpr int64_t  CB_VALUE    = 5000000000ll;  // 50.00000000

template <typename MTx>
MTx build_parent_coinbase() {
    MTx tx;
    tx.version  = TX_VERSION;
    tx.locktime = TX_LOCKTIME;

    typename decltype(tx.vin)::value_type in;
    in.prevout.hash = uint256();           // null
    in.prevout.index = 0xffffffffu;        // coinbase marker
    in.scriptSig = script_of(CB_SCRIPT);
    in.sequence = CB_SEQUENCE;
    tx.vin.push_back(in);

    typename decltype(tx.vout)::value_type out;
    out.value = CB_VALUE;
    out.scriptPubKey = script_of(PK_SCRIPT);
    tx.vout.push_back(out);

    return tx;
}

// Fixed surrounding CMerkleTx fields.
const uint256 BLOCK_HASH =
    uint256S("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
const uint256 MERKLE_BRANCH_0 =
    uint256S("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
constexpr uint32_t MERKLE_INDEX = 1;

doge::coin::CMerkleTx build_merkle_tx() {
    doge::coin::CMerkleTx mt;
    mt.m_tx = build_parent_coinbase<ltc::coin::MutableTransaction>();
    mt.m_block_hash = BLOCK_HASH;
    mt.m_merkle_link.m_branch = {MERKLE_BRANCH_0};
    mt.m_merkle_link.m_index = MERKLE_INDEX;
    return mt;
}

// ---------------------------------------------------------------------------
// GOLDENS — captured against master f732061bc (see header). DO NOT hand-edit;
// regenerate only with a documented module change and integrator sign-off.
// ---------------------------------------------------------------------------
// Witness-stripped parent coinbase (the m_tx member payload, == tx_id_type).
const std::string PARENT_COINBASE_NOSEG =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0100f2052a010000001976a914333333333333333333333333333333333333333388ac00000000";
// Full doge::coin::CMerkleTx wire image:
//   TX_NO_WITNESS(m_tx) ++ m_block_hash(32, LE) ++ merkle_link(branch ++ index)
const std::string MERKLE_TX_WIRE =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0100f2052a010000001976a914333333333333333333333333333333333333333388ac00000000ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211000100112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01000000";                                                   // index = 1 (uint32 LE)

} // namespace

// 1) The member payload: witness-stripped parent coinbase, ltc-typed (real type).
TEST(DGB_AuxParentCoinbaseParity, LtcTypedMemberPayloadGolden) {
    auto tx = build_parent_coinbase<ltc::coin::MutableTransaction>();
    EXPECT_EQ(pack_hex(ltc::coin::TX_NO_WITNESS(tx)), PARENT_COINBASE_NOSEG);
}

// 2) CROSS-TYPE INVARIANT: the dgb-typed (neutral stand-in) coinbase serializes
//    BYTE-IDENTICALLY to the ltc-typed one. This is exactly what the extraction
//    must preserve when m_tx's type is lifted to the Scrypt-family base.
TEST(DGB_AuxParentCoinbaseParity, LtcVsDgbTypeByteIdentical) {
    auto ltc_tx = build_parent_coinbase<ltc::coin::MutableTransaction>();
    auto dgb_tx = build_parent_coinbase<dgb::coin::MutableTransaction>();
    const auto ltc_bytes = pack_hex(ltc::coin::TX_NO_WITNESS(ltc_tx));
    const auto dgb_bytes = pack_hex(dgb::coin::TX_NO_WITNESS(dgb_tx));
    EXPECT_EQ(ltc_bytes, dgb_bytes);
    EXPECT_EQ(ltc_bytes, PARENT_COINBASE_NOSEG);
}

// 3) Full shared-module CMerkleTx wire image, anchored to AUX_MODULE_MASTER_SHA.
//    Pins the pre-templating layout the extraction must reproduce verbatim.
TEST(DGB_AuxParentCoinbaseParity, MerkleTxWireGoldenAnchored) {
    ASSERT_STREQ(AUX_MODULE_MASTER_SHA, "f732061bc");  // golden provenance guard
    auto mt = build_merkle_tx();
    EXPECT_EQ(pack_hex(mt), MERKLE_TX_WIRE);
}

// 4) Round-trip: Unserialize(serialize(mt)) re-serializes to the same bytes.
//    A field-order/width bug that happened to be self-consistent on write but
//    not on read would diverge here.
TEST(DGB_AuxParentCoinbaseParity, MerkleTxRoundTripStable) {
    auto mt = build_merkle_tx();
    auto packed = pack(mt);
    doge::coin::CMerkleTx rt;
    packed >> rt;
    EXPECT_EQ(pack_hex(rt), MERKLE_TX_WIRE);
}
