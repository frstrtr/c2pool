// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DB) — DGB-as-PARENT AuxPoW commitment binding
// KAT.  Fenced / test-only — consumes the shared aux module, modifies nothing.
//
// PURPOSE.  Phase DA landed the -DAUX_DOGE build flag + the inert coin/node.hpp
// seam; the shared aux module (ltc-doge's domain) is now TEMPLATED on the
// parent coinbase type (PR #313, doge::coin::CMerkleTx / CAuxPow / parse_aux_
// header default to ltc::coin::MutableTransaction).  Phase DB binds the DGB
// side: the dual-parent path instantiates the commitment record with
// dgb::coin::MutableTransaction as the parent coinbase.  This KAT is the first
// DB slice — it proves that instantiation is sound and wire-neutral BEFORE any
// run-loop commitment wiring consumes it.
//
// DEPENDENCY.  Binds against the TEMPLATED shared module (PR #313).  Until #313
// lands in master, this test is built on the #313 branch; merge is held until
// #313 is in master so the binding is against the landed surface (per
// integrator UID-1851).
//
// ACCEPTANCE GATE (DGB analog of #313's named LTC gate).  #313's safety claim
// is that the LTC instantiation serializes byte-identically to the pre-template
// image.  The mirror claim for the DGB-as-parent path: instantiating the SAME
// canonical commitment content through dgb::coin::MutableTransaction must
// produce the SAME witness-stripped wire bytes as the ltc::coin::Mutable-
// Transaction default.  Both parent types extend bitcoin_family::coin::base_
// transaction, so a divergence would mean the templated parent seam is NOT
// type-neutral — exactly what DB must not introduce.  No external golden is
// pinned here: the gate is a pure cross-type / round-trip invariant, so it
// cannot drift against a re-shaped serializer (that drift is caught by the
// sibling dgb_aux_parent_coinbase_parity_test golden anchor instead).
//
// Per-coin isolation note: legitimately links the ltc OBJECT lib because it
// exercises the -DAUX_DOGE dual-parent CONSUMPTION path, whose shared module
// already includes ltc/coin/transaction.hpp by design.  We CONSUME the module;
// we do not modify it.  MUST appear in BOTH test/CMakeLists.txt AND the
// build.yml --target allowlist or it becomes a NOT_BUILT sentinel that reds
// master (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/doge/coin/auxpow.hpp>          // the REAL shared module (SSOT, templated by #313)
#include <impl/ltc/coin/transaction.hpp>      // ltc::coin::MutableTransaction (default parent type)
#include <impl/dgb/coin/transaction.hpp>      // dgb::coin::MutableTransaction (DGB-as-parent type)
#include <impl/dgb/coin/aux_doge_parent_traits.hpp> // DGB-tree parent_coinbase_no_witness<> specialization (per #313 doc)

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

// --- canonical, deterministic parent coinbase fields -----------------------
// Identical to the sibling parity test's coinbase so the only variable across
// the two instantiations is the parent transaction TYPE, not the data.
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

// A deterministic, non-trivial merkle link shared by both instantiations:
// two (null-valued) branch hashes + a fixed slot index. Exercises the
// CompactSize vector-length prefix and the index field of CMerkleLink.
doge::coin::CMerkleLink canonical_merkle_link() {
    doge::coin::CMerkleLink link;
    link.m_branch = std::vector<uint256>{uint256(), uint256()};
    link.m_index = 5;
    return link;
}

// Build the parent merkle-tx (parent coinbase + block hash + branch) for a
// given parent coinbase type, with content held constant across types.
template <typename ParentTx>
doge::coin::CMerkleTx<ParentTx> build_merkle_tx() {
    doge::coin::CMerkleTx<ParentTx> mt;
    mt.m_tx = build_parent_coinbase<ParentTx>();
    mt.m_block_hash = uint256();
    mt.m_merkle_link = canonical_merkle_link();
    return mt;
}

// Build the full AuxPoW commitment record for a given parent coinbase type.
template <typename ParentTx>
doge::coin::CAuxPow<ParentTx> build_auxpow() {
    doge::coin::CAuxPow<ParentTx> aux;
    aux.SetNull();                                   // null chain link + parent header
    aux.m_merkle_tx = build_merkle_tx<ParentTx>();
    aux.m_chain_merkle_link = canonical_merkle_link();
    return aux;
}

} // namespace

// 1) The templated shared module instantiates cleanly with the DGB parent
//    coinbase type — the core of the DB binding.
TEST(DGB_AuxDogeDBCommitmentBind, CAuxPowDgbParentInstantiates) {
    doge::coin::CAuxPow<dgb::coin::MutableTransaction> aux;
    aux.SetNull();
    EXPECT_TRUE(aux.m_chain_merkle_link.IsNull());
}

// 2) Round-trip: Unserialize(serialize(merkle_tx)) re-serializes identically
//    for the DGB-as-parent instantiation. A field-order/width bug that was
//    self-consistent on write but not on read would diverge here.
TEST(DGB_AuxDogeDBCommitmentBind, MerkleTxDgbParentRoundTripStable) {
    auto mt = build_merkle_tx<dgb::coin::MutableTransaction>();
    const auto wire = pack_hex(mt);
    auto packed = pack(mt);
    doge::coin::CMerkleTx<dgb::coin::MutableTransaction> rt;
    packed >> rt;
    EXPECT_EQ(pack_hex(rt), wire);
}

// 3) ACCEPTANCE GATE — cross-type wire byte-identity at the merkle-tx layer.
//    The DGB-as-parent instantiation must serialize the SAME canonical
//    commitment content byte-for-byte identically to the LTC default. A single
//    moved byte fails here.
TEST(DGB_AuxDogeDBCommitmentBind, MerkleTxDgbVsLtcByteIdentical) {
    const auto dgb_wire = pack_hex(build_merkle_tx<dgb::coin::MutableTransaction>());
    const auto ltc_wire = pack_hex(build_merkle_tx<ltc::coin::MutableTransaction>());
    EXPECT_EQ(dgb_wire, ltc_wire);
}

// 4) ACCEPTANCE GATE — cross-type wire byte-identity at the FULL CAuxPow layer.
//    End-to-end: the whole DGB-as-parent commitment record (merkle_tx + chain
//    link + parent header) is byte-identical to the LTC default for identical
//    content. This is the wire image phase DB's commitment wiring will emit.
TEST(DGB_AuxDogeDBCommitmentBind, CAuxPowDgbVsLtcByteIdentical) {
    const auto dgb_wire = pack_hex(build_auxpow<dgb::coin::MutableTransaction>());
    const auto ltc_wire = pack_hex(build_auxpow<ltc::coin::MutableTransaction>());
    EXPECT_EQ(dgb_wire, ltc_wire);
}

// 5) Round-trip stability of the full CAuxPow<dgb> record.
TEST(DGB_AuxDogeDBCommitmentBind, CAuxPowDgbParentRoundTripStable) {
    auto aux = build_auxpow<dgb::coin::MutableTransaction>();
    const auto wire = pack_hex(aux);
    auto packed = pack(aux);
    doge::coin::CAuxPow<dgb::coin::MutableTransaction> rt;
    packed >> rt;
    EXPECT_EQ(pack_hex(rt), wire);
}