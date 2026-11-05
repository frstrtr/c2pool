// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DA) — "ONE PARENT PER DOGE BLOCK" AuxPoW
// invariant KAT.  Fenced / test-only — consumes the shared aux module and the
// DGB parent trait; modifies NOTHING in src/impl/doge/coin/.
//
// WHAT THIS PINS (distinct from the sibling DC tests).  The dual-target select
// KAT pins the FIRE decision; the DC proof KAT pins producer<->struct byte
// parity + round-trip.  Neither states the core AuxPoW consensus invariant this
// deployment rests on: a single DOGE block is merge-mined under EXACTLY ONE
// parent chain.  For the DGB deployment that one parent is DGB — a SEPARATE
// deployment from the canonical LTC+DOGE (never both parents for one DOGE
// block).  This KAT makes that invariant load-bearing at compile time and
// through a parse round-trip, so a future reshape that let a proof carry a
// second parent (a container of headers / coinbases, or the LTC default type
// leaking in) fails HERE, not silently on the wire.
//
// The invariant has two faces:
//   STRUCTURAL (compile-time).  doge::coin::CAuxPow<dgb::coin::MutableTransaction>
//     holds ONE parent block header (a lone CPureBlockHeader, not a container)
//     and ONE parent coinbase merkle-tx (a lone CMerkleTx, not a container),
//     and that coinbase is DGB-typed — provably NOT the shared module's LTC
//     default.  Two parents are UNREPRESENTABLE in the type.
//   BINDING (round-trip).  A DOGE header carrying the 0x100 AuxPoW bit frames
//     the proof; the parser recovers exactly ONE DGB parent coinbase + ONE
//     parent header, and re-parsing is idempotent — no parent multiplication.
//
// Per-coin isolation: links the ltc OBJECT lib only because the -DAUX_DOGE
// consumption path's shared module includes ltc/coin/transaction.hpp by design
// (same as the DB/DC siblings).  We CONSUME the module; we modify nothing.
// MUST appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist
// or it becomes a NOT_BUILT sentinel that reds master (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/doge/coin/auxpow.hpp>                 // shared aux module (templated)
#include <impl/ltc/coin/transaction.hpp>            // ltc::coin::MutableTransaction (the default we forbid)
#include <impl/dgb/coin/transaction.hpp>            // dgb::coin::MutableTransaction (the one parent)
#include <impl/dgb/coin/aux_doge_parent_traits.hpp> // DGB parent_coinbase_no_witness<> specialization

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/opscript.hpp>

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace {

using DgbAuxPow  = doge::coin::CAuxPow<dgb::coin::MutableTransaction>;
using DgbMerkle  = doge::coin::CMerkleTx<dgb::coin::MutableTransaction>;

// --- STRUCTURAL single-parent shape (compile-time). ------------------------

// ONE parent block header: a lone CPureBlockHeader, never a container. If a
// reshape ever made this a vector<CPureBlockHeader> to carry two parents, this
// breaks.
static_assert(
    std::is_same_v<decltype(DgbAuxPow::m_parent_block_header),
                   doge::coin::CPureBlockHeader>,
    "one-parent: CAuxPow must carry exactly ONE parent block header");

// ONE parent coinbase merkle-tx: a lone CMerkleTx, never a container.
static_assert(
    std::is_same_v<decltype(DgbAuxPow::m_merkle_tx), DgbMerkle>,
    "one-parent: CAuxPow must carry exactly ONE parent coinbase merkle-tx");

// The one parent coinbase is DGB-typed — the SEPARATE-deployment guard. The
// shared module defaults ParentCoinbaseTx to ltc::coin::MutableTransaction; a
// DGB proof that bound the LTC default would mean the DOGE block was mined
// under the LTC parent, i.e. the wrong (second) parent.
static_assert(
    std::is_same_v<decltype(DgbMerkle::m_tx), dgb::coin::MutableTransaction>,
    "one-parent: the single parent coinbase must be the DGB type");
static_assert(
    !std::is_same_v<dgb::coin::MutableTransaction, ltc::coin::MutableTransaction>,
    "one-parent: DGB parent must be distinct from the shared LTC default");

// --- fixture helpers (mirror the DC sibling geometry so only intent varies). -

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
std::string dgb_coinbase_nowitness_hex(const dgb::coin::MutableTransaction& cb) {
    return pack_hex(doge::coin::parent_coinbase_no_witness<
                        dgb::coin::MutableTransaction>::value(cb));
}

const std::vector<unsigned char> CB_SCRIPT = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> PK_SCRIPT =
    unhex(std::string("76a914") + std::string(40, '3') + "88ac");
const uint256 PARENT_BLOCK_HASH =
    uint256S("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
const uint256 PARENT_BRANCH_0 =
    uint256S("1111111111111111111111111111111111111111111111111111111111111111");
const uint256 AUX_BRANCH_0 =
    uint256S("2222222222222222222222222222222222222222222222222222222222222222");
const uint256 AUX_BRANCH_1 =
    uint256S("3333333333333333333333333333333333333333333333333333333333333333");
constexpr uint32_t PARENT_MERKLE_INDEX = 0;
constexpr uint32_t AUX_SLOT_INDEX      = 1;

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
DgbAuxPow build_one_parent_auxpow(const dgb::coin::MutableTransaction& cb) {
    DgbAuxPow aux;
    aux.SetNull();
    aux.m_merkle_tx.m_tx                   = cb;
    aux.m_merkle_tx.m_block_hash           = PARENT_BLOCK_HASH;
    aux.m_merkle_tx.m_merkle_link.m_branch = std::vector<uint256>{PARENT_BRANCH_0};
    aux.m_merkle_tx.m_merkle_link.m_index  = PARENT_MERKLE_INDEX;
    aux.m_chain_merkle_link.m_branch = std::vector<uint256>{AUX_BRANCH_0, AUX_BRANCH_1};
    aux.m_chain_merkle_link.m_index  = AUX_SLOT_INDEX;
    aux.m_parent_block_header        = build_parent_header();
    return aux;
}

// Frame a DOGE (aux) header carrying the 0x100 AuxPoW bit ahead of the proof,
// exactly as a real merged-mined DOGE block is wired.
std::string frame_doge_block(const DgbAuxPow& aux) {
    doge::coin::CPureBlockHeader doge_hdr;
    doge_hdr.SetNull();
    doge_hdr.m_version = 0x100;              // is_auxpow_version() -> true
    return pack_hex(doge_hdr) + pack_hex(aux);
}

} // namespace

// 1) STRUCTURAL — a freshly-nulled proof exposes exactly ONE parent slot: one
//    header, one coinbase, one chain-merkle index. There is no field in which a
//    second parent could live (the static_asserts above are the compile proof;
//    this checks the runtime default is a single, empty parent, not N).
TEST(DGB_AuxOneParent, NulledProofHasExactlyOneEmptyParent) {
    DgbAuxPow aux; aux.SetNull();
    EXPECT_TRUE(aux.m_parent_block_header.IsNull());     // one header, currently empty
    EXPECT_TRUE(aux.m_merkle_tx.m_merkle_link.IsNull()); // one coinbase link, empty
    EXPECT_EQ(aux.m_merkle_tx.m_tx.vin.size(), 0u);      // one coinbase, empty
}

// 2) BINDING — a DOGE block frames ONE DGB parent; parse recovers exactly that
//    single parent coinbase (witness-stripped, DGB-typed) and single parent
//    header. The DOGE block commits to one parent, no more.
TEST(DGB_AuxOneParent, DogeBlockBindsExactlyOneDgbParent) {
    const auto cb  = build_dgb_coinbase();
    const auto aux = build_one_parent_auxpow(cb);
    const std::string framed = frame_doge_block(aux);

    PackStream ps(unhex(framed));
    DgbAuxPow out; bool has_aux = false;
    auto recovered_hdr =
        doge::coin::parse_aux_header<PackStream, dgb::coin::MutableTransaction>(
            ps, out, has_aux);

    EXPECT_TRUE(has_aux);
    EXPECT_EQ(static_cast<int64_t>(recovered_hdr.m_version), 0x100);

    // THE one parent coinbase — DGB-typed, byte-identical to the one we framed.
    EXPECT_EQ(dgb_coinbase_nowitness_hex(out.m_merkle_tx.m_tx),
              dgb_coinbase_nowitness_hex(cb));
    // THE one parent header — byte-identical, single, non-null.
    EXPECT_FALSE(out.m_parent_block_header.IsNull());
    EXPECT_EQ(pack_hex(out.m_parent_block_header), pack_hex(build_parent_header()));
    // ONE slot in ONE parent's aux tree.
    EXPECT_EQ(out.m_chain_merkle_link.m_index, AUX_SLOT_INDEX);
}

// 3) IDEMPOTENT — re-parsing the re-serialized proof yields the identical single
//    parent. No path multiplies parents on a round-trip.
TEST(DGB_AuxOneParent, ReparseDoesNotMultiplyParents) {
    const auto cb  = build_dgb_coinbase();
    const auto aux = build_one_parent_auxpow(cb);

    const std::string once = pack_hex(aux);
    PackStream ps(unhex(once));
    DgbAuxPow out; ::Unserialize(ps, out);
    const std::string twice = pack_hex(out);

    EXPECT_EQ(once, twice);
    EXPECT_EQ(dgb_coinbase_nowitness_hex(out.m_merkle_tx.m_tx),
              dgb_coinbase_nowitness_hex(cb));
    EXPECT_EQ(pack_hex(out.m_parent_block_header), pack_hex(build_parent_header()));
}
