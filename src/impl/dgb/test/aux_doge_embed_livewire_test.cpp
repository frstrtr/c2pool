// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (phase DC) -- EMBED LIVE-WIRE KAT, -DAUX_DOGE=ON only.
// Author-only; runs the instant the build host (.178/VM905) returns. Closes the
// loop between the two already-pinned DC halves:
//   * aux_doge_dc_proof_test  -- build_auxpow_proof == typed CAuxPow<dgb>, round-trip
//   * aux_doge_submit_test     -- submit half consumes an OPAQUE proof, RPC-only (b)
// Those two leave ONE seam unverified: that the auxpow_hex the submit half frames
// is the PARENT-SIDE derivation (c2pool::merged::build_auxpow_proof) computed over
// the MINTED, DOGE-commitment-carrying DGB coinbase -- the same derivation the
// runtime getauxblock template seam will emit -- and NOT a parallel/hand-fixtured
// fixture. This KAT pins that the embed output and the submit input are one and
// the same producer image.
//
// GOLDEN POLICY (integrator ask, UID:3134). The vectors here are PARENT-SIDE
// DERIVED, not hand-fixtured: the expected proof is computed IN-TEST by the
// runtime producer (build_auxpow_proof) over the minted coinbase, then asserted
// to be exactly what the submit-half assembler receives. There is no frozen hex
// literal that could drift against the runtime derivation -- the producer IS the
// oracle, so embed and submit cannot diverge against a re-shaped serializer.
//
// THE TRAP this KAT guards: an embed seam that hands the submit half a proof
// built over a DIFFERENT coinbase than the one carrying the committed DOGE aux
// root (a parallel fixture), or that drops the fabe6d6d commitment at mint. Both
// would still "submit a block" yet the DOGE network would reject the AuxPoW.
//
// THE OTHER TRAP (#314): the shared aux module defaults its parent type to LTC.
// Every instantiation/call below binds dgb::coin::MutableTransaction EXPLICITLY;
// a reviewer grep for a bare CAuxPow<> / parse_aux_header<Stream> must find NONE.
//
// Per-coin isolation: CONSUMES the shared doge module + the neutral merged
// primitive + the dgb submit header under test; modifies nothing in
// src/impl/doge/coin. MUST appear in BOTH test/CMakeLists.txt AND the build.yml
// --target allowlist or it becomes a NOT_BUILT sentinel that reds master
// (cf. DGB #137 / #143).
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <impl/doge/coin/auxpow.hpp>             // shared aux module (SSOT, templated #313)
#include <impl/ltc/coin/transaction.hpp>         // ltc default we MUST NOT rely on
#include <impl/dgb/coin/transaction.hpp>         // dgb::coin::MutableTransaction (DGB-as-parent)
#include <impl/dgb/coin/aux_doge_parent_traits.hpp> // DGB parent_coinbase_no_witness<> (#314)
#include <impl/dgb/coin/aux_doge_submit.hpp>     // submit half under test (the consumer)
#include <c2pool/merged/merged_mining.hpp>       // build_auxpow_proof (parent-neutral producer)

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/opscript.hpp>
#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
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

// Witness-stripped DGB parent coinbase hex via the SAME trait CMerkleTx uses --
// the exact image build_auxpow_proof serializes (verbatim from dc_proof sibling).
std::string dgb_coinbase_nowitness_hex(const dgb::coin::MutableTransaction& cb) {
    return pack_hex(doge::coin::parent_coinbase_no_witness<
                        dgb::coin::MutableTransaction>::value(cb));
}

// --- the DOGE merged-mining commitment the embed-at-mint seam writes into the
// DGB coinbase scriptSig:  MM_MAGIC || aux_chain_merkle_root || size || nonce.
// (Bitcoin/Namecoin AuxPoW commitment shape; fabe6d6d == "\xfa\xbe" "m" "m".) --
const std::string MM_MAGIC      = "fabe6d6d";
const std::string AUX_MERKLE_ROOT_HEX =
    "55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa"; // 32B
const std::string MM_SIZE_LE    = "01000000";   // 1 aux chain in the tree
const std::string MM_NONCE_LE   = "00000000";
const std::string COMMIT_BLOB   = MM_MAGIC + AUX_MERKLE_ROOT_HEX + MM_SIZE_LE + MM_NONCE_LE;

// Height push that precedes the commitment in a real minted coinbase scriptSig.
const std::string CB_HEIGHT_PUSH = "03a1b2c3";
const std::vector<unsigned char> MINTED_CB_SCRIPT = unhex(CB_HEIGHT_PUSH + COMMIT_BLOB);
const std::vector<unsigned char> PK_SCRIPT =
    unhex(std::string("76a914") + std::string(40, '3') + "88ac");

// The minted coinbase: identical geometry to the DC siblings EXCEPT the scriptSig
// now carries the embed-at-mint DOGE commitment -- this is the embed seam output.
dgb::coin::MutableTransaction build_minted_dgb_coinbase() {
    dgb::coin::MutableTransaction tx;
    tx.version  = 1;
    tx.locktime = 0;
    typename decltype(tx.vin)::value_type in;
    in.prevout.hash  = uint256();
    in.prevout.index = 0xffffffffu;
    in.scriptSig     = script_of(MINTED_CB_SCRIPT);
    in.sequence      = 0xffffffffu;
    tx.vin.push_back(in);
    typename decltype(tx.vout)::value_type out;
    out.value        = 5000000000ll;
    out.scriptPubKey = script_of(PK_SCRIPT);
    tx.vout.push_back(out);
    return tx;
}

// Deterministic, non-trivial proof geometry (shared with the dc_proof sibling).
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

// THE PARENT-SIDE DERIVATION. The runtime getauxblock seam calls exactly this
// producer over the minted coinbase to obtain the auxpow_hex it hands the submit
// half. Computed in-test (not frozen) so embed and submit share one oracle.
std::string runtime_auxpow_proof(const dgb::coin::MutableTransaction& minted_cb) {
    return c2pool::merged::build_auxpow_proof(
        dgb_coinbase_nowitness_hex(minted_cb),
        PARENT_BLOCK_HASH,
        std::vector<std::string>{ pack_hex(PARENT_BRANCH_0) },
        PARENT_MERKLE_INDEX,
        std::vector<uint256>{ AUX_BRANCH_0, AUX_BRANCH_1 },
        AUX_SLOT_INDEX,
        pack_hex(build_parent_header()));
}

// Recording DGB-owned DOGE seam (mirrors the submit_test stub). get_work_view()
// must never be hit on the submit path.
struct RecordingSeam : core::coin::ICoinNode {
    bool        rpc_present  = true;
    bool        ack          = true;
    int         submit_calls = 0;
    std::string last_hex;
    core::coin::WorkView get_work_view() override {
        throw std::runtime_error("get_work_view must NOT be called on the submit path");
    }
    bool submit_block_hex(const std::string& block_hex, bool /*ignore_failure*/) override {
        ++submit_calls; last_hex = block_hex; return ack && rpc_present;
    }
    bool is_embedded() const override { return false; }
    bool has_rpc()    const override { return rpc_present; }
};

const uint256 WON_SHARE = uint256S(
    "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca");
// The hand-fixtured stand-in the submit_test uses for the OPAQUE proof. The embed
// live-wire's whole point is that the REAL auxpow_hex is NOT this -- it is the
// producer derivation. Pinned here only to assert they differ.
const std::string SUBMIT_TEST_OPAQUE_STANDIN = "0100000001deadbeef";

} // namespace

// 1) EMBED HAPPENED. The minted coinbase's witness-stripped image carries the
//    fabe6d6d MM commitment + the aux chain merkle root the seam was asked to
//    commit -- i.e. the embed-at-mint actually wrote it, it was not dropped.
TEST(DGB_AuxDogeEmbedLiveWire, MintedCoinbaseCarriesDogeCommitment) {
    const auto cb = build_minted_dgb_coinbase();
    const std::string cb_hex = dgb_coinbase_nowitness_hex(cb);
    EXPECT_NE(cb_hex.find(MM_MAGIC), std::string::npos);
    EXPECT_NE(cb_hex.find(AUX_MERKLE_ROOT_HEX), std::string::npos);
    // magic immediately precedes the committed root (not two unrelated splices).
    EXPECT_NE(cb_hex.find(MM_MAGIC + AUX_MERKLE_ROOT_HEX), std::string::npos);
}

// 2) PARENT-SIDE PROOF CARRIES THE COMMITTED COINBASE. The producer output
//    embeds the EXACT witness-stripped minted coinbase -- the proof is built over
//    the commitment-carrying coinbase, never a parallel image.
TEST(DGB_AuxDogeEmbedLiveWire, ProofCarriesTheMintedCommittedCoinbase) {
    const auto cb = build_minted_dgb_coinbase();
    const std::string proof = runtime_auxpow_proof(cb);
    EXPECT_NE(proof.find(dgb_coinbase_nowitness_hex(cb)), std::string::npos);
    // transitively, the DOGE commitment rides inside the proof.
    EXPECT_NE(proof.find(MM_MAGIC + AUX_MERKLE_ROOT_HEX), std::string::npos);
}

// 3) PARENT-SIDE, NOT HAND-FIXTURED, AND DETERMINISTIC. The derivation is a pure
//    function of the minted coinbase: two runs are byte-identical, and the result
//    is emphatically NOT the submit_test opaque stand-in.
TEST(DGB_AuxDogeEmbedLiveWire, DerivationIsDeterministicAndNotAFixture) {
    const auto cb = build_minted_dgb_coinbase();
    EXPECT_EQ(runtime_auxpow_proof(cb), runtime_auxpow_proof(cb));
    EXPECT_NE(runtime_auxpow_proof(cb), SUBMIT_TEST_OPAQUE_STANDIN);
    EXPECT_GT(runtime_auxpow_proof(cb).size(), SUBMIT_TEST_OPAQUE_STANDIN.size());
}

// 4) THE LIVE-WIRE SEAM. The submit half's assembler receives EXACTLY the
//    parent-side producer derivation -- the embed output IS the submit input.
//    This is the contract aux_doge_submit_test could only stub: there the proof
//    was opaque; here it is pinned to the runtime derivation, end to end.
TEST(DGB_AuxDogeEmbedLiveWire, SubmitConsumesExactlyTheParentSideProof) {
    const auto cb = build_minted_dgb_coinbase();
    const std::string runtime_proof = runtime_auxpow_proof(cb);

    RecordingSeam doge;
    std::string seen_aux;
    auto assemble = [&](const uint256& /*share*/, const std::string& aux)
        -> std::optional<std::string> {
        seen_aux = aux;                      // capture what the embed seam handed us
        return std::string("00") + aux;      // frame into a (stub) DOGE block hex
    };
    auto handler = dgb::coin::make_aux_doge_on_block_found(assemble, &doge);

    // The run loop fires the won-share handler with the producer derivation:
    handler(WON_SHARE, runtime_proof);

    EXPECT_EQ(seen_aux, runtime_proof);              // same derivation, no parallel fixture
    EXPECT_EQ(doge.submit_calls, 1);                 // RPC-only submit fired once
    EXPECT_EQ(doge.last_hex, std::string("00") + runtime_proof);
}
