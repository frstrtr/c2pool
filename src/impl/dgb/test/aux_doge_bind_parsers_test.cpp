// ---------------------------------------------------------------------------
// DGB+DOGE merged-mining (M3) — bind_aux_doge_parsers() PRODUCTION-binding KAT.
// Fenced / test-only — links the PRODUCTION dgb object lib, consumes the shared
// aux module, modifies nothing in src/impl/doge.
//
// PURPOSE.  Phase DA/DB pinned the DGB-as-parent AuxPoW *contracts*
// (parse_aux_header<dgb::coin::MutableTransaction> + CAuxPow<dgb::coin::Mutable-
// Transaction>) but only ever exercised them from test fixtures; the production
// dgb node seam bind_aux_doge_parsers() was declaration-only.  M3 gives that
// member a real body: it ASSIGNS a stored parser callable that drives bytes
// through the DGB-parent parser, ODR-USING / emitting those template
// instantiations inside the production dgb object library.
//
// This KAT proves the binding is NON-HOLLOW: it constructs a real DGB-parent
// AuxPoW header blob, instantiates a dgb::coin::Node, calls
// bind_aux_doge_parsers(), then feeds the blob THROUGH the bound member and
// asserts the parsed CAuxPow<dgb> round-trips and carries the expected parent
// coinbase field (has_aux true; parent coinbase value matches).
//
// CANONICAL BLOB.  The blob is captured as ONE hex literal (CANONICAL_AUX_BLOB),
// produced deterministically from the shared serializer (see BuildCanonicalBlob
// below, whose self-consistency is asserted) — never hand-split.
//
// Per-coin isolation note: legitimately links the ltc OBJECT lib because the
// -DAUX_DOGE shared module includes ltc/coin/transaction.hpp by design.  We
// CONSUME the module; we do not modify it.  MUST appear in BOTH
// test/CMakeLists.txt AND the build.yml --target allowlist or it becomes a
// NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <impl/dgb/coin/node.hpp>             // PRODUCTION dgb node seam (bind_aux_doge_parsers)
#include <impl/doge/coin/auxpow.hpp>          // shared SSOT: CAuxPow<>, parse_aux_header<>, CPureBlockHeader
#include <impl/dgb/coin/transaction.hpp>      // dgb::coin::MutableTransaction
#include <impl/dgb/coin/aux_doge_parent_traits.hpp> // DGB-parent witness-strip specialization

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <core/opscript.hpp>

#include <boost/asio/io_context.hpp>   // dgb::coin::Node ctx ctor param type

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
std::vector<unsigned char> pack_bytes(const T& value) {
    auto packed = pack(value);
    auto sp = packed.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

OPScript script_of(const std::vector<unsigned char>& bytes) {
    return OPScript(bytes.data(), bytes.data() + bytes.size());
}

// --- canonical, deterministic parent coinbase fields -----------------------
const std::vector<unsigned char> CB_SCRIPT = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> PK_SCRIPT =
    unhex(std::string("76a914") + std::string(40, '3') + "88ac");
constexpr int32_t  TX_VERSION  = 1;
constexpr uint32_t TX_LOCKTIME = 0;
constexpr uint32_t CB_SEQUENCE = 0xffffffffu;
constexpr int64_t  CB_VALUE    = 5000000000ll;  // 50.00000000

dgb::coin::MutableTransaction build_parent_coinbase() {
    dgb::coin::MutableTransaction tx;
    tx.version  = TX_VERSION;
    tx.locktime = TX_LOCKTIME;

    typename decltype(tx.vin)::value_type in;
    in.prevout.hash = uint256();
    in.prevout.index = 0xffffffffu;
    in.scriptSig = script_of(CB_SCRIPT);
    in.sequence = CB_SEQUENCE;
    tx.vin.push_back(in);

    typename decltype(tx.vout)::value_type out;
    out.value = CB_VALUE;
    out.scriptPubKey = script_of(PK_SCRIPT);
    tx.vout.push_back(out);
    return tx;
}

doge::coin::CMerkleLink canonical_merkle_link() {
    doge::coin::CMerkleLink link;
    link.m_branch = std::vector<uint256>{uint256(), uint256()};
    link.m_index = 5;
    return link;
}

doge::coin::CAuxPow<dgb::coin::MutableTransaction> build_auxpow() {
    doge::coin::CAuxPow<dgb::coin::MutableTransaction> aux;
    aux.SetNull();
    aux.m_merkle_tx.m_tx = build_parent_coinbase();
    aux.m_merkle_tx.m_block_hash = uint256();
    aux.m_merkle_tx.m_merkle_link = canonical_merkle_link();
    aux.m_chain_merkle_link = canonical_merkle_link();
    return aux;
}

// Child header carrying the AuxPoW version bit (0x100) so parse_aux_header
// deserializes the trailing CAuxPow proof.
constexpr uint32_t AUXPOW_VERSION = 0x00620100u;  // chain-id 0x62 in high bits | aux bit 0x100
constexpr uint32_t HDR_TIMESTAMP  = 0x5f5e1000u;
constexpr uint32_t HDR_BITS       = 0x1e0ffff0u;
constexpr uint32_t HDR_NONCE      = 0x12345678u;

doge::coin::CPureBlockHeader build_child_header() {
    doge::coin::CPureBlockHeader hdr;
    hdr.SetNull();
    hdr.m_version        = AUXPOW_VERSION;
    hdr.m_previous_block = uint256();
    hdr.m_merkle_root    = uint256();
    hdr.m_timestamp      = HDR_TIMESTAMP;
    hdr.m_bits           = HDR_BITS;
    hdr.m_nonce          = HDR_NONCE;
    return hdr;
}

// Build the full wire image: 80-byte child header followed by the structured
// CAuxPow<dgb> proof — exactly the byte stream parse_aux_header consumes.
std::vector<unsigned char> build_canonical_blob() {
    std::vector<unsigned char> blob = pack_bytes(build_child_header());
    std::vector<unsigned char> aux  = pack_bytes(build_auxpow());
    blob.insert(blob.end(), aux.begin(), aux.end());
    return blob;
}

// The ONE canonical hex literal — captured from build_canonical_blob() and
// pinned here so the bound-parser path is fed a fixed wire image, not a
// re-derived structure. (Self-consistency asserted in BlobMatchesBuilder.)
const char* CANONICAL_AUX_BLOB =
    "00016200"                                                          // version (LE 0x00620100) + aux bit
    "0000000000000000000000000000000000000000000000000000000000000000"  // prev block
    "0000000000000000000000000000000000000000000000000000000000000000"  // merkle root
    "00105e5f"                                                          // timestamp
    "f0ff0f1e"                                                          // bits
    "78563412"                                                          // nonce
    // --- CAuxPow<dgb> proof ---
    // m_merkle_tx: parent coinbase
    "01000000"                                                          // tx version
    "01"                                                                // vin count
    "0000000000000000000000000000000000000000000000000000000000000000"  // prevout hash
    "ffffffff"                                                          // prevout index
    "0d03a1b2c3041122334455667788"                                      // scriptSig (len 13 + bytes)
    "ffffffff"                                                          // sequence
    "01"                                                                // vout count
    "00f2052a01000000"                                                  // value 50 BTC LE
    "1976a914333333333333333333333333333333333333333388ac"             // scriptPubKey (len 25 + p2pkh)
    "00000000"                                                          // locktime
    // m_block_hash
    "0000000000000000000000000000000000000000000000000000000000000000"
    // m_merkle_link
    "02"                                                                // branch count
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "05000000"                                                          // index 5
    // m_chain_merkle_link
    "02"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "05000000"
    // m_parent_block_header (null 80-byte)
    "00000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000"
    "00000000"
    "00000000";

} // namespace

// Sanity: the pinned hex literal equals the deterministically built wire image.
// If the shared serializer field-order ever drifts, this trips (and so does the
// sibling parity golden) — proving the literal is a faithful capture, not magic.
TEST(DGB_AuxDogeBindParsers, BlobMatchesBuilder) {
    EXPECT_EQ(tohex(build_canonical_blob()), std::string(CANONICAL_AUX_BLOB));
}

#ifdef AUX_DOGE  // node seam (bind_aux_doge_parsers/aux_doge_parser) exists
                 // only in the dual-parent build; default Scrypt-only arm skips these.
// CORE: the production seam binds a NON-HOLLOW parser. Build a node, bind, feed
// the canonical blob through the bound member, assert the DGB-parent proof is
// parsed (has_aux true) and carries the expected parent coinbase value.
TEST(DGB_AuxDogeBindParsers, BoundParserConsumesDgbParentBlob) {
    struct FakeConfig { bool m_testnet = false; };
    FakeConfig cfg;
    boost::asio::io_context ioc;  // ctor only stores the pointer; no transport bring-up / run() here.
    dgb::coin::Node<FakeConfig> node(&ioc, &cfg);

    // Before bind: parser is unbound.
    ASSERT_FALSE(static_cast<bool>(node.aux_doge_parser()));

    node.bind_aux_doge_parsers();
    ASSERT_TRUE(static_cast<bool>(node.aux_doge_parser()));

    PackStream s(unhex(CANONICAL_AUX_BLOB));
    auto parsed = node.aux_doge_parser()(s);

    // Non-hollow: the aux version bit was honored and a real proof deserialized.
    EXPECT_TRUE(parsed.m_has_aux);
    EXPECT_EQ(parsed.m_header.m_version, AUXPOW_VERSION);
    EXPECT_EQ(parsed.m_header.m_nonce, HDR_NONCE);

    // Parent coinbase round-tripped THROUGH the DGB-parent CAuxPow<dgb> path.
    ASSERT_EQ(parsed.m_aux.m_merkle_tx.m_tx.vout.size(), 1u);
    EXPECT_EQ(parsed.m_aux.m_merkle_tx.m_tx.vout[0].value, CB_VALUE);
    EXPECT_EQ(parsed.m_aux.m_chain_merkle_link.m_index, 5);
}

// The parsed CAuxPow<dgb> re-serializes to the same proof bytes that followed
// the 80-byte header in the canonical blob (byte-exact round trip via the
// production-bound parser).
TEST(DGB_AuxDogeBindParsers, BoundParserAuxRoundTripsByteIdentical) {
    struct FakeConfig { bool m_testnet = false; };
    FakeConfig cfg;
    boost::asio::io_context ioc;
    dgb::coin::Node<FakeConfig> node(&ioc, &cfg);
    node.bind_aux_doge_parsers();

    const auto whole = unhex(CANONICAL_AUX_BLOB);
    PackStream s(whole);
    auto parsed = node.aux_doge_parser()(s);

    // Re-emit header+aux and require byte-for-byte identity with the input blob.
    std::vector<unsigned char> reemit = pack_bytes(parsed.m_header);
    std::vector<unsigned char> aux    = pack_bytes(parsed.m_aux);
    reemit.insert(reemit.end(), aux.begin(), aux.end());
    EXPECT_EQ(tohex(reemit), tohex(whole));
}

#endif  // AUX_DOGE
