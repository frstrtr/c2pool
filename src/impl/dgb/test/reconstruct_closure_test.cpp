// ---------------------------------------------------------------------------
// dgb_reconstruct_closure_test -- pins coin/reconstruct_closure.hpp, the run-
// loop's faithful WonBlockReconstructor (#82) that main_dgb.cpp binds into
// make_on_block_found in place of the interim `return nullopt` stub.
//
// Proves the two contracts that matter for the reward path:
//   * SUCCESS: a fully-resolvable won share reconstructs to EXACTLY the block
//     reconstruct_won_block produces from the same unpacked gentx + ancestry
//     (the closure adds the share-field + gentx-regen seams and changes nothing
//     about the composed bytes / hex).
//   * FAIL-CLOSED (integrator 2026-06-20, REWARD-PATH CRITICAL): the callback
//     NEVER throws and NEVER emits a partial block -- an unknown share, a
//     missing known-tx, an out-of-range ref-walk, a gentx-regen failure, and a
//     malformed gentx serialization EACH yield std::nullopt (announce + audit,
//     RPC fallback still attempts). The broad catch swallows ANY std::exception,
//     not only std::out_of_range, so a regen path throwing some other type
//     still fails closed rather than crashing the compute thread.
//
// SYNTHETIC seams only (no live ShareTracker / mempool), mirroring the fixture
// in reconstruct_won_block_test.cpp. Links the dgb OBJECT lib like
// dgb_reconstruct_won_block_test (pulls block_assembly.hpp via the closure).
// MUST also appear in the build.yml --target allowlist (#143 NOT_BUILT trap).
// ---------------------------------------------------------------------------
#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <stdexcept>
#include <utility>
#include <vector>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include "../coin/reconstruct_closure.hpp"

using dgb::coin::make_reconstruct_closure;
using dgb::coin::ShareReconstructFields;
using dgb::coin::reconstruct_won_block;
using dgb::coin::unpack_gentx_coinbase;
using dgb::coin::SmallBlockHeaderType;
using dgb::coin::MutableTransaction;
using dgb::TxHashRefs;
using dgb::coin::make_reconstruct_closure_from_template;
using dgb::coin::reconstruct_won_block_from_template;
using dgb::coin::WonShareInputs;

namespace {

uint256 H(const char* two) // 0x"two" repeated to 64 hex chars
{
    std::string s;
    for (int i = 0; i < 32; ++i) s += two;
    uint256 h; h.SetHex(s);
    return h;
}

MutableTransaction make_tx(int64_t value)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out;
    out.value = value;
    tx.vout.push_back(out);
    return tx;
}

MutableTransaction make_gentx()
{
    MutableTransaction tx;
    tx.version = 1;
    tx.locktime = 0;
    dgb::coin::TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;   // coinbase
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    dgb::coin::TxOut out;
    out.value = 5000000000LL;
    tx.vout.push_back(out);
    return tx;
}

SmallBlockHeaderType make_small_header()
{
    SmallBlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
    h.m_timestamp = 1718700000;
    h.m_bits = 0x1a0fffff;
    h.m_nonce = 0x12345678;
    return h;
}

// Canonical non-witness serialization of a gentx -- the exact bytes the run-loop
// gentx_bytes_fn surfaces (generate_share_transaction's GentxCoinbase.bytes).
std::vector<unsigned char> noseg_bytes(const MutableTransaction& tx)
{
    auto packed = pack(dgb::coin::TX_NO_WITNESS(tx));
    auto sp = packed.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

// Synthetic ancestry won <- p1 <- p2 (p2 has no parent => walks past it run off
// the known chain), each share carrying new_transaction_hashes, plus a known_txs
// store. e0/e1 (p2's new txs) are deliberately ABSENT from `known` so a ref that
// resolves to them models a missing known-tx.
struct Fixture
{
    uint256 won = H("a0"), p1 = H("a1"), p2 = H("a2");
    std::map<uint256, uint256> parent;
    std::map<uint256, std::vector<uint256>> nths;
    std::map<uint256, MutableTransaction> known;

    Fixture()
    {
        parent[won] = p1;
        parent[p1]  = p2;                 // parent[p2] unset => walk off-chain
        nths[won] = { H("c0"), H("c1") };
        nths[p1]  = { H("d0") };
        nths[p2]  = { H("e0"), H("e1") }; // NOT in `known`
        known[H("c1")] = make_tx(11);
        known[H("d0")] = make_tx(22);
        known[H("c0")] = make_tx(33);
    }

    std::function<uint256(const uint256&, uint64_t)> nth_parent() const
    {
        auto p = parent;
        return [p](const uint256& start, uint64_t n) {
            uint256 cur = start;
            for (uint64_t i = 0; i < n; ++i) {
                auto it = p.find(cur);
                if (it == p.end()) return uint256();
                cur = it->second;
            }
            return cur;
        };
    }
    std::function<const std::vector<uint256>&(const uint256&)> new_tx() const
    {
        return [this](const uint256& h) -> const std::vector<uint256>& { return nths.at(h); };
    }
    std::function<const MutableTransaction*(const uint256&)> known_fn() const
    {
        return [this](const uint256& h) -> const MutableTransaction* {
            auto it = known.find(h);
            return it == known.end() ? nullptr : &it->second;
        };
    }
    // share_fields_fn: knows ONLY the won share; throws std::out_of_range for any
    // other hash (the run-loop's chain.get_share miss).
    std::function<ShareReconstructFields(const uint256&)>
    share_fields(SmallBlockHeaderType sh, ::dgb::MerkleLink link,
                 std::vector<TxHashRefs> refs) const
    {
        uint256 w = won;
        return [w, sh, link, refs](const uint256& h) -> ShareReconstructFields {
            if (h != w) throw std::out_of_range("share_fields: unknown share");
            return ShareReconstructFields{sh, link, refs};
        };
    }
};

} // namespace

// --- Test 1: success path == reconstruct_won_block on the same inputs ---------
TEST(DgbReconstructClosure, SuccessComposesIdenticalBlock)
{
    Fixture f;
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    std::vector<TxHashRefs> refs = { TxHashRefs(0, 1), TxHashRefs(1, 0) }; // -> c1, d0
    auto gentx_bytes = noseg_bytes(make_gentx());
    auto ug = unpack_gentx_coinbase(gentx_bytes);

    auto expected = reconstruct_won_block(sh, link, ug.tx, ug.txid, f.won, refs,
                                          f.nth_parent(), f.new_tx(), f.known_fn());

    auto closure = make_reconstruct_closure(
        f.share_fields(sh, link, refs),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        f.nth_parent(), f.new_tx(), f.known_fn());

    auto got = closure(f.won);
    ASSERT_TRUE(got.has_value());
    EXPECT_FALSE(got->first.empty());
    EXPECT_EQ(got->first, expected.bytes);
    EXPECT_EQ(got->second, expected.hex);
}

// --- Test 2: unknown share => nullopt (share_fields miss) ---------------------
TEST(DgbReconstructClosure, UnknownShareFailsClosed)
{
    Fixture f;
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    auto gentx_bytes = noseg_bytes(make_gentx());

    auto closure = make_reconstruct_closure(
        f.share_fields(sh, link, {}),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        f.nth_parent(), f.new_tx(), f.known_fn());

    EXPECT_FALSE(closure(H("ff")).has_value());   // not the won share
}

// --- Test 3: missing known-tx => nullopt (assemble_other_txs out_of_range) -----
TEST(DgbReconstructClosure, MissingKnownTxFailsClosed)
{
    Fixture f;
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    std::vector<TxHashRefs> refs = { TxHashRefs(2, 0) }; // won->p2, nths[0]=e0 (absent)
    auto gentx_bytes = noseg_bytes(make_gentx());

    auto closure = make_reconstruct_closure(
        f.share_fields(sh, link, refs),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        f.nth_parent(), f.new_tx(), f.known_fn());

    EXPECT_FALSE(closure(f.won).has_value());
}

// --- Test 4: ref-walk past chain end => nullopt -------------------------------
TEST(DgbReconstructClosure, OutOfRangeRefWalkFailsClosed)
{
    Fixture f;
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    std::vector<TxHashRefs> refs = { TxHashRefs(9, 0) }; // walks off the known chain
    auto gentx_bytes = noseg_bytes(make_gentx());

    auto closure = make_reconstruct_closure(
        f.share_fields(sh, link, refs),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        f.nth_parent(), f.new_tx(), f.known_fn());

    EXPECT_FALSE(closure(f.won).has_value());
}

// --- Test 5: gentx regen throws (non-out_of_range) => still nullopt -----------
TEST(DgbReconstructClosure, GentxRegenThrowFailsClosed)
{
    Fixture f;
    auto sh = make_small_header();
    ::dgb::MerkleLink link;

    auto closure = make_reconstruct_closure(
        f.share_fields(sh, link, {}),
        [](const uint256&) -> std::vector<unsigned char> {
            throw std::runtime_error("regen boom"); },
        f.nth_parent(), f.new_tx(), f.known_fn());

    EXPECT_FALSE(closure(f.won).has_value());   // broad catch, not just out_of_range
}

// --- Test 6: malformed gentx bytes => nullopt (unpack out_of_range) -----------
TEST(DgbReconstructClosure, MalformedGentxBytesFailsClosed)
{
    Fixture f;
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    auto bad = noseg_bytes(make_gentx());
    bad.push_back(0xff);                         // trailing byte => unpack throws

    auto closure = make_reconstruct_closure(
        f.share_fields(sh, link, {}),
        [bad](const uint256&) { return bad; },
        f.nth_parent(), f.new_tx(), f.known_fn());

    EXPECT_FALSE(closure(f.won).has_value());
}


// =============================================================================
// from-template closure (#82 version-AGNOSTIC path, #271 source + #279 share
// fields). This is the closure the run-loop installs: its non-coinbase tx set
// is the captured GBT template, NOT the share's tx_hash_refs, so there is no
// ancestry walk and no known-tx store -- only the two share-side fields, the
// gentx, and the template's other txs.
// =============================================================================

// won_share_fields_fn knows ONLY the won share; throws for any other hash
// (the run-loop's chain.get_share miss).
static std::function<WonShareInputs(const uint256&)>
won_fields(const uint256& won, SmallBlockHeaderType sh, ::dgb::MerkleLink link)
{
    return [won, sh, link](const uint256& h) -> WonShareInputs {
        if (h != won) throw std::out_of_range("won_share_fields: unknown share");
        return WonShareInputs{sh, link};
    };
}

// --- Test 7: from-template success == reconstruct_won_block_from_template -----
TEST(DgbReconstructClosure, FromTemplateSuccessComposesIdenticalBlock)
{
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    uint256 won = H("a0");
    auto gentx_bytes = noseg_bytes(make_gentx());
    auto ug = unpack_gentx_coinbase(gentx_bytes);
    std::vector<MutableTransaction> other = { make_tx(11), make_tx(22) };

    auto expected =
        reconstruct_won_block_from_template(sh, link, ug.tx, ug.txid, other);

    auto closure = make_reconstruct_closure_from_template(
        won_fields(won, sh, link),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        [other](const uint256&) { return other; });

    auto got = closure(won);
    ASSERT_TRUE(got.has_value());
    EXPECT_FALSE(got->first.empty());
    EXPECT_EQ(got->first, expected.bytes);       // closure adds seams, not bytes
    EXPECT_EQ(got->second, expected.hex);
}

// --- Test 8: empty template => valid coinbase-only block (NOT fail-closed) ----
TEST(DgbReconstructClosure, FromTemplateEmptyOtherTxsIsCoinbaseOnly)
{
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    uint256 won = H("a0");
    auto gentx_bytes = noseg_bytes(make_gentx());
    auto ug = unpack_gentx_coinbase(gentx_bytes);

    auto expected = reconstruct_won_block_from_template(
        sh, link, ug.tx, ug.txid, std::vector<MutableTransaction>{});

    auto closure = make_reconstruct_closure_from_template(
        won_fields(won, sh, link),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        [](const uint256&) { return std::vector<MutableTransaction>{}; });

    auto got = closure(won);
    ASSERT_TRUE(got.has_value());                 // correct-and-empty, not nullopt
    EXPECT_EQ(got->first, expected.bytes);
}

// --- Test 9: unknown share => nullopt (won_share_fields miss) -----------------
TEST(DgbReconstructClosure, FromTemplateUnknownShareFailsClosed)
{
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    uint256 won = H("a0");
    auto gentx_bytes = noseg_bytes(make_gentx());

    auto closure = make_reconstruct_closure_from_template(
        won_fields(won, sh, link),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        [](const uint256&) { return std::vector<MutableTransaction>{}; });

    EXPECT_FALSE(closure(H("ff")).has_value());   // not the won share
}

// --- Test 10: malformed gentx bytes => nullopt (unpack out_of_range) ----------
TEST(DgbReconstructClosure, FromTemplateMalformedGentxFailsClosed)
{
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    uint256 won = H("a0");
    auto bad = noseg_bytes(make_gentx());
    bad.push_back(0xff);                          // trailing byte => unpack throws

    auto closure = make_reconstruct_closure_from_template(
        won_fields(won, sh, link),
        [bad](const uint256&) { return bad; },
        [](const uint256&) { return std::vector<MutableTransaction>{}; });

    EXPECT_FALSE(closure(won).has_value());
}

// --- Test 11: template source throws (non-out_of_range) => still nullopt ------
TEST(DgbReconstructClosure, FromTemplateOtherTxsThrowFailsClosed)
{
    auto sh = make_small_header();
    ::dgb::MerkleLink link;
    uint256 won = H("a0");
    auto gentx_bytes = noseg_bytes(make_gentx());

    auto closure = make_reconstruct_closure_from_template(
        won_fields(won, sh, link),
        [gentx_bytes](const uint256&) { return gentx_bytes; },
        [](const uint256&) -> std::vector<MutableTransaction> {
            throw std::runtime_error("template boom"); });

    EXPECT_FALSE(closure(won).has_value());       // broad catch, not just out_of_range
}
