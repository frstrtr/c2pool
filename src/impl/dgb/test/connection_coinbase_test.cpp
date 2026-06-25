// DGB Phase B — per-connection Stratum coinbase assembler + split KAT.
//
// Locks dgb::coin::build_connection_coinbase_parts() (coin/connection_coinbase.hpp)
// against the SAME ground-truth oracle vector used by the gentx assembler KAT
// (gentx_coinbase_test.cpp NOSEG_BYTES — derived from frstrtr/p2pool-dgb-scrypt
// util/pack.py + donation 4104ffd0...ac). A PASS proves:
//
//   1. the per-connection coinbase serializes byte-identical to the oracle wire
//      (the assembler path used == the verification SSOT), AND
//   2. the Stratum split invariant holds:
//        coinb1 || extranonce1(4) || extranonce2(4) || coinb2 == full gentx bytes
//      with the 8-byte extranonce slot landing exactly on the OP_RETURN
//      last_txout_nonce (the submit path reconstructs the header off this).
//
// Pure / no tracker: the (ref_hash, last_txout_nonce) are fixed inputs, so the
// vector is the oracle serializer's output — not self-generated.

#include <gtest/gtest.h>
#include <impl/dgb/coin/connection_coinbase.hpp>
#include <impl/dgb/coin/last_txout_nonce.hpp>
#include <c2pool/merged/merged_mining.hpp>  // core SSOT: build_auxpow_commitment

#include <map>
#include <set>
#include <optional>
#include <string>
#include <utility>
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

// --- inputs shared verbatim with gentx_coinbase_test.cpp NOSEG vector --------
const std::vector<unsigned char> CB  = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> P1  = unhex(std::string("76a914") + std::string(40, '1') + "88ac");
const std::vector<unsigned char> P2  = unhex(std::string("76a914") + std::string(40, '2') + "88ac");
const std::vector<unsigned char> DON = unhex("4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac");

const std::vector<std::pair<std::vector<unsigned char>, uint64_t>> PAYOUTS = {
    {P1, 5000000000ull},
    {P2, 2500000000ull},
};

// ref_hash = 0xab * 32 ; last_txout_nonce LE bytes = 08 07 06 05 04 03 02 01.
const uint64_t NONCE = 0x0102030405060708ull;

// Oracle ground truth (identical to gentx_coinbase_test.cpp NOSEG_BYTES).
const std::string NOSEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0400f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";

dgb::coin::ConnCoinbaseParts build() {
    dgb::coin::ConnCoinbaseInputs in;
    in.coinbase_script = CB;
    in.segwit_commitment_script = std::nullopt;
    in.payout_outputs = PAYOUTS;
    in.donation_amount = 1;                 // matches NOSEG donation value (1 sat)
    in.donation_script = DON;
    in.ref_hash = uint256(std::vector<unsigned char>(32, 0xab));
    in.last_txout_nonce = NONCE;
    return dgb::coin::build_connection_coinbase_parts(in);
}

// (1) full assembled bytes == oracle wire.
TEST(ConnCoinbase, FullBytesMatchOracle) {
    auto parts = build();
    EXPECT_EQ(tohex(parts.gentx.bytes), NOSEG_BYTES);
}

// (2) the Stratum split reassembles to the exact oracle bytes with the
//     8-byte extranonce slot filling the OP_RETURN nonce.
TEST(ConnCoinbase, SplitReassemblesToOracle) {
    auto parts = build();
    const std::string extranonce = "0807060504030201"; // en1(4)||en2(4), LE nonce
    EXPECT_EQ(parts.coinb1 + extranonce + parts.coinb2, NOSEG_BYTES);
}

// (3) coinb1 is the prefix up to (excl.) the nonce slot; coinb2 is the locktime.
TEST(ConnCoinbase, Coinb1PrefixCoinb2Locktime) {
    auto parts = build();
    ASSERT_GE(NOSEG_BYTES.size(), size_t{24});
    // coinb1 == oracle minus the last 12 bytes (nonce 8 + locktime 4 = 24 hex)
    EXPECT_EQ(parts.coinb1, NOSEG_BYTES.substr(0, NOSEG_BYTES.size() - 24));
    // coinb2 == final 4 bytes (locktime), all-zero
    EXPECT_EQ(parts.coinb2, "00000000");
}

// (4) the OP_RETURN ref script is the canonical 6a28 || ref_hash || nonce(LE).
TEST(ConnCoinbase, RefOpReturnLayout) {
    auto op = dgb::coin::build_ref_op_return(
        uint256(std::vector<unsigned char>(32, 0xab)), NONCE);
    std::string ref32; for (int i = 0; i < 32; ++i) ref32 += "ab";
    EXPECT_EQ(tohex(op), std::string("6a28") + ref32 + "0807060504030201");
}


// ============================================================================
// (5)-(8) PPLNS SSOT wiring: build_connection_coinbase_from_pplns delegates the
// payout split to compute_pplns_payout_split (the #329 verification SSOT) and
// forwards every non-payout field unchanged into build_connection_coinbase_parts.
//
// These are DELEGATION-IDENTITY tests, not a second payout implementation: each
// asserts the PPLNS-sourced path produces bytes identical to the manual path
// fed by the SAME SSOT split. Reintroducing inline payout math, dropping the
// v36 floor, or mis-forwarding a field would diverge them. The split MATH
// itself is pinned independently in pplns_payout_split_test.cpp.

using Script = std::vector<unsigned char>;

// Build the manual reference: run the SSOT split, hand it to the parts builder.
dgb::coin::ConnCoinbaseParts manual_from_split(
    const std::map<Script, uint288>& w, const uint288& total, uint64_t subsidy,
    bool v36, const Script& finder,
    const std::optional<Script>& seg, const uint256& ref, uint64_t nonce) {
    auto split = dgb::coin::compute_pplns_payout_split(w, total, subsidy, v36, finder);
    dgb::coin::ConnCoinbaseInputs in;
    in.coinbase_script = CB;
    in.segwit_commitment_script = seg;
    in.payout_outputs = split.payout_outputs;
    in.donation_amount = split.donation_amount;
    in.donation_script = DON;
    in.ref_hash = ref;
    in.last_txout_nonce = nonce;
    return dgb::coin::build_connection_coinbase_parts(in);
}

dgb::coin::ConnCoinbaseParts wired_from_pplns(
    const std::map<Script, uint288>& w, const uint288& total, uint64_t subsidy,
    bool v36, const Script& finder,
    const std::optional<Script>& seg, const uint256& ref, uint64_t nonce) {
    dgb::coin::ConnCoinbasePplnsInputs in;
    in.coinbase_script = CB;
    in.segwit_commitment_script = seg;
    in.weights = w;
    in.total_weight = total;
    in.subsidy = subsidy;
    in.use_v36_pplns = v36;
    in.finder_script = finder;
    in.donation_script = DON;
    in.ref_hash = ref;
    in.last_txout_nonce = nonce;
    return dgb::coin::build_connection_coinbase_from_pplns(in);
}

void expect_parts_eq(const dgb::coin::ConnCoinbaseParts& a,
                     const dgb::coin::ConnCoinbaseParts& b) {
    EXPECT_EQ(tohex(a.gentx.bytes), tohex(b.gentx.bytes));
    EXPECT_EQ(a.coinb1, b.coinb1);
    EXPECT_EQ(a.coinb2, b.coinb2);
    EXPECT_EQ(a.gentx.txid, b.gentx.txid);
}

// (5) V36 split (no finder fee, >=1 sat donation floor) flows through identically.
TEST(ConnCoinbasePplns, V36WiredEqualsManual) {
    std::map<Script, uint288> w{{P1, uint288(3)}, {P2, uint288(1)}};
    uint256 ref(std::vector<unsigned char>(32, 0xab));
    auto wired  = wired_from_pplns(w, uint288(4), 10000, true, {}, std::nullopt, ref, NONCE);
    auto manual = manual_from_split(w, uint288(4), 10000, true, {}, std::nullopt, ref, NONCE);
    expect_parts_eq(wired, manual);
}

// (6) Pre-V36 path (use_v36_pplns=false + finder_script) forwards the flag and
//     the 0.5% finder fee target — proves both are wired, not hard-coded.
TEST(ConnCoinbasePplns, PreV36FinderFeeWiredEqualsManual) {
    std::map<Script, uint288> w{{P1, uint288(1)}, {P2, uint288(1)}};
    uint256 ref(std::vector<unsigned char>(32, 0xab));
    auto wired  = wired_from_pplns(w, uint288(2), 20000, false, P1, std::nullopt, ref, NONCE);
    auto manual = manual_from_split(w, uint288(2), 20000, false, P1, std::nullopt, ref, NONCE);
    expect_parts_eq(wired, manual);
}

// (7) Non-payout fields (segwit commitment, distinct ref_hash, distinct nonce)
//     forward unchanged into the assembler.
TEST(ConnCoinbasePplns, SegwitAndRefFieldsForwarded) {
    std::map<Script, uint288> w{{P1, uint288(5)}, {P2, uint288(2)}};
    Script seg = unhex("6a24aa21a9ed" + std::string(64, 'c'));
    uint256 ref(std::vector<unsigned char>(32, 0x5c));
    const uint64_t alt_nonce = 0x1112131415161718ull;
    auto wired  = wired_from_pplns(w, uint288(7), 7777777, true, {}, seg, ref, alt_nonce);
    auto manual = manual_from_split(w, uint288(7), 7777777, true, {}, seg, ref, alt_nonce);
    expect_parts_eq(wired, manual);
}

// (8) Value anchor (independent of the wiring): the SSOT split the wired path
//     consumes carries the hand-computed V36 amounts in ascending order, and
//     the assembled coinbase preserves that exact PPLNS vout sequence.
//     subsidy 1000, P1:2 P2:1 (total 3) -> P1=666, P2=333, sum 999, donation 1;
//     >=1 sat floor satisfied without deduction. asc(amount): P2(333), P1(666).
TEST(ConnCoinbasePplns, ValueAnchorAscendingPayoutOrder) {
    std::map<Script, uint288> w{{P1, uint288(2)}, {P2, uint288(1)}};
    auto split = dgb::coin::compute_pplns_payout_split(w, uint288(3), 1000, true, {});
    std::vector<std::pair<Script, uint64_t>> expect{{P2, 333}, {P1, 666}};
    EXPECT_EQ(split.payout_outputs, expect);
    EXPECT_EQ(split.donation_amount, 1u);
    // The wired coinbase is assembled from exactly this split (covered by (5)-(7)).
}


// ============================================================================
// DGB+DOGE phase DB -- embed-at-mint: the optional aux_mm_commitment field on
// ConnCoinbasePplnsInputs appends the core c2pool::merged::build_auxpow_commitment blob to the
// coinbase scriptSig at mint (the -DAUX_DOGE=ON DGB-as-DOGE-parent path).
// Two invariants, both proven non-circularly off the same fixed inputs:
//   (E1) DEFAULT (nullopt) is BYTE-IDENTICAL to the standalone-parent coinbase
//        -- the no-op is structural, so the standalone build cannot regress.
//   (E2) When set, the assembled scriptSig is the baseline scriptSig with the
//        44-byte MM tag appended verbatim (magic..root..size..nonce), and the
//        gentx grows by EXACTLY 44 bytes -- nothing else in the coinbase moves.
// ============================================================================

// (E1) nullopt leaves the gentx byte-identical to the no-aux build.
TEST(ConnCoinbaseEmbedAtMint, NulloptIsByteIdentical) {
    std::map<Script, uint288> w{{P1, uint288(3)}, {P2, uint288(1)}};
    uint256 ref(std::vector<unsigned char>(32, 0xab));
    // baseline: aux_mm_commitment defaults to nullopt inside wired_from_pplns.
    auto baseline = wired_from_pplns(w, uint288(4), 10000, true, {}, std::nullopt, ref, NONCE);

    dgb::coin::ConnCoinbasePplnsInputs in;
    in.coinbase_script = CB;
    in.segwit_commitment_script = std::nullopt;
    in.weights = w; in.total_weight = uint288(4); in.subsidy = 10000;
    in.use_v36_pplns = true; in.donation_script = DON;
    in.ref_hash = ref; in.last_txout_nonce = NONCE;
    in.aux_mm_commitment = std::nullopt;            // explicit default
    auto with_field = dgb::coin::build_connection_coinbase_from_pplns(in);

    EXPECT_EQ(tohex(baseline.gentx.bytes), tohex(with_field.gentx.bytes));
    EXPECT_EQ(baseline.gentx.txid, with_field.gentx.txid);
}

// (E2) a populated commitment appends the 44-byte MM tag to the scriptSig and
//      grows the gentx by exactly 44 bytes; the tag bytes match the core SSOT.
TEST(ConnCoinbaseEmbedAtMint, AppendsMmTagToScriptSig) {
    std::map<Script, uint288> w{{P1, uint288(3)}, {P2, uint288(1)}};
    uint256 ref(std::vector<unsigned char>(32, 0xab));
    auto baseline = wired_from_pplns(w, uint288(4), 10000, true, {}, std::nullopt, ref, NONCE);

    // aux merkle root = 0x11..0x11 (internal LE); build the canonical 44-byte tag.
    uint256 aux_root(std::vector<unsigned char>(32, 0x11));
    auto tag = c2pool::merged::build_auxpow_commitment(aux_root, /*size=*/1, /*nonce=*/0);
    ASSERT_EQ(tag.size(), size_t{44});  // magic4+root32+size4+nonce4

    dgb::coin::ConnCoinbasePplnsInputs in;
    in.coinbase_script = CB;
    in.segwit_commitment_script = std::nullopt;
    in.weights = w; in.total_weight = uint288(4); in.subsidy = 10000;
    in.use_v36_pplns = true; in.donation_script = DON;
    in.ref_hash = ref; in.last_txout_nonce = NONCE;
    in.aux_mm_commitment = tag;
    auto embedded = dgb::coin::build_connection_coinbase_from_pplns(in);

    // gentx grows by EXACTLY the 44-byte tag -- nothing else shifts.
    EXPECT_EQ(embedded.gentx.bytes.size(), baseline.gentx.bytes.size() + tag.size());

    // the embedded scriptSig is the baseline scriptSig (CB) followed by the tag.
    std::vector<unsigned char> expect_script = CB;
    expect_script.insert(expect_script.end(), tag.begin(), tag.end());
    // the scriptSig sits right after the 42-byte coinbase txin prologue
    // (version4 + vin_count1 + prevout36 + script_len1); locate it by content.
    const std::string g = tohex(embedded.gentx.bytes);
    EXPECT_NE(g.find(tohex(expect_script)), std::string::npos);
    // and the bare tag is present where the baseline had none.
    EXPECT_NE(g.find(tohex(tag)), std::string::npos);
    EXPECT_EQ(tohex(baseline.gentx.bytes).find(tohex(tag)), std::string::npos);
}


// ============================================================================
// last_txout_nonce SSOT (coin/last_txout_nonce.hpp) -- oracle-faithful uniform
// 64-bit draw. Replaced three drifted std::time()-XOR formulas in
// share_check.hpp. The value is consensus-irrelevant (carried verbatim into the
// minted share, re-read on verify), so these KATs pin the DRAW PROPERTY, not a
// fixed vector: full-width entropy + uniqueness -- exactly what the old
// clock-seeded, low-entropy formulas did not provide.
// ============================================================================

// (A) Full-width entropy: over many draws every bit position is observed both
//     set and clear. The old time-XOR formulas left whole sub-words constrained
//     (low half = std::time, high half = header nonce); a uniform draw saturates
//     all 64 bits. Failure probability for a real uniform source is ~2^-N.
TEST(LastTxoutNonceSsot, FullWidthEntropy) {
    constexpr int N = 4096;
    uint64_t or_acc = 0;
    uint64_t and_acc = ~0ull;
    for (int i = 0; i < N; ++i) {
        const uint64_t v = dgb::make_last_txout_nonce();
        or_acc  |= v;
        and_acc &= v;
    }
    EXPECT_EQ(or_acc, ~0ull);   // every bit set at least once
    EXPECT_EQ(and_acc, 0ull);   // every bit clear at least once
}

// (B) Uniqueness intent: the draw exists to make the OP_RETURN unique per share.
//     Over N draws in a 2^64 space collisions are astronomically unlikely, so
//     the full set must be distinct (birthday collision prob here ~2^-40).
TEST(LastTxoutNonceSsot, DrawsAreDistinct) {
    constexpr int N = 4096;
    std::set<uint64_t> seen;
    for (int i = 0; i < N; ++i) seen.insert(dgb::make_last_txout_nonce());
    EXPECT_EQ(seen.size(), static_cast<size_t>(N));
}

} // namespace
