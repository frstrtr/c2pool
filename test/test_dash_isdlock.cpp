// SPDX-License-Identifier: AGPL-3.0-or-later
/// G4 isdlock intake — acquire -> BLS-verify -> use, all fail-closed.
///
/// The four claims this suite pins, in dependency order:
///
///   1. WIRE. `isdlock` is registered in the p2p::Handler type list and its
///      codec decodes the dashd InstantSendLock wire layout byte-exactly
///      (KAT: hand-assembled golden bytes, independent of the codec). A
///      message absent from the registry dies silently at DEBUG — the exact
///      DIP-24 qrinfo failure mode (#1077) — so registry membership gets its
///      own RED-able test, same as test_dash_qrinfo_wire.cpp.
///
///   2. VERIFY (selection half). requestId = SHA256d("islock" || inputs)
///      matches an INDEPENDENTLY computed digest (python hashlib, not this
///      codebase), and the rotated signer-index derivation reproduces dashd's
///      SelectQuorumForSigning rotated arm (llmq/quorumsman.cpp:699-717)
///      including its (64 - n - 1) shift quirk. Cycle-keyed candidate
///      filtering fails closed on every uncertainty.
///
///   3. USE (G4 red/green). Feeding one verified isdlock through the REAL
///      production path (CoinStateMaintainer::on_new_isdlock -> on_islock ->
///      Mempool::add_islock) EXCLUDES a conflicting tx from the selected
///      template and KEEPS a non-conflicting one. The same suite asserts the
///      no-feed baseline INCLUDES the conflicting tx — that assertion is what
///      goes RED when the feed lands and the guard fires, and it is what the
///      feed-half was proven against (observed red with the feed lines
///      commented out; see the PR's result matrix).
///
///   4. FAIL-CLOSED (BLS half, gated on C2POOL_DASH_BLS). A real
///      threshold-signed isdlock verifies end-to-end; a one-bit-tampered
///      signature is REJECTED and add_islock is never called; no verifier
///      registered means nothing is ever adopted.

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_messages.hpp>
#include <impl/dash/coin/islock_verify.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_lane.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using dash::coin::CoinStateMaintainer;
using dash::coin::NodeCoinState;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::UtxoLane;
using dash::coin::dash_txid;
using dash::coin::LlmqParamsView;
using dash::coin::LlmqNetwork;
using dash::coin::islock::RotatedQuorumCandidate;
using dash::coin::islock::gen_islock_request_id;
using dash::coin::islock::rotated_signer_index;
using dash::coin::islock::select_rotated_quorum;
using dash::coin::islock::build_islock_sign_target;
using dash::coin::islock::islock_params;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

namespace {

// ─── byte helpers ────────────────────────────────────────────────────────────

std::vector<uint8_t> unhex(const std::string& s)
{
    std::vector<uint8_t> o;
    o.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        o.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return o;
}

/// uint256 whose RAW WIRE BYTES are 32 consecutive values starting at `base`.
uint256 raw256(uint8_t base)
{
    uint256 h;
    for (size_t i = 0; i < 32; ++i)
        h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}

/// uint256 from little-endian wire hex.
uint256 u256_le(const std::string& le_hex) { return uint256(unhex(le_hex)); }

const LlmqParamsView& p60_75() { return *islock_params(LlmqNetwork::Mainnet); }

// The fixed synthetic lock this suite reuses:
//   inputs = [ (txid bytes 00..1f, vout 7) ], txid = bytes 22..41,
//   cycleHash arbitrary, sig = 96 x 0xab.
std::vector<std::pair<uint256, uint32_t>> kat_inputs()
{
    return {{raw256(0x00), 7u}};
}

// ── INDEPENDENT digests (python hashlib over the hand-assembled preimage,
//    NOT this codebase). Preimage for kat_inputs():
//      06 "islock" 01 <32B txid 00..1f> <07 00 00 00>
//    = 0669736c6f636b01000102...1f07000000
const char* kExpectRequestIdLe =
    "a6ffa135a6a6d7a1e1b5bebf8539fa2587ce4a0af67d2c2cc9cd2e7b81b8d14f";
// Two-input variant (second outpoint: txid bytes 20..3f, vout 0xffffffff):
const char* kExpectRequestId2Le =
    "1b99869c3b93277f4b3aa9a43de6deb0648028a8e97640637a55724ca0bd1c64";
// Signer indices dashd's rotated arm derives from those requestIds
// (n=5, b=GetUint64(3), signer=((1<<5)-1)&(b>>58)) — computed by hand:
//   b  = 0x4fd1b8817b2ecdc9 -> top-6 bits 010011 -> & 0x1f = 19
//   b2 = 0x641cbda04c72557a -> top-6 bits 011001 -> & 0x1f = 25
constexpr uint64_t kExpectSigner  = 19;
constexpr uint64_t kExpectSigner2 = 25;

// ─── wire fixtures ───────────────────────────────────────────────────────────

/// Hand-assemble the golden isdlock wire bytes for kat_inputs() —
/// independently of the codec under test, straight from the dashd layout
/// (instantsend/lock.h SERIALIZE_METHODS):
///   u8 version || CompactSize(#inputs) || (32B txid, u32LE vout)* ||
///   32B txid || 32B cycleHash || 96B sig
std::vector<unsigned char> golden_isdlock_bytes(uint8_t version = 1)
{
    std::vector<unsigned char> w;
    w.push_back(version);
    w.push_back(0x01);                                   // CompactSize(1)
    for (size_t i = 0; i < 32; ++i) w.push_back(static_cast<unsigned char>(i));
    w.push_back(0x07); w.push_back(0); w.push_back(0); w.push_back(0);
    for (size_t i = 0; i < 32; ++i) w.push_back(static_cast<unsigned char>(0x22 + i));
    for (size_t i = 0; i < 32; ++i) w.push_back(static_cast<unsigned char>(0x33 + i));
    for (size_t i = 0; i < 96; ++i) w.push_back(0xab);
    return w;
}

/// Deliver `payload` to the coin p2p Handler exactly as the socket read loop
/// does (mirrors test_dash_qrinfo_wire.cpp): as a RawMessage carrying only a
/// command string and opaque bytes. Throws whatever parse() throws.
dash::coin::p2p::Handler::result_t deliver(const std::string& command,
                                           const std::vector<unsigned char>& payload)
{
    auto raw = std::make_unique<RawMessage>(command, PackStream(payload));
    dash::coin::p2p::Handler handler;
    return handler.parse(raw);
}

/// std::visit + requires, NOT std::get_if — keeps this file compilable on a
/// tree WITHOUT isdlock registered, so a removed registry entry fails as a
/// legible RED test (parse() throw), not a build break.
std::string parsed_command(const dash::coin::p2p::Handler::result_t& r)
{
    return std::visit([](const auto& m) {
        return m ? m->m_command : std::string{};
    }, r);
}

std::optional<uint256> parsed_isdlock_txid(const dash::coin::p2p::Handler::result_t& r)
{
    return std::visit([](const auto& m) -> std::optional<uint256> {
        if constexpr (requires { m->m_cycle_hash; m->m_txid; }) {
            if (m) return m->m_txid;
        }
        return std::nullopt;
    }, r);
}

// ─── mempool fixtures (mirror test_dash_mempool.cpp) ─────────────────────────

uint256 mint_hash(uint32_t seed)
{
    MutableTransaction t;
    t.version = 1;
    t.type = 0;
    t.locktime = 0x51000000u ^ seed;
    auto ps = ::pack(t);
    return ::Hash(ps.get_span());
}

TxIn make_input(const uint256& prev_hash, uint32_t prev_index)
{
    TxIn in;
    in.prevout.hash = prev_hash;
    in.prevout.index = prev_index;
    in.sequence = 0xffffffffu;
    return in;
}

TxOut make_output(int64_t value)
{
    TxOut out;
    out.value = value;
    return out;
}

MutableTransaction make_spend(const uint256& prev_hash, uint32_t prev_index,
                              int64_t out_value, uint32_t salt = 0)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    tx.vin.push_back(make_input(prev_hash, prev_index));
    tx.vout.push_back(make_output(out_value));
    return tx;
}

MutableTransaction make_coinbase(std::vector<int64_t> values, uint32_t salt)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = 0x0cb00000u ^ salt;
    for (int64_t v : values) tx.vout.push_back(make_output(v));
    return tx;
}

dash::coin::BlockType make_block(std::vector<MutableTransaction> txs, uint32_t salt)
{
    dash::coin::BlockType b;
    b.m_nonce = salt;
    b.m_previous_block = mint_hash(0xb10c0000u ^ salt);
    b.m_txs = std::move(txs);
    return b;
}

/// Whether `txid` is in the selected template.
bool selected_contains(Mempool& mp, const uint256& txid)
{
    auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20);
    for (const auto& e : sel)
        if (dash_txid(e.tx) == txid) return true;
    return false;
}

} // namespace

// ═══ 1. WIRE ═════════════════════════════════════════════════════════════════

// Registry membership: a message type absent from p2p::Handler is not merely
// unhandled — parse() throws and CoinClient::handle drops the payload at
// DEBUG. This test is the gate that keeps isdlock out of that failure mode.
TEST(DashIsdlockWire, HandlerRegistryDispatchesIsdlock)
{
    dash::coin::p2p::Handler::result_t res;
    ASSERT_NO_THROW(res = deliver("isdlock", golden_isdlock_bytes()))
        << "isdlock is missing from the p2p::Handler type list — every "
           "isdlock reply to our own getdata would be discarded at DEBUG "
           "(the DIP-24 qrinfo silent-drop failure mode, #1077)";
    EXPECT_EQ(parsed_command(res), "isdlock");
    auto txid = parsed_isdlock_txid(res);
    ASSERT_TRUE(txid.has_value());
    EXPECT_EQ(*txid, raw256(0x22));
}

// Codec KAT: golden bytes (hand-assembled from the dashd wire layout, not
// produced by the codec) decode to the expected fields AND re-encode
// byte-exactly.
TEST(DashIsdlockWire, CodecDecodesGoldenBytesAndRoundtrips)
{
    const auto golden = golden_isdlock_bytes();

    PackStream in{golden};
    dash::coin::p2p::message_isdlock msg;
    ASSERT_NO_THROW(in >> msg);

    EXPECT_EQ(msg.m_version, 1u);
    ASSERT_EQ(msg.m_inputs.size(), 1u);
    EXPECT_EQ(msg.m_inputs[0].hash, raw256(0x00));
    EXPECT_EQ(msg.m_inputs[0].index, 7u);
    EXPECT_EQ(msg.m_txid, raw256(0x22));
    EXPECT_EQ(msg.m_cycle_hash, raw256(0x33));
    ASSERT_EQ(msg.m_sig.size(), 96u);
    for (auto b : msg.m_sig) EXPECT_EQ(b, 0xab);

    auto out = ::pack(msg);
    auto sp = out.get_span();
    ASSERT_EQ(sp.size(), golden.size());
    EXPECT_EQ(0, std::memcmp(sp.data(), golden.data(), golden.size()))
        << "re-encode must be byte-identical to the golden wire bytes";
}

// Structural bounds: zero inputs is a decodable-but-refused shape (handler
// refusal, not stream error) — but an inputs count over dashd's MAX_INPUTS
// must refuse at decode, before any allocation of attacker-priced size.
TEST(DashIsdlockWire, DecodeRejectsOversizedInputsVector)
{
    // CompactSize(0xFE + LE32) claiming 2^24 inputs, then nothing.
    std::vector<unsigned char> w;
    w.push_back(1);
    w.push_back(0xfe);
    w.push_back(0); w.push_back(0); w.push_back(0); w.push_back(0x01); // 16777216
    PackStream in{w};
    dash::coin::p2p::message_isdlock msg;
    EXPECT_THROW(in >> msg, std::exception)
        << "an inputs count over MAX_ISDLOCK_INPUTS must be refused at decode";
}

// The inv-type predicate admits isdlock (type 31); the runtime flag gating
// happens at the p2p_client pull site, which is exercised by the flag-OFF
// handler test below and by soak — the PREDICATE must include the type or
// the lane is structurally dark (the pre-#1071 clsig failure).
TEST(DashIsdlockWire, InvTypePredicateAdmitsIsdlock)
{
    using dash::coin::p2p::inv_type_is_pulled;
    using dash::coin::p2p::inventory_type;
    EXPECT_TRUE(inv_type_is_pulled(inventory_type::isdlock));
    EXPECT_EQ(static_cast<uint32_t>(inventory_type::isdlock), 31u)
        << "MSG_ISDLOCK is 31 (dashcore protocol.h:524)";
}

// ═══ 2. VERIFY — selection half (no BLS backend needed) ══════════════════════

TEST(DashIslockVerify, RequestIdMatchesIndependentDigest)
{
    // Single input — digest computed OUTSIDE this codebase (python hashlib
    // over the hand-assembled preimage; see the constants block above).
    EXPECT_EQ(gen_islock_request_id(kat_inputs()), u256_le(kExpectRequestIdLe));

    // Two inputs, max index — order matters and the index is LE.
    std::vector<std::pair<uint256, uint32_t>> two = {
        {raw256(0x00), 7u}, {raw256(0x20), 0xffffffffu}};
    EXPECT_EQ(gen_islock_request_id(two), u256_le(kExpectRequestId2Le));
}

TEST(DashIslockVerify, RotatedSignerIndexMatchesDashdArm)
{
    // The hand-derived indices for the two KAT requestIds.
    EXPECT_EQ(rotated_signer_index(p60_75(), u256_le(kExpectRequestIdLe)),
              kExpectSigner);
    EXPECT_EQ(rotated_signer_index(p60_75(), u256_le(kExpectRequestId2Le)),
              kExpectSigner2);

    // Structural pins of the upstream quirk (quorumsman.cpp:700-704):
    // b = GetUint64(3) = LE64 of wire bytes 24..31; signer = (b >> 58) & 0x1f.
    // All-FF: (0xffff... >> 58) & 0x1f = 0x1f = 31.
    uint256 ff; for (int i = 24; i < 32; ++i) ff.data()[i] = 0xff;
    EXPECT_EQ(rotated_signer_index(p60_75(), ff), 31u);
    // Only the TOP bit set: b = 0x8000...; >>58 = 0x20; & 0x1f = 0 — the top
    // bit is DISCARDED by upstream's (64 - n - 1) shift. Do not "fix" this.
    uint256 top; top.data()[31] = 0x80;
    EXPECT_EQ(rotated_signer_index(p60_75(), top), 0u);
    // Bit 58 alone: b = 0x0400...; >>58 = 1.
    uint256 one; one.data()[31] = 0x04;
    EXPECT_EQ(rotated_signer_index(p60_75(), one), 1u);
}

namespace {

/// A synthetic cycle of rotated candidates: base_height = cycle + index
/// (the rotated-commitment invariant dashd's CFinalCommitment::Verify
/// enforces, commitment.cpp:52). Public keys are DISTINCT per index so a
/// selection mistake cannot silently verify.
std::vector<RotatedQuorumCandidate> synthetic_cycle(uint32_t cycle_height,
                                                    uint8_t key_salt)
{
    std::vector<RotatedQuorumCandidate> v;
    for (uint16_t qi = 0; qi < 32; ++qi) {
        RotatedQuorumCandidate c;
        c.quorum_hash  = mint_hash(cycle_height + qi);
        c.base_height  = cycle_height + qi;
        c.quorum_index = qi;
        for (size_t i = 0; i < c.quorum_public_key.size(); ++i)
            c.quorum_public_key[i] =
                static_cast<uint8_t>(key_salt ^ (qi * 7) ^ i);
        v.push_back(c);
    }
    return v;
}

} // namespace

TEST(DashIslockVerify, SelectionPicksDesignatedIndexWithinCycle)
{
    constexpr uint32_t kCycle = 288 * 8000;   // a dkgInterval boundary
    const uint256 rid = gen_islock_request_id(kat_inputs());

    // Two full cycles present — selection must stay inside the NAMED one.
    auto cands = synthetic_cycle(kCycle, /*key_salt=*/0x10);
    auto prev  = synthetic_cycle(kCycle - 288, /*key_salt=*/0x90);
    cands.insert(cands.end(), prev.begin(), prev.end());

    auto q = select_rotated_quorum(p60_75(), cands, kCycle, rid);
    ASSERT_TRUE(q.has_value());
    EXPECT_EQ(q->quorum_index, kExpectSigner);
    EXPECT_EQ(q->base_height, kCycle + kExpectSigner);
    EXPECT_EQ(q->quorum_hash, mint_hash(kCycle + kExpectSigner));

    // The PREVIOUS cycle resolves to ITS OWN index-19 quorum.
    auto qp = select_rotated_quorum(p60_75(), cands, kCycle - 288, rid);
    ASSERT_TRUE(qp.has_value());
    EXPECT_EQ(qp->base_height, kCycle - 288 + kExpectSigner);
    EXPECT_NE(qp->quorum_hash, q->quorum_hash);

    // Only the designated quorum of the cycle held (others missing, e.g. one
    // index stayed on this cycle after a failed DKG while the rest rotated
    // out): still selected. Upstream's `signer > quorums.size()` guard is
    // taken against the full signing list, never against what we hold.
    std::vector<RotatedQuorumCandidate> only;
    for (const auto& c : synthetic_cycle(kCycle, 0x10))
        if (c.quorum_index == kExpectSigner) only.push_back(c);
    ASSERT_EQ(only.size(), 1u);
    auto q1 = select_rotated_quorum(p60_75(), only, kCycle, rid);
    ASSERT_TRUE(q1.has_value()) << "a held designated quorum refused because the held subset is small";
    EXPECT_EQ(q1->quorum_index, kExpectSigner);
}

TEST(DashIslockVerify, SelectionFailsClosedOnEveryUncertainty)
{
    constexpr uint32_t kCycle = 288 * 8000;
    const uint256 rid = gen_islock_request_id(kat_inputs());
    auto cands = synthetic_cycle(kCycle, 0x10);

    // (a) cycle height not a dkgInterval boundary => nullopt.
    EXPECT_FALSE(select_rotated_quorum(p60_75(), cands, kCycle + 1, rid).has_value());
    // (b) a cycle we hold no candidates for => nullopt.
    EXPECT_FALSE(select_rotated_quorum(p60_75(), cands, kCycle + 288, rid).has_value());
    // (c) the DESIGNATED index missing from an otherwise-full cycle => nullopt
    //     (dashd would fall back to the previous cycle's commitment for that
    //     index; we cannot see mined-until from the active set, so refuse).
    auto missing = cands;
    missing.erase(std::remove_if(missing.begin(), missing.end(),
                                 [](const RotatedQuorumCandidate& c) {
                                     return c.quorum_index == kExpectSigner;
                                 }),
                  missing.end());
    EXPECT_FALSE(select_rotated_quorum(p60_75(), missing, kCycle, rid).has_value());
    // (d) empty inputs / null txid at the target builder => nullopt.
    EXPECT_FALSE(build_islock_sign_target(p60_75(), cands, kCycle, {}, raw256(0x22))
                     .has_value());
    EXPECT_FALSE(build_islock_sign_target(p60_75(), cands, kCycle, kat_inputs(),
                                          uint256{})
                     .has_value());
    // (e) a NON-rotated params view => nullopt (this selector is the rotated
    //     arm only; the score-sort arm lives in chainlock_verify.hpp).
    EXPECT_FALSE(select_rotated_quorum(dash::coin::kLlmq400_60, cands, kCycle, rid)
                     .has_value());
}

// ═══ Retained quorums — locks signed by the previous rotation cycle ══════════
//
// A lock names its signing quorum's own cycle, and for a few blocks after a
// rotation the network still signs with the previous cycle; Dash Core resolves
// the lock's own cycle (net_instantsend.cpp:136-145) and accepts it. Our
// active set drops that cycle at the rotation diff, so every such lock was
// refused (mainnet 11-20: the 8 blocks after each rotation). These pin the
// retained set and the active-then-retained selection, with a stub in place
// of the BLS check.

using dash::coin::QuorumManager;
using dash::coin::islock::IslockVerifyPass;
using dash::coin::islock::RotatedQuorumCandidate;
using dash::coin::islock::verify_islock_two_pass;
using dash::coin::islock::previous_cycle_max_age;

namespace {

uint256 qhash(uint8_t tag, uint8_t index)
{
    uint256 h;
    h.data()[0] = tag;
    h.data()[1] = index;
    h.data()[31] = 0x5a;
    return h;
}

dash::coin::vendor::CFinalCommitment commit(uint8_t type, uint8_t tag, uint8_t index)
{
    dash::coin::vendor::CFinalCommitment c;
    c.llmqType = type;
    c.quorumHash = qhash(tag, index);
    c.quorumIndex = index;
    c.quorumPublicKey[0] = tag;
    c.quorumPublicKey[1] = index;
    return c;
}

// A full rotated cycle: 32 quorums at base cycle_height + i, index i, and a
// pubkey that names the cycle (byte 0) and the index (byte 1).
std::vector<RotatedQuorumCandidate> cycle(uint8_t tag, uint32_t cycle_height)
{
    std::vector<RotatedQuorumCandidate> out;
    for (uint8_t i = 0; i < 32; ++i) {
        RotatedQuorumCandidate c;
        c.quorum_hash = qhash(tag, i);
        c.base_height = cycle_height + i;
        c.quorum_index = i;
        c.quorum_public_key[0] = tag;
        c.quorum_public_key[1] = i;
        out.push_back(c);
    }
    return out;
}

} // namespace

TEST(DashIsdlockPass2, QuorumManagerRetainsRecentlyRetiredQuorumsPerType)
{
    QuorumManager q;
    constexpr uint8_t kIs = 103;   // the rotated type's byte value is irrelevant here
    constexpr uint8_t kCl = 104;
    auto rotate = [&](uint8_t from, uint8_t to, uint8_t first, uint8_t last) {
        dash::coin::vendor::QuorumTail t;
        for (uint8_t i = first; i <= last; ++i) {
            t.deletedQuorums.emplace_back(kIs, qhash(from, i));
            t.newQuorums.push_back(commit(kIs, to, i));
        }
        q.apply(t);
    };
    auto retired_of = [&](uint8_t tag) {
        size_t n = 0;
        for (const auto& e : q.retired_entries())
            n += (e.key.llmqType == kIs && e.key.quorumHash.data()[0] == tag);
        return n;
    };

    dash::coin::vendor::QuorumTail t;
    for (uint8_t i = 0; i < 32; ++i) t.newQuorums.push_back(commit(kIs, 0xA0, i));
    t.newQuorums.push_back(commit(kCl, 0xC0, 0));
    q.apply(t);
    EXPECT_TRUE(q.retired_entries().empty());

    // Rotation A -> B delivered in TWO diffs (31, then a late 1): the whole
    // previous cycle is retained, not just the last diff's part.
    rotate(0xA0, 0xB0, 0, 30);
    rotate(0xA0, 0xB0, 31, 31);
    EXPECT_EQ(retired_of(0xA0), 32u) << "a split rotation lost part of the previous cycle";
    EXPECT_EQ(q.active_count(), 33u) << "retired entries are not in the active set";

    // Another type retiring does not touch the rotated type.
    dash::coin::vendor::QuorumTail r2;
    r2.deletedQuorums.emplace_back(kCl, qhash(0xC0, 0));
    q.apply(r2);
    EXPECT_EQ(retired_of(0xA0), 32u);
    EXPECT_EQ(q.retired_entries().size(), 33u);

    // B -> D: both A and B retained (two cycles = the per-type cap of 64).
    rotate(0xB0, 0xD0, 0, 31);
    EXPECT_EQ(retired_of(0xA0), 32u);
    EXPECT_EQ(retired_of(0xB0), 32u);

    // D -> E: the oldest cycle (A) leaves; B and D stay.
    rotate(0xD0, 0xE0, 0, 31);
    EXPECT_EQ(retired_of(0xA0), 0u) << "the per-type cap must drop the oldest cycle";
    EXPECT_EQ(retired_of(0xB0), 32u);
    EXPECT_EQ(retired_of(0xD0), 32u);

    // A retired quorum that comes back is active again, not retired.
    dash::coin::vendor::QuorumTail r4;
    r4.newQuorums.push_back(commit(kIs, 0xB0, 1));
    q.apply(r4);
    for (const auto& e : q.retired_entries())
        EXPECT_FALSE(e.key == (QuorumManager::ActiveKey{kIs, qhash(0xB0, 1)}));
    EXPECT_EQ(retired_of(0xB0), 31u);

    // A wipe and a warm load both empty the retained set.
    q.clear();
    EXPECT_TRUE(q.retired_entries().empty());
    q.apply(t);
    rotate(0xA0, 0xB0, 0, 31);
    ASSERT_FALSE(q.retired_entries().empty());
    q.replace_state({}, {});
    EXPECT_TRUE(q.retired_entries().empty());
}

TEST(DashIsdlockPass2, TwoPassSelectsThePreviousCycleOnlyWhenTheLockNamesIt)
{
    const auto* p = islock_params(LlmqNetwork::Mainnet);
    ASSERT_NE(p, nullptr);
    const uint32_t I = p->dkg_interval;
    const uint32_t prev_cycle = I * 9000;          // the retired cycle
    const uint32_t cur_cycle  = I * 9001;          // the active cycle
    const uint32_t tip        = cur_cycle + 40;    // a few blocks after the rotation
    const auto active   = cycle(0xB0, cur_cycle);
    const auto previous = cycle(0xA0, prev_cycle);
    const std::vector<std::pair<uint256, uint32_t>> inputs{{raw256(0x10), 1u}};
    const uint256 txid = raw256(0x20);

    // The stub "BLS check" passes for the quorum of the expected cycle only
    // (pubkey byte 0 names the cycle), and counts how often it runs.
    int calls = 0;
    auto signed_by = [&](uint8_t tag) {
        return [&calls, tag](const auto& pubkey, const uint256&) {
            ++calls;
            return pubkey[0] == tag;
        };
    };

    // A lock signed by the current cycle: pass 1.
    calls = 0;
    EXPECT_EQ(verify_islock_two_pass(*p, active, previous, tip, cur_cycle, inputs, txid, signed_by(0xB0)),
              IslockVerifyPass::Active);
    EXPECT_EQ(calls, 1);

    // A lock signed by the previous cycle: refused by pass 1 (no quorum of
    // that cycle in the active set, so no BLS work), accepted by pass 2.
    calls = 0;
    EXPECT_EQ(verify_islock_two_pass(*p, active, previous, tip, prev_cycle, inputs, txid, signed_by(0xA0)),
              IslockVerifyPass::Previous);
    EXPECT_EQ(calls, 1) << "pass 2 must not add a second BLS check for the same lock";

    // Without the retained set (master): the same lock is refused.
    calls = 0;
    EXPECT_EQ(verify_islock_two_pass(*p, active, {}, tip, prev_cycle, inputs, txid, signed_by(0xA0)),
              IslockVerifyPass::None);
    EXPECT_EQ(calls, 0);

    // A bad signature naming either cycle: refused, one BLS check at most.
    calls = 0;
    EXPECT_EQ(verify_islock_two_pass(*p, active, previous, tip, cur_cycle, inputs, txid, signed_by(0xEE)),
              IslockVerifyPass::None);
    EXPECT_EQ(calls, 1);
    calls = 0;
    EXPECT_EQ(verify_islock_two_pass(*p, active, previous, tip, prev_cycle, inputs, txid, signed_by(0xEE)),
              IslockVerifyPass::None);
    EXPECT_EQ(calls, 1);

    // A cycle in neither set: refused with no BLS work.
    calls = 0;
    EXPECT_EQ(verify_islock_two_pass(*p, active, previous, tip, I * 8000, inputs, txid, signed_by(0xA0)),
              IslockVerifyPass::None);
    EXPECT_EQ(calls, 0);

    // The retained set ages out: base blocks more than previous_cycle_max_age()
    // below the tip are ignored (a rotation diff that never arrived).
    const uint32_t late_tip = prev_cycle + 31 + previous_cycle_max_age(*p) + 1;
    calls = 0;
    EXPECT_EQ(verify_islock_two_pass(*p, active, previous, late_tip, prev_cycle, inputs, txid, signed_by(0xA0)),
              IslockVerifyPass::None);
    EXPECT_EQ(calls, 0);
}

// ═══ 3. USE — the G4 red/green KAT ════════════════════════════════════════════

// THE KAT. One mempool, two priced txs:
//   X spends outpoint O            (the coinbase's output 0)
//   Y spends a different outpoint  (the coinbase's output 1)
// A verified isdlock arrives claiming O is locked to a DIFFERENT txid.
//
// WITHOUT the feed, the selected template contains BOTH X and Y — asserted
// below as the baseline (this exact assertion pair is what was observed to
// FAIL — RED — when the feed ran and to hold on master where the feed cannot
// run; and conversely the exclusion assertions are RED without the feed).
// WITH the feed through the REAL maintainer path, X is EXCLUDED and Y stays.
TEST(DashIsdlockG4, VerifiedIsdlockExcludesConflictKeepsNonConflict)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    Mempool& mp = st.mempool();

    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));          // ephemeral cache-only (synthetic mode)
    lane.attach(mp);

    auto cb = make_coinbase({100'000, 90'000}, /*salt=*/1);
    lane.on_block_connected(make_block({cb}, /*salt=*/1), /*height=*/1);
    const uint256 cb_txid = dash_txid(cb);
    const std::pair<uint256, uint32_t> O{cb_txid, 0u};

    auto X = make_spend(cb_txid, 0, 90'000, /*salt=*/11);   // spends O, fee 10k
    auto Y = make_spend(cb_txid, 1, 80'000, /*salt=*/12);   // no conflict, fee 10k
    ASSERT_TRUE(mp.add_tx(X));
    ASSERT_TRUE(mp.add_tx(Y));
    const uint256 x_txid = dash_txid(X);
    const uint256 y_txid = dash_txid(Y);

    // ── BASELINE (no feed): both selected, map empty. The two X-assertions
    // here are the ones the feed flips — they are the "red without the feed"
    // proof in executable form. ──────────────────────────────────────────────
    EXPECT_EQ(mp.islock_outpoint_count(), 0u);
    ASSERT_TRUE(selected_contains(mp, x_txid))
        << "baseline: without an isdlock the conflicting spend is a normal tx";
    ASSERT_TRUE(selected_contains(mp, y_txid));

    // ── FEED: a VERIFIED isdlock locking O to a txid that is NOT X. Stub
    // verifier == true stands in for the BLS gate (the BLS half has its own
    // suite below); the point here is the USE path is the REAL one:
    // on_new_isdlock -> on_islock -> Mempool::add_islock -> G4 guard. ────────
    const uint256 locked_txid = raw256(0x77);   // the network's winner, != X
    m.set_islock_verify_fn(
        [](const std::vector<std::pair<uint256, uint32_t>>&, const uint256&,
           const uint256&, const std::array<uint8_t, 96>&) { return true; });
    std::array<uint8_t, 96> sig{}; sig.fill(0xab);
    m.on_new_isdlock({O}, locked_txid, raw256(0x33), sig);

    // ── GREEN: X (conflicts with the lock) is OUT — evicted by add_islock's
    // defence 1 AND excluded by the G4 selection guard; Y is UNAFFECTED. ─────
    EXPECT_EQ(mp.islock_outpoint_count(), 1u);
    EXPECT_FALSE(selected_contains(mp, x_txid))
        << "G4: a tx spending an outpoint islocked to a DIFFERENT txid must "
           "not be packed (dashd validation.cpp conflict-tx-lock)";
    EXPECT_TRUE(selected_contains(mp, y_txid))
        << "the guard is exclusion-only: a non-conflicting tx must survive";
}

// The same feed with NO verifier registered, and with a REFUSING verifier:
// nothing is adopted, selection is byte-identical to the baseline.
TEST(DashIsdlockG4, UnverifiedIsdlockChangesNothing)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    Mempool& mp = st.mempool();

    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    lane.attach(mp);
    auto cb = make_coinbase({100'000}, /*salt=*/2);
    lane.on_block_connected(make_block({cb}, /*salt=*/2), /*height=*/1);
    auto X = make_spend(dash_txid(cb), 0, 90'000, /*salt=*/21);
    ASSERT_TRUE(mp.add_tx(X));
    const uint256 x_txid = dash_txid(X);
    std::array<uint8_t, 96> sig{}; sig.fill(0xab);

    // (a) no verifier registered => fail closed, adopt nothing.
    m.on_new_isdlock({{dash_txid(cb), 0u}}, raw256(0x77), raw256(0x33), sig);
    EXPECT_EQ(mp.islock_outpoint_count(), 0u);
    EXPECT_TRUE(selected_contains(mp, x_txid));

    // (b) verifier REFUSES => same.
    m.set_islock_verify_fn(
        [](const std::vector<std::pair<uint256, uint32_t>>&, const uint256&,
           const uint256&, const std::array<uint8_t, 96>&) { return false; });
    m.on_new_isdlock({{dash_txid(cb), 0u}}, raw256(0x77), raw256(0x33), sig);
    EXPECT_EQ(mp.islock_outpoint_count(), 0u)
        << "a refused isdlock must leave the map EXACTLY as it was";
    EXPECT_TRUE(selected_contains(mp, x_txid));
}

// ═══ N2 — a lock that arrives while a template carrying the conflict is served ═
//
// Dash Core v24.0.2 rejects a block whose tx conflicts with a known islock
// unless that block is already ChainLocked (validation.cpp:2811-2829,
// conflict-tx-lock). Eviction and the G4 guard above only shape the NEXT
// template; a body built before the lock arrived still carries the tx. These
// pin the three pieces that act on such a body: the pure body scan, the
// verified-only map + sink (a forged relay-lane lock must drive neither), and
// the once-per-second coalescer behind the forced refresh.

using dash::coin::IslockRefreshCoalescer;
using dash::coin::body_conflicts_with_lock;
using dash::coin::Transaction;

TEST(DashIsdlockN2, BodyScanNamesTheConflictingTxAndTheLock)
{
    auto cb = make_coinbase({100'000, 90'000}, /*salt=*/3);
    const uint256 cbid = dash_txid(cb);
    const auto A = make_spend(cbid, 0, 90'000, /*salt=*/31);
    const auto Z = make_spend(cbid, 1, 80'000, /*salt=*/32);
    const uint256 a = dash_txid(A);
    const uint256 z = dash_txid(Z);
    const std::vector<Transaction> body{Transaction(Z), Transaction(A)};
    const std::vector<uint256> ids{z, a};
    const std::vector<std::pair<uint256, uint32_t>> lockO{{cbid, 0u}};

    // O locked to another txid: A (index 1) is the conflict.
    const auto c = body_conflicts_with_lock(body, ids, raw256(0x77), lockO);
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c->index, 1u);
    EXPECT_EQ(c->txid, a);
    EXPECT_EQ(c->locked_txid, raw256(0x77));
    EXPECT_EQ(c->outpoint, lockO[0]);

    // O locked to A itself: A IS the locked tx, nothing to do.
    EXPECT_FALSE(body_conflicts_with_lock(body, ids, a, lockO).has_value());

    // Ids not lined up with the body: computed, same verdicts.
    const auto c2 = body_conflicts_with_lock(body, {}, raw256(0x77), lockO);
    ASSERT_TRUE(c2.has_value());
    EXPECT_EQ(c2->txid, a);
    EXPECT_FALSE(body_conflicts_with_lock(body, {}, a, lockO).has_value());

    // A lock on an outpoint the body does not spend: no conflict.
    EXPECT_FALSE(body_conflicts_with_lock(body, ids, raw256(0x77),
                                          {{raw256(0x99), 0u}}).has_value());
}

TEST(DashIsdlockN2, OnlyTheVerifiedLaneArmsTheBeltAndTheRefreshSink)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    Mempool& mp = st.mempool();

    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    lane.attach(mp);
    auto cb = make_coinbase({100'000, 90'000}, /*salt=*/4);
    lane.on_block_connected(make_block({cb}, /*salt=*/4), /*height=*/1);
    const uint256 cbid = dash_txid(cb);
    const std::pair<uint256, uint32_t> O{cbid, 0u};
    const auto A = make_spend(cbid, 0, 90'000, /*salt=*/41);
    const uint256 a = dash_txid(A);

    // The template being served was built before any lock: it carries A.
    const std::vector<Transaction> served{Transaction(A)};
    const std::vector<uint256> served_ids{a};

    int sink_calls = 0;
    uint256 sink_txid;
    std::vector<std::pair<uint256, uint32_t>> sink_inputs;
    m.set_on_verified_islock(
        [&](const uint256& t, const std::vector<std::pair<uint256, uint32_t>>& in) {
            ++sink_calls;
            sink_txid = t;
            sink_inputs = in;
        });
    std::array<uint8_t, 96> sig{}; sig.fill(0xab);

    // (1) Relay lane (unverified, any peer): the eviction map fills, the
    //     verified map does not, the sink is not called, the belt is quiet.
    m.on_islock(raw256(0x77), {O});
    EXPECT_EQ(mp.islock_outpoint_count(), 1u);
    EXPECT_EQ(mp.verified_islock_outpoint_count(), 0u);
    EXPECT_FALSE(mp.verified_islock_conflict_in(served, served_ids).has_value())
        << "a forged relay-lane lock must not be able to refuse templates";
    EXPECT_EQ(sink_calls, 0)
        << "a forged relay-lane lock must not be able to force clean notifies";

    // (2) BLS verifier refuses: same.
    m.set_islock_verify_fn(
        [](const std::vector<std::pair<uint256, uint32_t>>&, const uint256&,
           const uint256&, const std::array<uint8_t, 96>&) { return false; });
    m.on_new_isdlock({O}, raw256(0x77), raw256(0x33), sig);
    EXPECT_EQ(mp.verified_islock_outpoint_count(), 0u);
    EXPECT_EQ(sink_calls, 0);

    // (3) Verified: map + sink (with the lock's own txid and outpoints); the
    //     belt and the sink's served-template check both name A.
    m.set_islock_verify_fn(
        [](const std::vector<std::pair<uint256, uint32_t>>&, const uint256&,
           const uint256&, const std::array<uint8_t, 96>&) { return true; });
    m.on_new_isdlock({O}, raw256(0x77), raw256(0x33), sig);
    EXPECT_EQ(mp.verified_islock_outpoint_count(), 1u);
    ASSERT_EQ(sink_calls, 1);
    EXPECT_EQ(sink_txid, raw256(0x77));
    ASSERT_EQ(sink_inputs.size(), 1u);
    EXPECT_EQ(sink_inputs[0], O);
    const auto c = mp.verified_islock_conflict_in(served, served_ids);
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c->txid, a);
    EXPECT_EQ(c->locked_txid, raw256(0x77));
    EXPECT_TRUE(body_conflicts_with_lock(served, served_ids, sink_txid, sink_inputs).has_value());

    // (4) A verified lock on the served tx itself is not a conflict.
    const auto B = make_spend(cbid, 1, 80'000, /*salt=*/42);
    const std::vector<Transaction> served_b{Transaction(B)};
    m.on_new_isdlock({{cbid, 1u}}, dash_txid(B), raw256(0x33), sig);
    EXPECT_FALSE(mp.verified_islock_conflict_in(served_b, {dash_txid(B)}).has_value());

    // (5) The outpoint confirmed in a block: the entry is resolved and pruned.
    ASSERT_EQ(mp.verified_islock_outpoint_count(), 2u);
    mp.remove_for_block(make_block({make_coinbase({1}, 5), B}, /*salt=*/5));
    EXPECT_EQ(mp.verified_islock_outpoint_count(), 1u) << "only O:1 was spent";
    mp.clear();
    EXPECT_EQ(mp.verified_islock_outpoint_count(), 0u);
}

// The relay lane never overrides an outpoint a VERIFIED lock owns: it does not
// rewrite the entry and does not evict the verified tx. Otherwise selection
// (G4) and the emit belt (verified map) disagree and every freshly built
// template is refused.
TEST(DashIsdlockN2, ARelayLaneLockCannotOverrideAVerifiedOutpoint)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    Mempool& mp = st.mempool();
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    lane.attach(mp);
    auto cb = make_coinbase({100'000, 90'000}, /*salt=*/6);
    lane.on_block_connected(make_block({cb}, /*salt=*/6), /*height=*/1);
    const uint256 cbid = dash_txid(cb);
    const std::pair<uint256, uint32_t> O{cbid, 0u};
    const auto A = make_spend(cbid, 0, 90'000, /*salt=*/61);
    const uint256 a = dash_txid(A);
    ASSERT_TRUE(mp.add_tx(A));
    std::array<uint8_t, 96> sig{}; sig.fill(0xab);
    m.set_islock_verify_fn(
        [](const std::vector<std::pair<uint256, uint32_t>>&, const uint256&,
           const uint256&, const std::array<uint8_t, 96>&) { return true; });
    m.on_islock(a, {O});
    m.on_new_isdlock({O}, a, raw256(0x33), sig);
    ASSERT_TRUE(selected_contains(mp, a));

    // A relay-lane lock claiming O for T: A stays (not evicted, still selected).
    const auto T = make_spend(cbid, 0, 80'000, /*salt=*/62);
    const uint256 t = dash_txid(T);
    m.on_islock(t, {O});
    EXPECT_TRUE(selected_contains(mp, a)) << "a relay-lane lock evicted or excluded the verified tx";

    // T itself (if admitted) is never selected: O belongs to the verified A.
    (void)mp.add_tx(T);
    EXPECT_FALSE(selected_contains(mp, t))
        << "selection admitted a tx the emit belt refuses (verified lock on its outpoint)";
}

TEST(DashIsdlockN2, RefreshCoalescerFiresOncePerGapWithOneTrailing)
{
    using C = IslockRefreshCoalescer;
    using std::chrono::milliseconds;
    using std::chrono::seconds;
    C co(seconds(1));
    const auto t0 = C::clock::time_point{} + std::chrono::hours(1);

    EXPECT_EQ(co.on_trigger(t0).act, C::Act::FireNow);
    const auto d = co.on_trigger(t0 + milliseconds(300));
    EXPECT_EQ(d.act, C::Act::ScheduleTrailing);
    EXPECT_TRUE(d.delay == milliseconds(700));
    EXPECT_EQ(co.on_trigger(t0 + milliseconds(500)).act, C::Act::AlreadyPending)
        << "triggers before the trailing refresh are absorbed";
    co.on_trailing_fired(t0 + seconds(1));
    EXPECT_FALSE(co.pending());
    EXPECT_EQ(co.on_trigger(t0 + milliseconds(1500)).act, C::Act::ScheduleTrailing)
        << "the trailing refresh counts as the last fire";
    co.on_trailing_fired(t0 + seconds(2));
    EXPECT_EQ(co.on_trigger(t0 + seconds(3)).act, C::Act::FireNow);
}

// ═══ Revoke on reject — a refused lock keeps no relay-lane effect ════════════
//
// The relay lane applies every isdlock unverified (hold short-circuit, G4
// outpoint exclusion, eviction) before the BLS lane checks it. Dash Core acts
// only on locks it verified, so when the BLS lane refuses a lock its
// relay-lane effects are undone (Mempool::revoke_unverified_islock). The real
// path is driven: on_islock (relay lane) then on_new_isdlock (BLS lane), as the
// isdlock handler does.

namespace {

struct RevokeRig {
    NodeCoinState st;
    CoinStateMaintainer m{st};
    UtxoLane lane;
    uint256 cbid;
    std::array<uint8_t, 96> sig{};
    explicit RevokeRig(uint32_t salt)
    {
        lane.open("");
        lane.attach(st.mempool());
        auto cb = make_coinbase({100'000, 90'000, 80'000, 70'000}, salt);
        lane.on_block_connected(make_block({cb}, salt), /*height=*/1);
        cbid = dash_txid(cb);
        sig.fill(0xab);
    }
    void verifier(bool pass)
    {
        m.set_islock_verify_fn(
            [pass](const std::vector<std::pair<uint256, uint32_t>>&, const uint256&,
                   const uint256&, const std::array<uint8_t, 96>&) { return pass; });
    }
    // What the isdlock handler does with one lock: relay lane, then BLS lane.
    void deliver(const uint256& txid, const std::vector<std::pair<uint256, uint32_t>>& in)
    {
        m.on_islock(txid, in);
        m.on_new_isdlock(in, txid, raw256(0x33), sig);
    }
};

} // namespace

TEST(DashIsdlockRevoke, AForgedLockCannotLiftTheHoldOffAYoungTx)
{
    RevokeRig r(7);
    Mempool& mp = r.st.mempool();
    mp.set_instantsend_mining_hold(true);
    // A live feed (an unrelated honest lock) arms the hold.
    r.m.on_islock(raw256(0x44), {{raw256(0x45), 0u}});
    const auto A = make_spend(r.cbid, 0, 90'000, /*salt=*/71);
    ASSERT_TRUE(mp.add_tx(A));
    const uint256 a = dash_txid(A);
    ASSERT_FALSE(selected_contains(mp, a)) << "fixture: a young unlocked tx is held";

    // A forged isdlock(A): the relay lane applies it, the BLS lane refuses it.
    r.verifier(false);
    r.deliver(a, {{r.cbid, 0u}});
    EXPECT_FALSE(mp.islock_txid_known(a)) << "the refused lock must not stay a hold short-circuit";
    EXPECT_FALSE(selected_contains(mp, a))
        << "a refused lock must not lift the 600 s hold";
    // The hold is still ARMED (the revocation did not make the feed look
    // dark): another young unlocked tx is held too.
    const auto Y = make_spend(r.cbid, 3, 60'000, /*salt=*/72);
    ASSERT_TRUE(mp.add_tx(Y));
    EXPECT_FALSE(selected_contains(mp, dash_txid(Y))) << "a revocation disarmed the hold";

    // The same lock, VERIFIED: A is safe to mine at once (dashd IsLocked).
    r.verifier(true);
    r.deliver(a, {{r.cbid, 0u}});
    EXPECT_TRUE(selected_contains(mp, a));

    // A later forged copy naming the verified txid with junk inputs changes nothing.
    r.verifier(false);
    r.deliver(a, {{raw256(0x66), 3u}});
    EXPECT_TRUE(mp.islock_txid_known(a));
    EXPECT_TRUE(selected_contains(mp, a));
}

TEST(DashIsdlockRevoke, AMalformedLockIsNeverApplied)
{
    RevokeRig r(10);
    Mempool& mp = r.st.mempool();
    mp.set_instantsend_mining_hold(true);
    r.m.on_islock(raw256(0x44), {{raw256(0x45), 0u}});   // live feed
    const auto A = make_spend(r.cbid, 0, 90'000, /*salt=*/101);
    ASSERT_TRUE(mp.add_tx(A));
    const uint256 a = dash_txid(A);
    // No inputs: Dash Core's TriviallyValid refuses it; it must not become a
    // hold short-circuit (it never reaches the BLS lane, so nothing revokes it).
    r.m.on_islock(a, {});
    EXPECT_FALSE(mp.islock_txid_known(a));
    EXPECT_FALSE(selected_contains(mp, a));
    // Null txid: no eviction, no exclusion.
    r.m.on_islock(uint256{}, {{r.cbid, 0u}});
    EXPECT_EQ(mp.islock_outpoint_count(), 1u) << "only the live-feed lock's entry";
    mp.set_instantsend_mining_hold(false);
    EXPECT_TRUE(selected_contains(mp, a)) << "a null-txid lock evicted or excluded a tx";
}

TEST(DashIsdlockRevoke, AForgedLocksOutpointExclusionIsCleared)
{
    RevokeRig r(8);
    Mempool& mp = r.st.mempool();
    mp.set_instantsend_mining_hold(false);   // isolate G4 from the hold
    const auto Y = make_spend(r.cbid, 1, 80'000, /*salt=*/81);
    const uint256 y = dash_txid(Y);
    ASSERT_TRUE(mp.add_tx(Y));
    ASSERT_TRUE(selected_contains(mp, y));

    // A forged lock claims Y's outpoint for another txid: the relay lane evicts
    // Y (not undone: it is re-relayed) and excludes the outpoint; the refusal
    // clears the exclusion.
    r.verifier(false);
    r.deliver(raw256(0x77), {{r.cbid, 1u}});
    EXPECT_EQ(mp.islock_outpoint_count(), 0u) << "the forged lock's G4 entry must be cleared";
    ASSERT_TRUE(mp.add_tx(Y)) << "re-relayed";
    EXPECT_TRUE(selected_contains(mp, y)) << "a refused lock must not keep its outpoint excluded";
}

TEST(DashIsdlockRevoke, AForgedLockCannotOverwriteAVerifiedOutpoint)
{
    RevokeRig r(9);
    Mempool& mp = r.st.mempool();
    mp.set_instantsend_mining_hold(false);
    const std::pair<uint256, uint32_t> O{r.cbid, 2u};
    const uint256 x = raw256(0x88);            // the network's verified winner for O

    r.verifier(true);
    r.deliver(x, {O});
    ASSERT_EQ(mp.verified_islock_outpoint_count(), 1u);

    // A refused lock claiming O for W: the relay lane leaves a verified
    // outpoint alone, and after the refusal O still points at X (G4 keeps
    // excluding what the emit belt refuses).
    r.verifier(false);
    r.deliver(raw256(0x99), {O});
    const auto T = make_spend(r.cbid, 2, 70'000, /*salt=*/91);   // spends O, txid != X
    ASSERT_TRUE(mp.add_tx(T));
    EXPECT_FALSE(selected_contains(mp, dash_txid(T)))
        << "O's exclusion must point at the verified lock again after the forged one is refused";
    EXPECT_EQ(mp.islock_outpoint_count(), 1u);
}

// ═══ 4. FAIL-CLOSED — real BLS (gated on the dashbls backend) ════════════════

#ifdef C2POOL_DASH_BLS

#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>

namespace {

struct MintedQuorum {
    std::vector<RotatedQuorumCandidate> candidates;   // one full cycle
    std::array<uint8_t, 96>             sig{};        // valid threshold sig
    uint32_t                            cycle{288 * 9000};
    uint256                             txid = raw256(0x22);
    uint256                             locked_cycle_hash;
};

/// Mint a real BLS key for the DESIGNATED signer slot of kat_inputs()'s
/// requestId, produce a genuinely valid signature over the isdlock sign
/// hash, and return the cycle's candidate set carrying that real pubkey.
MintedQuorum mint_signed_isdlock()
{
    MintedQuorum mq;
    mq.candidates = synthetic_cycle(mq.cycle, /*key_salt=*/0x10);

    const uint256 rid    = gen_islock_request_id(kat_inputs());
    const uint64_t signer = rotated_signer_index(p60_75(), rid);
    EXPECT_EQ(signer, kExpectSigner);

    std::vector<uint8_t> seed(32, 0x5a);
    auto sk = bls::BasicSchemeMPL().KeyGen(bls::Bytes(seed.data(), seed.size()));
    auto pk_bytes = sk.GetG1Element().Serialize(/*fLegacy=*/false);
    EXPECT_EQ(pk_bytes.size(), 48u);
    for (auto& c : mq.candidates)
        if (c.quorum_index == signer)
            for (size_t i = 0; i < 48; ++i) c.quorum_public_key[i] = pk_bytes[i];

    auto target = build_islock_sign_target(p60_75(), mq.candidates, mq.cycle,
                                           kat_inputs(), mq.txid);
    EXPECT_TRUE(target.has_value());
    if (target) {
        auto s = bls::BasicSchemeMPL().Sign(
            sk, bls::Bytes(target->sign_hash.data(), 32));
        auto sb = s.Serialize(/*fLegacy=*/false);
        EXPECT_EQ(sb.size(), 96u);
        for (size_t i = 0; i < 96; ++i) mq.sig[i] = sb[i];
    }
    return mq;
}

/// The production verifier body, minus the header-chain lookups (candidates
/// and cycle height injected directly — the header chain is exercised live).
bool verify_isdlock(const MintedQuorum& mq,
                    const std::vector<std::pair<uint256, uint32_t>>& inputs,
                    const uint256& txid, const std::array<uint8_t, 96>& sig)
{
    auto t = build_islock_sign_target(p60_75(), mq.candidates, mq.cycle,
                                      inputs, txid);
    if (!t) return false;
    return dash::coin::vendor::verify_chainlock_sig(
        t->quorum.quorum_public_key, t->sign_hash, sig);
}

} // namespace

TEST(DashIsdlockBls, RealSignatureVerifiesEndToEnd)
{
    auto mq = mint_signed_isdlock();
    EXPECT_TRUE(verify_isdlock(mq, kat_inputs(), mq.txid, mq.sig))
        << "a threshold signature from the DESIGNATED rotated quorum must "
           "verify end-to-end";
}

// ** THE LOAD-BEARING NEGATIVE ** — a verifier that accepts everything would
// pass RealSignatureVerifiesEndToEnd trivially. Flip bits; every flip must
// be REJECTED, and through the maintainer add_islock must NEVER be called.
TEST(DashIsdlockBls, TamperedSignatureIsRejectedAndNeverReachesMempool)
{
    auto mq = mint_signed_isdlock();

    for (size_t byte_i : {0u, 7u, 31u, 48u, 64u, 95u}) {
        auto t = mq.sig;
        t[byte_i] ^= 0x20;
        EXPECT_FALSE(verify_isdlock(mq, kat_inputs(), mq.txid, t))
            << "bit-tampered isdlock signature verified at byte " << byte_i;
    }

    // Wrong txid under the REAL signature: the sign hash commits to the
    // txid, so a peer cannot re-point a real lock at a different victim tx.
    EXPECT_FALSE(verify_isdlock(mq, kat_inputs(), raw256(0x55), mq.sig));
    // Wrong inputs: requestId changes => different designated quorum and
    // different sign hash => rejected.
    EXPECT_FALSE(verify_isdlock(mq, {{raw256(0x20), 1u}}, mq.txid, mq.sig));

    // End-to-end through the maintainer gate with the REAL BLS verifier:
    // tampered => add_islock never called; genuine => folded.
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_islock_verify_fn(
        [&mq](const std::vector<std::pair<uint256, uint32_t>>& inputs,
              const uint256& txid, const uint256& /*cycle*/,
              const std::array<uint8_t, 96>& sig) {
            return verify_isdlock(mq, inputs, txid, sig);
        });

    auto bad = mq.sig; bad[0] ^= 0x20;
    m.on_new_isdlock(kat_inputs(), mq.txid, mq.locked_cycle_hash, bad);
    EXPECT_EQ(st.mempool().islock_outpoint_count(), 0u)
        << "a BLS-rejected isdlock must never reach Mempool::add_islock";

    m.on_new_isdlock(kat_inputs(), mq.txid, mq.locked_cycle_hash, mq.sig);
    EXPECT_EQ(st.mempool().islock_outpoint_count(), 1u)
        << "the genuine signature must pass the same gate";
}

#endif // C2POOL_DASH_BLS
