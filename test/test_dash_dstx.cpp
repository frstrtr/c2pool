// SPDX-License-Identifier: AGPL-3.0-or-later
/// W5-B DSTX intake — acquire -> BLS-verify -> zero-fee prioritised admission,
/// all fail-closed.
///
/// The claims this suite pins, in dependency order:
///
///   1. WIRE. `dstx` is registered in the p2p::Handler type list (the DIP-24
///      qrinfo silent-drop failure mode, #1077, gets its own RED-able test)
///      and the codec decodes the dashd CCoinJoinBroadcastTx v23 wire layout
///      byte-exactly (KAT: hand-assembled golden bytes, independent of the
///      codec) and re-encodes byte-identically.
///
///   2. PRE-IMAGE. dstx_signature_hash reproduces dashd
///      CCoinJoinBroadcastTx::GetSignatureHash — SHA256d over an
///      INDEPENDENTLY hand-assembled byte stream
///      (tx-wire-bytes ‖ protxHash ‖ sigTime LE), with the tx wire bytes
///      themselves hand-assembled (pins pack(tx) too). SER_GETHASH excludes
///      vchSig; changing the sig must NOT change the digest.
///
///   3. STRUCTURE. dstx_is_valid_structure applies dashd IsValidStructure's
///      refusals: null protx, vin!=vout, vin<3, vin>180, non-denominated
///      vout, non-P2PKH vout, sig!=96B.
///
///   4. USE (the red/green pair). A dstx-shaped ZERO-fee tx admitted as a
///      PLAIN tx is left OUT of the template (blockMinFeeRate floor) — the
///      baseline, master's behaviour. The SAME tx through the REAL verified
///      path (CoinStateMaintainer::on_new_dstx -> Mempool::add_dstx) enters
///      the template FIRST (modified ancestor score = +0.1 COIN, dashd's
///      GetModFeesWithAncestors sort) while total_fees still EXCLUDES the
///      delta (coinbasevalue byte-parity: dashd accounts base fees).
///
///   5. FAIL-CLOSED. No verifier registered => nothing admitted. A verifier
///      running the REAL BLS entry point (verify_govvote_operator_sig)
///      against a bad signature => REJECTED, add_dstx never called.
///
///   6. FEE SAFETY. A DSTX whose inputs the view cannot price is admitted at
///      fee=0 (understate-only) — never fee-unknown-excluded, never a
///      guessed positive fee.

#include <gtest/gtest.h>

#include <impl/dash/coin/p2p_messages.hpp>
#include <impl/dash/coin/coin_state_maintainer.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/utxo_lane.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>

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
using dash::coin::p2p::dstx_is_valid_structure;
using dash::coin::p2p::dstx_signature_hash;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

namespace {

// The 0.10000100 DASH denomination (coinjoin/common.h), duffs.
constexpr int64_t kDenom = 10000100;

/// uint256 whose RAW WIRE BYTES are 32 consecutive values starting at `base`.
uint256 raw256(uint8_t base)
{
    uint256 h;
    for (size_t i = 0; i < 32; ++i)
        h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}

std::vector<uint8_t> p2pkh_script(uint8_t tag)
{
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

TxIn make_input(const uint256& prev_hash, uint32_t prev_index)
{
    TxIn in;
    in.prevout.hash = prev_hash;
    in.prevout.index = prev_index;
    in.sequence = 0xffffffffu;
    return in;
}

TxOut make_output(int64_t value, std::vector<uint8_t> script = {})
{
    TxOut out;
    out.value = value;
    out.scriptPubKey.m_data = std::move(script);
    return out;
}

/// The canonical synthetic DSTX this suite reuses: 3-in/3-out, every output
/// the 0.10000100 denomination to P2PKH, spending (prev_base..)+vout 0..2.
MutableTransaction make_dstx_tx(const uint256& prev, uint32_t salt = 0)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = salt;
    for (uint32_t i = 0; i < 3; ++i)
        tx.vin.push_back(make_input(prev, i));
    for (uint8_t i = 0; i < 3; ++i)
        tx.vout.push_back(make_output(kDenom, p2pkh_script(0x40 + i)));
    return tx;
}

// ─── INDEPENDENT byte assembly (deliberately NOT the codec / pack layer) ────

void put_le32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i)
        v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
}
void put_le64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i)
        v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
}
void put_u256(std::vector<uint8_t>& v, const uint256& h)
{
    v.insert(v.end(), h.data(), h.data() + 32);
}

/// Hand-assembled network serialization of make_dstx_tx(prev, salt) — the
/// dashd tx wire: version|type<<16 (4B LE), vin count, per-vin prevout(36B) +
/// scriptSig(compactsize 0) + sequence, vout count, per-vout value(8B LE) +
/// script(compactsize + bytes), locktime (4B LE). Type 0 => no extra payload.
std::vector<uint8_t> hand_tx_bytes(const uint256& prev, uint32_t salt = 0)
{
    std::vector<uint8_t> w;
    put_le32(w, 1u);            // version 1, type 0
    w.push_back(0x03);          // vin count
    for (uint32_t i = 0; i < 3; ++i) {
        put_u256(w, prev);
        put_le32(w, i);
        w.push_back(0x00);      // empty scriptSig
        put_le32(w, 0xffffffffu);
    }
    w.push_back(0x03);          // vout count
    for (uint8_t i = 0; i < 3; ++i) {
        put_le64(w, static_cast<uint64_t>(kDenom));
        auto s = p2pkh_script(0x40 + i);
        w.push_back(static_cast<uint8_t>(s.size()));   // 0x19
        w.insert(w.end(), s.begin(), s.end());
    }
    put_le32(w, salt);          // locktime
    return w;
}

/// Hand-assembled `dstx` message payload: tx ‖ protxHash ‖ vchSig
/// (CompactSize 0x60 + 96 bytes) ‖ sigTime (8B LE).
std::vector<uint8_t> golden_dstx_bytes(const uint256& prev,
                                       const uint256& protx,
                                       uint8_t sig_fill, int64_t sig_time)
{
    std::vector<uint8_t> w = hand_tx_bytes(prev);
    put_u256(w, protx);
    w.push_back(0x60);
    for (int i = 0; i < 96; ++i) w.push_back(sig_fill);
    put_le64(w, static_cast<uint64_t>(sig_time));
    return w;
}

/// Deliver `payload` to the coin p2p Handler exactly as the socket read loop
/// does (mirrors test_dash_isdlock.cpp).
dash::coin::p2p::Handler::result_t deliver(const std::string& command,
                                           const std::vector<unsigned char>& payload)
{
    auto raw = std::make_unique<RawMessage>(command, PackStream(payload));
    dash::coin::p2p::Handler handler;
    return handler.parse(raw);
}

std::string parsed_command(const dash::coin::p2p::Handler::result_t& r)
{
    return std::visit([](const auto& m) {
        return m ? m->m_command : std::string{};
    }, r);
}

std::optional<uint256> parsed_dstx_protx(const dash::coin::p2p::Handler::result_t& r)
{
    return std::visit([](const auto& m) -> std::optional<uint256> {
        if constexpr (requires { m->m_protx_hash; m->m_sig_time; }) {
            if (m) return m->m_protx_hash;
        }
        return std::nullopt;
    }, r);
}

// ─── mempool fixtures (mirror test_dash_isdlock.cpp) ────────────────────────

MutableTransaction make_coinbase(std::vector<std::pair<int64_t, uint8_t>> outs,
                                 uint32_t salt)
{
    MutableTransaction tx;
    tx.version = 1;
    tx.type = 0;
    tx.locktime = 0x0cb00000u ^ salt;
    for (auto [v, tag] : outs)
        tx.vout.push_back(make_output(v, p2pkh_script(tag)));
    return tx;
}

dash::coin::BlockType make_block(std::vector<MutableTransaction> txs,
                                 uint32_t salt)
{
    dash::coin::BlockType b;
    b.m_nonce = salt;
    b.m_previous_block = raw256(static_cast<uint8_t>(salt));
    b.m_txs = std::move(txs);
    return b;
}

std::vector<uint256> selected_order(Mempool& mp)
{
    auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20);
    std::vector<uint256> out;
    for (const auto& e : sel) out.push_back(dash_txid(e.tx));
    return out;
}

} // namespace

// ═══ 1. WIRE ════════════════════════════════════════════════════════════════

// Registry membership: a message type absent from p2p::Handler is not merely
// unhandled — parse() throws and CoinClient::handle drops the payload at
// DEBUG. This test is the gate that keeps dstx out of that failure mode.
TEST(DashDstxWire, HandlerRegistryDispatchesDstx)
{
    dash::coin::p2p::Handler::result_t res;
    ASSERT_NO_THROW(res = deliver(
        "dstx", golden_dstx_bytes(raw256(0x00), raw256(0x22), 0xab, 1720000000)))
        << "dstx is missing from the p2p::Handler type list — every dstx "
           "reply to our own getdata would be discarded at DEBUG (the DIP-24 "
           "qrinfo silent-drop failure mode, #1077)";
    EXPECT_EQ(parsed_command(res), "dstx");
    auto protx = parsed_dstx_protx(res);
    ASSERT_TRUE(protx.has_value());
    EXPECT_EQ(*protx, raw256(0x22));
}

// Codec KAT: golden bytes (hand-assembled from the dashd wire layout, not
// produced by the codec) decode to the expected fields AND re-encode
// byte-exactly.
TEST(DashDstxWire, CodecDecodesGoldenBytesAndRoundtrips)
{
    const auto golden =
        golden_dstx_bytes(raw256(0x00), raw256(0x22), 0xab, 1720000000);

    PackStream in{golden};
    dash::coin::p2p::message_dstx msg;
    ASSERT_NO_THROW(in >> msg);

    EXPECT_EQ(msg.m_tx.vin.size(), 3u);
    EXPECT_EQ(msg.m_tx.vout.size(), 3u);
    EXPECT_EQ(msg.m_tx.vin[1].prevout.hash, raw256(0x00));
    EXPECT_EQ(msg.m_tx.vin[1].prevout.index, 1u);
    EXPECT_EQ(msg.m_tx.vout[0].value, kDenom);
    EXPECT_EQ(msg.m_protx_hash, raw256(0x22));
    ASSERT_EQ(msg.m_sig.size(), 96u);
    EXPECT_EQ(msg.m_sig[0], 0xab);
    EXPECT_EQ(msg.m_sig_time, 1720000000);

    PackStream out;
    out << msg;
    auto sp = out.get_span();
    ASSERT_EQ(sp.size(), golden.size());
    EXPECT_EQ(0, std::memcmp(sp.data(), golden.data(), golden.size()));
}

// ═══ 2. PRE-IMAGE ═══════════════════════════════════════════════════════════

// dstx_signature_hash == SHA256d over the INDEPENDENTLY assembled preimage
// (hand tx bytes ‖ protx ‖ sigTime LE) — which also pins that pack(tx)
// produces exactly the hand-assembled network tx serialization.
TEST(DashDstxSigHash, MatchesIndependentPreimage)
{
    const uint256 prev = raw256(0x00);
    const uint256 protx = raw256(0x22);
    const int64_t sig_time = 1720000000;
    auto tx = make_dstx_tx(prev);

    // pack(tx) is byte-identical to the hand assembly (dash_txid base).
    auto hand = hand_tx_bytes(prev);
    auto ps = ::pack(tx);
    auto sp = ps.get_span();
    ASSERT_EQ(sp.size(), hand.size());
    ASSERT_EQ(0, std::memcmp(sp.data(), hand.data(), hand.size()));

    std::vector<uint8_t> pre = hand;
    put_u256(pre, protx);
    put_le64(pre, static_cast<uint64_t>(sig_time));
    const uint256 want = ::Hash(pre);   // double SHA256

    EXPECT_EQ(dstx_signature_hash(tx, protx, sig_time), want);
    // The sig is EXCLUDED (SER_GETHASH guard) — no sig argument exists, so
    // the digest is a pure function of (tx, protx, sigTime); a different
    // sigTime must change it.
    EXPECT_NE(dstx_signature_hash(tx, protx, sig_time + 1), want);
    EXPECT_NE(dstx_signature_hash(tx, raw256(0x23), sig_time), want);
}

// ═══ 3. STRUCTURE ═══════════════════════════════════════════════════════════

TEST(DashDstxStructure, RefusalsMatchIsValidStructure)
{
    const uint256 prev = raw256(0x00);
    const uint256 protx = raw256(0x22);
    auto good = make_dstx_tx(prev);
    EXPECT_TRUE(dstx_is_valid_structure(good, protx, 96));

    // Null protx.
    EXPECT_FALSE(dstx_is_valid_structure(good, uint256(), 96));
    // Sig != 96 bytes.
    EXPECT_FALSE(dstx_is_valid_structure(good, protx, 95));
    // vin != vout.
    auto lop = good;
    lop.vout.pop_back();
    EXPECT_FALSE(dstx_is_valid_structure(lop, protx, 96));
    // vin < 3 (nPoolMinParticipants).
    auto small = good;
    small.vin.resize(2);
    small.vout.resize(2);
    EXPECT_FALSE(dstx_is_valid_structure(small, protx, 96));
    // vin > 180 (20 participants x 9 entries).
    auto big = good;
    while (big.vin.size() <= 180) {
        big.vin.push_back(make_input(prev, static_cast<uint32_t>(big.vin.size())));
        big.vout.push_back(make_output(kDenom, p2pkh_script(0x40)));
    }
    EXPECT_FALSE(dstx_is_valid_structure(big, protx, 96));
    // Non-denominated output value.
    auto baddenom = good;
    baddenom.vout[1].value = kDenom + 1;
    EXPECT_FALSE(dstx_is_valid_structure(baddenom, protx, 96));
    // Non-P2PKH output script.
    auto badscript = good;
    badscript.vout[2].scriptPubKey.m_data = {0x6a};   // OP_RETURN
    EXPECT_FALSE(dstx_is_valid_structure(badscript, protx, 96));
}

// ═══ 4. USE — the red/green pair (KAT b) ════════════════════════════════════

// PLAIN admission of the zero-fee mixing tx (the network also relays it as
// MSG_TX): priced fee=0, and the blockMinFeeRate floor keeps it OUT of the
// template — the baseline, byte-identical to master. The SAME tx through the
// REAL verified DSTX path enters FIRST (modified ancestor score +0.1 COIN)
// while total_fees still excludes the delta AND the zero base fee.
TEST(DashDstxUse, VerifiedDstxRanksFirstAndFeesStayBase)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    Mempool& mp = st.mempool();

    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));          // ephemeral cache-only
    lane.attach(mp);

    // Coinbase: three denomination coins (the DSTX inputs) + one 200k coin
    // (the fee-paying competitor's input).
    auto cb = make_coinbase(
        {{kDenom, 0x01}, {kDenom, 0x02}, {kDenom, 0x03}, {200'000, 0x04}},
        /*salt=*/1);
    lane.on_block_connected(make_block({cb}, /*salt=*/1), /*height=*/1);
    const uint256 cb_txid = dash_txid(cb);

    auto dstx_tx = make_dstx_tx(cb_txid, /*salt=*/7);
    const uint256 dstx_txid = dash_txid(dstx_tx);

    MutableTransaction competitor;
    competitor.version = 1;
    competitor.type = 0;
    competitor.locktime = 9;
    competitor.vin.push_back(make_input(cb_txid, 3));
    competitor.vout.push_back(make_output(150'000, p2pkh_script(0x50)));
    const uint256 comp_txid = dash_txid(competitor);
    ASSERT_TRUE(mp.add_tx(competitor));   // fee 50'000

    // ── BASELINE (plain admission): fee computes to 0, and the
    // blockMinFeeRate floor (dashd DEFAULT_BLOCK_MIN_TX_FEE) leaves the
    // zero-fee tx OUT. This is master's behaviour — the assertion that goes
    // RED when the delta is applied. ─────────────────────────────────────────
    ASSERT_TRUE(mp.add_tx(dstx_tx));
    {
        auto e = mp.get_entry(dstx_txid);
        ASSERT_TRUE(e.has_value());
        EXPECT_TRUE(e->fee_known);
        EXPECT_EQ(e->fee, 0u);
        EXPECT_EQ(e->fee_delta, 0u);
        auto order = selected_order(mp);
        ASSERT_EQ(order.size(), 1u)
            << "baseline: a zero-fee tx must not clear the min-feerate floor";
        EXPECT_EQ(order[0], comp_txid);
    }

    // ── FEED: the SAME tx through the REAL verified path. Stub verifier ==
    // true stands in for the BLS gate (fail-closed halves have their own
    // tests below); the USE path is the production one:
    // on_new_dstx -> add_dstx -> retro-applied delta -> modified scoring. ────
    m.set_dstx_verify_fn(
        [](const MutableTransaction&, const uint256&, const uint256&,
           const std::array<uint8_t, 96>&, int64_t) { return true; });
    std::array<uint8_t, 96> sig{};
    sig.fill(0xab);
    m.on_new_dstx(dstx_tx, dstx_txid, raw256(0x22), sig, 1720000000);

    {
        auto e = mp.get_entry(dstx_txid);
        ASSERT_TRUE(e.has_value());
        EXPECT_TRUE(e->fee_known);
        EXPECT_EQ(e->fee, 0u);                        // BASE fee stays 0
        EXPECT_EQ(e->fee_delta, Mempool::DSTX_FEE_DELTA);
        auto [sel, fees] = mp.get_sorted_txs_with_fees(1u << 20);
        ASSERT_EQ(sel.size(), 2u)
            << "the +0.1 COIN modified fee must clear the floor";
        // dashd sorts on GetModFeesWithAncestors: the DSTX (modified 10M
        // over ~a few hundred bytes) outranks the 50k-fee competitor.
        EXPECT_EQ(dash_txid(sel[0].tx), dstx_txid);
        EXPECT_EQ(dash_txid(sel[1].tx), comp_txid);
        // ACCOUNTING stays BASE: coinbasevalue parity — dashd's nFees is
        // unmodified fees, so the delta must NEVER reach total_fees.
        EXPECT_EQ(fees, 50'000u);
        EXPECT_EQ(sel[0].fee, 0u);
    }
}

// Admission BEFORE the plain tx ever arrives (the dashd message order):
// delta recorded pre-admission, fee=0 forced when inputs are unpriceable —
// never fee-unknown-excluded, never a guessed positive fee (KAT: fee
// safety). Inputs unknown to the view => the selection guard still refuses
// the vin (correctly — nothing vouches for the coins), but the ENTRY is
// priced and indexed, and prices exactly 0.
TEST(DashDstxUse, UnpriceableInputsAdmitAtZeroFee)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    Mempool& mp = st.mempool();
    UtxoLane lane;
    ASSERT_TRUE(lane.open(""));
    lane.attach(mp);

    auto dstx_tx = make_dstx_tx(raw256(0x66), /*salt=*/8);   // unknown prevouts
    m.set_dstx_verify_fn(
        [](const MutableTransaction&, const uint256&, const uint256&,
           const std::array<uint8_t, 96>&, int64_t) { return true; });
    std::array<uint8_t, 96> sig{};
    sig.fill(0xab);
    m.on_new_dstx(dstx_tx, dash_txid(dstx_tx), raw256(0x22), sig, 1720000000);

    auto e = mp.get_entry(dash_txid(dstx_tx));
    ASSERT_TRUE(e.has_value());
    EXPECT_TRUE(e->fee_known);
    EXPECT_EQ(e->fee, 0u);
    EXPECT_EQ(e->fee_delta, Mempool::DSTX_FEE_DELTA);
}

// ═══ 5. FAIL-CLOSED (KAT d) ═════════════════════════════════════════════════

// No verifier registered: nothing is ever admitted.
TEST(DashDstxFailClosed, NoVerifierAdmitsNothing)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    auto dstx_tx = make_dstx_tx(raw256(0x66));
    std::array<uint8_t, 96> sig{};
    sig.fill(0xab);
    m.on_new_dstx(dstx_tx, dash_txid(dstx_tx), raw256(0x22), sig, 1720000000);
    EXPECT_EQ(st.mempool().size(), 0u);
}

// A bad BLS signature through the REAL BLS entry point
// (verify_govvote_operator_sig — the byte-identical VerifyInsecure contract
// dashd's CheckSignature uses) is REJECTED and add_dstx is never called.
// Fail-closed in BOTH postures: with the BLS backend absent the entry point
// returns false unconditionally; with it present, an all-zero operator key /
// garbage signature fails point deserialization or the pairing check.
TEST(DashDstxFailClosed, BadBlsSignatureIsRejected)
{
    NodeCoinState st;
    CoinStateMaintainer m(st);
    m.set_dstx_verify_fn(
        [](const MutableTransaction& tx, const uint256&,
           const uint256& protx, const std::array<uint8_t, 96>& s,
           int64_t t) -> bool {
            std::array<uint8_t,
                       dash::coin::vendor::CFinalCommitment::BLS_PUBKEY_SIZE>
                zero_key{};
            return dash::coin::vendor::verify_govvote_operator_sig(
                zero_key, /*key_legacy_scheme=*/false,
                dstx_signature_hash(tx, protx, t),
                std::vector<uint8_t>(s.begin(), s.end()));
        });
    auto dstx_tx = make_dstx_tx(raw256(0x66));
    std::array<uint8_t, 96> bad{};
    bad.fill(0xcd);
    m.on_new_dstx(dstx_tx, dash_txid(dstx_tx), raw256(0x22), bad, 1720000000);
    EXPECT_EQ(st.mempool().size(), 0u)
        << "an unverifiable DSTX must never reach add_dstx";
}
